"""Outbound sync scheduler_event (hourly). Policy pull + kill-switch/blacklist
reaping are unconditional (not configurable in v1, and a disable/blacklist
change must always reach a guard). Log push and retention are gated on
policy.log_sync_enabled. All state referenced here is file-backed, per
PROTOCOL.md/DESIGN.md.
"""

import os
from datetime import datetime, timezone

import frappe

from access_guard.config_utils import (
	atomic_write_json,
	locked_file,
	logs_dir,
	pushed_dir,
	read_json,
)
from access_guard.hub_client import pull_policy, push_logs
from access_guard.logging_ import _SUFFIX_BY_KIND
from access_guard.policy import get_policy, verify_and_store_policy
from access_guard.protocol import (
	MAX_PUSH_BYTES,
	POLICY_LOG_SYNC_ENABLED,
	POLICY_PUSH_GRACE_DAYS,
	POLICY_RETENTION_DAYS,
	parse_iso,
	utc_iso,
	utc_now,
)
from access_guard.reaper import reap_disabled_and_blacklisted


def _jti_and_kind_from_filename(name: str) -> tuple[str, str] | None:
	for log_kind, suffix in _SUFFIX_BY_KIND.items():
		if name.endswith(suffix):
			return name[: -len(suffix)], log_kind
	return None


def _pushed_meta_path(jti: str, log_kind: str) -> str:
	return os.path.join(pushed_dir(), f"{jti}.{log_kind}.meta")


def _pushed_meta(jti: str, log_kind: str) -> dict:
	return read_json(_pushed_meta_path(jti, log_kind), default={}) or {}


def _pushed_bytes(jti: str, log_kind: str) -> int:
	"""Byte offset up to which this file's content has already reached the
	hub. Each sync only sends the tail past this, so a session spanning
	multiple hourly cycles doesn't get re-pushed (and re-appended on the hub
	side) from the start every time."""
	return int(_pushed_meta(jti, log_kind).get("pushed_bytes", 0))


def _acked_at(jti: str, log_kind: str) -> datetime | None:
	"""UTC-aware, or None. Written by _mark_pushed as UTC (meta is a file, not
	a DocType); parse_iso rejects a naive value rather than guessing, so a
	meta file from an older build is treated as 'never acked' instead of
	silently comparing against the wrong clock."""
	acked_at = _pushed_meta(jti, log_kind).get("acked_at")
	if not acked_at:
		return None
	try:
		return parse_iso(acked_at)
	except (ValueError, TypeError):
		return None


def _mark_pushed(jti: str, log_kind: str, pushed_bytes: int) -> None:
	path = _pushed_meta_path(jti, log_kind)
	with locked_file(path + ".lock"):
		atomic_write_json(
			path,
			{"pushed_bytes": pushed_bytes, "acked_at": utc_iso()},
		)


def sync_hourly() -> None:
	_pull_and_verify_policy()

	policy = get_policy()
	if not policy.get(POLICY_LOG_SYNC_ENABLED, True):
		return
	_push_all_logs()
	_enforce_retention(policy)


def _split_chunks(blob: bytes) -> list[tuple[bytes, int]]:
	"""`blob` split on line boundaries into (chunk, source_bytes) pairs, every
	chunk at most MAX_PUSH_BYTES so the hub can never reject one.

	Line-aligned, never a blind slice: the hub appends what it receives verbatim,
	so cutting mid-line would file two corrupt half-lines. A single line over the
	cap has no boundary to split on, so it is truncated to fit - `source_bytes` is
	then larger than the chunk, which is why the caller advances its file offset by
	that rather than by len(chunk)."""
	chunks = []
	current = bytearray()
	consumed = 0
	for line in blob.splitlines(keepends=True):
		if len(current) + len(line) > MAX_PUSH_BYTES:
			if current:
				chunks.append((bytes(current), consumed))
				current, consumed = bytearray(), 0
			consumed += len(line)
			line = line[:MAX_PUSH_BYTES]
		else:
			consumed += len(line)
		current += line
	if current:
		chunks.append((bytes(current), consumed))
	return chunks


def _push_all_logs() -> None:
	log_dir = logs_dir()
	if not os.path.isdir(log_dir):
		return

	for name in os.listdir(log_dir):
		parsed = _jti_and_kind_from_filename(name)
		if parsed is None:
			continue
		jti, log_kind = parsed
		path = os.path.join(log_dir, name)
		offset = _pushed_bytes(jti, log_kind)
		# Binary: pushed_bytes is a byte offset, and the hub's MAX_PUSH_BYTES is a
		# byte cap - text mode would let a multi-byte character make len() disagree
		# with both.
		try:
			with open(path, "rb") as f:
				f.seek(offset)
				blob = f.read()
		except OSError:
			continue
		if not blob.strip():
			continue

		# Chunked, because the hub rejects anything over MAX_PUSH_BYTES outright.
		# Sent in order, advancing the offset per accepted chunk: a failure partway
		# through keeps what already landed and resumes from there next hour,
		# instead of re-sending (and duplicating) the whole tail.
		for chunk, source_bytes in _split_chunks(blob):
			result = push_logs(jti=jti, log_kind=log_kind, lines=chunk.decode(errors="replace"))
			if not (result and result.get("ok")):
				break  # hub unreachable or refused; resume from `offset` next run
			offset += source_bytes
			_mark_pushed(jti, log_kind, offset)


def _pull_and_verify_policy() -> None:
	token = pull_policy()
	if not token:
		return
	try:
		verify_and_store_policy(token)
	except Exception:
		frappe.log_error(title="access_guard sync: policy verification failed")
		return
	reap_disabled_and_blacklisted()


def _enforce_retention(policy: dict) -> None:
	"""A file is only eligible for early (grace-period) deletion once it is
	*fully* acked - pushed_bytes covering its whole current size - not merely
	acked at all. A long-running session that keeps getting appended to after
	its last successful push otherwise has its unpushed tail deleted right
	along with the acked prefix. Past retention_days it's deleted regardless
	(backstop for a file that never gets fully pushed, e.g. push_logs failing
	permanently) - v2 concern: truncating just the acked prefix so an
	active session's log doesn't grow unbounded in the meantime.

	The stat-then-remove below is locked against the same `path + ".lock"`
	append_line() takes (config_utils.py), so a write racing in right as a
	file crosses into grace/retention can't be silently destroyed by the
	delete."""
	retention_days = int(policy.get(POLICY_RETENTION_DAYS) or 365)
	grace_days = int(policy.get(POLICY_PUSH_GRACE_DAYS) or 7)

	log_dir = logs_dir()
	if not os.path.isdir(log_dir):
		return

	# One clock for both comparisons: acked_at is UTC-aware, and st_mtime is an
	# epoch timestamp read as UTC. Previously these were now_datetime() (naive
	# *System Settings* tz) vs fromtimestamp() (naive *OS* tz) - routinely hours
	# apart in a container, which could age a file out early.
	now = utc_now()
	for name in os.listdir(log_dir):
		parsed = _jti_and_kind_from_filename(name)
		if parsed is None:
			continue
		jti, log_kind = parsed
		path = os.path.join(log_dir, name)

		with locked_file(path + ".lock"):
			try:
				stat = os.stat(path)
			except OSError:
				continue

			fully_acked = _pushed_bytes(jti, log_kind) >= stat.st_size
			acked_at = _acked_at(jti, log_kind)
			grace_elapsed = acked_at is not None and (now - acked_at).days > grace_days

			mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
			age_days = (now - mtime).days

			if (fully_acked and grace_elapsed) or age_days > retention_days:
				try:
					os.remove(path)
				except FileNotFoundError:
					pass

		if (fully_acked and grace_elapsed) or age_days > retention_days:
			meta_path = _pushed_meta_path(jti, log_kind)
			try:
				os.remove(meta_path)
			except FileNotFoundError:
				pass
