"""Outbound sync scheduler_event (hourly). Policy pull + kill-switch/blacklist
reaping are unconditional (not configurable in v1, and a disable/blacklist
change must always reach a guard). Log push and retention are gated on
policy.log_sync_enabled. All state referenced here is file-backed, per
PROTOCOL.md/DESIGN.md.
"""

import os
from datetime import datetime

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
from access_guard.protocol import POLICY_LOG_SYNC_ENABLED, POLICY_PUSH_GRACE_DAYS, POLICY_RETENTION_DAYS
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
	acked_at = _pushed_meta(jti, log_kind).get("acked_at")
	return frappe.utils.get_datetime(acked_at) if acked_at else None


def _mark_pushed(jti: str, log_kind: str, pushed_bytes: int) -> None:
	path = _pushed_meta_path(jti, log_kind)
	with locked_file(path + ".lock"):
		atomic_write_json(
			path,
			{"pushed_bytes": pushed_bytes, "acked_at": frappe.utils.now_datetime().isoformat()},
		)


def sync_hourly() -> None:
	_pull_and_verify_policy()

	policy = get_policy()
	if not policy.get(POLICY_LOG_SYNC_ENABLED, True):
		return
	_push_all_logs()
	_enforce_retention(policy)


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
		try:
			with open(path) as f:
				f.seek(offset)
				new_text = f.read()
				total_bytes = f.tell()
		except OSError:
			continue
		if not new_text.strip():
			continue

		result = push_logs(jti=jti, log_kind=log_kind, lines=new_text)
		if result and result.get("ok"):
			_mark_pushed(jti, log_kind, total_bytes)


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
	active session's log doesn't grow unbounded in the meantime."""
	retention_days = int(policy.get(POLICY_RETENTION_DAYS) or 365)
	grace_days = int(policy.get(POLICY_PUSH_GRACE_DAYS) or 7)

	log_dir = logs_dir()
	if not os.path.isdir(log_dir):
		return

	now = frappe.utils.now_datetime()
	for name in os.listdir(log_dir):
		parsed = _jti_and_kind_from_filename(name)
		if parsed is None:
			continue
		jti, log_kind = parsed
		path = os.path.join(log_dir, name)
		try:
			stat = os.stat(path)
		except OSError:
			continue

		fully_acked = _pushed_bytes(jti, log_kind) >= stat.st_size
		acked_at = _acked_at(jti, log_kind)
		grace_elapsed = acked_at is not None and (now - acked_at).days > grace_days

		mtime = datetime.fromtimestamp(stat.st_mtime)
		age_days = (now - mtime).days

		if (fully_acked and grace_elapsed) or age_days > retention_days:
			try:
				os.remove(path)
			except FileNotFoundError:
				pass
			meta_path = _pushed_meta_path(jti, log_kind)
			try:
				os.remove(meta_path)
			except FileNotFoundError:
				pass
