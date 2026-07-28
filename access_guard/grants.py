"""File-backed grant records + used-jti replay store.

Both are integrity-critical (PROTOCOL.md §6) and therefore live under
site/private/access_guard/ — never in a DocType. Concurrency is handled
with a simple flock per shared file.

Grants are one JSON file ({jti: record, ...}), not one file per jti -
find_grant_by_sid runs on nearly every request, so a directory scan per
call was N file reads too many. Redis mirrors it as one key holding both
{"grants": ..., "sid_map": ...}, refreshed from inside the same file lock
as the disk write, so redis can't reorder relative to disk across
concurrent writers (see policy.py's store_verified_policy for the same fix).
"""

from datetime import timedelta, timezone

import frappe

from access_guard.config_utils import (
	atomic_write_json,
	grants_path,
	locked_file,
	read_json,
	used_jti_path,
)
from access_guard.constants import (
	CLOCK_SKEW_LEEWAY_SECONDS,
	GRANTS_CACHE_KEY,
	GRANTS_CACHE_TTL_SECONDS,
)
from access_guard.protocol import TokenReplayError
from access_guard.tokens import parse_iso


def mark_jti_used(jti: str, exp: str) -> None:
	"""Atomically check-and-set. Raises TokenReplayError if already used.

	Locked so two concurrent accept() calls for the same jti can't both
	pass the check before either writes (the actual replay-prevention
	guarantee, not just a convenience wrapper). Also prunes entries whose
	token `exp` (+ clock-skew leeway) has passed, while the lock is already
	held and the file is already being rewritten - a jti can only ever be
	replayed while its grant token still verifies, so once exp has passed it
	is dead weight and there's no need for a separate scheduled cleanup.
	"""
	path = used_jti_path()
	lock_path = path + ".lock"
	with locked_file(lock_path):
		data = read_json(path, default={})
		if jti in data:
			raise TokenReplayError(f"jti already used: {jti}")
		now = frappe.utils.now_datetime().replace(tzinfo=timezone.utc)
		data = {existing_jti: entry for existing_jti, entry in data.items() if not _is_expired(entry, now)}
		data[jti] = {"exp": exp}
		atomic_write_json(path, data)


def _is_expired(entry, now) -> bool:
	exp = entry.get("exp") if isinstance(entry, dict) else None
	if not exp:
		return True  # legacy entry (no exp recorded) or malformed - drop it
	try:
		exp_dt = parse_iso(exp)
	except (ValueError, TypeError):
		return True
	return now > exp_dt + timedelta(seconds=CLOCK_SKEW_LEEWAY_SECONDS)


def _grants_lock_path() -> str:
	return grants_path() + ".lock"


def _sid_map(grants: dict[str, dict]) -> dict[str, str]:
	return {record["sid"]: jti for jti, record in grants.items() if record.get("sid")}


def _refresh_cache(grants: dict[str, dict]) -> None:
	"""Called from inside the file lock only - see module docstring."""
	frappe.cache.set_value(
		GRANTS_CACHE_KEY,
		{"grants": grants, "sid_map": _sid_map(grants)},
		expires_in_sec=GRANTS_CACHE_TTL_SECONDS,
	)


def write_grant(jti: str, record: dict) -> None:
	with locked_file(_grants_lock_path()):
		path = grants_path()
		grants = read_json(path, default={})
		grants[jti] = record
		atomic_write_json(path, grants)
		_refresh_cache(grants)


def read_grant(jti: str) -> dict | None:
	return all_grants().get(jti)


def update_grant(jti: str, **fields) -> dict | None:
	with locked_file(_grants_lock_path()):
		path = grants_path()
		grants = read_json(path, default={})
		record = grants.get(jti)
		if record is None:
			return None
		record.update(fields)
		atomic_write_json(path, grants)
		_refresh_cache(grants)
		return record


def _cached_grants() -> dict:
	"""{"grants": {...}, "sid_map": {...}}, redis-first - see module docstring.

	expires=True: RedisWrapper.get_value's default caches a miss into
	frappe.local.cache, but set_value skips that cache whenever expires_in_sec
	is passed (as _refresh_cache always does) - so a miss here followed by a
	write there would leave frappe.local.cache stuck on a stale None for the
	rest of the process. expires=True avoids frappe.local.cache entirely."""
	cached = frappe.cache.get_value(GRANTS_CACHE_KEY, expires=True)
	if cached is not None:
		return cached

	# Same lock the writers use, so a concurrent writer can't land between
	# this read and this set_value and get clobbered by a stale repopulate.
	with locked_file(_grants_lock_path()):
		grants = read_json(grants_path(), default={})
		_refresh_cache(grants)
		return {"grants": grants, "sid_map": _sid_map(grants)}


def all_grants() -> dict[str, dict]:
	"""jti -> grant record, for every grant currently on disk."""
	return _cached_grants()["grants"]


def delete_grant(jti: str) -> None:
	with locked_file(_grants_lock_path()):
		path = grants_path()
		grants = read_json(path, default={})
		if grants.pop(jti, None) is None:
			return
		atomic_write_json(path, grants)
		_refresh_cache(grants)


def find_grant_by_sid(sid: str) -> tuple[str, dict] | tuple[None, None]:
	"""'Is this session ephemeral?' — frappe.session.sid appears as `sid` in
	some grant record (PROTOCOL.md §6)."""
	cached = _cached_grants()
	jti = cached["sid_map"].get(sid)
	if jti is None:
		return None, None
	return jti, cached["grants"][jti]


def ephemeral_users() -> set[str]:
	"""Namespace filter: only users named in grant records may ever be touched
	by the reaper. Never derived from any DB query — grant records are the
	sole source of truth for "which users are ephemeral"."""
	return {record.get("user") for record in all_grants().values() if record.get("user")}
