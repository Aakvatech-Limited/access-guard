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
	PRUNE_MARGIN_SECONDS,
)
from access_guard.protocol import TokenReplayError, parse_iso, utc_now


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
		# utc_now(), never now_datetime().replace(tzinfo=utc) - that mislabels
		# naive *system-local* time as UTC, so this prune ran on a different
		# clock than _check_exp's real-UTC accept test. Where they disagreed,
		# a still-verifiable jti could be pruned and its token replayed.
		now = utc_now()
		data = {existing_jti: entry for existing_jti, entry in data.items() if not _is_expired(entry, now)}
		data[jti] = {"exp": exp}
		atomic_write_json(path, data)


def _is_expired(entry, now) -> bool:
	"""Is this used-jti entry safe to forget? Deliberately a STRICTLY LATER
	bound than tokens._check_exp's accept test (same exp + leeway, plus
	PRUNE_MARGIN_SECONDS): forgetting a jti whose token still verifies would
	make that token redeemable a second time. The margin means the two can't
	flip order even if their clocks drift slightly."""
	exp = entry.get("exp") if isinstance(entry, dict) else None
	if not exp:
		return True  # legacy entry (no exp recorded) or malformed - drop it
	try:
		exp_dt = parse_iso(exp)
	except (ValueError, TypeError):
		return True
	dead_at = exp_dt + timedelta(seconds=CLOCK_SKEW_LEEWAY_SECONDS + PRUNE_MARGIN_SECONDS)
	return now > dead_at


def _grants_lock_path() -> str:
	return grants_path() + ".lock"


def _sid_map(grants: dict[str, dict]) -> dict[str, str]:
	return {record["sid"]: jti for jti, record in grants.items() if record.get("sid")}


def _user_map(grants: dict[str, dict]) -> dict[str, str]:
	"""user -> jti. Several grants can name one user (accept() reuses the User
	row on re-request), so the newest issued_at wins - all of them answer "is
	this user ephemeral" identically, and the newest is the live one."""

	def issued(jti):
		return grants[jti].get("issued_at") or ""

	by_user: dict[str, str] = {}
	for jti, record in grants.items():
		user = record.get("user")
		if not user:
			continue
		if user not in by_user or issued(jti) > issued(by_user[user]):
			by_user[user] = jti
	return by_user


def _refresh_cache(grants: dict[str, dict]) -> None:
	"""Called from inside the file lock only - see module docstring."""
	frappe.cache.set_value(
		GRANTS_CACHE_KEY,
		{"grants": grants, "sid_map": _sid_map(grants), "user_map": _user_map(grants)},
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
	"""{"grants": ..., "sid_map": ..., "user_map": ...}, redis-first - see
	module docstring.

	expires=True: RedisWrapper.get_value's default caches a miss into
	frappe.local.cache, but set_value skips that cache whenever expires_in_sec
	is passed (as _refresh_cache always does) - so a miss here followed by a
	write there would leave frappe.local.cache stuck on a stale None for the
	rest of the process. expires=True avoids frappe.local.cache entirely."""
	cached = frappe.cache.get_value(GRANTS_CACHE_KEY, expires=True)
	# A cached blob from a build before user_map existed would KeyError in
	# current_grant's user lookup - i.e. fail open on an upgrade. Treat it as a
	# miss.
	if cached is not None and "user_map" in cached:
		return cached

	# Same lock the writers use, so a concurrent writer can't land between
	# this read and this set_value and get clobbered by a stale repopulate.
	with locked_file(_grants_lock_path()):
		grants = read_json(grants_path(), default={})
		_refresh_cache(grants)
		return {"grants": grants, "sid_map": _sid_map(grants), "user_map": _user_map(grants)}


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


def _lookup(cached: dict, map_key: str, value: str) -> tuple[str, dict] | tuple[None, None]:
	if not value:
		return None, None
	jti = cached[map_key].get(value)
	if jti is None:
		return None, None
	return jti, cached["grants"][jti]


def find_grant_by_sid(sid: str) -> tuple[str, dict] | tuple[None, None]:
	"""'Is this exact session ephemeral?' — `sid` appears as some grant's `sid`
	(PROTOCOL.md §6). Narrower than current_grant(): use that one to decide
	whether policy applies, since a background job has no real sid."""
	return _lookup(_cached_grants(), "sid_map", sid)


def current_grant() -> tuple[str, dict] | tuple[None, None]:
	"""The grant the current execution context acts under - the single test for
	"does policy apply here?".

	sid first: in a real request it names the exact session that acted, which
	matters when one ephemeral user holds several grants (accept() reuses the
	User row on re-request).

	User second, because sid is not always a sid. frappe.set_user() overwrites
	session.sid with the *username*, and background_jobs.execute_job calls it -
	so in any worker a sid-only test finds nothing and enforcement fails OPEN.
	That covers bulk delete (>10 docs), bulk update/submit/cancel (>=20), queued
	submit, rename with enqueue=True and Data Import, all reachable from the
	stock desk UI. The user survives all of them."""
	session = getattr(frappe.local, "session", None)
	if not session:
		return None, None

	# One _cached_grants() for both lookups: this runs on nearly every request,
	# and the two maps come out of the same blob anyway.
	cached = _cached_grants()

	jti, record = _lookup(cached, "sid_map", session.get("sid"))
	if jti is not None:
		return jti, record

	return _lookup(cached, "user_map", session.get("user"))


def ephemeral_users() -> set[str]:
	"""Namespace filter: only users named in grant records may ever be touched
	by the reaper. Never derived from any DB query — grant records are the
	sole source of truth for "which users are ephemeral"."""
	return {record.get("user") for record in all_grants().values() if record.get("user")}
