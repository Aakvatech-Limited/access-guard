"""Deprovisioning: scheduled reaper (~15 min) + on_logout immediate teardown.

Namespace filter: the reaper only ever acts on users named in grant files
(access_guard.grants.ephemeral_users()) — never derived from a DB query, so
a real client user can never be touched even if an attacker tries to shape
a grant file's contents (grant files are guard-written, but this module
treats "is this even still a live user" via frappe.db, not the reverse).

Never talks to Redis directly. Session deletion goes through
`frappe.sessions.delete_session`, which clears both the `tabSessions` DB row
and the corresponding Redis-backed session cache in one call.
"""

import frappe
from frappe.sessions import delete_session, get_expiry_in_seconds

from access_guard.grants import all_grants, delete_grant
from access_guard.hub_client import report_provisioning
from access_guard.logging_ import log_session_event
from access_guard.policy import get_policy
from access_guard.protocol import (
	POLICY_ACCESS_DISABLED,
	POLICY_BLACKLISTED_EMAILS,
	POLICY_SESSION_EXPIRY_SECONDS,
)


def _effective_expiry_seconds() -> int:
	policy = get_policy()
	policy_expiry = int(policy.get(POLICY_SESSION_EXPIRY_SECONDS) or 0)
	site_expiry = get_expiry_in_seconds()
	if policy_expiry <= 0:
		return site_expiry
	return min(policy_expiry, site_expiry)


def _live_sessions_for_user(user: str) -> list[dict]:
	sessions = frappe.qb.DocType("Sessions")
	rows = (
		frappe.qb.from_(sessions)
		.select(sessions.sid, sessions.lastupdate)
		.where(sessions.user == user)
		.run(as_dict=True)
	)
	return rows


def _is_idle_expired(lastupdate, expiry_seconds: int) -> bool:
	if not lastupdate:
		return False
	idle_for = frappe.utils.time_diff_in_seconds(frappe.utils.now_datetime(), lastupdate)
	return idle_for > expiry_seconds


def reap_idle_sessions() -> None:
	"""scheduler_event, ~15 min. For each ephemeral session idle beyond the
	effective expiry, kill it; once a grant's user has zero live sessions,
	delete the user and report "reaped"."""
	expiry_seconds = _effective_expiry_seconds()
	grants = all_grants()

	for jti, record in grants.items():
		user = record.get("user")
		sid = record.get("sid")
		if not user:
			continue

		live_sessions = _live_sessions_for_user(user)
		live_sids = {row["sid"] for row in live_sessions}

		for row in live_sessions:
			if _is_idle_expired(row["lastupdate"], expiry_seconds):
				delete_session(sid=row["sid"], user=user, reason="access_guard: idle expiry")
				live_sids.discard(row["sid"])
				if row["sid"] == sid:
					log_session_event(jti, "logout", reason="idle_expired")

		if not live_sids:
			_reap_user(jti, record)


def reap_disabled_and_blacklisted() -> None:
	"""Called right after a policy is (re)verified — both on the guest-allowed
	push (`receive_policy`) and the guaranteed hourly pull (`sync_hourly`) —
	so a kill-switch or blacklist takes effect immediately, not just at the
	next idle-expiry tick. Unlike reap_idle_sessions, ignores idle state
	entirely: a matching grant is reaped regardless of its last activity."""
	policy = get_policy()
	blacklist = set(policy.get(POLICY_BLACKLISTED_EMAILS) or [])
	disabled = bool(policy.get(POLICY_ACCESS_DISABLED))
	if not disabled and not blacklist:
		return

	for jti, record in all_grants().items():
		if disabled or record.get("emp_email") in blacklist:
			_reap_now(jti, record, reason="access_disabled" if disabled else "blacklisted")


def _reap_now(jti: str, record: dict, *, reason: str) -> None:
	user = record.get("user")
	# Belt-and-suspenders, same as _reap_user: `user` comes from a grant
	# record, which accept() only ever writes for an ephemeral user (a
	# standing-user collision raises EphemeralUserCollisionError before any
	# grant is written) - re-checking here means a future refactor can't
	# accidentally kill sessions for an arbitrary/non-ephemeral user.
	if user and _is_ephemeral_namespace_safe(user):
		for row in _live_sessions_for_user(user):
			delete_session(sid=row["sid"], user=user, reason=f"access_guard: {reason}")
	log_session_event(jti, "logout", reason=reason)
	_reap_user(jti, record)


def _reap_user(jti: str, record: dict) -> None:
	"""Deletes the grant BEFORE the User, not after: User.on_trash calls
	login_manager.logout(), which re-fires on_logout -> teardown_on_logout
	-> this function again. Without the grant gone first, that recursed
	indefinitely (User still "exists" by the time find_grant_by_sid ran, so
	it deleted itself again, forever). With the grant gone first, the
	recursive call's find_grant_by_sid returns nothing and no-ops.
	"""
	user = record.get("user")
	is_safe = user and _is_ephemeral_namespace_safe(user)
	delete_grant(jti)
	if is_safe and frappe.db.exists("User", user):
		frappe.delete_doc("User", user, force=True, ignore_permissions=True)
		frappe.db.commit()
	log_session_event(jti, "logout", reason="reaped")
	report_provisioning(jti=jti, event="reaped", user=user)


def _is_ephemeral_namespace_safe(user: str) -> bool:
	"""Extra belt-and-suspenders check: the user we're about to delete must
	actually be present in the grant-file-derived namespace (it is, by
	construction, since we only ever get here from a grant record) — this
	function exists so a future refactor can't accidentally call _reap_user
	on an arbitrary user without going through the namespace filter."""
	from access_guard.grants import ephemeral_users

	return user in ephemeral_users()


def teardown_on_logout(login_manager=None) -> None:
	"""on_logout hook. Frappe calls this as
	`frappe.call(fn, login_manager=self)` (see LoginManager.run_trigger),
	*before* the session row is deleted by the core logout flow — so
	frappe.session.sid is still the outgoing session's sid at this point.
	Immediate teardown so an early-finished session doesn't linger until
	the next reaper tick. Records the logout reason.
	"""
	from access_guard.grants import find_grant_by_sid

	try:
		sid = frappe.session.sid
	except Exception:
		sid = None
	if not sid:
		return

	jti, record = find_grant_by_sid(sid)
	if jti is None:
		return  # not an ephemeral session

	log_session_event(jti, "logout", reason="user_logout")

	remaining = [row for row in _live_sessions_for_user(record.get("user")) if row["sid"] != sid]
	if not remaining:
		_reap_user(jti, record)
