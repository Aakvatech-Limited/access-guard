"""Deprovisioning: scheduled reaper (~15 min) + on_logout immediate teardown.

Namespace filter: the reaper only ever acts on users named in grant files
(access_guard.grants.ephemeral_users()) — never derived from a DB query, so
a real client user can never be touched even if an attacker tries to shape
a grant file's contents (grant files are guard-written, but this module
treats "is this even still a live user" via frappe.db, not the reverse).

Never talks to Redis directly. Session deletion goes through
`frappe.sessions.delete_session`, which clears both the `tabSessions` DB row
and the corresponding Redis-backed session cache in one call.

Both reap paths (idle-expiry, kill-switch/denylist) share `_reap_users`: per
user, kill the doomed sessions, drop every grant whose sid is then gone, and
delete the User only if none of its grants survived. Keyed per user, not per
grant — two jtis can share one ephemeral `user` (accept() reuses the User row
when the same email accepts again while an earlier grant is live), and
deleting it takes down *all* its sessions. One session query per reap, never
one per grant.
"""

import frappe
from frappe.sessions import delete_session

from access_guard.constants import IDLE_EXPIRY_FALLBACK_SECONDS
from access_guard.grants import all_grants, delete_grant
from access_guard.logging_ import log_session_event
from access_guard.policy import get_policy
from access_guard.protocol import (
	POLICY_ACCESS_DISABLED,
	POLICY_BLACKLISTED_EMAILS,
	POLICY_SESSION_EXPIRY_SECONDS,
)


def _effective_expiry_seconds() -> int:
	"""Idle window before an ephemeral session is killed. Policy-only - Frappe's
	own session middleware separately self-expires sessions past the site-wide
	default on every request.

	0/unset falls back to IDLE_EXPIRY_FALLBACK_SECONDS rather than meaning
	"never expire": Frappe's `reqd` doesn't reject 0 on an Int field, so an
	operator can save it (or a mis-seeded install can leave it), and treating
	that as "off" left ephemeral System Manager sessions alive for Frappe's
	site-wide default of 10 days - with the User row never deleted at all."""
	policy = get_policy()
	return int(policy.get(POLICY_SESSION_EXPIRY_SECONDS) or 0) or IDLE_EXPIRY_FALLBACK_SECONDS


def _live_sessions_for_users(users) -> dict[str, list[dict]]:
	"""{user: [{sid, lastupdate}, ...]} in one query - a kill-switch tick can
	cover every grant on the site, so per-user lookups would be N+1."""
	by_user: dict[str, list[dict]] = {user: [] for user in users}
	if not by_user:
		return by_user
	sessions = frappe.qb.DocType("Sessions")
	rows = (
		frappe.qb.from_(sessions)
		.select(sessions.user, sessions.sid, sessions.lastupdate)
		.where(sessions.user.isin(list(by_user)))
		.run(as_dict=True)
	)
	for row in rows:
		by_user[row["user"]].append(row)
	return by_user


def _grants_by_user(grants: dict[str, dict]) -> dict[str, list[str]]:
	"""{user: [jti, ...]}. Grants with no `user` are skipped - _reap_users
	handles those separately (no session/User to touch)."""
	by_user: dict[str, list[str]] = {}
	for jti, record in grants.items():
		if record.get("user"):
			by_user.setdefault(record["user"], []).append(jti)
	return by_user


def _is_idle_expired(lastupdate, expiry_seconds: int) -> bool:
	if not lastupdate:
		return False
	idle_for = frappe.utils.time_diff_in_seconds(frappe.utils.now_datetime(), lastupdate)
	return idle_for > expiry_seconds


def reap_idle_sessions() -> None:
	"""scheduler_event, ~15 min. Kills every ephemeral session idle beyond the
	effective expiry, then reaps the grants left without a live session.

	Note there is no "idle-expiry disabled" early return: reaping a grant whose
	session is already gone must happen regardless of how the idle window is
	configured, or a stale grant + its System Manager User row live forever.
	_effective_expiry_seconds() falls back to a sane window rather than 0."""
	expiry_seconds = _effective_expiry_seconds()

	def is_idle(row):
		return _is_idle_expired(row["lastupdate"], expiry_seconds)

	_reap_users(all_grants(), doomed=is_idle, reason="idle_expired")


def reap_disabled_and_blacklisted() -> None:
	"""Called right after a policy is (re)verified — both on the guest-allowed
	push (`receive_policy`) and the guaranteed hourly pull (`sync_hourly`) —
	so a kill-switch or blacklist takes effect immediately, not just at the
	next idle-expiry tick. Unlike reap_idle_sessions, ignores idle state
	entirely: a matching grant is reaped regardless of its last activity."""
	policy = get_policy()
	# Hub unions two distinct causes (explicit admin blacklist row, or the
	# hub-side User simply being disabled) into this one flat email list
	# (access_hub_settings.as_policy_dict) - can't tell which applied here,
	# so the reason logged below is deliberately neutral rather than
	# claiming "blacklisted" for what might just be an inactive user.
	denylisted = set(policy.get(POLICY_BLACKLISTED_EMAILS) or [])
	disabled = bool(policy.get(POLICY_ACCESS_DISABLED))
	if not disabled and not denylisted:
		return

	matched = {
		jti: record
		for jti, record in all_grants().items()
		if disabled or record.get("user_email") in denylisted
	}
	reason = "access_disabled" if disabled else "policy_denied"
	_reap_users(matched, doomed=lambda row: True, reason=reason)


def _reap_users(grants: dict[str, dict], *, doomed, reason: str) -> None:
	"""Kill each session `doomed(row)` selects, then reap every grant whose own
	sid is no longer live, deleting the shared User once the last of its grants
	goes. One session query for all users, none per grant."""
	grants_by_user = _grants_by_user(grants)
	sessions_by_user = _live_sessions_for_users(grants_by_user)

	for user, jtis in grants_by_user.items():
		live_sids = {row["sid"] for row in sessions_by_user[user]}
		# Belt-and-suspenders: only touch users the grant namespace vouches for.
		is_safe = _is_ephemeral_namespace_safe(user)
		if is_safe:
			for row in sessions_by_user[user]:
				if doomed(row):
					delete_session(sid=row["sid"], user=user, reason=f"access_guard: {reason}")
					live_sids.discard(row["sid"])

		# Grants whose sid is now gone are done; siblings with a live sid keep
		# the User alive, so it's only deleted once every grant qualifies.
		reaped = [jti for jti in jtis if grants[jti].get("sid") not in live_sids]
		_reap_grants(reaped, reason=reason, user=user if is_safe and len(reaped) == len(jtis) else None)

	# No `user` means no session/User to touch, just a stale record to drop.
	_reap_grants([jti for jti, r in grants.items() if not r.get("user")], reason=reason, user=None)


def _reap_grants(jtis: list[str], *, reason: str, user: str | None) -> None:
	"""Drop each grant, then `user` (if given) once they're all gone - in
	that order, since User.on_trash re-fires on_logout -> teardown_on_logout,
	and the recursive call needs the grant already gone to no-op instead of
	looping forever. Events log after, so a failed cleanup can't claim a
	logout that didn't happen."""
	for jti in jtis:
		delete_grant(jti)
	if user and frappe.db.exists("User", user):
		frappe.delete_doc("User", user, force=True, ignore_permissions=True)
		frappe.db.commit()
	for jti in jtis:
		log_session_event(jti, "logout", reason=reason)


def _is_ephemeral_namespace_safe(user: str) -> bool:
	"""True only if `user` is named in a grant file - never trust a caller's
	own idea of "is this ephemeral"."""
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

	# `!= sid`: this session is still in tabSessions (core deletes it after
	# this hook) but is on its way out, so it shouldn't count as keeping the
	# User alive - any other live session (sibling grant or not) should.
	user = record.get("user")
	keep_user = not user or not _is_ephemeral_namespace_safe(user)
	if not keep_user:
		keep_user = any(row["sid"] != sid for row in _live_sessions_for_users([user])[user])
	_reap_grants([jti], reason="user_logout", user=None if keep_user else user)
