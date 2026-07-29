"""Whitelisted endpoints — access_guard.api.<fn> (PROTOCOL.md §5).

accept          allow_guest=True   the grant token redemption path
receive_policy  allow_guest=True   best-effort policy push from the hub
"""

import frappe

from access_guard.config_utils import get_guard_conf
from access_guard.grants import mark_jti_used, write_grant
from access_guard.logging_ import log_session_event
from access_guard.policy import get_policy, store_verified_policy
from access_guard.protocol import (
	CLAIM_JTI,
	CLAIM_USER_EMAIL,
	CLAIM_USER_FIRST_NAME,
	CLAIM_USER_LAST_NAME,
	CLAIM_USER_MIDDLE_NAME,
	POLICY_DISALLOW_SIMULTANEOUS_SESSIONS,
	POLICY_NAME_SUFFIX,
	AccessProtocolError,
	EphemeralUserCollisionError,
	TokenAudienceError,
	TokenMalformedError,
	transport_token_hash,
	utc_iso,
)
from access_guard.tokens import verify_hub_token


def _respond_with_error(exc: AccessProtocolError) -> None:
	frappe.local.response["http_status_code"] = exc.http_status
	frappe.local.response.update(exc.as_response())
	# Whitelisted method handlers can `return` after calling this; nothing
	# else should be set on frappe.local.response for this request.


def _ingest_api(fn):
	"""Drop-in replacement for `@frappe.whitelist(allow_guest=True)` on every
	hub-signed access_guard endpoint (PROTOCOL.md §5: accept, receive_policy,
	and any future one). Mirrors access_hub.api.ingest_endpoint: verifies the
	incoming `token` itself (steps 1-4 of PROTOCOL.md §3 — parse, signature,
	pv, exp) via verify_hub_token, then calls the handler with the decoded
	claims dict rather than the raw token — handlers never re-verify. Any
	AccessProtocolError raised anywhere in the call — token verification, the
	handler itself — is caught exactly once and turned into the standard
	error response, instead of every handler repeating its own try/except.

	The wire field is always named `token` — both endpoints use this same
	name (receive_policy included; the hub posts {"token": ...} to it, not
	{"policy_token": ...}) so there's exactly one call convention, not one
	per endpoint.

	Handlers should take `claims` as their only argument, `raise` the
	appropriate AccessProtocolError subclass for any further (endpoint-
	specific) verification, and return their normal success value.
	"""

	@frappe.whitelist(allow_guest=True)
	def wrapper(token: str | None = None):
		try:
			claims = verify_hub_token(token)
			return fn(claims)
		except AccessProtocolError as e:
			_respond_with_error(e)
			return None

	return wrapper


@_ingest_api
def accept(claims: dict):
	"""Grant acceptance endpoint. _ingest_api has already done PROTOCOL.md §3
	steps 1-4 (parse, signature, pv, exp); this does the remaining
	grant-specific steps 5-6 (aud, jti-replay), then provisions the
	ephemeral user + session and redirects into desk.

	Any AccessProtocolError raised here is turned into the standard error
	response by the @_ingest_api decorator — just raise and return.
	"""
	# aud == transport_token_hash(local token)
	expected_aud = transport_token_hash(frappe.conf["access_guard_transport_token"])
	if claims.get("aud") != expected_aud:
		raise TokenAudienceError("grant token audience does not match this client")

	# jti replay (file-backed; check-and-set is atomic)
	jti = claims.get(CLAIM_JTI)
	if not jti:
		raise TokenMalformedError("missing jti claim")
	mark_jti_used(jti, exp=claims.get("exp"))

	user_email = claims.get(CLAIM_USER_EMAIL)
	first_name = claims.get(CLAIM_USER_FIRST_NAME)
	middle_name = claims.get(CLAIM_USER_MIDDLE_NAME)
	last_name = claims.get(CLAIM_USER_LAST_NAME)
	if not user_email:
		raise TokenMalformedError("missing user_email claim")

	# Everything from here on is trusted (the token verified above), so the
	# rest of provisioning — user create/reuse, policy read, grant write —
	# runs as Administrator rather than Guest (allow_guest=True means
	# frappe.session.user is still "Guest" at this point). _start_session
	# below performs the real login and moves frappe.session.user off
	# Administrator onto the ephemeral user itself, so there's no separate
	# "restore" step needed — the Administrator window ends exactly where
	# the real session begins. (Deliberate: created-by-Guest audit stamps
	# and any User-controller logic keyed on frappe.session.user are both
	# wrong outcomes we don't want, not just a permission check to bypass.)
	frappe.set_user("Administrator")

	policy = get_policy()
	user = _create_or_reuse_ephemeral_user(
		user_email,
		first_name,
		middle_name,
		last_name,
		policy.get(POLICY_NAME_SUFFIX),
		disallow_simultaneous=bool(policy.get(POLICY_DISALLOW_SIMULTANEOUS_SESSIONS)),
	)
	# Written after login, sid already known - see session_guard.py for the
	# narrow gap this leaves during post_login() itself.
	_start_session(user)
	sid = frappe.session.sid

	issued_at = utc_iso()  # grant file, not a DocType -> UTC
	# Grant file before the commit: an orphan grant file is harmless (the reaper
	# collects it), a committed session with no grant file is unenforceable by
	# session_guard and invisible to the reaper.
	write_grant(
		jti,
		{
			"jti": jti,
			"pv": claims.get("pv"),
			"user_name": " ".join(p for p in (first_name, middle_name, last_name) if p),
			"user_email": user_email,
			"user": user,
			"sid": sid,
			"issued_at": issued_at,
		},
	)
	# Explicit: accept() is a GET (redirectable link), and sync_database() only
	# commits on unsafe verbs - the user row and session would be rolled back.
	frappe.db.commit()
	log_session_event(jti, "login")

	# Land where Frappe's own post-login would for a system user: the
	# configured default app (system/user default_app), falling back to /app.
	# get_default_path reads frappe.session.user, set by _start_session above.
	from frappe.apps import get_default_path

	frappe.local.response["type"] = "redirect"
	frappe.local.response["location"] = get_default_path() or "/app"


def _create_or_reuse_ephemeral_user(
	user_email: str,
	first_name: str | None,
	middle_name: str | None,
	last_name: str | None,
	name_suffix: str,
	disallow_simultaneous: bool,
):
	"""Idempotent create keyed on user_email. first_name/middle_name/last_name
	come straight from the hub's User record (protocol claims), not a
	re-split full name - re-splitting a joined string loses middle names and
	mangles multi-word first/last names. full_name is generated by Frappe
	from first_name/last_name, so the hub-configured name suffix is appended
	to last_name -> e.g. "John Doe (consultant)". name_suffix may be blank
	(policy.name_suffix is optional) -> no trailing parens, last_name is left
	as-is. Caller (accept) has already switched to Administrator before
	calling this — no ignore_permissions needed, and owner/modified_by are
	correctly stamped Administrator, not Guest.

	simultaneous_sessions is set from the current policy on every call, reuse
	included - not just at first creation - so a later policy change actually
	takes effect for a user who requests access again, rather than freezing
	whatever was true the first time this email was provisioned. Safe to
	change on an already-live reused user: Frappe only enforces the cap
	(get_sessions_to_clear's offset logic, frappe/sessions.py) when a NEW
	session is created, which is exactly what this reuse path is about to do
	via _start_session - it doesn't retroactively evict anything before that.

	Reuse is only safe for a user THIS guard provisioned. If the email already
	belongs to a standing (non-ephemeral) user, refuse — handing them a fresh
	System Manager session is exactly the standing-access abuse we prevent.
	Ephemeral membership is grant-file-derived (ephemeral_users()), never a DB
	flag: a User row exists iff a live grant names them (the reaper deletes both
	together), so this is the authoritative test."""
	# Frappe's get_sessions_to_clear falls back to 1 on a falsy value (`or 1`),
	# so 0 does NOT mean unlimited here - it's as restrictive as 1. There's no
	# real "unlimited" sentinel in core, so "off" uses a large-enough cap
	# instead of relying on that.
	simultaneous_sessions = 1 if disallow_simultaneous else 100

	if frappe.db.exists("User", user_email):
		from access_guard.grants import ephemeral_users

		if user_email not in ephemeral_users():
			raise EphemeralUserCollisionError(
				f"{user_email} is already a standing user on this site; refusing to "
				"start an ephemeral session for it."
			)
		frappe.db.set_value("User", user_email, "simultaneous_sessions", simultaneous_sessions)
		return user_email

	last_name = last_name or ""
	suffix = f"({name_suffix})" if name_suffix else ""
	suffixed_last_name = f"{last_name} {suffix}".strip() if last_name else suffix

	user_doc = frappe.new_doc("User")
	user_doc.email = user_email
	user_doc.first_name = first_name or user_email
	user_doc.middle_name = middle_name
	user_doc.last_name = suffixed_last_name
	user_doc.send_welcome_email = 0
	user_doc.enabled = 1
	user_doc.user_type = "System User"
	user_doc.simultaneous_sessions = simultaneous_sessions
	user_doc.insert()
	from frappe.core.doctype.user.user import get_all_roles

	user_doc.add_roles(*get_all_roles())
	return user_doc.name


def _start_session(user: str) -> None:
	"""Programmatic login, following the pattern used by
	frappe/integrations/doctype/ldap_settings for a verified-out-of-band
	identity: assign login_manager.user directly and run post_login().
	"""
	frappe.local.login_manager.user = user
	frappe.local.login_manager.post_login()


@_ingest_api
def receive_policy(claims: dict):
	"""Best-effort policy push from the hub. Authenticated entirely by the
	policy token's own signature (PROTOCOL.md §4, already verified by
	_ingest_api) — no transport token needed, since anyone who could forge
	this token could forge anything.
	"""
	from access_guard.reaper import reap_disabled_and_blacklisted

	store_verified_policy(claims)
	reap_disabled_and_blacklisted()
	return {"ok": True}
