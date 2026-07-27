"""boot_session hook: stamp bootinfo with an "am I ephemeral?" flag,
derived from the grant file — never a DB flag (DESIGN.md "Monitoring
notice on client sites"). The notice text itself is static in v1 (see
access_guard/public/js/monitoring_notice.js) — not hub-configurable."""

import hashlib

import frappe

from access_guard.grants import find_grant_by_sid


def boot_session(bootinfo):
	try:
		sid = frappe.session.sid
	except Exception:
		sid = None

	jti, _record = (None, None) if not sid else find_grant_by_sid(sid)
	bootinfo.access_guard_ephemeral = bool(jti)
	if jti:
		# md5(sid), not the raw sid — client only needs a stable per-login
		# dedup key, not the actual session id.
		bootinfo.access_guard_login_hash = hashlib.md5(sid.encode()).hexdigest()
