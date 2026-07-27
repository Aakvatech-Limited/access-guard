"""before_request / after_request hooks: log every whitelisted call for an
ephemeral session (PROTOCOL.md §7), minus READ_SKIP_METHODS when
policy.log_reads is off. Fail-open to logging: anything not on the
read-skip list is logged, no separate write-list, no reliance on
frappe.db.transaction_writes (unreliable per DESIGN.md).
"""

import frappe

from access_guard.logging_ import log_request


def _resolve_method_name() -> str | None:
	cmd = frappe.form_dict.get("cmd")
	if cmd:
		return cmd
	path = getattr(frappe.request, "path", "") or ""
	prefix = "/api/method/"
	if path.startswith(prefix):
		return path[len(prefix) :]
	return None


def _current_sid() -> str | None:
	try:
		return frappe.session.sid
	except Exception:
		return None


def before_request():
	method = _resolve_method_name()
	if not method:
		return
	sid = _current_sid()
	if not sid:
		return
	frappe.local.access_guard_request_method = method
	log_request(sid, method, "attempt", dict(frappe.form_dict))


def after_request(response=None):
	method = getattr(frappe.local, "access_guard_request_method", None)
	if not method:
		return
	sid = _current_sid()
	if not sid:
		return
	status = "ok"
	try:
		code = getattr(response, "status_code", None)
		if code and code >= 400:
			status = "error"
	except Exception:
		pass
	log_request(sid, method, status, dict(frappe.form_dict))
