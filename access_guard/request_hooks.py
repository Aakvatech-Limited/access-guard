"""before_request / after_request hooks: log every whitelisted call for an
ephemeral session (PROTOCOL.md §7), one line per call written from
after_request (before_request only stashes what's needed — there is no
separate "attempt" line). Safe HTTP verbs (GET/HEAD/OPTIONS) are skipped
unless policy.log_reads is on — a mutating user action always arrives via
an unsafe verb, so this is a reliable, version-proof signal (no per-endpoint
denylist, no reliance on frappe.db.transaction_writes).
"""

import frappe

from access_guard.logging_ import log_request


def _http_method() -> str:
	return getattr(frappe.request, "method", "") or ""


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


def _request_body() -> str:
	try:
		return frappe.request.get_data(as_text=True) or ""
	except Exception:
		return ""


def before_request():
	method = _resolve_method_name()
	if not method:
		return
	if not _current_sid():
		return
	frappe.local.access_guard_request_method = method
	frappe.local.access_guard_request_http_method = _http_method()
	frappe.local.access_guard_request_body = _request_body()


def after_request(response=None):
	method = getattr(frappe.local, "access_guard_request_method", None)
	if not method:
		return
	sid = _current_sid()
	if not sid:
		return

	code = None
	status = "ok"
	try:
		code = getattr(response, "status_code", None)
		if code and code >= 400:
			status = "error"
	except Exception:
		pass

	http_method = getattr(frappe.local, "access_guard_request_http_method", "")
	body = getattr(frappe.local, "access_guard_request_body", "")
	log_request(sid, method, http_method, status, code, body)
