"""after_request hook: log every whitelisted call for an ephemeral session
(PROTOCOL.md §7), one line per call. No before_request hook - frappe.request
and frappe.session are still the same live objects by the time after_request
runs (frappe.destroy() happens later, after the response is sent), so
there's nothing to stash ahead of time. Safe HTTP verbs (GET/HEAD/OPTIONS)
are skipped unless policy.log_reads is on — a mutating user action always
arrives via an unsafe verb, so this is a reliable, version-proof signal (no
per-endpoint denylist, no reliance on frappe.db.transaction_writes).
"""

import json

import frappe

from access_guard.logging_ import log_request


def _http_method() -> str:
	return getattr(frappe.request, "method", "") or ""


def _resolve_path() -> str | None:
	"""cmd= RPC calls and /api/method/<x> both resolve to the whitelisted
	method name itself, logged under the same `path` field; anything else
	(desk page loads, /api/resource/..., etc.) falls back to the raw request
	path, so those requests still get logged instead of silently skipped."""
	cmd = frappe.form_dict.get("cmd")
	if cmd:
		return cmd
	path = getattr(frappe.request, "path", "") or ""
	prefix = "/api/method/"
	if path.startswith(prefix):
		return path[len(prefix) :]
	return path or None


def _current_sid() -> str | None:
	try:
		return frappe.session.sid
	except Exception:
		return None


def _request_params() -> dict:
	"""Query args + form-encoded fields, read straight from frappe.request,
	not frappe.form_dict - form_dict is mutable process-global state a
	whitelisted handler could have already altered by the time we read it,
	which isn't trustworthy for an audit log."""
	params: dict = {}
	try:
		params.update(frappe.request.args or {})
		params.update(frappe.request.form or {})
	except Exception:
		pass
	return params


def _request_body():
	"""The raw request body, kept separate from _request_params() - folding
	it into the same dict (e.g. under a "body" key) risks colliding with an
	actual query/form field of that name and silently clobbering one or the
	other. Parsed as JSON when request.is_json (Frappe's own make_form_dict
	uses the same signal) says the content-type actually is JSON; otherwise
	logged as the raw string as-is (still truncated, just not structured) -
	a non-JSON body is not silently dropped just because it can't be parsed."""
	try:
		raw = frappe.request.get_data(as_text=True)
	except Exception:
		return None
	if not raw:
		return None
	try:
		if frappe.request.is_json:
			return json.loads(raw)
	except Exception:
		pass
	return raw


def after_request(response=None):
	path = _resolve_path()
	if not path:
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

	log_request(sid, path, _http_method(), status, code, _request_params(), _request_body())
