"""Session guard: is-this-ephemeral? + deny/warn enforcement + doc-change
logging, all in one pass per doc event.

The ephemeral user has System Manager, so DB permissions can't gate
anything (DESIGN.md "Enforcement mechanics") — enforcement is entirely
guard *code*, hooked via doc_events["*"] (wildcard — policy rules are not
scoped to a fixed doctype list) and keyed on whether the current session's
sid appears in a grant file. Policy is read from the file, never the DB.

Logging a doc change (full state, at commit) is decided in the same pass:
either a matching warn rule, or the doctype being in always_log_doctypes -
one after_commit log line either way, never both, and now covers
submit/cancel too (not just write/delete).
"""

import frappe

from access_guard.grants import find_grant_by_sid
from access_guard.logging_ import log_doc_event
from access_guard.policy import enforce, get_policy
from access_guard.protocol import MODE_DENY, MODE_WARN, POLICY_ALWAYS_LOG_DOCTYPES, PolicyDeniedError


def _current_ephemeral_jti() -> str | None:
	try:
		sid = frappe.session.sid
	except Exception:
		return None
	if not sid:
		return None
	jti, _record = find_grant_by_sid(sid)
	return jti


def is_ephemeral_session() -> bool:
	return _current_ephemeral_jti() is not None


def _enforce_for_doc(doc, action: str) -> None:
	jti = _current_ephemeral_jti()
	if jti is None:
		return  # not an ephemeral session -> policy does not apply

	mode = enforce(doc.doctype, action)

	if mode == MODE_DENY:
		# Nothing commits on a deny, so log the attempt now rather than via
		# after_commit (there's no commit coming).
		log_doc_event(frappe.session.sid, doc.doctype, doc.name, f"denied:{action}", doc.as_dict())
		frappe.throw(
			frappe._(
				"This operation ({0} on {1}) is blocked for monitored sessions by access policy."
			).format(action, doc.doctype),
			exc=PolicyDeniedError,
		)
		return

	if mode == MODE_WARN:
		frappe.msgprint(
			frappe._("This is a sensitive operation on a client account and will be recorded."),
			indicator="orange",
			alert=True,
		)

	always_log = doc.doctype in (get_policy().get(POLICY_ALWAYS_LOG_DOCTYPES) or [])
	if mode == MODE_WARN or always_log:
		_register_after_commit_log(doc, action, jti)


def _register_after_commit_log(doc, action: str, jti: str) -> None:
	sid = frappe.session.sid

	def _log():
		log_doc_event(sid, doc.doctype, doc.name, action, doc.as_dict())

	frappe.db.after_commit.add(_log)


def before_validate(doc, method=None):
	"""doc_events['*']['before_validate'] — fires for create/write and
	submit (docstatus is already Submitted by then, hence the branch below),
	but not cancel - before_cancel handles that. Unlike validate(), this
	still runs when the caller passed ignore_validate=True."""
	if doc.docstatus.is_submitted():
		action = "submit"
	else:
		action = "create" if doc.is_new() else "write"
	_enforce_for_doc(doc, action)


def before_cancel(doc, method=None):
	_enforce_for_doc(doc, "cancel")


def on_trash(doc, method=None):
	_enforce_for_doc(doc, "delete")
