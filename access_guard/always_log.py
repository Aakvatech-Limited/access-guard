"""doc_events on_update/on_trash for policy.always_log_doctypes.

Registers an frappe.db.after_commit callback that appends the doc's full
state at commit time — no commit, no log (rolled-back writes aren't
logged); exempt from the request log's size cap. This is the reliable
channel that always knows the doctype, catching a sensitive write even if
it rode a whitelisted *read* method (e.g. a bulk-edit dialog backed by a
"get" call).

log_doc_event() itself already no-ops for non-ephemeral sessions (no jti
maps to the current sid), so this hook is safe to register unconditionally
for every save/delete of a listed doctype.
"""

import frappe

from access_guard.logging_ import log_doc_event
from access_guard.policy import get_policy
from access_guard.protocol import POLICY_ALWAYS_LOG_DOCTYPES


def _is_always_log_doctype(doctype: str) -> bool:
	policy = get_policy()
	return doctype in (policy.get(POLICY_ALWAYS_LOG_DOCTYPES) or [])


def on_update(doc, method=None):
	if not _is_always_log_doctype(doc.doctype):
		return
	try:
		sid = frappe.session.sid
	except Exception:
		return

	def _log():
		log_doc_event(sid, doc.doctype, doc.name, "write", doc.as_dict())

	frappe.db.after_commit.add(_log)


def on_trash(doc, method=None):
	if not _is_always_log_doctype(doc.doctype):
		return
	try:
		sid = frappe.session.sid
	except Exception:
		return

	def _log():
		log_doc_event(sid, doc.doctype, doc.name, "delete", doc.as_dict())

	frappe.db.after_commit.add(_log)
