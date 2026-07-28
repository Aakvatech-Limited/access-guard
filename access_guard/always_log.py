"""doc_events on_update/on_trash for policy.always_log_doctypes.

Registers an frappe.db.after_commit callback that appends the doc's full
state at commit time — no commit, no log (rolled-back writes aren't
logged); exempt from the request log's size cap. This is the reliable
channel that always knows the doctype, catching a sensitive write even if
it rode a whitelisted *read* method (e.g. a bulk-edit dialog backed by a
"get" call).

Registered for doctype "*" (every save/delete on the site, not just
ephemeral sessions - e.g. Administrator edits, the scheduler, even
frappe.log_error()'s own Error Log insert). get_policy() can raise (no
default policy to fall back to) and pull-and-verify synchronously on a
cache miss, so it must never run for a request that isn't even a granted
session - check find_grant_by_sid FIRST (cheap, local, can't recurse) and
only touch policy once we know this is a real ephemeral session, which by
construction already has a policy cached (accept() pulls one before a
grant can exist).
"""

import frappe

from access_guard.grants import find_grant_by_sid
from access_guard.logging_ import log_doc_event
from access_guard.policy import get_policy
from access_guard.protocol import POLICY_ALWAYS_LOG_DOCTYPES


def _is_always_log_doctype(doctype: str) -> bool:
	policy = get_policy()
	return doctype in (policy.get(POLICY_ALWAYS_LOG_DOCTYPES) or [])


def on_update(doc, method=None):
	try:
		sid = frappe.session.sid
	except Exception:
		return
	jti, _grant = find_grant_by_sid(sid)
	if jti is None or not _is_always_log_doctype(doc.doctype):
		return

	def _log():
		log_doc_event(sid, doc.doctype, doc.name, "write", doc.as_dict())

	frappe.db.after_commit.add(_log)


def on_trash(doc, method=None):
	try:
		sid = frappe.session.sid
	except Exception:
		return
	jti, _grant = find_grant_by_sid(sid)
	if jti is None or not _is_always_log_doctype(doc.doctype):
		return

	def _log():
		log_doc_event(sid, doc.doctype, doc.name, "delete", doc.as_dict())

	frappe.db.after_commit.add(_log)
