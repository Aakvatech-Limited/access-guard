"""Session guard: is-this-ephemeral? + deny/warn enforcement + doc-change
logging, all in one pass per doc event.

The ephemeral user has System Manager, so DB permissions can't gate
anything (DESIGN.md "Enforcement mechanics") — enforcement is entirely
guard *code*, hooked via doc_events["*"] (wildcard — policy rules are not
scoped to a fixed doctype list) and keyed on whether the current session's
sid appears in a grant file. Policy is read from the file, never the DB.

Logging a doc change is decided in the same pass: either a matching warn
rule, or the doctype being in always_log_doctypes - one line either way,
never both (after_commit, or immediately for a deny - see _enforce_for_doc).
write/submit log a diff (Version.get_diff against the pre-save state,
already loaded by Frappe before this hook runs - even a denied write has
one); create/cancel/delete log the full doc; rename logs {old_name,
new_name} instead, via the same shared enforcement pass (see before_rename).
"""

import frappe
from frappe.core.doctype.version.version import get_diff

from access_guard.grants import find_grant_by_sid
from access_guard.logging_ import log_doc_event
from access_guard.policy import get_enforce_mode, get_policy
from access_guard.protocol import MODE_DENY, MODE_WARN, POLICY_ALWAYS_LOG_DOCTYPES, PolicyDeniedError

_DIFFABLE_ACTIONS = ("write", "submit")


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


def _doc_or_diff(doc, action: str, before) -> tuple[dict | None, dict | None]:
	"""(doc, diff) - exactly one is set. write/submit log a diff against
	`before` (write/submit/denied-write's pre-save state, fetched once via
	get_doc_before_save() before it can change); create/cancel/delete log
	the full doc, since there's no useful "before" to diff against for any
	of those. Falls back to the full doc if get_diff itself errors - logging
	must not fail just because a diff couldn't be computed for some doctype.

	Called at the point of actually logging (immediately for a deny, inside
	the after_commit closure otherwise) so doc.as_dict()/get_diff(before,
	doc) reflect doc's state as of commit time, not whatever it looked like
	when the hook first ran - doc can still be mutated in place by other
	hooks/db_update side effects in between."""
	if action in _DIFFABLE_ACTIONS and before is not None:
		try:
			return None, get_diff(before, doc)
		except Exception:
			frappe.log_error(title="access_guard: get_diff failed, falling back to full doc")
	return doc.as_dict(), None


def _enforce_for_doc(doc, action: str, *, old_name=None, new_name=None, payload=None) -> None:
	"""Shared deny/warn/always-log pass for every action, including rename.
	`payload()` returns (doc_snapshot, diff) for the log line - defaults to
	_doc_or_diff (full doc or a diff against the pre-save state); rename
	passes a fixed {old_name, new_name} instead, since there's no doc state
	to diff, only two names. denied_name/committed_name let rename log under
	old_name when denied (nothing changed) vs. new_name once actually
	committed - every other action logs under doc.name either way."""
	jti = _current_ephemeral_jti()
	if jti is None:
		return  # not an ephemeral session -> policy does not apply

	mode = get_enforce_mode(doc.doctype, action)
	if payload is None:
		before = doc.get_doc_before_save()
		payload = lambda: _doc_or_diff(doc, action, before)  # noqa: E731

	if mode == MODE_DENY:
		# Nothing commits on a deny, so log the attempt now rather than via
		# after_commit (there's no commit coming) - doc's current in-memory
		# state IS the final state here, there's no later mutation to wait for.
		doc_snapshot, diff = payload()
		log_doc_event(
			frappe.session.sid,
			doc.doctype,
			old_name if old_name is not None else doc.name,
			f"denied:{action}",
			doc=doc_snapshot,
			diff=diff,
		)
		frappe.throw(
			frappe._(
				"This operation ({0} on {1}) is blocked for monitored sessions by access policy."
			).format(action, doc.doctype),
			exc=PolicyDeniedError,
		)
		return

	if mode == MODE_WARN:
		frappe.msgprint(
			frappe._("This operation ({0} on {1}) is sensitive and will be recorded.").format(
				action, doc.doctype
			),
			indicator="orange",
			alert=True,
		)

	always_log = doc.doctype in (get_policy().get(POLICY_ALWAYS_LOG_DOCTYPES) or [])
	if mode == MODE_WARN or always_log:
		sid = frappe.session.sid
		name = new_name if new_name is not None else doc.name

		def _log():
			doc_snapshot, diff = payload()
			log_doc_event(sid, doc.doctype, name, action, doc=doc_snapshot, diff=diff)

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


def before_rename(doc, method=None, old_name=None, new_name=None, merge=False):
	"""doc_events['*']['before_rename'] — fires before the rename itself, so
	a deny here blocks it outright. No separate after_rename needed: the log
	payload is just {old_name, new_name} - both already known here as hook
	params - there's no full/diff doc state that needs the freshly-renamed
	doc after_rename would hand us, only the after_commit timing (no commit
	-> no log)."""
	_enforce_for_doc(
		doc,
		"rename",
		old_name=old_name,
		new_name=new_name,
		payload=lambda: ({"old_name": old_name, "new_name": new_name}, None),
	)
