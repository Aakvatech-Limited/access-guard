"""Session guard: is-this-ephemeral? + deny/warn enforcement.

The ephemeral user has System Manager, so DB permissions can't gate
anything (DESIGN.md "Enforcement mechanics") — enforcement is entirely
guard *code*, hooked via doc_events["*"] (wildcard — policy rules are not
scoped to a fixed doctype list) and keyed on whether the current session's
sid appears in a grant file. Policy is read from the file, never the DB.
"""

from __future__ import annotations

import frappe

from access_guard.grants import find_grant_by_sid
from access_guard.logging_ import log_doc_event
from access_guard.policy import enforce
from access_guard.protocol import MODE_WARN, PolicyDeniedError


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

    try:
        mode = enforce(doc.doctype, action, jti=jti)
    except PolicyDeniedError:
        frappe.throw(
            frappe._(
                "This operation ({0} on {1}) is blocked for monitored sessions by access policy."
            ).format(action, doc.doctype),
            exc=PolicyDeniedError,
        )
        return

    if mode == MODE_WARN:
        frappe.msgprint(
            frappe._(
                "This is a sensitive operation on a client account and will be recorded."
            ),
            indicator="orange",
            alert=True,
        )
        _register_after_commit_log(doc, action, jti)


def _register_after_commit_log(doc, action: str, jti: str) -> None:
    sid = frappe.session.sid

    def _log():
        log_doc_event(sid, doc.doctype, doc.name, action, _diff_for(doc))

    frappe.db.after_commit.add(_log)


def _diff_for(doc) -> dict:
    try:
        before = doc.get_doc_before_save()
    except Exception:
        before = None
    if not before:
        return {"after": doc.as_dict()}
    return {"before": before.as_dict(), "after": doc.as_dict()}


def validate(doc, method=None):
    """doc_events['*']['validate'] — fires on both create and write (Frappe
    calls validate() on insert and on save alike)."""
    action = "create" if doc.is_new() else "write"
    _enforce_for_doc(doc, action)


def before_submit(doc, method=None):
    _enforce_for_doc(doc, "submit")


def before_cancel(doc, method=None):
    _enforce_for_doc(doc, "cancel")


def on_trash(doc, method=None):
    _enforce_for_doc(doc, "delete")
