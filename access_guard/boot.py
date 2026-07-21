"""boot_session hook: stamp bootinfo with an "am I ephemeral?" flag +
monitoring notice text, derived from the grant file — never a DB flag
(DESIGN.md "Monitoring notice on client sites")."""

from __future__ import annotations

import frappe

from access_guard.grants import find_grant_by_sid
from access_guard.policy import get_policy
from access_guard.protocol import POLICY_MONITORING_NOTICE_TEXT


def boot_session(bootinfo):
    try:
        sid = frappe.session.sid
    except Exception:
        sid = None

    jti, _record = (None, None) if not sid else find_grant_by_sid(sid)
    bootinfo.access_guard_ephemeral = bool(jti)
    if jti:
        policy = get_policy()
        bootinfo.access_guard_notice_text = policy.get(POLICY_MONITORING_NOTICE_TEXT)
