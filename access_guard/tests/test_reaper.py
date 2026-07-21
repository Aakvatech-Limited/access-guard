"""Tests for the reaper: idle-expired grants get their user+sessions
deleted; a real (non-ephemeral) client user is never touched — namespace
filter is strictly "users named in grant files"."""

from __future__ import annotations

from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from access_guard.grants import delete_grant, read_grant, write_grant
from access_guard.reaper import reap_idle_sessions


class TestReaper(FrappeTestCase):
    def setUp(self):
        self._users_to_clean = []
        self._jtis_to_clean = []
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for jti in self._jtis_to_clean:
            delete_grant(jti)
        for user in self._users_to_clean:
            if frappe.db.exists("User", user):
                frappe.delete_doc("User", user, force=True, ignore_permissions=True)
        frappe.db.commit()

    def _make_ephemeral_user(self, email):
        user = frappe.new_doc("User")
        user.email = email
        user.first_name = "Reap"
        user.last_name = "Target (consultant)"
        user.send_welcome_email = 0
        user.user_type = "System User"
        user.insert(ignore_permissions=True)
        user.add_roles("System Manager")
        frappe.db.commit()
        self._users_to_clean.append(email)
        return user.name

    def _make_session_row(self, user, sid, lastupdate):
        frappe.db.sql("DELETE FROM `tabSessions` WHERE sid=%s", sid)
        sessions = frappe.qb.DocType("Sessions")
        (
            frappe.qb.into(sessions)
            .columns(sessions.sessiondata, sessions.user, sessions.lastupdate, sessions.sid, sessions.status)
            .insert(("{}", user, lastupdate, sid, "Active"))
        ).run()
        frappe.db.commit()

    def test_idle_expired_grant_is_reaped(self):
        email = "reap-target@example.com"
        user = self._make_ephemeral_user(email)
        jti = "reaper-jti-1"
        sid = "reaper-sid-1"
        self._jtis_to_clean.append(jti)

        old_time = frappe.utils.add_to_date(frappe.utils.now_datetime(), hours=-10)
        self._make_session_row(user, sid, old_time)

        write_grant(
            jti,
            {
                "jti": jti,
                "pv": 1,
                "emp_name": "Reap Target",
                "emp_email": email,
                "user": user,
                "sid": sid,
                "issued_at": frappe.utils.now_datetime().isoformat(),
                "effective_expiry_seconds": 3600,  # 1h — old_time (10h ago) is well past this
            },
        )

        with patch("access_guard.reaper.report_provisioning", return_value=None):
            reap_idle_sessions()

        self.assertFalse(frappe.db.exists("User", email), "ephemeral user should be reaped")
        self.assertIsNone(read_grant(jti), "grant file should be removed after reap")
        self.assertFalse(
            frappe.db.exists("Sessions", {"sid": sid}), "session row should be deleted"
        )

    def test_non_ephemeral_user_never_touched(self):
        """A real client user (no grant file referencing it) must survive
        the reaper regardless of session idle time — namespace filter."""
        email = "real-client-user@example.com"
        user = frappe.new_doc("User")
        user.email = email
        user.first_name = "Real"
        user.last_name = "Client"
        user.send_welcome_email = 0
        user.user_type = "System User"
        user.insert(ignore_permissions=True)
        frappe.db.commit()
        self._users_to_clean.append(email)

        sid = "real-user-sid-1"
        old_time = frappe.utils.add_to_date(frappe.utils.now_datetime(), hours=-100)
        self._make_session_row(email, sid, old_time)

        with patch("access_guard.reaper.report_provisioning", return_value=None):
            reap_idle_sessions()

        self.assertTrue(frappe.db.exists("User", email), "real client user must never be reaped")
