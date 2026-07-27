"""Tests for deny/warn policy enforcement, keyed on "is this session
ephemeral?" (grant-file sid lookup) -- never a DB permission check
(DESIGN.md "Enforcement mechanics")."""

from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from access_guard.grants import write_grant
from access_guard.protocol import PolicyDeniedError


def _write_fake_grant(jti: str, sid: str, user: str):
	write_grant(
		jti,
		{
			"jti": jti,
			"pv": 1,
			"user_name": "Test User",
			"user_email": user,
			"user": user,
			"sid": sid,
			"issued_at": frappe.utils.now_datetime().isoformat(),
			"effective_expiry_seconds": 21600,
		},
	)


class TestPolicyEnforcement(FrappeTestCase):
	def setUp(self):
		self._grant_jtis = []
		self.addCleanup(self._cleanup)

	def _cleanup(self):
		from access_guard.grants import delete_grant

		for jti in self._grant_jtis:
			delete_grant(jti)

	def _fake_ephemeral_session(self, jti: str, user: str = "ephemeral@example.com"):
		sid = f"fake-sid-{jti}"
		_write_fake_grant(jti, sid, user)
		self._grant_jtis.append(jti)
		return sid

	def test_deny_rule_blocks_user_create(self):
		sid = self._fake_ephemeral_session("deny-jti-1")
		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="ephemeral@example.com")):
			new_user = frappe.new_doc("User")
			new_user.email = "blocked-by-policy@example.com"
			new_user.first_name = "Blocked"
			with self.assertRaises(PolicyDeniedError):
				new_user.insert(ignore_permissions=True)
		self.assertFalse(frappe.db.exists("User", "blocked-by-policy@example.com"))

	def test_deny_does_not_apply_to_non_ephemeral_session(self):
		# No grant file for the current (real) session -> policy must not
		# apply; ordinary creation should proceed normally.
		new_user = frappe.new_doc("User")
		new_user.email = "not-ephemeral-allowed@example.com"
		new_user.first_name = "Allowed"
		new_user.send_welcome_email = 0
		new_user.insert(ignore_permissions=True)
		self.addCleanup(
			lambda: frappe.delete_doc(
				"User", "not-ephemeral-allowed@example.com", force=True, ignore_permissions=True
			)
		)
		self.assertTrue(frappe.db.exists("User", "not-ephemeral-allowed@example.com"))

	def test_warn_rule_logs_and_allows(self):
		from access_guard.config_utils import atomic_write_json, policy_path

		sid = self._fake_ephemeral_session("warn-jti-1")

		warn_policy = {
			"token": "n/a",
			"policy": {
				"pv": 1,
				"rules": [{"doctype": "ToDo", "actions": ["create"], "mode": "warn"}],
			},
			"verified_at": frappe.utils.now_datetime().isoformat(),
		}
		original = None
		import os

		path = policy_path()
		if os.path.exists(path):
			from access_guard.config_utils import read_json

			original = read_json(path)
		atomic_write_json(path, warn_policy)
		try:
			with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="ephemeral@example.com")):
				todo = frappe.new_doc("ToDo")
				todo.description = "warn-mode op"
				todo.insert(ignore_permissions=True)
				frappe.db.commit()  # trigger after_commit callbacks

			log_path = _log_path_for("warn-jti-1")
			with open(log_path) as f:
				lines = f.readlines()
			self.assertTrue(any("event=create" in line and "doctype=ToDo" in line for line in lines))
		finally:
			if original is not None:
				atomic_write_json(path, original)
			elif os.path.exists(path):
				os.remove(path)


def _log_path_for(jti):
	from access_guard.logging_ import log_file_path

	return log_file_path(jti, "doc")
