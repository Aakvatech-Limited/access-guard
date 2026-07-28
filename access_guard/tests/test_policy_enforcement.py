"""Tests for deny/warn policy enforcement, keyed on "is this session
ephemeral?" (grant-file sid lookup) -- never a DB permission check
(DESIGN.md "Enforcement mechanics")."""

from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from access_guard.grants import write_grant
from access_guard.protocol import PolicyDeniedError, utc_iso


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
			"issued_at": utc_iso(),
		},
	)


class TestPolicyEnforcement(FrappeTestCase):
	def setUp(self):
		self._grant_jtis = []
		self.addCleanup(self._cleanup)

	def _cleanup(self):
		import os

		from access_guard.grants import delete_grant
		from access_guard.logging_ import log_file_path

		for jti in self._grant_jtis:
			delete_grant(jti)
			for kind in ("request", "doc"):
				path = log_file_path(jti, kind)
				if os.path.exists(path):
					os.remove(path)

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

	def test_before_validate_dispatches_submit_not_write(self):
		"""A submitted doc must be enforced as "submit", not "write" too -
		before_validate fires for both create/write and submit (docstatus is
		already Submitted by the time Frappe calls it), so it must branch on
		docstatus rather than blindly treating every before_validate as write."""
		from frappe.model.docstatus import DocStatus

		from access_guard.session_guard import before_validate

		sid = self._fake_ephemeral_session("submit-dispatch-jti")
		doc = frappe.new_doc("ToDo")
		doc.description = "submit-dispatch test"
		doc.docstatus = DocStatus.submitted()

		with (
			patch.object(frappe.local, "session", frappe._dict(sid=sid, user="ephemeral@example.com")),
			patch("access_guard.session_guard.get_enforce_mode") as mock_get_enforce_mode,
		):
			before_validate(doc)

		mock_get_enforce_mode.assert_called_once()
		self.assertEqual(mock_get_enforce_mode.call_args.args[1], "submit")

	def test_deny_rule_blocks_rename(self):
		import os

		from access_guard.config_utils import atomic_write_json, policy_path, read_json
		from access_guard.tests.keys import clear_policy_cache

		sid = self._fake_ephemeral_session("deny-rename-jti")

		deny_policy = {
			"policy": {"pv": 1, "rules": [{"doctype": "ToDo", "actions": ["rename"], "mode": "deny"}]},
			"verified_at": utc_iso(),
		}
		path = policy_path()
		original = read_json(path) if os.path.exists(path) else None
		atomic_write_json(path, deny_policy)
		clear_policy_cache()

		todo = frappe.new_doc("ToDo")
		todo.description = "rename-deny test"
		todo.insert(ignore_permissions=True)
		self.addCleanup(lambda: frappe.delete_doc("ToDo", todo.name, force=True, ignore_permissions=True))
		frappe.db.commit()
		old_name = todo.name

		try:
			with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="ephemeral@example.com")):
				with self.assertRaises(PolicyDeniedError):
					frappe.rename_doc("ToDo", old_name, "renamed-todo-should-not-exist")
			self.assertTrue(frappe.db.exists("ToDo", old_name))
			self.assertFalse(frappe.db.exists("ToDo", "renamed-todo-should-not-exist"))
		finally:
			if original is not None:
				atomic_write_json(path, original)
			elif os.path.exists(path):
				os.remove(path)
			clear_policy_cache()

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
		from access_guard.tests.keys import clear_policy_cache

		sid = self._fake_ephemeral_session("warn-jti-1")

		warn_policy = {
			"policy": {
				"pv": 1,
				"rules": [{"doctype": "ToDo", "actions": ["create"], "mode": "warn"}],
			},
			"verified_at": utc_iso(),
		}
		original = None
		import os

		path = policy_path()
		if os.path.exists(path):
			from access_guard.config_utils import read_json

			original = read_json(path)
		atomic_write_json(path, warn_policy)
		clear_policy_cache()
		log_path = _log_path_for("warn-jti-1")
		try:
			with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="ephemeral@example.com")):
				todo = frappe.new_doc("ToDo")
				todo.description = "warn-mode op"
				todo.insert(ignore_permissions=True)
				frappe.db.commit()  # trigger after_commit callbacks
			self.addCleanup(lambda: frappe.delete_doc("ToDo", todo.name, force=True, ignore_permissions=True))

			with open(log_path) as f:
				lines = f.readlines()
			self.assertTrue(any("event=create" in line and "doctype=ToDo" in line for line in lines))
		finally:
			if original is not None:
				atomic_write_json(path, original)
			elif os.path.exists(path):
				os.remove(path)
			clear_policy_cache()
			if os.path.exists(log_path):
				os.remove(log_path)


def _log_path_for(jti):
	from access_guard.logging_ import log_file_path

	return log_file_path(jti, "doc")
