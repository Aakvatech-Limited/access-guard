"""Tests for per-session JSONL logging (PROTOCOL.md §7):
- a safe-verb (GET) call is not logged when log_reads is off,
- an unsafe-verb (POST) call is logged,
- a rolled-back always-log write produces no `doc` line, a committed one does.
"""

import json
import os
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from access_guard.config_utils import atomic_write_json, policy_path, read_json
from access_guard.constants import LOG_TYPE_DOC
from access_guard.grants import delete_grant, write_grant
from access_guard.logging_ import log_file_path


def _write_fake_grant(jti: str, sid: str, user: str = "logtest@example.com"):
	write_grant(
		jti,
		{
			"jti": jti,
			"pv": 1,
			"emp_name": "Log Test",
			"emp_email": user,
			"user": user,
			"sid": sid,
			"issued_at": frappe.utils.now_datetime().isoformat(),
			"effective_expiry_seconds": 21600,
		},
	)


class TestLogging(FrappeTestCase):
	def setUp(self):
		self._jtis = []
		self.addCleanup(self._cleanup)

	def _cleanup(self):
		for jti in self._jtis:
			delete_grant(jti)
			path = log_file_path(jti)
			if os.path.exists(path):
				os.remove(path)

	def _fake_session(self, jti):
		sid = f"log-sid-{jti}"
		_write_fake_grant(jti, sid)
		self._jtis.append(jti)
		return sid

	def _read_lines(self, jti):
		path = log_file_path(jti)
		if not os.path.exists(path):
			return []
		with open(path) as f:
			return [json.loads(line) for line in f if line.strip()]

	def test_safe_verb_not_logged_when_log_reads_off(self):
		from access_guard.request_hooks import before_request

		jti = "log-jti-safeverb"
		sid = self._fake_session(jti)

		# GET is a safe verb -> skipped even for an endpoint that could write.
		frappe.utils.set_request(method="GET", path="/api/method/frappe.client.save")
		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			before_request()

		lines = self._read_lines(jti)
		self.assertEqual(lines, [])

	def test_unsafe_verb_is_logged(self):
		from access_guard.request_hooks import before_request

		jti = "log-jti-unsafeverb"
		sid = self._fake_session(jti)

		frappe.utils.set_request(method="POST", path="/api/method/frappe.client.save")
		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			before_request()

		lines = self._read_lines(jti)
		self.assertEqual(len(lines), 1)
		self.assertEqual(lines[0]["type"], "request")
		self.assertEqual(lines[0]["method"], "frappe.client.save")
		self.assertEqual(lines[0]["http_method"], "POST")

	def test_rolled_back_write_produces_no_doc_line(self):
		from access_guard.always_log import on_update

		jti = "log-jti-rollback"
		sid = self._fake_session(jti)

		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			doc = frappe.get_doc("User", "Administrator")
			on_update(doc)  # registers an after_commit callback
		# Simulate the write never committing: run after_rollback instead.
		frappe.db.after_commit.reset()

		lines = self._read_lines(jti)
		self.assertEqual(lines, [])

	def test_committed_write_produces_doc_line(self):
		from access_guard.always_log import on_update

		jti = "log-jti-committed"
		sid = self._fake_session(jti)

		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			doc = frappe.get_doc("User", "Administrator")
			on_update(doc)
		frappe.db.after_commit.run()

		lines = self._read_lines(jti)
		self.assertEqual(len(lines), 1)
		self.assertEqual(lines[0]["type"], LOG_TYPE_DOC)
		self.assertEqual(lines[0]["doctype"], "User")
