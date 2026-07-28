"""Tests for per-session logfmt logging (PROTOCOL.md §7):
- a safe-verb (GET) call is not logged when log_reads is off,
- an unsafe-verb (POST) call is logged, as one line from after_request,
- a rolled-back always-log write produces no doc line, a committed one does.
"""

import os
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from access_guard.config_utils import atomic_write_json, policy_path, read_json
from access_guard.grants import delete_grant, write_grant
from access_guard.logging_ import log_file_path


def _write_fake_grant(jti: str, sid: str, user: str = "logtest@example.com"):
	write_grant(
		jti,
		{
			"jti": jti,
			"pv": 1,
			"user_name": "Log Test",
			"user_email": user,
			"user": user,
			"sid": sid,
			"issued_at": frappe.utils.now_datetime().isoformat(),
			"effective_expiry_seconds": 21600,
		},
	)


def _parse_logfmt(line: str) -> dict:
	"""Minimal logfmt parser for test assertions: key=value, where a
	whitespace-containing value is JSON-quoted (see logging_._format_line)."""
	import json

	fields = {}
	i = 0
	while i < len(line):
		eq = line.index("=", i)
		key = line[i:eq]
		i = eq + 1
		if i < len(line) and line[i] == '"':
			decoder = json.JSONDecoder()
			value, end = decoder.raw_decode(line, i)
			fields[key] = value
			i = end
		else:
			end = line.index(" ", i) if " " in line[i:] else len(line)
			fields[key] = line[i:end]
			i = end
		i += 1
	return fields


class TestLogging(FrappeTestCase):
	def setUp(self):
		self._jtis = []
		self.addCleanup(self._cleanup)

	def _cleanup(self):
		for jti in self._jtis:
			delete_grant(jti)
			for kind in ("request", "doc"):
				path = log_file_path(jti, kind)
				if os.path.exists(path):
					os.remove(path)

	def _fake_session(self, jti):
		sid = f"log-sid-{jti}"
		_write_fake_grant(jti, sid)
		self._jtis.append(jti)
		return sid

	def _read_lines(self, jti, kind="request"):
		path = log_file_path(jti, kind)
		if not os.path.exists(path):
			return []
		with open(path) as f:
			return [_parse_logfmt(line) for line in f if line.strip()]

	def test_safe_verb_not_logged_when_log_reads_off(self):
		from access_guard.request_hooks import after_request, before_request

		jti = "log-jti-safeverb"
		sid = self._fake_session(jti)

		# GET is a safe verb -> skipped even for an endpoint that could write.
		frappe.utils.set_request(method="GET", path="/api/method/frappe.client.save")
		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			before_request()
			after_request(response=frappe._dict(status_code=200))

		lines = self._read_lines(jti)
		self.assertEqual(lines, [])

	def test_unsafe_verb_is_logged(self):
		from access_guard.request_hooks import after_request, before_request

		jti = "log-jti-unsafeverb"
		sid = self._fake_session(jti)

		frappe.utils.set_request(method="POST", path="/api/method/frappe.client.save")
		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			before_request()
			after_request(response=frappe._dict(status_code=200))

		lines = self._read_lines(jti)
		self.assertEqual(len(lines), 1)
		self.assertEqual(lines[0]["path"], "frappe.client.save")
		self.assertEqual(lines[0]["http_method"], "POST")
		self.assertEqual(lines[0]["status"], "ok")

	def test_error_response_logged_as_error_status(self):
		from access_guard.request_hooks import after_request, before_request

		jti = "log-jti-errorstatus"
		sid = self._fake_session(jti)

		frappe.utils.set_request(method="POST", path="/api/method/frappe.client.save")
		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			before_request()
			after_request(response=frappe._dict(status_code=417))

		lines = self._read_lines(jti)
		self.assertEqual(lines[0]["status"], "error")
		self.assertEqual(lines[0]["code"], "417")

	def _stub_always_log_only_policy(self):
		"""User in always_log_doctypes, no deny/warn rule for it - isolates
		the always-log path from enforcement, regardless of whatever policy
		another test left cached. Restores whatever was there before, so
		this doesn't leak into later test modules."""
		from access_guard.tests.keys import clear_policy_cache, stub_policy_file

		path = policy_path()
		original = read_json(path) if os.path.exists(path) else None
		stub_policy_file({"pv": 1, "rules": [], "always_log_doctypes": ["User"]})

		def _restore():
			if original is not None:
				atomic_write_json(path, original)
			elif os.path.exists(path):
				os.remove(path)
			clear_policy_cache()

		self.addCleanup(_restore)

	def test_rolled_back_write_produces_no_doc_line(self):
		from access_guard.session_guard import _enforce_for_doc

		jti = "log-jti-rollback"
		sid = self._fake_session(jti)
		self._stub_always_log_only_policy()

		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			doc = frappe.get_doc("User", "Administrator")
			_enforce_for_doc(doc, "write")  # registers an after_commit callback
		# Simulate the write never committing: run after_rollback instead.
		frappe.db.after_commit.reset()

		lines = self._read_lines(jti, kind="doc")
		self.assertEqual(lines, [])

	def test_committed_write_produces_doc_line(self):
		from access_guard.session_guard import _enforce_for_doc

		jti = "log-jti-committed"
		sid = self._fake_session(jti)
		self._stub_always_log_only_policy()

		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			doc = frappe.get_doc("User", "Administrator")
			_enforce_for_doc(doc, "write")
		frappe.db.after_commit.run()

		lines = self._read_lines(jti, kind="doc")
		self.assertEqual(len(lines), 1)
		self.assertEqual(lines[0]["event"], "write")
		self.assertEqual(lines[0]["doctype"], "User")

	def test_denied_write_is_logged_immediately(self):
		"""A denied operation never commits, so it can't ride after_commit -
		it must log synchronously, at the point of denial."""
		from access_guard.protocol import PolicyDeniedError
		from access_guard.session_guard import _enforce_for_doc
		from access_guard.tests.keys import clear_policy_cache, stub_policy_file

		jti = "log-jti-denied"
		sid = self._fake_session(jti)
		path = policy_path()
		original = read_json(path) if os.path.exists(path) else None
		stub_policy_file({"pv": 1, "rules": [{"doctype": "User", "actions": ["write"], "mode": "deny"}]})

		def _restore():
			if original is not None:
				atomic_write_json(path, original)
			elif os.path.exists(path):
				os.remove(path)
			clear_policy_cache()

		self.addCleanup(_restore)

		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			doc = frappe.get_doc("User", "Administrator")
			with self.assertRaises(PolicyDeniedError):
				_enforce_for_doc(doc, "write")

		lines = self._read_lines(jti, kind="doc")
		self.assertEqual(len(lines), 1)
		self.assertEqual(lines[0]["event"], "denied:write")
		self.assertEqual(lines[0]["doctype"], "User")
