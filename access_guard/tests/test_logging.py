"""Tests for per-session logfmt logging (PROTOCOL.md §7):
- a safe-verb (GET) call is not logged when log_reads is off,
- an unsafe-verb (POST) call is logged, as one line from after_request,
- a rolled-back always-log write produces no doc line, a committed one does.
"""

import json
import os
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from access_guard.config_utils import atomic_write_json, policy_path, read_json
from access_guard.grants import delete_grant, write_grant
from access_guard.logging_ import _TRUNCATED_MARKER, log_file_path


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
		},
	)


def _parse_logfmt(line: str) -> dict:
	"""Minimal logfmt parser for test assertions: key=value, where a
	whitespace-containing value is JSON-quoted (see logging_._format_line)."""
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
			return [_parse_logfmt(line.strip()) for line in f if line.strip()]

	def test_safe_verb_not_logged_when_log_reads_off(self):
		from access_guard.request_hooks import after_request

		jti = "log-jti-safeverb"
		sid = self._fake_session(jti)

		# GET is a safe verb -> skipped even for an endpoint that could write.
		frappe.utils.set_request(method="GET", path="/api/method/frappe.client.save")
		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			after_request(response=frappe._dict(status_code=200))

		lines = self._read_lines(jti)
		self.assertEqual(lines, [])

	def test_unsafe_verb_is_logged(self):
		from access_guard.request_hooks import after_request

		jti = "log-jti-unsafeverb"
		sid = self._fake_session(jti)

		frappe.utils.set_request(method="POST", path="/api/method/frappe.client.save")
		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			after_request(response=frappe._dict(status_code=200))

		lines = self._read_lines(jti)
		self.assertEqual(len(lines), 1)
		self.assertEqual(lines[0]["path"], "frappe.client.save")
		self.assertEqual(lines[0]["http_method"], "POST")
		self.assertEqual(lines[0]["status"], "ok")

	def test_non_api_request_falls_back_to_raw_path(self):
		"""A request that's neither a cmd= RPC nor /api/method/... (e.g. a
		desk page load or /api/resource/...) must still be logged, keyed on
		the raw path, not silently skipped."""
		from access_guard.request_hooks import after_request

		jti = "log-jti-nonapi"
		sid = self._fake_session(jti)

		frappe.utils.set_request(method="POST", path="/api/resource/ToDo")
		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			after_request(response=frappe._dict(status_code=200))

		lines = self._read_lines(jti)
		self.assertEqual(len(lines), 1)
		self.assertEqual(lines[0]["path"], "/api/resource/ToDo")

	def test_json_body_kept_separate_from_params(self):
		"""A JSON body and query params must never collide by being merged
		into one dict - a query param literally named "body" must survive
		alongside the parsed JSON body, not get overwritten by it."""
		from access_guard.request_hooks import after_request

		jti = "log-jti-jsonbody"
		sid = self._fake_session(jti)

		frappe.utils.set_request(
			method="POST",
			path="/api/method/frappe.client.save",
			query_string={"body": "not-the-json-body"},
			json={"doctype": "ToDo", "description": "hello"},
		)
		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			after_request(response=frappe._dict(status_code=200))

		lines = self._read_lines(jti)
		self.assertEqual(len(lines), 1)
		params = json.loads(lines[0]["params"])
		self.assertEqual(params["body"], "not-the-json-body")
		body = json.loads(lines[0]["body"])
		self.assertEqual(body["description"], "hello")

	def test_non_json_body_logged_as_raw_string(self):
		"""A body that isn't JSON must still be logged (truncated, not
		parsed) rather than silently dropped just because it can't be
		parsed as JSON."""
		from access_guard.request_hooks import after_request

		jti = "log-jti-rawbody"
		sid = self._fake_session(jti)

		frappe.utils.set_request(
			method="POST",
			path="/api/method/frappe.client.save",
			content_type="text/plain",
			data="plain text body",
		)
		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			after_request(response=frappe._dict(status_code=200))

		lines = self._read_lines(jti)
		self.assertEqual(len(lines), 1)
		self.assertEqual(lines[0]["body"], "plain text body")

	def test_json_object_body_truncated_per_key(self):
		"""A JSON-object body gets the same per-key truncation as params -
		one oversized field inside it can't crowd out a small one."""
		from access_guard.logging_ import log_request
		from access_guard.tests.keys import clear_policy_cache, stub_policy_file

		jti = "log-jti-body-per-key"
		sid = self._fake_session(jti)
		path = policy_path()
		original = read_json(path) if os.path.exists(path) else None
		stub_policy_file({"pv": 1, "rules": [], "log_reads": True, "max_key_size_bytes": 20})

		def _restore():
			if original is not None:
				atomic_write_json(path, original)
			elif os.path.exists(path):
				os.remove(path)
			clear_policy_cache()

		self.addCleanup(_restore)

		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			log_request(
				sid,
				"some.whitelisted.method",
				"GET",
				"ok",
				200,
				{},
				{"small": "ok", "huge": "x" * 500},
			)

		lines = self._read_lines(jti)
		self.assertEqual(len(lines), 1)
		body = json.loads(lines[0]["body"])
		self.assertEqual(body["small"], "ok")
		self.assertTrue(body["huge"].endswith(_TRUNCATED_MARKER))

	def test_error_response_logged_as_error_status(self):
		from access_guard.request_hooks import after_request

		jti = "log-jti-errorstatus"
		sid = self._fake_session(jti)

		frappe.utils.set_request(method="POST", path="/api/method/frappe.client.save")
		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			after_request(response=frappe._dict(status_code=417))

		lines = self._read_lines(jti)
		self.assertEqual(lines[0]["status"], "error")
		self.assertEqual(lines[0]["code"], "417")

	def _stub_always_log_only_policy(self):
		self._stub_always_log_only_policy_for("User")

	def _stub_always_log_only_policy_for(self, doctype: str):
		"""`doctype` in always_log_doctypes, no deny/warn rule for it -
		isolates the always-log path from enforcement, regardless of
		whatever policy another test left cached. Restores whatever was
		there before, so this doesn't leak into later test modules."""
		from access_guard.tests.keys import clear_policy_cache, stub_policy_file

		path = policy_path()
		original = read_json(path) if os.path.exists(path) else None
		stub_policy_file({"pv": 1, "rules": [], "always_log_doctypes": [doctype]})

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
		"""No doc_before_save available here (a bare frappe.get_doc(), not a
		real save() flow) - falls back to full-doc, same as create/cancel/
		delete. See test_committed_write_with_before_state_logs_diff for the
		diff path."""
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
		self.assertIn("doc", lines[0])
		self.assertNotIn("diff", lines[0])

	def test_committed_write_with_before_state_logs_diff(self):
		"""A real save() populates doc_before_save, so the write is logged as
		a diff (changed fields only), not the full doc."""
		from access_guard.session_guard import _enforce_for_doc

		jti = "log-jti-diff"
		sid = self._fake_session(jti)
		self._stub_always_log_only_policy_for("ToDo")

		todo = frappe.get_doc({"doctype": "ToDo", "description": "before"}).insert(ignore_permissions=True)
		self.addCleanup(lambda: frappe.delete_doc("ToDo", todo.name, force=True, ignore_permissions=True))
		frappe.db.commit()

		todo.load_doc_before_save()  # what _save() calls internally, before validate/before_validate
		todo.description = "after"

		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			_enforce_for_doc(todo, "write")
		frappe.db.after_commit.run()

		lines = self._read_lines(jti, kind="doc")
		self.assertEqual(len(lines), 1)
		self.assertNotIn("doc", lines[0])
		self.assertIn("diff", lines[0])
		diff = json.loads(lines[0]["diff"])
		changed_fields = {row[0] for row in diff["changed"]}
		self.assertIn("description", changed_fields)

	def test_get_diff_failure_falls_back_to_full_doc(self):
		"""If get_diff itself raises, the write must still get logged -
		as the full doc, not silently dropped."""
		from access_guard.session_guard import _enforce_for_doc

		jti = "log-jti-diff-fallback"
		sid = self._fake_session(jti)
		self._stub_always_log_only_policy_for("ToDo")

		todo = frappe.get_doc({"doctype": "ToDo", "description": "before"}).insert(ignore_permissions=True)
		self.addCleanup(lambda: frappe.delete_doc("ToDo", todo.name, force=True, ignore_permissions=True))
		frappe.db.commit()

		todo.load_doc_before_save()
		todo.description = "after"

		with (
			patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")),
			patch("access_guard.session_guard.get_diff", side_effect=RuntimeError("boom")),
		):
			_enforce_for_doc(todo, "write")
			# get_diff is called lazily inside the after_commit closure (see
			# _register_after_commit_log), so the mock must still be active
			# when the callback actually runs, not just at registration time.
			frappe.db.after_commit.run()

		lines = self._read_lines(jti, kind="doc")
		self.assertEqual(len(lines), 1)
		self.assertIn("doc", lines[0])
		self.assertNotIn("diff", lines[0])

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

	def test_always_log_rename_logs_old_and_new_name(self):
		jti = "log-jti-rename"
		sid = self._fake_session(jti)
		self._stub_always_log_only_policy_for("ToDo")

		todo = frappe.get_doc({"doctype": "ToDo", "description": "rename test"}).insert(
			ignore_permissions=True
		)
		frappe.db.commit()
		old_name = todo.name
		new_name = f"{old_name}-renamed"
		self.addCleanup(lambda: frappe.delete_doc("ToDo", new_name, force=True, ignore_permissions=True))

		from frappe.model.rename_doc import rename_doc

		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			rename_doc(doctype="ToDo", old=old_name, new=new_name, ignore_permissions=True)
		frappe.db.after_commit.run()

		lines = self._read_lines(jti, kind="doc")
		self.assertEqual(len(lines), 1)
		self.assertEqual(lines[0]["event"], "rename")
		doc_payload = json.loads(lines[0]["doc"])
		self.assertEqual(doc_payload["old_name"], old_name)
		self.assertEqual(doc_payload["new_name"], new_name)

	def test_request_params_truncated_per_key(self):
		"""One oversized param must not crowd out a small one - each
		top-level key of the request's params is truncated independently."""
		from access_guard.logging_ import log_request
		from access_guard.tests.keys import clear_policy_cache, stub_policy_file

		jti = "log-jti-per-key-truncate"
		sid = self._fake_session(jti)
		path = policy_path()
		original = read_json(path) if os.path.exists(path) else None
		stub_policy_file({"pv": 1, "rules": [], "log_reads": True, "max_key_size_bytes": 20})

		def _restore():
			if original is not None:
				atomic_write_json(path, original)
			elif os.path.exists(path):
				os.remove(path)
			clear_policy_cache()

		self.addCleanup(_restore)

		with patch.object(frappe.local, "session", frappe._dict(sid=sid, user="logtest@example.com")):
			log_request(
				sid,
				"some.whitelisted.method",
				"GET",
				"ok",
				200,
				{"small": "ok", "huge": "x" * 500},
			)

		lines = self._read_lines(jti)
		self.assertEqual(len(lines), 1)
		params = json.loads(lines[0]["params"])
		self.assertEqual(params["small"], "ok")
		self.assertTrue(params["huge"].endswith(_TRUNCATED_MARKER))
		self.assertLessEqual(len(params["huge"].encode("utf-8")), 20)
