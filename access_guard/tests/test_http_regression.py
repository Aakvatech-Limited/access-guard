"""Regression coverage for the class of bug that only reproduces over a real
HTTP request, never via direct Python calls: frappe.whitelist() runs every
wrapped function through validate_argument_types() -> transform_parameter_types()
during real request dispatch, which direct calls (fn(...) in Python, as every
other test module here does) never exercise. Mirrors access_hub's
TestIngestEndpointsOverRealHttp (access_hub/tests/test_protocol_flows.py)."""

import base64
import json
import os
from datetime import datetime, timedelta, timezone

import frappe
from frappe.installer import get_site_config_path, update_site_config
from frappe.tests.utils import FrappeTestCase

from access_guard.tests.keys import TestKeypair

TRANSPORT_TOKEN = "http-regression-transport-token-1"


def _decode_claims(token: str) -> dict:
	"""Decode without verifying (test-only convenience, mirrors
	test_accept.py -- the token was minted by the test itself)."""
	payload_b64 = token.split(".")[2]
	padded = payload_b64 + "=" * (-len(payload_b64) % 4)
	raw = base64.urlsafe_b64decode(padded)
	return json.loads(raw[:-64])  # PASETO v4.public payload = message || 64-byte signature


class TestGuestEndpointsOverRealHttp(FrappeTestCase):
	"""Every test here drives a real HTTP request through frappe.app.application,
	which auto-commits (frappe/app.py's request teardown) and — for accept() —
	performs a real programmatic login that mutates process-global
	frappe.local.session/login_manager. Clean up explicitly; FrappeTestCase's
	class-level rollback can't undo either effect.

	frappe.app.application's request setup calls frappe.init(..., force=True),
	which reassigns frappe.conf from a fresh read of site_config.json -- so
	patch.dict(frappe.conf, ...) (test_accept.py's pattern for direct calls)
	is discarded before the handler ever runs. Write the guard conf keys to
	the real site_config.json for the duration of each test instead, and
	restore the exact original file content on cleanup (update_site_config's
	"delete" sentinel is the string "None", not Python None -- passing None
	just writes a JSON null, so restoring the raw snapshot is the only way
	back to "key absent").
	"""

	def setUp(self):
		self.keypair = TestKeypair()
		self._created_users = []
		self.addCleanup(self._cleanup_users)

		self._orig_session = getattr(frappe.local, "session", None)
		self._orig_login_manager = getattr(frappe.local, "login_manager", None)
		self.addCleanup(self._restore_session)

		# A real HTTP request leaves frappe.local.form_dict/request populated
		# (cmd=<the method just called>) -- nothing resets them between test
		# methods outside a real request cycle, so a later direct-call test
		# in another module that reads frappe.form_dict.get("cmd") (e.g.
		# request_hooks._resolve_method_name) would otherwise see this
		# test's method name instead of its own.
		self._orig_form_dict = getattr(frappe.local, "form_dict", None)
		self._orig_request = getattr(frappe.local, "request", None)
		self.addCleanup(self._restore_request_globals)

		config_path = get_site_config_path()
		with open(config_path) as f:
			original_config = f.read()
		self.addCleanup(self._restore_site_config, config_path, original_config)

		update_site_config("access_guard_hub_url", "https://hub.example.com")
		update_site_config("access_guard_hub_public_key", self.keypair.public_paserk)
		update_site_config("access_guard_transport_token", TRANSPORT_TOKEN)

	@staticmethod
	def _restore_site_config(config_path, original_config):
		with open(config_path, "w") as f:
			f.write(original_config)

	def _restore_session(self):
		frappe.local.session = self._orig_session
		frappe.local.login_manager = self._orig_login_manager

	def _restore_request_globals(self):
		frappe.local.form_dict = self._orig_form_dict
		frappe.local.request = self._orig_request
		if hasattr(frappe.local, "access_guard_request_method"):
			del frappe.local.access_guard_request_method

	def _cleanup_users(self):
		for user in self._created_users:
			if frappe.db.exists("User", user):
				frappe.delete_doc("User", user, force=True, ignore_permissions=True)
		frappe.db.commit()

	def _client(self):
		import frappe.app
		from werkzeug.test import Client

		return Client(frappe.app.application)

	def _post(self, method, body: bytes):
		headers = {"Host": "guard.localhost", "Content-Type": "application/json"}
		return self._client().post(f"/api/method/{method}", headers=headers, data=body)

	def test_accept_valid_token_over_http_redirects(self):
		token = self.keypair.mint_grant_token(
			emp_email="http-accept@example.com", transport_token=TRANSPORT_TOKEN
		)
		self._created_users.append("http-accept@example.com")
		self.addCleanup(self._delete_grant_artifacts, _decode_claims(token)["jti"])
		body = json.dumps({"token": token}).encode()
		resp = self._post("access_guard.api.accept", body)

		# accept() sets a redirect into the app (get_default_path()-based, not a
		# hardcoded path); werkzeug.test.Client doesn't follow redirects.
		self.assertEqual(resp.status_code, 302)
		self.assertTrue(resp.headers.get("Location", "").startswith("/"))
		self.assertTrue(frappe.db.exists("User", "http-accept@example.com"))

	@staticmethod
	def _delete_grant_artifacts(jti):
		from access_guard.config_utils import atomic_write_json, read_json, used_jti_path
		from access_guard.grants import delete_grant
		from access_guard.logging_ import log_file_path

		delete_grant(jti)
		used = read_json(used_jti_path(), default={})
		if jti in used:
			del used[jti]
			atomic_write_json(used_jti_path(), used)
		for kind in ("request", "doc"):
			log_path = log_file_path(jti, kind)
			if os.path.exists(log_path):
				os.remove(log_path)

	def test_accept_malformed_token_over_http_returns_error_shape_not_crash(self):
		body = json.dumps({"token": "not-a-real-paseto-token"}).encode()
		resp = self._post("access_guard.api.accept", body)

		# A signature-introspection bug in the whitelist wrapper manifests as
		# an unhandled 500 with no "error" key -- distinct from the intended
		# AccessProtocolError JSON response, which is what this must get.
		self.assertEqual(resp.status_code, 400)
		payload = json.loads(resp.get_data(as_text=True))
		self.assertEqual(payload.get("error", {}).get("code"), "token_malformed")

	def test_receive_policy_valid_token_over_http(self):
		# receive_policy() overwrites the shared on-disk policy.json for real
		# -- snapshot/restore it so this test can't leak policy state into
		# other test modules that read get_policy().
		self.addCleanup(self._restore_policy_file, self._snapshot_policy_file())

		# mint_policy_token() doesn't set exp by default; verify_and_decode
		# requires one (TokenMalformedError otherwise) -- supply one via the
		# policy override.
		exp = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
		policy_token = self.keypair.mint_policy_token(policy={"exp": exp})
		body = json.dumps({"policy_token": policy_token}).encode()
		resp = self._post("access_guard.api.receive_policy", body)

		self.assertEqual(resp.status_code, 200)
		payload = json.loads(resp.get_data(as_text=True))
		self.assertTrue(payload.get("message", {}).get("ok"))

	@staticmethod
	def _snapshot_policy_file():
		from access_guard.config_utils import policy_path

		path = policy_path()
		if os.path.exists(path):
			with open(path) as f:
				return path, f.read()
		return path, None

	@staticmethod
	def _restore_policy_file(snapshot):
		path, original = snapshot
		if original is None:
			if os.path.exists(path):
				os.remove(path)
		else:
			with open(path, "w") as f:
				f.write(original)

	def test_receive_policy_bad_signature_over_http_returns_error_shape_not_crash(self):
		policy_token = self.keypair.mint_policy_token()
		tampered = self.keypair.tamper(policy_token)
		body = json.dumps({"policy_token": tampered}).encode()
		resp = self._post("access_guard.api.receive_policy", body)

		self.assertEqual(resp.status_code, 401)
		payload = json.loads(resp.get_data(as_text=True))
		self.assertEqual(payload.get("error", {}).get("code"), "token_bad_signature")
