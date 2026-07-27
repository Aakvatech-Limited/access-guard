"""Tests for the grant acceptance endpoint (api.accept) and the token
verification order mandated by PROTOCOL.md §3."""

import json
import os
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from access_guard.config_utils import atomic_write_json, policy_path
from access_guard.grants import read_grant
from access_guard.protocol import (
	POLICY_DEFAULTS,
	ClientNotConfiguredError,
	EphemeralUserCollisionError,
	ProtocolVersionError,
	TokenAudienceError,
	TokenExpiredError,
	TokenReplayError,
	TokenSignatureError,
)
from access_guard.tests.keys import TestKeypair

TRANSPORT_TOKEN = "test-transport-token-12345"


def _conf(keypair: TestKeypair, **overrides):
	conf = {
		"access_guard_hub_url": "https://hub.example.com",
		"access_guard_hub_public_key": keypair.public_paserk,
		"access_guard_transport_token": TRANSPORT_TOKEN,
	}
	conf.update(overrides)
	return conf


class TestAccept(FrappeTestCase):
	def setUp(self):
		self.keypair = TestKeypair()
		self.addCleanup(self._cleanup_users)
		self._created_users = []

		# accept() calls get_policy(), which raises PolicyUnavailableError
		# rather than silently falling back to defaults if nothing is
		# cached - stub an already-verified policy file directly (bypassing
		# signature verification, which needs frappe.conf patched with this
		# keypair - each test does that itself, scoped narrower than setUp).
		atomic_write_json(
			policy_path(),
			{
				"token": "n/a",
				"policy": dict(POLICY_DEFAULTS),
				"verified_at": frappe.utils.now_datetime().isoformat(),
			},
		)
		self.addCleanup(self._remove_policy_file)

		# accept()/reaper flows call log_session_event(), which enqueues a
		# push to the hub via frappe.enqueue - avoid every test actually
		# queuing/running that job.
		patcher = patch("frappe.enqueue")
		patcher.start()
		self.addCleanup(patcher.stop)

		# accept() performs a REAL programmatic login via LoginManager,
		# which mutates process-global frappe.local.session/login_manager
		# for the rest of this worker -- restore both after every test so
		# a login here can't leak into later tests (e.g. session_guard
		# treating a later test's real User.insert() as ephemeral-session
		# activity because frappe.session.sid still equals the sid this
		# test's accept() call set).
		self._orig_session = getattr(frappe.local, "session", None)
		self._orig_login_manager = getattr(frappe.local, "login_manager", None)
		self.addCleanup(self._restore_session)

	def _restore_session(self):
		frappe.local.session = self._orig_session
		frappe.local.login_manager = self._orig_login_manager

	def _remove_policy_file(self):
		if os.path.exists(policy_path()):
			os.remove(policy_path())

	def _cleanup_users(self):
		for user in self._created_users:
			if frappe.db.exists("User", user):
				frappe.delete_doc("User", user, force=True, ignore_permissions=True)
		frappe.db.commit()

	def _call_accept(self, token):
		# accept() performs a real programmatic login (LoginManager), which
		# needs frappe.local.request to exist (it reads request.path) --
		# set up a throwaway GET request context like the real endpoint
		# would have.
		from frappe.auth import CookieManager

		from access_guard.api import accept

		frappe.utils.set_request(method="GET", path="/api/method/access_guard.api.accept")
		frappe.local.cookie_manager = CookieManager()
		# Each real HTTP request gets a fresh response; mirror that so a prior
		# call's error/redirect can't leak into this one's assertions.
		frappe.local.response = frappe._dict()
		return accept(token=token)

	def test_valid_token_creates_user_and_grant_file(self):
		token = self.keypair.mint_grant_token(
			emp_name="Jane Doe", emp_email="jane.doe@example.com", transport_token=TRANSPORT_TOKEN
		)
		with patch.dict(frappe.conf, _conf(self.keypair)):
			self._call_accept(token)
		self._created_users.append("jane.doe@example.com")

		self.assertTrue(frappe.db.exists("User", "jane.doe@example.com"))
		user_doc = frappe.get_doc("User", "jane.doe@example.com")
		self.assertIn("(consultant)", user_doc.last_name)
		self.assertEqual(user_doc.full_name, "Jane Doe (consultant)")
		from frappe.core.doctype.user.user import get_all_roles

		granted_roles = {r.role for r in user_doc.roles}
		self.assertEqual(granted_roles, set(get_all_roles()))
		self.assertIn("System Manager", granted_roles)

		claims = _decode_claims_for_test(token)
		jti = claims["jti"]
		record = read_grant(jti)
		self.assertIsNotNone(record)
		self.assertEqual(record["user"], "jane.doe@example.com")
		self.assertIsNotNone(record["sid"])
		self.assertEqual(record["emp_email"], "jane.doe@example.com")

	def test_replay_second_use_rejected(self):
		token = self.keypair.mint_grant_token(emp_email="replay@example.com")
		with patch.dict(frappe.conf, _conf(self.keypair)):
			self._call_accept(token)
		self._created_users.append("replay@example.com")

		with patch.dict(frappe.conf, _conf(self.keypair)):
			self._call_accept(token)

		self.assertEqual(frappe.local.response.get("error", {}).get("code"), TokenReplayError.code)
		self.assertEqual(frappe.local.response.get("http_status_code"), TokenReplayError.http_status)

	def test_replay_survives_with_used_jti_file_only(self):
		"""Replay protection must hold even if we simulate the used-jti
		file being the only surviving state (no reliance on any DB row)."""
		token = self.keypair.mint_grant_token(emp_email="replay2@example.com")
		with patch.dict(frappe.conf, _conf(self.keypair)):
			self._call_accept(token)
		self._created_users.append("replay2@example.com")

		# Delete the ephemeral user + grant file to simulate "only the
		# used-jti store survives" — replay must still be rejected.
		claims = _decode_claims_for_test(token)
		jti = claims["jti"]
		from access_guard.grants import delete_grant

		delete_grant(jti)
		if frappe.db.exists("User", "replay2@example.com"):
			frappe.delete_doc("User", "replay2@example.com", force=True, ignore_permissions=True)
			frappe.db.commit()

		with patch.dict(frappe.conf, _conf(self.keypair)):
			self._call_accept(token)

		self.assertEqual(frappe.local.response.get("error", {}).get("code"), TokenReplayError.code)

	def test_expired_token_rejected(self):
		token = self.keypair.mint_grant_token(
			emp_email="expired@example.com", ttl_seconds=1, issued_delta_seconds=-3600
		)
		with patch.dict(frappe.conf, _conf(self.keypair)):
			self._call_accept(token)

		self.assertEqual(frappe.local.response.get("error", {}).get("code"), TokenExpiredError.code)
		self.assertFalse(frappe.db.exists("User", "expired@example.com"))

	def test_tampered_token_rejected(self):
		token = self.keypair.mint_grant_token(emp_email="tampered@example.com")
		tampered = self.keypair.tamper(token)
		with patch.dict(frappe.conf, _conf(self.keypair)):
			self._call_accept(tampered)

		self.assertEqual(frappe.local.response.get("error", {}).get("code"), TokenSignatureError.code)

	def test_wrong_audience_rejected(self):
		token = self.keypair.mint_grant_token(
			emp_email="wrongaud@example.com", transport_token="a-different-transport-token"
		)
		with patch.dict(frappe.conf, _conf(self.keypair)):
			self._call_accept(token)

		self.assertEqual(frappe.local.response.get("error", {}).get("code"), TokenAudienceError.code)
		self.assertFalse(frappe.db.exists("User", "wrongaud@example.com"))

	def test_pv_mismatch_rejected(self):
		token = self.keypair.mint_grant_token(emp_email="badpv@example.com", pv=2)
		with patch.dict(frappe.conf, _conf(self.keypair)):
			self._call_accept(token)

		self.assertEqual(frappe.local.response.get("error", {}).get("code"), ProtocolVersionError.code)

	def test_standing_user_collision_rejected(self):
		"""A grant for an email that already belongs to a NON-ephemeral user
		must be refused — no session, no grant file — with a 409 collision."""
		email = "standing.user@example.com"
		standing = frappe.new_doc("User")
		standing.email = email
		standing.first_name = "Standing"
		standing.send_welcome_email = 0
		standing.insert(ignore_permissions=True)
		frappe.db.commit()
		self._created_users.append(email)

		token = self.keypair.mint_grant_token(emp_email=email, transport_token=TRANSPORT_TOKEN)
		with patch.dict(frappe.conf, _conf(self.keypair)):
			self._call_accept(token)

		self.assertEqual(
			frappe.local.response.get("error", {}).get("code"),
			EphemeralUserCollisionError.code,
		)
		self.assertEqual(
			frappe.local.response.get("http_status_code"),
			EphemeralUserCollisionError.http_status,
		)
		# no grant file was written for this jti
		claims = _decode_claims_for_test(token)
		self.assertIsNone(read_grant(claims["jti"]))

	def test_returning_ephemeral_user_reused(self):
		"""A user this guard provisioned (named in a grant file) is reused on a
		second, distinct grant — not treated as a standing-user collision."""
		email = "returning@example.com"
		first = self.keypair.mint_grant_token(emp_email=email, transport_token=TRANSPORT_TOKEN)
		with patch.dict(frappe.conf, _conf(self.keypair)):
			self._call_accept(first)
		self._created_users.append(email)
		self.assertTrue(frappe.db.exists("User", email))

		# A different grant (new jti) for the same, now-ephemeral, email.
		second = self.keypair.mint_grant_token(emp_email=email, transport_token=TRANSPORT_TOKEN)
		with patch.dict(frappe.conf, _conf(self.keypair)):
			self._call_accept(second)

		self.assertIsNone(frappe.local.response.get("error"))
		self.assertEqual(frappe.local.response.get("type"), "redirect")
		from access_guard.grants import delete_grant

		for tok in (first, second):
			delete_grant(_decode_claims_for_test(tok)["jti"])

	def test_missing_config_rejected(self):
		token = self.keypair.mint_grant_token(emp_email="noconf@example.com")
		# Ensure none of the three required keys are present.
		with patch.dict(frappe.conf, {}, clear=False):
			for key in (
				"access_guard_hub_url",
				"access_guard_hub_public_key",
				"access_guard_transport_token",
			):
				frappe.conf.pop(key, None)
			self._call_accept(token)

		self.assertEqual(frappe.local.response.get("error", {}).get("code"), ClientNotConfiguredError.code)


def _decode_claims_for_test(token: str) -> dict:
	"""Decode without verifying (test-only convenience — the token was
	minted by the test itself, so we already know it's well-formed)."""
	parts = token.split(".")
	import base64

	payload_b64 = parts[2]
	padded = payload_b64 + "=" * (-len(payload_b64) % 4)
	raw = base64.urlsafe_b64decode(padded)
	# PASETO v4.public payload = message || signature(64 bytes)
	message = raw[:-64]
	return json.loads(message)
