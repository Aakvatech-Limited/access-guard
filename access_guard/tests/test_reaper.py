"""Tests for the reaper: idle-expired grants get their user+sessions
deleted; a real (non-ephemeral) client user is never touched — namespace
filter is strictly "users named in grant files"."""

import os
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from access_guard.config_utils import atomic_write_json, policy_path, read_json
from access_guard.grants import delete_grant, read_grant, write_grant
from access_guard.protocol import utc_iso
from access_guard.reaper import reap_disabled_and_blacklisted, reap_idle_sessions
from access_guard.tests.keys import isolate_policy_from_hub


class TestReaper(FrappeTestCase):
	def setUp(self):
		isolate_policy_from_hub(self)
		self._users_to_clean = []
		self._jtis_to_clean = []
		self._sids_to_clean = []
		self.addCleanup(self._cleanup)

	def _cleanup(self):
		for jti in self._jtis_to_clean:
			delete_grant(jti)
		for user in self._users_to_clean:
			if frappe.db.exists("User", user):
				frappe.delete_doc("User", user, force=True, ignore_permissions=True)
		for sid in self._sids_to_clean:
			frappe.db.sql("DELETE FROM `tabSessions` WHERE sid=%s", sid)
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

	def _session_exists(self, sid) -> bool:
		"""Raw count, NOT frappe.db.exists("Sessions", ...) - tabSessions has no
		`name` column, so exists() selects nothing and always returns None. An
		assertFalse on it passes vacuously whether the row is there or not."""
		return bool(frappe.db.sql("SELECT COUNT(*) FROM `tabSessions` WHERE sid=%s", sid)[0][0])

	def _make_session_row(self, user, sid, lastupdate):
		self._sids_to_clean.append(sid)
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
				"user_name": "Reap Target",
				"user_email": email,
				"user": user,
				"sid": sid,
				"issued_at": utc_iso(),
			},
		)

		with patch("frappe.enqueue"):
			reap_idle_sessions()

		self.assertFalse(frappe.db.exists("User", email), "ephemeral user should be reaped")
		self.assertIsNone(read_grant(jti), "grant file should be removed after reap")
		self.assertFalse(self._session_exists(sid), "session row should be deleted")

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

		with patch("frappe.enqueue"):
			reap_idle_sessions()

		self.assertTrue(frappe.db.exists("User", email), "real client user must never be reaped")
		self.assertTrue(self._session_exists(sid), "real client session must never be killed")

	def _write_policy(self, policy: dict):
		"""Stub POLICY_FILE (bypassing signature verification) and bust the cache.

		The original is captured on the FIRST call only and restored once. Calling
		this twice in one test used to snapshot the first stub as the second's
		"original", so a restore could write a stub back over the site's real
		policy file and leak into later tests."""
		from access_guard.tests.keys import clear_policy_cache, isolate_policy_from_hub

		path = policy_path()
		if not hasattr(self, "_policy_restored"):
			original = read_json(path) if os.path.exists(path) else None

			def _restore():
				if original is not None:
					atomic_write_json(path, original)
				elif os.path.exists(path):
					os.remove(path)
				clear_policy_cache()

			self.addCleanup(_restore)
			self._policy_restored = True

		atomic_write_json(path, {"policy": policy, "verified_at": utc_iso()})
		clear_policy_cache()

	def _make_live_grant(self, email, jti, sid):
		user = self._make_ephemeral_user(email)
		self._jtis_to_clean.append(jti)
		self._make_session_row(user, sid, frappe.utils.now_datetime())
		write_grant(
			jti,
			{
				"jti": jti,
				"pv": 1,
				"user_name": "Reap Target",
				"user_email": email,
				"user": user,
				"sid": sid,
				"issued_at": utc_iso(),
			},
		)
		return user

	def test_access_disabled_reaps_every_live_grant(self):
		email = "kill-switch-target@example.com"
		jti, sid = "kill-switch-jti-1", "kill-switch-sid-1"
		self._make_live_grant(email, jti, sid)
		self._write_policy({"pv": 1, "rules": [], "access_disabled": True})

		with patch("frappe.enqueue"):
			reap_disabled_and_blacklisted()

		self.assertFalse(frappe.db.exists("User", email), "access_disabled must reap live grants")
		self.assertIsNone(read_grant(jti))
		self.assertFalse(self._session_exists(sid))

	def test_blacklisted_email_is_reaped_others_untouched(self):
		blacklisted_email = "blacklisted-target@example.com"
		safe_email = "not-blacklisted@example.com"
		b_jti, b_sid = "blacklist-jti-1", "blacklist-sid-1"
		s_jti, s_sid = "blacklist-jti-2", "blacklist-sid-2"
		self._make_live_grant(blacklisted_email, b_jti, b_sid)
		self._make_live_grant(safe_email, s_jti, s_sid)
		self._write_policy(
			{"pv": 1, "rules": [], "access_disabled": False, "blacklisted_emails": [blacklisted_email]}
		)

		with patch("frappe.enqueue"):
			reap_disabled_and_blacklisted()

		self.assertFalse(frappe.db.exists("User", blacklisted_email), "blacklisted user must be reaped")
		self.assertIsNone(read_grant(b_jti))
		self.assertTrue(frappe.db.exists("User", safe_email), "non-blacklisted user must be untouched")
		self.assertIsNotNone(read_grant(s_jti))

	def test_expiry_zero_adds_no_idle_window(self):
		"""expiry 0 = "add no limit of our own": a long-idle session is left for
		Frappe's own expiry to kill, not reaped here."""
		email = "expiry-zero-live@example.com"
		jti, sid = "expiry-zero-jti-1", "expiry-zero-sid-1"
		user = self._make_ephemeral_user(email)
		self._jtis_to_clean.append(jti)
		old_time = frappe.utils.add_to_date(frappe.utils.now_datetime(), hours=-100)
		self._make_session_row(user, sid, old_time)
		write_grant(jti, {"jti": jti, "pv": 1, "user": user, "sid": sid, "issued_at": utc_iso()})
		self._write_policy({"pv": 1, "rules": [], "session_expiry_seconds": 0})

		with patch("frappe.enqueue"):
			reap_idle_sessions()

		self.assertTrue(frappe.db.exists("User", email), "expiry 0 must not idle-kill")
		self.assertIsNotNone(read_grant(jti))
		self.assertTrue(self._session_exists(sid))

	def test_expiry_zero_still_deletes_user_once_session_is_gone(self):
		"""The reap is not gated on the idle window: whoever ended the session
		(here: Frappe, simulated by no session row at all), the grant is dropped
		and the ephemeral User deleted."""
		email = "expiry-zero-dead@example.com"
		jti = "expiry-zero-jti-2"
		user = self._make_ephemeral_user(email)
		self._jtis_to_clean.append(jti)
		write_grant(
			jti, {"jti": jti, "pv": 1, "user": user, "sid": "already-gone-sid", "issued_at": utc_iso()}
		)
		self._write_policy({"pv": 1, "rules": [], "session_expiry_seconds": 0})

		with patch("frappe.enqueue"):
			reap_idle_sessions()

		self.assertFalse(frappe.db.exists("User", email), "user must be deleted regardless of expiry 0")
		self.assertIsNone(read_grant(jti))

	def test_no_disabled_or_blacklist_is_a_noop(self):
		email = "unaffected@example.com"
		jti, sid = "noop-jti-1", "noop-sid-1"
		self._make_live_grant(email, jti, sid)
		self._write_policy({"pv": 1, "rules": [], "access_disabled": False, "blacklisted_emails": []})

		with patch("frappe.enqueue"):
			reap_disabled_and_blacklisted()

		self.assertTrue(frappe.db.exists("User", email))
		self.assertIsNotNone(read_grant(jti))
