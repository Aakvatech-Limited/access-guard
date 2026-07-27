"""mark_jti_used: replay check-and-set, plus the opportunistic pruning of
used-jti entries whose token exp (+ clock-skew leeway) has passed."""

import os
from datetime import timedelta, timezone

import frappe
from frappe.tests.utils import FrappeTestCase

from access_guard.config_utils import atomic_write_json, read_json, used_jti_path
from access_guard.grants import mark_jti_used
from access_guard.protocol import TokenReplayError


def _iso(dt):
	return dt.isoformat()


class TestMarkJtiUsedPrunes(FrappeTestCase):
	def setUp(self):
		self._remove_used_jti_file()
		self.addCleanup(self._remove_used_jti_file)

	def _remove_used_jti_file(self):
		if os.path.exists(used_jti_path()):
			os.remove(used_jti_path())

	def _now(self):
		return frappe.utils.now_datetime().replace(tzinfo=timezone.utc)

	def test_expired_entries_dropped_on_next_mark(self):
		atomic_write_json(
			used_jti_path(),
			{"expired-jti": {"exp": _iso(self._now() - timedelta(hours=1))}},
		)

		mark_jti_used("fresh-jti", exp=_iso(self._now() + timedelta(minutes=2)))

		data = read_json(used_jti_path(), default={})
		self.assertNotIn("expired-jti", data)
		self.assertIn("fresh-jti", data)

	def test_legacy_entry_without_exp_dropped(self):
		"""Entries written before exp-based pruning (bare ISO string, no exp
		key) are treated as immediately prunable - safe, since any token old
		enough to predate this format has long since expired anyway."""
		atomic_write_json(used_jti_path(), {"legacy-jti": "2000-01-01T00:00:00+00:00"})

		mark_jti_used("fresh-jti", exp=_iso(self._now() + timedelta(minutes=2)))

		data = read_json(used_jti_path(), default={})
		self.assertNotIn("legacy-jti", data)
		self.assertIn("fresh-jti", data)

	def test_not_yet_expired_entries_survive(self):
		mark_jti_used("recent-jti", exp=_iso(self._now() + timedelta(minutes=2)))
		mark_jti_used("another-jti", exp=_iso(self._now() + timedelta(minutes=2)))

		data = read_json(used_jti_path(), default={})
		self.assertIn("recent-jti", data)
		self.assertIn("another-jti", data)

	def test_replay_still_rejected_before_prune_runs(self):
		exp = _iso(self._now() + timedelta(minutes=2))
		mark_jti_used("dup-jti", exp=exp)
		with self.assertRaises(TokenReplayError):
			mark_jti_used("dup-jti", exp=exp)
