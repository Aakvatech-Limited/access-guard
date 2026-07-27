"""sync_hourly: policy pull (+ kill-switch/blacklist reaping) is unconditional;
log push/announce/retention are gated on policy.log_sync_enabled."""

import os
from unittest.mock import patch

from frappe.tests.utils import FrappeTestCase

from access_guard.config_utils import policy_path
from access_guard.sync import sync_hourly
from access_guard.tests.keys import TestKeypair


class TestSyncHourly(FrappeTestCase):
	def setUp(self):
		self.keypair = TestKeypair()
		if os.path.exists(policy_path()):
			os.remove(policy_path())
		self.addCleanup(self._remove_policy_file)

	def _remove_policy_file(self):
		if os.path.exists(policy_path()):
			os.remove(policy_path())

	def test_policy_pull_and_reap_run_even_when_log_sync_disabled(self):
		token = self.keypair.mint_policy_token(
			policy={"rules": [], "log_sync_enabled": False, "access_disabled": False}
		)

		with (
			patch("access_guard.sync.pull_policy", return_value=token),
			patch("access_guard.policy._get_public_key", return_value=self.keypair.public_paserk),
			patch("access_guard.sync.reap_disabled_and_blacklisted") as mock_reap,
			patch("access_guard.sync._push_all_logs") as mock_push,
			patch("access_guard.sync._announce") as mock_announce,
			patch("access_guard.sync._enforce_retention") as mock_retention,
		):
			sync_hourly()

		mock_reap.assert_called_once()
		mock_push.assert_not_called()
		mock_announce.assert_not_called()
		mock_retention.assert_not_called()

	def test_log_sync_enabled_runs_the_rest(self):
		token = self.keypair.mint_policy_token(
			policy={"rules": [], "log_sync_enabled": True, "access_disabled": False}
		)

		with (
			patch("access_guard.sync.pull_policy", return_value=token),
			patch("access_guard.policy._get_public_key", return_value=self.keypair.public_paserk),
			patch("access_guard.sync.reap_disabled_and_blacklisted") as mock_reap,
			patch("access_guard.sync._push_all_logs") as mock_push,
			patch("access_guard.sync._announce") as mock_announce,
			patch("access_guard.sync._enforce_retention") as mock_retention,
		):
			sync_hourly()

		mock_reap.assert_called_once()
		mock_push.assert_called_once()
		mock_announce.assert_called_once()
		mock_retention.assert_called_once()

	def test_no_policy_available_still_runs_log_sync_by_default(self):
		"""No policy ever pulled -> get_policy() falls back to POLICY_DEFAULTS,
		where log_sync_enabled defaults True."""
		with (
			patch("access_guard.sync.pull_policy", return_value=None),
			patch("access_guard.sync.reap_disabled_and_blacklisted") as mock_reap,
			patch("access_guard.sync._push_all_logs") as mock_push,
			patch("access_guard.sync._announce") as mock_announce,
			patch("access_guard.sync._enforce_retention") as mock_retention,
		):
			sync_hourly()

		mock_reap.assert_not_called()  # no token pulled -> nothing (re)verified
		mock_push.assert_called_once()
		mock_announce.assert_called_once()
		mock_retention.assert_called_once()
