"""sync_hourly: policy pull (+ kill-switch/blacklist reaping) is unconditional;
log push/retention are gated on policy.log_sync_enabled."""

import os
from unittest.mock import patch

from frappe.tests.utils import FrappeTestCase

from access_guard.config_utils import logs_dir, policy_path
from access_guard.sync import _push_all_logs, _pushed_meta_path, sync_hourly
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
			patch("access_guard.sync._enforce_retention") as mock_retention,
		):
			sync_hourly()

		mock_reap.assert_called_once()
		mock_push.assert_not_called()
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
			patch("access_guard.sync._enforce_retention") as mock_retention,
		):
			sync_hourly()

		mock_reap.assert_called_once()
		mock_push.assert_called_once()
		mock_retention.assert_called_once()

	def test_no_policy_available_still_runs_log_sync_by_default(self):
		"""No policy ever pulled -> get_policy() falls back to POLICY_DEFAULTS,
		where log_sync_enabled defaults True."""
		with (
			patch("access_guard.sync.pull_policy", return_value=None),
			patch("access_guard.sync.reap_disabled_and_blacklisted") as mock_reap,
			patch("access_guard.sync._push_all_logs") as mock_push,
			patch("access_guard.sync._enforce_retention") as mock_retention,
		):
			sync_hourly()

		mock_reap.assert_not_called()  # no token pulled -> nothing (re)verified
		mock_push.assert_called_once()
		mock_retention.assert_called_once()


class TestPushAllLogsIsIncremental(FrappeTestCase):
	"""A session spans multiple hourly syncs while still active - each sync
	must only send the tail written since the last successful push, or the
	hub's append-only file accumulates duplicate copies of earlier lines."""

	def setUp(self):
		self.jti = f"test-push-incremental-{self._testMethodName}-jti"
		self.log_path = os.path.join(logs_dir(), f"{self.jti}.log")
		self.addCleanup(self._cleanup)

	def _cleanup(self):
		for path in (self.log_path, _pushed_meta_path(self.jti, "request")):
			if os.path.exists(path):
				os.remove(path)

	def test_second_sync_only_sends_lines_written_since_first(self):
		with open(self.log_path, "w") as f:
			f.write("ts=1 path=a\n")

		with patch(
			"access_guard.sync.push_logs", return_value={"ok": True, "received_lines": 1}
		) as mock_push:
			_push_all_logs()

		self.assertEqual(mock_push.call_args.kwargs["lines"], "ts=1 path=a\n")

		with open(self.log_path, "a") as f:
			f.write("ts=2 path=b\n")

		with patch(
			"access_guard.sync.push_logs", return_value={"ok": True, "received_lines": 1}
		) as mock_push:
			_push_all_logs()

		self.assertEqual(mock_push.call_args.kwargs["lines"], "ts=2 path=b\n")

	def test_failed_push_does_not_advance_offset(self):
		with open(self.log_path, "w") as f:
			f.write("ts=1 path=a\n")

		with patch("access_guard.sync.push_logs", return_value=None):
			_push_all_logs()

		with patch(
			"access_guard.sync.push_logs", return_value={"ok": True, "received_lines": 1}
		) as mock_push:
			_push_all_logs()

		# offset never advanced on the failed attempt, so the retry still
		# includes the same content, not an empty tail.
		self.assertEqual(mock_push.call_args.kwargs["lines"], "ts=1 path=a\n")
