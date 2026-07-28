"""sync_hourly: policy pull (+ kill-switch/blacklist reaping) is unconditional;
log push/retention are gated on policy.log_sync_enabled."""

import os
from unittest.mock import patch

import frappe
from frappe.tests.utils import FrappeTestCase

from access_guard.config_utils import logs_dir, policy_path
from access_guard.protocol import MAX_PUSH_BYTES
from access_guard.sync import _push_all_logs, _pushed_bytes, _pushed_meta_path, _split_chunks, sync_hourly
from access_guard.tests.keys import TestKeypair, clear_policy_cache


class TestSyncHourly(FrappeTestCase):
	def setUp(self):
		self.keypair = TestKeypair()
		self._remove_policy_file()
		self.addCleanup(self._remove_policy_file)

	def _remove_policy_file(self):
		if os.path.exists(policy_path()):
			os.remove(policy_path())
		clear_policy_cache()

	def test_policy_pull_and_reap_run_even_when_log_sync_disabled(self):
		token = self.keypair.mint_policy_token(
			policy={"rules": [], "log_sync_enabled": False, "access_disabled": False}
		)

		with (
			patch("access_guard.sync.pull_policy", return_value=token),
			patch.dict(frappe.conf, {"access_guard_hub_public_key": self.keypair.public_paserk}),
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
			patch.dict(frappe.conf, {"access_guard_hub_public_key": self.keypair.public_paserk}),
			patch("access_guard.sync.reap_disabled_and_blacklisted") as mock_reap,
			patch("access_guard.sync._push_all_logs") as mock_push,
			patch("access_guard.sync._enforce_retention") as mock_retention,
		):
			sync_hourly()

		mock_reap.assert_called_once()
		mock_push.assert_called_once()
		mock_retention.assert_called_once()

	def test_no_policy_available_still_runs_log_sync_by_default(self):
		"""No policy ever pulled and none cached -> get_policy() would raise
		PolicyUnavailableError, but this test's guard.localhost site_config
		points at a real hub.localhost, so pull_policy() actually succeeds
		against it - not a fully isolated unit test."""
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
		self.log_path = os.path.join(logs_dir(), f"{self.jti}.request.log")
		self.addCleanup(self._cleanup)

	def _cleanup(self):
		for path in (self.log_path, _pushed_meta_path(self.jti, "request")):
			if os.path.exists(path):
				os.remove(path)

	def _call_for_this_jti(self, mock_push):
		"""_push_all_logs() scans the whole logs_dir(), so other tests'
		leftover files (if any weren't cleaned up) get pushed too in the
		same call - find the one call for THIS test's jti rather than
		assuming it's the only or the last one."""
		for call in mock_push.call_args_list:
			if call.kwargs.get("jti") == self.jti:
				return call
		self.fail(f"push_logs was never called for jti={self.jti!r}")

	def test_second_sync_only_sends_lines_written_since_first(self):
		with open(self.log_path, "w") as f:
			f.write("ts=1 path=a\n")

		with patch(
			"access_guard.sync.push_logs", return_value={"ok": True, "received_lines": 1}
		) as mock_push:
			_push_all_logs()

		self.assertEqual(self._call_for_this_jti(mock_push).kwargs["lines"], "ts=1 path=a\n")

		with open(self.log_path, "a") as f:
			f.write("ts=2 path=b\n")

		with patch(
			"access_guard.sync.push_logs", return_value={"ok": True, "received_lines": 1}
		) as mock_push:
			_push_all_logs()

		self.assertEqual(self._call_for_this_jti(mock_push).kwargs["lines"], "ts=2 path=b\n")

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
		self.assertEqual(self._call_for_this_jti(mock_push).kwargs["lines"], "ts=1 path=a\n")

	def _calls_for_this_jti(self, mock_push):
		return [c for c in mock_push.call_args_list if c.kwargs.get("jti") == self.jti]

	def test_tail_over_the_cap_is_chunked_not_sent_whole(self):
		"""The hub rejects anything over MAX_PUSH_BYTES outright, so an
		unchunked oversized tail would be refused forever and the offset would
		never advance - the file stalls until retention deletes it unpushed."""
		line = "y" * 1023 + "\n"
		lines_per_chunk = MAX_PUSH_BYTES // len(line)
		with open(self.log_path, "w") as f:
			f.write(line * (lines_per_chunk + 10))  # just over one chunk
		total = os.path.getsize(self.log_path)

		with patch(
			"access_guard.sync.push_logs", return_value={"ok": True, "received_lines": 1}
		) as mock_push:
			_push_all_logs()

		calls = self._calls_for_this_jti(mock_push)
		self.assertGreater(len(calls), 1, "oversized tail must be split across calls")
		for call in calls:
			self.assertLessEqual(len(call.kwargs["lines"].encode()), MAX_PUSH_BYTES)
		# Reassembles to exactly the file, and the offset lands at EOF.
		self.assertEqual("".join(c.kwargs["lines"] for c in calls), line * (lines_per_chunk + 10))
		self.assertEqual(_pushed_bytes(self.jti, "request"), total)

	def test_failure_midway_keeps_the_chunks_that_landed(self):
		"""Per-chunk offset advance: a failure on chunk 2 must not re-send
		chunk 1 next run (the hub appends, so that would duplicate lines)."""
		line = "z" * 1023 + "\n"
		lines_per_chunk = MAX_PUSH_BYTES // len(line)
		with open(self.log_path, "w") as f:
			f.write(line * (lines_per_chunk + 10))

		first_ok = [{"ok": True, "received_lines": 1}, None]  # chunk 1 ok, chunk 2 fails
		with patch("access_guard.sync.push_logs", side_effect=first_ok) as mock_push:
			_push_all_logs()
		landed = len(self._calls_for_this_jti(mock_push)[0].kwargs["lines"].encode())
		self.assertEqual(_pushed_bytes(self.jti, "request"), landed)

		with patch(
			"access_guard.sync.push_logs", return_value={"ok": True, "received_lines": 1}
		) as mock_push:
			_push_all_logs()

		resumed = self._calls_for_this_jti(mock_push)
		self.assertTrue(resumed, "must resume the unpushed remainder")
		# Resumes exactly where it stopped - no overlap with what already landed.
		self.assertEqual(_pushed_bytes(self.jti, "request"), os.path.getsize(self.log_path))

	def test_oversized_line_is_truncated_and_the_offset_still_clears_it(self):
		"""A single line over the cap has no boundary to split on. It's truncated
		to fit, and the offset advances past the WHOLE source line - otherwise the
		file would stall on it forever."""
		with open(self.log_path, "w") as f:
			f.write("x" * (MAX_PUSH_BYTES + 100) + "\n")
			f.write("ts=after path=ok\n")

		with patch(
			"access_guard.sync.push_logs", return_value={"ok": True, "received_lines": 1}
		) as mock_push:
			_push_all_logs()

		sent = [c.kwargs["lines"] for c in self._calls_for_this_jti(mock_push)]
		for payload in sent:
			self.assertLessEqual(len(payload.encode()), MAX_PUSH_BYTES)
		self.assertIn("ts=after path=ok\n", sent[-1], "lines after the huge one still get pushed")
		self.assertEqual(_pushed_bytes(self.jti, "request"), os.path.getsize(self.log_path))


class TestSplitChunks(FrappeTestCase):
	def _blob(self, chunks):
		return b"".join(chunk for chunk, _ in chunks)

	def test_splits_only_on_line_boundaries(self):
		line = b"a" * 100 + b"\n"
		chunks = _split_chunks(line * 5)
		self.assertEqual(self._blob(chunks), line * 5)
		for chunk, _ in chunks:
			self.assertTrue(chunk.endswith(b"\n"))

	def test_small_input_is_one_chunk(self):
		self.assertEqual(_split_chunks(b"one\ntwo\n"), [(b"one\ntwo\n", 8)])

	def test_empty_input_is_no_chunks(self):
		self.assertEqual(_split_chunks(b""), [])

	def test_exactly_at_the_cap_stays_one_chunk(self):
		"""Boundary: == cap is allowed (the hub rejects only > cap), so this
		must not split into a needless second call."""
		blob = b"b" * (MAX_PUSH_BYTES - 1) + b"\n"
		self.assertEqual(len(_split_chunks(blob)), 1)

	def test_no_chunk_ever_exceeds_the_cap(self):
		line = b"c" * 999 + b"\n"
		blob = line * ((MAX_PUSH_BYTES // len(line)) * 2 + 7)
		chunks = _split_chunks(blob)
		self.assertGreater(len(chunks), 2)
		self.assertEqual(self._blob(chunks), blob)
		for chunk, _ in chunks:
			self.assertLessEqual(len(chunk), MAX_PUSH_BYTES)

	def test_source_bytes_always_sums_to_the_input_length(self):
		"""The caller advances its file offset by source_bytes, so this sum must
		equal the input exactly or the offset drifts and lines are re-sent or
		skipped."""
		line = b"e" * 511 + b"\n"
		for blob in (b"", b"one\n", line * 3, line * (MAX_PUSH_BYTES // len(line) + 5)):
			self.assertEqual(sum(n for _, n in _split_chunks(blob)), len(blob))

	def test_oversized_line_is_truncated_but_fully_consumed(self):
		"""Truncated to the cap, yet source_bytes covers the whole original line -
		that's what lets the caller skip past it instead of stalling."""
		big = b"d" * (MAX_PUSH_BYTES + 10) + b"\n"
		chunks = _split_chunks(b"before\n" + big + b"after\n")
		for chunk, _ in chunks:
			self.assertLessEqual(len(chunk), MAX_PUSH_BYTES)
		self.assertEqual(sum(n for _, n in chunks), len(b"before\n" + big + b"after\n"))
		self.assertEqual(chunks[0][0], b"before\n")
		self.assertEqual(chunks[-1][0], b"after\n")
