"""Outbound sync scheduler_event (hourly). Policy pull + kill-switch/blacklist
reaping are unconditional (not configurable in v1, and a disable/blacklist
change must always reach a guard). Log push, announce, and retention are
gated on policy.log_sync_enabled. All state referenced here is file-backed,
per PROTOCOL.md/DESIGN.md.
"""

import os
from datetime import datetime

import frappe

from access_guard.config_utils import (
	atomic_write_json,
	logs_dir,
	pushed_dir,
	read_json,
)
from access_guard.grants import read_grant
from access_guard.hub_client import announce, pull_policy, push_logs
from access_guard.policy import get_policy, verify_and_store_policy
from access_guard.protocol import (
	POLICY_LOG_SYNC_ENABLED,
	POLICY_PUSH_GRACE_DAYS,
	POLICY_RETENTION_DAYS,
	PV,
)
from access_guard.reaper import reap_disabled_and_blacklisted


def _pushed_meta_path(jti: str) -> str:
	return os.path.join(pushed_dir(), f"{jti}.meta")


def _mark_pushed(jti: str, received_lines: int) -> None:
	atomic_write_json(
		_pushed_meta_path(jti),
		{
			"acked": True,
			"acked_at": frappe.utils.now_datetime().isoformat(),
			"received_lines": received_lines,
		},
	)


def _is_acked(jti: str) -> bool:
	meta = read_json(_pushed_meta_path(jti), default=None)
	return bool(meta and meta.get("acked"))


def sync_hourly() -> None:
	_pull_and_verify_policy()

	policy = get_policy()
	if not policy.get(POLICY_LOG_SYNC_ENABLED, True):
		return
	_push_all_logs()
	_announce()
	_enforce_retention(policy)


def _push_all_logs() -> None:
	log_dir = logs_dir()
	if not os.path.isdir(log_dir):
		return

	host = frappe.local.site if getattr(frappe.local, "site", None) else frappe.utils.get_url()

	for name in os.listdir(log_dir):
		if not name.endswith(".jsonl"):
			continue
		jti = name[: -len(".jsonl")]
		path = os.path.join(log_dir, name)
		try:
			with open(path) as f:
				ndjson = f.read()
		except OSError:
			continue
		if not ndjson.strip():
			continue

		grant = read_grant(jti) or {}
		session_meta = {
			"emp_email": grant.get("emp_email"),
			"user": grant.get("user"),
			"issued_at": grant.get("issued_at"),
		}
		result = push_logs(jti=jti, host=host, session_meta=session_meta, ndjson=ndjson)
		if result and result.get("ok"):
			_mark_pushed(jti, result.get("received_lines", 0))


def _announce() -> None:
	try:
		url = frappe.utils.get_url()
		parsed_port = 443 if url.startswith("https") else 80
		announce(
			host=frappe.local.site,
			port=parsed_port,
			protocol="https" if url.startswith("https") else "http",
			app_version=frappe.get_attr("access_guard.__version__"),
			pv=PV,
		)
	except Exception:
		frappe.log_error(title="access_guard sync: announce failed")


def _pull_and_verify_policy() -> None:
	token = pull_policy()
	if not token:
		return
	try:
		verify_and_store_policy(token)
	except Exception:
		frappe.log_error(title="access_guard sync: policy verification failed")
		return
	reap_disabled_and_blacklisted()


def _enforce_retention(policy: dict) -> None:
	retention_days = int(policy.get(POLICY_RETENTION_DAYS) or 365)
	grace_days = int(policy.get(POLICY_PUSH_GRACE_DAYS) or 7)

	log_dir = logs_dir()
	if not os.path.isdir(log_dir):
		return

	now = frappe.utils.now_datetime()
	for name in os.listdir(log_dir):
		if not name.endswith(".jsonl"):
			continue
		jti = name[: -len(".jsonl")]
		path = os.path.join(log_dir, name)
		try:
			mtime = datetime.fromtimestamp(os.path.getmtime(path))
		except OSError:
			continue
		age_days = (now - mtime).days

		acked = _is_acked(jti)
		if (acked and age_days > grace_days) or age_days > retention_days:
			try:
				os.remove(path)
			except FileNotFoundError:
				pass
			meta_path = _pushed_meta_path(jti)
			try:
				os.remove(meta_path)
			except FileNotFoundError:
				pass
