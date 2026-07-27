"""Outbound client -> hub channel (PROTOCOL.md §5, DESIGN.md "channel").

All calls are best-effort from the guard's perspective except where noted;
a failure here must never raise into a request/response cycle that isn't
itself the sync job (e.g. report_session_event from the reaper should not
blow up the reaper if the hub is briefly unreachable).
"""

import json

import frappe
import requests

from access_guard.config_utils import get_guard_conf
from access_guard.protocol import TRANSPORT_TOKEN_HEADER


def _hub_url(method: str) -> str:
	base = get_guard_conf()["access_guard_hub_url"].rstrip("/")
	return f"{base}/api/method/{method}"


def _headers() -> dict:
	token = get_guard_conf()["access_guard_transport_token"]
	return {TRANSPORT_TOKEN_HEADER: token}


def _post(method: str, payload: dict, timeout: int = 15) -> dict | None:
	try:
		resp = requests.post(_hub_url(method), json=payload, headers=_headers(), timeout=timeout)
		resp.raise_for_status()
		return resp.json()
	except Exception:
		frappe.log_error(title=f"access_guard hub_client: {method} failed")
		return None


def push_logs(jti: str, log_kind: str, lines: str) -> dict | None:
	return _post("access_hub.api.push_logs", {"jti": jti, "log_kind": log_kind, "lines": lines})


def report_session_event(jti: str, event: str, reason: str | None = None) -> dict | None:
	"""Immediate (not hourly-batched) push of a session lifecycle event, so
	the hub's Access Grant reflects accept/login/logout in near-real-time.
	Always sent - unlike log push, there is no policy opt-out for this."""
	return _post(
		"access_hub.api.report_session_event",
		{"jti": jti, "event": event, "reason": reason},
	)


def pull_policy() -> str | None:
	"""GET the signed policy token from the hub. Returns the raw token
	string (still needs verification by the caller — access_guard.policy)."""
	try:
		base = get_guard_conf()["access_guard_hub_url"].rstrip("/")
		resp = requests.get(f"{base}/api/method/access_hub.api.get_policy", headers=_headers(), timeout=15)
		resp.raise_for_status()
		data = resp.json()
		# Frappe whitelisted GET responses are wrapped under "message".
		payload = data.get("message", data)
		if isinstance(payload, str):
			payload = json.loads(payload)
		return payload.get("policy_token")
	except Exception:
		frappe.log_error(title="access_guard hub_client: pull_policy failed")
		return None
