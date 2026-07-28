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
	"""POST and return the handler's own return value, unwrapped from Frappe's
	`{"message": ...}` envelope (added by frappe.handler for every whitelisted
	call, POST included) - callers check fields the handler returned, e.g.
	sync.py's `result.get("ok")`, which silently never matched while this
	returned the envelope itself.

	`message=` is passed to log_error explicitly: the default (no message)
	makes Frappe fill the body with a variable-dumping traceback, which
	includes this module's `headers` local and requests' `kwargs` - i.e. the
	transport token - into an Error Log row the ephemeral System Manager on
	this very site can read."""
	try:
		resp = requests.post(_hub_url(method), json=payload, headers=_headers(), timeout=timeout)
		resp.raise_for_status()
		data = resp.json()
		return data.get("message", data) if isinstance(data, dict) else data
	except Exception as e:
		frappe.log_error(title=f"access_guard hub_client: {method} failed", message=str(e)[:1000])
		return None


def push_logs(jti: str, log_kind: str, lines: str) -> dict | None:
	return _post("access_hub.api.push_logs", {"jti": jti, "log_kind": log_kind, "lines": lines}, timeout=30)


def report_session_event(jti: str, session_event: str, reason: str | None = None) -> dict | None:
	"""Immediate (not hourly-batched) push of a session lifecycle event, so
	the hub's Access Grant reflects accept/login/logout in near-real-time.
	Always sent - unlike log push, there is no policy opt-out for this.
	Parameter is `session_event`, not `event` - frappe.enqueue() has its own
	same-named `event` kwarg (job-clearing) that steals a plain `event=...`
	before it reaches **kwargs, silently dropping it and dying async with a
	missing-argument TypeError. The wire field name (PROTOCOL.md §5) is
	still "event", just not this function's local parameter name."""
	return _post(
		"access_hub.api.report_session_event",
		{"jti": jti, "event": session_event, "reason": reason},
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
	except Exception as e:
		# message= for the same token-leak reason as _post.
		frappe.log_error(title="access_guard hub_client: pull_policy failed", message=str(e)[:1000])
		return None
