"""Outbound client -> hub channel (PROTOCOL.md §5, DESIGN.md "channel").

All calls are best-effort from the guard's perspective except where noted;
a failure here must never raise into a request/response cycle that isn't
itself the sync job (e.g. report_provisioning from the reaper should not
blow up the reaper if the hub is briefly unreachable).
"""

from __future__ import annotations

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


def push_logs(jti: str, host: str, session_meta: dict, ndjson: str) -> dict | None:
    return _post(
        "access_hub.api.push_logs",
        {"jti": jti, "host": host, "session_meta": session_meta, "ndjson": ndjson},
    )


def announce(host: str, port: int, protocol: str, app_version: str, pv: int) -> dict | None:
    return _post(
        "access_hub.api.announce",
        {"host": host, "port": port, "protocol": protocol, "app_version": app_version, "pv": pv},
    )


def report_provisioning(jti: str, event: str, user: str | None, ts: str | None = None) -> dict | None:
    ts = ts or frappe.utils.now_datetime().isoformat()
    return _post(
        "access_hub.api.report_provisioning",
        {"jti": jti, "event": event, "user": user, "ts": ts},
    )


def pull_policy() -> str | None:
    """GET the signed policy token from the hub. Returns the raw token
    string (still needs verification by the caller — access_guard.policy)."""
    try:
        base = get_guard_conf()["access_guard_hub_url"].rstrip("/")
        resp = requests.get(
            f"{base}/api/method/access_hub.api.get_policy", headers=_headers(), timeout=15
        )
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
