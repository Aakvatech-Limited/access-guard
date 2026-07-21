"""access-protocol — the shared contract between access-hub and access-guard.

This module is intentionally FRAPPE-AGNOSTIC (only stdlib) so it can be imported
in unit tests without a site, and so both apps can vendor an *identical* copy.

VENDORING RULE: this file is duplicated verbatim as
    access_hub/access_hub/protocol.py   (authoritative)
    access_guard/access_guard/protocol.py   (copy)
The guard site does not have access_hub installed, so it cannot import from it —
keep the two copies byte-identical. Any change is a coordinated change to both.
See docs/PROTOCOL.md for the human-readable spec.
"""

from __future__ import annotations

import hashlib

# --- Protocol version -------------------------------------------------------
# Bump on any breaking wire change. v1 supports exactly this value; a mismatch
# is a clean ProtocolVersionError, never a best-effort parse.
PV = 1

# --- site_config.json keys --------------------------------------------------
# Hub (helpdesk) side:
CONF_HUB_PRIVATE_KEY = "access_hub_private_key"  # PASETO v4.public Ed25519 secret (paserk k4.secret)
CONF_HUB_PUBLIC_KEY_LOCAL = "access_hub_public_key"  # paserk k4.public — hub's own copy, for the
# enrollment-help surface (bench command / desk page) so the value survives beyond the one-time
# keygen printout and never needs re-deriving from the secret key.

# Guard (client) side:
CONF_HUB_URL = "access_guard_hub_url"
CONF_HUB_PUBLIC_KEY = "access_guard_hub_public_key"  # paserk k4.public
CONF_TRANSPORT_TOKEN = "access_guard_transport_token"  # min length 8

REQUIRED_GUARD_CONF = (CONF_HUB_URL, CONF_HUB_PUBLIC_KEY, CONF_TRANSPORT_TOKEN)
TRANSPORT_TOKEN_MIN_LEN = 8

# --- Transport header --------------------------------------------------------
# Deliberately NOT the standard `Authorization` header. Frappe's own
# validate_auth() (frappe/auth.py) intercepts any 2-part `Authorization` value
# (e.g. "Bearer <token>") before any whitelisted method — even allow_guest —
# ever runs, and only lets it through via a real session (OAuth/API-key) or a
# registered `auth_hooks` entry. Our transport token is neither, so using
# `Authorization` forced a global auth_hooks registration on the hub just to
# clear that gate (considered and rejected as unnecessary complexity — see
# DESIGN.md). Using a custom header instead means validate_auth() never even
# looks at it (its Authorization-only check is skipped entirely), so no hub
# registration point is needed at all: `ingest_endpoint` is the ONLY place
# this token is ever checked, end to end.
TRANSPORT_TOKEN_HEADER = "X-Access-Guard-Transport-Token"

# --- Grant token claims (PASETO v4.public) ----------------------------------
# Registered claims iat/exp/aud are handled by pyseto. Custom claims below.
CLAIM_EMP_NAME = "emp_name"
CLAIM_EMP_EMAIL = "emp_email"
CLAIM_JTI = "jti"
CLAIM_PV = "pv"
# aud = transport_token_hash(client transport token); exp = iat + GRANT_TTL.
GRANT_TTL_SECONDS_DEFAULT = 45 * 60  # 30-60 min band; URL redemption deadline, NOT session length
CLOCK_SKEW_LEEWAY_SECONDS = 60

# --- Policy document (delivered as a PASETO v4.public token, hub-signed) -----
# The policy token's claims are the object below + iat + pv.
POLICY_RULES = "rules"  # [{doctype, actions:[...], mode:"deny"|"warn"}]
POLICY_SESSION_EXPIRY_SECONDS = "session_expiry_seconds"  # default 6h; effective = min(this, site)
POLICY_ALWAYS_LOG_DOCTYPES = "always_log_doctypes"
POLICY_MAX_KEY_SIZE_BYTES = "max_key_size_bytes"
POLICY_LOG_READS = "log_reads"
POLICY_MONITORING_NOTICE_TEXT = "monitoring_notice_text"
POLICY_SYNC_ENABLED = "sync_enabled"
POLICY_RETENTION_DAYS = "retention_days"
POLICY_PUSH_GRACE_DAYS = "push_grace_days"

MODE_DENY = "deny"
MODE_WARN = "warn"
VALID_MODES = (MODE_DENY, MODE_WARN)
# Frappe canonical permission actions used in rule "actions".
VALID_ACTIONS = ("create", "write", "delete", "submit", "cancel", "read")

POLICY_DEFAULTS = {
    POLICY_RULES: [{"doctype": "User", "actions": ["create", "write", "delete"], "mode": MODE_DENY}],
    POLICY_SESSION_EXPIRY_SECONDS: 6 * 60 * 60,
    POLICY_ALWAYS_LOG_DOCTYPES: ["User", "Server Script"],
    POLICY_MAX_KEY_SIZE_BYTES: 512 * 1024,
    POLICY_LOG_READS: False,
    POLICY_MONITORING_NOTICE_TEXT: "Your activity on this site is being recorded for audit.",
    POLICY_SYNC_ENABLED: True,
    POLICY_RETENTION_DAYS: 365,
    POLICY_PUSH_GRACE_DAYS: 7,
}

# --- Logging ----------------------------------------------------------------
LOG_TYPE_SESSION = "session"  # lifecycle: accepted / login / logout
LOG_TYPE_REQUEST = "request"  # a whitelisted method call (every attempt, minus reads)
LOG_TYPE_DOC = "doc"  # committed change to an always-log doctype (after_commit)

# Methods that are pure reads; skipped when log_reads is False. Maintained here,
# NOT a write-list — anything not on this list is logged (fail-open to logging).
READ_SKIP_METHODS = frozenset(
    {
        "frappe.client.get",
        "frappe.client.get_list",
        "frappe.client.get_count",
        "frappe.client.get_value",
        "frappe.client.get_single_value",
        "frappe.desk.form.load.getdoc",
        "frappe.desk.form.load.getdoctype",
        "frappe.desk.search.search_link",
        "frappe.desk.search.search_widget",
        "frappe.desk.reportview.get",
        "frappe.desk.reportview.get_count",
        "frappe.desk.reportview.get_list",
        "frappe.desk.form.utils.get_pdf",
        "frappe.ping",
    }
)

# --- On-disk layout (guard, under site/private/<PRIVATE_DIR>/) ---------------
PRIVATE_DIR = "access_guard"
GRANTS_SUBDIR = "grants"  # <jti>.json  — authoritative grant records
USED_JTI_FILE = "used_jti.json"  # replay set
POLICY_FILE = "policy.json"  # {"token": "<paseto>", "policy": {...}, "verified_at": iso}
LOGS_SUBDIR = "logs"  # <jti>.jsonl
PUSHED_SUBDIR = "pushed"  # <jti>.meta — push-ack state for retention


# --- Shared helpers ---------------------------------------------------------
def transport_token_hash(token: str) -> str:
    """SHA-256 hex of the transport token. Used as the grant `aud`, as the hub's
    at-rest verifier for the ingest channel, and by the guard to verify `aud`."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --- Error taxonomy ---------------------------------------------------------
class AccessProtocolError(Exception):
    code = "access_protocol_error"
    http_status = 400

    def __init__(self, message: str | None = None):
        super().__init__(message or self.code)
        self.message = message or self.code

    def as_response(self) -> dict:
        return {"error": {"code": self.code, "pv": PV, "message": self.message}}


class ClientNotConfiguredError(AccessProtocolError):
    code = "client_not_configured"
    http_status = 503


class TokenMalformedError(AccessProtocolError):
    code = "token_malformed"
    http_status = 400


class TokenSignatureError(AccessProtocolError):
    code = "token_bad_signature"
    http_status = 401


class TokenExpiredError(AccessProtocolError):
    code = "token_expired"
    http_status = 401


class TokenAudienceError(AccessProtocolError):
    code = "token_wrong_audience"
    http_status = 403


class TokenReplayError(AccessProtocolError):
    code = "token_replayed"
    http_status = 409


class ProtocolVersionError(AccessProtocolError):
    code = "protocol_version_mismatch"
    http_status = 426  # Upgrade Required


class TransportAuthError(AccessProtocolError):
    code = "transport_auth_failed"
    http_status = 401


class PolicyDeniedError(AccessProtocolError):
    code = "policy_denied"
    http_status = 403


ERROR_BY_CODE = {
    cls.code: cls
    for cls in (
        ClientNotConfiguredError,
        TokenMalformedError,
        TokenSignatureError,
        TokenExpiredError,
        TokenAudienceError,
        TokenReplayError,
        ProtocolVersionError,
        TransportAuthError,
        PolicyDeniedError,
    )
}


def check_pv(value) -> None:
    """Raise ProtocolVersionError unless `value` matches this build's PV."""
    if value != PV:
        raise ProtocolVersionError(f"expected pv={PV}, got pv={value!r}")
