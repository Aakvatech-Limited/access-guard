"""access-protocol — shared wire contract between access-hub and access-guard.

FRAPPE-AGNOSTIC (stdlib only) so both apps can vendor an *identical* copy and
import it in unit tests without a site.

VENDORING RULE: byte-identical in access_hub/ (authoritative) and access_guard/.
The guard can't import from the hub, so any change is coordinated across both.
Only names both apps encode/decode belong here; one-sided names live in each
app's own constants.py. Human-readable spec: docs/PROTOCOL.md.
"""

import hashlib

# Protocol version. Bump on any breaking wire change; a mismatch is a clean
# ProtocolVersionError, never a best-effort parse.
PV = 1

# Deliberately NOT `Authorization`. Frappe's validate_auth() intercepts 2-part
# Authorization values before any whitelisted method runs, letting them through
# only via a real session or a registered auth_hooks entry — which our token is
# neither, so it would force an auth_hooks registration just to clear the gate
# (rejected, see DESIGN.md). A custom header skips validate_auth() entirely, so
# `ingest_endpoint` is the ONLY place this token is ever checked.
TRANSPORT_TOKEN_HEADER = "X-Access-Guard-Transport-Token"

# Guard site_config.json keys (the enrollment contract). Shared because the hub
# emits them and the guard reads them. The `access_guard_` prefix marks them as
# living in the GUARD's site_config (the hub's own keys are `access_hub_*`).
GUARD_CONF_HUB_URL = "access_guard_hub_url"
GUARD_CONF_HUB_PUBLIC_KEY = "access_guard_hub_public_key"  # paserk k4.public
GUARD_CONF_TRANSPORT_TOKEN = "access_guard_transport_token"  # min length 8

# Grant token custom claims (PASETO v4.public; iat/exp/aud handled by pyseto).
# Name is sent as its three source parts, not a pre-joined full name - the
# guard needs first_name/last_name (User's real fields) to provision the
# ephemeral user, and re-splitting a joined string is lossy for anyone with a
# middle name or a multi-word first/last name.
CLAIM_USER_FIRST_NAME = "user_first_name"
CLAIM_USER_MIDDLE_NAME = "user_middle_name"
CLAIM_USER_LAST_NAME = "user_last_name"
CLAIM_USER_EMAIL = "user_email"
CLAIM_JTI = "jti"
CLAIM_PV = "pv"

# Policy document — hub-signed PASETO v4.public token; claims are the keys
# below + iat + pv.
POLICY_RULES = "rules"  # [{doctype, actions:[...], mode:"deny"|"warn"}]
POLICY_SESSION_EXPIRY_SECONDS = "session_expiry_seconds"  # default 6h; effective = min(this, site)
POLICY_ALWAYS_LOG_DOCTYPES = "always_log_doctypes"
POLICY_MAX_KEY_SIZE_BYTES = "max_key_size_bytes"
POLICY_LOG_READS = "log_reads"
POLICY_LOG_SYNC_ENABLED = "log_sync_enabled"  # gates the guard's hourly log push/retention only
POLICY_RETENTION_DAYS = "retention_days"
POLICY_PUSH_GRACE_DAYS = "push_grace_days"
POLICY_NAME_SUFFIX = "name_suffix"  # appended to ephemeral user's last_name, e.g. "(consultant)"
POLICY_ACCESS_DISABLED = "access_disabled"  # global kill switch: reap every live grant, refuse new ones
POLICY_BLACKLISTED_EMAILS = "blacklisted_emails"  # user_email values to reap + refuse, individually

MODE_DENY = "deny"
MODE_WARN = "warn"


def transport_token_hash(token: str) -> str:
	"""SHA-256 hex of the transport token. Serves as grant `aud`, the hub's
	ingest-channel verifier, and the guard's `aud` check."""
	return hashlib.sha256(token.encode("utf-8")).hexdigest()


# Error taxonomy
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


class PolicyUnavailableError(AccessProtocolError):
	# No policy has ever been received AND a synchronous pull also failed -
	# the guard must never fall back to any default policy; there is none.
	code = "policy_unavailable"
	http_status = 503


class EphemeralUserCollisionError(AccessProtocolError):
	# The grant's email already belongs to a NON-ephemeral (real, standing) user
	# on the target site. Never log that user in — the whole point is to avoid
	# handing out standing accounts. The guard refuses; no session is started.
	code = "ephemeral_user_collision"
	http_status = 409


def check_pv(value) -> None:
	"""Raise ProtocolVersionError unless `value` matches this build's PV."""
	if value != PV:
		raise ProtocolVersionError(f"expected pv={PV}, got pv={value!r}")
