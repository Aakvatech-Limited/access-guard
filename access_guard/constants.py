"""Guard-only constants — not part of the wire contract, so not vendored to
access_hub (contrast with protocol.py, which IS vendored verbatim)."""

# --- site_config.json keys (guard side) -------------------------------------
# The key strings themselves live in the vendored protocol.py (the hub emits
# them, the guard reads them — shared vocabulary). Aliased here under the
# guard's short CONF_* names.
from access_guard.protocol import (
	GUARD_CONF_HUB_PUBLIC_KEY as CONF_HUB_PUBLIC_KEY,
)
from access_guard.protocol import (
	GUARD_CONF_HUB_URL as CONF_HUB_URL,
)
from access_guard.protocol import (
	GUARD_CONF_TRANSPORT_TOKEN as CONF_TRANSPORT_TOKEN,
)

REQUIRED_GUARD_CONF = (CONF_HUB_URL, CONF_HUB_PUBLIC_KEY, CONF_TRANSPORT_TOKEN)

CLOCK_SKEW_LEEWAY_SECONDS = 60

# --- Logging ------------------------------------------------------------------
LOG_TYPE_SESSION = "session"  # lifecycle: accepted / login / logout
LOG_TYPE_REQUEST = "request"  # a whitelisted method call (safe verbs skipped unless log_reads)
LOG_TYPE_DOC = "doc"  # committed change to an always-log doctype (after_commit)

# --- On-disk layout, under site/private/<PRIVATE_DIR>/ -----------------------
PRIVATE_DIR = "access_guard"
GRANTS_SUBDIR = "grants"  # <jti>.json  — authoritative grant records
USED_JTI_FILE = "used_jti.json"  # replay set
POLICY_FILE = "policy.json"  # {"token": "<paseto>", "policy": {...}, "verified_at": iso}
LOGS_SUBDIR = "logs"  # <jti>.jsonl
PUSHED_SUBDIR = "pushed"  # <jti>.meta — push-ack state for retention
