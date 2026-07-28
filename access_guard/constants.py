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

# --- Redis cache ---------------------------------------------------------
# Disk (POLICY_FILE) is the durable source of truth; redis is purely an
# accelerator in front of it, invalidated explicitly on every write
# (store_verified_policy) so this TTL only needs to be a generous backstop
# against cache/disk divergence (e.g. a redis flush) - matches
# access_hub's POLICY_TOKEN_CACHE_TTL_SECONDS in spirit.
POLICY_CACHE_KEY = "access_guard_policy"
POLICY_CACHE_TTL_SECONDS = 24 * 60 * 60

# --- Logging ------------------------------------------------------------------
# Two log kinds, each its own file (no per-line "type" needed - the filename
# says it). Session lifecycle (accepted/login/logout) has no local file at
# all: it's pushed straight to the hub, see logging_.log_session_event.
LOG_KIND_REQUEST = "request"  # <jti>.log      — one line per whitelisted call
LOG_KIND_DOC = "doc"  # <jti>.doc.log  — one line per committed change to an always-log doctype

# --- On-disk layout, under site/private/<PRIVATE_DIR>/ -----------------------
PRIVATE_DIR = "access_guard"
GRANTS_SUBDIR = "grants"  # <jti>.json  — authoritative grant records
USED_JTI_FILE = "used_jti.json"  # replay set
POLICY_FILE = "policy.json"  # {"policy": {...}, "verified_at": iso}
LOGS_SUBDIR = "logs"  # <jti>.log, <jti>.doc.log
PUSHED_SUBDIR = "pushed"  # <jti>.<kind>.meta — push-ack state for retention
