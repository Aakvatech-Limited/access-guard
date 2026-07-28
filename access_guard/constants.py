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

# Extra grace before a used-jti entry is pruned from the replay store, on top
# of exp + CLOCK_SKEW_LEEWAY_SECONDS. Keeps the prune bound strictly later than
# tokens._check_exp's accept bound: a jti forgotten while its token still
# verifies is a replayable token (see grants._is_expired).
PRUNE_MARGIN_SECONDS = 300

# Idle window used when policy.session_expiry_seconds is 0/unset. Deprovisioning
# is not an operator-tunable "off" switch: Frappe's `reqd` doesn't reject 0 on an
# Int field, and treating 0 as "never expire" left ephemeral System Manager
# sessions alive for Frappe's site-wide 10-day default with the User never
# deleted. Matches the hub's own default (6h) so behaviour is unchanged for a
# correctly-configured hub.
IDLE_EXPIRY_FALLBACK_SECONDS = 6 * 60 * 60

# --- Redis cache ---------------------------------------------------------
# Disk (POLICY_FILE) is the durable source of truth; redis is purely an
# accelerator in front of it, invalidated explicitly on every write
# (store_verified_policy) so this TTL only needs to be a generous backstop
# against cache/disk divergence (e.g. a redis flush) - matches
# access_hub's POLICY_TOKEN_CACHE_TTL_SECONDS in spirit.
POLICY_CACHE_KEY = "access_guard_policy"
POLICY_CACHE_TTL_SECONDS = 24 * 60 * 60

# Same accelerator-in-front-of-disk shape as policy, for GRANTS_FILE. One key,
# holding {"grants": {jti: record, ...}, "sid_map": {sid: jti, ...}} - a single
# object, not two independently-written keys, so the two halves can never
# disagree on a cache hit (they always come from the same set_value call,
# itself made inside the same file lock as the disk write - see grants.py).
# The TTL is purely a backstop against e.g. a redis flush, not a normal expiry
# path.
GRANTS_CACHE_KEY = "access_guard_grants"
GRANTS_CACHE_TTL_SECONDS = 24 * 60 * 60

# --- Logging ------------------------------------------------------------------
# Two log kinds, each its own file (no per-line "type" needed - the filename
# says it). Session lifecycle (login/logout) has no local file at
# all: it's pushed straight to the hub, see logging_.log_session_event.
LOG_KIND_REQUEST = "request"  # <jti>.request.log — one line per whitelisted call
LOG_KIND_DOC = "doc"  # <jti>.doc.log — one line per committed change to an always-log doctype

# --- On-disk layout, under site/private/<PRIVATE_DIR>/ -----------------------
PRIVATE_DIR = "access_guard"
GRANTS_FILE = "grants.json"  # one shared file, {jti: record, ...} — authoritative grant records
USED_JTI_FILE = "used_jti.json"  # replay set
POLICY_FILE = "policy.json"  # {"policy": {...}, "verified_at": iso}
LOGS_SUBDIR = "logs"  # <jti>.request.log, <jti>.doc.log
PUSHED_SUBDIR = "pushed"  # <jti>.<kind>.meta — push-ack state for retention
