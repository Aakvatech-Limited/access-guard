"""Guard-only constants — not part of the wire contract, so not vendored to
access_hub (contrast with protocol.py, which IS vendored verbatim)."""

# --- site_config.json keys (guard side) -------------------------------------
CONF_HUB_URL = "access_guard_hub_url"
CONF_HUB_PUBLIC_KEY = "access_guard_hub_public_key"  # paserk k4.public
CONF_TRANSPORT_TOKEN = "access_guard_transport_token"  # min length 8

REQUIRED_GUARD_CONF = (CONF_HUB_URL, CONF_HUB_PUBLIC_KEY, CONF_TRANSPORT_TOKEN)

CLOCK_SKEW_LEEWAY_SECONDS = 60

# --- Logging ------------------------------------------------------------------
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

# --- On-disk layout, under site/private/<PRIVATE_DIR>/ -----------------------
PRIVATE_DIR = "access_guard"
GRANTS_SUBDIR = "grants"  # <jti>.json  — authoritative grant records
USED_JTI_FILE = "used_jti.json"  # replay set
POLICY_FILE = "policy.json"  # {"token": "<paseto>", "policy": {...}, "verified_at": iso}
LOGS_SUBDIR = "logs"  # <jti>.jsonl
PUSHED_SUBDIR = "pushed"  # <jti>.meta — push-ack state for retention
