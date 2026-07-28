"""Guard-side policy: verify the hub-signed policy token, persist it to a
file (never a DocType — an ephemeral System Manager would just edit "deny
User" away), and answer "what should happen for this doctype+action?".
"""

from datetime import datetime, timezone

import frappe

from access_guard.config_utils import (
	atomic_write_json,
	locked_file,
	policy_path,
	read_json,
)
from access_guard.constants import POLICY_CACHE_KEY, POLICY_CACHE_TTL_SECONDS
from access_guard.hub_client import pull_policy
from access_guard.protocol import (
	MODE_DENY,
	MODE_WARN,
	POLICY_RULES,
	PolicyDeniedError,
	PolicyUnavailableError,
)
from access_guard.tokens import verify_hub_token


def store_verified_policy(claims: dict) -> dict:
	"""Atomically write already-verified policy claims as {policy,
	verified_at} to POLICY_FILE, and refresh the redis cache with the new
	policy so the next get_policy() call doesn't need to hit disk. The raw
	token itself isn't kept - callers only ever have `claims` at this point
	(verification, wherever it happened, already consumed the token), and
	nothing ever re-verifies or forwards it later."""
	# Keep pv; drop only the registered housekeeping claims layered on by pyseto/mint side.
	policy = {k: v for k, v in claims.items() if k not in ("iat", "exp", "nbf")}

	record = {
		"policy": policy,
		"verified_at": datetime.now(timezone.utc).isoformat(),
	}
	path = policy_path()
	with locked_file(path + ".lock"):
		atomic_write_json(path, record)
	frappe.cache.set_value(POLICY_CACHE_KEY, policy, expires_in_sec=POLICY_CACHE_TTL_SECONDS)
	return record


def verify_and_store_policy(policy_token: str) -> dict:
	"""Verify the policy token's own signature (that IS the authentication
	for a pushed policy — no transport token needed, per PROTOCOL.md §4)
	and persist it. For callers that only have a raw token (e.g. get_policy's
	pull-and-verify fallback below) - the receive_policy endpoint is already
	handed verified claims by ingest_api, so it calls store_verified_policy
	directly instead."""
	return store_verified_policy(verify_hub_token(policy_token))


def get_policy() -> dict:
	"""Read the policy — redis-first (disk is the durable source of truth,
	but this is called on essentially every whitelisted request, so a redis
	hit avoids a file read + json parse each time); never reads from the DB,
	never falls back to defaults (those are the hub's install-seed values
	only; a guard must always enforce a real policy). If nothing has ever
	been received (e.g. brand-new install, before the first accept()/hourly
	sync), pull and verify one synchronously. Raises PolicyUnavailableError
	if that also fails - there is no silent fallback."""
	cached = frappe.cache.get_value(POLICY_CACHE_KEY)
	if cached is not None:
		return cached

	record = read_json(policy_path(), default=None)
	if record and isinstance(record.get("policy"), dict):
		policy = record["policy"]
		frappe.cache.set_value(POLICY_CACHE_KEY, policy, expires_in_sec=POLICY_CACHE_TTL_SECONDS)
		return policy

	token = pull_policy()
	if not token:
		raise PolicyUnavailableError("No policy cached and the hub could not be reached.")
	try:
		record = verify_and_store_policy(token)
	except Exception as e:
		raise PolicyUnavailableError(f"Pulled policy failed verification: {e}") from e
	return record["policy"]


def match_rule(doctype: str, action: str) -> dict | None:
	"""First matching rule for (doctype, action), or None (no rule -> allow,
	consistent with the deny+warn-only, fail-open-to-allow v1 policy shape;
	everything sensitive is covered by an explicit seeded rule)."""
	policy = get_policy()
	for rule in policy.get(POLICY_RULES, []):
		if rule.get("doctype") == doctype and action in (rule.get("actions") or []):
			return rule
	return None


def enforce(doctype: str, action: str, *, jti: str | None = None, sid: str | None = None) -> str | None:
	"""Returns None (allowed silently), MODE_WARN (allowed, caller should
	log+notice), or raises PolicyDeniedError (MODE_DENY)."""
	rule = match_rule(doctype, action)
	if rule is None:
		return None
	mode = rule.get("mode")
	if mode == MODE_DENY:
		raise PolicyDeniedError(
			f"Operation '{action}' on '{doctype}' is denied by policy for monitored sessions."
		)
	if mode == MODE_WARN:
		return MODE_WARN
	return None
