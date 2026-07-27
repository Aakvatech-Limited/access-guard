"""Guard-side policy: verify the hub-signed policy token, persist it to a
file (never a DocType — an ephemeral System Manager would just edit "deny
User" away), and answer "what should happen for this doctype+action?".
"""

from datetime import datetime, timezone

import frappe

from access_guard.config_utils import (
	atomic_write_json,
	get_guard_conf,
	locked_file,
	policy_path,
	read_json,
)
from access_guard.protocol import (
	MODE_DENY,
	MODE_WARN,
	POLICY_DEFAULTS,
	POLICY_RULES,
	PolicyDeniedError,
)
from access_guard.tokens import verify_and_decode


def _get_public_key() -> str:
	return get_guard_conf()["access_guard_hub_public_key"]


def verify_and_store_policy(policy_token: str) -> dict:
	"""Verify the policy token's own signature (that IS the authentication
	for a pushed policy — no transport token needed, per PROTOCOL.md §4)
	and atomically write {token, policy, verified_at} to POLICY_FILE."""
	claims = verify_and_decode(policy_token, _get_public_key())

	# Keep pv; drop only the registered housekeeping claims layered on by pyseto/mint side.
	policy = {k: v for k, v in claims.items() if k not in ("iat", "exp", "nbf")}

	record = {
		"token": policy_token,
		"policy": policy,
		"verified_at": datetime.now(timezone.utc).isoformat(),
	}
	path = policy_path()
	with locked_file(path + ".lock"):
		atomic_write_json(path, record)
	return record


def get_policy() -> dict:
	"""Read the policy from file. Falls back to POLICY_DEFAULTS if no
	policy has ever been received (e.g. brand-new install) — never reads
	from the DB."""
	record = read_json(policy_path(), default=None)
	if record and isinstance(record.get("policy"), dict):
		merged = dict(POLICY_DEFAULTS)
		merged.update(record["policy"])
		return merged
	return dict(POLICY_DEFAULTS)


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
