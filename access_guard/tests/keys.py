"""Test-only helper: mint a throwaway PASETO v4.public keypair + tokens, so
the guard's tests never depend on a running hub (BUILD_PLAN.md "Tests").
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import frappe
import pyseto
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pyseto.versions.v4 import V4Public

from access_guard.config_utils import atomic_write_json, policy_path
from access_guard.constants import POLICY_CACHE_KEY
from access_guard.protocol import (
	MODE_DENY,
	POLICY_ACCESS_DISABLED,
	POLICY_ALWAYS_LOG_DOCTYPES,
	POLICY_BLACKLISTED_EMAILS,
	POLICY_LOG_READS,
	POLICY_LOG_SYNC_ENABLED,
	POLICY_MAX_KEY_SIZE_BYTES,
	POLICY_NAME_SUFFIX,
	POLICY_PUSH_GRACE_DAYS,
	POLICY_RETENTION_DAYS,
	POLICY_RULES,
	POLICY_SESSION_EXPIRY_SECONDS,
	PV,
	transport_token_hash,
)

# Test-only fixture: a full, realistic policy shape for minting test policy
# tokens. Not a runtime default - the guard never falls back to one (see
# PolicyUnavailableError), and the hub's own install-time seed lives in
# access_hub_settings.DEFAULT_RULES/DEFAULT_ALWAYS_LOG_DOCTYPES.
TEST_POLICY_DEFAULTS = {
	POLICY_RULES: [{"doctype": "User", "actions": ["create", "write", "delete"], "mode": MODE_DENY}],
	POLICY_SESSION_EXPIRY_SECONDS: 6 * 60 * 60,
	POLICY_ALWAYS_LOG_DOCTYPES: ["User", "Server Script", "Scheduled Job Type"],
	POLICY_MAX_KEY_SIZE_BYTES: 256 * 1024,
	POLICY_LOG_READS: False,
	POLICY_LOG_SYNC_ENABLED: True,
	POLICY_RETENTION_DAYS: 365,
	POLICY_PUSH_GRACE_DAYS: 7,
	POLICY_NAME_SUFFIX: "consultant",
	POLICY_ACCESS_DISABLED: False,
	POLICY_BLACKLISTED_EMAILS: [],
}


def stub_policy_file(policy: dict, verified_at: str | None = None) -> None:
	"""Write POLICY_FILE directly (bypassing signature verification, for
	tests that don't have a matching keypair patched into frappe.conf yet)
	and clear the redis policy cache so get_policy() actually picks up this
	fresh file instead of a stale cached value left by an earlier test or
	an earlier call in this same test - get_policy() only reads from disk
	when the cache misses (see access_guard.policy.get_policy)."""
	atomic_write_json(
		policy_path(),
		{
			"policy": policy,
			"verified_at": verified_at or frappe.utils.now_datetime().isoformat(),
		},
	)
	frappe.cache.delete_value(POLICY_CACHE_KEY)


def clear_policy_cache() -> None:
	frappe.cache.delete_value(POLICY_CACHE_KEY)


class TestKeypair:
	def __init__(self):
		sk_obj = Ed25519PrivateKey.generate()
		self.secret_key = V4Public(sk_obj)
		self.public_key = V4Public(sk_obj.public_key())

	@property
	def public_paserk(self) -> str:
		return self.public_key.to_paserk()

	def mint_grant_token(
		self,
		*,
		user_first_name: str = "Jane",
		user_middle_name: str | None = None,
		user_last_name: str = "Doe",
		user_email: str = "jane.doe@example.com",
		transport_token: str = "test-transport-token-12345",
		jti: str | None = None,
		pv: int = PV,
		ttl_seconds: int = 45 * 60,
		issued_delta_seconds: int = 0,
		extra_claims: dict | None = None,
	) -> str:
		now = datetime.now(timezone.utc) + timedelta(seconds=issued_delta_seconds)
		exp = now + timedelta(seconds=ttl_seconds)
		claims = {
			"user_first_name": user_first_name,
			"user_middle_name": user_middle_name,
			"user_last_name": user_last_name,
			"user_email": user_email,
			"aud": transport_token_hash(transport_token),
			"iat": now.isoformat(),
			"exp": exp.isoformat(),
			"jti": jti or uuid.uuid4().hex,
			"pv": pv,
		}
		if extra_claims:
			claims.update(extra_claims)
		return pyseto.encode(self.secret_key, claims).decode("utf-8")

	def mint_policy_token(
		self,
		*,
		policy: dict | None = None,
		pv: int = PV,
		issued_delta_seconds: int = 0,
		ttl_seconds: int = 30 * 24 * 60 * 60,
	) -> str:
		now = datetime.now(timezone.utc) + timedelta(seconds=issued_delta_seconds)
		claims = dict(TEST_POLICY_DEFAULTS)
		if policy:
			claims.update(policy)
		claims["iat"] = now.isoformat()
		claims["exp"] = (now + timedelta(seconds=ttl_seconds)).isoformat()
		claims["pv"] = pv
		return pyseto.encode(self.secret_key, claims).decode("utf-8")

	def tamper(self, token: str) -> str:
		"""Flip the token so signature verification fails."""
		raw = token.encode("utf-8") if isinstance(token, str) else token
		return (raw[:-5] + b"AAAAA").decode("utf-8")
