"""Test-only helper: mint a throwaway PASETO v4.public keypair + tokens, so
the guard's tests never depend on a running hub (BUILD_PLAN.md "Tests").
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pyseto
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pyseto.versions.v4 import V4Public

from access_guard.protocol import POLICY_DEFAULTS, PV, transport_token_hash


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
		user_name: str = "Jane Doe",
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
			"user_name": user_name,
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
		claims = dict(POLICY_DEFAULTS)
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
