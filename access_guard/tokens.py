"""PASETO v4.public verification helpers, guard side.

Only ever verifies with the hub's PUBLIC key (access_guard_hub_public_key).
The guard never holds/needs the private key. Verification order for the
grant token follows PROTOCOL.md §3 exactly:

    1. parse                       -> TokenMalformedError
    2. verify signature            -> TokenSignatureError
    3. check_pv(claims.pv)         -> ProtocolVersionError
    4. exp (+ leeway)              -> TokenExpiredError
    5. aud == transport_token_hash -> TokenAudienceError
    6. jti replay                  -> TokenReplayError

Steps 5/6 are grant-specific and live in access_guard.api.accept, not here,
because the policy token has no aud/jti concept. This module does steps 1-4
(parse, signature, pv, exp) generically for both token kinds.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pyseto
from pyseto import Key

from access_guard.protocol import (
    CLAIM_PV,
    CLOCK_SKEW_LEEWAY_SECONDS,
    TokenExpiredError,
    TokenMalformedError,
    TokenSignatureError,
    check_pv,
)


def _load_public_key(paserk_public_key: str) -> Key:
    try:
        return Key.from_paserk(paserk_public_key)
    except Exception as e:
        raise TokenSignatureError(f"invalid public key configuration: {e}")


def verify_and_decode(token: str, paserk_public_key: str) -> dict:
    """Verify signature, pv, and exp (with leeway). Returns claims dict.

    Does NOT check aud or jti — callers that need those checks (accept)
    perform them explicitly afterward, in the order PROTOCOL.md mandates.
    """
    if not token or not isinstance(token, str):
        raise TokenMalformedError("token missing or not a string")

    key = _load_public_key(paserk_public_key)

    try:
        decoded = pyseto.decode(key, token)
    except pyseto.exceptions.VerifyError as e:
        raise TokenSignatureError(str(e))
    except Exception as e:
        # pyseto raises various errors (ValueError, binascii.Error, etc.)
        # for a malformed/garbage token before it ever gets to signature
        # verification.
        raise TokenMalformedError(str(e))

    try:
        payload = decoded.payload
        claims = json.loads(payload) if isinstance(payload, bytes | str) else payload
    except (ValueError, TypeError) as e:
        raise TokenMalformedError(f"invalid claim payload: {e}")

    if not isinstance(claims, dict):
        raise TokenMalformedError("claim payload is not an object")

    # pv check (step 3)
    check_pv(claims.get(CLAIM_PV))

    # exp check (step 4), with clock-skew leeway
    _check_exp(claims)

    return claims


def _check_exp(claims: dict) -> None:
    exp = claims.get("exp")
    if not exp:
        raise TokenMalformedError("missing exp claim")
    try:
        exp_dt = _parse_iso(exp)
    except (ValueError, TypeError) as e:
        raise TokenMalformedError(f"invalid exp claim: {e}")

    now = datetime.now(timezone.utc)
    if now > exp_dt + timedelta(seconds=CLOCK_SKEW_LEEWAY_SECONDS):
        raise TokenExpiredError(f"token expired at {exp}")


def _parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
