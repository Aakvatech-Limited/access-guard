# access-protocol — frozen wire contract (v1, pv=1)

This is the **single source of truth** shared by access-hub and access-guard. Both apps
implement against it independently; nothing here is negotiable at build time. The machine-readable
half of this spec is `protocol.py` (constants, error classes, helpers), vendored **byte-identical**
into both apps at `<app>/<app>/protocol.py`.

If you are building one app, treat the *other* side of every exchange below as fixed. Integration
is verified after both apps are independently green.

---

## 0. Crypto primitive

Everything signed uses **PASETO `v4.public` (Ed25519)** via `pyseto`. The hub holds the private
key (`k4.secret`), the guard holds only the public key (`k4.public`). Two things are signed:
1. the **grant token** (hub → browser → guard),
2. the **policy token** (hub → guard).

No other signature scheme, no symmetric crypto, no HMAC in v1. `pv` (=`1`) is a claim in every
signed artifact and a field in every JSON payload; a mismatch → `ProtocolVersionError` (HTTP 426).

## 1. Configuration (`site_config.json`)

**Guard site** (all three required; missing any → `ClientNotConfiguredError`, refuse tokens):
- `access_guard_hub_url` — base URL of the hub.
- `access_guard_hub_public_key` — hub's PASETO public key (`k4.public...`).
- `access_guard_transport_token` — per-client bearer, **min length 8**.

**Hub site:**
- `access_hub_private_key` — PASETO secret (`k4.secret...`), generated once by a bench command.
- `access_hub_public_key` — the matching `k4.public...`, persisted on the hub itself (not just
  printed once at keygen). This is what backs the hub's own enrollment-help surface (a bench
  command + a Remote Site desk action) that hands a client admin the `access_guard_hub_url` +
  `access_guard_hub_public_key` + `access_guard_transport_token` they need to enroll — without
  ever reading `site_config.json` by hand.

## 2. `aud` / transport-token binding

`transport_token_hash(token) = sha256(token).hexdigest()`. This one value is used three ways:
- Hub stores it on the Remote Site as `transport_token_hash` (the token itself is never stored
  plaintext after registration).
- It is the grant token's **`aud`** claim (binds the token to one client → anti cross-client replay).
- The guard verifies `aud == transport_token_hash(local transport token)`.

## 3. Grant token (hub → browser → guard)

PASETO `v4.public`, signed with the hub private key. Claims:

| claim | source | notes |
|---|---|---|
| `emp_name` | employee full name | custom |
| `emp_email` | employee email | custom; becomes the ephemeral user id |
| `aud` | `transport_token_hash(client token)` | registered; verified on accept |
| `iat` | now | registered (ISO-8601) |
| `exp` | `iat + ~45m` | registered; **URL redemption deadline**, not session length |
| `jti` | uuid4 hex | custom; single-use |
| `pv` | `1` | custom |

**Delivery:** the hub redirects the employee's browser (HTTPS) to
`GET {guard_url}/api/method/access_guard.api.accept?token=<paseto>`.

**Guard accept — verify in this order**, mapping failures to the named errors:
1. parse → `TokenMalformedError`
2. verify signature w/ public key → `TokenSignatureError`
3. `check_pv(claims.pv)` → `ProtocolVersionError`
4. `exp` (allow `CLOCK_SKEW_LEEWAY_SECONDS`) → `TokenExpiredError`
5. `aud == transport_token_hash(local token)` → `TokenAudienceError`
6. `jti` not in used set → `TokenReplayError`; then mark used.

On success: write grant file, create/reuse ephemeral user, start session, redirect to `/app`.

## 4. Policy token (hub → guard)

The policy is delivered as a **PASETO `v4.public` token** whose claims are the policy object +
`iat` + `pv`. Guard verifies the signature (this *is* the authentication — no transport token
needed for a pushed policy) and writes `{token, policy, verified_at}` to the policy file.

Policy object keys (defaults live in `protocol.py::POLICY_DEFAULTS`):

```json
{
  "pv": 1,
  "rules": [{"doctype": "User", "actions": ["create","write","delete"], "mode": "deny"}],
  "session_expiry_seconds": 21600,
  "always_log_doctypes": ["User", "Server Script"],
  "max_key_size_bytes": 524288,
  "log_reads": false,
  "monitoring_notice_text": "...",
  "sync_enabled": true,
  "retention_days": 365,
  "push_grace_days": 7
}
```

`mode ∈ {deny, warn}`; `actions ⊂ {create,write,delete,submit,cancel,read}`.
**Delivery:** best-effort push on save + guaranteed hourly pull (see endpoints).

## 5. Endpoints

### Hub (authenticated by transport token: `X-Access-Guard-Transport-Token: <raw token>`)
**Deliberately not the `Authorization` header** — see `protocol.py::TRANSPORT_TOKEN_HEADER` for why
(Frappe's `validate_auth()` intercepts any 2-part `Authorization` value before a whitelisted method
runs at all, forcing an unnecessary global `auth_hooks` registration; a custom header sidesteps that
gate entirely, so `ingest_endpoint` is the only place this token is ever checked).
Hub computes `transport_token_hash(received)` and matches a Remote Site → else `TransportAuthError`.

| method | payload | returns |
|---|---|---|
| `access_hub.api.get_policy` | — | `{ "policy_token": "<paseto>" }` |
| `access_hub.api.push_logs` | `{ jti, host, session_meta, ndjson }` | `{ ok, received_lines }` |
| `access_hub.api.announce` | `{ host, port, protocol, app_version, pv }` | `{ ok }` |
| `access_hub.api.report_provisioning` | `{ jti, event: "created"\|"reaped", user, ts }` | `{ ok }` |

### Guard
| method | auth | payload | returns |
|---|---|---|---|
| `access_guard.api.accept` (allow_guest) | the grant token | `?token=<paseto>` | 302 → `/app` |
| `access_guard.api.receive_policy` (allow_guest) | the policy token itself | `{ policy_token }` | `{ ok }` |

All error responses use `AccessProtocolError.as_response()` →
`{ "error": { "code", "pv", "message" } }` with the class's `http_status`.

## 6. Grant file (`site/private/access_guard/grants/<jti>.json`)

Authoritative for the reaper, the session guard, and provisioning reports. Never in the DB.

```json
{
  "jti": "...", "pv": 1,
  "emp_name": "...", "emp_email": "...",
  "user": "john.doe@example.com",     // ephemeral user id (== emp_email in v1)
  "sid": "...",                        // recorded at login → maps session to jti
  "issued_at": "iso",
  "effective_expiry_seconds": 21600    // min(policy.session_expiry, site session_expiry) at accept
}
```

"Is this session ephemeral?" → `frappe.session.sid` appears as a `sid` in some grant file.
"Which users may the reaper touch?" → only `user` values present in grant files (namespace filter).

## 7. Log line schema (`site/private/access_guard/logs/<jti>.jsonl`)

One file per session (jti). Append-only, plain open-append-close per request.

```json
{"ts":"iso","jti":"...","sid":"...","type":"request","method":"...","status":"ok|error","args":<truncated to max_key_size>}
{"ts":"iso","jti":"...","sid":"...","type":"doc","doctype":"User","name":"...","action":"write","diff":{...}}   // after_commit, size-exempt
{"ts":"iso","jti":"...","sid":"...","type":"session","event":"accepted|login|logout","reason":"..."}
```

Request logging: log **every** whitelisted call except, when `log_reads` is false, methods in
`READ_SKIP_METHODS`. No write-list; no reliance on `transaction_writes`.

## 8. Version / errors

`pv = 1`. Error codes + HTTP statuses are defined once in `protocol.py` (`ERROR_BY_CODE`). v1
supports exactly `pv=1`; anything else is `ProtocolVersionError`, not a degraded parse.
