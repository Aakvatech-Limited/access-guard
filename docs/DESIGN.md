# Ephemeral Access Provisioning — Design Plan

## Driving principle

Don't over-engineer. Ship v1 fast and learn from real use. **A few breaking upgrades on
both sides are acceptable while this matures** — so we version the wire format (cheap) but do
*not* build multi-version compatibility yet. Everything below is split into **v1 (Current)** and
**Future** so execution plans can be cut per app from the v1 slice.

## Context

An ERPNext consultancy gives employees standing **System Manager** accounts on hundreds of
client sites. A few employees abused those permanent elevated permissions, causing data
breaches. The goal is to eliminate standing access: an employee gets System Manager on a
client site **only for a short window**, provisioned on demand from the central helpdesk
site and torn down automatically — and everything they do is logged out of their reach.

The hard constraint (user_story.md:29): **no per-client base user + copied API key-pair.**
Storing a long-lived api_key/api_secret per client on the helpdesk is itself the standing,
copyable, breach-amplifying credential we are trying to remove. So the design avoids any
shared secret per client.

**App naming:**
- **access-hub** — helpdesk/hub-side app.
- **access-guard** — client-side app.
- **access-protocol** — the shared contract (docs + wire schema) between them. Vendored, not a
  third app in v1 (see Repo structure).

**Target Frappe versions: v15, v16, and above.** Not v14 or below. All hooks relied on below
(`app_include_js`, `boot_session`, `doc_events`, `scheduler_events`, `on_logout`) are stable
across v15/v16.

### Foundational: no client-DB trust

An employee can become System Manager on a client site, so the **client DB is
attacker-controlled**. Nothing the security model depends on may live in the DB. All
integrity-critical state lives in **files** under `site/private/access_guard/` (JSON config,
per-session `.jsonl` logs, grant/jti state), out of desk reach. **Redis** and **site_config**
are NOT reachable from the UI or server scripts (confirmed), so Redis is a *trusted-but-volatile*
cache: files remain authoritative for durability (Redis flushes/evicts → re-derive from files),
but Redis values need not be treated as attacker-forged.

### Foundational: constrained ephemeral user

The ephemeral User object unavoidably lives in the client DB. Rather than police it after the
fact, access-guard **prevents** it from performing the meta-operations that would let it subvert
the access system (v1 default: deny User create/edit/delete), so the reaper and guard can safely
trust file-backed state. See Access policy.

---

## Scope: v1 vs Future

**v1 (Current):**
- Single browser-mediated signed-token provisioning path (all sites).
- Manual enrollment (typed `site_config.json`) for all sites.
- Deny + warn policy, global, signed, file-backed on the client.
- Idle-based session expiry + 15-min reaper + `on_logout` teardown.
- File-based per-session logging, pushed hourly to the hub.
- Hub: Remote Site registry, Access Grant record, token minting, ingest endpoints.
- Wire-format version stamp (`pv`) + documented error taxonomy.

**Future (v2+):**
- Approvals (auto-grant vs require-approval per client).
- Hub-side reconciliation / persistence detection + flagging + notifications.
- Early/remote revoke (hub → client push).
- FC enrollment add-on (auto-register + write config).
- Per-client policy overrides (v1 policy is global).
- Ephemeral email generation (v1: reuse helpdesk email).
- "Disallow simultaneous sessions" toggle (clamp to single session).
- Absolute max session duration / force-logout independent of idle expiry.
- HMAC + timestamp/nonce on the transport channel.
- Multi-version protocol tolerance (server serves N old guard versions).
- Standalone access-protocol repo + submodule.

---

## Provisioning: one path — asymmetric-signed token via browser (v1)

A single provisioning mechanism for all sites, FC or not. Trust flows one direction via
public-key crypto. The **helpdesk holds one private key**; each **client stores only the
helpdesk's public key** (non-secret, identical everywhere, shippable in the app). No base user on
clients; no secret copied to the helpdesk.

Flow when an employee clicks **Request access** on the helpdesk:
1. Helpdesk mints a **grant token** — **PASETO `v4.public`, Ed25519** (`pyseto` both sides).
   PASETO is chosen so the token format is unmisconfigurable (no `alg` header → no `alg:none` /
   key-confusion bugs).
2. **Claims (v1 — WHO + WHERE + WHEN only, no policy):**
   - employee identity (name + email),
   - `aud` = **SHA-256 of the client's transport token** (see below) — enforced on verify to
     prevent cross-client replay,
   - `iat`,
   - short `exp` (default **30–60 min**) — this is the **redemption deadline for the URL**, not the
     session lifetime; a captured-but-unclicked URL goes dead after `exp`,
   - unique `jti` (single-use),
   - `pv` (protocol version).
   No `roles`/`deny`/`warn` claims — the guard owns policy (see Access policy).
3. Employee's browser is redirected to the client's grant-acceptance URL with the token as a
   parameter (**HTTPS mandatory** so the token isn't sniffed).
4. access-guard verifies signature against the stored public key, checks `exp`, checks `jti`
   unused (file-backed store), and checks `aud == SHA-256(local transport token)`. On success it:
   - writes a **grant file** under `site/private/access_guard/` (employee / email / jti / sid /
     issued / effective session expiry) — authoritative for the reaper, the session guard, and
     provisioning-outcome reports; records the **jti ↔ sid** mapping here at login,
   - creates/reuses an ephemeral `User` (idempotent, keyed on email + name suffix),
   - assigns **all assignable roles on the target site** (v1: every role Frappe's own
     `get_all_roles()` would show as a checkbox on the User form — i.e. every non-disabled,
     domain-active role except the automatic ones: Guest / All / System User / Administrator —
     including any custom roles the client has defined; not just System Manager),
   - sets `simultaneous_sessions` on the user (0/1) at creation — no special multi-session
     handling; multiple tabs share one sid in Frappe anyway,
   - starts a Frappe login session (the token doubles as a one-time login credential).

The token is self-contained and signed, so the client validates it **without calling back** to
the helpdesk — exactly what the browser-redirect (no server-to-server) choice requires.

**`aud` = hashed transport token — rationale.** The transport token is already required config on
every client, so reusing it as the audience needs **zero extra config** (no separate client-id
field). The value stored on the hub for at-rest hashing (`H = SHA-256(transport_token)`) *is*
the `aud`: hub sets `aud = H` at mint (doesn't need the plaintext), client verifies
`aud == SHA-256(its local token)`, and a token minted for client A fails at client B. This is the
"this is for you" binding needed on the **server → user(browser) → client** courier path, where
the (possibly malicious) employee carries the token — cross-client replay is what `aud` + single-use
`jti` + short `exp` jointly defeat. `H` is exposed in the browser token but the whole token is
PASETO-signed (unforgeable); user-defined transport tokens require a **minimum length of 8**.

---

## Enrollment (wiring a client to the hub)

One-time, low-stakes, separate from provisioning. Writes a fixed config shape on the client:
**hub URL + helpdesk public key + per-client transport token.**

- **v1 — manual (all sites):** admin installs access-guard and pastes the three values into
  `site_config.json`. The transport token may be **admin-chosen** (so a site can be configured
  before the hub knows it exists) or hub-autogenerated; either way the hub registers it
  on first announce.
- **Future — FC add-on:** for FC sites, auto-registers the site in the hub registry and writes
  the config automatically (incl. the transport token via one FC↔hub handshake). Slots behind
  the same config shape — the rest of the system can't tell manual from FC enrollment. See
  [[fc-automation-scope]].

The three configs are validated at boot; if any is missing the guard refuses to accept tokens
(`ClientNotConfiguredError`).

**Enrollment-help surface (hub side).** The hub persists its own public key to its own
`site_config.json` (`access_hub_public_key`), not just a one-time printout at keygen — so it can
hand it back out later. Two surfaces read it: a `bench access-hub-enroll-info` command (hub URL +
public key), and a **"Get Enrollment Info" action on the Remote Site doctype** that returns the
full three-value snippet — `access_guard_hub_url`, `access_guard_hub_public_key`,
`access_guard_transport_token` (plaintext, only available right after that Remote Site's token was
created/regenerated, since only its hash persists after) — for one client. The point: an operator
enrolling a new client site should never need to read `site_config.json` by hand on either side.

---

## Client → hub channel (outbound, one shared channel)

All client-initiated traffic goes to the hub's known URL over **HTTPS**, carrying the
**per-client transport token** in a **custom header** (`X-Access-Guard-Transport-Token`, see
`protocol.py::TRANSPORT_TOKEN_HEADER`) — low-privilege; reaches only hub ingest endpoints; leak =
post-as-that-one-client, nothing more. The hub stores the token **hashed** at rest (`SHA-256`) and
compares `hash(incoming)`; it never needs the plaintext after registration. No HMAC/nonce in v1 —
the header-over-TLS is sufficient; TLS also authenticates the hub's identity, so no separate
"client verifies server" mechanism is needed on this channel (the Ed25519-signed grant token
already authenticates the hub on the provisioning path).

**Why a custom header, not `Authorization: Bearer <token>` (revised 2026-07-21).** An earlier
revision used `Authorization`, which forced a global `auth_hooks` registration on the hub
(`access_hub/auth.py`) purely to clear Frappe's own `validate_auth()` gate — that function
intercepts any 2-part `Authorization` value (e.g. `"Bearer <token>"`) *before* Frappe even resolves
which whitelisted method is being called, let alone runs any decorator wrapping it, and rejects
with `AuthenticationError` unless the header resolves to a real session via OAuth/API-key/an
`auth_hooks` entry — so no per-endpoint decorator could intercept it; some global registration was
structurally unavoidable as long as the token rode in `Authorization`. Traced this precisely against
`frappe/auth.py::validate_auth()`: its gate is keyed *only* on the literal `Authorization` header
having exactly 2 space-separated parts — nothing else about the request. Moving the token to a
custom header means `validate_auth()` never looks at it at all, so **no hub-side registration point
is needed** — `ingest_endpoint` (in `api.py`) is the *only* place this token is ever checked,
end to end, exactly matching how a per-endpoint decorator was meant to work. `access_hub/auth.py`
and its `auth_hooks` entry are removed entirely as a result — not narrowed, deleted.

Uses:
- **Audit-log push** (scheduled, **hourly**, on/off — not tunable in v1): upload per-session log
  files. The file on disk is the durable source of truth, so delayed sync loses nothing.
- **Auto-enroll / announce**: report existence + URL/version so the hub registry self-populates.
- **Provisioning-outcome reports**: report create/reap of an ephemeral user per `jti`.
- **Policy pull** (hourly): fetch the signed global policy blob (see below).

Deferred (Future): early/remote revoke — reachability + FC API make hub → client push trivial
when wanted; managers force-logout manually meanwhile.

---

## Access policy: deny + warn, global, guard-enforced (v1)

**Posture: prevent the meta-operations that enable persistence, warn on other sensitive ops, log
everything.** This is a deliberate reversal of an earlier "allow everything, catch persistence via
reconciliation" idea — because **reconciliation is deferred to Future**, allowing User ops with no
reconciliation would leave persistence entirely uncaught. So v1 **denies** the meta-ops instead.

**Policy shape (future-proof).**
- UI: a child table (or two sections) on the hub's `Remote Access Settings`.
- Wire/file: a **normalized, versioned JSON rule list**, decoupled from the UI:
  ```json
  { "pv": 1, "rules": [
    { "doctype": "User", "actions": ["create", "write", "delete"], "mode": "deny" },
    { "doctype": "Server Script", "actions": ["write"], "mode": "warn" }
  ]}
  ```
  A single `mode` field (`deny` / `warn`, extensible later to `require-approval` etc.) keeps the
  schema stable. Actions use Frappe's canonical names (`create/write/delete/submit/cancel/read`).
- **Default seed:** `User → deny [create, write, delete]`, seeded via an **idempotent
  `after_install`** (guard-on-existence-before-insert, following the india-compliance pattern).

**Policy is global in v1** (not per-client). Authored on the hub as a Single DocType
`Remote Access Settings`, **signed with the helpdesk key**, and delivered two ways:
- **best-effort push on save** (fire-and-forget; failure OK — reachable clients update fast),
- **guaranteed hourly pull** by the guard (covers firewalled/offline/new clients).

The guard verifies the signature against the public key and writes the policy to a **file** under
`site/private/access_guard/` — **never a client DocType** (an ephemeral System Manager would just
edit "deny User" away). Per-client policy overrides are Future.

**Enforcement mechanics.** The ephemeral user has System Manager, so DB permissions can't gate
anything — enforcement is entirely guard **code** keyed on "is this an ephemeral session?" (read
from the grant file):
- **deny** → block the op before write (`has_permission` / `validate` / before-write hook),
- **warn** → a **warn interstitial** ("this is a sensitive operation on a client account and will
  be recorded") before proceeding, then log + allow.

**Prevention vs. detection boundary (accepted).** The guard is app code; an attacker with
server-script (Python) execution could sidestep hooks. Accepted — mitigation is **detection via
logging**, and the log sink is out of reach: `.jsonl` files under `site/private/` are not touchable
by a server script absent an actual exploit, and once a line is pushed to the hub it is immutable
from the client. Shorter push interval = smaller pre-immutability window; v1 fixes this at hourly
(acceptable given the file is already out of desk reach).

---

## Session & deprovisioning (must be bulletproof)

**Session lifetime = idle timeout = `min(RemoteAccessSettings.session_expiry, site session_expiry)`.**
`session_expiry` (default **6h**) is a Remote Access Settings field; its help text states the
effective duration is the lower of it and the client site's own System Settings value. It is
**idle-based** (Frappe semantics). There is **no absolute wall-clock cap in v1** — an actively-used
session refreshes and can persist up to the idle limit; a hard max-duration / force-logout is Future.

- **Scheduled reaper (primary), `scheduler_event` every ~15 min:** for each ephemeral session,
  if idle beyond the effective expiry → kill the session (delete `tabSessions` rows + clear Redis);
  when an ephemeral user has **zero live sessions** → delete the user. Enforcing the *lower* bound
  ourselves matters because Frappe's `session_expiry` is global and may be higher than ours. Grant
  files under `site/private/` are authoritative, so this survives downtime / dropped jobs / never-logout.
- **Session-tied cleanup (secondary), `on_logout` hook:** tear the user down immediately on logout
  (with logout reason recorded) so early-finished sessions don't linger to the next tick.
- **Reaper safety:** acts only on the ephemeral naming namespace; deletes sessions before the user
  so an active tab can't outlive it; **never touches the client's own users.**
- **User identity:** idempotent create keyed on **helpdesk email** (ephemeral-email generation is
  Future). `full_name` is generated, so the **name suffix** (default `consultant`, e.g. company
  short name) is appended to **last_name** → e.g. `John Doe (consultant)`.

---

## Logging (v1)

Rides the client→hub channel. Actions are written to files under `site/private/access_guard/`
(unreachable through Frappe), stamped with the grant `jti`, pushed hourly. No per-site signing keys
(the file-outside-the-DB boundary already defends against the in-scope adversary).

**Mechanism — one file per session, plain append.** Do **not** use `frappe.logger` (routes by
module, wrong dir) and do **not** create one `logging.Logger` per sid (handler/fd leak in
long-lived workers). Instead **append JSONL to a per-session file, open-append-close per request**
(traffic is a human doing manual ops — low volume). The file is named by **`jti`** (stable, ties to
hub records); `sid → jti` is recorded in the grant file at login, so `before_request` reads
`frappe.session.sid` → maps to `jti` → appends.

**What to log:**
- **Request stream (every attempt):** logged at `before_request` (+ outcome/status at
  `after_request`). Skip only reads, and only when read-logging is off (default off): maintain a
  single **read-skip method list** in the protocol spec (`getdoc`, `getdoctype`, `reportview.get`,
  `get_list`, `frappe.ping`, …) — note `frappe.ping`, not the deprecated standalone `ping`.
  Everything not on that list is logged. **No write-method list and no
  reliance on `transaction_writes`** (unreliable; and unnecessary given fail-open logging).
- **Sensitive-doctype writes (always, in full):** `doc_events` `on_update` / `on_trash` on a
  configurable **always-log doctype list** (default: User, Server Script) register an
  **`frappe.db.after_commit` callback** that appends the diff — **no commit → no log** (rolled-back
  writes aren't logged). Exempt from the size cap. This is also the reliable channel that knows the
  doctype, so it catches a write even if it rode a whitelisted read method.
- **Max key size (default 512 KB):** truncate logged request args beyond this; sensitive-doctype
  diffs are exempt.
- **Uploads:** logged as a normal request, nothing special (the size cap covers the body).
- **Session lifecycle:** grant-accepted / client-pushed-login / logout (+ reason) recorded to the
  same session file.

---

## Hub-side storage & retention (v1)

The hub is **not** attacker-controlled (employees are not System Managers on the helpdesk), so
DocTypes are fine here — the no-DB-trust rule is client-only.

- **Session Log → DocType:** one row per session (client, jti, employee, start, end, logout reason)
  — low volume, queryable.
- **Request log → files + index (hybrid):** store the pushed per-session `.jsonl` as **files**
  (`base/client/jti.jsonl`) — a DocType table would bloat across hundreds of clients — plus a
  **lightweight index DocType** (client, jti, employee, date, path, size, line count) for
  search/browse. The Session Log row points at its file.
- **Safe serving:** never accept a client-supplied path. Serve by DocType id → resolve to a
  canonical path server-side → normalize and assert the real path is within `base_dir` (traversal
  guard) → support line/byte-range for partial views. Hub System Managers only.
- **Retention:** hub-configured, default **365 days**, polled daily by the guard; a session's
  local file is deleted when **(acked by hub AND local age > grace [default ~7 days]) OR age >
  max (365d)**. The grace buffer protects against hub-side loss before durable backup and leaves
  a debugging window.

---

## Protocol versioning & error taxonomy (v1)

**Version stamp now, tolerance later.** Every wire artifact carries `pv` (protocol version): grant
token, policy blob, log-push / announce / provisioning-report payloads, error responses. In v1 the
hub supports exactly one `pv` and returns a clean `ProtocolVersionError` ("upgrade required") on
mismatch — that *is* the defined degraded behavior. Building a compatibility matrix is Future; the
version field + mismatch error cost almost nothing now.

**Documented error types** (in the protocol spec, stable codes):
`ClientNotConfiguredError` (missing any of pubkey / hub URL / transport token),
`TokenSignatureError`, `TokenExpiredError`, `TokenReplayError` (jti used),
`TokenAudienceError` (cross-client), `TokenMalformedError`, `ProtocolVersionError`,
`TransportAuthError`, `PolicyDeniedError` (deny-list op attempted).

---

## Monitoring notice on client sites (v1)

An unintrusive, enabled-by-default notice ("your activity is being monitored"), configurable in
Remote Access Settings. Rendered version-robustly via **`app_include_js`** (a slim configurable
bar), gated on "am I ephemeral?" via a **`boot_session`** flag derived from the **grant file** (not
a DB flag). Both hooks are stable v15/v16; avoid touching desk DOM internals.

---

## Components to build

### access-hub (helpdesk site)
**v1:**
- Provisioning: single signed-token-redirect flow for all sites.
- Keypair management: private key in `site_config.json` / env (never DB, never shipped); one-time
  generation command; public key ships to all clients (identical everywhere).
- `Access Grant` DocType: employee, target client site, jti, status (Issued/Expired), timestamps.
  (No approval workflow in v1.)
- "Request access" UI: list client sites → mint token → redirect the browser to the acceptance URL.
- Token minting: PASETO `v4.public` (`pyseto`), WHO + `aud`(=hashed transport token) + `iat` +
  `exp` + `jti` + `pv`, no policy claims.
- `Remote Access Settings` (Single): global config — deny/warn rule list, `session_expiry` (6h),
  always-log doctype list, max key size (512 KB), log-read toggle (off), monitoring-notice text,
  sync on/off, retention (365d). Signed + served for push/pull.
- `Remote Site` DocType (client registry): host (title), port (default 443), protocol (default
  https; suggest http only for `:80` or `.localhost`, user-editable — never auto-downgrade), name
  autogenerated, **transport token** admin-input or autogenerated (min length 8), stored **hashed**.
- Ingest endpoints: authenticated receivers for log push, announce, provisioning reports; validate
  the hashed transport token.
- Session Log DocType + request-log file store + index + safe range-serving (above).

**Future:** approval workflow; reconciliation / persistence-flagging job; FC enrollment add-on
(check `fc_mis` for reusable FC modeling); revoke channel; per-client policy overrides.

### access-guard (client site)
All integrity-critical state in **files** under `site/private/access_guard/`; Redis caches the hot
read path only.

**v1:**
- Config (file): helpdesk public key, hub URL, transport token — written at enrollment;
  validated at boot (`ClientNotConfiguredError` if incomplete).
- Whitelisted acceptance endpoint (`@frappe.whitelist(allow_guest=True)`): verify signature / `exp`
  / single-use `jti` (file store) / `aud`; write grant file (incl. jti↔sid); create/reuse ephemeral
  user; set `simultaneous_sessions`; start session; redirect into desk.
- Grant store (files): one record per `jti`. Used-`jti` store (file) for replay protection.
- Policy file (signed, pulled hourly + best-effort push): deny/warn rule list.
- Session guard (hooks): identify ephemeral session from grant files; enforce **deny** (block) and
  **warn** (interstitial + log) per the hardcoded-in-guard global policy.
- Reaper `scheduler_event` (~15 min, idle expiry = min(ours, site)) + `on_logout` cleanup.
- Per-session `.jsonl` logging (jti-named); read-skip list; sensitive-doctype `after_commit` diffs;
  512 KB cap; session lifecycle events.
- Outbound sync `scheduler_event` (hourly): push logs, announce, provisioning reports, pull policy;
  local log deletion per retention.
- Monitoring-notice bar (`app_include_js` + `boot_session`).
- File-write discipline: atomic write-temp-then-rename + per-file locks for grant/jti/policy;
  append-only for logs (DB transactional safety is now our responsibility).

**Future:** disallow-simultaneous toggle; absolute max session duration / force-logout; ephemeral
email; per-client policy.

### Frappe primitives to reuse (not reinvent)
- `frappe.get_doc` / `frappe.new_doc` for User creation; roles via `add_roles`.
- `frappe.local.login_manager` / `frappe.auth` to establish a session after verification.
- `hooks.py`: `scheduler_events` (reaper, sync), `on_logout`, `doc_events`, `app_include_js`,
  `boot_session`.
- `@frappe.whitelist(allow_guest=True)` for the acceptance endpoint.
- `frappe.db.after_commit` for commit-gated sensitive logging.
- Secrets via `frappe.conf` (site_config.json), never DocType fields.

---

## Repo structure (v1)

**No third Frappe app in v1.** The protocol spec + docs live in the **access-hub repo**; the
guard vendors what it needs. If real *shared code* emerges (error classes, token/policy JSON
schema, `pv` constants), factor it into a small **pip-installable package** both apps depend on to
avoid copy-paste drift — even that can wait; v1 can vendor a single `protocol.py`. A standalone
repo + submodule earns its keep only when external parties implement the protocol or shared code
churns; **Future**.

---

## Security notes / edge cases

- **Short `exp` + single-use `jti`** bound a leaked redirect URL: useless after `exp` or first use.
- **Clock skew:** allow small leeway on `exp`.
- **Key rotation:** clients hold only the public key → rotation = ship a new public key (support a
  small valid set during transition). No per-client secret churn.
- **Compromised helpdesk** still needs the private key to forge grants; there is no vault of
  per-client api_secrets to steal — the central design goal.
- **HTTPS mandatory** on the redirect and the transport channel.
- **Transport token entropy:** autogenerated tokens are CSPRNG (32 bytes); admin-defined tokens
  require min length 8. `aud` exposes only `SHA-256(token)`; the grant token is signed (unforgeable).
- **Never delete non-ephemeral users** — reaper filters strictly on the ephemeral namespace.
- **No wall-clock session cap in v1** — an active session persists to the idle limit; force-logout
  is Future.

---

## Verification (v1; deferred items marked)

1. Install both apps on a local helpdesk and client site; generate the keypair; ship the public key.
2. **Provisioning:** click Request access → land logged-in as ephemeral System Manager → confirm a
   **grant file** exists for that `jti` (employee / email / jti / sid / issued / expiry) and the user
   carries the naming convention + suffix.
3. **File is authoritative (Redis is a cache):** with a live grant, flush Redis → session guard +
   reaper still behave by re-deriving from files; hot-read path re-populates Redis.
4. **Idle expiry via reaper:** set a low `session_expiry`, go idle past it, run the reaper → user +
   sessions deleted; repeat with Redis pre-flushed → still expires from the file.
5. **Session-tied cleanup:** log out early → user deleted before the next reaper tick, logout reason
   logged.
6. **Replay (file-backed jti):** reuse a spent token URL → rejected (jti in file store); repeat with
   Redis flushed → still rejected.
7. **Tamper:** alter a token claim → PASETO verification fails.
8. **Cross-client replay:** present client A's token to client B → rejected on `aud` (hashed
   transport token mismatch).
9. **Deny (v1 policy):** as the ephemeral user, attempt a User create → blocked; entry logged.
10. **Warn (v1 policy):** attempt a warn-listed op → interstitial appears, action logged then allowed.
11. **Sensitive logging is commit-gated:** perform a sensitive write that rolls back → no diff logged;
    one that commits → full diff logged (size-cap-exempt).
12. **Read-skip:** with read-logging off, a `getdoc` is not logged; a non-read attempt is.
13. **Log immutability off-site:** confirm `.jsonl` lines push hourly and a client-side edit of an
    already-pushed line can't affect the hub copy; confirm safe range-serving rejects traversal.
14. **Negative:** a real client user is never touched by the reaper (namespace filter only).
15. **Protocol version:** an guard/hub `pv` mismatch returns `ProtocolVersionError`.
16. *(Future)* Approval path; hub-side reconciliation flags a backdoor account no grant explains.
