# access-guard — build plan (v1)

> **Parallel scope.** You own **access-guard only**. Do not edit access-hub. The wire contract is
> frozen in [`docs/PROTOCOL.md`](PROTOCOL.md) and the shared code in
> [`access_guard/protocol.py`](../access_guard/protocol.py) — implement against them; do not change
> them without a coordinated change to the hub's identical copy. Full design rationale is in
> [`docs/DESIGN.md`](DESIGN.md).

The guard runs on the (attacker-controlled) client site. **No client-DB trust:** all
integrity-critical state lives in **files** under `site/private/access_guard/` (paths in
`protocol.py`); Redis is a volatile cache only. You do not have access_hub installed here — never
import from it; use the vendored `access_guard.protocol`.

## Conventions
- Whitelisted methods in `access_guard/access_guard/api.py` → `access_guard.api.<fn>`.
- **Guest-facing endpoints use `@guest_api` (in `access_guard/errors.py`), not
  `@frappe.whitelist(allow_guest=True)` directly.** It calls `frappe.whitelist(allow_guest=True)`
  internally and additionally catches any `AccessProtocolError` raised by the handler, turning it
  into the standard `{"error": {...}}` response via `respond_with_error` — so a handler just
  `raise`s the right error subclass and returns its normal success value; it never needs its own
  try/except. Already applied to `accept` and `receive_policy`; use it for any new guest endpoint.
- File writes atomic (write-temp + `os.rename`) with a per-file lock; logs append-only.
- Secrets/config via `frappe.conf` only.
- **SETTLED, do not revert:** in `accept`, once the grant token is fully verified (signature, `pv`,
  `exp`, `aud`, `jti` replay), switch to Administrator for the rest of the handler via
  `frappe.set_user("Administrator")` — don't do the trusted work (user create/reuse, policy read,
  grant file write) as Guest, and don't use `ignore_permissions=True` as a substitute for this.
  This was explicitly decided by the project owner (not a side-channel/unverified instruction) after
  a prior build pass reverted it to a narrower `ignore_permissions`-only scoping — that narrower
  version is rejected: "created by Guest" in the audit trail is the wrong outcome, not just a
  permission check to bypass.
  `allow_guest=True` means `frappe.session.user` is `"Guest"` until the real login happens.
  `ignore_permissions=True` on `insert()` only bypasses the permission *check* — it doesn't change
  who `owner`/`modified_by` get stamped as, and doesn't help any controller logic that branches on
  `frappe.session.user` directly. No explicit "restore" step is needed: `_start_session`'s
  `login_manager.post_login()` moves `frappe.session.user` off Administrator onto the real
  ephemeral user, so the Administrator window ends exactly where the real session begins. (No
  cross-request leak risk either way — Frappe tears down all thread-local session state via
  `frappe.destroy()` at the end of every request.) Already applied in `api.py`'s `accept`.
- **Never talk to Redis directly** (no raw `redis-py` client, no hand-built keys). Use Frappe's own
  APIs for every cache/session touch:
  - Ad-hoc caching → `frappe.cache` — it's a `RedisWrapper` instance (see
    `frappe/utils/redis_wrapper.py`), used as `frappe.cache.get_value(...)` /
    `.set_value(...)` / `.delete_value(...)` / `.hget(...)` etc. (`frappe.cache()` also works —
    `RedisWrapper.__call__` returns `self` for backward compatibility — but the bare attribute is
    the current form; either is fine, just don't reach for a bespoke client).
  - Killing a session (the reaper's "clear Redis" step) → use Frappe's own session-deletion path,
    e.g. `frappe.sessions.clear_sessions(user, keep_current=False)` (or the equivalent helper current
    on this Frappe version — check `frappe/sessions.py`), which correctly clears both the
    `tabSessions` DB rows and the Redis-backed session cache in one call. Don't delete the DB row and
    separately hand-roll a Redis delete.
  - If you ever need to confirm the file-is-authoritative property from DESIGN.md's verification
    checklist, use `bench --site <site> clear-cache` / `frappe.cache.delete_value(...)`, not a
    direct `FLUSHDB`.

## Tasks (in order)

1. **Config + boot validation.** Read `REQUIRED_GUARD_CONF` from `frappe.conf`; if any missing,
   the accept endpoint raises `ClientNotConfiguredError`. Helper to load the public key + transport
   token. Create the `site/private/access_guard/` tree lazily (`grants/`, `logs/`, `pushed/`).

2. **Grant acceptance endpoint** (`api.accept`, `allow_guest=True`). Verify strictly in the
   PROTOCOL §3 order (malformed → signature → pv → exp+leeway → aud → jti-replay). On success:
   write the grant file (§6), create/reuse the ephemeral **User** (idempotent, id = `emp_email`;
   suffix appended to **last_name** so generated `full_name` reads `John Doe (consultant)`), assign
   **all assignable roles** on the target site (`frappe.core.doctype.user.user.get_all_roles()` —
   every non-disabled, domain-active role except the automatic ones, including custom roles; not
   just System Manager), set `simultaneous_sessions` (0/1), start a login session, record `sid`
   into the grant file, then redirect to `/app`. Replay/used-jti store is file-backed (`USED_JTI_FILE`).

3. **Policy file + session guard.** `api.receive_policy` (allow_guest; authenticated by the policy
   token's own signature) verifies + writes `POLICY_FILE`. A pull is also run from the sync job.
   **Guard hooks** (`has_permission` / `validate` / `doc_events`) keyed on "ephemeral session?"
   (sid ∈ grant files): enforce `rules` — `deny` blocks before write (→ `PolicyDeniedError` UX),
   `warn` shows an interstitial then logs + allows. Policy read from the file, never the DB.

4. **Deprovisioning.** Reaper `scheduler_event` (~15 min): effective idle expiry =
   `min(policy.session_expiry_seconds, site session_expiry)`; kill sessions idle past it (delete
   `tabSessions` rows + clear Redis); delete an ephemeral user once it has **zero live sessions**.
   Namespace filter = users named in grant files only — never touch the client's own users.
   `on_logout` hook: immediate teardown + record logout reason. Send a `report_provisioning`
   ("reaped") on delete.

5. **Logging** (PROTOCOL §7). `before_request` (+ `after_request` status): append a `request` line
   for every whitelisted call except `READ_SKIP_METHODS` when `log_reads` is false; truncate `args`
   to `max_key_size_bytes`. `doc_events on_update/on_trash` for `always_log_doctypes`: register a
   `frappe.db.after_commit` callback that appends a `doc` line with the diff (no commit → no log;
   size-exempt). `session` lines on accept/login/logout. One file per jti; plain open-append-close.

6. **Outbound sync `scheduler_event`** (hourly, gated on `sync_enabled`). Push each session's
   ndjson via `push_logs` (transport token sent as `X-Access-Guard-Transport-Token`, **not**
   `Authorization` — see `protocol.py::TRANSPORT_TOKEN_HEADER`; HTTPS); `announce`; pull
   `get_policy` and re-verify; local retention: delete a session file when
   `(acked AND age > push_grace_days) OR age > retention_days`.

7. **Monitoring notice.** `boot_session` sets an "ephemeral?" flag from the grant file;
   `app_include_js` renders a slim bar with `policy.monitoring_notice_text`. No desk DOM internals.

## Tests (`bench run-tests`)
Put tests under `access_guard/access_guard/tests/` (add `__init__.py`). Use `FrappeTestCase`.
**Keep tests self-contained:** generate a throwaway PASETO keypair *in the test* and mint tokens
locally (via `pyseto`) so the guard's tests need no running hub. Cover:
- accept: valid token → ephemeral user created + grant file written (incl `sid`); suffix on last_name.
- replay: second use of the same `jti` → `TokenReplayError` (survives with the used-jti file only).
- expired token → `TokenExpiredError`; tampered claim → `TokenSignatureError`; wrong `aud` →
  `TokenAudienceError`; `pv` mismatch → `ProtocolVersionError`; missing config → `ClientNotConfiguredError`.
- deny rule blocks a `User` create; warn rule logs + allows.
- reaper: an idle-expired grant's user + sessions are deleted; a non-ephemeral user is never touched.
- logging (`before_request`/`after_request` in `request_hooks.py`): use
  **`frappe.utils.set_request(method="GET", path="/api/method/<name>")`** (or `cmd=` in
  `frappe.form_dict`) to give the test a real `frappe.local.request`/`frappe.request.path` before
  calling `before_request()`/`after_request()` directly — `_resolve_method_name()` reads
  `frappe.form_dict["cmd"]` or `frappe.request.path`, so it needs an actual request object, not a
  mock. Cover: a `READ_SKIP_METHODS` call is not logged when `log_reads` off; a non-read is; a
  rolled-back always-log write produces no `doc` line, a committed one does.

**Run:** `bench --site <guard-site> run-tests --app access_guard` (developer mode + app installed;
`pip install pyseto` first). See ../../access_hub/docs/HANDOVER.md for site setup.

## Done criteria
`bench --site <guard-site> run-tests --app access_guard` is green; a token minted with a test
keypair round-trips through `accept` and lands a logged-in ephemeral user with a grant file.
