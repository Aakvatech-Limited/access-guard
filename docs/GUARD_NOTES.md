# Guard implementation notes

Guard-internal decisions for a maintainer editing `access_guard`. Shared design,
the wire contract, and operations live in the **access-hub** repo — read those
first; this doc only covers what's guard-specific and not there:

- `access-hub/docs/DESIGN.md` — shared design + rationale (enforcement model, no-client-DB-trust, logging strategy).
- `access-hub/docs/PROTOCOL.md` — the frozen wire contract (token/claim shapes, verify order, error responses, log lines).
- `access-hub/docs/OPERATIONS.md` — install/enroll/use/test runbook.

The guard runs on the **attacker-controlled client site**. Never import from
`access_hub` (it isn't installed here); use the vendored `access_guard.protocol`,
which must stay byte-identical to the hub's copy — coordinate any change.

## Conventions

- Whitelisted endpoints live in `api.py` → called as `access_guard.api.<fn>`.
- **Guest endpoints use `@_ingest_api` (`api.py`), never raw
  `@frappe.whitelist(allow_guest=True)`.** It whitelists internally *and* catches
  any `AccessProtocolError` once, turning it into the PROTOCOL §5 `{"error": {...}}`
  response with the class's `http_status`. Handlers just `raise` the right subclass
  and return their success value — no per-handler try/except. Applies to `accept`,
  `receive_policy`, and any new guest endpoint.
- Integrity-critical writes are **atomic** (temp file + `fsync` + `os.rename`) under a
  **per-file flock**, via `config_utils` (`atomic_write_json`, `locked_file`). Logs are
  **append-only**, open-append-close per line (`append_line`) — no persistent handle
  held between writes.
- Secrets/config come from `frappe.conf` only (`get_guard_conf` validates the three
  `REQUIRED_GUARD_CONF` keys). Never a DocType, never the DB.

## Administrator window in `accept()` — SETTLED, do not revert

Once the grant token is **fully verified** (signature, `pv`, `exp`, `aud`, `jti`-replay),
`accept()` calls `frappe.set_user("Administrator")` for the trusted work — user
create/reuse, policy read, grant-file write. This is a deliberate identity switch, **not**
an `ignore_permissions=True` scoping.

Rationale: `allow_guest=True` means `frappe.session.user` is still `"Guest"` until the real
login. `ignore_permissions` only skips the permission *check* — it would still stamp
`owner`/`modified_by` as **Guest** and wouldn't help controller logic that branches on
`frappe.session.user`. "Created by Guest" in the audit trail is the wrong outcome, not just
a check to bypass. No explicit restore step: `_start_session`'s `login_manager.post_login()`
moves `frappe.session.user` off Administrator onto the real ephemeral user, so the window
ends exactly where the session begins (and `frappe.destroy()` tears down thread-local state
per request regardless).

Decided explicitly by the project owner after a prior pass narrowed it to
`ignore_permissions` — that narrower version is **rejected**. Do not revert.

## On-disk layout — `site/private/access_guard/` (0o700)

Names in `constants.py`; created lazily by `config_utils.private_base_dir()`.

| Path | Contents |
|------|----------|
| `grants.json` | one shared file, `{jti: record, ...}` — authoritative grant records (incl. `sid`, `user`, `user_email`) |
| `used_jti.json` | replay set — atomic check-and-set under lock in `mark_jti_used` |
| `policy.json` | `{"token", "policy", "verified_at"}` — read via file, never DB |
| `logs/<jti>.request.log` | one append-only logfmt log per session, one line per whitelisted call |
| `logs/<jti>.doc.log` | one append-only logfmt log per session, one line per doc event |
| `pushed/<jti>.<kind>.meta` | push-ack state for retention (`pushed_bytes`, `acked_at`), one per log kind |

`jti` is validated by `safe_jti_path` before use as a path component (it's
attacker-influenced pre-verification): alnum/`-`/`_` only, with a realpath-containment check.

## Enforcement is code, not DB permissions

The ephemeral user holds all roles (System Manager), so DB permissions gate nothing.
Enforcement keys entirely off `find_grant_by_sid(frappe.session.sid)` — "is this sid in a
grant file?". Everything that enforces or logs uses that same test:

- `session_guard` on `doc_events["*"]` (`before_validate` → create/write/submit,
  `before_cancel`, `on_trash`, `before_rename` — no separate `after_rename`,
  the {old_name, new_name} payload is fully known before the rename even
  happens): `deny` →
  `frappe.throw(PolicyDeniedError)` before write, logged immediately (nothing
  commits on a deny); `warn` → interstitial `msgprint` + an `after_commit`
  doc-log. Always-log doctypes are decided in the same pass (one log line
  either way, never both) and now cover submit/cancel/rename too, not just
  write/delete. `write`/`submit` log a diff (`Version.get_diff` against the
  pre-save state, computed lazily at commit time so it reflects doc's final
  state); everything else logs the full doc (or `{old_name, new_name}` for
  rename).
- `request_hooks.after_request`: log every whitelisted call; skip safe HTTP verbs
  (GET/HEAD/OPTIONS) unless `policy.log_reads` — the verb, not an endpoint denylist, is the
  version-proof mutation signal. No `before_request` hook — everything's read fresh
  from `frappe.request`/`frappe.session` in `after_request` itself. Params come
  straight from the request object (query args + form + parsed JSON body when
  `request.is_json`), never `frappe.form_dict` (mutable, handler-writable).
- `boot.boot_session`: stamps `bootinfo.access_guard_ephemeral` + a `md5(sid)` login hash
  for the static monitoring bar (`app_include_js`; notice text is not hub-configurable in v1).

`get_enforce_mode()`/policy always read the file, never the DB.

## Reaper ordering gotcha

`_reap_user` deletes the **grant file before the User**. `User.on_trash` →
`login_manager.logout()` → re-fires `on_logout` → `teardown_on_logout` → back into
`_reap_user`. With the grant already gone, the recursed `find_grant_by_sid` returns nothing
and no-ops; delete the User first and it recurses forever. The reaper only ever touches users
in the grant-file-derived namespace (`ephemeral_users()`, never a DB query) — a standing
client user is never deletable, and reuse of an existing email is refused for the same reason
(`EphemeralUserCollisionError`).

## Test approach

- Self-contained, **no running hub**: mint a throwaway PASETO keypair in the test
  (`tests/keys.py`) and sign tokens locally with `pyseto`. `pip install pyseto` first.
- `FrappeTestCase`; tests under `access_guard/access_guard/tests/`.
- To exercise `after_request`, give the test a real request with
  `frappe.utils.set_request(method=..., path="/api/method/<name>")` (or set
  `frappe.form_dict["cmd"]`) — `_resolve_path()` reads `frappe.request.path` /
  `form_dict["cmd"]`, so a mock won't do.
- Run: `bench --site <guard-site> run-tests --app access_guard` (developer mode, app installed).
