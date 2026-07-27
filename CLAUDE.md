# access_guard

Client-side enforcement and logging for ephemeral Frappe site access.

## Security model
- Client DB is attacker-controlled. Never trust it for authorization/integrity decisions — keep integrity state in files, not client-writable doctypes.
- Policy on tamper/violation: deny + warn (not silent allow, not hard lock). Confirmed choice — don't switch to auto-lockout without asking.

## Scope
- Enforcement/logging lives here; enrollment issuance lives in `access_hub`. Don't duplicate enrollment logic — check the sibling app first.

## Typing
- Don't use `from __future__ import annotations` in files with `@frappe.whitelist()` (or
  `@guest_api`-wrapped) endpoints (or anywhere, for consistency — neither app needs it:
  `requires-python = ">=3.10"` and `X | None` already works natively at runtime). Frappe's
  `validate_argument_types` (`frappe/utils/typing_validations.py`) does runtime pydantic
  validation/coercion of whitelisted args based on `func.__annotations__`, but silently skips any
  argument whose annotation is a string/ForwardRef — which is exactly what the future import turns
  every annotation into. So it doesn't error, it just quietly disables argument validation for that
  function.
- Keep whitelisted-function signatures to plain, unparameterized types (`tuple`, not
  `tuple[SomeType, str]`) for the same reason — same file, same silent-skip behavior applies to
  parameterized generics containing a ForwardRef/str in `__args__`.
- Forward references to a class not yet defined: use a quoted string literal
  (`def f() -> "SomeClass":`), not the future import.
