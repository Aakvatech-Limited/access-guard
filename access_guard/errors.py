"""Shared helpers for turning an AccessProtocolError into the wire response
shape mandated by PROTOCOL.md §5: {"error": {"code", "pv", "message"}} with
the class's http_status set on the HTTP response."""

from __future__ import annotations

import functools

import frappe

from access_guard.protocol import AccessProtocolError


def respond_with_error(exc: AccessProtocolError) -> None:
    frappe.local.response["http_status_code"] = exc.http_status
    frappe.local.response.update(exc.as_response())
    # Whitelisted method handlers can `return` after calling this; nothing
    # else should be set on frappe.local.response for this request.


def guest_api(fn):
    """Drop-in replacement for `@frappe.whitelist(allow_guest=True)` on every
    guest-facing access_guard endpoint (PROTOCOL.md §5: accept, receive_policy,
    and any future one). Calls frappe.whitelist internally, then wraps the
    handler so any AccessProtocolError raised anywhere in the call — token
    verification, policy verification, whatever — is caught exactly once and
    turned into the standard error response via respond_with_error, instead of
    every handler repeating its own try/except AccessProtocolError block.

    Handlers should just `raise` the appropriate AccessProtocolError subclass
    and return their normal success value; this decorator does the rest.
    """

    @frappe.whitelist(allow_guest=True)
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except AccessProtocolError as e:
            respond_with_error(e)
            return None

    return wrapper
