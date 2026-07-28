"""Shared helpers for turning an AccessProtocolError into the wire response
shape mandated by PROTOCOL.md §5: {"error": {"code", "pv", "message"}} with
the class's http_status set on the HTTP response."""

import frappe

from access_guard.protocol import AccessProtocolError
from access_guard.tokens import verify_hub_token


def respond_with_error(exc: AccessProtocolError) -> None:
	frappe.local.response["http_status_code"] = exc.http_status
	frappe.local.response.update(exc.as_response())
	# Whitelisted method handlers can `return` after calling this; nothing
	# else should be set on frappe.local.response for this request.


def ingest_api(fn):
	"""Drop-in replacement for `@frappe.whitelist(allow_guest=True)` on every
	hub-signed access_guard endpoint (PROTOCOL.md §5: accept, receive_policy,
	and any future one). Mirrors access_hub.api.ingest_endpoint: verifies the
	incoming `token` itself (steps 1-4 of PROTOCOL.md §3 — parse, signature,
	pv, exp) via verify_hub_token, then calls the handler with the decoded
	claims dict rather than the raw token — handlers never re-verify. Any
	AccessProtocolError raised anywhere in the call — token verification, the
	handler itself — is caught exactly once and turned into the standard
	error response via respond_with_error, instead of every handler
	repeating its own try/except AccessProtocolError block.

	The wire field is always named `token` — both endpoints use this same
	name (receive_policy included; the hub posts {"token": ...} to it, not
	{"policy_token": ...}) so there's exactly one call convention, not one
	per endpoint.

	Handlers should take `claims` as their only argument, `raise` the
	appropriate AccessProtocolError subclass for any further (endpoint-
	specific) verification, and return their normal success value.
	"""

	@frappe.whitelist(allow_guest=True)
	def wrapper(token: str | None = None):
		try:
			claims = verify_hub_token(token)
			return fn(claims)
		except AccessProtocolError as e:
			respond_with_error(e)
			return None

	return wrapper
