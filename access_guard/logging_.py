"""Per-session append-only logfmt logging (PROTOCOL.md §7). Named `logging_`
to avoid shadowing stdlib `logging`. Two files per jti — <jti>.log
(requests) and <jti>.doc.log (doc changes); no per-line type/jti/sid, since
the filename already identifies both. Session lifecycle has no local file —
see log_session_event.
"""

import json
from datetime import datetime, timezone

import frappe
from frappe.auth import SAFE_HTTP_METHODS

from access_guard.config_utils import append_line, logs_dir, safe_jti_path
from access_guard.constants import LOG_KIND_DOC, LOG_KIND_REQUEST
from access_guard.grants import find_grant_by_sid
from access_guard.hub_client import report_session_event
from access_guard.policy import get_policy
from access_guard.protocol import POLICY_LOG_READS, POLICY_MAX_KEY_SIZE_BYTES

_SUFFIX_BY_KIND = {LOG_KIND_REQUEST: ".log", LOG_KIND_DOC: ".doc.log"}


def log_file_path(jti: str, kind: str) -> str:
	return safe_jti_path(logs_dir(), jti, _SUFFIX_BY_KIND[kind])


def _now() -> str:
	return datetime.now(timezone.utc).isoformat()


def _truncate(value: str, max_bytes: int) -> str:
	raw = value.encode("utf-8")
	if len(raw) <= max_bytes:
		return value
	return raw[:max_bytes].decode("utf-8", errors="ignore") + "...(truncated)"


def _to_json(value, max_bytes: int | None = None) -> str:
	"""Compact (no spaces) so the result is always one logfmt token, never
	ambiguous with the space-separated fields around it."""
	try:
		raw = json.dumps(value, separators=(",", ":"), default=str)
	except (TypeError, ValueError):
		raw = json.dumps({"_unserializable": True})
	return _truncate(raw, max_bytes) if max_bytes else raw


def _format_line(fields: dict) -> str:
	"""logfmt: key=value, space-separated. Any value containing whitespace is
	JSON-quoted (json.dumps of a string escapes/quotes it into one token)."""
	parts = []
	for key, value in fields.items():
		if value is None:
			continue
		text = value if isinstance(value, str) else str(value)
		if any(c.isspace() for c in text):
			text = json.dumps(text)
		parts.append(f"{key}={text}")
	return " ".join(parts)


def _write(jti: str, kind: str, fields: dict) -> None:
	append_line(log_file_path(jti, kind), _format_line(fields))


def log_session_event(jti: str, event: str, reason: str | None = None) -> None:
	"""No local file — pushed to the Access Grant via a background worker
	(see report_session_event), not gated on log_sync_enabled. Enqueued so
	an unreachable/slow hub never blocks the request or job this runs in."""
	frappe.enqueue(
		report_session_event, queue="short", enqueue_after_commit=True, jti=jti, event=event, reason=reason
	)


def log_request(sid: str, path: str, http_method: str, status: str, code: int | None, body: str) -> None:
	"""One line per whitelisted call, written from after_request. Safe verbs
	(GET/HEAD/OPTIONS) are skipped unless log_reads is on."""
	jti, _grant = find_grant_by_sid(sid)
	if jti is None:
		return

	policy = get_policy()
	log_reads = bool(policy.get(POLICY_LOG_READS, False))
	if not log_reads and (http_method or "").upper() in SAFE_HTTP_METHODS:
		return

	max_bytes = int(policy.get(POLICY_MAX_KEY_SIZE_BYTES) or 0)
	_write(
		jti,
		LOG_KIND_REQUEST,
		{
			"ts": _now(),
			"path": path,
			"http_method": http_method,
			"status": status,
			"code": code,
			"body": _truncate(body, max_bytes) if max_bytes else body,
		},
	)


def log_doc_event(sid: str, doctype: str, name: str, action: str, doc: dict) -> None:
	"""Called after_commit. `doc` is the full state at commit time, not a
	diff — size-exempt (DESIGN.md: sensitive-doctype changes)."""
	jti, _grant = find_grant_by_sid(sid)
	if jti is None:
		return
	_write(
		jti,
		LOG_KIND_DOC,
		{
			"ts": _now(),
			"event": action,
			"doctype": doctype,
			"name": name,
			"doc": _to_json(doc),
		},
	)
