"""Per-session append-only logfmt logging (PROTOCOL.md §7). Named `logging_`
to avoid shadowing stdlib `logging`. Two files per jti — <jti>.request.log
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

_SUFFIX_BY_KIND = {LOG_KIND_REQUEST: ".request.log", LOG_KIND_DOC: ".doc.log"}


def log_file_path(jti: str, kind: str) -> str:
	return safe_jti_path(logs_dir(), jti, _SUFFIX_BY_KIND[kind])


def _now() -> str:
	return datetime.now(timezone.utc).isoformat()


_TRUNCATED_MARKER = "<truncated>"


def _truncate(value: str, max_bytes: int) -> str:
	"""Cap `value` at max_bytes total, marker included - not max_bytes of
	content plus the marker on top (the previous version returned up to
	len(marker) bytes over the cap)."""
	raw = value.encode("utf-8")
	if len(raw) <= max_bytes:
		return value
	marker = _TRUNCATED_MARKER.encode("utf-8")
	budget = max(0, max_bytes - len(marker))
	return raw[:budget].decode("utf-8", errors="ignore") + _TRUNCATED_MARKER


def _dump_json(value) -> str:
	"""Compact (no spaces) so the result is always one logfmt token, never
	ambiguous with the space-separated fields around it."""
	try:
		return json.dumps(value, separators=(",", ":"), default=str)
	except (TypeError, ValueError):
		return json.dumps({"_unserializable": True})


def _to_json(value, max_bytes: int | None = None) -> str:
	raw = _dump_json(value)
	return _truncate(raw, max_bytes) if max_bytes else raw


def _capped_value(val, max_bytes: int | None = None):
	"""A string is truncated as-is; anything else is JSON-dumped first, then
	truncated - keeps a plain string field from picking up an extra layer of
	quoting/escaping in the final log line. No truncation at all when
	max_bytes is falsy (same "0/None means unconfigured" convention as
	_to_json), not "truncate to zero bytes"."""
	text = val if isinstance(val, str) else _dump_json(val)
	return _truncate(text, max_bytes) if max_bytes else text


def _to_json_per_key(value, max_bytes: int | None = None) -> str | None:
	"""For a dict, each top-level value is capped independently (one huge
	value can't crowd out or hide a small one elsewhere in the same dict) -
	used for both `params` and a JSON-object `body`, so a large field nested
	in either can't push a small one out of the line. Falls back to
	whole-value capping (via _capped_value, so a plain string doesn't pick up
	an extra layer of JSON quoting) for anything that isn't a dict -
	best-effort, not a parser."""
	if not value:
		return
	if not max_bytes or not isinstance(value, dict):
		return _capped_value(value, max_bytes)
	capped = {key: _capped_value(val, max_bytes) for key, val in value.items()}
	return _dump_json(capped)


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


def log_request(
	sid: str,
	path: str,
	http_method: str,
	status: str,
	code: int | None,
	params: dict,
	body=None,
) -> None:
	"""One line per whitelisted call, written from after_request. Safe verbs
	(GET/HEAD/OPTIONS) are skipped unless log_reads is on. `params` (query args
	+ form-encoded fields) and `body` (the request body - parsed JSON, or the
	raw string if not JSON) are logged as separate fields - never merged into
	one dict, which would risk a JSON body key colliding with an actual
	query/form field of the same name. Both go through _to_json_per_key: each
	top-level key is truncated independently when the value is a dict (so one
	oversized field, in params or in a JSON-object body, can't push a small
	one out of the line), or the whole value is capped when it isn't."""
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
			"params": _to_json_per_key(params, max_bytes),
			"body": _to_json_per_key(body, max_bytes),
		},
	)


def log_doc_event(
	sid: str, doctype: str, name: str, action: str, *, doc: dict | None = None, diff: dict | None = None
) -> None:
	"""Called after_commit (or synchronously for a denied attempt, which
	never commits). Exactly one of doc/diff is given:
	- doc: full state at commit time - create, cancel, delete, and any
	  denied attempt (nothing to diff against, or the doc is gone/never
	  existed).
	- diff: Version.get_diff(before, after) shape - write and submit, where
	  a before-state exists and the full doc would mostly repeat unchanged
	  fields already on the hub from a prior event.
	Size-exempt either way (DESIGN.md: sensitive-doctype changes)."""
	jti, _grant = find_grant_by_sid(sid)
	if jti is None:
		return
	fields = {
		"ts": _now(),
		"event": action,
		"doctype": doctype,
		"name": name,
	}
	if doc is not None:
		fields["doc"] = _to_json(doc)
	if diff is not None:
		fields["diff"] = _to_json(diff)
	_write(jti, LOG_KIND_DOC, fields)
