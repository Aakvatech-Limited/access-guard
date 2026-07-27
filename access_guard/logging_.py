"""Per-session append-only JSONL logging (PROTOCOL.md §7).

Named `logging_` to avoid shadowing stdlib `logging` (and because we
deliberately do NOT use frappe.logger / a per-sid logging.Logger — see
DESIGN.md "Logging"). One file per jti, plain open-append-close per line.
"""

import json
from datetime import datetime, timezone

from access_guard.config_utils import append_line, logs_dir, safe_jti_path
from access_guard.constants import LOG_TYPE_DOC, LOG_TYPE_REQUEST, LOG_TYPE_SESSION, READ_SKIP_METHODS
from access_guard.grants import find_grant_by_sid
from access_guard.policy import get_policy
from access_guard.protocol import POLICY_LOG_READS, POLICY_MAX_KEY_SIZE_BYTES


def log_file_path(jti: str) -> str:
	return safe_jti_path(logs_dir(), jti, ".jsonl")


def _now() -> str:
	return datetime.now(timezone.utc).isoformat()


def _truncate_args(args, max_bytes: int):
	try:
		raw = json.dumps(args, default=str)
	except (TypeError, ValueError):
		return {"_unserializable": True}
	if len(raw.encode("utf-8")) <= max_bytes:
		return args
	return {"_truncated": True, "preview": raw[: max(0, max_bytes)]}


def _write(jti: str, record: dict) -> None:
	append_line(log_file_path(jti), json.dumps(record, default=str))


def doc_diff(doc) -> dict:
	try:
		before = doc.get_doc_before_save()
	except Exception:
		before = None
	if not before:
		return {"after": doc.as_dict()}
	return {"before": before.as_dict(), "after": doc.as_dict()}


def log_session_event(jti: str, sid: str | None, event: str, reason: str | None = None) -> None:
	record = {"ts": _now(), "jti": jti, "sid": sid, "type": LOG_TYPE_SESSION, "event": event}
	if reason:
		record["reason"] = reason
	_write(jti, record)


def log_request(sid: str, method: str, status: str, args) -> None:
	"""Called from before_request/after_request. Looks up jti from sid via
	the grant file (the authoritative sid<->jti map); no-op for non-
	ephemeral sessions (nothing to log against)."""
	jti, _grant = find_grant_by_sid(sid)
	if jti is None:
		return

	policy = get_policy()
	log_reads = bool(policy.get(POLICY_LOG_READS, False))
	if not log_reads and method in READ_SKIP_METHODS:
		return

	max_bytes = int(policy.get(POLICY_MAX_KEY_SIZE_BYTES) or 0)
	record = {
		"ts": _now(),
		"jti": jti,
		"sid": sid,
		"type": LOG_TYPE_REQUEST,
		"method": method,
		"status": status,
		"args": _truncate_args(args, max_bytes) if max_bytes else args,
	}
	_write(jti, record)


def log_doc_event(sid: str, doctype: str, name: str, action: str, diff: dict) -> None:
	"""Called from an after_commit callback registered in doc_events —
	no commit, no call, so this function itself has no rollback concern.
	Exempt from the size cap (DESIGN.md: sensitive-doctype diffs are
	size-exempt)."""
	jti, _grant = find_grant_by_sid(sid)
	if jti is None:
		return
	record = {
		"ts": _now(),
		"jti": jti,
		"sid": sid,
		"type": LOG_TYPE_DOC,
		"doctype": doctype,
		"name": name,
		"action": action,
		"diff": diff,
	}
	_write(jti, record)
