"""File-backed grant records + used-jti replay store.

Both are integrity-critical (PROTOCOL.md §6) and therefore live under
site/private/access_guard/ — never in a DocType. Concurrency is handled
with a simple flock per shared file.
"""

import os

import frappe

from access_guard.config_utils import (
	atomic_write_json,
	grants_dir,
	locked_file,
	read_json,
	safe_jti_path,
	used_jti_path,
)
from access_guard.protocol import TokenReplayError


def is_jti_used(jti: str) -> bool:
	data = read_json(used_jti_path(), default={})
	return jti in data


def mark_jti_used(jti: str) -> None:
	"""Atomically check-and-set. Raises TokenReplayError if already used.

	Locked so two concurrent accept() calls for the same jti can't both
	pass the check before either writes (the actual replay-prevention
	guarantee, not just a convenience wrapper).
	"""
	path = used_jti_path()
	lock_path = path + ".lock"
	with locked_file(lock_path):
		data = read_json(path, default={})
		if jti in data:
			raise TokenReplayError(f"jti already used: {jti}")
		data[jti] = frappe.utils.now_datetime().isoformat()
		atomic_write_json(path, data)


def grant_file_path(jti: str) -> str:
	return safe_jti_path(grants_dir(), jti, ".json")


def write_grant(jti: str, record: dict) -> None:
	lock_path = grant_file_path(jti) + ".lock"
	with locked_file(lock_path):
		atomic_write_json(grant_file_path(jti), record)


def read_grant(jti: str) -> dict | None:
	return read_json(grant_file_path(jti), default=None)


def update_grant(jti: str, **fields) -> dict | None:
	path = grant_file_path(jti)
	lock_path = path + ".lock"
	with locked_file(lock_path):
		record = read_json(path, default=None)
		if record is None:
			return None
		record.update(fields)
		atomic_write_json(path, record)
		return record


def all_grants() -> dict[str, dict]:
	"""jti -> grant record, for every grant file currently on disk."""
	out = {}
	d = grants_dir()
	if not os.path.isdir(d):
		return out
	for name in os.listdir(d):
		if not name.endswith(".json"):
			continue
		jti = name[: -len(".json")]
		record = read_json(os.path.join(d, name), default=None)
		if record is not None:
			out[jti] = record
	return out


def delete_grant(jti: str) -> None:
	path = grant_file_path(jti)
	lock_path = path + ".lock"
	with locked_file(lock_path):
		try:
			os.remove(path)
		except FileNotFoundError:
			pass
	try:
		os.remove(lock_path)
	except FileNotFoundError:
		pass


def find_grant_by_sid(sid: str) -> tuple[str, dict] | tuple[None, None]:
	"""'Is this session ephemeral?' — frappe.session.sid appears as `sid` in
	some grant file (PROTOCOL.md §6)."""
	for jti, record in all_grants().items():
		if record.get("sid") == sid:
			return jti, record
	return None, None


def ephemeral_users() -> set[str]:
	"""Namespace filter: only users named in grant files may ever be touched
	by the reaper. Never derived from any DB query — grant files are the
	sole source of truth for "which users are ephemeral"."""
	return {record.get("user") for record in all_grants().values() if record.get("user")}
