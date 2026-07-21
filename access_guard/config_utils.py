"""Guard-side configuration and on-disk layout helpers.

Named `config_utils` (not `config`) to avoid clashing with the Frappe
convention where `<app>/config/` is a package of desktop/module config.

Everything integrity-critical lives under `site/private/access_guard/`
(see protocol.py's PRIVATE_DIR et al.) — never in a DocType or the DB,
because the client DB is attacker-controlled (an ephemeral user can
become System Manager here). This module only deals with:
- reading + validating the three required site_config.json keys,
- resolving/creating the private directory tree,
- small atomic-write / file-lock helpers shared by every other module
  that persists integrity-critical state to disk.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
import tempfile

import frappe

from access_guard.protocol import (
    GRANTS_SUBDIR,
    LOGS_SUBDIR,
    POLICY_FILE,
    PRIVATE_DIR,
    PUSHED_SUBDIR,
    REQUIRED_GUARD_CONF,
    USED_JTI_FILE,
    ClientNotConfiguredError,
)


def get_guard_conf() -> dict:
    """Return the three required guard config values from frappe.conf.

    Raises ClientNotConfiguredError if any is missing/blank. Callers on the
    accept path MUST call this before doing anything else (PROTOCOL.md §1).
    """
    conf = frappe.conf
    values = {}
    missing = []
    for key in REQUIRED_GUARD_CONF:
        val = conf.get(key)
        if not val:
            missing.append(key)
        else:
            values[key] = val
    if missing:
        raise ClientNotConfiguredError(
            f"Missing required guard configuration: {', '.join(missing)}"
        )
    return values


def private_base_dir() -> str:
    """Absolute path to site/private/access_guard, creating it (and its
    standard subdirectories) lazily if it doesn't exist yet."""
    base = frappe.get_site_path("private", PRIVATE_DIR)
    os.makedirs(base, mode=0o700, exist_ok=True)
    for sub in (GRANTS_SUBDIR, LOGS_SUBDIR, PUSHED_SUBDIR):
        os.makedirs(os.path.join(base, sub), mode=0o700, exist_ok=True)
    return base


def grants_dir() -> str:
    return os.path.join(private_base_dir(), GRANTS_SUBDIR)


def logs_dir() -> str:
    return os.path.join(private_base_dir(), LOGS_SUBDIR)


def pushed_dir() -> str:
    return os.path.join(private_base_dir(), PUSHED_SUBDIR)


def used_jti_path() -> str:
    return os.path.join(private_base_dir(), USED_JTI_FILE)


def policy_path() -> str:
    return os.path.join(private_base_dir(), POLICY_FILE)


def safe_jti_path(directory: str, jti: str, suffix: str) -> str:
    """Build `<directory>/<jti><suffix>`, refusing any jti that is not a
    plain-looking token (path-traversal guard: jti is attacker-influenced —
    it comes from an unverified-at-parse-time token claim before signature
    verification completes in some call paths, so never trust it as a path
    component without checking)."""
    if not jti or not isinstance(jti, str):
        raise ValueError("invalid jti")
    # jti is a uuid4 hex per protocol; be strict rather than merely "safe".
    if not all(c.isalnum() or c in "-_" for c in jti) or "/" in jti or ".." in jti:
        raise ValueError("invalid jti")
    path = os.path.join(directory, f"{jti}{suffix}")
    real_dir = os.path.realpath(directory)
    real_path = os.path.realpath(path)
    if os.path.commonpath([real_dir, real_path]) != real_dir:
        raise ValueError("path traversal detected")
    return path


@contextlib.contextmanager
def locked_file(lock_path: str):
    """A simple per-file advisory lock (flock) used to serialize
    read-modify-write cycles on shared JSON state files (used-jti store,
    policy file, grant files) across concurrent workers/requests."""
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def atomic_write_json(path: str, data) -> None:
    """Write JSON atomically: write-temp in the same directory, fsync, then
    os.rename over the target. Avoids partial/corrupt files on crash."""
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp_path, path)
    except Exception:
        with contextlib.suppress(OSError):
            os.remove(tmp_path)
        raise


def read_json(path: str, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except (OSError, json.JSONDecodeError):
        return default


def append_line(path: str, line: str) -> None:
    """Open-append-close a single line to a log file. Deliberately not
    buffered/cached — traffic here is a human doing manual ops (low volume),
    per DESIGN.md; a stray fd leak from a persistent logger is worse."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        os.write(fd, (line if line.endswith("\n") else line + "\n").encode("utf-8"))
    finally:
        os.close(fd)


def ensure_errno_dir(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
