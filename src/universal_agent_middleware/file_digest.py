"""Bounded, change-detecting SHA-256 of a file's raw bytes.

``digest_file`` is the byte-level half of ``file_digest``: the caller has already been authorised
(``WorkspaceReader`` decides that exactly as it does for a read) and hands over a resolved path. The
answer never contains content, and it only claims a digest for a file that stayed the same file,
with the same size and modification time, from before the first byte to after the last one.

A digest that cannot be claimed is reported as incomplete with a reason, and carries no digest at
all (a hash of a partial or shifting file proves nothing and is easy to mistake for a proof):

* ``byte_limit``: the file is, or grew to be, larger than ``max_bytes``;
* ``time_limit``: hashing took longer than ``max_seconds``;
* ``changed_while_hashing``: the path was replaced, removed or turned into a link, or the file's
  size or modification time moved while it was read;
* ``os_permission_denied``: the operating system refused to open the file for UAM's own account.

Limits of the guarantee: ``max_seconds`` is checked between chunks, so a single read that blocks on
a stalled device is not interrupted, and a file rewritten in place with the same size and the same
modification time (the clock is the only witness) is indistinguishable from an unchanged one.
"""
from __future__ import annotations

import errno
import hashlib
import os
import stat
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import UAMError, WorkspaceError

CHUNK_BYTES = 1024 * 1024
DEFAULT_MAX_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_SECONDS = 10.0

_PATH_NO_LONGER_A_FILE = frozenset({errno.ENOENT, errno.ENOTDIR, errno.ELOOP, errno.EISDIR})

_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)  # a link swapped in after the path was resolved is not followed
    | getattr(os, "O_NONBLOCK", 0)  # a FIFO swapped in must not block the open
    | getattr(os, "O_CLOEXEC", 0)
)


def _open_readonly(path: Path) -> int:
    return os.open(path, _OPEN_FLAGS)


def _read_chunk(descriptor: int, size: int) -> bytes:
    return os.read(descriptor, size)


def _modified_at(mtime_ns: int) -> str:
    seconds, nanoseconds = divmod(mtime_ns, 1_000_000_000)
    moment = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return moment.replace(microsecond=nanoseconds // 1000).isoformat()


def _same_file(before: os.stat_result, now: os.stat_result) -> bool:
    return (now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns) == (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
    )


def _new_result(before: os.stat_result) -> dict[str, Any]:
    return {
        "algorithm": "sha256",
        "complete": False,
        "sha256": None,
        "size_bytes": before.st_size,
        "bytes_hashed": 0,
        "mtime_ns": before.st_mtime_ns,
        "modified_at": _modified_at(before.st_mtime_ns),
        "permission_check": {"os_read": "allowed"},
        "reason": None,
    }


def digest_denied(info: os.stat_result) -> dict[str, Any]:
    """The answer for a file the operating system refused to open for UAM's own account."""
    result = _new_result(info)
    result["permission_check"] = {"os_read": "denied"}
    result["reason"] = "os_permission_denied"
    return result


def _hash_open_descriptor(
    descriptor: int,
    before: os.stat_result,
    result: dict[str, Any],
    restat: Callable[[], os.stat_result],
    max_bytes: int,
    max_seconds: float,
    clock: Callable[[], float],
    started: float,
) -> dict[str, Any]:
    """Hash an open descriptor (closed here). ``restat`` re-reads what the name refers to after the last byte."""
    hasher = hashlib.sha256()
    hashed = 0
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_file(before, opened):
            result["reason"] = "changed_while_hashing"
            return result
        while True:
            if clock() - started > max_seconds:
                result["reason"] = "time_limit"
                break
            chunk = _read_chunk(descriptor, CHUNK_BYTES)
            if not chunk:
                break
            if hashed + len(chunk) > max_bytes:
                result["reason"] = "byte_limit"
                break
            hashed += len(chunk)
            hasher.update(chunk)
    finally:
        os.close(descriptor)
        result["bytes_hashed"] = hashed

    if result["reason"] is not None:
        return result
    # Judged on the name, not on the descriptor: a rename leaves the descriptor on the old file, while the name
    # (what the caller named) now answers for another one.
    try:
        after = restat()
    except (OSError, UAMError):
        result["reason"] = "changed_while_hashing"
        return result
    if hashed != before.st_size or not _same_file(before, after):
        result["reason"] = "changed_while_hashing"
        return result
    result.update(complete=True, sha256=hasher.hexdigest())
    return result


def digest_file(
    target: Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Digest a file given by path (the caller has resolved and authorised it).

    The workspace reader no longer comes through here: it opens the file by walking names from the workspace root and
    calls ``digest_opened_file``. This path-based form remains for callers that hold only a path.
    """
    started = clock()
    try:
        before = os.stat(target)
    except OSError as exc:
        raise WorkspaceError(f"digest failed: {type(exc).__name__}") from exc
    result = _new_result(before)
    if before.st_size > max_bytes:
        result["reason"] = "byte_limit"
        return result

    try:
        descriptor = _open_readonly(target)
    except PermissionError:
        return digest_denied(before)
    except OSError as exc:
        if exc.errno not in _PATH_NO_LONGER_A_FILE:
            raise WorkspaceError(f"digest failed: {type(exc).__name__}") from exc
        # Removed, or a link where the regular file was: the path no longer names the file that
        # was measured.
        result["reason"] = "changed_while_hashing"
        return result
    return _hash_open_descriptor(descriptor, before, result, lambda: os.stat(target), max_bytes, max_seconds, clock, started)


def digest_opened_file(
    descriptor: int,
    *,
    restat: Callable[[], os.stat_result],
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Digest a regular file that is ALREADY open; the descriptor is closed by this call.

    The open was the authorisation point (see ``descriptor_io.open_beneath``): every byte hashed comes from this
    descriptor. ``restat`` is called after the last byte and must return the ``stat`` of what the file's NAME refers to
    now, so a file replaced or renamed meanwhile is reported as ``changed_while_hashing`` and gets no digest.
    """
    started = clock()
    try:
        before = os.fstat(descriptor)
    except OSError as exc:
        os.close(descriptor)
        raise WorkspaceError(f"digest failed: {type(exc).__name__}") from exc
    result = _new_result(before)
    if before.st_size > max_bytes:
        os.close(descriptor)
        result["reason"] = "byte_limit"
        return result
    return _hash_open_descriptor(descriptor, before, result, restat, max_bytes, max_seconds, clock, started)