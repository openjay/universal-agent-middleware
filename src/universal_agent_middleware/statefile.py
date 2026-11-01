"""Small durable-write primitives for UAM's own state files (POSIX only).

UAM's state directory is written by more than one process (the read-only server, the task-control
server, a command-line client), so a state file must never be observable half-written and an
"already exists" must be decided atomically, not by a check followed by a write.

* ``write_new``: create a file with its full content or not at all; ``FileExistsError`` if it exists.
* ``replace``: swap a file's content atomically (readers see the old or the new content, never a mix).
* ``exclusive_lock``: a blocking advisory lock held for the duration of a read-modify-write.

These are the same guarantees the hash-chained audit log relies on (process locking, POSIX
semantics). They protect against torn writes and concurrent writers on one host; they are not an
authentication mechanism and do not defend against another process running as the same user.
"""
from __future__ import annotations

import fcntl
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def _sync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_temporary(directory: Path, text: str) -> str:
    descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=".state-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        os.unlink(temporary)
        raise
    return temporary


def write_new(path: Path, text: str) -> None:
    """Create ``path`` holding ``text``, atomically and exclusively.

    The content is written and flushed to a temporary file first and linked into place, so ``path``
    never exists without its full content, and two writers racing for the same ``path`` cannot both
    succeed (the loser gets ``FileExistsError``).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = _write_temporary(path.parent, text)
    try:
        os.link(temporary, path)
    finally:
        os.unlink(temporary)
    _sync_directory(path.parent)


def replace(path: Path, text: str) -> None:
    """Atomically replace the content of ``path`` (creating it if needed)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = _write_temporary(path.parent, text)
    try:
        os.replace(temporary, path)
    except BaseException:
        os.unlink(temporary)
        raise
    _sync_directory(path.parent)


@contextmanager
def exclusive_lock(lock_path: Path) -> Iterator[None]:
    """Hold a blocking advisory lock on ``lock_path`` (created owner-only) for the ``with`` body."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)
