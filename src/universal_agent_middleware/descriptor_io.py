"""Descriptor-relative access beneath a workspace root: the check and the open are one act.

``resolve_safe_path`` used to check a path and ``Path.read_bytes`` opened it later. Between the two the filesystem can
change: a component replaced by a symlink after the check is followed by the open, and ``O_NOFOLLOW`` protects only
the LAST component. The reader here walks the names itself, one component at a time, and never lets the kernel follow
a link on its behalf:

* every directory is opened with ``O_DIRECTORY | O_NOFOLLOW`` relative to the descriptor of its parent (``dir_fd``);
* every component NAME is checked against the sensitive-name rules before it is opened, including the names that come
  out of a symlink target, so an innocent-looking alias of a denied file is denied by where it really lives;
* a symlink is resolved here, by reading its text (``readlink`` relative to the parent descriptor), bounded to
  ``MAX_SYMLINK_HOPS`` and kept beneath the root; an absolute target is accepted only if it names something below the
  root, and is then walked again from the root by name (so nothing the kernel resolves is trusted);
* the object that was opened is judged by ``fstat`` of the descriptor, and every byte is read from that same descriptor
  against a budget counted on the bytes actually read, never on an earlier ``stat``.

A link swapped in after a name was validated makes the ``O_NOFOLLOW`` open fail (``PathChangedError``); it is never
followed. The platform has to provide the primitives: where it does not, ``require_descriptor_walk`` refuses the
operation. There is no fallback to opening by path.

What this does NOT prove: it constrains this process's own opens. It says nothing about what a subprocess (Git,
ripgrep) opens by itself; those are bounded and tested separately. A hard link is the same bytes under another name and
is judged by ``PathPolicy`` from the held object's link count, not here.
"""
from __future__ import annotations

import errno
import os
import stat
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

from .errors import PathPolicyError, WorkspaceError
from .policy import is_denied_component

MAX_SYMLINK_HOPS = 8
READ_CHUNK_BYTES = 64 * 1024
_RACE_ERRNOS = frozenset({errno.ELOOP, errno.ENOTDIR, errno.EMLINK})


class DescriptorWalkUnsupported(WorkspaceError):
    """The platform lacks descriptor-relative open; content access is refused instead of done by path."""


class PathChangedError(WorkspaceError, OSError):
    """A name that was validated no longer names what it named (a link or another type was swapped in).

    Typed and coded so that a tool answers it (``PATH_CHANGED``, retryable) instead of letting it escape the tool body;
    it stays an ``OSError`` for the callers that treat any I/O failure alike. The entry name is deliberately NOT part of
    the error: a message that echoes it reaches a client's error text and the server's logs.
    """

    code = "PATH_CHANGED"

    def __init__(self, name: str = "") -> None:  # ``name`` is accepted so every raise site reads alike, then dropped
        super().__init__("the path changed while it was being opened; nothing was read, retry")
        self.errno = errno.ELOOP


class NotADirectoryTarget(WorkspaceError):
    """The path as written names something that is not a directory where a directory was wanted."""


class OpenDenied(WorkspaceError, PermissionError):
    """The operating system refused the final open for UAM's own account. ``info`` is the entry's ``lstat``.

    Coded (``PATH_UNREADABLE``) for the tools that answer it as an error, and still a ``PermissionError`` for the
    callers that treat an OS refusal as a result. Like ``PathChangedError`` it never carries the entry name.
    """

    code = "PATH_UNREADABLE"
    info: os.stat_result

    def __init__(self, err: int, strerror: str | None, name: str) -> None:  # strerror and name: see the class docstring
        super().__init__("the operating system refused this account access to the path; nothing was read")
        self.errno = err


def _probe_walk_support() -> bool:
    """Whether every primitive the walk depends on exists here. Nothing is assumed from the platform name."""
    return bool(
        hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd and os.stat in os.supports_follow_symlinks
        and os.readlink in os.supports_dir_fd
        and os.scandir in os.supports_fd
    )


# Probed once, at import, with the real functions: a later patch of ``os.open`` (a test double, an instrumented build)
# must not be able to turn the answer into "unsupported" or, worse, hide a platform that really lacks a primitive.
_WALK_SUPPORTED = _probe_walk_support()


def descriptor_walk_supported() -> bool:
    return _WALK_SUPPORTED


def require_descriptor_walk() -> None:
    if not descriptor_walk_supported():
        raise DescriptorWalkUnsupported(
            "descriptor-relative open is not available on this platform: content access is refused "
            "(it is never done by path)"
        )


def _dir_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _file_flags() -> int:
    # O_NONBLOCK: a FIFO swapped in must not block the open. O_NOCTTY: a terminal must not become ours.
    return (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOCTTY", 0))


def open_child(name: str, dir_fd: int, *, directory: bool) -> int:
    """Open one entry of ``dir_fd`` without following a link. A link or a type change raises ``PathChangedError``."""
    require_descriptor_walk()
    try:
        return os.open(name, _dir_flags() if directory else _file_flags(), dir_fd=dir_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        if exc.errno in _RACE_ERRNOS:
            raise PathChangedError(name) from exc
        raise


def list_directory(dir_fd: int) -> list[os.DirEntry[str]]:
    """The entries of an open directory, read through its descriptor."""
    with os.scandir(dir_fd) as iterator:
        return list(iterator)


@dataclass
class Opened:
    """An object opened by walking names from the root. ``fd`` is owned by this value: use it as a context manager."""

    fd: int
    parts: tuple[str, ...]  # the components below the root of what was REALLY opened (symlinks already resolved)
    info: os.stat_result  # fstat of ``fd`` taken right after the open

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> Opened:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()


def open_root(root: Path) -> int:
    """Open the workspace root directory (its own last component must not be a link)."""
    require_descriptor_walk()
    try:
        return os.open(root, _dir_flags())
    except FileNotFoundError:
        raise
    except OSError as exc:
        if exc.errno in _RACE_ERRNOS:
            raise WorkspaceError("workspace root is not a directory") from exc
        raise


def _names_below_root(root_real: Path, target: str) -> list[str]:
    """The component names an ABSOLUTE symlink target gives below the root, or a refusal.

    ``realpath`` is used only to derive NAMES. Every name is then validated and opened one component at a time
    without following links, so whatever the kernel would have resolved is not trusted.
    """
    resolved = Path(os.path.realpath(target))
    try:
        return list(resolved.relative_to(root_real).parts)
    except ValueError as exc:
        raise PathPolicyError("resolved path escapes workspace") from exc


def open_beneath(root_fd: int, root_real: Path, parts: Sequence[str], *, kind: str) -> Opened:
    """Open ``parts`` below the root and return the descriptor of what is really there.

    ``kind`` is ``"file"`` (a regular file) or ``"dir"``. Raises ``PathPolicyError`` for a denied name, an escape
    or a link loop, ``FileNotFoundError`` for a missing name, ``WorkspaceError`` for the wrong type, and
    ``PathChangedError`` if the tree changes under the walk.
    """
    require_descriptor_walk()
    if kind not in ("file", "dir"):
        raise ValueError(f"unknown kind: {kind}")
    pending: deque[str] = deque(parts)
    entered: list[int] = []  # descriptors of the directories entered below the root, innermost last
    below: list[str] = []  # their names
    hops = 0
    try:
        while pending:
            name = pending.popleft()
            if name in ("", "."):
                continue
            current = entered[-1] if entered else root_fd
            if name == "..":  # only a symlink target can name it: callers refuse it in a path as written
                if not entered:
                    raise PathPolicyError("resolved path escapes workspace")
                os.close(entered.pop())
                below.pop()
                continue
            if "\0" in name:
                raise PathPolicyError("invalid path component")
            if is_denied_component(name):
                if hops:  # a name out of a link's target, not one the caller sent: refuse without repeating it
                    raise PathPolicyError("denied resolved path component")
                raise PathPolicyError(f"denied path component: {name}")
            info = os.stat(name, dir_fd=current, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                hops += 1
                if hops > MAX_SYMLINK_HOPS:
                    raise PathPolicyError("too many levels of symbolic links")
                target = os.readlink(name, dir_fd=current)
                if target.startswith("/"):
                    for descriptor in entered:
                        os.close(descriptor)
                    entered.clear()
                    below.clear()
                    pending.extendleft(reversed(_names_below_root(root_real, target)))
                else:
                    pending.extendleft(reversed(target.split("/")))
                continue
            while pending and pending[0] in ("", "."):
                pending.popleft()
            if pending:  # an intermediate component has to be a directory
                if not stat.S_ISDIR(info.st_mode):
                    raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), name)
                entered.append(open_child(name, current, directory=True))
                below.append(name)
                continue
            if kind == "dir":
                if not stat.S_ISDIR(info.st_mode):
                    raise NotADirectoryTarget("path is not a directory")
            elif not stat.S_ISREG(info.st_mode):  # judged BEFORE the open: a FIFO or device is never opened
                raise WorkspaceError("path is not a file")
            try:
                descriptor = open_child(name, current, directory=(kind == "dir"))
            except PermissionError as exc:
                denied = OpenDenied(exc.errno, exc.strerror, name)
                denied.info = info
                raise denied from exc
            held = os.fstat(descriptor)
            wanted = stat.S_ISDIR if kind == "dir" else stat.S_ISREG
            if not wanted(held.st_mode):
                os.close(descriptor)
                raise PathChangedError(name)
            return Opened(descriptor, (*below, name), held)
        # The walk ended on a directory (an empty path, or a link that names one): only a directory is wanted.
        if kind != "dir":
            raise WorkspaceError("path is not a file")
        landed = entered[-1] if entered else root_fd
        duplicate = os.dup(landed)
        return Opened(duplicate, tuple(below), os.fstat(duplicate))
    finally:
        for descriptor in entered:
            os.close(descriptor)


def stat_beneath(root_fd: int, root_real: Path, parts: Sequence[str], *, kind: str) -> os.stat_result:
    """``fstat`` of what ``parts`` really names right now (walked again, links never followed by the kernel)."""
    with open_beneath(root_fd, root_real, parts, kind=kind) as opened:
        return opened.info


def read_bounded(descriptor: int, limit: int) -> bytes | None:
    """Read the whole file from ``descriptor``, or ``None`` if it holds more than ``limit`` bytes.

    The budget is counted on the bytes actually read: a file that grew after any earlier ``stat`` is still cut off
    at ``limit + 1`` bytes and never held in memory.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(READ_CHUNK_BYTES, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
