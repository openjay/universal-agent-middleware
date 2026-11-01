"""An unstaged ``git diff`` built only from objects that were authorized BEFORE they were read.

``git diff`` run inside the observed repository opens worktree files by path, applies the repository's own
configuration and attributes, and prints whatever it read. Every protection that can be put around that (an
exclusion list, a screen over the patch it produced) is a filter on Git's behaviour, not a decision about which
objects may be read, and each of them has a way past it:

* a hard link is the same bytes under another name, so excluding names excludes nothing;
* the work tree Git reads is whatever the repository's configuration says it is (``core.worktree``), and a workspace
  nested in a bigger repository is diffed together with everything outside it;
* Git follows a link or opens a swapped-in file between its own check and its own read;
* one unsupported file (a pipe) fails the whole diff.

So Git is not allowed to look at the work tree at all. This module decides first and reads second:

1. the index is listed once (``git ls-files -s -z --debug``: names, modes, object ids and stat data, no file opened):
   that listing is the only input about WHICH paths are in play, so an entry added to the index afterwards is never
   read;
2. every path is judged by name and by scope authority before anything is opened; a refused path is not even
   ``lstat``-ed;
3. admitted paths are compared with the stat data of the index (as Git does) to find those that may have changed;
   a path that cannot have changed is never read;
4. a path that may have changed is read through descriptors, by this process, with no link followed at any component:
   a regular file with a single name only (a file with other names may be a refused file under an innocent name),
   judged by ``fstat`` of the descriptor that is read, within a byte budget; a link is read as its text, never
   followed; a pipe or device is never opened;
5. the old and the new side of those paths are put into a private, throw-away repository that has no configuration,
   no attributes of its own and no hooks, and Git diffs THAT, so its output is Git's own unstaged-diff format and
   every byte of it comes from an object that was admitted.

What this does not prove: it does not stop the filesystem from changing one admitted name's content between the
``fstat`` and the last ``read`` of that one descriptor (that is detected and the path is dropped, not prevented), and
a file replaced by another file BEFORE the walk is, by name, still an admitted path. Names that were refused are
reported as a count, never by name.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
import threading
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, Final

from .descriptor_io import PathChangedError, open_child, open_root, read_bounded, require_descriptor_walk
from .errors import WorkspaceError
from .models import RootIdentity
from .path_authority import PathPolicy
from .policy import is_denied_component, is_git_metadata_component
from .workspace import open_verified_root, verify_bound_root_fd

MODE_FILE: Final = 0o100644
MODE_EXECUTABLE: Final = 0o100755
MODE_LINK: Final = 0o120000
MODE_GITLINK: Final = 0o160000
_PLAIN_MODES: Final = frozenset({MODE_FILE, MODE_EXECUTABLE, MODE_LINK})

# ``ce_flags`` as ``ls-files --debug`` prints them (hex).
_FLAG_ASSUME_VALID: Final = 0x8000
_FLAG_INTENT_TO_ADD: Final = 0x20000000
_FLAG_SKIP_WORKTREE: Final = 0x40000000

# Why a path is not in the diff. ``refused_name`` and ``scope_denied`` are reported as counts only: the name of a
# refused object is metadata about it. Every other reason names an object whose name is admitted, and is listed.
REFUSED_NAME: Final = "refused_name"
SCOPE_DENIED: Final = "scope_denied"
HARD_LINK: Final = "hard_link"
SPECIAL_FILE: Final = "special_file"
UNREADABLE: Final = "unreadable"
PATH_REPLACED: Final = "path_replaced"
CHANGED_DURING_READ: Final = "changed_during_read"
UNSAFE_PATH: Final = "unsafe_path"
OVER_BUDGET: Final = "over_budget"
UNMERGED: Final = "unmerged"
PATH_COLLISION: Final = "path_collision"
UNSUPPORTED_ENTRY: Final = "unsupported_entry"
OBJECT_MISSING: Final = "object_missing"
_UNNAMED_REASONS: Final = frozenset({REFUSED_NAME, SCOPE_DENIED, UNSAFE_PATH})
MAX_REPORTED_PATHS: Final = 50
_MAX_SUBPROCESS_BYTES: Final = 16 << 20
_MAX_STDERR_BYTES: Final = 64 << 10

_TIME = re.compile(rb"  (?:ctime|mtime): (\d+):(\d+)")
_DEV_INO = re.compile(rb"  dev: (\d+)\tino: (\d+)")
_UID_GID = re.compile(rb"  uid: (\d+)\tgid: (\d+)")
_SIZE_FLAGS = re.compile(rb"  size: (\d+)\tflags: ([0-9a-f]+)")
_HEX_OID = re.compile(rb"[0-9a-f]{40}|[0-9a-f]{64}")
_U32 = 0xFFFFFFFF

# Options for the Git processes that run inside the private repository. It has no configuration worth trusting
# either way, so these are belt and braces: nothing may start a program, page, convert or fetch.
_PRIVATE_OPTIONS: Final = (
    "-c", "core.fsmonitor=false", "-c", "core.pager=cat", "-c", "pager.diff=false", "-c", "diff.external=",
    "-c", f"core.attributesFile={os.devnull}", "-c", f"core.hooksPath={os.devnull}", "-c", "core.autocrlf=false",
    "-c", "core.safecrlf=false", "-c", "core.bigFileThreshold=8m", "-c", "diff.renames=false",
    "-c", "protocol.allow=never",
)
# Highest precedence of every attribute source: nothing converts, filters or re-encodes a file on its way into the
# comparison, whatever a tracked ``.gitattributes`` says. (A driver is configuration, and the private repository has none.)
_PRIVATE_ATTRIBUTES: Final = b"* -text -ident -filter -working-tree-encoding\n"


@dataclass(frozen=True)
class DiffBudgets:
    """Limits of one diff. A path beyond a limit is reported as ``over_budget``, never read and never dropped silently."""

    max_entries: int = 1_000_000
    max_candidates: int = 2_000
    max_file_bytes: int = 4 << 20
    max_total_bytes: int = 16 << 20
    max_diff_bytes: int = 16 << 20
    timeout_seconds: int = 30


@dataclass(frozen=True)
class IndexEntry:
    mode: int
    oid: str
    stage: int
    path: str
    ctime: tuple[int, int]
    mtime: tuple[int, int]
    dev: int
    ino: int
    uid: int
    gid: int
    size: int
    flags: int


@dataclass
class Omissions:
    """The paths a diff does not cover, by reason."""

    reasons: Counter[str] = field(default_factory=Counter)
    paths: list[str] = field(default_factory=list)

    def add(self, reason: str, path: str) -> None:
        self.reasons[reason] += 1
        if reason not in _UNNAMED_REASONS and len(self.paths) < MAX_REPORTED_PATHS:
            self.paths.append(path)

    @property
    def count(self) -> int:
        return sum(self.reasons.values())

    def report(self) -> dict[str, Any]:
        return {"count": self.count, "reasons": dict(sorted(self.reasons.items())), "paths": sorted(self.paths)}


@dataclass(frozen=True)
class SnapshotDiff:
    text: str
    omissions: Omissions
    diff_truncated: bool = False


def _unreadable_listing() -> WorkspaceError:
    return WorkspaceError("git observation failed: the index listing could not be understood")


def parse_index_listing(raw: bytes) -> list[IndexEntry]:
    """The entries of ``git ls-files -s -z --debug``. Anything that does not parse is an error, never a guess."""
    entries: list[IndexEntry] = []
    position = 0
    while position < len(raw):
        tab = raw.find(b"\t", position)
        end = raw.find(b"\0", tab + 1) if tab >= 0 else -1
        if tab < 0 or end < 0:
            raise _unreadable_listing()
        head = raw[position:tab].split(b" ")
        if len(head) != 3 or not _HEX_OID.fullmatch(head[1]) or head[2] not in (b"0", b"1", b"2", b"3"):
            raise _unreadable_listing()
        try:
            mode = int(head[0], 8)
        except ValueError:
            raise _unreadable_listing() from None
        path = os.fsdecode(raw[tab + 1:end])
        position = end + 1
        lines: list[bytes] = []
        for _ in range(5):
            stop = raw.find(b"\n", position)
            if stop < 0:
                raise _unreadable_listing()
            lines.append(raw[position:stop])
            position = stop + 1
        ctime, mtime = _TIME.fullmatch(lines[0]), _TIME.fullmatch(lines[1])
        dev_ino, uid_gid, size_flags = _DEV_INO.fullmatch(lines[2]), _UID_GID.fullmatch(lines[3]), _SIZE_FLAGS.fullmatch(lines[4])
        if not (ctime and mtime and dev_ino and uid_gid and size_flags):
            raise _unreadable_listing()
        entries.append(IndexEntry(
            mode=mode, oid=head[1].decode("ascii"), stage=int(head[2]), path=path,
            ctime=(int(ctime[1]), int(ctime[2])), mtime=(int(mtime[1]), int(mtime[2])),
            dev=int(dev_ino[1]), ino=int(dev_ino[2]), uid=int(uid_gid[1]), gid=int(uid_gid[2]),
            size=int(size_flags[1]), flags=int(size_flags[2], 16),
        ))
    return entries


def _split(path: str) -> tuple[str, ...]:
    return tuple(path.split("/"))


def _unsafe(parts: tuple[str, ...]) -> bool:
    """A path that must never be rebuilt in a scratch tree: it could name a place other than a plain child of it."""
    return any(part in ("", ".", "..") or "\0" in part or is_git_metadata_component(part) for part in parts)


def _executable_mode(info: os.stat_result) -> int:
    if stat.S_ISLNK(info.st_mode):
        return MODE_LINK
    return MODE_EXECUTABLE if info.st_mode & 0o100 else MODE_FILE


def _same_as_index(entry: IndexEntry, info: os.stat_result, index_mtime_ns: int | None) -> bool:
    """Whether the stat data of the worktree entry equals the index's, so that Git itself would not look at the content.

    Conservative on purpose: any difference, a racily-clean entry (not older than the index itself) or an unknown index
    time says "may have changed". Being wrong in that direction costs one read; the other direction would hide a change.
    """
    if index_mtime_ns is None or not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
        return False
    index_time = (index_mtime_ns // 1_000_000_000, index_mtime_ns % 1_000_000_000)
    if entry.mtime >= index_time:
        return False
    return (
        _executable_mode(info) == entry.mode
        and info.st_size & _U32 == entry.size
        and (info.st_mtime_ns // 1_000_000_000 & _U32, info.st_mtime_ns % 1_000_000_000) == entry.mtime
        and (info.st_ctime_ns // 1_000_000_000 & _U32, info.st_ctime_ns % 1_000_000_000) == entry.ctime
        and info.st_ino & _U32 == entry.ino and info.st_dev & _U32 == entry.dev
        and info.st_uid & _U32 == entry.uid and info.st_gid & _U32 == entry.gid
    )


@dataclass(frozen=True)
class Worktree:
    """What is at one admitted path right now: ``absent``, a ``file`` (bytes), a ``link`` (text) or ``refused``."""

    kind: str
    reason: str = ""
    executable: bool = False
    data: bytes = b""
    target: str = ""


_ABSENT: Final = Worktree("absent")


class StrictWalker:
    """Descriptor-relative lookups below a root that never follow a link.

    Unlike ``descriptor_io.open_beneath`` (which resolves link text to serve a reader that asked for a path), a diff
    must compare the path itself, as Git does: a link at any component is a change of the path, not a way through to
    what it points at. Directories stay open while consecutive paths share them.
    """

    def __init__(
        self,
        root: Path,
        *,
        root_identity: RootIdentity | None = None,
        authority_check: Callable[[], None] | None = None,
    ):
        require_descriptor_walk()
        self._root_identity = root_identity
        self._authority_check = authority_check
        if root_identity is not None:
            self._root_fd, _ = open_verified_root(root_identity)
        else:
            self._root_fd = open_root(root)
        if self._authority_check is not None:
            try:
                self._authority_check()
            except BaseException:
                os.close(self._root_fd)
                self._root_fd = -1
                raise
        self._chain: list[tuple[str, int]] = []

    def verify_root(self) -> None:
        if self._root_identity is not None and self._root_fd >= 0:
            verify_bound_root_fd(self._root_fd, self._root_identity)
        if self._authority_check is not None:
            self._authority_check()

    def close(self) -> None:
        while self._chain:
            os.close(self._chain.pop()[1])
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self) -> StrictWalker:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

    def _directory(self, parts: tuple[str, ...]) -> int | None:
        """The descriptor of directory ``parts``, ``None`` if it is not a directory; a link raises ``PathChangedError``."""
        keep = 0
        while keep < len(self._chain) and keep < len(parts) and self._chain[keep][0] == parts[keep]:
            keep += 1
        while len(self._chain) > keep:
            os.close(self._chain.pop()[1])
        for name in parts[keep:]:
            parent = self._chain[-1][1] if self._chain else self._root_fd
            try:
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except (FileNotFoundError, NotADirectoryError):
                return None
            if stat.S_ISLNK(info.st_mode):
                raise PathChangedError(name)
            if not stat.S_ISDIR(info.st_mode):
                return None
            try:
                descriptor = open_child(name, parent, directory=True)
            except FileNotFoundError:
                return None
            held = os.fstat(descriptor)
            if (held.st_dev, held.st_ino) != (info.st_dev, info.st_ino):
                os.close(descriptor)
                raise PathChangedError(name)
            self._chain.append((name, descriptor))
        return self._chain[-1][1] if self._chain else self._root_fd

    def lstat(self, parts: tuple[str, ...]) -> os.stat_result | None:
        """``lstat`` of the path, ``None`` if there is nothing at it (or a link stands in the way: see ``PathChangedError``)."""
        directory = self._directory(parts[:-1])
        if directory is None:
            return None
        try:
            return os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError):
            return None

    def observe(self, parts: tuple[str, ...], *, limit: int) -> Worktree:
        """The path as it is: its bytes if it is a regular file with one name, its text if it is a link, else a refusal."""
        try:
            directory = self._directory(parts[:-1])
        except PathChangedError:
            return Worktree("refused", PATH_REPLACED)
        if directory is None:
            return _ABSENT
        name = parts[-1]
        try:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError):
            return _ABSENT
        except OSError:
            return Worktree("refused", UNREADABLE)
        if stat.S_ISLNK(info.st_mode):
            try:
                return Worktree("link", target=os.readlink(name, dir_fd=directory))
            except OSError:
                return Worktree("refused", UNREADABLE)
        if stat.S_ISDIR(info.st_mode):
            return _ABSENT  # a directory where a file was tracked: the file is gone, as Git sees it
        if not stat.S_ISREG(info.st_mode):
            return Worktree("refused", SPECIAL_FILE)  # judged before the open: a pipe or a device is never opened
        try:
            descriptor = open_child(name, directory, directory=False)
        except FileNotFoundError:
            return _ABSENT
        except PathChangedError:
            return Worktree("refused", CHANGED_DURING_READ)
        except OSError:
            return Worktree("refused", UNREADABLE)
        try:
            held = os.fstat(descriptor)
            if not stat.S_ISREG(held.st_mode) or (held.st_dev, held.st_ino) != (info.st_dev, info.st_ino):
                return Worktree("refused", CHANGED_DURING_READ)
            if held.st_nlink > 1:  # judged on the object that is held, before the first byte: it may be a refused file
                return Worktree("refused", HARD_LINK)
            if held.st_size > limit:
                return Worktree("refused", OVER_BUDGET)
            data = read_bounded(descriptor, limit)
            if data is None:
                return Worktree("refused", OVER_BUDGET)
            after = os.fstat(descriptor)
            if (after.st_size, after.st_mtime_ns, after.st_nlink) != (held.st_size, held.st_mtime_ns, held.st_nlink):
                return Worktree("refused", CHANGED_DURING_READ)
            return Worktree("file", executable=bool(held.st_mode & 0o100), data=data)
        except OSError:
            return Worktree("refused", UNREADABLE)
        finally:
            os.close(descriptor)


class _PrivateTree:
    """The scratch work tree. Names are created through descriptors and no link is ever followed, so two crafted index
    entries (a link, then a path below it) cannot write outside it."""

    def __init__(self, root: Path):
        self._root = root

    def _parent(self, parts: tuple[str, ...]) -> int:
        descriptor = open_root(self._root)
        try:
            for name in parts[:-1]:
                try:
                    os.mkdir(name, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = open_child(name, descriptor, directory=True)  # a link or a file in the way: PathChangedError
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def write_file(self, parts: tuple[str, ...], data: bytes, *, executable: bool) -> None:
        parent = self._parent(parts)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(parts[-1], flags, 0o600, dir_fd=parent)
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(descriptor, view):]
                os.fchmod(descriptor, 0o755 if executable else 0o644)
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)

    def write_link(self, parts: tuple[str, ...], target: str) -> None:
        parent = self._parent(parts)
        try:
            os.symlink(target, parts[-1], dir_fd=parent)
        finally:
            os.close(parent)


@dataclass(frozen=True)
class _BoundedResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool = False


def _trim_incomplete_utf8_tail(raw: bytes) -> bytes:
    """Drop an incomplete trailing UTF-8 multi-byte sequence (1..3 bytes) when ``raw`` was cut on a byte budget."""
    n = len(raw)
    i = n
    while i > 0 and (n - i) < 4 and (raw[i - 1] & 0xC0) == 0x80:
        i -= 1
    if i > 0 and i <= n:
        lead = raw[i - 1]
        if lead >= 0x80:
            if (lead & 0xE0) == 0xC0:
                expected = 2
            elif (lead & 0xF0) == 0xE0:
                expected = 3
            elif (lead & 0xF8) == 0xF0:
                expected = 4
            else:
                expected = 1
            if (n - (i - 1)) < expected:
                return raw[: i - 1]
    return raw


def _run_bounded(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: float,
    stdin: bytes | None = None,
    max_stdout_bytes: int = _MAX_SUBPROCESS_BYTES,
    max_stderr_bytes: int = _MAX_STDERR_BYTES,
    truncate_stdout: bool = False,
) -> _BoundedResult:
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    out_total = 0
    err_total = 0
    out_overflow = False

    def _read_out() -> None:
        nonlocal out_total, out_overflow
        try:
            while True:
                want = min(65536, (max_stdout_bytes + 1) - out_total)
                if want <= 0:
                    out_overflow = True
                    break
                chunk = os.read(out_r, want)
                if not chunk:
                    break
                out_chunks.append(chunk)
                out_total += len(chunk)
                if out_total > max_stdout_bytes:
                    out_overflow = True
                    break
        except OSError:
            pass
        finally:
            try:
                os.close(out_r)
            except OSError:
                pass

    def _read_err() -> None:
        nonlocal err_total
        try:
            while True:
                want = min(16384, (max_stderr_bytes + 1) - err_total)
                if want <= 0:
                    break
                chunk = os.read(err_r, want)
                if not chunk:
                    break
                err_chunks.append(chunk)
                err_total += len(chunk)
        except OSError:
            pass
        finally:
            try:
                os.close(err_r)
            except OSError:
                pass

    t_out = threading.Thread(target=_read_out, daemon=True)
    t_err = threading.Thread(target=_read_err, daemon=True)
    t_out.start()
    t_err.start()
    try:
        try:
            done = subprocess.run(
                list(command),
                cwd=cwd,
                env=dict(environment),
                input=stdin,
                stdout=out_w,
                stderr=err_w,
                timeout=timeout,
                check=False,
            )
        finally:
            for fd in (out_w, err_w):
                try:
                    os.close(fd)
                except OSError:
                    pass
            t_out.join(timeout=5.0)
            t_err.join(timeout=5.0)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WorkspaceError(f"git observation failed: {type(exc).__name__}") from exc

    raw_out = b"".join(out_chunks)
    raw_err = b"".join(err_chunks)[:max_stderr_bytes]
    if out_overflow:
        if not truncate_stdout:
            raise WorkspaceError("git observation failed: subprocess output exceeded budget")
        return _BoundedResult(
            returncode=0,
            stdout=_trim_incomplete_utf8_tail(raw_out[:max_stdout_bytes]),
            stderr=raw_err,
            stdout_truncated=True,
        )
    return _BoundedResult(
        returncode=done.returncode,
        stdout=raw_out,
        stderr=raw_err,
        stdout_truncated=False,
    )


def _checked(done: _BoundedResult, what: str) -> bytes:
    if done.returncode != 0:
        raise WorkspaceError(f"git returned {done.returncode} ({what}): {done.stderr.decode('utf-8', 'replace').strip()[:300]}")
    return done.stdout


def _classify_unmerged_path(
    path: str, *, root_real: Path, policy: PathPolicy, walker: StrictWalker,
) -> str:
    """Apply lexical, scope, workspace, and worktree link/hard-link checks before reporting an unmerged entry."""
    parts = _split(path)
    if any(is_denied_component(part) for part in parts):
        return REFUSED_NAME
    if _unsafe(parts):
        return UNSAFE_PATH
    if not policy.allows("read", root_real.joinpath(*parts)):
        return SCOPE_DENIED
    try:
        directory = walker._directory(parts[:-1])
    except PathChangedError:
        return PATH_REPLACED
    if directory is None:
        return UNMERGED
    try:
        info = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
    except (FileNotFoundError, NotADirectoryError):
        return UNMERGED
    except OSError:
        return UNREADABLE
    if stat.S_ISLNK(info.st_mode):
        try:
            raw_target = os.readlink(parts[-1], dir_fd=directory)
        except OSError:
            return UNREADABLE
        target_parts = tuple(p for p in Path(raw_target).parts if p not in ("", ".", "/"))
        if any(is_denied_component(p) for p in target_parts):
            return REFUSED_NAME
        resolved_target = (root_real.joinpath(*parts[:-1]) / raw_target).resolve(strict=False)
        if not resolved_target.is_relative_to(root_real):
            return UNSAFE_PATH
        rel_target_parts = resolved_target.relative_to(root_real).parts
        if any(is_denied_component(p) for p in rel_target_parts):
            return REFUSED_NAME
        if not policy.allows("read", resolved_target):
            return SCOPE_DENIED
        return UNMERGED
    if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
        return HARD_LINK
    if not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode):
        return SPECIAL_FILE
    return UNMERGED


@dataclass(frozen=True)
class _Candidate:
    entry: IndexEntry
    parts: tuple[str, ...]


def build_unstaged_diff(
    *, root: Path, listing: bytes, index_mtime_ns: int | None, git_command: Sequence[str],
    environment: Mapping[str, str], objects_dir: Path, object_format: str, policy: PathPolicy, budgets: DiffBudgets,
    root_identity: RootIdentity | None = None, authority_check: Callable[[], None] | None = None,
) -> SnapshotDiff:
    """The unstaged diff of the paths in ``listing`` that are admitted, read as described in the module docstring.

    ``git_command`` is the Git executable (and nothing else) to run in the private repository; ``environment`` is the
    hermetic environment those processes get; ``root`` is the workspace root the listed names are relative to.
    """
    if "\n" in str(objects_dir):  # an alternates file is one path per line: a name with a newline cannot be listed in it
        raise WorkspaceError("git observation refused: the object directory has an unusable name")
    entries = parse_index_listing(listing)
    if len(entries) > budgets.max_entries:
        raise WorkspaceError("git observation refused: the index lists too many paths to judge")
    omissions = Omissions()
    root_real = Path(root_identity.root) if root_identity is not None else root.resolve()

    # -- 1. what is in play: judged by name and authority first ----------------------------------------------------
    unmerged = {entry.path for entry in entries if entry.stage != 0}
    admitted: list[_Candidate] = []
    for entry in entries:
        if entry.stage != 0 or entry.path in unmerged or entry.mode == MODE_GITLINK:
            continue  # a submodule is not observed (``--ignore-submodules=all``)
        if entry.flags & (_FLAG_ASSUME_VALID | _FLAG_SKIP_WORKTREE):
            continue  # Git does not compare these either
        parts = _split(entry.path)
        if any(is_denied_component(part) for part in parts):
            omissions.add(REFUSED_NAME, entry.path)
        elif _unsafe(parts):
            omissions.add(UNSAFE_PATH, entry.path)
        elif not policy.allows("read", root_real.joinpath(*parts)):
            omissions.add(SCOPE_DENIED, entry.path)
        elif entry.mode not in _PLAIN_MODES:
            omissions.add(UNSUPPORTED_ENTRY, entry.path)
        else:
            admitted.append(_Candidate(entry, parts))

    # -- 2. which admitted paths may have changed (stat only), plus authorized unmerged inspection ----------------
    stat_candidates: list[tuple[_Candidate, os.stat_result | None]] = []
    examined = 0
    with StrictWalker(root_real, root_identity=root_identity, authority_check=authority_check) as walker:
        for path in sorted(unmerged):
            omissions.add(_classify_unmerged_path(path, root_real=root_real, policy=policy, walker=walker), path)
        for candidate in admitted:
            try:
                info = walker.lstat(candidate.parts)
            except PathChangedError:
                omissions.add(PATH_REPLACED, candidate.entry.path)
                continue
            if info is not None and _same_as_index(candidate.entry, info, index_mtime_ns):
                continue
            examined += 1
            if examined > budgets.max_candidates:
                omissions.add(OVER_BUDGET, candidate.entry.path)
                continue
            stat_candidates.append((candidate, info))
        walker.verify_root()
        if not stat_candidates:
            return SnapshotDiff("", omissions)

        # -- 3 & 4. inspect old blob metadata/sizes BEFORE reading old blobs or worktree content, then diff --------
        with tempfile.TemporaryDirectory(prefix="uam-git-diff-", ignore_cleanup_errors=True) as scratch_name:
            scratch = Path(os.path.realpath(scratch_name))
            work = scratch / "work"
            empty_template = scratch / "template"
            work.mkdir()
            empty_template.mkdir()
            private_environment = {**environment, "GIT_CEILING_DIRECTORIES": str(scratch), "GIT_NO_LAZY_FETCH": "1"}
            base = [*git_command, *_PRIVATE_OPTIONS]
            _checked(_run_bounded(
                [*base, "init", "-q", f"--object-format={object_format}", f"--template={empty_template}", str(work)],
                cwd=scratch, environment=private_environment, timeout=budgets.timeout_seconds,
            ), "private init")
            private_git = work / ".git"
            (private_git / "info").mkdir(exist_ok=True)
            (private_git / "info" / "attributes").write_bytes(_PRIVATE_ATTRIBUTES)
            (private_git / "objects" / "info").mkdir(parents=True, exist_ok=True)
            (private_git / "objects" / "info" / "alternates").write_bytes(os.fsencode(str(objects_dir)) + b"\n")

            # Check old object existence, type, and byte size BEFORE reading old blob content or worktree files.
            present = _checked(_run_bounded(
                [*base, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
                cwd=work, environment=private_environment, timeout=budgets.timeout_seconds,
                stdin="".join(f"{item.entry.oid}\n" for item, _ in stat_candidates).encode("ascii"),
            ), "object check").decode("ascii", "replace").splitlines()
            if len(present) != len(stat_candidates):
                raise WorkspaceError("git observation failed: the object check answered unexpectedly")

            changed: list[tuple[_Candidate, Worktree]] = []
            total = 0
            for (candidate, info), answer in zip(stat_candidates, present, strict=True):
                path = candidate.entry.path
                if answer.endswith(" missing"):
                    omissions.add(OBJECT_MISSING, path)
                    continue
                fields = answer.split(" ")
                if len(fields) != 3 or fields[1] != "blob":
                    omissions.add(UNSUPPORTED_ENTRY, path)
                    continue
                try:
                    old_size = int(fields[2])
                except ValueError:
                    omissions.add(UNSUPPORTED_ENTRY, path)
                    continue
                if old_size < 0 or old_size > budgets.max_file_bytes or (total + old_size) > budgets.max_total_bytes:
                    omissions.add(OVER_BUDGET, path)
                    continue
                remaining_for_new = budgets.max_total_bytes - (total + old_size)
                limit = min(budgets.max_file_bytes, remaining_for_new)
                if limit <= 0 and info is not None and (not stat.S_ISDIR(info.st_mode)) and info.st_size > 0:
                    omissions.add(OVER_BUDGET, path)
                    continue
                seen = walker.observe(candidate.parts, limit=max(0, limit))
                if seen.kind == "refused":
                    omissions.add(seen.reason, path)
                    continue
                new_size = (
                    len(seen.data)
                    if seen.kind == "file"
                    else (len(seen.target.encode("utf-8", errors="surrogateescape")) if seen.kind == "link" else 0)
                )
                if (total + old_size + new_size) > budgets.max_total_bytes:
                    omissions.add(OVER_BUDGET, path)
                    continue
                total += old_size + new_size
                changed.append((candidate, seen))

            walker.verify_root()
            if not changed:
                return SnapshotDiff("", omissions)

            tree = _PrivateTree(work)
            index_records: list[bytes] = []
            placed: set[tuple[str, ...]] = set()
            for candidate, seen in changed:
                path = candidate.entry.path
                if any(candidate.parts[:cut] in placed for cut in range(1, len(candidate.parts))):
                    omissions.add(PATH_COLLISION, path)  # a path below another tracked path: not a tree that can exist
                    continue
                try:
                    if seen.kind == "file":
                        tree.write_file(candidate.parts, seen.data, executable=seen.executable)
                    elif seen.kind == "link":
                        tree.write_link(candidate.parts, seen.target)
                except (FileExistsError, PathChangedError, NotADirectoryError):
                    omissions.add(PATH_COLLISION, path)
                    continue
                except OSError:
                    omissions.add(UNSAFE_PATH, path)
                    continue
                placed.add(candidate.parts)
                index_records.append(
                    f"{candidate.entry.mode:o} {candidate.entry.oid} 0\t".encode("ascii") + os.fsencode(path) + b"\0"
                )
            if not index_records:
                return SnapshotDiff("", omissions)
            _checked(_run_bounded(
                [*base, "update-index", "--add", "-z", "--index-info"],
                cwd=work, environment=private_environment, timeout=budgets.timeout_seconds, stdin=b"".join(index_records),
            ), "private index")
            diff_res = _run_bounded(
                [*base, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--no-color", "--ignore-submodules=all"],
                cwd=work, environment=private_environment, timeout=budgets.timeout_seconds,
                max_stdout_bytes=budgets.max_diff_bytes, truncate_stdout=True,
            )
            if not diff_res.stdout_truncated and diff_res.returncode != 0:
                raise WorkspaceError(
                    f"git returned {diff_res.returncode} (private diff): "
                    f"{diff_res.stderr.decode('utf-8', 'replace').strip()[:300]}"
                )
            walker.verify_root()
    return SnapshotDiff(
        diff_res.stdout.decode("utf-8", errors="replace"),
        omissions,
        diff_truncated=diff_res.stdout_truncated,
    )
