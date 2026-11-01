"""Scope search: authorise first, read second, search third.

``uam_search_scope`` used to hand ripgrep the scope root and a list of exclusion globs. Any filter
placed *after* ripgrep returns (dropping a hit, hiding a path) is a second layer at best: ripgrep
had already opened the file, and its pre-execution globs were anchored to its own working directory,
not to the scope, so they excluded nothing. Authority has to be decided before a byte is read, and by
the process that reads:

1. **Enumerate under authority.** This module walks the scope itself, one directory file
   descriptor at a time (``O_NOFOLLOW``, ``scandir(fd)``), and applies the filters the ripgrep
   command line used to carry: depth, hidden entries, the repository ignore files, excluded
   directory names, the secret firewall, system directories, symlinks. A directory is entered, and
   a file considered, only where the *current* effective ``text_search`` authority allows it,
   judged by ``PathPolicy`` (as written and as a case- and normalization-insensitive filesystem
   sees the name; the most specific nested scope wins). A denying directory is never listed.
2. **Open and verify.** A candidate file is opened relative to its directory descriptor with
   ``O_NOFOLLOW``. The open object must be a regular file, the object that was listed, and, while a
   nested scope denies search, a file with a single name: a hard link is the same bytes under
   another name, and its other name may lie inside the denied scope. Only then is any content read.
3. **Search the descriptors.** Ripgrep never walks a directory and never opens a path. It is given
   ``/dev/fd/N`` for descriptors this module has already opened and verified, in bounded batches.
   Whatever is replaced on disk after the open cannot change which object is read, and nothing
   outside the authorised set is reachable from the command line.

Budgets (entries, files, bytes, the deadline, ripgrep's output) end a search as explicitly
incomplete. A search never falls back to letting ripgrep walk a wide directory.

The checks that remain after ripgrep returns (in ``DiscoveryEngine.search_scope``) are a second
layer, not the boundary.

Known, declared approximations (``search_domain`` says so): ignore files are read only from inside
the search root, never from its parents (reading outside the scope would itself be an unauthorised
read); binary files are recognised by a NUL byte in the first 64 KiB, and a file handed to ripgrep
by descriptor is searched past a later NUL, where a walked file would stop there.
"""
from __future__ import annotations

import errno
import os
import resource
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from .ignore_rules import EMPTY_RULES, MAX_IGNORE_FILE_BYTES, IgnoreRules, IgnoreVerdict, parse_ignore_file
from .path_authority import PathPolicy
from .policy import is_denied_component, is_denied_path

SEARCH_TIMEOUT_SECONDS: Final = 30
MAX_DEPTH: Final = 5
EXCLUDED_DIRECTORY_NAMES: Final = (
    "node_modules", ".git", ".venv", "__pycache__", "target", "dist", "build", "vendor",
)
SYSTEM_DIRECTORY_NAMES: Final = ("Library", "Applications", ".Trash", "Pictures", "Music", "Movies")
IGNORE_FILE_NAMES: Final = (".gitignore", ".ignore", ".rgignore")
BINARY_PROBE_BYTES: Final = 65536

_NEVER_SEARCHED: Final = frozenset(EXCLUDED_DIRECTORY_NAMES) | frozenset(SYSTEM_DIRECTORY_NAMES)

_FILE_FLAGS: Final = (
    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | getattr(os, "O_NOCTTY", 0)
)
_DIR_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_RG_ENV: Final = {"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "LC_ALL": "C", "HOME": "/nonexistent"}
_DESCRIPTOR_PREFIX: Final = b"/dev/fd/"
_UTF16_BOMS: Final = (b"\xff\xfe", b"\xfe\xff")
_PERMISSION_ERRNOS: Final = frozenset({errno.EACCES, errno.EPERM})
_VANISHED_ERRNOS: Final = frozenset({errno.ENOENT, errno.ENOTDIR, errno.ELOOP, errno.EMLINK})

RIPGREP_CANDIDATES: Final[tuple[str, ...]] = (
    "/usr/bin/rg", "/usr/local/bin/rg", "/opt/homebrew/bin/rg", str(Path.home() / ".local/bin/rg"),
)


@dataclass(frozen=True)
class ScopeSearchLimits:
    """Resource budgets of one scope search. Exhausting one ends the search as incomplete."""

    max_entries: int = 1_000_000
    max_files: int = 250_000
    max_bytes: int = 4 * 1024**3
    deadline_seconds: float = float(SEARCH_TIMEOUT_SECONDS)
    max_output_bytes: int = 1 << 20
    batch_files: int = 64


DEFAULT_LIMITS: Final = ScopeSearchLimits()


def find_ripgrep() -> str | None:
    """The first usable ripgrep executable, or None."""
    for candidate in RIPGREP_CANDIDATES:
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def search_domain(
    *, scope_authority_exclusions: bool, ignore_rules_not_applied: bool = False,
    limits: ScopeSearchLimits = DEFAULT_LIMITS,
) -> dict[str, Any]:
    """Declare what a scope search covers and what it cannot see.

    The search is bounded on purpose (depth, ignore files, hidden and binary files, symlinks,
    secret and system paths, budgets), so an empty result is evidence only about this domain.
    Nothing here names a path or counts what a scope's authority keeps out: a count would reveal
    what is there. Denied subtrees are never opened, so nothing in a response depends on what they
    contain.

    ``ignore_rules_not_applied`` says that an ignore file in the searched tree held a rule this
    search could not interpret faithfully (or could not read), so the ignore files were not applied
    exactly as ripgrep would have applied them.
    """
    not_covered = [
        "beyond_max_depth", "ignored_by_ignore_files", "hidden_paths", "binary_files",
        "symlinked_paths", "excluded_directory_names", "secret_firewall_paths", "system_directories",
        "unreadable_paths",
    ]
    if scope_authority_exclusions:
        not_covered.extend(["scope_authority", "hard_linked_files"])
    if ignore_rules_not_applied:
        not_covered.append("ignore_rules_not_applied")
    return {
        "engine": "ripgrep",
        "match": "case-insensitive literal text; first match per file",
        "enumeration": "authorised files are opened by the server and searched as open descriptors",
        "max_depth": MAX_DEPTH,
        "max_depth_from": "each search root",
        "excluded_directory_names": list(EXCLUDED_DIRECTORY_NAMES),
        "ignore_files_honoured": list(IGNORE_FILE_NAMES),
        "ignore_files_read_from": "inside the search root only",
        "binary_detection": f"a NUL byte in the first {BINARY_PROBE_BYTES} bytes",
        "limits": {
            "deadline_seconds": limits.deadline_seconds,
            "max_entries": limits.max_entries,
            "max_files": limits.max_files,
            "max_bytes": limits.max_bytes,
        },
        "scope_authority_exclusions": scope_authority_exclusions,
        "exhaustive": False,
        "not_covered": not_covered,
    }


def is_sensitive_name(name: str) -> bool:
    """Whether one path component triggers the central secret firewall (``policy.is_denied_component``).

    This module used to keep its own, slightly different name lists; they diverged from ``policy`` (it denied
    ``.envrc*`` and ``.env-*`` where ``policy`` did not). There is one list now, in ``policy``.
    """
    return is_denied_component(name)


def is_sensitive_path(path: str) -> bool:
    """Check if any path component triggers the central secret firewall (``policy.is_denied_path``)."""
    return is_denied_path(path)


@dataclass(frozen=True)
class HitRecords:
    """Descriptor numbers recovered from ``rg -l`` output, plus the records that could not be."""

    descriptors: list[int]
    unterminated: int = 0
    unexpected: int = 0


def parse_hit_records(output: bytes | bytearray | str | None, *, producer_finished: bool) -> HitRecords:
    """Turn captured ``rg -l`` output into descriptor numbers at the subprocess boundary.

    Ripgrep prints ``/dev/fd/N`` for each file it matched. ``subprocess.TimeoutExpired.stdout`` is
    ``bytes`` even when the call used ``text=True``, and ``None`` when nothing was captured, so
    bytes, str and None are all accepted here instead of at each use site. After a timeout the last
    record may have been cut off (``/dev/fd/1`` for ``/dev/fd/12``) and could name a different
    descriptor, so an unterminated fragment is dropped and counted unless the process exited on its
    own. A record that is not a descriptor path is counted and dropped.
    """
    if output is None:
        return HitRecords(descriptors=[])
    if isinstance(output, str):
        segments = [segment.encode("utf-8", "surrogateescape") for segment in output.split("\n")]
    elif isinstance(output, (bytes, bytearray)):
        segments = bytes(output).split(b"\n")
    else:
        raise TypeError(f"unsupported subprocess output type: {type(output).__name__}")
    tail = segments.pop()
    unterminated = 0
    if tail:
        if producer_finished:
            segments.append(tail)
        else:
            unterminated = 1
    descriptors: list[int] = []
    unexpected = 0
    for segment in segments:
        text = segment.strip()
        if not text:
            continue
        number = text[len(_DESCRIPTOR_PREFIX):]
        if not text.startswith(_DESCRIPTOR_PREFIX) or not number.isdigit():
            unexpected += 1
            continue
        descriptors.append(int(number))
    return HitRecords(descriptors=descriptors, unterminated=unterminated, unexpected=unexpected)


@dataclass
class TreeSearch:
    """What one authorised walk and search found, and why it stopped."""

    hits: list[tuple[str, ...]] = field(default_factory=list)
    truncated: bool = False
    timed_out: bool = False
    rg_failed: bool = False
    launch_failed: bool = False
    error_type: str | None = None
    enumeration_failed: bool = False
    scan_limit: str | None = None
    changed: int = 0
    other_errors: int = 0
    undecodable: int = 0
    unterminated: int = 0
    unexpected_output: int = 0
    # Internal measures. None of these is a response field: a count of what authority keeps out
    # would reveal what is there. ``ignore_rules_skipped`` only becomes a flag in the declared domain.
    skipped_unreadable: int = 0
    refused_hard_links: int = 0
    ignore_rules_skipped: int = 0
    files_searched: int = 0
    bytes_searched: int = 0
    entries_seen: int = 0


@dataclass(frozen=True)
class _Candidate:
    index: int
    parts: tuple[str, ...]
    fd: int


@dataclass(frozen=True)
class _IgnoreLevel:
    parts: tuple[str, ...]
    custom: IgnoreRules
    generic: IgnoreRules
    git: IgnoreRules
    has_git: bool


def _ignore_verdict(
    levels: tuple[_IgnoreLevel, ...], entry_parts: tuple[str, ...], *, is_dir: bool,
) -> IgnoreVerdict | None:
    """Which ignore rule decides ``entry_parts``, with ripgrep's precedence (see ``ignore_rules``)."""
    if not levels:
        return None
    any_git = any(level.has_git for level in levels)
    saw_git = False
    custom: IgnoreVerdict | None = None
    generic: IgnoreVerdict | None = None
    git: IgnoreVerdict | None = None
    for level in reversed(levels):
        relative = "/".join(entry_parts[len(level.parts):])
        if custom is None and level.custom:
            custom = level.custom.verdict(relative, is_dir=is_dir)
        if generic is None and level.generic:
            generic = level.generic.verdict(relative, is_dir=is_dir)
        if any_git and not saw_git and git is None and level.git:
            git = level.git.verdict(relative, is_dir=is_dir)
        saw_git = saw_git or level.has_git
    return custom or generic or git


def _looks_binary(head: bytes) -> bool:
    return b"\0" in head and not head.startswith(_UTF16_BOMS)


def _renderable(name: str) -> bool:
    """Whether a name survives UTF-8: a path that cannot be shown faithfully is not searched."""
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _batch_size(wanted: int) -> int:
    soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft == resource.RLIM_INFINITY:
        return max(1, wanted)
    return max(1, min(wanted, (soft - 128) // 2))


class _Walk:
    """One search: walk under authority, open and verify, hand descriptors to ripgrep."""

    def __init__(
        self, *, real_root: Path, query: str, executable: str, policy: PathPolicy,
        limits: ScopeSearchLimits, max_results: int,
    ) -> None:
        self.real_root = real_root
        self.query = query
        self.executable = executable
        self.policy = policy
        self.limits = limits
        self.max_results = max_results
        self.deadline = time.monotonic() + limits.deadline_seconds
        self.out = TreeSearch()
        self.batch: list[_Candidate] = []
        self.batch_limit = _batch_size(limits.batch_files)
        self.stop: str | None = None
        self.files = 0
        self.bytes = 0
        self.entries = 0

    # -- control -----------------------------------------------------------------------------

    def _halt(self, reason: str) -> None:
        if self.stop is None:
            self.stop = reason

    def _exhaust(self, budget: str) -> None:
        if self.out.scan_limit is None:
            self.out.scan_limit = budget
        self._halt("budget")

    def _halted(self) -> bool:
        """Whether the walk must stop; also where the deadline is noticed."""
        if self.stop is not None:
            return True
        if time.monotonic() >= self.deadline:
            self.out.timed_out = True
            self._halt("timeout")
            return True
        return False

    # -- driver ------------------------------------------------------------------------------

    def run(self) -> TreeSearch:
        try:
            root_fd = os.open(self.real_root, _DIR_FLAGS)
        except OSError as exc:
            self.out.enumeration_failed = True
            self.out.error_type = type(exc).__name__
            return self.out
        try:
            try:
                opened, named = os.fstat(root_fd), os.stat(self.real_root)
                same = (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino)
            except OSError:
                same = False
            if not same:
                self.out.enumeration_failed = True
                self.out.error_type = "RootChanged"
                return self.out
            self._walk_directory(root_fd, (), 0, ())
            for pocket in self.policy.pockets("scope_search", self.real_root):
                if self._halted():
                    break
                self._walk_pocket(root_fd, pocket)
            self._flush()
        finally:
            os.close(root_fd)
            self._release_batch()
            self.out.bytes_searched = self.bytes
            self.out.entries_seen = self.entries
        return self.out

    # -- walking -----------------------------------------------------------------------------

    def _walk_directory(
        self, dir_fd: int, parts: tuple[str, ...], depth: int, levels: tuple[_IgnoreLevel, ...],
    ) -> None:
        if self._halted():
            return
        entries: list[os.DirEntry[str]] = []
        try:
            with os.scandir(dir_fd) as iterator:
                for entry in iterator:
                    entries.append(entry)
                    self.entries += 1
                    if self.entries > self.limits.max_entries:
                        self._exhaust("max_entries")
                        return
        except OSError as exc:
            self._note_error(exc)
            return
        entries.sort(key=lambda entry: entry.name)
        names = {entry.name for entry in entries}
        chain = levels + (self._ignore_level(dir_fd, parts, names),)
        for entry in entries:
            if self._halted():
                return
            self._visit(dir_fd, parts, depth, chain, entry)

    def _ignore_level(self, dir_fd: int, parts: tuple[str, ...], names: set[str]) -> _IgnoreLevel:
        rules = {
            kind: self._read_ignore_file(dir_fd, parts, kind) if kind in names else EMPTY_RULES
            for kind in IGNORE_FILE_NAMES
        }
        return _IgnoreLevel(
            parts=parts, custom=rules[".rgignore"], generic=rules[".ignore"],
            git=rules[".gitignore"], has_git=".git" in names,
        )

    def _read_ignore_file(self, dir_fd: int, parts: tuple[str, ...], name: str) -> IgnoreRules:
        """An ignore file is read, so it is authorised and verified like any candidate file.

        One that is present but cannot be applied (refused, unreadable, too large, not a regular
        file, or holding rules that cannot be translated) is counted, and the domain says so.
        """
        if not self._allowed(parts + (name,)):
            return EMPTY_RULES  # a denied ignore file is not part of this search at all
        try:
            fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
        except OSError:
            self.out.ignore_rules_skipped += 1
            return EMPTY_RULES
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_IGNORE_FILE_BYTES:
                self.out.ignore_rules_skipped += 1
                return EMPTY_RULES
            if self.policy.refuses_other_names("scope_search", info):
                self.out.refused_hard_links += 1
                self.out.ignore_rules_skipped += 1
                return EMPTY_RULES
            rules = parse_ignore_file(os.read(fd, MAX_IGNORE_FILE_BYTES + 1))
            self.out.ignore_rules_skipped += rules.skipped_rules
            return rules
        except OSError:
            self.out.ignore_rules_skipped += 1
            return EMPTY_RULES
        finally:
            os.close(fd)

    def _allowed(self, parts: tuple[str, ...]) -> bool:
        if not self.policy.restricted:
            return True
        return self.policy.allows("scope_search", self.real_root.joinpath(*parts))

    def _note_error(self, exc: OSError) -> None:
        """Permission refusals are a declared gap (``unreadable_paths``); anything else is not."""
        if exc.errno in _PERMISSION_ERRNOS:
            self.out.skipped_unreadable += 1
        elif exc.errno in _VANISHED_ERRNOS:
            self.out.changed += 1
        else:
            self.out.other_errors += 1

    def _visit(
        self, dir_fd: int, parts: tuple[str, ...], depth: int,
        chain: tuple[_IgnoreLevel, ...], entry: os.DirEntry[str],
    ) -> None:
        name = entry.name
        if name in _NEVER_SEARCHED or is_sensitive_name(name):
            return
        try:
            if entry.is_symlink():
                return
            is_dir = entry.is_dir(follow_symlinks=False)
            if not is_dir and not entry.is_file(follow_symlinks=False):
                return
        except OSError as exc:
            self._note_error(exc)
            return
        child = parts + (name,)
        if not self._allowed(child):
            return
        verdict = _ignore_verdict(chain, child, is_dir=is_dir)
        if verdict == "ignore":
            return
        if verdict is None and name.startswith("."):
            return
        if not _renderable(name):
            self.out.undecodable += 1
            return
        if is_dir:
            if depth + 1 < MAX_DEPTH:
                self._enter(dir_fd, child, depth + 1, chain, entry)
        else:
            self._consider(dir_fd, child, entry)

    def _enter(
        self, dir_fd: int, parts: tuple[str, ...], depth: int,
        chain: tuple[_IgnoreLevel, ...], entry: os.DirEntry[str],
    ) -> None:
        try:
            before = entry.stat(follow_symlinks=False)
            fd = os.open(entry.name, _DIR_FLAGS, dir_fd=dir_fd)
        except OSError as exc:
            self._note_error(exc)
            return
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
                self.out.changed += 1
                return
            self._walk_directory(fd, parts, depth, chain)
        except OSError as exc:
            self._note_error(exc)
        finally:
            os.close(fd)

    def _walk_pocket(self, root_fd: int, pocket: tuple[str, ...]) -> None:
        """Reach an allowed nested scope that lies inside a denying one, without listing the latter.

        Each component is opened (never listed) relative to its parent with ``O_NOFOLLOW``: that is
        path traversal, what a path lookup does implicitly, and it returns no entries.
        """
        if any(is_sensitive_name(component) for component in pocket):
            return
        held: list[int] = []
        try:
            current = root_fd
            for component in pocket:
                try:
                    current = os.open(component, _DIR_FLAGS, dir_fd=current)
                except OSError as exc:
                    if exc.errno != errno.ENOENT:
                        self._note_error(exc)
                    return
                held.append(current)
            self._walk_directory(current, pocket, 0, ())
        finally:
            for fd in held:
                os.close(fd)

    # -- candidates --------------------------------------------------------------------------

    def _consider(self, dir_fd: int, parts: tuple[str, ...], entry: os.DirEntry[str]) -> None:
        if self.files >= self.limits.max_files:
            self._exhaust("max_files")
            return
        try:
            before = entry.stat(follow_symlinks=False)
        except OSError as exc:
            self._note_error(exc)
            return
        if self.policy.refuses_other_names("scope_search", before):
            self.out.refused_hard_links += 1  # refused before it is even opened
            return
        try:
            fd = os.open(entry.name, _FILE_FLAGS, dir_fd=dir_fd)
        except OSError as exc:
            self._note_error(exc)
            return
        keep = False
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
                self.out.changed += 1
                return
            if self.policy.refuses_other_names("scope_search", info):
                self.out.refused_hard_links += 1  # linked after it was listed
                return
            if info.st_size == 0:
                return
            if self.bytes + info.st_size > self.limits.max_bytes:
                self._exhaust("max_bytes")
                return
            if _looks_binary(os.read(fd, BINARY_PROBE_BYTES)):
                return
            os.lseek(fd, 0, os.SEEK_SET)
            self.files += 1
            self.bytes += info.st_size
            self.batch.append(_Candidate(index=self.files, parts=parts, fd=fd))
            keep = True
        except OSError as exc:
            self._note_error(exc)
        finally:
            if not keep:
                os.close(fd)
        if len(self.batch) >= self.batch_limit:
            self._flush()

    # -- ripgrep -----------------------------------------------------------------------------

    def _release_batch(self) -> None:
        batch, self.batch = self.batch, []
        for candidate in batch:
            os.close(candidate.fd)

    def _flush(self) -> None:
        batch, self.batch = self.batch, []
        try:
            if batch and self.stop in (None, "budget"):
                self._run_ripgrep(batch)
        finally:
            for candidate in batch:
                os.close(candidate.fd)

    def _run_ripgrep(self, batch: list[_Candidate]) -> None:
        out = self.out
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            out.timed_out = True
            self._halt("timeout")
            return
        command = [
            self.executable, "--no-config", "--fixed-strings", "--ignore-case", "-l",
            "--no-messages", "--max-count=1", "--no-mmap", "--", self.query,
            *(f"/dev/fd/{candidate.fd}" for candidate in batch),
        ]
        stdout: bytes | str | None = None
        timed_out = False
        try:
            proc = subprocess.run(
                command, capture_output=True, stdin=subprocess.DEVNULL, timeout=remaining,
                pass_fds=tuple(candidate.fd for candidate in batch), env=_RG_ENV,
            )
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = exc.stdout
        except (OSError, ValueError) as exc:
            out.rg_failed = True
            out.launch_failed = True
            out.error_type = type(exc).__name__
            self._halt("ripgrep")
            return
        else:
            if proc.returncode in (0, 1):
                stdout = proc.stdout
            else:
                out.rg_failed = True
                if proc.returncode == 2:
                    stdout = proc.stdout
        out.files_searched += len(batch)
        if stdout is not None and len(stdout) > self.limits.max_output_bytes:
            out.rg_failed = True
            out.error_type = "OutputBudget"
            stdout = None
        records = parse_hit_records(stdout, producer_finished=not timed_out)
        out.unterminated += records.unterminated
        out.unexpected_output += records.unexpected
        by_descriptor = {candidate.fd: candidate for candidate in batch}
        matched: dict[int, _Candidate] = {}
        for descriptor in records.descriptors:
            candidate = by_descriptor.get(descriptor)
            if candidate is None:
                out.unexpected_output += 1
            else:
                matched[candidate.index] = candidate
        for index in sorted(matched):
            out.hits.append(matched[index].parts)
            if len(out.hits) >= self.max_results:
                out.truncated = True
                self._halt("results")
                break
        if timed_out:
            out.timed_out = True
            self._halt("timeout")
        elif out.rg_failed:
            self._halt("ripgrep")


def search_tree(
    root: Path, query: str, *, executable: str, policy: PathPolicy, max_results: int,
    limits: ScopeSearchLimits = DEFAULT_LIMITS,
) -> TreeSearch:
    """Search ``root`` for ``query`` under ``policy``; the module docstring gives the order of events.

    ``root`` is resolved once here, and every hit is a tuple of path components below that resolved
    root. ``policy`` is the live nested-scope authority beneath ``root``, taken by the caller as one
    snapshot for this search. The authority of ``root`` itself is the caller's to establish.
    """
    real_root = Path(os.path.realpath(root))
    if is_sensitive_path(str(real_root)):
        return TreeSearch()
    walk = _Walk(
        real_root=real_root, query=query, executable=executable, policy=policy,
        limits=limits, max_results=max_results,
    )
    return walk.run()
