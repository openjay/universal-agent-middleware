from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .errors import WorkspaceError
from .git_snapshot import DiffBudgets, build_unstaged_diff
from .models import RootIdentity
from .path_authority import PathOperation, PathPolicy
from .policy import ensure_relative_path, is_denied_path, resolve_safe_path
from .workspace import bind_root_identity, open_verified_root, verify_bound_root_fd

# Git is given the exclusions as arguments; a repository with more sensitive tracked paths than this is refused rather
# than observed with a truncated, and therefore unsafe, exclusion list. (``status`` only: see ``ReadOnlyGit.diff``.)
MAX_EXCLUDE_ARGUMENT_BYTES = 100_000
MAX_DIFF_CHARS = 200_000
_FILTER_VARIABLES = ("clean", "smudge", "process")
_HERMETIC_ENV = {
    "PATH": "/usr/bin:/bin:/usr/local/bin",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_NO_LAZY_FETCH": "1",  # a missing object of a partial clone is reported, never fetched (no network, no helper)
    "GIT_PAGER": "cat",
    "PAGER": "cat",
    "LC_ALL": "C",
}


_QUOTED_BYTE_ESCAPES = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, '"': 34}
_OCTAL = frozenset("01234567")


def unquote_git_path(text: str) -> str:
    """The path a ``git status --short`` line shows, with Git's C-style quoting undone (``ValueError`` if malformed)."""
    if len(text) < 2 or not (text.startswith('"') and text.endswith('"')):
        return text
    body = text[1:-1]
    data = bytearray()
    index = 0
    while index < len(body):
        char = body[index]
        index += 1
        if char != "\\":
            data += char.encode("utf-8")
            continue
        if index >= len(body):
            raise ValueError("dangling escape")
        escape = body[index]
        if escape in _QUOTED_BYTE_ESCAPES:
            data.append(_QUOTED_BYTE_ESCAPES[escape])
            index += 1
        elif escape in _OCTAL:
            digits = body[index:index + 3]
            if len(digits) < 3 or not set(digits) <= _OCTAL:
                raise ValueError("malformed octal escape")
            data.append(int(digits, 8))
            index += 3
        else:
            raise ValueError("unknown escape")
    return data.decode("utf-8", errors="replace")


def drop_denied_status_lines(status: str) -> str:
    """Remove the lines of ``git status --short`` (renames off) whose path has a sensitive-name component.

    Status reports names, and for a tracked file a modified/deleted flag that Git derives by hashing the worktree file:
    the name is metadata about a refused object and the flag is a bit of its content. Tracked sensitive paths are
    excluded from Git's own walk (see ``ReadOnlyGit.status``); this screen also covers the untracked ones, which only
    Git's listing can name. A line that cannot be parsed is dropped rather than returned: fail closed.
    """
    kept: list[str] = []
    for line in status.splitlines(keepends=True):
        try:
            path = unquote_git_path(line.rstrip("\n")[3:])
        except ValueError:
            continue
        if not is_denied_path(path):
            kept.append(line)
    return "".join(kept)


@dataclass(frozen=True)
class _RepositoryFacts:
    index_path: Path
    objects_dir: Path
    object_format: str


class ReadOnlyGit:
    """Hermetic, fixed Git observations.

    The target repository is treated as untrusted input. Repository/global Git
    configuration must not be able to turn a read operation into an external
    process launch (for example via fsmonitor, external diff, pager, textconv or a
    ``filter.<driver>`` clean/smudge/process command).

    ``path_policy`` carries the authority of RootScopes nested under the repository root.

    ``diff`` never lets Git look at the work tree: it lists the index once, judges every path by name and authority
    before anything is opened, reads the paths that may have changed itself, and has Git diff a private copy (see
    ``git_snapshot``). The result says what it left out (``omitted``) instead of leaving it out silently.

    ``status`` still runs Git over the work tree, because Git is the only thing that can list untracked files with the
    ignore rules applied. It is therefore bounded from outside: always to this workspace (``-- .``), never when the
    repository's work tree is somewhere else, with the subtrees whose scope denies it and every tracked path with a
    sensitive name excluded from Git's own walk, and filtered again by name. What it does not cover: Git hashes the
    work tree file of every other tracked path whose stat data changed, so the modified flag of a file that is a hard
    link to a refused file is one bit about that file.

    ``git_executable`` is the Git to run: a bare name is looked up on the hermetic PATH, an absolute path is used as is.
    """

    def __init__(
        self, root: str | Path, *, path_policy: PathPolicy | None = None, git_executable: str = "git",
        budgets: DiffBudgets | None = None, root_identity: RootIdentity | None = None,
        authority_check: Callable[[], None] | None = None, require_bound_identity: bool = False,
    ):
        if require_bound_identity and (root_identity is None or authority_check is None):
            raise WorkspaceError("git observation refused: bound RootIdentity and live authority_check are required")
        self._authority_check = authority_check
        if root_identity is not None:
            declared = Path(root).expanduser()
            try:
                declared_real = declared.resolve(strict=True)
            except OSError as exc:
                raise WorkspaceError("workspace root identity changed or became inaccessible") from exc
            if declared_real != Path(root_identity.root):
                raise WorkspaceError("workspace root identity changed")
            self._root_identity = root_identity
        else:
            self._root_identity = bind_root_identity(root)
        self._git_entry_stat: tuple[int, int, int] | None = None
        fd, _ = open_verified_root(self._root_identity)
        try:
            self._git_entry_stat = self._probe_git_entry(fd)
            if self._authority_check is not None:
                self._authority_check()
        finally:
            os.close(fd)
        self.root = self._root_identity.root
        self._policy = path_policy or PathPolicy.unrestricted()
        self._git = self._checked_executable(git_executable)
        self._budgets = budgets or DiffBudgets()
        self._filter_overrides: list[str] | None = None
        self._facts = self._repository_facts()

    @property
    def root_identity(self) -> RootIdentity:
        return self._root_identity

    @staticmethod
    def _probe_git_entry(root_fd: int) -> tuple[int, int, int] | None:
        try:
            info = os.stat(".git", dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise WorkspaceError("workspace root identity changed: .git entry unreadable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise WorkspaceError("git observation refused: .git must not be a symlink")
        return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))

    def _verify_git_entry(self, root_fd: int) -> None:
        current = self._probe_git_entry(root_fd)
        expected = getattr(self, "_git_entry_stat", None)
        if expected is not None and current != expected:
            raise WorkspaceError("workspace root identity changed: .git entry replaced")

    @contextmanager
    def _verified_root_session(self) -> Iterator[int]:
        """Hold the verified root descriptor open across a Git subprocess call and re-verify before and after."""
        root_fd, _ = open_verified_root(self._root_identity)
        try:
            self._verify_git_entry(root_fd)
            if self._authority_check is not None:
                self._authority_check()
            yield root_fd
            verify_bound_root_fd(root_fd, self._root_identity)
            self._verify_git_entry(root_fd)
            if self._authority_check is not None:
                self._authority_check()
        finally:
            os.close(root_fd)

    def _verify_root(self) -> None:
        with self._verified_root_session():
            pass

    @staticmethod
    def _checked_executable(executable: str) -> str:
        if os.sep not in executable:
            return executable
        path = Path(executable)
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            raise WorkspaceError("git observation failed: the git executable is not usable")
        return str(path)

    def _repository_facts(self) -> _RepositoryFacts:
        """What the repository says about itself, and a refusal if its work tree is not this workspace.

        ``core.worktree`` (or a ``.git`` file) can point the repository at another directory: Git would then read THAT
        directory for ``status``, outside the workspace's authority. The workspace may lie inside the work tree (a
        project below the repository's top level); it may not lie beside it.
        """
        raw = self._run([
            "rev-parse", "--show-toplevel", "--show-prefix", "--git-path", "index", "--git-path", "objects",
            "--show-object-format",
        ])
        lines = raw.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        if len(lines) != 5:
            raise WorkspaceError("git observation failed: unexpected rev-parse output")
        toplevel, prefix, index_path, objects_dir, object_format = lines
        try:
            same = (Path(toplevel) / prefix).resolve(strict=True) == Path(self.root)
        except OSError:
            same = False
        if not same:
            raise WorkspaceError("git observation refused: the repository's work tree is not this workspace")
        if object_format not in ("sha1", "sha256"):
            raise WorkspaceError("git observation failed: unknown object format")
        return _RepositoryFacts(
            index_path=Path(self.root, index_path), objects_dir=Path(self.root, objects_dir), object_format=object_format,
        )

    def _scope_pathspec(
        self, operation: PathOperation, extra: Iterable[str] = (), *, include: str = ".",
    ) -> list[str]:
        """Pathspec arguments for ``include`` that leave out the subtrees whose scope denies ``operation`` and the
        ``extra`` paths. Always bounded to ``include``: without a pathspec Git reports the whole repository, which is
        more than this workspace when the workspace lies below the repository's top level."""
        excluded = [*self._policy.excluded_subtrees(operation, Path(self.root)), *extra]
        specs = [f":(exclude,literal){rel}" for rel in excluded]
        if sum(len(spec) + 1 for spec in specs) > MAX_EXCLUDE_ARGUMENT_BYTES:
            raise WorkspaceError("git observation refused: too many excluded paths to apply safely")
        return ["--", include, *specs]

    def _base_command(self) -> list[str]:
        # ``core.hooksPath`` is an execution entry point of its own: r2's ``diff`` refreshed and rewrote the index and
        # that started the repository's ``post-index-change`` hook. r3's observations no longer write the repository,
        # and this keeps a hook out of reach should one ever do (Git finds no hook below ``/dev/null``).
        return [
            self._git,
            "-c", "core.fsmonitor=false",
            "-c", f"core.hooksPath={os.devnull}",
            "-c", "core.pager=cat",
            "-c", "pager.status=false",
            "-c", "pager.diff=false",
            "-c", "pager.log=false",
            "-c", "diff.external=",
            "-C", self.root,
        ]

    def _spawn(self, command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
        with self._verified_root_session():
            try:
                return subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    errors="replace",  # a name or a message that is not UTF-8 must not end the observation with a decode error
                    timeout=timeout,
                    env=dict(_HERMETIC_ENV),
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise WorkspaceError(f"git observation failed: {type(exc).__name__}") from exc

    def _run_bytes(self, args: list[str], *, timeout: int = 60) -> bytes:
        """Run Git and return its stdout undecoded (names are bytes: they are decoded where they are judged)."""
        with self._verified_root_session():
            try:
                proc = subprocess.run(
                    [*self._base_command(), *args], check=False, capture_output=True, timeout=timeout,
                    env=dict(_HERMETIC_ENV),
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise WorkspaceError(f"git observation failed: {type(exc).__name__}") from exc
            if proc.returncode != 0:
                raise WorkspaceError(f"git returned {proc.returncode}: {proc.stderr.decode('utf-8', 'replace').strip()[:300]}")
            return proc.stdout

    def _declared_filters(self) -> list[str]:
        """``-c`` arguments that switch off every ``filter.<driver>`` the repository's own configuration declares.

        ``status`` and ``diff`` hash worktree files, and a driver's ``clean`` (or ``process``) command runs for that
        whenever ``.gitattributes`` or ``.git/info/attributes`` selects it: the repository config alone could start a
        program. The drivers are enumerated from the configuration (which executes nothing) and each is blanked, with
        ``required`` off so Git carries on unfiltered. An enumeration that fails stops the observation: it is never
        replaced by "assume none".
        """
        if self._filter_overrides is None:
            done = self._spawn([*self._base_command(), "config", "-z", "--get-regexp", r"^filter\."], timeout=15)
            if done.returncode not in (0, 1):  # 1 is Git's answer for "no such key"
                raise WorkspaceError(f"git returned {done.returncode}: {done.stderr.strip()[:300]}")
            drivers: set[str] = set()
            for record in done.stdout.split("\0"):
                key = record.partition("\n")[0]
                section, _, remainder = key.partition(".")
                driver, dot, _variable = remainder.rpartition(".")
                if section.lower() == "filter" and dot and driver:
                    drivers.add(driver)
            overrides: list[str] = []
            for driver in sorted(drivers):
                for variable in _FILTER_VARIABLES:
                    overrides += ["-c", f"filter.{driver}.{variable}="]
                overrides += ["-c", f"filter.{driver}.required=false"]
            self._filter_overrides = overrides
        return self._filter_overrides

    def _execute(
        self, args: list[str], *, timeout: int, hashes_worktree: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        with self._verified_root_session():
            overrides = self._declared_filters() if hashes_worktree else []
            return self._spawn([*self._base_command(), *overrides, *args], timeout=timeout)

    def _run(self, args: list[str], *, timeout: int = 15, hashes_worktree: bool = False) -> str:
        proc = self._execute(args, timeout=timeout, hashes_worktree=hashes_worktree)
        if proc.returncode != 0:
            raise WorkspaceError(f"git returned {proc.returncode}: {proc.stderr.strip()[:300]}")
        return proc.stdout

    def _probe(self, args: list[str], *, timeout: int = 15) -> tuple[int, str]:
        """Run Git and return ``(exit code, stdout)`` for the commands whose exit code is the answer."""
        proc = self._execute(args, timeout=timeout)
        return proc.returncode, proc.stdout

    def worktree_list(self) -> list[dict[str, str | bool]]:
        """Return all worktrees for this repository (read-only discovery)."""
        self._verify_root()
        raw = self._run(["worktree", "list", "--porcelain"])
        worktrees: list[dict[str, str | bool]] = []
        current: dict[str, str | bool] = {}
        for line in raw.splitlines():
            if not line.strip():
                if current:
                    worktrees.append(current)
                    current = {}
                continue
            if line.startswith("worktree "):
                current["path"] = line[len("worktree "):]
            elif line.startswith("HEAD "):
                current["head"] = line[len("HEAD "):]
            elif line.startswith("branch "):
                ref = line[len("branch "):]
                current["branch"] = ref.replace("refs/heads/", "")
            elif line == "bare":
                current["bare"] = True
            elif line == "detached":
                current["branch"] = None
                current["detached"] = True
        if current:
            worktrees.append(current)
        self._verify_root()
        return worktrees

    def is_tracked(self, path: str) -> bool:
        """Return whether the lexical workspace-relative path is tracked in HEAD/index.

        The caller should separately resolve the path through the filesystem
        confinement policy. Keeping this check lexical preserves Git identity
        for tracked symlinks while still preventing path traversal/secret names.
        """
        self._verify_root()
        rel = ensure_relative_path(path).as_posix()
        try:
            self._run(["ls-files", "--error-unmatch", "--", rel])
        except WorkspaceError:
            return False
        self._verify_root()
        return True

    def _resolve_head(self) -> str | None:
        """The commit HEAD names, or ``None`` when it names none (see ``_unborn_branch``)."""
        code, out = self._probe(["rev-parse", "--verify", "--quiet", "HEAD"])
        return out.strip() if code == 0 else None

    def _unborn_branch(self) -> str:
        """The branch HEAD points at while that branch has no commit yet.

        Recognised from Git's own answers, never assumed from a failure: HEAD must name a branch
        (``symbolic-ref``), Git must report the ref missing (``show-ref``) and no loose ref *file*
        may sit at that name. A detached HEAD that names no commit, or a branch ref that exists but
        cannot be resolved, is a broken repository and stays an error. The file check does not
        depend on how ``symbolic-ref`` answers for a broken ref (Git 2.51 fails it; that is not a
        contract), while a directory at that name is only what a deleted ``branch/name`` leaves
        behind and says nothing against the branch being unborn.
        """
        code, ref_out = self._probe(["symbolic-ref", "--quiet", "HEAD"])
        ref = ref_out.strip()
        if code != 0 or not ref:
            raise WorkspaceError("git observation failed: HEAD does not name a commit or a branch")
        missing, _ = self._probe(["show-ref", "--verify", "--quiet", ref])
        path_code, path_out = self._probe(["rev-parse", "--git-path", ref])
        if missing != 1 or path_code != 0:
            raise WorkspaceError("git observation failed: HEAD does not resolve")
        loose = Path(path_out.strip())
        if not loose.is_absolute():
            loose = Path(self.root) / loose
        if loose.is_file():
            raise WorkspaceError("git observation failed: the branch ref exists but does not resolve")
        return ref.removeprefix("refs/heads/")

    def _head(self) -> tuple[str | None, str | None, str]:
        """``(commit, branch, state)`` where ``state`` is ``attached``, ``detached`` or ``unborn``."""
        commit = self._resolve_head()
        if commit is None:
            return None, self._unborn_branch(), "unborn"
        branch_raw = self._run(["branch", "--show-current"]).strip()
        if branch_raw:
            return commit, branch_raw, "attached"
        code, _ = self._probe(["symbolic-ref", "--quiet", "HEAD"])
        return commit, None, "attached" if code == 0 else "detached"

    def status(self) -> dict[str, Any]:
        self._verify_root()
        commit, branch, head_state = self._head()
        result = {
            "head": commit,
            "branch": branch,
            "head_state": head_state,
            # An unborn branch has no history to read; its status (staged and untracked files) is real.
            "history_available": commit is not None,
            # Tracked sensitive paths are kept out of Git's walk (so their worktree files are not even hashed for the
            # modified flag), renames are off (pairing compares content), and the untracked ones are screened by name.
            "status": drop_denied_status_lines(self._run([
                "status", "--short", "--untracked-files=normal", "--no-renames", "--ignore-submodules=all",
                *self._scope_pathspec("enumerate", self._denied_tracked_paths()),
            ], hashes_worktree=True)),
        }
        self._verify_root()
        return result

    def _denied_tracked_paths(self) -> list[str]:
        """Tracked paths below this workspace with a sensitive-name component, read from the index alone (no worktree
        file is opened). Names are relative to the workspace, like the pathspecs they become."""
        listing = self._run(["ls-files", "-z"])
        return sorted(path for path in listing.split("\0") if path and is_denied_path(path))

    def diff(self, path: str | None = None) -> dict[str, object]:
        """The unstaged changes (index against work tree) of this workspace, or of ``path`` (a file or a subtree).

        Returns ``diff`` (Git's own unified-diff text), ``truncated``, ``complete`` and ``omitted``. ``omitted`` counts
        the paths that are NOT in ``diff`` by reason (``git_snapshot`` lists them): a refused name or a denied scope
        is a count only, every other reason (a hard-linked file, a pipe, a file over budget, a path that changed
        under the read ...) also names the path. ``complete`` is false whenever anything was left out. A path named
        explicitly whose name or scope is refused is an error, as it always was.
        """
        self._verify_root()
        selection: list[str] = []
        if path:
            # Decide from the path as written before the filesystem is consulted (no existence
            # oracle), then again on the real path (an alias of a denied file is denied). A path that does
            # not exist is not an error: it has no changes (and a deleted tracked file has one).
            self._policy.require("read", Path(self.root) / ensure_relative_path(path))
            safe = resolve_safe_path(self.root, path, must_exist=False)
            self._policy.require("read", safe)
            self._policy.require_single_name("read", safe)
            rel = safe.relative_to(Path(self.root)).as_posix()
            if rel != ".":
                selection = ["--", f":(literal){rel}"]
        # The index is listed once, by Git, with no worktree file opened. From here on Git is not asked about the
        # work tree again: which paths are in play is decided by this listing and by UAM's own authority checks.
        listing = self._run_bytes(["ls-files", "-s", "-z", "--debug", *selection])
        try:
            index_mtime_ns: int | None = os.stat(self._facts.index_path).st_mtime_ns
        except OSError:
            index_mtime_ns = None
        effective_budgets = replace(
            self._budgets,
            max_diff_bytes=min(self._budgets.max_diff_bytes, MAX_DIFF_CHARS * 4),
        )
        built = build_unstaged_diff(
            root=Path(self.root), listing=listing, index_mtime_ns=index_mtime_ns, git_command=[self._git],
            environment=dict(_HERMETIC_ENV), objects_dir=self._facts.objects_dir,
            object_format=self._facts.object_format, policy=self._policy, budgets=effective_budgets,
            root_identity=self._root_identity, authority_check=self._authority_check,
        )
        truncated = built.diff_truncated or len(built.text) > MAX_DIFF_CHARS
        self._verify_root()
        return {
            "diff": built.text[:MAX_DIFF_CHARS],
            "truncated": truncated,
            "complete": not truncated and built.omissions.count == 0,
            "omitted": built.omissions.report(),
        }

    def log(self, limit: int = 20) -> dict[str, Any]:
        self._verify_root()
        if not (1 <= limit <= 100):
            raise WorkspaceError("limit must be 1..100")
        if self._resolve_head() is None:
            self._unborn_branch()  # a broken repository is an error, not an empty history
            self._verify_root()
            return {"commits": [], "history_available": False, "reason": "unborn_head"}
        fmt = "%H%x1f%aI%x1f%an%x1f%s"
        raw = self._run(["log", f"-{limit}", "--no-show-signature", f"--pretty=format:{fmt}"])
        commits = []
        for line in raw.splitlines():
            parts = line.split("\x1f", 3)
            if len(parts) == 4:
                commits.append({"sha": parts[0], "authored_at": parts[1], "author": parts[2], "subject": parts[3]})
        self._verify_root()
        return {"commits": commits, "history_available": True}
