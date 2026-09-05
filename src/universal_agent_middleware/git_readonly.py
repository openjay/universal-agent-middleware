from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .errors import WorkspaceError
from .policy import ensure_relative_path, resolve_safe_path


class ReadOnlyGit:
    """Hermetic, fixed Git observations.

    The target repository is treated as untrusted input. Repository/global Git
    configuration must not be able to turn a read operation into an external
    process launch (for example via fsmonitor, external diff, pager, or textconv).
    """

    def __init__(self, root: str):
        self.root = str(Path(root).resolve(strict=True))
        self._run(["rev-parse", "--is-inside-work-tree"])

    def _run(self, args: list[str], *, timeout: int = 15) -> str:
        cmd = [
            "git",
            "-c", "core.fsmonitor=false",
            "-c", "core.pager=cat",
            "-c", "pager.status=false",
            "-c", "pager.diff=false",
            "-c", "pager.log=false",
            "-c", "diff.external=",
            "-C", self.root,
            *args,
        ]
        env = {
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            "LC_ALL": "C",
        }
        try:
            proc = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise WorkspaceError(f"git observation failed: {type(exc).__name__}") from exc
        if proc.returncode != 0:
            raise WorkspaceError(f"git returned {proc.returncode}: {proc.stderr.strip()[:300]}")
        return proc.stdout


    def worktree_list(self) -> list[dict[str, str | bool]]:
        """Return all worktrees for this repository (read-only discovery)."""
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
        return worktrees

    def is_tracked(self, path: str) -> bool:
        """Return whether the lexical workspace-relative path is tracked in HEAD/index.

        The caller should separately resolve the path through the filesystem
        confinement policy. Keeping this check lexical preserves Git identity
        for tracked symlinks while still preventing path traversal/secret names.
        """
        rel = ensure_relative_path(path).as_posix()
        try:
            self._run(["ls-files", "--error-unmatch", "--", rel])
        except WorkspaceError:
            return False
        return True

    def status(self) -> dict[str, str]:
        head = self._run(["rev-parse", "HEAD"]).strip()
        branch_raw = self._run(["branch", "--show-current"]).strip()

        if branch_raw:
            head_state = "attached"
            branch = branch_raw
        else:
            try:
                self._run(["symbolic-ref", "-q", "HEAD"])
                head_state = "attached"
                branch = None
            except Exception:
                head_state = "detached"
                branch = None

        return {
            "head": head,
            "branch": branch,
            "head_state": head_state,
            "status": self._run(["status", "--short", "--untracked-files=normal", "--ignore-submodules=all"]),
        }

    def diff(self, path: str | None = None) -> dict[str, object]:
        args = ["diff", "--no-ext-diff", "--no-textconv", "--no-color", "--ignore-submodules=all"]
        if path:
            safe = resolve_safe_path(self.root, path)
            rel = safe.relative_to(Path(self.root)).as_posix()
            args.extend(["--", rel])
        output = self._run(args)
        return {"diff": output[:200_000], "truncated": len(output) > 200_000}

    def log(self, limit: int = 20) -> dict[str, object]:
        if not (1 <= limit <= 100):
            raise WorkspaceError("limit must be 1..100")
        fmt = "%H%x1f%aI%x1f%an%x1f%s"
        raw = self._run(["log", f"-{limit}", "--no-show-signature", f"--pretty=format:{fmt}"])
        commits = []
        for line in raw.splitlines():
            parts = line.split("\x1f", 3)
            if len(parts) == 4:
                commits.append({"sha": parts[0], "authored_at": parts[1], "author": parts[2], "subject": parts[3]})
        return {"commits": commits}
