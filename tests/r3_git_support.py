"""Shared pieces of the R3-02 / R3-05 Git tests (``test_r3_git_boundary`` and ``test_r3_git_snapshot``).

Everything is synthetic: a real Git, synthetic repositories under a per-test temporary directory, fictional bodies.
The oracle for "a program the repository declared was started" is a marker file written only by a program that
carries this test's token, so that an editor running its own Git in the same directory cannot trip it (see
``test_git_hardening``).
"""
from __future__ import annotations

import contextlib
import os
import stat
import subprocess
import tempfile
import unittest
import uuid
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

from universal_agent_middleware import git_readonly
from universal_agent_middleware.git_readonly import ReadOnlyGit

SECRET = "S1_R3_FICTIONAL_SECRET_BODY_5c1e"
OUTSIDE = "S1_R3_FICTIONAL_OUTSIDE_BODY_77ab"
TOKEN_VARIABLE = "UAM_R3_TEST_TOKEN"
PLAIN_DIFF = ("diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--no-color", "--ignore-submodules=all")
needs_non_root = unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "needs a non-root POSIX account")
GIT_EXECUTABLES = [path for path in ("/usr/bin/git", "/opt/homebrew/bin/git") if Path(path).is_file()]
needs_two_gits = unittest.skipIf(
    len(GIT_EXECUTABLES) < 2, "needs Apple Git (/usr/bin/git) and Homebrew Git (/opt/homebrew/bin/git)",
)

BASE_FILES = {
    "src/app.py": "value = 1\n",
    "docs/old.txt": "shared fictional text one\nshared fictional text two\n",
    "notes.txt": "old notes\n",
    ".secrets.env": "TOKEN=old\n",
    "bin/tool.sh": "#!/bin/sh\necho tool\n",
}


def git_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    return {
        **os.environ, "GIT_AUTHOR_NAME": "UAM R3", "GIT_AUTHOR_EMAIL": "r3@example.invalid",
        "GIT_COMMITTER_NAME": "UAM R3", "GIT_COMMITTER_EMAIL": "r3@example.invalid", **(extra or {}),
    }


def run_git(repo: Path, *args: str, executable: str = "git", check: bool = True, stdin: bytes | None = None,
            ) -> subprocess.CompletedProcess[str]:
    """Run Git and return its text. Decoded here, not by ``text=True``: that would turn a CRLF into an LF and a
    comparison against the bytes Git printed would no longer compare the same thing."""
    done = subprocess.run(
        [executable, "-C", str(repo), *args], capture_output=True, timeout=60, env=git_env(), input=stdin,
    )
    result = subprocess.CompletedProcess(
        done.args, done.returncode, done.stdout.decode("utf-8", "replace"), done.stderr.decode("utf-8", "replace"),
    )
    if check and result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result


def reasons_of(result: dict) -> dict[str, int]:
    """The omission reasons of a result, without the one the fixture itself causes.

    ``BASE_FILES`` tracks a ``.secrets.env``: its name is refused, so every diff of the repository reports it as
    ``refused_name`` (a count, never the name) whether it changed or not -- it was not looked at, which is the point.
    """
    return {reason: count for reason, count in result["omitted"]["reasons"].items() if reason != "refused_name"}


def make_repo(path: Path, files: dict[str, str], *, executable: str = "git") -> Path:
    """A repository built by the given Git (so a test can have one Git write it and the other observe it)."""
    path.mkdir(parents=True)
    run_git(path, "init", "-q", executable=executable)
    run_git(path, "config", "user.email", "r3@example.invalid", executable=executable)
    run_git(path, "config", "user.name", "UAM R3", executable=executable)
    for rel, body in files.items():
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    run_git(path, "add", "-A", executable=executable)
    run_git(path, "commit", "-qm", "base", executable=executable)
    return path


class WorldCase(unittest.TestCase):
    """A base directory per test and the token oracle; ``self.repo`` is built from ``BASE_FILES``."""

    def setUp(self) -> None:
        self.token = uuid.uuid4().hex
        for target in (os.environ, git_readonly._HERMETIC_ENV):
            patcher = mock.patch.dict(target, {TOKEN_VARIABLE: self.token})
            patcher.start()
            self.addCleanup(patcher.stop)
        tmp = tempfile.TemporaryDirectory(prefix="uam-r3-git-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.repo = make_repo(self.base / "repo", BASE_FILES)

    def script(self, name: str, *, body: str = "exit 0") -> tuple[Path, Path]:
        """A program the repository may declare and the marker it leaves when THIS test's Git starts it.

        ``body`` is what it does besides leaving the marker; it must not wait for input that never comes (a filter
        passes its input through with ``cat``, a textconv prints the file it is given, anything else just exits).
        """
        marker = self.base / f"{name}.marker"
        path = self.base / f"{name}.sh"
        path.write_text(f'#!/bin/sh\n[ "${TOKEN_VARIABLE}" = "{self.token}" ] && echo ran >> \'{marker}\'\n{body}\n',
                        encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path, marker

    @contextlib.contextmanager
    def use_git(self, executable: str) -> Iterator[None]:
        """Let the observer find THIS Git first on its hermetic PATH (a wrapper that execs the given binary).

        The observer resolves ``git`` on ``_HERMETIC_ENV['PATH']`` (r2 and r3 alike), so this is how a test chooses the
        Git under test without any parameter that only one of the two sources has.
        """
        shim = self.base / f"git-shim-{GIT_EXECUTABLES.index(executable)}"
        shim.mkdir(exist_ok=True)
        wrapper = shim / "git"
        if not wrapper.exists():
            wrapper.write_text(f'#!/bin/sh\nexec "{executable}" "$@"\n', encoding="utf-8")
            wrapper.chmod(0o755)
        with mock.patch.dict(git_readonly._HERMETIC_ENV, {"PATH": f"{shim}:/usr/bin:/bin"}):
            yield

    def observe(self, root: Path | None = None, **options) -> ReadOnlyGit:
        return ReadOnlyGit(str(root or self.repo), **options)
