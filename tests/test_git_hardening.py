"""S1-C: a whole-repository ``git diff`` must not carry a file the name rules refuse to read.

``ReadOnlyGit.diff()`` checked the path only when one was given; without it the diff covered every tracked file, so a
tracked ``.env`` or ``tokens.env`` with local changes came back in full. These tests run REAL Git subprocesses against
synthetic repositories (fictional bodies only) and prove the properties separately:

* content independence: changing only the body of a refused file changes nothing that is returned;
* the refused file is never opened (a mode-000 file does not make the diff fail);
* rename/copy detection cannot pair a refused file with an allowed one;
* textconv, external diff and ``filter.<driver>`` commands in the repository's own config never run;
* every check has a control that shows the scenario really leaks without the fix.

r3: ``diff()`` no longer filters Git's output (an exclusion list and a patch screen); it decides which paths may be
read before anything is read, and Git only diffs a private copy of what was admitted (``git_snapshot``). The tests
that exercised the two filters (``test_too_many_exclusions_are_refused_not_truncated`` for ``diff``, the patch-screen
class, the diff half of ``test_an_enumeration_that_fails_stops_the_observation``) were replaced by tests of the new
contract here and in ``test_r3_git_boundary``; ``status`` keeps the exclusion list and its test.
"""
from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from universal_agent_middleware import git_readonly
from universal_agent_middleware.errors import PathPolicyError, WorkspaceError
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.git_readonly import ReadOnlyGit

from tests.synthetic_fixtures import init_git_repo, write_workspace_registry

BODY_A = "S1_FICTIONAL_BODY_A_7f3a"
BODY_B = "S1_FICTIONAL_BODY_B_91cd"
SHARED = "shared fictional text one\nshared fictional text two\nshared fictional text three\n"
DENIED_TRACKED = (
    ".secrets.env", "config/tokens.env", "config/.env.local", "keys/server.pem", "deploy/id_rsa", ".aws/credentials",
)
needs_non_root = unittest.skipIf(not hasattr(os, "geteuid") or os.geteuid() == 0, "needs a non-root POSIX account")

# The oracle for "a program the repository declared was started" is a marker file written by that program. An editor or
# indexer that watches the directory the synthetic repository lives in runs ITS OWN Git there (``git status -z -uall``,
# ``git diff``), which starts the same program and would trip the oracle although ReadOnlyGit never ran it (observed:
# Cursor's Git extension and retrieval host, one second after the repository was created). The program therefore writes
# the marker only when it carries this token, and the token reaches it through the environment of the Git processes
# THIS test starts: its own subprocesses and ReadOnlyGit's hermetic environment, never a bystander's.
TOKEN_VARIABLE = "UAM_S1_TEST_TOKEN"


def run_git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=30)
    if check and done.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {done.stderr}")
    return done


class RepoCase(unittest.TestCase):
    def setUp(self) -> None:
        if not hasattr(self, "token"):  # setUp() is also called to get a fresh repository inside one test
            self.token = uuid.uuid4().hex
            for target in (os.environ, git_readonly._HERMETIC_ENV):
                patcher = mock.patch.dict(target, {TOKEN_VARIABLE: self.token})
                patcher.start()
                self.addCleanup(patcher.stop)
        tmp = tempfile.TemporaryDirectory(prefix="uam-s1-git-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.repo = self.base / "repo"
        files = {"src/app.py": "value = 1\n", "docs/old.txt": SHARED}
        files.update({rel: f"TOKEN={BODY_A}\nline two {BODY_A}\n" for rel in DENIED_TRACKED})
        init_git_repo(self.repo, files=files)

    def rewrite_denied(self, body: str) -> None:
        for rel in DENIED_TRACKED:
            (self.repo / rel).write_text(f"TOKEN={body}\nchanged line {body}\nmore {body}\n", encoding="utf-8")

    def change_allowed(self) -> None:
        (self.repo / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")

    def script(self, name: str, *, body: str = "cat") -> tuple[Path, Path]:
        """A program the repository may declare, and the marker it leaves when THIS test's Git starts it.

        ``body`` is what it does besides leaving the marker: a filter passes its input through (``cat``), a textconv
        prints the file it is given, an external diff just exits (neither may wait for input that never comes).
        """
        marker = self.base / f"{name}.marker"
        path = self.base / f"{name}.sh"
        guard = f'[ "${TOKEN_VARIABLE}" = "{self.token}" ]'
        path.write_text(f"#!/bin/sh\n{guard} && echo ran >> '{marker}'\n{body}\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path, marker


class ContentIndependenceTests(RepoCase):
    def test_the_diff_carries_no_denied_file_and_does_not_depend_on_one(self) -> None:
        self.change_allowed()
        observed: list[str] = []
        for body in (BODY_A, BODY_B, "x"):
            self.rewrite_denied(body)
            observed.append(ReadOnlyGit(str(self.repo)).diff()["diff"])
        self.assertEqual(observed[0], observed[1])
        self.assertEqual(observed[0], observed[2])
        text = observed[0]
        self.assertIn("src/app.py", text)
        self.assertIn("+value = 2", text)
        for forbidden in (BODY_A, BODY_B, "TOKEN=", *DENIED_TRACKED, "tokens.env", "server.pem"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_control_without_the_exclusion_the_same_scenario_leaks(self) -> None:
        self.change_allowed()
        self.rewrite_denied(BODY_A)
        raw = run_git(self.repo, "diff", "--no-ext-diff", "--no-textconv").stdout
        self.assertIn(BODY_A, raw)  # the scenario is live: the defect was real
        for rel in DENIED_TRACKED:
            self.assertIn(rel, raw)

    def test_the_same_holds_through_the_gateway(self) -> None:
        self.change_allowed()
        self.rewrite_denied(BODY_A)
        registry = write_workspace_registry(self.base / "config" / "workspaces.json", [{
            "workspace_id": "proj", "root": str(self.repo), "kind": "git-repository",
            "capabilities": ["filesystem.read", "git.observe"],
        }])
        gateway = MiddlewareGateway(str(registry), str(self.base / "state"))
        text = gateway.git_diff("proj")["diff"]
        self.assertIn("+value = 2", text)
        self.assertNotIn(BODY_A, text)
        self.assertNotIn("tokens.env", text)

    def test_a_path_named_explicitly_is_still_refused(self) -> None:
        self.rewrite_denied(BODY_A)
        reader = ReadOnlyGit(str(self.repo))
        for rel in DENIED_TRACKED:
            with self.subTest(path=rel):
                with self.assertRaises(PathPolicyError):
                    reader.diff(rel)

    def test_a_diff_of_an_allowed_path_still_works(self) -> None:
        self.change_allowed()
        text = ReadOnlyGit(str(self.repo)).diff("src/app.py")["diff"]
        self.assertIn("+value = 2", text)


class ExclusionBeforeReadTests(RepoCase):
    @needs_non_root
    def test_git_does_not_open_a_denied_file_at_all(self) -> None:
        self.change_allowed()
        self.rewrite_denied(BODY_A)
        locked = [self.repo / rel for rel in DENIED_TRACKED]
        for path in locked:
            path.chmod(0)
            self.addCleanup(path.chmod, 0o600)
        control = run_git(self.repo, "diff", "--no-ext-diff", "--no-textconv", check=False)
        self.assertTrue(
            control.returncode != 0 or "Permission denied" in control.stderr,
            "control: a plain diff must trip over an unreadable modified file, or the oracle proves nothing",
        )
        result = ReadOnlyGit(str(self.repo)).diff()  # raises if Git touched any of them
        self.assertIn("+value = 2", result["diff"])

    def test_too_many_exclusions_are_refused_not_truncated(self) -> None:
        """``status`` still hands Git an exclusion list; one that does not fit is refused, never cut short."""
        self.rewrite_denied(BODY_A)
        with mock.patch.object(git_readonly, "MAX_EXCLUDE_ARGUMENT_BYTES", 40):
            with self.assertRaisesRegex(WorkspaceError, "too many excluded paths"):
                ReadOnlyGit(str(self.repo)).status()

    def test_the_diff_hands_git_no_exclusion_list_at_all(self) -> None:
        """``diff`` has no list to truncate or to miss: it never asks Git about the work tree."""
        self.change_allowed()
        self.rewrite_denied(BODY_A)
        with mock.patch.object(git_readonly, "MAX_EXCLUDE_ARGUMENT_BYTES", 40), \
                mock.patch.object(ReadOnlyGit, "_denied_tracked_paths", side_effect=AssertionError("consulted")):
            result = ReadOnlyGit(str(self.repo)).diff()
        self.assertIn("+value = 2", result["diff"])
        self.assertNotIn(BODY_A, result["diff"])


class RenamePairingTests(RepoCase):
    def test_a_denied_file_cannot_surface_as_the_other_half_of_a_rename(self) -> None:
        # docs/old.txt is deleted, and a denied-name file with the same body is registered with intent-to-add:
        # rename detection would report "rename from docs/old.txt, rename to prod.env".
        (self.repo / "docs" / "old.txt").unlink()
        (self.repo / "prod.env").write_text(SHARED, encoding="utf-8")
        run_git(self.repo, "add", "-N", "prod.env")
        control = run_git(self.repo, "diff", "-M", "--no-ext-diff", "--no-textconv").stdout
        self.assertIn("prod.env", control, "control: rename detection pairs them without the fix")
        text = ReadOnlyGit(str(self.repo)).diff()["diff"]
        self.assertNotIn("prod.env", text)
        self.assertNotIn("rename", text)
        self.assertNotIn("similarity", text)
        self.assertIn("docs/old.txt", text)  # the allowed half is still reported, as a plain deletion
        self.assertIn("deleted file mode", text)


class RepositoryConfigTests(RepoCase):
    def test_the_marker_oracle_only_counts_this_tests_git(self) -> None:
        script, marker = self.script("oracle")
        (self.repo / ".gitattributes").write_text("*.py filter=probe\n", encoding="utf-8")
        run_git(self.repo, "config", "filter.probe.clean", str(script))
        self.change_allowed()
        bystander = {name: value for name, value in os.environ.items() if name != TOKEN_VARIABLE}
        subprocess.run(["git", "-C", str(self.repo), "status", "--short"], capture_output=True, env=bystander,
                       timeout=30, check=True)
        self.assertFalse(marker.exists(), "a Git that does not carry the token must not leave the marker")
        run_git(self.repo, "status", "--short")
        self.assertTrue(marker.exists(), "a Git started by this test must leave it, or the oracle is dead")

    # Each program gets its own repository: with both configured Git runs the external diff and never reaches the
    # textconv, so a shared repository would leave one of the two oracles blind.
    def test_textconv_never_runs(self) -> None:
        textconv, marker = self.script("textconv", body='cat "$1"')
        (self.repo / ".gitattributes").write_text("*.py diff=probe\n", encoding="utf-8")
        run_git(self.repo, "config", "diff.probe.textconv", str(textconv))
        self.change_allowed()
        run_git(self.repo, "diff", "--no-ext-diff")
        self.assertTrue(marker.exists(), "control: a plain diff runs the declared textconv")
        marker.unlink()
        text = ReadOnlyGit(str(self.repo)).diff()["diff"]
        self.assertIn("+value = 2", text)
        self.assertFalse(marker.exists(), "an untrusted textconv ran")

    def test_external_diff_never_runs(self) -> None:
        external, marker = self.script("external", body="exit 0")
        run_git(self.repo, "config", "diff.external", str(external))
        self.change_allowed()
        run_git(self.repo, "diff")
        self.assertTrue(marker.exists(), "control: a plain diff runs the declared external diff")
        marker.unlink()
        text = ReadOnlyGit(str(self.repo)).diff()["diff"]
        self.assertIn("+value = 2", text)
        self.assertFalse(marker.exists(), "an untrusted external diff ran")

    def test_declared_filter_drivers_never_run(self) -> None:
        drivers = {
            "clean": ("probe-clean", {"clean"}), "required": ("probe-required", {"clean", "required"}),
            "smudge": ("probe-smudge", {"smudge"}), "process": ("probe-process", {"process"}),
            "dotted-name": ("my.driver.v2", {"clean"}),  # the subsection itself contains dots
        }
        for label, (driver, kinds) in drivers.items():
            for attributes_in in ("worktree", "info"):
                with self.subTest(driver=label, attributes_in=attributes_in):
                    self.setUp()  # a fresh repository per case
                    script, marker = self.script(f"filter-{label}-{attributes_in}")
                    rule = f"*.py filter={driver}\n"
                    if attributes_in == "worktree":
                        (self.repo / ".gitattributes").write_text(rule, encoding="utf-8")
                    else:
                        (self.repo / ".git" / "info" / "attributes").write_text(rule, encoding="utf-8")
                    for kind in kinds:
                        run_git(self.repo, "config", f"filter.{driver}.{kind}", "true" if kind == "required" else str(script))
                    self.change_allowed()
                    marker.unlink(missing_ok=True)
                    run_git(self.repo, "-c", "core.fsmonitor=false", "status", "--short")
                    if kinds != {"smudge"}:
                        self.assertTrue(marker.exists(), "control: a plain status runs the declared driver")
                    marker.unlink(missing_ok=True)
                    observed = ReadOnlyGit(str(self.repo))
                    status = observed.status()["status"]
                    diff = observed.diff()["diff"]
                    self.assertFalse(marker.exists(), "a repository filter driver ran")
                    self.assertIn("src/app.py", status)
                    self.assertIn("+value = 2", diff)

    def test_an_enumeration_that_fails_stops_the_observation(self) -> None:
        """``status`` hashes work tree files, so it enumerates the repository's filter drivers first, and a failed
        enumeration stops it. ``diff`` never has Git hash a work tree file, so it needs no enumeration at all."""
        self.change_allowed()
        observed = ReadOnlyGit(str(self.repo))
        real_spawn = ReadOnlyGit._spawn
        enumerated: list[bool] = []

        def failing(instance, command, *, timeout):
            if "--get-regexp" in command:
                enumerated.append(True)
                return subprocess.CompletedProcess(command, 129, "", "usage: git config")
            return real_spawn(instance, command, timeout=timeout)

        with mock.patch.object(ReadOnlyGit, "_spawn", failing):
            self.assertIn("+value = 2", observed.diff()["diff"])
            self.assertEqual(enumerated, [], "diff must not depend on the filter enumeration")
            with self.assertRaisesRegex(WorkspaceError, "git returned 129"):
                observed.status()


class IndexRaceTests(RepoCase):
    """The index is listed once and that listing decides what is in play: there is no second look at the index and
    no screen over a patch that was already produced (the r2 design), so nothing added later can be read."""

    def test_an_entry_added_to_the_index_after_the_listing_is_never_read(self) -> None:
        self.change_allowed()
        late = self.repo / "late" / "prod.env"
        late.parent.mkdir()
        late.write_text(f"TOKEN={BODY_A}\n", encoding="utf-8")
        real_run_bytes = ReadOnlyGit._run_bytes

        def listing_then_stage_a_refused_file(instance, args, *, timeout=60):
            output = real_run_bytes(instance, args, timeout=timeout)
            if args[:1] == ["ls-files"]:  # right after the one listing, a refused file enters the index and changes
                run_git(self.repo, "add", "-f", "late/prod.env")
                late.write_text(f"TOKEN={BODY_B}\nmore\n", encoding="utf-8")
            return output

        with mock.patch.object(ReadOnlyGit, "_run_bytes", listing_then_stage_a_refused_file):
            result = ReadOnlyGit(str(self.repo)).diff()
        self.assertIn("+value = 2", result["diff"])
        for forbidden in (BODY_A, BODY_B, "prod.env"):
            self.assertNotIn(forbidden, result["diff"])
        self.assertEqual(
            run_git(self.repo, "ls-files", "late/prod.env").stdout.strip(), "late/prod.env",
            "control: the file really did enter the index after the listing",
        )


class StatusHardeningTests(RepoCase):
    """``git status`` names refused files and, for a tracked one, derives a modified flag by hashing the worktree file."""

    UNTRACKED_DENIED = (".env.production", ".ssh/config", "src/\u00fcn\u00ef/.env", "docs/tokens.env")

    def prepare(self) -> None:
        """A tracked directory with a non-ASCII name (Git quotes it), untracked refused files, an untracked visible one."""
        (self.repo / "src" / "\u00fcn\u00ef").mkdir()
        (self.repo / "src" / "\u00fcn\u00ef" / "keep.txt").write_text("kept\n", encoding="utf-8")
        run_git(self.repo, "add", "src")
        run_git(self.repo, "commit", "-qm", "add src/uni")
        self.change_allowed()
        for rel in self.UNTRACKED_DENIED:
            target = self.repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"TOKEN={BODY_A}\n", encoding="utf-8")
        (self.repo / "new_visible.txt").write_text("visible\n", encoding="utf-8")

    def observed(self) -> str:
        return ReadOnlyGit(str(self.repo)).status()["status"]

    def test_status_carries_no_refused_name_and_no_bit_of_a_refused_body(self) -> None:
        self.prepare()
        seen: list[str] = []
        for body in (BODY_A, BODY_B, "x"):
            self.rewrite_denied(body)
            seen.append(self.observed())
        run_git(self.repo, "checkout", "--", *DENIED_TRACKED)  # back to the committed bytes: no modified flag exists
        seen.append(self.observed())
        self.assertEqual(len(set(seen)), 1, "status depends on the content of a refused file")
        text = seen[0]
        self.assertIn(" M src/app.py", text)
        self.assertIn("?? new_visible.txt", text)
        for forbidden in (
            *DENIED_TRACKED, ".env", ".ssh", "tokens", "secrets", "credentials", "id_rsa", "server.pem", "\\303",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_control_a_plain_status_names_them_and_the_flag_follows_the_content(self) -> None:
        self.prepare()
        self.rewrite_denied(BODY_A)
        modified = run_git(self.repo, "status", "--short", "--untracked-files=normal").stdout
        for name in (" M .secrets.env", " M config/tokens.env", ".env.production", "tokens.env"):
            self.assertIn(name, modified)
        run_git(self.repo, "checkout", "--", *DENIED_TRACKED)
        restored = run_git(self.repo, "status", "--short", "--untracked-files=normal").stdout
        self.assertNotIn(" M .secrets.env", restored)  # the flag is a bit of the content: restoring it flips the bit

    def test_git_does_not_hash_a_refused_tracked_file_for_status(self) -> None:
        """Hashing a worktree file runs its clean filter, so a filter that logs ``%f`` shows exactly which files Git read.

        (An unreadable file is no oracle here: for the modified flag Git swallows the failed open and just reports ``M``.)
        """
        self.prepare()
        # Same size as the committed bytes, so Git cannot call a file modified from its size alone and has to hash it.
        for rel in DENIED_TRACKED:
            (self.repo / rel).write_text(f"TOKEN={BODY_B}\nline two {BODY_B}\n", encoding="utf-8")
        log = self.base / "hashed.log"
        logger = self.base / "hash-logger.sh"
        logger.write_text(f"#!/bin/sh\necho \"$1\" >> '{log}'\ncat\n", encoding="utf-8")
        logger.chmod(logger.stat().st_mode | stat.S_IXUSR)
        (self.repo / ".git" / "info" / "attributes").write_text("* filter=hashlog\n", encoding="utf-8")
        run_git(self.repo, "config", "filter.hashlog.clean", f"{logger} %f")
        self.change_allowed()

        run_git(self.repo, "-c", "core.fsmonitor=false", "status", "--short")
        hashed = log.read_text(encoding="utf-8").split()
        self.assertIn("src/app.py", hashed, "control: the logger sees the files a plain status hashes")
        for rel in DENIED_TRACKED:
            self.assertIn(rel, hashed, f"control: a plain status hashes {rel}")

        log.unlink()
        # The filter must really be allowed to run for the exclusion to be what is measured here.
        with mock.patch.object(ReadOnlyGit, "_declared_filters", return_value=[]):
            text = self.observed()
        hashed = log.read_text(encoding="utf-8").split() if log.exists() else []
        self.assertIn("src/app.py", hashed, "the logger is live inside the observer's own status")
        self.assertEqual([rel for rel in DENIED_TRACKED if rel in hashed], [], "Git hashed a refused file")
        self.assertIn(" M src/app.py", text)

    def test_the_same_holds_through_the_gateway(self) -> None:
        self.prepare()
        self.rewrite_denied(BODY_A)
        registry = write_workspace_registry(self.base / "config" / "workspaces.json", [{
            "workspace_id": "proj", "root": str(self.repo), "kind": "git-repository",
            "capabilities": ["filesystem.read", "git.observe"],
        }])
        gateway = MiddlewareGateway(str(registry), str(self.base / "state"))
        text = gateway.git_status("proj")["status"]
        self.assertIn(" M src/app.py", text)
        for forbidden in (*DENIED_TRACKED, ".env", ".ssh", "tokens"):
            self.assertNotIn(forbidden, text)

    def test_a_directory_diff_leaves_out_the_refused_files_it_contains(self) -> None:
        self.rewrite_denied(BODY_A)
        run_git(self.repo, "checkout", "--", "config/.env.local")  # keep one refused file unchanged: still excluded
        text = ReadOnlyGit(str(self.repo)).diff("config")["diff"]
        self.assertNotIn(BODY_A, text)
        self.assertNotIn("tokens.env", text)
        control = run_git(self.repo, "diff", "--no-ext-diff", "--no-textconv", "--", "config").stdout
        self.assertIn(BODY_A, control, "control: Git itself diffs the directory including the refused file")


class StatusScreenTests(unittest.TestCase):
    def test_git_quoting_is_undone(self) -> None:
        cases = {
            "plain.txt": "plain.txt",
            "with space/file": "with space/file",
            '"\\303\\274n\\303\\257/.env"': "\u00fcn\u00ef/.env",
            '"quo\\"ted\\\\back\\ttab\\nnl"': 'quo"ted\\back\ttab\nnl',
            '"\\001\\177"': "\x01\x7f",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(git_readonly.unquote_git_path(text), expected)

    def test_a_malformed_quote_is_an_error_not_a_guess(self) -> None:
        for text in ('"dangling\\"', '"bad\\q"', '"short\\30"', '"nonoctal\\389"'):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    git_readonly.unquote_git_path(text)

    def test_lines_naming_a_refused_component_are_dropped_and_malformed_ones_fail_closed(self) -> None:
        status = (
            " M src/app.py\n"
            "?? .env.production\n"
            " M config/tokens.env\n"
            '?? ".ssh/with space"\n'
            '?? "\\303\\274n/.secrets.env"\n'
            '?? "bad\\q/readme.md"\n'
            "?? docs/readme.md\n"
            "?? .ssh/\n"
        )
        self.assertEqual(
            git_readonly.drop_denied_status_lines(status),
            " M src/app.py\n?? docs/readme.md\n",
        )
        self.assertEqual(git_readonly.drop_denied_status_lines(""), "")


if __name__ == "__main__":
    unittest.main()
