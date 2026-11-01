"""R3-02 / R3-05: the Git read boundary of ``ReadOnlyGit`` (``uam_git_diff`` and ``uam_git_status``).

The audit of r2 found that its whole-repository and directory diffs were protected by filters around Git (an
exclusion list built from names, and a screen over the patch Git had already produced), and that Git itself decided
what to open. Each test below is a counterexample that is shown to FAIL on r2 and PASS on r3 with the same bytes
(``tools/r3_cx.sh``); a test that r2 already passes is labelled as a guard.

This module uses only what r2 and r3 both have (``ReadOnlyGit(root)`` and the public tool surface); the tests of the
r3 mechanism itself are in ``test_r3_git_snapshot``. The Git under test is chosen through the hermetic PATH
(``WorldCase.use_git``), so Apple Git and Homebrew Git are exercised by the same bytes on both sources.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import unittest
from collections.abc import Callable
from pathlib import Path

from universal_agent_middleware.errors import PathPolicyError, WorkspaceError
from universal_agent_middleware.git_readonly import ReadOnlyGit

from r3_git_support import (
    BASE_FILES, GIT_EXECUTABLES, OUTSIDE, PLAIN_DIFF, SECRET, WorldCase, make_repo, needs_non_root, needs_two_gits,
    reasons_of, run_git,
)
from r3_world import STATIC_ID, ProtocolWorld, call_protocol, create_session_read_server, decode, run

MCP_AVAILABLE = create_session_read_server is not None


# ---------------------------------------------------------------------------------------------------------------------
class HardLinkTests(WorldCase):
    """A hard link is the same bytes under another name: a decision made from names cannot see it."""

    def link_notes_to_the_refused_file(self) -> None:
        os.unlink(self.repo / "notes.txt")
        os.link(self.repo / ".secrets.env", self.repo / "notes.txt")
        (self.repo / ".secrets.env").write_text(f"TOKEN={SECRET}\n", encoding="utf-8")

    def test_control_plain_git_diffs_the_hard_link_with_the_refused_body(self) -> None:
        self.link_notes_to_the_refused_file()
        self.assertIn(SECRET, run_git(self.repo, *PLAIN_DIFF, "--", "notes.txt").stdout)

    def test_a_hard_link_to_a_refused_file_never_reaches_a_whole_repository_diff(self) -> None:
        self.link_notes_to_the_refused_file()
        (self.repo / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")
        result = self.observe().diff()
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertIn("+value = 2", result["diff"])  # the rest of the diff is still there
        self.assertFalse(result["complete"])
        self.assertEqual(reasons_of(result), {"hard_link": 1})
        self.assertIn("notes.txt", result["omitted"]["paths"])

    def test_a_hard_link_is_refused_when_it_is_named_explicitly(self) -> None:
        self.link_notes_to_the_refused_file()
        result = self.observe().diff("notes.txt")
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(result["omitted"]["reasons"], {"hard_link": 1})  # one file in scope: nothing else is counted
        self.assertEqual(result["diff"], "")

    def test_a_directory_diff_refuses_the_hard_link_inside_it(self) -> None:
        (self.repo / "docs" / "linked.txt").write_text("old linked\n", encoding="utf-8")
        run_git(self.repo, "add", "docs/linked.txt")
        run_git(self.repo, "commit", "-qm", "linked")
        os.unlink(self.repo / "docs" / "linked.txt")
        os.link(self.repo / ".secrets.env", self.repo / "docs" / "linked.txt")
        (self.repo / ".secrets.env").write_text(f"TOKEN={SECRET}\n", encoding="utf-8")
        (self.repo / "docs" / "old.txt").write_text("edited\n", encoding="utf-8")
        result = self.observe().diff("docs")
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertIn("+edited", result["diff"])
        self.assertEqual(result["omitted"]["reasons"], {"hard_link": 1})  # the refused file lies outside ``docs``

    def test_a_link_between_two_innocent_names_is_refused_too(self) -> None:
        """Stricter than the Reader on purpose: a file with other names cannot be proven to be an admitted object."""
        os.link(self.repo / "src" / "app.py", self.base / "elsewhere.py")
        (self.repo / "src" / "app.py").write_text("value = 9\n", encoding="utf-8")
        result = self.observe().diff()
        self.assertEqual(result["diff"], "")
        self.assertEqual(reasons_of(result), {"hard_link": 1})

    def test_control_a_file_with_one_name_is_diffed(self) -> None:
        self.link_notes_to_the_refused_file()
        os.unlink(self.repo / ".secrets.env")  # the link count drops back to one
        result = self.observe().diff("notes.txt")
        self.assertIn(f"+TOKEN={SECRET}", result["diff"])  # an admitted name with one name is an ordinary file
        self.assertTrue(result["complete"])


# ---------------------------------------------------------------------------------------------------------------------
class WorkspaceBoundaryTests(WorldCase):
    """The workspace root is the boundary: Git must not report more than lies below it, and not from elsewhere."""

    def nested(self) -> Path:
        outer = make_repo(self.base / "outer", {"outer.txt": "outer v1\n", "sub/app.py": "v=1\n"})
        (outer / "outer.txt").write_text(f"{OUTSIDE}\n", encoding="utf-8")
        (outer / "sub" / "app.py").write_text("v=2\n", encoding="utf-8")
        return outer / "sub"

    def test_a_workspace_below_the_repository_top_level_is_diffed_alone(self) -> None:
        workspace = self.nested()
        result = self.observe(workspace).diff()
        self.assertNotIn(OUTSIDE, json.dumps(result))
        self.assertNotIn("outer.txt", json.dumps(result))
        self.assertIn("+v=2", result["diff"])
        self.assertTrue(result["complete"])

    def test_control_plain_git_diffs_the_whole_repository_from_the_subdirectory(self) -> None:
        workspace = self.nested()
        self.assertIn(OUTSIDE, run_git(workspace, *PLAIN_DIFF).stdout)

    def test_the_status_of_a_nested_workspace_names_nothing_outside_it(self) -> None:
        workspace = self.nested()
        status = self.observe(workspace).status()["status"]
        self.assertNotIn("outer.txt", status)
        self.assertIn("app.py", status)

    def test_a_nested_workspace_diff_equals_git_relative_to_it(self) -> None:
        workspace = self.nested()
        expected = run_git(workspace, *PLAIN_DIFF, "--relative").stdout
        self.assertEqual(self.observe(workspace).diff()["diff"], expected)

    def test_naming_the_workspace_itself_stays_inside_it(self) -> None:
        workspace = self.nested()
        result = self.observe(workspace).diff(".")
        self.assertNotIn(OUTSIDE, json.dumps(result))
        self.assertIn("+v=2", result["diff"])

    def test_a_repository_whose_work_tree_is_elsewhere_is_refused(self) -> None:
        elsewhere = self.base / "elsewhere"
        (elsewhere / "src").mkdir(parents=True)
        (elsewhere / "src" / "app.py").write_text(f"{OUTSIDE}\n", encoding="utf-8")
        run_git(self.repo, "config", "core.worktree", str(elsewhere))
        control = run_git(self.repo, *PLAIN_DIFF).stdout
        self.assertIn(OUTSIDE, control, "control: Git itself reads the other directory for this repository")
        with self.assertRaises(WorkspaceError) as refused:
            observed = self.observe()
            observed.diff()
        self.assertNotIn(OUTSIDE, str(refused.exception))

    def test_a_redirected_work_tree_is_refused_for_status_too(self) -> None:
        elsewhere = self.base / "elsewhere"
        (elsewhere / "src").mkdir(parents=True)
        (elsewhere / "src" / "app.py").write_text("changed elsewhere\n", encoding="utf-8")
        run_git(self.repo, "config", "core.worktree", str(elsewhere))
        with self.assertRaises(WorkspaceError):
            self.observe().status()


# ---------------------------------------------------------------------------------------------------------------------
class SpecialPathTests(WorldCase):
    """Deletion, replacement by a link or a pipe, an unreadable file: each is decided before Git or a read can act."""

    def test_a_pipe_in_place_of_a_tracked_file_is_reported_and_the_rest_is_still_diffed(self) -> None:
        (self.repo / "docs" / "old.txt").write_text("edited\n", encoding="utf-8")
        os.unlink(self.repo / "src" / "app.py")
        os.mkfifo(self.repo / "src" / "app.py")
        result = self.observe().diff()
        self.assertIn("+edited", result["diff"], "one unsupported file must not take the whole diff down")
        self.assertEqual(reasons_of(result), {"special_file": 1})
        self.assertEqual(result["omitted"]["paths"], ["src/app.py"])

    def test_a_file_replaced_by_a_link_to_a_refused_name_shows_the_link_text_only(self) -> None:
        """Guard: r2 passes it (Git reads a link as text); r3 must keep it."""
        (self.repo / ".secrets.env").write_text(f"TOKEN={SECRET}\n", encoding="utf-8")
        os.unlink(self.repo / "src" / "app.py")
        os.symlink("../.secrets.env", self.repo / "src" / "app.py")
        result = self.observe().diff()
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertIn("+../.secrets.env", result["diff"])

    def test_a_directory_replaced_by_a_link_out_of_the_workspace_is_not_followed(self) -> None:
        """Git reads nothing beyond a link either; r3 must also say which paths it could not look at."""
        outside = self.base / "private"
        outside.mkdir()
        (outside / "old.txt").write_text(f"{OUTSIDE}\n", encoding="utf-8")
        shutil.rmtree(self.repo / "docs")
        os.symlink(str(outside), self.repo / "docs")
        result = self.observe().diff()
        self.assertNotIn(OUTSIDE, json.dumps(result))
        self.assertEqual(reasons_of(result), {"path_replaced": 1})

    def test_a_deleted_tracked_file_is_reported_as_a_deletion(self) -> None:
        (self.repo / "docs" / "old.txt").unlink()
        result = self.observe().diff("docs/old.txt")
        self.assertIn("deleted file mode", result["diff"])
        self.assertIn("-shared fictional text one", result["diff"])
        self.assertTrue(result["complete"])

    def test_a_directory_in_place_of_a_tracked_file_is_a_deletion(self) -> None:
        (self.repo / "notes.txt").unlink()
        (self.repo / "notes.txt").mkdir()
        (self.repo / "notes.txt" / "inner.txt").write_text(f"{OUTSIDE}\n", encoding="utf-8")
        result = self.observe().diff()
        self.assertIn("deleted file mode", result["diff"])
        self.assertNotIn(OUTSIDE, json.dumps(result))

    @needs_non_root
    def test_a_file_the_account_cannot_open_is_reported_unreadable(self) -> None:
        target = self.repo / "src" / "app.py"
        target.write_text("value = 3\n", encoding="utf-8")
        target.chmod(0)
        self.addCleanup(target.chmod, 0o600)
        (self.repo / "docs" / "old.txt").write_text("edited\n", encoding="utf-8")
        result = self.observe().diff()
        self.assertIn("+edited", result["diff"])
        self.assertEqual(reasons_of(result), {"unreadable": 1})

    def test_a_path_that_does_not_exist_has_no_changes_and_is_no_existence_oracle(self) -> None:
        self.assertEqual(self.observe().diff("no/such/file.txt")["diff"], "")
        self.assertEqual(self.observe().diff("src/app.py")["diff"], "")  # tracked and unchanged: the same answer

    def test_a_refused_name_named_explicitly_is_still_an_error(self) -> None:
        (self.repo / ".secrets.env").write_text(f"TOKEN={SECRET}\n", encoding="utf-8")
        with self.assertRaises(PathPolicyError):
            self.observe().diff(".secrets.env")

    def test_a_tracked_symlink_whose_target_changed_is_diffed_as_text(self) -> None:
        os.symlink("src/app.py", self.repo / "lnk")
        run_git(self.repo, "add", "lnk")
        run_git(self.repo, "commit", "-qm", "link")
        os.unlink(self.repo / "lnk")
        os.symlink("docs/old.txt", self.repo / "lnk")
        result = self.observe().diff()
        self.assertIn("-src/app.py", result["diff"])
        self.assertIn("+docs/old.txt", result["diff"])


# ---------------------------------------------------------------------------------------------------------------------
class UnstagedDiffParityTests(WorldCase):
    """The diff keeps Git's unstaged-diff semantics: for ordinary changes it is the very text ``git diff`` prints.

    Both Gits of this host are used as the writer of the repository and as the observer, so a format or behavior
    difference between Apple Git and Homebrew Git cannot hide behind the one that happened to be first on a PATH.
    """

    FILES = {
        "src/app.py": "value = 1\n", "docs/old.txt": "one\ntwo\nthree\n", "bin/tool.sh": "#!/bin/sh\necho tool\n",
        "data/blob.bin": "binary\x00payload\x01one", "name with space.txt": "space\n",
        "\u00fcn\u00ef/caf\u00e9.txt": "unicode\n", "empty.txt": "", "crlf.txt": "a\r\nb\r\n", "noeol.txt": "no newline",
        "big/lines.txt": "".join(f"row {index}\n" for index in range(300)),
    }

    def mutations(self) -> dict[str, Callable[[Path], None]]:
        def modify(repo: Path) -> None:
            (repo / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")

        def delete(repo: Path) -> None:
            (repo / "docs" / "old.txt").unlink()

        def chmod(repo: Path) -> None:
            (repo / "bin" / "tool.sh").chmod(0o644)

        def binary(repo: Path) -> None:
            (repo / "data" / "blob.bin").write_bytes(b"binary\x00payload\x01two")

        def names(repo: Path) -> None:
            (repo / "name with space.txt").write_text("space changed\n", encoding="utf-8")
            (repo / "\u00fcn\u00ef" / "caf\u00e9.txt").write_text("unicode changed\n", encoding="utf-8")

        def fill_empty(repo: Path) -> None:
            (repo / "empty.txt").write_text("now not empty\n", encoding="utf-8")

        def endings(repo: Path) -> None:
            (repo / "crlf.txt").write_bytes(b"a\r\nB\r\n")
            (repo / "noeol.txt").write_text("no newline\n", encoding="utf-8")

        def far_apart(repo: Path) -> None:
            lines = (repo / "big" / "lines.txt").read_text(encoding="utf-8").splitlines(keepends=True)
            lines[3], lines[250] = "row three!\n", "row 250!\n"
            (repo / "big" / "lines.txt").write_text("".join(lines), encoding="utf-8")

        def typechange(repo: Path) -> None:
            (repo / "docs" / "old.txt").unlink()
            os.symlink("../src/app.py", repo / "docs" / "old.txt")

        def several(repo: Path) -> None:
            modify(repo)
            delete(repo)
            chmod(repo)
            names(repo)

        return {
            "modify": modify, "delete": delete, "chmod": chmod, "binary": binary, "names": names,
            "fill_empty": fill_empty, "endings": endings, "far_apart": far_apart, "typechange": typechange,
            "several": several, "nothing": lambda repo: None,
        }

    def check_parity(self, writer: str, observer: str) -> None:
        for label, mutate in self.mutations().items():
            with self.subTest(writer=writer, observer=observer, change=label):
                repo = make_repo(
                    self.base / f"parity-{label}-{GIT_EXECUTABLES.index(writer)}-{GIT_EXECUTABLES.index(observer)}",
                    self.FILES, executable=writer,
                )
                mutate(repo)
                expected = run_git(repo, *PLAIN_DIFF, executable=observer).stdout
                with self.use_git(observer):
                    result = ReadOnlyGit(str(repo)).diff()
                self.assertEqual(result["diff"], expected)

    def test_the_diff_is_what_git_prints_for_each_installed_git(self) -> None:
        self.assertTrue(GIT_EXECUTABLES, "no usable git in this environment")
        for executable in GIT_EXECUTABLES:
            self.check_parity(executable, executable)

    @needs_two_gits
    def test_a_repository_written_by_one_git_is_observed_identically_by_the_other(self) -> None:
        first, second = GIT_EXECUTABLES[:2]
        self.check_parity(first, second)
        self.check_parity(second, first)

    def test_an_ordinary_change_is_a_complete_diff(self) -> None:
        for label in ("modify", "delete", "chmod", "binary", "names", "endings", "typechange"):
            with self.subTest(change=label):
                repo = make_repo(self.base / f"complete-{label}", self.FILES)
                self.mutations()[label](repo)
                result = ReadOnlyGit(str(repo)).diff()
                self.assertTrue(result["complete"], result["omitted"])
                self.assertEqual(result["omitted"], {"count": 0, "reasons": {}, "paths": []})

    @needs_two_gits
    def test_the_boundary_holds_for_each_git(self) -> None:
        for executable in GIT_EXECUTABLES:
            with self.subTest(git=executable):
                repo = make_repo(
                    self.base / f"boundary-{GIT_EXECUTABLES.index(executable)}", BASE_FILES, executable=executable,
                )
                os.unlink(repo / "notes.txt")
                os.link(repo / ".secrets.env", repo / "notes.txt")
                (repo / ".secrets.env").write_text(f"TOKEN={SECRET}\n", encoding="utf-8")
                os.mkfifo(repo / "bin" / "pipe")  # untracked: never in the listing, never opened
                (repo / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")
                with self.use_git(executable):
                    result = ReadOnlyGit(str(repo)).diff()
                self.assertNotIn(SECRET, json.dumps(result))
                self.assertIn("+value = 2", result["diff"])
                self.assertEqual(result["omitted"]["reasons"], {"hard_link": 1, "refused_name": 1})


# ---------------------------------------------------------------------------------------------------------------------
def operations(observed: ReadOnlyGit):
    """Every observation ``ReadOnlyGit`` offers, by name."""
    yield "status", observed.status
    yield "diff", observed.diff
    yield "diff-path", lambda: observed.diff("src/app.py")
    yield "log", observed.log
    yield "worktrees", observed.worktree_list
    yield "is_tracked", lambda: observed.is_tracked("src/app.py")


class ExecutionEntryPointTests(WorldCase):
    """R3-05: no configuration entry point of the observed repository starts a program, for ANY observation.

    Each case declares one entry point in a repository the way a hostile repository would, proves with each installed
    Git that the oracle is live (the program runs for a plain Git command), and then runs every ``ReadOnlyGit``
    operation with that same Git.
    """

    ticks = 0

    def dirty(self) -> None:
        """Make the work tree differ from the index in a way that gives Git something to refresh (and so to write).

        The mtime is different on every call: setting the same one again would leave a file that a previous refresh
        already made consistent, and the control would then prove nothing.
        """
        type(self).ticks += 1
        (self.repo / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")
        stamp = 1_000_000_000 + self.ticks
        os.utime(self.repo / "docs" / "old.txt", (stamp, stamp))

    def hold(self, label: str, configure, control, *, body: str = "exit 0") -> None:
        """``control(git)`` runs the entry point's own trigger with the named Git."""
        script, marker = self.script(label, body=body)
        configure(script)
        for executable in GIT_EXECUTABLES:
            self.dirty()
            marker.unlink(missing_ok=True)
            control(executable)
            self.assertTrue(marker.exists(), f"control: {label} must run for plain {executable}, or the oracle proves nothing")
            marker.unlink()
            with self.use_git(executable):
                observed = self.observe()
                for name, operation in operations(observed):
                    self.dirty()
                    with self.subTest(entry_point=label, git=executable, operation=name):
                        operation()
                        ran = marker.exists()
                        marker.unlink(missing_ok=True)  # one operation's failure must not be blamed on the next
                        self.assertFalse(ran, f"{label}: a program the repository declared ran during {name}")

    def test_fsmonitor_hook(self) -> None:
        self.hold("fsmonitor", lambda script: run_git(self.repo, "config", "core.fsmonitor", str(script)),
                  lambda git: run_git(self.repo, "status", "--short", executable=git))

    def test_hooks_path_post_index_change(self) -> None:
        def configure(script: Path) -> None:
            hooks = self.base / "hooks"
            hooks.mkdir()
            (hooks / "post-index-change").write_bytes(script.read_bytes())
            (hooks / "post-index-change").chmod(0o755)
            run_git(self.repo, "config", "core.hooksPath", str(hooks))

        self.hold("hookspath", configure, lambda git: run_git(self.repo, "status", "--short", executable=git))

    def test_diff_driver_command_selected_by_attributes(self) -> None:
        def configure(script: Path) -> None:
            (self.repo / ".gitattributes").write_text("*.py diff=probe\n", encoding="utf-8")
            run_git(self.repo, "config", "diff.probe.command", str(script))

        self.hold("diffcommand", configure, lambda git: run_git(self.repo, "diff", executable=git))

    def test_textconv_selected_by_attributes(self) -> None:
        def configure(script: Path) -> None:
            (self.repo / ".gitattributes").write_text("*.py diff=probe\n", encoding="utf-8")
            run_git(self.repo, "config", "diff.probe.textconv", str(script))

        self.hold("textconv", configure, lambda git: run_git(self.repo, "diff", "--no-ext-diff", executable=git),
                  body='cat "$1"')

    def test_filter_driver_declared_in_an_included_file(self) -> None:
        def configure(script: Path) -> None:
            (self.repo / "included.cfg").write_text(f'[filter "probe"]\n\tclean = {script}\n', encoding="utf-8")
            run_git(self.repo, "config", "include.path", "../included.cfg")
            (self.repo / ".git" / "info" / "attributes").write_text("*.py filter=probe\n", encoding="utf-8")

        self.hold("includedfilter", configure, lambda git: run_git(self.repo, "status", "--short", executable=git),
                  body="cat")

    def test_fsmonitor_set_by_an_included_file(self) -> None:
        def configure(script: Path) -> None:
            (self.repo / "included.cfg").write_text(f"[core]\n\tfsmonitor = {script}\n", encoding="utf-8")
            run_git(self.repo, "config", "include.path", "../included.cfg")

        self.hold("includedfsmonitor", configure, lambda git: run_git(self.repo, "status", "--short", executable=git))

    def test_conditional_include_by_gitdir(self) -> None:
        def configure(script: Path) -> None:
            (self.repo / "cond.cfg").write_text(f"[core]\n\tfsmonitor = {script}\n", encoding="utf-8")
            run_git(self.repo, "config", f"includeIf.gitdir:{self.repo}/.git.path", "../cond.cfg")

        self.hold("condinclude", configure, lambda git: run_git(self.repo, "status", "--short", executable=git))

    def test_fsmonitor_set_in_the_per_worktree_config(self) -> None:
        def configure(script: Path) -> None:
            run_git(self.repo, "config", "extensions.worktreeConfig", "true")
            (self.repo / ".git" / "config.worktree").write_text(f"[core]\n\tfsmonitor = {script}\n", encoding="utf-8")

        self.hold("worktreeconfig", configure, lambda git: run_git(self.repo, "status", "--short", executable=git))

    def test_gpg_program_for_signed_commits_in_the_log(self) -> None:
        def configure(script: Path) -> None:
            commit = run_git(self.repo, "cat-file", "commit", "HEAD").stdout
            head, message = commit.split("\n\n", 1)
            signed = f"{head}\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n fictional\n -----END PGP SIGNATURE-----\n\n{message}"
            oid = run_git(self.repo, "hash-object", "-t", "commit", "-w", "--stdin", stdin=signed.encode()).stdout.strip()
            run_git(self.repo, "update-ref", "HEAD", oid)
            run_git(self.repo, "config", "gpg.program", str(script))
            run_git(self.repo, "config", "log.showSignature", "true")

        self.hold("gpgprogram", configure, lambda git: run_git(self.repo, "log", "-1", check=False, executable=git))


# ---------------------------------------------------------------------------------------------------------------------
class ReadOnlyInvariantTests(WorldCase):
    """An observation never writes the repository it observes.

    r2's ``git diff`` refreshed and rewrote the index of a work tree that had a stat-dirty file; that write is also how
    a repository's ``post-index-change`` hook got started (``ExecutionEntryPointTests.test_hooks_path_...``). The
    invariant is stated on the bytes of ``.git`` itself, so it does not depend on which hook or entry point is declared.
    """

    def git_directory_state(self) -> dict[str, tuple[int, int, str]]:
        state: dict[str, tuple[int, int, str]] = {}
        for path in sorted((self.repo / ".git").rglob("*")):
            if path.is_file():
                info = path.stat()
                state[str(path.relative_to(self.repo))] = (
                    info.st_size, info.st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest(),
                )
        return state

    def test_no_operation_writes_the_repository(self) -> None:
        (self.repo / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")
        os.utime(self.repo / "docs" / "old.txt", (1_000_000_000, 1_000_000_000))  # stat-dirty: Git has an index to refresh
        control_before = self.git_directory_state()
        run_git(self.repo, "status", "--short")
        self.assertNotEqual(self.git_directory_state(), control_before, "control: a plain git status does rewrite the index")
        os.utime(self.repo / "docs" / "old.txt", (1_000_000_001, 1_000_000_001))
        observed = self.observe()
        for name, operation in operations(observed):
            with self.subTest(operation=name):
                before = self.git_directory_state()
                operation()
                self.assertEqual(self.git_directory_state(), before, f"{name} wrote to the repository it observes")


# ---------------------------------------------------------------------------------------------------------------------
@unittest.skipUnless(MCP_AVAILABLE, "the MCP SDK is an optional extra")
class ProtocolTests(unittest.TestCase):
    """What a client sees over a real MCP session: refusals are answers, never failures, and say what they omit."""

    def setUp(self) -> None:
        self.world = ProtocolWorld()
        self.addCleanup(self.world.cleanup)
        repo = self.world.repo
        os.unlink(repo / "notes.txt")
        (repo / ".secrets.env").write_text(f"TOKEN={SECRET}\n", encoding="utf-8")
        os.link(repo / ".secrets.env", repo / "notes.txt")
        (repo / "src" / "app.py").write_text("def main():\n    return 'edited'\n", encoding="utf-8")

    def call(self, name: str, **arguments):
        return run(call_protocol(self.world.server(), name, **arguments))

    def test_a_whole_repository_diff_over_the_protocol_carries_no_refused_body_and_says_what_it_omits(self) -> None:
        is_error, text = self.call("uam_git_diff", workspace_id=STATIC_ID)
        self.assertFalse(is_error)
        self.assertNotIn(SECRET, text)
        answer = decode(text)
        self.assertIn("+    return 'edited'", answer["diff"])
        self.assertFalse(answer["complete"])
        self.assertEqual(answer["omitted"]["reasons"].get("hard_link"), 1)

    def test_an_explicit_refused_name_is_an_error_answer_without_the_body(self) -> None:
        is_error, text = self.call("uam_git_diff", workspace_id=STATIC_ID, path=".secrets.env")
        self.assertNotIn(SECRET, text)
        self.assertTrue(is_error or "error" in decode(text))

    def test_a_hard_link_named_explicitly_is_an_answer_that_omits_it(self) -> None:
        is_error, text = self.call("uam_git_diff", workspace_id=STATIC_ID, path="notes.txt")
        self.assertFalse(is_error)
        self.assertNotIn(SECRET, text)
        self.assertEqual(decode(text)["omitted"]["reasons"], {"hard_link": 1})

    def test_the_status_over_the_protocol_names_no_refused_file(self) -> None:
        is_error, text = self.call("uam_git_status", workspace_id=STATIC_ID)
        self.assertFalse(is_error)
        self.assertNotIn(".secrets.env", text)
        self.assertNotIn(SECRET, text)


if __name__ == "__main__":
    unittest.main()
