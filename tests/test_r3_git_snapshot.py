"""R3-02: the mechanism behind ``ReadOnlyGit.diff`` -- ``git_snapshot`` and the budgets of ``DiffBudgets``.

These tests have no r2 counterpart (r2 has no ``git_snapshot``): they pin the properties the boundary tests in
``test_r3_git_boundary`` rely on -- that Git is never asked to read the work tree for ``diff``, that a path is judged
before anything is stat-ed or opened, that what is opened is held by descriptor and checked on the object it names,
and that a crafted index cannot make the private copy write outside itself.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from universal_agent_middleware import git_readonly, git_snapshot
from universal_agent_middleware.errors import WorkspaceError
from universal_agent_middleware.git_snapshot import (
    DiffBudgets, IndexEntry, _same_as_index, build_unstaged_diff, parse_index_listing,
)
from universal_agent_middleware.path_authority import PathPolicy

from r3_git_support import OUTSIDE, SECRET, WorldCase, reasons_of, run_git


class SnapshotMechanismTests(WorldCase):
    def test_git_is_never_asked_to_diff_the_work_tree(self) -> None:
        (self.repo / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")
        seen: list[tuple[list[str], str]] = []
        real_run = subprocess.run

        def recording(command, *args, **kwargs):
            seen.append((list(command), str(kwargs.get("cwd") or "")))
            return real_run(command, *args, **kwargs)

        with mock.patch.object(git_readonly.subprocess, "run", recording), \
                mock.patch.object(git_snapshot.subprocess, "run", recording):
            result = self.observe().diff()
        self.assertIn("+value = 2", result["diff"])
        diffs = [(command, cwd) for command, cwd in seen if "diff" in command]
        self.assertEqual(len(diffs), 1)
        command, cwd = diffs[0]
        self.assertNotEqual(Path(cwd).resolve(), self.repo, "git diff ran inside the observed repository")
        self.assertNotIn(str(self.repo), command)
        for command, cwd in seen:  # and what does run against the repository only lists the index or asks rev-parse
            if str(self.repo) in command:
                self.assertTrue({"ls-files", "rev-parse"} & set(command), command)

    def test_a_path_that_cannot_have_changed_is_never_read(self) -> None:
        for index in range(30):
            (self.repo / "bulk").mkdir(exist_ok=True)
            (self.repo / "bulk" / f"f{index}.txt").write_text(f"bulk {index}\n", encoding="utf-8")
        run_git(self.repo, "add", "-A")
        run_git(self.repo, "commit", "-qm", "bulk")
        # Files made a moment ago are racily clean (Git records them with a size of 0 so that it compares content);
        # old files with refreshed stat data are what a long-lived work tree is made of.
        for name in self.repo.rglob("*"):
            if name.is_file() and ".git" not in name.relative_to(self.repo).parts:
                os.utime(name, (1_000_000_000, 1_000_000_000))
        run_git(self.repo, "update-index", "--really-refresh")
        (self.repo / "bulk" / "f7.txt").write_text("bulk 7 but edited\n", encoding="utf-8")
        read: list[tuple[str, ...]] = []
        real = git_snapshot.StrictWalker.observe

        def recording(walker, parts, *, limit):
            read.append(parts)
            return real(walker, parts, limit=limit)

        with mock.patch.object(git_snapshot.StrictWalker, "observe", recording):
            result = self.observe().diff()
        self.assertEqual(read, [("bulk", "f7.txt")])
        self.assertIn("+bulk 7 but edited", result["diff"])

    def test_a_touched_but_unchanged_file_is_read_and_adds_nothing(self) -> None:
        os.utime(self.repo / "src" / "app.py", (1_000_000_000, 1_000_000_000))
        result = self.observe().diff()
        self.assertEqual(result["diff"], "")
        self.assertEqual(reasons_of(result), {})

    def test_a_racily_clean_entry_is_compared_by_content(self) -> None:
        entry = IndexEntry(mode=0o100644, oid="0" * 40, stage=0, path="a", ctime=(10, 0), mtime=(10, 5), dev=1, ino=2,
                           uid=3, gid=4, size=7, flags=0)
        info = mock.Mock(st_mode=0o100644, st_size=7, st_mtime_ns=10_000_000_005, st_ctime_ns=10_000_000_000,
                         st_ino=2, st_dev=1, st_uid=3, st_gid=4)
        self.assertTrue(_same_as_index(entry, info, 11_000_000_000), "control: older than the index, all equal")
        self.assertFalse(_same_as_index(entry, info, 10_000_000_005), "as new as the index: racy")
        self.assertFalse(_same_as_index(entry, info, 10_000_000_000), "newer than the index: racy")
        self.assertFalse(_same_as_index(entry, info, None), "no index time: unknown")

    def test_a_path_swapped_for_a_link_between_the_stat_and_the_open_is_never_followed(self) -> None:
        (self.repo / ".secrets.env").write_text(f"TOKEN={SECRET}\n", encoding="utf-8")
        (self.repo / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")
        real = git_snapshot.open_child

        def swap_then_open(name, directory_fd, *, directory):
            if name == "app.py" and not directory:
                os.unlink(self.repo / "src" / "app.py")
                os.symlink("../.secrets.env", self.repo / "src" / "app.py")
            return real(name, directory_fd, directory=directory)

        with mock.patch.object(git_snapshot, "open_child", swap_then_open):
            result = self.observe().diff()
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(reasons_of(result), {"changed_during_read": 1})

    def test_a_path_swapped_for_a_hard_link_between_the_stat_and_the_open_is_refused_by_the_held_object(self) -> None:
        (self.repo / ".secrets.env").write_text(f"TOKEN={SECRET}\n", encoding="utf-8")
        (self.repo / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")
        real = git_snapshot.open_child

        def swap_then_open(name, directory_fd, *, directory):
            if name == "app.py" and not directory:
                os.unlink(self.repo / "src" / "app.py")
                os.link(self.repo / ".secrets.env", self.repo / "src" / "app.py")
            return real(name, directory_fd, directory=directory)

        with mock.patch.object(git_snapshot, "open_child", swap_then_open):
            result = self.observe().diff()
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(sum(reasons_of(result).values()), 1)

    def test_a_path_swapped_for_a_pipe_between_the_stat_and_the_open_does_not_block(self) -> None:
        (self.repo / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")
        real = git_snapshot.open_child

        def swap_then_open(name, directory_fd, *, directory):
            if name == "app.py" and not directory:
                os.unlink(self.repo / "src" / "app.py")
                os.mkfifo(self.repo / "src" / "app.py")
            return real(name, directory_fd, directory=directory)

        with mock.patch.object(git_snapshot, "open_child", swap_then_open):
            result = self.observe().diff()
        self.assertEqual(reasons_of(result), {"changed_during_read": 1})

    def test_an_entry_with_a_refused_name_is_neither_stat_ed_nor_opened(self) -> None:
        (self.repo / ".secrets.env").write_text(f"TOKEN={SECRET}\n", encoding="utf-8")
        touched: list[tuple[str, ...]] = []
        real_lstat, real_observe = git_snapshot.StrictWalker.lstat, git_snapshot.StrictWalker.observe

        def lstat(walker, parts):
            touched.append(parts)
            return real_lstat(walker, parts)

        def observe(walker, parts, *, limit):
            touched.append(parts)
            return real_observe(walker, parts, limit=limit)

        with mock.patch.object(git_snapshot.StrictWalker, "lstat", lstat), \
                mock.patch.object(git_snapshot.StrictWalker, "observe", observe):
            result = self.observe().diff()
        self.assertNotIn((".secrets.env",), touched)
        self.assertEqual(result["omitted"]["reasons"], {"refused_name": 1})
        self.assertEqual(result["omitted"]["paths"], [], "a refused name is a count, never a name")

    def listing_of(self, entries: list[tuple[int, str]]) -> bytes:
        """A listing in the format of ``git ls-files -s -z --debug`` for entries Git itself would refuse to create."""
        debug = b"  ctime: 0:0\n  mtime: 0:0\n  dev: 0\tino: 0\n  uid: 0\tgid: 0\n  size: 0\tflags: 0\n"
        blob = run_git(self.repo, "hash-object", "-w", "--stdin", stdin=b"payload\n").stdout.strip()
        return b"".join(f"{mode:o} {blob} 0\t".encode() + os.fsencode(path) + b"\0" + debug for mode, path in entries)

    def build(self, listing: bytes):
        return build_unstaged_diff(
            root=self.repo, listing=listing, index_mtime_ns=None, git_command=["git"],
            environment=dict(git_readonly._HERMETIC_ENV), objects_dir=self.repo / ".git" / "objects",
            object_format="sha1", policy=PathPolicy.unrestricted(), budgets=DiffBudgets(),
        )

    def test_a_crafted_index_cannot_make_the_private_copy_write_outside_itself(self) -> None:
        """A link entry followed by a path below it, a parent reference and a ``.git`` entry (Git refuses to create
        these; a crafted index file can still list them, and the repository is untrusted input)."""
        victim = self.base / "victim"
        victim.mkdir()
        os.symlink(str(victim), self.repo / "evil")
        built = self.build(self.listing_of([
            (0o120000, "evil"), (0o100644, "evil/file.txt"), (0o100644, "../victim/pwned.txt"),
            (0o100644, "sub/.git/config"), (0o100644, "sub/.GIT/hooks"), (0o100644, "ok.txt"),
        ]))
        self.assertEqual(list(victim.iterdir()), [], "nothing was written through a link or a parent reference")
        self.assertNotIn("pwned", built.text)
        self.assertEqual(dict(built.omissions.reasons), {
            "unsafe_path": 1,  # the parent reference
            "refused_name": 2,  # both spellings of ``.git`` are refused names: decided before any open
            "path_replaced": 1,  # a path below a link: the link is never followed
        })
        self.assertIn("evil/file.txt", built.omissions.paths)

    def test_two_entries_the_filesystem_cannot_tell_apart_are_reported_not_merged(self) -> None:
        (self.repo / "Case.txt").write_text("one\n", encoding="utf-8")
        built = self.build(self.listing_of([(0o100644, "Case.txt"), (0o100644, "case.txt")]))
        folded = (self.repo / "case.txt").exists()  # case-insensitive volume: the same file under both names
        self.assertEqual(built.omissions.reasons.get("path_collision", 0), 1 if folded else 0)

    def test_the_private_copy_is_removed_afterwards(self) -> None:
        (self.repo / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")
        scratch_root = self.base / "scratch"
        scratch_root.mkdir()
        with mock.patch.object(tempfile, "tempdir", str(scratch_root)):
            self.observe().diff()
        self.assertEqual(list(scratch_root.iterdir()), [])

    def test_unmerged_paths_are_reported_not_diffed(self) -> None:
        run_git(self.repo, "checkout", "-qb", "side")
        (self.repo / "notes.txt").write_text("side change\n", encoding="utf-8")
        run_git(self.repo, "commit", "-qam", "side")
        run_git(self.repo, "checkout", "-q", "-")
        (self.repo / "notes.txt").write_text("main change\n", encoding="utf-8")
        run_git(self.repo, "commit", "-qam", "main")
        run_git(self.repo, "merge", "side", check=False)
        result = self.observe().diff()
        self.assertEqual(reasons_of(result), {"unmerged": 1})

    def test_assume_unchanged_and_skip_worktree_paths_are_left_out_as_git_does(self) -> None:
        (self.repo / "notes.txt").write_text("hidden change\n", encoding="utf-8")
        (self.repo / "docs" / "old.txt").write_text("hidden too\n", encoding="utf-8")
        run_git(self.repo, "update-index", "--assume-unchanged", "notes.txt")
        run_git(self.repo, "update-index", "--skip-worktree", "docs/old.txt")
        plain = ("diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--no-color", "--ignore-submodules=all")
        self.assertEqual(run_git(self.repo, *plain).stdout, "", "control: Git shows neither")
        self.assertEqual(self.observe().diff()["diff"], "")

    def test_an_unusable_git_executable_is_refused(self) -> None:
        for value in ("relative/git", "/no/such/git", OUTSIDE):
            with self.subTest(executable=value):
                with self.assertRaises(WorkspaceError):
                    self.observe(git_executable=value)


class ListingParserTests(unittest.TestCase):
    def test_a_listing_that_does_not_parse_is_an_error(self) -> None:
        for raw in (b"garbage", b"100644 abc 0\tpath\0", b"100644 " + b"a" * 40 + b" 0\tp\0  ctime: 1:2\n"):
            with self.subTest(raw=raw[:30]):
                with self.assertRaises(WorkspaceError):
                    parse_index_listing(raw)

    def test_an_empty_listing_is_no_entries(self) -> None:
        self.assertEqual(parse_index_listing(b""), [])


class BudgetTests(WorldCase):
    def test_paths_beyond_the_candidate_budget_are_reported_not_dropped(self) -> None:
        for index in range(5):
            (self.repo / "bulk").mkdir(exist_ok=True)
            (self.repo / "bulk" / f"f{index}.txt").write_text(f"{index}\n", encoding="utf-8")
        run_git(self.repo, "add", "-A")
        run_git(self.repo, "commit", "-qm", "bulk")
        for index in range(5):
            (self.repo / "bulk" / f"f{index}.txt").write_text(f"{index} changed\n", encoding="utf-8")
        result = self.observe(budgets=DiffBudgets(max_candidates=2)).diff()
        self.assertEqual(result["diff"].count("diff --git"), 2)
        self.assertEqual(reasons_of(result), {"over_budget": 3})
        self.assertEqual(len(result["omitted"]["paths"]), 3)
        self.assertFalse(result["complete"])

    def test_a_file_over_the_file_budget_is_reported(self) -> None:
        (self.repo / "src" / "app.py").write_text("x" * 5000, encoding="utf-8")
        result = self.observe(budgets=DiffBudgets(max_file_bytes=1000)).diff()
        self.assertEqual(reasons_of(result), {"over_budget": 1})
        self.assertEqual(result["diff"], "")

    def test_the_total_budget_stops_further_reads(self) -> None:
        (self.repo / "src" / "app.py").write_text("a" * 600, encoding="utf-8")
        (self.repo / "docs" / "old.txt").write_text("b" * 600, encoding="utf-8")
        result = self.observe(budgets=DiffBudgets(max_file_bytes=1000, max_total_bytes=800)).diff()
        self.assertEqual(reasons_of(result), {"over_budget": 1})
        self.assertEqual(result["diff"].count("diff --git"), 1)

    def test_a_diff_longer_than_the_output_limit_says_so(self) -> None:
        (self.repo / "src" / "app.py").write_text("".join(f"line {index}\n" for index in range(40_000)), encoding="utf-8")
        result = self.observe().diff()
        self.assertTrue(result["truncated"])
        self.assertFalse(result["complete"])
        self.assertEqual(len(result["diff"]), git_readonly.MAX_DIFF_CHARS)

    def test_an_index_with_too_many_paths_is_refused_not_judged_in_part(self) -> None:
        with self.assertRaisesRegex(WorkspaceError, "too many paths"):
            self.observe(budgets=DiffBudgets(max_entries=2)).diff()


if __name__ == "__main__":
    unittest.main()
