"""The authorised walk keeps every filter the ripgrep command line used to carry, and stops cleanly.

The scope search enumerates the tree itself (see ``scope_search``), so depth, hidden entries, ignore
files, excluded and system directories, symlinks, binary files and the secret firewall are enforced
by that walk and not by ripgrep flags. These tests pin each of them on its own, compare the ignore
semantics with what ripgrep itself would list for the same tree, and show that every resource budget
and every deadline ends a search as *explicitly incomplete* without ever widening it.

"Searched" means "the object behind this name was handed to ripgrep as an open descriptor".
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

from scope_search_instruments import (
    DESCRIPTOR_OPERAND,
    AtimeSentinel,
    OpenSpy,
    RunRecord,
    ScriptedRipgrep,
    completed,
    handed_relative_paths,
    identity_of,
)

from universal_agent_middleware import scope_search
from universal_agent_middleware.discovery import DiscoveryEngine
from universal_agent_middleware.path_authority import PathPolicy
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry
from universal_agent_middleware.scope_search import (
    EXCLUDED_DIRECTORY_NAMES,
    MAX_DEPTH,
    ScopeSearchLimits,
    TreeSearch,
    find_ripgrep,
    search_tree,
)

FIND_RIPGREP = "universal_agent_middleware.discovery.find_ripgrep"
SCOPE = "walk"


class WalkCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="uam-scope-walk-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(os.path.realpath(tmp.name))

    def write(self, relative: str, text: str | bytes = "needle\n") -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text, encoding="utf-8")
        return path

    def walk(
        self, *, policy: PathPolicy | None = None, limits: ScopeSearchLimits | None = None,
        reply: Any = None, max_results: int = 500, root: Path | None = None,
    ) -> tuple[TreeSearch, ScriptedRipgrep]:
        ripgrep = ScriptedRipgrep(reply or (lambda call: completed(b"", 1)))
        kwargs: dict[str, Any] = {} if limits is None else {"limits": limits}
        with ripgrep.patch():
            tree = search_tree(
                root or self.root, "needle", executable="/usr/bin/rg",
                policy=policy or PathPolicy.unrestricted(), max_results=max_results, **kwargs,
            )
        return tree, ripgrep

    def searched(self, ripgrep: ScriptedRipgrep) -> set[str]:
        return handed_relative_paths(ripgrep, self.root)

    def registry(self, *denied: str) -> RootScopeRegistry:
        registry = RootScopeRegistry()
        registry.add_scope(RootScope(scope_id=SCOPE, root=str(self.root), authority=RootScopeAuthority(text_search=True)))
        for relative in denied:
            registry.add_scope(RootScope(
                scope_id=f"deny:{relative}", root=str(self.root / relative), authority=RootScopeAuthority(),
            ))
        return registry

    def policy_denying(self, *relative: str) -> PathPolicy:
        return PathPolicy.beneath(self.registry(*relative), self.root)

    def engine(self, limits: ScopeSearchLimits, *denied: str) -> DiscoveryEngine:
        return DiscoveryEngine(self.registry(*denied), search_limits=limits)

    def search(
        self, limits: ScopeSearchLimits, reply: Any = None, *, denied: tuple[str, ...] = (),
    ) -> tuple[dict[str, Any], ScriptedRipgrep]:
        ripgrep = ScriptedRipgrep(reply or (lambda call: completed(b"", 1)))
        with mock.patch(FIND_RIPGREP, return_value="/usr/bin/rg"), ripgrep.patch():
            result = self.engine(limits, *denied).search_scope(SCOPE, "needle")
        return result, ripgrep


class WhatTheWalkSkipsTests(WalkCase):
    def test_depth_is_counted_from_the_search_root(self) -> None:
        self.write("a.txt")
        self.write("d1/d2/d3/d4/five.txt")
        self.write("d1/d2/d3/d4/d5/six.txt")
        _tree, ripgrep = self.walk()
        searched = self.searched(ripgrep)
        self.assertEqual(MAX_DEPTH, 5)
        self.assertEqual(searched, {"a.txt", "d1/d2/d3/d4/five.txt"})

    def test_hidden_files_and_directories_are_skipped(self) -> None:
        self.write("seen.txt")
        self.write(".hidden.txt")
        self.write(".config/inside.txt")
        self.write("sub/.dotfile")
        _tree, ripgrep = self.walk()
        self.assertEqual(self.searched(ripgrep), {"seen.txt"})

    def test_excluded_directory_names_are_skipped_at_every_depth(self) -> None:
        self.write("seen.txt")
        for name in EXCLUDED_DIRECTORY_NAMES:
            self.write(f"{name}/inside.txt")
            self.write(f"sub/{name}/inside.txt")
        _tree, ripgrep = self.walk()
        self.assertEqual(self.searched(ripgrep), {"seen.txt"})

    def test_system_directories_are_skipped_at_every_depth(self) -> None:
        self.write("seen.txt")
        for name in ("Library", "Applications", ".Trash", "Pictures", "Music", "Movies"):
            self.write(f"{name}/inside.txt")
            self.write(f"sub/{name}/inside.txt")
        _tree, ripgrep = self.walk()
        self.assertEqual(self.searched(ripgrep), {"seen.txt"})

    def test_secret_firewall_paths_are_skipped(self) -> None:
        self.write("seen.txt")
        for rel in (".env", ".env.local", "id_rsa", "id_ed25519", "credentials", "credentials.json",
                    "secrets.json", "server.pem", "bundle.p12", "cert.pfx", "private.key", "store.keystore",
                    ".npmrc", ".pypirc", ".netrc", "creds/credentials/token.txt", ".ssh/config", ".aws/credentials",
                    ".gnupg/key", ".kube/config", ".docker/config.json"):
            self.write(rel)
        _tree, ripgrep = self.walk()
        self.assertEqual(self.searched(ripgrep), {"seen.txt"})

    def test_symlinks_are_never_followed_or_handed_over(self) -> None:
        real = self.write("real/target.txt")
        (self.root / "link-file.txt").symlink_to(real)
        (self.root / "link-dir").symlink_to(self.root / "real", target_is_directory=True)
        (self.root / "dangling").symlink_to(self.root / "does-not-exist")
        _tree, ripgrep = self.walk()
        self.assertEqual(self.searched(ripgrep), {"real/target.txt"})

    def test_a_fifo_is_neither_opened_nor_waited_for(self) -> None:
        self.write("seen.txt")
        os.mkfifo(self.root / "pipe")
        started = time.monotonic()
        tree, ripgrep = self.walk()
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(self.searched(ripgrep), {"seen.txt"})
        self.assertFalse(tree.timed_out)

    def test_binary_empty_and_late_nul_files(self) -> None:
        self.write("text.txt")
        self.write("binary.dat", b"needle\0\1\2\3")
        self.write("empty.txt", "")
        self.write("utf16.txt", b"\xff\xfe" + "needle\n".encode("utf-16-le"))
        self.write("late_nul.txt", b"x" * 70_000 + b"needle\0tail")
        _tree, ripgrep = self.walk()
        searched = self.searched(ripgrep)
        self.assertIn("text.txt", searched)
        self.assertIn("utf16.txt", searched, "a UTF-16 file with a BOM is text, not binary")
        self.assertNotIn("binary.dat", searched)
        self.assertNotIn("empty.txt", searched)
        # Documented approximation: only the first 64 KiB is probed, so a NUL after that is not seen.
        self.assertIn("late_nul.txt", searched)

    def test_a_file_the_process_may_not_read_is_skipped_and_declared_not_fatal(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root can read a mode-000 file")
        locked = self.write("locked.txt")
        self.write("seen.txt")
        locked.chmod(0o000)
        self.addCleanup(locked.chmod, 0o644)
        tree, ripgrep = self.walk()
        self.assertEqual(self.searched(ripgrep), {"seen.txt"})
        self.assertEqual(tree.skipped_unreadable, 1)
        self.assertEqual((tree.changed, tree.other_errors), (0, 0))

    def test_a_directory_the_process_may_not_enter_is_skipped_and_declared_not_fatal(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root can enter a mode-000 directory")
        self.write("locked/inside.txt")
        self.write("seen.txt")
        (self.root / "locked").chmod(0o000)
        self.addCleanup((self.root / "locked").chmod, 0o755)
        tree, ripgrep = self.walk()
        self.assertEqual(self.searched(ripgrep), {"seen.txt"})
        self.assertGreaterEqual(tree.skipped_unreadable, 1)

    def test_a_scope_root_that_is_a_symlink_is_resolved_once_and_searched(self) -> None:
        self.write("real/seen.txt")
        link = self.root / "scope-link"
        link.symlink_to(self.root / "real", target_is_directory=True)
        tree, ripgrep = self.walk(root=link)
        self.assertEqual(tree.hits, [])
        self.assertEqual(handed_relative_paths(ripgrep, self.root / "real"), {"seen.txt"})

    def test_a_secret_scope_root_is_not_searched_at_all(self) -> None:
        self.write(".ssh/config")
        tree, ripgrep = self.walk(root=self.root / ".ssh")
        self.assertEqual(ripgrep.ripgrep_calls, [])
        self.assertEqual(tree.hits, [])

    def test_hits_come_back_in_enumeration_order_and_are_bounded_by_max_results(self) -> None:
        for name in ("c.txt", "a.txt", "b.txt", "d/e.txt"):
            self.write(name)

        def reply(call: RunRecord) -> subprocess.CompletedProcess[Any]:
            names = ("c.txt", "a.txt", "b.txt", "d/e.txt")
            return completed(b"".join(call.operand_for(self.root / n).encode() + b"\n" for n in names), 0)

        tree, _ = self.walk(reply=reply, max_results=3)
        self.assertEqual(tree.hits, [("a.txt",), ("b.txt",), ("c.txt",)])
        self.assertTrue(tree.truncated)


class ReplacementBeforeTheOpenTests(WalkCase):
    """A name can change between the listing and the open; the open object is what is judged."""

    def swapping_open(self, name: str, swap: Any) -> Any:
        real_open = os.open
        state = {"done": False}

        def opener(path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
            if dir_fd is not None and path == name and not state["done"]:
                state["done"] = True
                swap()
            return real_open(path, flags, mode, dir_fd=dir_fd)

        return opener

    def test_a_file_swapped_for_a_symlink_after_it_was_listed_is_refused_not_followed(self) -> None:
        denied = self.write("denied/secret.txt")
        target = self.write("public/target.txt")
        self.write("public/control.txt")

        def swap() -> None:
            target.unlink()
            target.symlink_to(denied)

        with mock.patch.object(os, "open", self.swapping_open("target.txt", swap)):
            spy = OpenSpy()  # built inside the swap patch, so it wraps the swapping open
            with spy.patch():
                tree, ripgrep = self.walk(policy=self.policy_denying("denied"))
        self.assertNotIn(identity_of(denied), ripgrep.handed_identities)
        self.assertNotIn(identity_of(denied), spy.opened)
        self.assertEqual(tree.changed, 1, "the refused open must be reported, not silently dropped")
        self.assertIn("public/control.txt", self.searched(ripgrep))

    def test_a_file_swapped_for_another_object_after_it_was_listed_is_not_handed_over(self) -> None:
        denied = self.write("denied/secret.txt")
        target = self.write("public/target.txt")
        self.write("public/control.txt")

        def swap() -> None:
            target.unlink()
            os.link(denied, target)

        with mock.patch.object(os, "open", self.swapping_open("target.txt", swap)):
            tree, ripgrep = self.walk(policy=self.policy_denying("denied"))
        self.assertNotIn(identity_of(denied), ripgrep.handed_identities)
        self.assertEqual(tree.changed, 1)
        self.assertIn("public/control.txt", self.searched(ripgrep))

    def test_a_hard_link_added_after_the_file_was_listed_is_refused_at_the_open(self) -> None:
        # The same inode, listed and opened: only the link count of the *open* object can reveal that
        # a second name for these bytes appeared inside the denied scope in between.
        target = self.write("public/target.txt")
        self.write("public/control.txt")
        (self.root / "denied").mkdir()

        def swap() -> None:
            os.link(target, self.root / "denied" / "alias.txt")

        with mock.patch.object(os, "open", self.swapping_open("target.txt", swap)):
            tree, ripgrep = self.walk(policy=self.policy_denying("denied"))
        self.assertGreaterEqual(os.stat(target).st_nlink, 2, "the second name was not created: the test proves nothing")
        self.assertNotIn(identity_of(target), ripgrep.handed_identities)
        self.assertEqual(tree.refused_hard_links, 1)
        self.assertEqual(tree.changed, 0, "it is the object that was listed; what changed is its names")
        self.assertIn("public/control.txt", self.searched(ripgrep))

    def test_a_directory_swapped_for_a_symlink_after_it_was_listed_is_not_entered(self) -> None:
        denied = self.write("denied/secret.txt")
        self.write("public/sub/inside.txt")
        self.write("public/control.txt")

        def swap() -> None:
            (self.root / "public" / "sub" / "inside.txt").unlink()
            (self.root / "public" / "sub").rmdir()
            (self.root / "public" / "sub").symlink_to(self.root / "denied", target_is_directory=True)

        with mock.patch.object(os, "open", self.swapping_open("sub", swap)):
            spy = OpenSpy()  # built inside the swap patch, so it wraps the swapping open
            with spy.patch():
                tree, ripgrep = self.walk(policy=self.policy_denying("denied"))
        self.assertNotIn(identity_of(denied), ripgrep.handed_identities)
        self.assertNotIn(identity_of(self.root / "denied"), spy.listed)
        self.assertGreaterEqual(tree.changed, 1)


class IgnoreFilesAreHandledAsFilesTests(WalkCase):
    """An ignore file is read, so it is authorised, opened without following links and verified as a file."""

    def test_a_rule_that_cannot_be_applied_is_declared_and_the_other_rules_still_apply(self) -> None:
        self.write(".ignore", "a**b\n*.tmp\n")
        self.write("x.tmp")
        self.write("plain.txt")
        result, ripgrep = self.search(ScopeSearchLimits())
        self.assertIn("ignore_rules_not_applied", result["search_domain"]["not_covered"])
        self.assertEqual(self.searched(ripgrep), {"plain.txt"})

    def test_a_tree_whose_ignore_files_all_apply_does_not_declare_it(self) -> None:
        self.write(".ignore", "*.tmp\n")
        self.write("x.tmp")
        self.write("plain.txt")
        result, _ripgrep = self.search(ScopeSearchLimits())
        self.assertNotIn("ignore_rules_not_applied", result["search_domain"]["not_covered"])

    def test_an_oversized_ignore_file_is_not_applied_and_declared(self) -> None:
        self.write(".ignore", "*.tmp\n" + "# padding\n" * 120_000)
        self.write("x.tmp")
        result, ripgrep = self.search(ScopeSearchLimits())
        self.assertIn("ignore_rules_not_applied", result["search_domain"]["not_covered"])
        self.assertIn("x.tmp", self.searched(ripgrep))

    def test_a_symlinked_ignore_file_is_not_followed_and_declared(self) -> None:
        outside = self.write("elsewhere/rules.txt", "*.tmp\n")
        (self.root / "public").mkdir()
        (self.root / "public" / ".ignore").symlink_to(outside)
        self.write("public/x.tmp")
        result, ripgrep = self.search(ScopeSearchLimits())
        self.assertIn("ignore_rules_not_applied", result["search_domain"]["not_covered"])
        self.assertIn("public/x.tmp", self.searched(ripgrep))

    def test_an_unreadable_ignore_file_is_not_applied_and_declared(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root can read a mode-000 file")
        rules = self.write(".ignore", "*.tmp\n")
        rules.chmod(0o000)
        self.addCleanup(rules.chmod, 0o644)
        self.write("x.tmp")
        result, ripgrep = self.search(ScopeSearchLimits())
        self.assertIn("ignore_rules_not_applied", result["search_domain"]["not_covered"])
        self.assertIn("x.tmp", self.searched(ripgrep))

    def test_an_ignore_file_inside_a_denied_scope_is_never_opened(self) -> None:
        rules = self.write("denied/.ignore", "*.tmp\n")
        self.write("denied/x.tmp")
        self.write("public/y.txt")
        spy = OpenSpy()
        with spy.patch():
            result, ripgrep = self.search(ScopeSearchLimits(), denied=("denied",))
        self.assertNotIn(identity_of(rules), spy.opened)
        self.assertNotIn(identity_of(self.root / "denied"), spy.listed)
        self.assertEqual(self.searched(ripgrep), {"public/y.txt"})
        self.assertNotIn("ignore_rules_not_applied", result["search_domain"]["not_covered"])

    def test_a_hard_linked_ignore_file_is_not_read_while_a_scope_denies_search(self) -> None:
        elsewhere = self.write("denied/rules.txt", "*.tmp\n")
        (self.root / "public").mkdir()
        os.link(elsewhere, self.root / "public" / ".ignore")
        control = self.write("public/x.tmp")
        sentinel = AtimeSentinel()
        sentinel.arm(elsewhere, control)
        result, ripgrep = self.search(ScopeSearchLimits(), denied=("denied",))
        self.assertIn("ignore_rules_not_applied", result["search_domain"]["not_covered"])
        self.assertIn("public/x.tmp", self.searched(ripgrep), "the refused ignore file must not have been applied")
        sentinel.require_alive(self, control)  # the walk's binary probe reads every searched file
        self.assertFalse(sentinel.was_read(elsewhere), "the denied inode was read as an ignore file")


class BudgetTests(WalkCase):
    """Every budget ends the search as explicitly incomplete; none lets ripgrep walk a directory."""

    def assertIncompleteNeverAbsent(self, result: dict[str, Any], *, reason: str, stage: str, status: str) -> None:
        self.assertEqual(result["search_completeness"], status)
        self.assertEqual(result["failure_reason"], reason)
        self.assertEqual(result["failure_stage"], stage)
        self.assertTrue(result["incomplete"])
        self.assertIs(result["safe_to_conclude_absent"], False)
        self.assertIs(result["absent_within_search_domain"], False)

    def assertOnlyDescriptors(self, ripgrep: ScriptedRipgrep) -> None:
        for operand in ripgrep.operands:
            self.assertIsNotNone(DESCRIPTOR_OPERAND.fullmatch(operand), operand)

    def test_the_file_budget_is_exhausted_as_scan_limit_and_never_absent(self) -> None:
        for index in range(6):
            self.write(f"f{index}.txt")
        result, ripgrep = self.search(ScopeSearchLimits(max_files=2))
        self.assertIncompleteNeverAbsent(result, reason="scan_limit", stage="limit", status="PARTIAL")
        self.assertEqual(result["limit_reached"], "max_files")
        self.assertEqual(len(self.searched(ripgrep)), 2, "files within the budget are still searched")
        self.assertOnlyDescriptors(ripgrep)

    def test_the_byte_budget_is_exhausted_as_scan_limit_and_never_absent(self) -> None:
        for index in range(6):
            self.write(f"f{index}.txt", "needle " * 20)  # 140 bytes each
        result, ripgrep = self.search(ScopeSearchLimits(max_bytes=300))
        self.assertIncompleteNeverAbsent(result, reason="scan_limit", stage="limit", status="PARTIAL")
        self.assertEqual(result["limit_reached"], "max_bytes")
        self.assertEqual(len(self.searched(ripgrep)), 2)
        self.assertOnlyDescriptors(ripgrep)

    def test_the_entry_budget_is_exhausted_as_scan_limit_and_never_absent(self) -> None:
        for index in range(10):
            self.write(f"f{index}.txt")
        result, ripgrep = self.search(ScopeSearchLimits(max_entries=4))
        self.assertIncompleteNeverAbsent(result, reason="scan_limit", stage="limit", status="PARTIAL")
        self.assertEqual(result["limit_reached"], "max_entries")
        self.assertOnlyDescriptors(ripgrep)

    def test_a_budget_hit_in_one_branch_stops_the_whole_walk(self) -> None:
        for index in range(4):
            self.write(f"a/f{index}.txt")
            self.write(f"b/f{index}.txt")
        result, ripgrep = self.search(ScopeSearchLimits(max_files=3))
        self.assertEqual(result["limit_reached"], "max_files")
        self.assertEqual(len(self.searched(ripgrep)), 3)

    def test_an_exhausted_deadline_is_a_timeout_and_runs_nothing(self) -> None:
        self.write("a.txt")
        result, ripgrep = self.search(ScopeSearchLimits(deadline_seconds=0.0))
        self.assertIncompleteNeverAbsent(result, reason="timeout", stage="timeout", status="FAILED")
        self.assertEqual(ripgrep.ripgrep_calls, [])
        self.assertEqual(result["results"], [])

    def test_a_deadline_that_passes_during_the_walk_is_a_timeout(self) -> None:
        for index in range(5):
            self.write(f"f{index}.txt")
        clock = {"now": 0.0, "calls": 0}

        def monotonic() -> float:
            clock["calls"] += 1
            if clock["calls"] > 6:
                clock["now"] = 1000.0
            return clock["now"]

        ripgrep = ScriptedRipgrep(lambda call: completed(b"", 1))
        with mock.patch(FIND_RIPGREP, return_value="/usr/bin/rg"), ripgrep.patch(), \
                mock.patch.object(scope_search, "time", SimpleNamespace(monotonic=monotonic)):
            result = self.engine(ScopeSearchLimits(deadline_seconds=100.0)).search_scope(SCOPE, "needle")
        self.assertIncompleteNeverAbsent(result, reason="timeout", stage="timeout", status="FAILED")
        self.assertOnlyDescriptors(ripgrep)

    def test_the_remaining_deadline_bounds_each_ripgrep_run(self) -> None:
        self.write("a.txt")
        _result, ripgrep = self.search(ScopeSearchLimits(deadline_seconds=7.5))
        (call,) = ripgrep.ripgrep_calls
        self.assertTrue(0 < call.kwargs["timeout"] <= 7.5)

    def test_batches_are_bounded_and_every_batch_is_descriptors_only(self) -> None:
        for index in range(7):
            self.write(f"f{index}.txt")
        result, ripgrep = self.search(ScopeSearchLimits(batch_files=3))
        self.assertEqual(result["search_completeness"], "COMPLETE")
        self.assertEqual([len(call.operands) for call in ripgrep.ripgrep_calls], [3, 3, 1])
        self.assertOnlyDescriptors(ripgrep)

    def test_descriptors_are_closed_after_every_search(self) -> None:
        for index in range(5):
            self.write(f"f{index}.txt")
        before = len(os.listdir("/dev/fd"))
        for _ in range(3):
            self.search(ScopeSearchLimits(batch_files=2))
            self.search(ScopeSearchLimits(max_files=2))
        self.assertLessEqual(len(os.listdir("/dev/fd")), before + 2)

    def test_a_failure_in_the_first_batch_stops_before_any_further_batch(self) -> None:
        for index in range(7):
            self.write(f"f{index}.txt")
        result, ripgrep = self.search(ScopeSearchLimits(batch_files=3), reply=lambda call: completed(b"", 2))
        self.assertIncompleteNeverAbsent(result, reason="execution_error", stage="execute", status="FAILED")
        self.assertEqual(len(ripgrep.ripgrep_calls), 1, "a failed ripgrep must not be followed by more batches")


@unittest.skipIf(find_ripgrep() is None, "ripgrep is not installed")
class IgnoreSemanticsMatchRipgrepTests(WalkCase):
    """The in-process ignore engine selects the same files ripgrep itself would list for the tree."""

    def listing(self) -> set[str]:
        """``rg --files`` for the tree, with the same depth and name exclusions the search applies."""
        command = [
            str(find_ripgrep()), "--files", "--no-config", "--no-ignore-parent", "--no-ignore-global",
            "--no-ignore-exclude", f"--max-depth={MAX_DEPTH}",
        ]
        for name in EXCLUDED_DIRECTORY_NAMES:
            command += ["-g", f"!{name}"]
        proc = subprocess.run(
            command, cwd=self.root, capture_output=True, text=True, timeout=60, check=False,
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C"},
        )
        self.assertIn(proc.returncode, (0, 1), proc.stderr)
        return {line.removeprefix("./") for line in proc.stdout.splitlines() if line}

    def assertSameSelection(self, label: str, *, ripgrep_skips: tuple[str, ...] = (), ripgrep_keeps: tuple[str, ...] = ()) -> None:
        """The walk hands over exactly what ``rg --files`` lists. ``ripgrep_skips`` / ``ripgrep_keeps`` pin
        what ripgrep itself does with the fixture, so the comparison cannot go vacuous."""
        _tree, ripgrep = self.walk()
        walked = self.searched(ripgrep)
        expected = self.listing()
        self.assertTrue(expected, f"{label}: ripgrep listed nothing, the comparison proves nothing")
        for name in ripgrep_skips:
            self.assertNotIn(name, expected, f"{label}: ripgrep no longer skips {name}")
        for name in ripgrep_keeps:
            self.assertIn(name, expected, f"{label}: ripgrep no longer keeps {name}")
        self.assertEqual(walked, expected, f"{label}: only in walk {sorted(walked - expected)}; only in ripgrep {sorted(expected - walked)}")

    def make_repo(self) -> None:
        (self.root / ".git").mkdir()

    def test_plain_tree_with_depth_edges(self) -> None:
        for rel in ("a.txt", "x/b.txt", "x/y/c.txt", "x/y/z/d.txt", "x/y/z/w/e.txt", "x/y/z/w/v/f.txt"):
            self.write(rel)
        self.assertSameSelection(
            "plain", ripgrep_keeps=("a.txt", "x/y/z/w/e.txt"), ripgrep_skips=("x/y/z/w/v/f.txt",),
        )

    def test_gitignore_patterns(self) -> None:
        self.make_repo()
        self.write(".gitignore", "\n".join([
            "# a comment", "*.log", "!keep.log", "/rooted.txt", "docs/*.md", "**/cache", "src/**/gen",
            "tmp/**", "only_dir/", "[ab].dat", "q?.cfg", "*.{js,css}", "\\#hash.txt", "\\!bang.txt",
            "trailing.txt   ", "a/**/b.txt", "",
        ]) + "\n")
        for rel in ("one.log", "keep.log", "sub/two.log", "rooted.txt", "sub/rooted.txt", "docs/a.md", "docs/deep/b.md",
                    "cache/f.txt", "m/cache/f.txt", "src/gen/g.txt", "src/q/gen/g.txt", "src/q/r/gen/g.txt",
                    "tmp/x.txt", "tmp/y/z.txt", "only_dir/f.txt", "sub/only_dir", "a.dat", "b.dat", "c.dat",
                    "qa.cfg", "qab.cfg", "app.js", "style.css", "app.ts", "#hash.txt", "!bang.txt", "trailing.txt",
                    "a/b.txt", "a/x/b.txt", "a/x/y/b.txt", "plain.txt"):
            self.write(rel)
        self.assertSameSelection(
            "gitignore patterns",
            ripgrep_skips=(
                "one.log", "rooted.txt", "docs/a.md", "m/cache/f.txt", "src/q/r/gen/g.txt", "tmp/y/z.txt",
                "only_dir/f.txt", "a.dat", "qa.cfg", "app.js", "#hash.txt", "trailing.txt", "a/x/y/b.txt",
            ),
            ripgrep_keeps=(
                "keep.log", "sub/rooted.txt", "docs/deep/b.md", "sub/only_dir", "c.dat", "qab.cfg", "app.ts", "plain.txt",
            ),
        )

    def test_gitignore_is_ignored_outside_a_git_repository(self) -> None:
        self.write(".gitignore", "*.log\n")
        self.write("one.log")
        self.write("two.txt")
        self.assertSameSelection("no .git", ripgrep_keeps=("one.log", "two.txt"))

    def test_a_git_file_marks_a_repository_too(self) -> None:
        self.write(".git", "gitdir: /nowhere\n")
        self.write(".gitignore", "*.log\n")
        self.write("one.log")
        self.write("two.txt")
        self.assertSameSelection(".git as a file", ripgrep_skips=("one.log",), ripgrep_keeps=("two.txt",))

    def test_nested_gitignore_overrides_the_parent(self) -> None:
        self.make_repo()
        self.write(".gitignore", "*.log\nsecret/\n")
        self.write("sub/.gitignore", "!keep.log\n*.tmp\n")
        for rel in ("a.log", "sub/keep.log", "sub/other.log", "sub/a.tmp", "sub/deeper/keep.log", "secret/x.txt", "sub/secret/y.txt"):
            self.write(rel)
        self.assertSameSelection(
            "nested .gitignore",
            ripgrep_skips=("a.log", "sub/other.log", "secret/x.txt", "sub/secret/y.txt", "sub/a.tmp"),
            ripgrep_keeps=("sub/keep.log", "sub/deeper/keep.log"),
        )

    def test_ignore_and_rgignore_take_precedence_over_gitignore(self) -> None:
        self.make_repo()
        self.write(".gitignore", "*.log\n")
        self.write(".ignore", "!a.log\n*.tmp\n")
        self.write("sub/.rgignore", "!b.tmp\n*.dat\n")
        for rel in ("a.log", "b.log", "c.tmp", "sub/b.tmp", "sub/c.tmp", "sub/x.dat", "sub/y.log", "plain.txt"):
            self.write(rel)
        self.assertSameSelection(
            "ignore precedence",
            ripgrep_skips=("b.log", "c.tmp", "sub/c.tmp", "sub/x.dat", "sub/y.log"),
            ripgrep_keeps=("a.log", "sub/b.tmp", "plain.txt"),
        )

    def test_whitelisting_a_hidden_name_makes_it_visible(self) -> None:
        self.write(".ignore", "!.keep.txt\n!.visible/\n")
        for rel in (".keep.txt", ".other.txt", ".visible/f.txt", ".hidden/f.txt", "plain.txt"):
            self.write(rel)
        self.assertSameSelection(
            "hidden whitelist",
            ripgrep_skips=(".other.txt", ".hidden/f.txt"), ripgrep_keeps=(".keep.txt", ".visible/f.txt", "plain.txt"),
        )

    def test_a_directory_rule_does_not_match_a_file_of_the_same_name(self) -> None:
        self.make_repo()
        self.write(".gitignore", "logs/\n")
        self.write("logs", "needle\n")
        self.write("sub/logs/inside.txt")
        self.write("plain.txt")
        self.assertSameSelection("directory-only rule", ripgrep_skips=("sub/logs/inside.txt",), ripgrep_keeps=("logs",))

    def test_a_file_cannot_be_re_included_inside_an_ignored_directory(self) -> None:
        self.make_repo()
        self.write(".gitignore", "build_out/\n!build_out/keep.txt\n")
        self.write("build_out/keep.txt")
        self.write("build_out/other.txt")
        self.write("plain.txt")
        self.assertSameSelection(
            "re-include under ignored dir",
            ripgrep_skips=("build_out/keep.txt", "build_out/other.txt"), ripgrep_keeps=("plain.txt",),
        )

    def test_negation_after_a_broad_rule_in_the_same_file(self) -> None:
        self.make_repo()
        self.write(".gitignore", "*\n!*/\n!*.py\n")
        for rel in ("a.py", "b.txt", "pkg/c.py", "pkg/d.md", "pkg/sub/e.py"):
            self.write(rel)
        self.assertSameSelection(
            "whitelist everything but python",
            ripgrep_skips=("b.txt", "pkg/d.md"), ripgrep_keeps=("a.py", "pkg/c.py", "pkg/sub/e.py"),
        )

    def test_unusual_but_valid_patterns(self) -> None:
        self.make_repo()
        self.write(".gitignore", "\n".join([
            "**/deep/**/leaf.txt", "x/**", "/y/*/z.txt", "ab*cd", "[!a]b.txt", "[a-c]x.txt", "foo bar.txt", "*.[ch]",
        ]) + "\n")
        for rel in ("deep/leaf.txt", "m/deep/n/leaf.txt", "m/deep/leaf.txt", "x/1.txt", "x/y/2.txt", "y/q/z.txt",
                    "y/q/r/z.txt", "abcd", "abXXcd", "ab.txt", "bb.txt", "ax.txt", "dx.txt", "foo bar.txt", "m.c", "m.h", "m.o"):
            self.write(rel)
        self.assertSameSelection(
            "unusual patterns",
            ripgrep_skips=("deep/leaf.txt", "m/deep/n/leaf.txt", "x/1.txt", "abcd", "bb.txt", "ax.txt", "foo bar.txt", "m.c"),
            ripgrep_keeps=("ab.txt", "dx.txt", "m.o"),
        )

    def test_ignore_files_are_read_only_inside_the_search_root(self) -> None:
        """Parent directories are not read (that would itself read outside the scope): documented."""
        self.make_repo()
        self.write(".gitignore", "*.log\n")
        self.write("scope/a.log")
        self.write("scope/b.txt")
        _tree, ripgrep = self.walk(root=self.root / "scope")
        searched = handed_relative_paths(ripgrep, self.root / "scope")
        self.assertEqual(searched, {"a.log", "b.txt"})


if __name__ == "__main__":
    unittest.main()
