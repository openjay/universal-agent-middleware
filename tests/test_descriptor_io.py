"""S1-D: the Reader opens by walking descriptors, so the check and the open are one act.

Before, ``resolve_safe_path`` checked a path and ``Path.read_bytes`` opened it later. A component replaced by a link
between the two was followed by the open, and ``O_NOFOLLOW`` protects only the last component. These tests inject the
swap exactly in that gap (after a name was validated, right before it is opened) and run the REAL call chain
(``WorkspaceReader``), with an open oracle that identifies protected files by inode, whatever name or path reached them.

Contract under test:
* a swapped link is never followed: ``PathChangedError``, and the protected file is never opened;
* an alias of a denied name is denied by where it really lives;
* a platform without the primitives REFUSES; it never falls back to opening by path;
* the byte budget is counted on the bytes read from the descriptor, not on an earlier ``stat``;
* a differential check keeps ``tree`` and ``search_text`` equal to the behavior they had on ``os.walk``.
"""
from __future__ import annotations

import hashlib
import os
import random
import stat
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from universal_agent_middleware import descriptor_io
from universal_agent_middleware import file_digest as file_digest_module
from universal_agent_middleware import workspace as workspace_module
from universal_agent_middleware.descriptor_io import (
    MAX_SYMLINK_HOPS,
    DescriptorWalkUnsupported,
    NotADirectoryTarget,
    PathChangedError,
    open_beneath,
    open_child,
    open_root,
    read_bounded,
)
from universal_agent_middleware.errors import PathPolicyError, WorkspaceError
from universal_agent_middleware.models import WorkspaceSpec
from universal_agent_middleware.policy import should_hide_path
from universal_agent_middleware.workspace import WorkspaceReader

from s1_instruments import OpenOracle, alarm

MARKER = "S1_FICTIONAL_DENIED_BODY_0042"
VISIBLE = "visible text line\n"

needs_symlinks = unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
needs_fifo = unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo unavailable")


class WalkCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="uam-s1-walk-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        self.root = self.base / "ws"
        self.outside = self.base / "outside"
        for directory in ("docs", "sub/deeper", ".ssh"):
            (self.root / directory).mkdir(parents=True)
        self.outside.mkdir()
        (self.root / "notes.txt").write_text(VISIBLE, encoding="utf-8")
        (self.root / "docs" / "guide.md").write_text("guide\n", encoding="utf-8")
        (self.root / "sub" / "deeper" / "x.txt").write_text("x\n", encoding="utf-8")
        (self.root / ".secrets.env").write_text(f"TOKEN={MARKER}\n", encoding="utf-8")
        (self.root / ".ssh" / "guide.md").write_text(f"{MARKER}\n", encoding="utf-8")
        (self.outside / "foreign.txt").write_text(f"{MARKER}-outside\n", encoding="utf-8")
        (self.outside / "guide.md").write_text(f"{MARKER}-outside-guide\n", encoding="utf-8")
        self.protected = [
            self.root / ".secrets.env", self.root / ".ssh" / "guide.md",
            self.outside / "foreign.txt", self.outside / "guide.md",
        ]
        self.oracle = OpenOracle(self.protected)
        self.reader = self.make_reader()

    def make_reader(self, **spec_overrides) -> WorkspaceReader:
        return WorkspaceReader(WorkspaceSpec(
            workspace_id="w", root=str(self.root), kind="git-repository", capabilities=["filesystem.read"],
            **spec_overrides,
        ))

    def root_descriptor(self) -> int:
        descriptor = open_root(self.root)
        self.addCleanup(os.close, descriptor)
        return descriptor

    def link(self, name: str, target: str | Path) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)
        return path

    @contextmanager
    def swap_before_open(self, name: str, action, *, module=descriptor_io):
        """Run ``action`` once, after ``name`` was validated and right before it is opened through ``module.open_child``."""
        real_open_child = module.open_child
        fired: list[bool] = []

        def hook(entry_name, dir_fd, *, directory):
            if entry_name == name and not fired:
                fired.append(True)
                action()
            return real_open_child(entry_name, dir_fd, directory=directory)

        with mock.patch.object(module, "open_child", hook):
            yield fired


@needs_symlinks
class WalkerTests(WalkCase):
    def test_plain_file_directory_and_root(self) -> None:
        root_fd = self.root_descriptor()
        with open_beneath(root_fd, self.root, ("docs", "guide.md"), kind="file") as opened:
            self.assertEqual(opened.parts, ("docs", "guide.md"))
            self.assertTrue(stat.S_ISREG(opened.info.st_mode))
            self.assertEqual(os.read(opened.fd, 100), b"guide\n")
        with open_beneath(root_fd, self.root, ("docs",), kind="dir") as opened:
            self.assertEqual(opened.parts, ("docs",))
        with open_beneath(root_fd, self.root, (), kind="dir") as opened:
            self.assertEqual(opened.parts, ())
            self.assertNotEqual(opened.fd, root_fd)  # a duplicate: closing it never closes the root descriptor
            self.assertEqual(os.fstat(opened.fd).st_ino, os.fstat(root_fd).st_ino)

    def test_the_context_manager_closes_the_descriptor(self) -> None:
        root_fd = self.root_descriptor()
        with open_beneath(root_fd, self.root, ("notes.txt",), kind="file") as opened:
            descriptor = opened.fd
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_links_that_stay_inside_the_root_are_followed_by_name(self) -> None:
        self.link("docs/alias.md", "guide.md")
        self.link("dir-alias", "docs")
        self.link("abs.md", self.root / "docs" / "guide.md")
        self.link("sub/up.md", "../notes.txt")
        root_fd = self.root_descriptor()
        cases = {
            ("docs", "alias.md"): ("docs", "guide.md"),
            ("dir-alias", "guide.md"): ("docs", "guide.md"),
            ("abs.md",): ("docs", "guide.md"),
            ("sub", "up.md"): ("notes.txt",),
        }
        for parts, real in cases.items():
            with self.subTest(parts=parts):
                with open_beneath(root_fd, self.root, parts, kind="file") as opened:
                    self.assertEqual(opened.parts, real)
        with open_beneath(root_fd, self.root, ("dir-alias",), kind="dir") as opened:
            self.assertEqual(opened.parts, ("docs",))

    def test_links_that_leave_the_root_are_refused(self) -> None:
        self.link("rel-escape.txt", "../outside/foreign.txt")
        self.link("abs-escape.txt", self.outside / "foreign.txt")
        self.link("dir-escape", "../outside")
        root_fd = self.root_descriptor()
        with self.oracle.watching():
            for parts in (("rel-escape.txt",), ("abs-escape.txt",), ("dir-escape", "foreign.txt")):
                with self.subTest(parts=parts):
                    with self.assertRaisesRegex(PathPolicyError, "escapes workspace"):
                        open_beneath(root_fd, self.root, parts, kind="file")
        self.assertEqual(self.oracle.violations, [])

    def test_link_loops_and_long_chains_are_bounded(self) -> None:
        self.link("loop-a", "loop-b")
        self.link("loop-b", "loop-a")
        for index in range(MAX_SYMLINK_HOPS + 1):
            self.link(f"chain-{index}", f"chain-{index + 1}" if index < MAX_SYMLINK_HOPS else "notes.txt")
        root_fd = self.root_descriptor()
        for name in ("loop-a", "chain-0"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(PathPolicyError, "too many levels"):
                    open_beneath(root_fd, self.root, (name,), kind="file")

    def test_an_alias_of_a_denied_name_is_denied_by_where_it_really_lives(self) -> None:
        self.link("notes-alias.txt", ".secrets.env")
        self.link("abs-alias.txt", self.root / ".secrets.env")
        self.link("dir-alias", ".ssh")
        self.link("abs-dir-alias", self.root / ".ssh")
        root_fd = self.root_descriptor()
        with self.oracle.watching():
            for parts in (
                ("notes-alias.txt",), ("abs-alias.txt",), ("dir-alias", "guide.md"), ("abs-dir-alias", "guide.md"),
            ):
                with self.subTest(parts=parts):
                    with self.assertRaisesRegex(PathPolicyError, "denied resolved path component"):
                        open_beneath(root_fd, self.root, parts, kind="file")
        self.assertEqual(self.oracle.violations, [])

    def test_a_denied_name_is_refused_before_the_filesystem_is_asked(self) -> None:
        root_fd = self.root_descriptor()
        for parts in ((".env",), ("docs", ".secrets.env"), (".ssh", "never-created")):
            with self.subTest(parts=parts):
                with self.assertRaises(PathPolicyError):  # not FileNotFoundError: no existence oracle
                    open_beneath(root_fd, self.root, parts, kind="file")
        with self.assertRaises(FileNotFoundError):
            open_beneath(root_fd, self.root, ("missing.txt",), kind="file")
        with self.assertRaises(PathPolicyError):
            open_beneath(root_fd, self.root, ("a\0b",), kind="file")

    def test_the_wrong_type_is_refused_with_a_specific_error(self) -> None:
        root_fd = self.root_descriptor()
        with self.assertRaises(NotADirectoryTarget):
            open_beneath(root_fd, self.root, ("notes.txt",), kind="dir")
        with self.assertRaisesRegex(WorkspaceError, "not a file"):
            open_beneath(root_fd, self.root, ("docs",), kind="file")
        with self.assertRaises(NotADirectoryError):
            open_beneath(root_fd, self.root, ("notes.txt", "below"), kind="file")

    @needs_fifo
    def test_a_fifo_is_refused_without_being_opened(self) -> None:
        os.mkfifo(self.root / "pipe")
        root_fd = self.root_descriptor()
        opened_names: list[str] = []
        real_open_child = descriptor_io.open_child

        def recording(name, dir_fd, *, directory):
            opened_names.append(name)
            return real_open_child(name, dir_fd, directory=directory)

        with alarm(), mock.patch.object(descriptor_io, "open_child", recording):
            with self.assertRaisesRegex(WorkspaceError, "not a file"):
                open_beneath(root_fd, self.root, ("pipe",), kind="file")
        self.assertNotIn("pipe", opened_names)

    def test_an_unsupported_platform_refuses_every_entry_point(self) -> None:
        root_fd = self.root_descriptor()
        with mock.patch.object(descriptor_io, "descriptor_walk_supported", return_value=False):
            with self.assertRaises(DescriptorWalkUnsupported):
                open_root(self.root)
            with self.assertRaises(DescriptorWalkUnsupported):
                open_child("notes.txt", root_fd, directory=False)
            with self.assertRaises(DescriptorWalkUnsupported):
                open_beneath(root_fd, self.root, ("notes.txt",), kind="file")

    def test_this_platform_supports_the_walk(self) -> None:
        # If this ever fails the suite must not quietly pass while content access is being refused.
        self.assertTrue(descriptor_io.descriptor_walk_supported())

    def test_the_read_budget_counts_bytes_read_not_the_earlier_stat(self) -> None:
        path = self.root / "growing.txt"
        path.write_bytes(b"a" * 50)
        descriptor = os.open(path, os.O_RDONLY)
        self.addCleanup(os.close, descriptor)
        stat_size = os.fstat(descriptor).st_size
        with path.open("ab") as handle:
            handle.write(b"b" * 5000)  # grows after the stat, through the same inode
        requested: list[int] = []
        real_read = os.read

        def recording(fd, length):
            requested.append(length)
            return real_read(fd, length)

        with mock.patch("os.read", recording):
            self.assertIsNone(read_bounded(descriptor, stat_size))
        self.assertLessEqual(max(requested), stat_size + 1)  # never asks for more than limit + 1 bytes
        os.lseek(descriptor, 0, os.SEEK_SET)
        self.assertEqual(len(read_bounded(descriptor, 10_000) or b""), 5050)
        os.lseek(descriptor, 0, os.SEEK_SET)
        self.assertEqual(read_bounded(descriptor, 5050), b"a" * 50 + b"b" * 5000)  # exactly at the limit is allowed


@needs_symlinks
class SwapRaceTests(WalkCase):
    """The injected swap lands after validation and before the open, through the real Reader."""

    def read_with_swap(self, name: str, swap, path: str | None = None, *, module=descriptor_io):
        with self.oracle.watching(), self.swap_before_open(name, swap, module=module) as fired:
            with self.assertRaises(PathChangedError):
                self.reader.read_file(path or name)
        self.assertTrue(fired, "the swap was never injected: the test proves nothing")
        self.assertEqual(self.oracle.violations, [])

    def replace_with_link(self, name: str, target: str | Path):
        def action():
            (self.root / name).unlink()
            (self.root / name).symlink_to(target)

        return action

    def test_the_final_component_swapped_for_a_link_to_a_denied_file_is_not_read(self) -> None:
        self.read_with_swap("notes.txt", self.replace_with_link("notes.txt", ".secrets.env"))

    def test_the_final_component_swapped_for_a_link_outside_the_root_is_not_read(self) -> None:
        for target in (self.outside / "foreign.txt", "../outside/foreign.txt"):
            with self.subTest(target=str(target)):
                (self.root / "notes.txt").unlink(missing_ok=True)
                (self.root / "notes.txt").write_text(VISIBLE, encoding="utf-8")
                self.oracle.violations.clear()
                self.read_with_swap("notes.txt", self.replace_with_link("notes.txt", target))

    def test_an_intermediate_directory_swapped_for_a_link_is_not_followed(self) -> None:
        for index, target in enumerate((self.root / ".ssh", self.outside)):
            with self.subTest(target=str(target)):
                moved = self.base / f"docs-moved-{index}"

                def action(moved=moved, target=target):
                    (self.root / "docs").rename(moved)
                    (self.root / "docs").symlink_to(target)

                self.read_with_swap("docs", action, "docs/guide.md")
                (self.root / "docs").unlink()
                moved.rename(self.root / "docs")
                self.oracle.violations.clear()

    def test_a_deeper_directory_swapped_for_a_link_is_not_followed(self) -> None:
        moved = self.base / "deeper-moved"

        def action():
            (self.root / "sub" / "deeper").rename(moved)
            (self.root / "sub" / "deeper").symlink_to(self.outside)

        self.read_with_swap("deeper", action, "sub/deeper/x.txt")

    @needs_fifo
    def test_the_final_component_swapped_for_a_fifo_never_blocks_and_is_refused(self) -> None:
        def action():
            (self.root / "notes.txt").unlink()
            os.mkfifo(self.root / "notes.txt")

        with alarm():
            self.read_with_swap("notes.txt", action)

    def test_the_final_component_swapped_for_a_directory_is_refused(self) -> None:
        def action():
            (self.root / "notes.txt").unlink()
            (self.root / "notes.txt").mkdir()

        self.read_with_swap("notes.txt", action)

    def test_digest_follows_the_same_rules(self) -> None:
        with self.oracle.watching(), self.swap_before_open(
            "notes.txt", self.replace_with_link("notes.txt", ".secrets.env"),
        ) as fired:
            with self.assertRaises(PathChangedError):
                self.reader.file_digest("notes.txt")
        self.assertTrue(fired)
        self.assertEqual(self.oracle.violations, [])

    def test_tree_does_not_enter_a_directory_swapped_after_it_was_listed(self) -> None:
        moved = self.base / "sub-moved"

        def action():
            (self.root / "sub").rename(moved)
            (self.root / "sub").symlink_to(self.outside)

        with self.oracle.watching(), self.swap_before_open("sub", action, module=workspace_module) as fired:
            listing = self.reader.tree(depth=4)
        self.assertTrue(fired)
        self.assertEqual(self.oracle.violations, [])
        self.assertNotIn("foreign.txt", str(listing))

    def test_search_does_not_read_a_file_swapped_after_it_was_listed(self) -> None:
        with self.oracle.watching(), self.swap_before_open(
            "notes.txt", self.replace_with_link("notes.txt", ".secrets.env"), module=workspace_module,
        ) as fired:
            result = self.reader.search_text("DENIED_BODY")
        self.assertTrue(fired)
        self.assertEqual(self.oracle.violations, [])
        self.assertEqual(result["results"], [])
        self.assertEqual(result["files_skipped"]["read_error"], 1)  # counted as an unreadable file, never followed

    def test_search_does_not_enter_a_directory_swapped_after_it_was_listed(self) -> None:
        moved = self.base / "docs-moved-search"

        def action():
            (self.root / "docs").rename(moved)
            (self.root / "docs").symlink_to(self.outside)

        with self.oracle.watching(), self.swap_before_open("docs", action, module=workspace_module) as fired:
            result = self.reader.search_text("outside-guide")
        self.assertTrue(fired)
        self.assertEqual(self.oracle.violations, [])
        self.assertEqual(result["results"], [])


class BudgetAndDigestTests(WalkCase):
    def test_a_file_that_grows_after_it_was_opened_is_still_cut_off_by_the_budget(self) -> None:
        reader = self.make_reader(max_file_bytes=100)
        path = self.root / "grows.txt"
        path.write_text("x" * 50, encoding="utf-8")
        real_read_bounded = workspace_module.read_bounded

        def growing(descriptor, limit):
            with path.open("ab") as handle:
                handle.write(b"y" * 5000)
            return real_read_bounded(descriptor, limit)

        with mock.patch.object(workspace_module, "read_bounded", growing):
            with self.assertRaisesRegex(WorkspaceError, "exceeds max_file_bytes"):
                reader.read_file("grows.txt")

    def test_search_counts_a_file_that_grew_past_the_budget_as_oversized(self) -> None:
        reader = self.make_reader(max_file_bytes=100)
        path = self.root / "grows.txt"
        path.write_text("needle\n", encoding="utf-8")
        real_read_bounded = workspace_module.read_bounded

        def growing(descriptor, limit):
            with path.open("ab") as handle:
                handle.write(b"y" * 5000)
            return real_read_bounded(descriptor, limit)

        with mock.patch.object(workspace_module, "read_bounded", growing):
            result = reader.search_text("needle")
        self.assertEqual(result["results"], [])
        self.assertEqual(result["files_skipped"]["oversized"], 1)

    def test_digest_of_an_untouched_file_matches_hashlib(self) -> None:
        data = os.urandom(300_000)
        (self.root / "evidence.bin").write_bytes(data)
        result = self.reader.file_digest("evidence.bin")
        self.assertTrue(result["complete"])
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["permission_check"], {"authority": "allowed", "os_read": "allowed"})

    @unittest.skipIf(not hasattr(os, "replace"), "os.replace unavailable")
    def test_a_file_replaced_while_it_is_hashed_gets_no_digest(self) -> None:
        (self.root / "evidence.bin").write_bytes(os.urandom(4096))
        replacement = self.base / "replacement.bin"
        replacement.write_bytes(os.urandom(4096))
        real_read_chunk = file_digest_module._read_chunk
        calls: list[int] = []

        def swapping(descriptor, size):
            chunk = real_read_chunk(descriptor, size)
            calls.append(len(chunk))
            if not chunk:  # end of file reached: the name now refers to another file
                os.replace(replacement, self.root / "evidence.bin")
            return chunk

        with mock.patch.object(file_digest_module, "_read_chunk", swapping):
            result = self.reader.file_digest("evidence.bin")
        self.assertEqual(calls[-1], 0)
        self.assertFalse(result["complete"])
        self.assertIsNone(result["sha256"])
        self.assertEqual(result["reason"], "changed_while_hashing")

    @unittest.skipIf(os.name != "posix" or os.geteuid() == 0, "needs a non-root POSIX account")
    def test_a_file_the_os_refuses_is_a_result_not_an_error(self) -> None:
        path = self.root / "locked.bin"
        path.write_bytes(b"locked")
        path.chmod(0)
        self.addCleanup(path.chmod, 0o600)
        result = self.reader.file_digest("locked.bin")
        self.assertFalse(result["complete"])
        self.assertEqual(result["reason"], "os_permission_denied")
        self.assertEqual(result["permission_check"], {"authority": "allowed", "os_read": "denied"})
        self.assertEqual(result["size_bytes"], 6)


class NoFallbackTests(WalkCase):
    def test_the_reader_refuses_instead_of_opening_by_path(self) -> None:
        def forbidden(*_args, **_kwargs):
            raise AssertionError("the Reader fell back to opening by path")

        with mock.patch.object(descriptor_io, "descriptor_walk_supported", return_value=False), \
                mock.patch.object(Path, "read_bytes", forbidden), mock.patch.object(Path, "read_text", forbidden), \
                mock.patch.object(Path, "open", forbidden), mock.patch("os.walk", forbidden):
            for name, call in (
                ("read_file", lambda: self.reader.read_file("notes.txt")),
                ("file_digest", lambda: self.reader.file_digest("notes.txt")),
                ("tree", lambda: self.reader.tree()),
                ("search_text", lambda: self.reader.search_text("visible")),
            ):
                with self.subTest(operation=name):
                    with self.assertRaises(DescriptorWalkUnsupported):
                        call()


# ---------------------------------------------------------------------------------------------------------------------
# Differential: the descriptor-based tree and search must answer exactly as the os.walk implementation they replace.
# The references below are that implementation, without the nested-scope policy (unrestricted by default).
# ---------------------------------------------------------------------------------------------------------------------
def reference_tree(root: Path, path: str, depth: int, max_entries: int) -> dict:
    base = (root / path).resolve()
    entries: list[dict] = []
    base_depth = len(base.parts)
    for current, dirs, files in os.walk(base, followlinks=False):
        current_path = Path(current)
        current_depth = len(current_path.parts) - base_depth
        descend = []
        for name in dirs:
            child = current_path / name
            if child.is_symlink() or should_hide_path(root, child) or current_depth >= depth:
                continue
            descend.append(name)
        dirs[:] = sorted(descend)
        for name in sorted(dirs + files):
            candidate = current_path / name
            if candidate.is_symlink() or should_hide_path(root, candidate):
                continue
            item = {"path": candidate.relative_to(root).as_posix(), "type": "dir" if candidate.is_dir() else "file"}
            if candidate.is_file():
                item["size"] = candidate.stat().st_size
            entries.append(item)
            if len(entries) >= max_entries:
                return {"entries": entries, "truncated": True}
    return {"entries": entries, "truncated": False}


def reference_search(root: Path, query: str, max_results: int, max_file_bytes: int, max_files: int) -> dict:
    results: list[dict] = []
    scanned = oversized = binary = errors = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(
            name for name in dirs
            if not (current_path / name).is_symlink() and not should_hide_path(root, current_path / name)
        )
        for name in sorted(files):
            target = current_path / name
            if target.is_symlink() or should_hide_path(root, target):
                continue
            try:
                regular = stat.S_ISREG(target.stat().st_mode)
            except OSError:
                errors += 1
                continue
            if not regular:
                continue
            scanned += 1
            if scanned > max_files:
                return {"results": results, "files_scanned": scanned - 1, "truncated": True,
                        "skipped": (oversized, binary, errors)}
            try:
                if target.stat().st_size > max_file_bytes:
                    oversized += 1
                    continue
                raw = target.read_bytes()
                if b"\x00" in raw[:8192]:
                    binary += 1
                    continue
                lines = raw.decode("utf-8", errors="replace").splitlines()
            except OSError:
                errors += 1
                continue
            for number, line in enumerate(lines, start=1):
                if query.lower() in line.lower():
                    results.append({"path": target.relative_to(root).as_posix(), "line": number, "text": line[:500]})
                    if len(results) >= max_results:
                        return {"results": results, "files_scanned": scanned, "truncated": True,
                                "skipped": (oversized, binary, errors)}
    return {"results": results, "files_scanned": scanned, "truncated": False, "skipped": (oversized, binary, errors)}


@needs_symlinks
class DifferentialTests(unittest.TestCase):
    """A seeded random tree with every shape the old walk had an opinion about."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="uam-s1-diff-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        self.root = self.base / "ws"
        self.root.mkdir()
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "foreign.txt").write_text("alpha foreign\n", encoding="utf-8")
        rng = random.Random(20261017)
        directories = [self.root]
        for index in range(14):
            parent = rng.choice(directories)
            child = parent / rng.choice(["a", "b", "c", "dd", "éé", "src", ".git", ".ssh", "node"]) / f"d{index}"
            child.mkdir(parents=True, exist_ok=True)
            directories.extend([child.parent, child])
        words = ["alpha", "Beta", "gamma", "delta", "ALPHA beta"]
        for index in range(60):
            parent = rng.choice(directories)
            name = rng.choice(["f", "g", "h", ".env", ".secrets.env", "notes", "ünï", "x.bin", "big"]) + str(index)
            kind = rng.random()
            path = parent / name
            if kind < 0.6:
                path.write_text("\n".join(rng.choice(words) for _ in range(rng.randint(1, 6))) + "\n", encoding="utf-8")
            elif kind < 0.7:
                path.write_bytes(b"\x00\x01binary" + bytes(rng.randrange(256) for _ in range(40)))
            elif kind < 0.78:
                path.write_text("alpha " * 400, encoding="utf-8")  # past the small budget used below
            elif kind < 0.86:
                path.write_bytes(b"")
            elif kind < 0.93:
                path.symlink_to(rng.choice([outside / "foreign.txt", "../nowhere", "."]))
            else:
                path.symlink_to(outside)
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.root / "fifo")
        (self.root / "empty-dir").mkdir()
        (self.root / "hidden-dir-link").symlink_to(".ssh" if (self.root / ".ssh").exists() else ".")

    def reader(self, **spec_overrides) -> WorkspaceReader:
        return WorkspaceReader(WorkspaceSpec(
            workspace_id="w", root=str(self.root), kind="git-repository", capabilities=["filesystem.read"],
            **spec_overrides,
        ))

    def test_tree_equals_the_walk_it_replaced(self) -> None:
        reader = self.reader()
        for depth in range(0, 6):
            for max_entries in (1, 3, 7, 500):
                with self.subTest(depth=depth, max_entries=max_entries):
                    actual = reader.tree(".", depth=depth, max_entries=max_entries)
                    expected = reference_tree(self.root, ".", depth, max_entries)
                    self.assertEqual(actual["entries"], expected["entries"])
                    self.assertEqual(actual["truncated"], expected["truncated"])

    def test_tree_of_a_subdirectory_equals_the_walk_it_replaced(self) -> None:
        reader = self.reader()
        subdirectories = [
            child.relative_to(self.root).as_posix() for child in sorted(self.root.rglob("*"))
            if child.is_dir() and not child.is_symlink() and not should_hide_path(self.root, child)
        ]
        self.assertGreater(len(subdirectories), 3)
        for subdirectory in subdirectories[:12]:
            with self.subTest(path=subdirectory):
                actual = reader.tree(subdirectory, depth=3, max_entries=500)
                expected = reference_tree(self.root, subdirectory, 3, 500)
                self.assertEqual(actual["entries"], expected["entries"])

    def test_search_equals_the_walk_it_replaced(self) -> None:
        for max_file_bytes, max_files in ((300, 5000), (300, 4), (524_288, 5000)):
            reader = self.reader(max_file_bytes=max_file_bytes, max_search_files=max_files)
            for query in ("alpha", "BETA", "gamma delta", "no-such-text"):
                for max_results in (1, 5, 500):
                    with self.subTest(budget=max_file_bytes, files=max_files, query=query, results=max_results):
                        actual = reader.search_text(query, max_results=max_results)
                        expected = reference_search(self.root, query, max_results, max_file_bytes, max_files)
                        self.assertEqual(actual["results"], expected["results"])
                        self.assertEqual(actual["files_scanned"], expected["files_scanned"])
                        self.assertEqual(actual["truncated"], expected["truncated"])
                        skipped = actual.get("files_skipped", {})
                        self.assertEqual(
                            (skipped.get("oversized", 0), skipped.get("binary", 0), skipped.get("read_error", 0)),
                            expected["skipped"],
                        )


if __name__ == "__main__":
    unittest.main()
