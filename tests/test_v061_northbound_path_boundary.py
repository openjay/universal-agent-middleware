"""PR-1 (v0.6.1): no host path leaves in an answer or an error of the session-read MCP server.

Before v0.6.1 the adapter dropped only strings that began with ``/Users/`` or ``/home/`` and only in some tools:
``uam_project_reality`` and ``uam_list_project_instances`` returned ``discovered_worktrees[].path`` verbatim, a
refusal echoed ``str(exc)`` and an exception that left a tool body reached the client as the SDK's own message.
The cases below put real repositories, a RootScope, a registry and Unicode names under a temporary directory (a path
that is NOT under ``/Users/``) and look for any spelling of it in what a client reads.
"""
from __future__ import annotations

import asyncio
import errno
import json
import os
import re
import subprocess
import tempfile
import unicodedata
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from directory_fixtures import authority_dict, static_repository
from r3_world import call_direct, call_protocol, decode, run
from synthetic_fixtures import init_git_repo, write_workspace_registry

from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.northbound import (
    HOST_PATH, HostRoot, NorthboundBoundary, default_roots, is_absolute_path_text, scope_relative,
    worktree_identifier,
)

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:  # pragma: no cover - the MCP SDK is an optional test dependency
    create_session_read_server = None  # type: ignore[assignment]

SCOPE_ID = "data-scope"
WORKTREE_ID = re.compile(r"^wt-[0-9a-f]{16}$")
UNICODE_NAME = "项目-café"


def git(root: Path, *arguments: str) -> None:
    subprocess.run(["git", "-C", str(root), *arguments], capture_output=True, timeout=15, check=True)


class PathWorld:
    """Two registered instances of one project, a RootScope around one of them and worktrees in and out of it.

    ``base`` lives under the temporary directory, so every path the server could leak is neither under ``/Users/``
    nor under ``/home/``; on macOS the temporary directory is also spelled two ways (``/var`` and ``/private/var``).
    """

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="uam-v061-northbound-")
        self.base = Path(os.path.realpath(self._tmp.name))
        self.data = self.base / "data"
        self.config = self.base / "config"
        self.outside = self.base / "outside"
        self.elsewhere = self.base / "elsewhere"
        self.main = self.data / "main"
        self.in_scope_worktree = self.data / "main-wt"
        self.unicode_worktree = self.data / UNICODE_NAME
        self.side = self.outside / "side"
        self.far_worktree = self.elsewhere / "wt"
        self.config.mkdir(parents=True)
        files = {"README.md": "# main\nplain readme line\n", "notes.txt": "plain note\n", "src/app.py": "VALUE = 1\n"}
        init_git_repo(self.main, files=files)
        git(self.main, "worktree", "add", "-q", "-b", "side-branch", str(self.in_scope_worktree))
        git(self.main, "worktree", "add", "-q", "-b", "unicode-branch", str(self.unicode_worktree))
        init_git_repo(self.side, files={"README.md": "# side\n"})
        git(self.side, "worktree", "add", "-q", "-b", "far-branch", str(self.far_worktree))
        (self.config / "root_scopes.json").write_text(json.dumps({
            "schema_version": "root-scope-registry-v1",
            "scopes": [{"scope_id": SCOPE_ID, "root": str(self.data), "authority": authority_dict(),
                        "description": "northbound scope"}],
            "overrides": {},
        }, indent=2), encoding="utf-8")
        self.registry_path = write_workspace_registry(self.config / "workspaces.json", [
            static_repository("main-ws", self.main, project_id="proj", role="canonical-main"),
            static_repository("side-ws", self.side, project_id="proj", role="candidate"),
        ])

    def cleanup(self) -> None:
        self._tmp.cleanup()

    def server(self):
        state = self.base / "state"
        state.mkdir(exist_ok=True)
        return create_session_read_server(registry_path=str(self.registry_path), state_dir=str(state))

    def forbidden(self) -> list[str]:
        """Every spelling of the host that must not appear in what a client reads."""
        spellings = {str(self.base), os.path.realpath(self.base), tempfile.gettempdir(), str(Path.home())}
        if str(self.base).startswith("/private/"):
            spellings.add(str(self.base)[len("/private"):])
        spellings |= {"/Users/", "/private/", "/var/folders", "/home/"}
        return sorted(item for item in spellings if len(item) > 1)


def assert_no_host(case: unittest.TestCase, text: str, world: PathWorld, label: str = "") -> None:
    for spelling in world.forbidden():
        case.assertNotIn(spelling, text, f"{label}: host spelling {spelling!r} left in the answer")


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class ProjectToolsTests(unittest.TestCase):
    """``uam_project_reality`` and ``uam_list_project_instances``: the two tools that returned worktree paths."""

    def setUp(self) -> None:
        self.world = PathWorld()
        self.addCleanup(self.world.cleanup)
        self.server = self.world.server()

    def answers(self) -> dict[str, str]:
        return {
            tool: run(call_direct(self.server, tool, project_id="proj"))
            for tool in ("uam_project_reality", "uam_list_project_instances")
        }

    def worktrees(self, text: str) -> list[dict[str, Any]]:
        return decode(text)["discovered_worktrees"]

    def test_no_spelling_of_the_host_leaves_in_either_tool(self) -> None:
        for tool, text in self.answers().items():
            with self.subTest(tool=tool):
                assert_no_host(self, text, self.world, tool)
                self.assertNotIn("error", decode(text), text[:200])

    def test_a_worktree_is_named_by_a_stable_identifier_and_never_by_a_path(self) -> None:
        for tool, text in self.answers().items():
            with self.subTest(tool=tool):
                found = self.worktrees(text)
                self.assertEqual(len(found), 5, "control: the worktrees of both instances were discovered")
                for worktree in found:
                    self.assertRegex(worktree["worktree_id"], WORKTREE_ID)
                    self.assertNotIn("path", worktree, "an absolute path survived as a field")

    def test_a_worktree_inside_a_scope_says_which_scope_and_where_in_it(self) -> None:
        found = {unicodedata.normalize("NFC", item["relative_path"]): item
                 for item in self.worktrees(self.answers()["uam_list_project_instances"]) if "relative_path" in item}
        self.assertEqual(set(found), {"main", "main-wt", unicodedata.normalize("NFC", UNICODE_NAME)})
        for relative, item in found.items():
            self.assertEqual(item["scope_id"], SCOPE_ID)
            self.assertFalse(is_absolute_path_text(relative), relative)

    def test_a_worktree_outside_every_scope_has_an_identifier_and_nothing_that_locates_it(self) -> None:
        outside = [item for item in self.worktrees(self.answers()["uam_list_project_instances"])
                   if "relative_path" not in item]
        self.assertEqual(len(outside), 2, "the second instance and its worktree lie outside the scope")
        for item in outside:
            self.assertNotIn("scope_id", item)
            self.assertNotIn("path", item)

    def test_the_identifier_of_a_directory_is_the_same_in_both_tools_and_across_servers(self) -> None:
        first = {item["worktree_id"] for item in self.worktrees(self.answers()["uam_project_reality"])}
        second = {item["worktree_id"] for item in self.worktrees(self.answers()["uam_list_project_instances"])}
        self.assertEqual(first, second)
        again = run(call_direct(self.world.server(), "uam_list_project_instances", project_id="proj"))
        self.assertEqual({item["worktree_id"] for item in self.worktrees(again)}, second)
        self.assertIn(worktree_identifier(str(self.world.far_worktree)), second)
        self.assertIn(worktree_identifier(str(self.world.main)), second)

    def test_what_the_tools_exist_to_report_is_unchanged(self) -> None:
        found = self.worktrees(self.answers()["uam_list_project_instances"])
        by_branch = {item["branch"]: item for item in found if item["branch"] in ("side-branch", "far-branch")}
        self.assertIsNone(by_branch["side-branch"]["registered_as"])
        self.assertIs(by_branch["far-branch"]["content_authorized"], False)
        self.assertEqual({item["registered_as"] for item in found} - {None}, {"main-ws", "side-ws"})

    def test_the_same_holds_through_a_real_mcp_client_session(self) -> None:
        for tool in ("uam_project_reality", "uam_list_project_instances"):
            with self.subTest(tool=tool):
                is_error, text = run(call_protocol(self.server, tool, project_id="proj"))
                self.assertFalse(is_error)
                assert_no_host(self, text, self.world, tool)

    def test_each_tool_describes_the_locator_it_returns(self) -> None:
        for tool in ("uam_project_reality", "uam_list_project_instances"):
            with self.subTest(tool=tool):
                description = self.server._tool_manager._tools[tool].description
                self.assertIn("worktree_id", description)
                self.assertIn("absolute host path is never returned", description)


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class EveryToolTests(unittest.TestCase):
    """All 20 tools, answered and refused, with the host's own directory as the thing to find."""

    def setUp(self) -> None:
        self.world = PathWorld()
        self.addCleanup(self.world.cleanup)
        self.server = self.world.server()
        (self.world.main / "notes.txt").write_text("plain note\nchanged line\n", encoding="utf-8")  # a diff to show

    def answered(self) -> list[tuple[str, dict[str, Any]]]:
        return [
            ("uam_list_workspaces", {}),
            ("uam_workspace_snapshot", {"workspace_id": "main-ws"}),
            ("uam_session_bootstrap", {"workspace_id": "main-ws"}),
            ("uam_tree", {"workspace_id": "main-ws"}),
            ("uam_read_file", {"workspace_id": "main-ws", "path": "README.md"}),
            ("uam_file_digest", {"workspace_id": "main-ws", "path": "README.md"}),
            ("uam_search_text", {"workspace_id": "main-ws", "query": "plain"}),
            ("uam_git_status", {"workspace_id": "main-ws"}),
            ("uam_git_diff", {"workspace_id": "main-ws"}),
            ("uam_git_log", {"workspace_id": "main-ws"}),
            ("uam_verify_audit", {}),
            ("uam_project_reality", {"project_id": "proj"}),
            ("uam_list_project_instances", {"project_id": "proj"}),
            ("uam_list_scopes", {}),
            ("uam_discover_projects", {"scope_id": SCOPE_ID}),
            ("uam_scope_inventory", {"scope_id": SCOPE_ID}),
            ("uam_search_scope", {"scope_id": SCOPE_ID, "query": "plain"}),
            ("uam_explain_coverage", {"scope_id": SCOPE_ID, "project_id": "main"}),
            ("uam_what_am_i_missing", {"scope_id": SCOPE_ID}),
            ("uam_explore", {"scope_id": SCOPE_ID, "intent": "readme"}),
            # A workspace addressed by its absolute path inside an authorized scope is a feature: the answer names
            # it by the derived identifier, never by the path the caller used.
            ("uam_workspace_snapshot", {"workspace_id": str(self.world.main)}),
            ("uam_tree", {"workspace_id": str(self.world.main)}),
            ("uam_read_file", {"workspace_id": str(self.world.main), "path": "README.md"}),
        ]

    def refused(self) -> list[tuple[str, dict[str, Any]]]:
        base = str(self.world.base)
        return [
            ("uam_read_file", {"workspace_id": "main-ws", "path": "/etc/passwd"}),
            ("uam_read_file", {"workspace_id": "main-ws", "path": "/Users/someone/.ssh/id_rsa"}),
            ("uam_read_file", {"workspace_id": "main-ws", "path": f"{base}/outside/side/README.md"}),
            ("uam_read_file", {"workspace_id": "main-ws", "path": "../../outside/side/README.md"}),
            ("uam_read_file", {"workspace_id": "main-ws", "path": ".git/config"}),
            ("uam_read_file", {"workspace_id": "ghost-ws", "path": "README.md"}),
            ("uam_file_digest", {"workspace_id": "main-ws", "path": base}),
            ("uam_tree", {"workspace_id": "main-ws", "path": "no/such/dir"}),
            ("uam_tree", {"workspace_id": "main-ws", "path": base}),
            ("uam_git_diff", {"workspace_id": "main-ws", "path": "/etc/hosts"}),
            ("uam_search_text", {"workspace_id": "main-ws", "query": "x", "path": "/Volumes/x"}),
            ("uam_session_bootstrap", {"workspace_id": "ghost-ws"}),
            ("uam_workspace_snapshot", {"workspace_id": f"{base}/outside/side"}),
            ("uam_project_reality", {"project_id": f"{base}/data/main"}),
            ("uam_list_project_instances", {"project_id": "ghost-project"}),
            ("uam_search_scope", {"scope_id": "no-scope", "query": "x"}),
            ("uam_discover_projects", {"scope_id": f"{base}/data"}),
            ("uam_explain_coverage", {"scope_id": SCOPE_ID, "project_id": "ghost-project"}),
        ]

    def test_control_each_answered_call_returns_an_answer_not_an_error(self) -> None:
        for tool, arguments in self.answered():
            with self.subTest(tool=tool):
                error = decode(run(call_direct(self.server, tool, **arguments))).get("error")
                if tool == "uam_search_scope" and error and "ripgrep" in error:
                    continue  # the environment has no ripgrep on its PATH; the leak sweeps below still read this answer
                self.assertFalse(error, f"the control call was refused: {error}")

    def test_no_answer_of_any_tool_contains_a_spelling_of_the_host(self) -> None:
        for tool, arguments in self.answered():
            with self.subTest(tool=tool):
                text = run(call_direct(self.server, tool, **arguments))
                assert_no_host(self, text, self.world, tool)

    def test_no_refusal_of_any_tool_contains_a_spelling_of_the_host(self) -> None:
        for tool, arguments in self.refused():
            with self.subTest(tool=tool, arguments=arguments):
                text = run(call_direct(self.server, tool, **arguments))
                assert_no_host(self, text, self.world, tool)
                self.assertIn("error", decode(text), "the negative case was answered, not refused: the test proves nothing")

    def test_the_refusals_look_the_same_through_a_real_mcp_client_session(self) -> None:
        for tool, arguments in self.refused():
            with self.subTest(tool=tool, arguments=arguments):
                is_error, text = run(call_protocol(self.server, tool, **arguments))
                self.assertFalse(is_error, text[:200])
                assert_no_host(self, text, self.world, tool)


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class UnexpectedFailureTests(unittest.TestCase):
    """An exception that is not one of UAM's own is answered, through the boundary, and never reaches the client raw."""

    def setUp(self) -> None:
        self.world = PathWorld()
        self.addCleanup(self.world.cleanup)
        self.server = self.world.server()
        self.secret_dir = self.world.base / "secret dir with spaces"
        self.secret_file = self.secret_dir / "payload.bin"

    def test_an_os_error_that_names_a_path_with_spaces_is_answered_without_the_path(self) -> None:
        error = OSError(errno.EACCES, "Permission denied", str(self.secret_file))
        for tool, arguments in (
            ("uam_read_file", {"workspace_id": "main-ws", "path": "README.md"}),
            ("uam_tree", {"workspace_id": "main-ws"}),
            ("uam_git_status", {"workspace_id": "main-ws"}),
        ):
            attribute = {"uam_read_file": "read_file", "uam_tree": "tree", "uam_git_status": "git_status"}[tool]
            with self.subTest(tool=tool), mock.patch.object(MiddlewareGateway, attribute, side_effect=error):
                is_error, text = run(call_protocol(self.server, tool, **arguments))
                self.assertFalse(is_error, "the SDK echoed the exception itself")
                assert_no_host(self, text, self.world, tool)
                self.assertNotIn("secret dir", text)
                self.assertNotIn("payload.bin", text)
                self.assertIn("error", decode(text))

    def test_an_unexpected_failure_in_a_project_tool_is_answered_too(self) -> None:
        for tool in ("uam_project_reality", "uam_list_project_instances"):
            attribute = {"uam_project_reality": "project_reality", "uam_list_project_instances": "project_instances"}[tool]
            plain = self.world.base / "secret-dir" / "payload.bin"
            with self.subTest(tool=tool), mock.patch.object(
                MiddlewareGateway, attribute, side_effect=RuntimeError(f"boom at {plain}"),
            ):
                is_error, text = run(call_protocol(self.server, tool, project_id="proj"))
                self.assertFalse(is_error)
                assert_no_host(self, text, self.world, tool)
                self.assertNotIn("payload.bin", text)
                self.assertNotIn("secret-dir", text)

    def test_a_path_that_straddles_the_500_character_cut_is_cleaned_before_it_is_cut(self) -> None:
        # Cut first and the answer would end in ``/Use``: the front of ``/Users``, which no rule recognises as a path.
        message = "x" * 495 + " /Users/someone/code/deeply/nested/name"
        with mock.patch.object(MiddlewareGateway, "git_status", side_effect=RuntimeError(message)):
            text = run(call_direct(self.server, "uam_git_status", workspace_id="main-ws"))
        error = decode(text)["error"]
        self.assertLessEqual(len(error), 500)
        self.assertNotIn("/Use", error, "the front half of a path survived the cut")
        self.assertTrue(error.startswith("x" * 495))

    def test_cancellation_is_not_an_unexpected_failure(self) -> None:
        with mock.patch.object(MiddlewareGateway, "git_status", side_effect=asyncio.CancelledError()):
            with self.assertRaises(asyncio.CancelledError):
                run(call_direct(self.server, "uam_git_status", workspace_id="main-ws"))


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class ContentIsDataTests(unittest.TestCase):
    """Content is the repository's data: a path inside a file, a diff or a commit subject is not metadata."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="uam-v061-content-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.repo = self.base / "repo"
        self.line = "see /Users/someone/else/project/file.txt and /opt/tool/bin/run for details"
        init_git_repo(self.repo, files={"docs.txt": f"{self.line}\n"})
        git(self.repo, "commit", "--allow-empty", "-qm", "fix /Users/someone/x path handling")
        (self.repo / "docs.txt").write_text(f"{self.line}\nsecond /Volumes/Data/y\n", encoding="utf-8")
        config = self.base / "config"
        write_workspace_registry(config / "workspaces.json", [static_repository("content-ws", self.repo)])
        self.server = create_session_read_server(
            registry_path=str(config / "workspaces.json"), state_dir=str(self.base / "state"),
        )

    def call(self, tool: str, **arguments: Any) -> dict[str, Any]:
        return decode(run(call_direct(self.server, tool, workspace_id="content-ws", **arguments)))

    def test_read_file_returns_the_file_exactly(self) -> None:
        self.assertIn(self.line, self.call("uam_read_file", path="docs.txt")["content"])

    def test_search_text_returns_the_matching_line_exactly(self) -> None:
        results = self.call("uam_search_text", query="see /Users/someone")["results"]
        self.assertEqual([item["text"] for item in results], [self.line])
        self.assertEqual([item["path"] for item in results], ["docs.txt"])

    def test_git_diff_returns_the_diff_exactly(self) -> None:
        self.assertIn("+second /Volumes/Data/y", self.call("uam_git_diff")["diff"])

    def test_git_log_returns_the_subject_exactly(self) -> None:
        subjects = [commit["subject"] for commit in self.call("uam_git_log")["commits"]]
        self.assertIn("fix /Users/someone/x path handling", subjects)

    def test_the_session_bootstrap_pack_keeps_commit_subjects_but_not_metadata_paths(self) -> None:
        pack = self.call("uam_session_bootstrap")
        self.assertIn("fix /Users/someone/x path handling", [c["subject"] for c in pack["repository"]["recent_commits"]])


class BoundaryUnitTests(unittest.TestCase):
    """``NorthboundBoundary`` itself: what is a host path, what is not, and every spelling of a known root."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="uam-v061-boundary-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.workspace = self.base / "work space"
        self.scope = self.base / "scope"
        self.state = self.base / "state"
        for path in (self.workspace, self.scope, self.state):
            path.mkdir()
        # Only these roots: the home and temporary directories of the machine running the test must not change a label.
        self.boundary = NorthboundBoundary(lambda: [
            HostRoot("workspace", "ws-a", str(self.workspace)),
            HostRoot("scope", "sc", str(self.scope)),
            HostRoot("state", "", str(self.state)),
        ])

    def test_an_absolute_path_other_than_users_is_replaced_in_any_position(self) -> None:
        paths = [
            "/Volumes/Data/projects/x.py", "/Volumes/数据/项目/文件.txt", "/opt/homebrew/Cellar/git@2/2.0/bin/git",
            "/private/var/folders/zz/abc/T/tmp.x/y", "/var/folders/zz/abc/T/y", "/tmp/a/b", "/etc/hosts",
            "/home/runner/work/x/y", "/mnt/data/x", "/srv/app/data", "/nix/store/abc-pkg/bin/x", "/Library/Caches/x/y",
            "/System/Volumes/Data/x", "/usr/local/lib/python3.14/site.py", "/cores/core.1", "//Volumes//x//y",
            "/tmp", "/etc", "/Users/example", "/Users/example/code/x/y.py", "/a/b",
        ]
        templates = [
            "{p}", "error: {p}", "cannot open '{p}'", 'cannot open "{p}"', "(at {p}, line 3)", "{p}: No such file",
            '["{p}"]', "at {p}.", "file://{p}", "see `{p}` now", "{p}; next", "<{p}>",
        ]
        for path in paths:
            for template in templates:
                with self.subTest(path=path, template=template):
                    cleaned = self.boundary.clean_text(template.format(p=path))
                    last = path.rstrip("/").rsplit("/", 1)[-1]
                    self.assertNotIn(path, cleaned)
                    if len(last) > 3 and last not in ("a", "b"):
                        self.assertNotIn(last, cleaned)
                    self.assertIn(HOST_PATH, cleaned)

    def test_the_home_temporary_and_working_directories_are_always_known(self) -> None:
        roots = default_roots()
        self.assertLessEqual({"<home>", "<tmp>", "<cwd>"}, {root.label for root in roots})
        boundary = NorthboundBoundary(lambda: default_roots())
        self.assertEqual(boundary.clean_text(f"in {tempfile.gettempdir()}/x/y"), "in <tmp>")

    def test_a_quoted_path_with_spaces_is_replaced_whole(self) -> None:
        cleaned = self.boundary.clean_text("[Errno 13] Permission denied: '/Volumes/My Disk/My Files/x y.txt'")
        self.assertEqual(cleaned, f"[Errno 13] Permission denied: '{HOST_PATH}'")

    def test_an_unquoted_path_with_a_space_is_redacted_up_to_the_space_and_never_leaves_its_absolute_front(self) -> None:
        # A deliberate limit (see the module docstring): free text cannot say where an unquoted path ends. What is
        # promised is that the absolute part, the one that locates the host, is gone.
        cleaned = self.boundary.clean_text("boom at /Volumes/My Disk/x")
        self.assertTrue(cleaned.startswith(f"boom at {HOST_PATH}"), cleaned)
        self.assertNotIn("/Volumes", cleaned)

    def test_windows_and_unc_paths_are_replaced_in_text(self) -> None:
        for text in ("C:\\Users\\example\\x.txt", "d:/data/x", "\\\\server\\share\\dir\\x"):
            with self.subTest(text=text):
                self.assertEqual(self.boundary.clean_text(f"failed on {text} now"), f"failed on {HOST_PATH} now")

    def test_a_relative_path_and_ordinary_slashes_are_not_touched(self) -> None:
        for text in (
            "src/app.py", "学习/资料/笔记", "café/menu", "a.b/c.d/e", "./x/y", "../x/y", "../../a/b/c", "~/notes/x",
            "1/2/3", "2026/10/19", "and/or", "read/write", "a / b", "ratio 3/4", "https://example.com/a/b",
            "git@host:org/repo.git", "docs/guide.md#a/b", "x-/y/z", "snake_/a/b",
        ):
            with self.subTest(text=text):
                self.assertEqual(self.boundary.clean_text(text), text)

    def test_a_known_root_is_named_by_its_label_in_every_spelling(self) -> None:
        spellings = {str(self.workspace), os.path.realpath(self.workspace), str(self.workspace).upper(),
                     str(self.workspace).lower(), unicodedata.normalize("NFD", str(self.workspace)),
                     unicodedata.normalize("NFC", str(self.workspace))}
        # The product promises the macOS aliases of exactly /var, /tmp and /etc (``northbound._ALIAS_PREFIXES``): a
        # workspace elsewhere (``/Users/...``, ``/home/...``) has no ``/private`` spelling, and inventing one here
        # produced a path the product rightly treats as an unrelated absolute path.
        workspace = str(self.workspace)
        for alias in ("var", "tmp", "etc"):
            if workspace.startswith(f"/private/{alias}/"):
                spellings.add(workspace[len("/private"):])
            elif workspace.startswith(f"/{alias}/"):
                spellings.add("/private" + workspace)
        for spelling in spellings:
            with self.subTest(spelling=spelling):
                cleaned = self.boundary.clean_text(f"failed in {spelling}/src/mod.py line 3")
                self.assertEqual(cleaned, "failed in <workspace:ws-a> line 3")

    def test_a_longer_name_that_merely_begins_like_a_root_is_not_that_root(self) -> None:
        cleaned = self.boundary.clean_text(f"in {self.scope}-other/x")
        self.assertNotIn("<scope:sc>", cleaned)
        self.assertIn(HOST_PATH, cleaned)

    def test_the_labels_of_the_other_kinds(self) -> None:
        self.assertEqual(self.boundary.clean_text(f"a {self.scope}/p/q"), "a <scope:sc>")
        self.assertEqual(self.boundary.clean_text(f"a {self.state}/audit.jsonl"), "a <state>")

    def test_a_unicode_root_matches_in_both_normalisation_forms(self) -> None:
        root = self.base / unicodedata.normalize("NFC", "café-项目")
        root.mkdir()
        boundary = NorthboundBoundary(lambda: [HostRoot("workspace", "uni", str(root))])
        for form in ("NFC", "NFD"):
            with self.subTest(form=form):
                text = unicodedata.normalize(form, f"see {root}/sub/file.txt")
                self.assertEqual(boundary.clean_text(text), "see <workspace:uni>")

    def test_a_symlinked_root_is_known_by_both_names(self) -> None:
        link = self.base / "link-to-work"
        link.symlink_to(self.workspace, target_is_directory=True)
        boundary = NorthboundBoundary(lambda: [HostRoot("workspace", "ws-a", str(link))])
        for spelling in (str(link), os.path.realpath(link)):
            with self.subTest(spelling=spelling):
                self.assertEqual(boundary.clean_text(f"in {spelling}/x"), "in <workspace:ws-a>")

    def test_the_field_rule_keeps_a_relative_path_and_drops_an_absolute_one(self) -> None:
        cleaned = self.boundary.clean({
            "path": "docs/a.md", "relative_path": "docs/b.md", "root": "/Volumes/X/y", "canonical_path": f"{self.scope}/q",
            "common_dir": "file:///opt/x/.git", "toplevel": "C:\\x", "rel_path": "学习/资料", "directory": "/etc",
            "nested": [{"path": "/abs/x", "name": "ok"}, {"path": "rel/x"}],
        })
        self.assertEqual(cleaned, {
            "path": "docs/a.md", "relative_path": "docs/b.md", "rel_path": "学习/资料",
            "nested": [{"name": "ok"}, {"path": "rel/x"}],
        })

    def test_a_key_that_is_a_path_is_cleaned_and_cannot_collide(self) -> None:
        cleaned = self.boundary.clean({f"{self.scope}/a": 1, f"{self.scope}/b": 2})
        self.assertEqual(sorted(cleaned.values()), [1, 2])
        for key in cleaned:
            self.assertNotIn(str(self.scope), key)

    def test_the_other_values_of_the_answer_are_cleaned_at_any_depth(self) -> None:
        cleaned = self.boundary.clean({"a": [{"b": {"detail": f"x {self.workspace}/y z"}}], "n": 3, "flag": True, "none": None})
        self.assertEqual(cleaned, {"a": [{"b": {"detail": "x <workspace:ws-a> z"}}], "n": 3, "flag": True, "none": None})

    def test_the_keys_a_tool_names_as_content_are_left_exactly_as_they_are(self) -> None:
        payload = {"content": "see /Users/x/y", "subject": "/opt/z", "error": "bad /Users/x/y", "path": "a/b"}
        cleaned = self.boundary.clean(payload, exempt=frozenset({"content", "subject"}))
        self.assertEqual(cleaned["content"], payload["content"])
        self.assertEqual(cleaned["subject"], payload["subject"])
        self.assertEqual(cleaned["error"], f"bad {HOST_PATH}")

    def test_the_input_is_not_modified(self) -> None:
        payload = {"discovered_worktrees": [{"path": "/Volumes/x/y", "branch": "b"}], "root": "/etc", "t": "/opt/x/y"}
        snapshot = json.dumps(payload, sort_keys=True)
        self.boundary.clean(payload)
        self.assertEqual(json.dumps(payload, sort_keys=True), snapshot)

    def test_a_root_list_that_fails_does_not_stop_the_generic_rule(self) -> None:
        def broken() -> list[HostRoot]:
            raise RuntimeError("the registry cannot be read")

        self.assertEqual(NorthboundBoundary(broken).clean_text("in /Volumes/x/y"), f"in {HOST_PATH}")
        self.assertEqual(NorthboundBoundary().clean({"root": "/etc", "x": "/opt/a/b"}), {"x": HOST_PATH})

    def test_worktree_entries_become_an_identifier_plus_a_scope_relative_locator(self) -> None:
        inside = self.scope / "proj" / "wt"
        inside.mkdir(parents=True)
        outside = self.base / "elsewhere"
        outside.mkdir()
        cleaned = self.boundary.clean({"discovered_worktrees": [
            {"path": str(inside), "branch": "b"}, {"path": str(outside), "branch": "c"}, {"path": str(self.scope)},
            {"path": "already/relative"}, "not-a-mapping /Volumes/x/y",
        ]})["discovered_worktrees"]
        self.assertEqual(cleaned[0], {
            "worktree_id": worktree_identifier(str(inside)), "scope_id": "sc", "relative_path": "proj/wt", "branch": "b",
        })
        self.assertEqual(cleaned[1], {"worktree_id": worktree_identifier(str(outside)), "branch": "c"})
        self.assertEqual(cleaned[2]["relative_path"], ".")
        self.assertEqual(cleaned[3], {"path": "already/relative"})
        self.assertEqual(cleaned[4], f"not-a-mapping {HOST_PATH}")


class IdentifierUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="uam-v061-identifier-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))

    def test_an_identifier_says_nothing_about_the_path(self) -> None:
        directory = self.base / "secret-customer-name" / "project"
        directory.mkdir(parents=True)
        identifier = worktree_identifier(str(directory))
        self.assertRegex(identifier, WORKTREE_ID)
        for part in directory.parts[1:]:
            self.assertNotIn(part, identifier)

    def test_one_directory_has_one_identifier_whatever_its_spelling(self) -> None:
        directory = self.base / "Real-Dir"
        directory.mkdir()
        link = self.base / "link"
        link.symlink_to(directory, target_is_directory=True)
        expected = worktree_identifier(str(directory))
        for spelling in (str(link), str(self.base / "real-dir"), str(directory) + "/", str(self.base / "x" / ".." / "Real-Dir")):
            with self.subTest(spelling=spelling):
                self.assertEqual(worktree_identifier(spelling), expected)

    def test_different_directories_have_different_identifiers(self) -> None:
        names = ["a", "b", "a-b", "ab", "项目", "café"]
        identifiers = {worktree_identifier(str(self.base / name)) for name in names}
        self.assertEqual(len(identifiers), len(names))

    def test_the_scope_of_a_path_is_the_most_specific_one_and_is_compared_by_whole_components(self) -> None:
        outer, inner = self.base / "data", self.base / "data" / "inner"
        (inner / "p").mkdir(parents=True)
        (self.base / "data-other").mkdir()
        scopes = [("outer", str(outer)), ("inner", str(inner))]
        self.assertEqual(scope_relative(str(inner / "p"), scopes), ("inner", "p"))
        self.assertEqual(scope_relative(str(outer / "x"), scopes), ("outer", "x"))
        self.assertEqual(scope_relative(str(inner), scopes), ("inner", "."))
        self.assertIsNone(scope_relative(str(self.base / "data-other"), scopes), "a longer sibling name is not inside the scope")
        self.assertIsNone(scope_relative(str(self.base / "elsewhere"), scopes))


class GatewayRootsTests(unittest.TestCase):
    """The roots the gateway tells the boundary about are the live registry's, declared and resolved, and the scopes'."""

    def setUp(self) -> None:
        self.world = PathWorld()
        self.addCleanup(self.world.cleanup)
        self.gateway = MiddlewareGateway(str(self.world.registry_path), str(self.world.base / "state"))

    def test_the_declared_and_the_resolved_root_of_each_workspace_are_known(self) -> None:
        names = {(root.kind, root.name) for root in self.gateway._host_roots()}
        self.assertIn(("workspace", "main-ws"), names)
        self.assertIn(("workspace", "side-ws"), names)
        self.assertIn(("scope", SCOPE_ID), names)
        self.assertIn(("state", ""), names)

    def test_a_workspace_registered_after_the_start_is_known_at_the_next_answer(self) -> None:
        late = self.world.base / "late repo"
        init_git_repo(late, files={"README.md": "late\n"})
        write_workspace_registry(self.world.registry_path, [
            static_repository("main-ws", self.world.main), static_repository("late-ws", late),
        ])
        cleaned = self.gateway.northbound.clean_text(f"failed in {late}/x/y")
        self.assertEqual(cleaned, "failed in <workspace:late-ws>")

    def test_a_malformed_registry_does_not_stop_the_boundary(self) -> None:
        self.world.registry_path.write_text("{ not json", encoding="utf-8")
        self.assertEqual(self.gateway.northbound.clean_text("in /Volumes/x/y"), f"in {HOST_PATH}")


if __name__ == "__main__":
    unittest.main()
