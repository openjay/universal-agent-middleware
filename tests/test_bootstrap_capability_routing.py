"""The read-only profile says what ``uam_session_bootstrap`` needs and routes by capability; the refusal itself is what it was.

``uam_session_bootstrap`` builds its context pack from Git status and recent commits, so it needs ``git.observe``. A ``filesystem-directory`` workspace can never hold that
capability, and the resolver refuses it with ``UNSUPPORTED_CAPABILITY`` (``tests/test_filesystem_directory_adapters.py`` pins that). What a client reads before it calls must say
so: the tool description names the requirement, and the server ``instructions`` send a known workspace to bootstrap only when it holds ``git.observe`` and to the filesystem tools
otherwise. These tests pin that text against the behaviour it describes (every tool it names exists, every tool it recommends for a directory serves a directory, every tool it
says a directory refuses does refuse) and pin that nothing else moved: the refusal payload, the absence of any Git run or filesystem change on a refusal, and the fact that the
capability, not the kind, decides.

Not covered here, on purpose: a directory-aware bootstrap (a context pack without Git). It is a contract change on the backlog, not part of this text-only correction.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import subprocess
import unittest
from typing import Any
from unittest import mock

from directory_fixtures import PLAIN_ID, WorldTestCase, static_directory, static_repository

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:
    create_session_read_server = None  # type: ignore[assignment]

BOOTSTRAP = "uam_session_bootstrap"
SNAPSHOT = "uam_workspace_snapshot"
DIRECTORY_WORKSPACES = (PLAIN_ID, "plain-static")  # a derived and a statically registered directory
# What a directory workspace is served by, with the arguments that make each call meaningful on the fixture.
FILESYSTEM_TOOL_ARGUMENTS: dict[str, dict[str, str]] = {
    "uam_tree": {},
    "uam_read_file": {"path": "README.md"},
    "uam_file_digest": {"path": "README.md"},
    "uam_search_text": {"query": "needle-markdown"},
}
DIRECTORY_REFUSAL = {
    "error": "workspace kind filesystem-directory does not support git.observe",
    "diagnostic": {
        "schema_version": "workspace-diagnostic-v1",
        "status": "UNSUPPORTED_CAPABILITY",
        "reason": "CAPABILITY_NOT_SUPPORTED_BY_WORKSPACE_KIND",
        "workspace_kind": "filesystem-directory",
        "capability": "git.observe",
        "supported_capabilities": ["filesystem.read"],
    },
}
TOOL_NAME = re.compile(r"\buam_[a-z_]+\b")


def squeeze(text: str) -> str:
    return " ".join(text.split())


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class RoutingCase(WorldTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.world.write_scope_file()
        self.world.write_registry([
            static_directory("plain-static", self.world.plain),
            static_repository("git-full", self.world.repo),
            static_repository("git-read-only", self.world.repo, capabilities=["filesystem.read"]),
        ])
        self.server = create_session_read_server(registry_path=str(self.world.registry_path), state_dir=str(self.world.state))
        self.tools = self.server._tool_manager._tools

    def call(self, name: str, **arguments: Any) -> dict[str, Any]:
        return json.loads(asyncio.run(self.tools[name].fn(**arguments, ctx=None)))

    @property
    def description(self) -> str:
        return squeeze(self.tools[BOOTSTRAP].description)

    @property
    def instructions(self) -> str:
        return squeeze(self.server.instructions or "")

    def routing_clauses(self) -> tuple[str, str]:
        """The two halves of the instructions' sentence for a known explicit workspace: what holds ``git.observe``, and what does not."""
        found = re.search(r"For a known explicit workspace, (.*?) For cross-project text search", self.instructions)
        self.assertIsNotNone(found, "the instructions no longer route a known explicit workspace")
        with_git, separator, without_git = found.group(1).partition("; ")
        self.assertTrue(separator, "the routing has no second clause for a workspace without git.observe")
        return with_git, without_git

    def alternatives_in(self, text: str) -> set[str]:
        return set(TOOL_NAME.findall(text))


class RoutingTextTests(RoutingCase):
    def test_the_description_states_the_requirement_and_what_a_directory_gets(self) -> None:
        description = self.description
        self.assertTrue(description.startswith("Bootstrap a fresh reasoning session"))
        for phrase in ("Requires the `git.observe` capability", "`capabilities` in `uam_list_workspaces`", "`filesystem-directory`", "`UNSUPPORTED_CAPABILITY`"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, description)
        found = re.search(r"Use ((?:`uam_[a-z_]+`(?:, | and )?)+) there\.", description)
        self.assertIsNotNone(found, "the description does not say which tools to use for a directory")
        self.assertEqual(self.alternatives_in(found.group(1)), set(FILESYSTEM_TOOL_ARGUMENTS))

    def test_the_instructions_send_a_workspace_to_bootstrap_only_with_git_observe(self) -> None:
        self.assertNotIn("For a known explicit workspace, use uam_session_bootstrap", self.instructions)
        with_git, without_git = self.routing_clauses()
        self.assertIn("uam_list_workspaces", with_git)
        self.assertLess(with_git.index("git.observe"), with_git.index(BOOTSTRAP))
        self.assertIn("a filesystem-directory (filesystem.read only)", without_git)
        self.assertIn(f"is not served by {BOOTSTRAP}", without_git)
        self.assertEqual(self.alternatives_in(without_git) - {BOOTSTRAP}, set(FILESYSTEM_TOOL_ARGUMENTS))

    def test_the_instructions_name_what_a_directory_refuses(self) -> None:
        found = re.search(r"\(read tools only; (.*?) refused\)", self.instructions)
        self.assertIsNotNone(found, "the instructions no longer say what a directory workspace refuses")
        self.assertEqual(self.alternatives_in(found.group(1)), {BOOTSTRAP, SNAPSHOT})
        self.assertIn("the git tools", found.group(1))

    def test_every_tool_the_routing_names_exists(self) -> None:
        for source, text in (("instructions", self.instructions), ("description", self.description)):
            for name in self.alternatives_in(text):
                with self.subTest(source=source, tool=name):
                    self.assertIn(name, self.tools)

    def test_the_listing_carries_the_two_fields_the_routing_reads(self) -> None:
        by_id = {entry["workspace_id"]: entry for entry in self.call("uam_list_workspaces")["registered"]}
        self.assertEqual((by_id["plain-static"]["kind"], by_id["plain-static"]["capabilities"]), ("filesystem-directory", ["filesystem.read"]))
        self.assertIn("git.observe", by_id["git-full"]["capabilities"])
        self.assertNotIn("git.observe", by_id["git-read-only"]["capabilities"])


class RoutingMatchesBehaviourTests(RoutingCase):
    def test_every_tool_recommended_for_a_directory_serves_one(self) -> None:
        recommended = self.alternatives_in(self.routing_clauses()[1]) - {BOOTSTRAP}
        self.assertEqual(recommended, set(FILESYSTEM_TOOL_ARGUMENTS), "a recommended tool has no call that proves it serves a directory")
        readme_sha256 = hashlib.sha256((self.world.plain / "README.md").read_bytes()).hexdigest()
        for workspace in DIRECTORY_WORKSPACES:
            for name in sorted(recommended):
                with self.subTest(workspace=workspace, tool=name):
                    payload = self.call(name, workspace_id=workspace, **FILESYSTEM_TOOL_ARGUMENTS[name])
                    self.assertNotIn("error", payload)
                    if name == "uam_file_digest":
                        self.assertEqual(payload["sha256"], readme_sha256)

    def test_every_tool_a_directory_is_said_to_refuse_refuses_it(self) -> None:
        refused = {BOOTSTRAP, SNAPSHOT, *(name for name in self.tools if name.startswith("uam_git_"))}
        for workspace in DIRECTORY_WORKSPACES:
            for name in sorted(refused):
                with self.subTest(workspace=workspace, tool=name):
                    payload = self.call(name, workspace_id=workspace)
                    self.assertEqual(payload["diagnostic"]["status"], "UNSUPPORTED_CAPABILITY")
                    self.assertEqual(payload["diagnostic"]["capability"], "git.observe")


class RefusalIsUnchangedTests(RoutingCase):
    def test_a_directory_is_refused_with_the_exact_diagnostic(self) -> None:
        for workspace in DIRECTORY_WORKSPACES:
            for name in (BOOTSTRAP, SNAPSHOT):
                with self.subTest(workspace=workspace, tool=name):
                    self.assertEqual(self.call(name, workspace_id=workspace), DIRECTORY_REFUSAL)

    def test_a_refusal_starts_no_process_and_leaves_the_tree_as_it_was(self) -> None:
        before = self.world.target_fingerprint()
        with mock.patch.object(subprocess, "Popen", side_effect=RuntimeError("a process was started")) as popen:
            for workspace in DIRECTORY_WORKSPACES:
                for name in (BOOTSTRAP, SNAPSHOT):
                    self.assertEqual(self.call(name, workspace_id=workspace), DIRECTORY_REFUSAL)
        self.assertEqual(popen.call_count, 0)
        self.assertFalse((self.world.plain / ".git").exists())
        self.assertEqual(self.world.target_fingerprint(), before)

    def test_the_capability_not_the_kind_decides(self) -> None:
        self.assertEqual(
            self.call(BOOTSTRAP, workspace_id="git-read-only"),
            {"error": "workspace git-read-only does not grant capability git.observe"},
        )
        served = self.call(BOOTSTRAP, workspace_id="git-full")
        self.assertEqual(served["schema_version"], "session-context-pack-v2")
        self.assertIn("git.observe", served["capabilities"])


if __name__ == "__main__":
    unittest.main()
