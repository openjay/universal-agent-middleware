"""Tests for the official MCP SDK adapter (D1A-02/03/04)."""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from synthetic_fixtures import SyntheticRegistryBundle

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:
    create_session_read_server = None  # type: ignore[assignment]

SKIP = create_session_read_server is None


@unittest.skipIf(SKIP, "MCP SDK unavailable")
class MCPSDKAdapterTests(unittest.TestCase):
    """Test the official MCP SDK read-only adapter."""

    @classmethod
    def setUpClass(cls):
        cls.bundle = SyntheticRegistryBundle()
        cls.state = tempfile.TemporaryDirectory(prefix="uam-sdk-test-")
        cls.addClassCleanup(cls.state.cleanup)
        cls.addClassCleanup(cls.bundle.cleanup)
        cls.server = create_session_read_server(
            registry_path=str(cls.bundle.registry_path),
            state_dir=cls.state.name,
        )
        cls.tools = cls.server._tool_manager._tools

    def test_01_correct_tool_count(self):
        self.assertEqual(len(self.tools), 19)

    def test_02_all_required_tools_present(self):
        required = {
            "uam_list_workspaces",
            "uam_workspace_snapshot",
            "uam_session_bootstrap",
            "uam_tree",
            "uam_read_file",
            "uam_search_text",
            "uam_git_status",
            "uam_git_diff",
            "uam_git_log",
            "uam_verify_audit",
            "uam_project_reality",
            "uam_list_project_instances",
            "uam_list_scopes",
            "uam_discover_projects",
            "uam_scope_inventory",
            "uam_search_scope",
            "uam_explain_coverage",
            "uam_what_am_i_missing",
            "uam_explore",
        }
        self.assertEqual(set(self.tools.keys()), required)

    def test_03_no_forbidden_tools(self):
        forbidden_patterns = [
            "create_contract", "contract_create", "record_result",
            "result_record", "write", "edit", "patch", "exec",
            "shell", "push", "merge", "deploy", "credential",
        ]
        tool_names = set(self.tools.keys())
        for pattern in forbidden_patterns:
            for name in tool_names:
                self.assertNotIn(
                    pattern, name,
                    f"forbidden pattern '{pattern}' found in tool '{name}'",
                )

    def test_04_tool_annotations_read_only(self):
        for name, tool in self.tools.items():
            annotations = tool.annotations
            if annotations:
                ann_dict = annotations if isinstance(annotations, dict) else annotations.model_dump()
                self.assertTrue(
                    ann_dict.get("readOnlyHint", ann_dict.get("read_only_hint")),
                    f"{name} missing readOnlyHint=true",
                )

    def test_05_list_workspaces_returns_json(self):
        async def run():
            fn = self.tools["uam_list_workspaces"].fn
            result = await fn(ctx=None)
            data = json.loads(result)
            self.assertIn("workspaces", data)
            ids = [w["workspace_id"] for w in data["workspaces"]]
            self.assertIn("workspace-a", ids)
            return data
        asyncio.run(run())

    def test_06_workspace_snapshot_valid(self):
        async def run():
            fn = self.tools["uam_workspace_snapshot"].fn
            result = await fn(workspace_id="primary", ctx=None)
            data = json.loads(result)
            self.assertEqual(data["schema_version"], "workspace-snapshot-v1")
            self.assertEqual(data["workspace_id"], "primary")
            self.assertIn("repository", data)
            self.assertEqual(len(data["repository"]["head"]), 40)
            return data
        asyncio.run(run())

    def test_07_session_bootstrap_valid(self):
        async def run():
            fn = self.tools["uam_session_bootstrap"].fn
            result = await fn(workspace_id="primary", ctx=None, intent="test", max_bytes=65536)
            data = json.loads(result)
            self.assertEqual(data["schema_version"], "session-context-pack-v2")
            self.assertIn("repository", data)
            self.assertIn("context_profile", data)
            self.assertTrue(data["context_profile"]["configured"])
            return data
        asyncio.run(run())

    def test_08_git_internal_path_denied(self):
        async def run():
            fn = self.tools["uam_read_file"].fn
            result = await fn(workspace_id="primary", path=".git/config", ctx=None)
            data = json.loads(result)
            self.assertIn("error", data)
            self.assertIn(".git", data["error"])
        asyncio.run(run())

    def test_09_traversal_denied(self):
        async def run():
            fn = self.tools["uam_read_file"].fn
            result = await fn(workspace_id="primary", path="../../../etc/passwd", ctx=None)
            data = json.loads(result)
            self.assertIn("error", data)
        asyncio.run(run())

    def test_10_audit_verify(self):
        async def run():
            fn = self.tools["uam_verify_audit"].fn
            result = await fn(ctx=None)
            data = json.loads(result)
            self.assertEqual(data["integrity"], "PASS")
            self.assertGreater(data["records"], 0)
        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
