"""Workspace registration and observation E2E using portable synthetic git fixtures."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.errors import PathPolicyError, WorkspaceError
from synthetic_fixtures import init_git_repo, write_workspace_registry


class SyntheticWorkspaceE2ETests(unittest.TestCase):
    """Portable workspace registration with synthetic git repositories."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="uam-real-workspace-e2e-")
        cls.root = Path(cls._tmp.name)
        cls.repo_a = cls.root / "workspace-a"
        cls.repo_b = cls.root / "workspace-b"
        init_git_repo(cls.repo_a, files={"README.md": "# workspace A\nimport json\n"})
        init_git_repo(cls.repo_b, files={"README.md": "# workspace B\nimport sys\n"})
        cls.registry_path = write_workspace_registry(
            cls.root / "workspaces.json",
            [
                {
                    "workspace_id": "workspace-a",
                    "project_id": "project-a",
                    "role": "canonical-main",
                    "root": str(cls.repo_a),
                    "kind": "git-repository",
                    "capabilities": ["filesystem.read", "git.observe"],
                },
                {
                    "workspace_id": "workspace-b",
                    "project_id": "project-b",
                    "role": "canonical-main",
                    "root": str(cls.repo_b),
                    "kind": "git-repository",
                    "capabilities": ["filesystem.read", "git.observe"],
                },
            ],
        )
        cls.state_dir = tempfile.mkdtemp(prefix="uam_real_test_")
        cls.gw = MiddlewareGateway(
            registry_path=str(cls.registry_path),
            state_dir=cls.state_dir,
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.state_dir, ignore_errors=True)
        cls._tmp.cleanup()

    def test_01_both_workspaces_listed(self):
        result = self.gw.list_workspaces()
        ids = [w["workspace_id"] for w in result["workspaces"]]
        self.assertIn("workspace-a", ids)
        self.assertIn("workspace-b", ids)
        self.assertGreaterEqual(len(ids), 2)

    def test_02_workspace_a_tree(self):
        result = self.gw.tree("workspace-a", ".", depth=1)
        self.assertIn("entries", result)
        self.assertGreater(len(result["entries"]), 0)

    def test_03_workspace_b_tree(self):
        result = self.gw.tree("workspace-b", ".", depth=1)
        self.assertIn("entries", result)
        self.assertGreater(len(result["entries"]), 0)

    def test_04_workspace_a_git_status(self):
        result = self.gw.git_status("workspace-a")
        self.assertIn("head", result)
        self.assertEqual(len(result["head"]), 40)
        self.assertIn("branch", result)
        self.assertIn("status", result)

    def test_05_workspace_b_git_status(self):
        result = self.gw.git_status("workspace-b")
        self.assertIn("head", result)
        self.assertEqual(len(result["head"]), 40)

    def test_06_workspace_a_git_log(self):
        result = self.gw.git_log("workspace-a", limit=5)
        self.assertIn("commits", result)
        self.assertGreater(len(result["commits"]), 0)
        first = result["commits"][0]
        self.assertIn("sha", first)
        self.assertIn("subject", first)

    def test_07_workspace_b_git_log(self):
        result = self.gw.git_log("workspace-b", limit=5)
        self.assertIn("commits", result)
        self.assertGreater(len(result["commits"]), 0)

    def test_08_cross_workspace_path_denied(self):
        with self.assertRaises((PathPolicyError, WorkspaceError)):
            self.gw.read_file("workspace-a", "../workspace-b/README.md")

    def test_09_traversal_denied(self):
        with self.assertRaises((PathPolicyError, WorkspaceError)):
            self.gw.read_file("workspace-b", "../../etc/passwd")

    def test_10_unknown_workspace_denied(self):
        with self.assertRaises(WorkspaceError):
            self.gw.tree("nonexistent", ".")

    def test_11_state_isolation_verified(self):
        state = Path(self.state_dir)
        self.assertFalse(str(state).startswith(str(self.repo_a)), "state must not be inside workspace-a")
        self.assertFalse(str(state).startswith(str(self.repo_b)), "state must not be inside workspace-b")

    def test_12_workspace_a_search(self):
        result = self.gw.search("workspace-a", "import", path=".", max_results=10)
        self.assertIn("results", result)
        self.assertGreater(len(result["results"]), 0)

    def test_13_workspace_b_search(self):
        result = self.gw.search("workspace-b", "import", path=".", max_results=10)
        self.assertIn("results", result)
        self.assertGreater(len(result["results"]), 0)

    def test_14_audit_log_created(self):
        audit_path = Path(self.state_dir) / "audit.jsonl"
        self.assertTrue(audit_path.exists())
        lines = audit_path.read_text().strip().splitlines()
        self.assertGreater(len(lines), 0)
        first = json.loads(lines[0])
        self.assertIn("action", first)
        self.assertIn("record_hash", first)
        self.assertIn("previous_hash", first)


@unittest.skipUnless(
    os.environ.get("UAM_REAL_WORKSPACE_E2E") == "1",
    "Operator-only real workspace E2E disabled; set UAM_REAL_WORKSPACE_E2E=1 to enable",
)
class OperatorRealWorkspaceE2ETests(unittest.TestCase):
    """Optional operator validation against live workspace registry paths."""

    @classmethod
    def setUpClass(cls):
        registry = os.environ.get("UAM_REAL_WORKSPACE_REGISTRY")
        if not registry or not Path(registry).is_file():
            raise unittest.SkipTest("UAM_REAL_WORKSPACE_REGISTRY must point to a workspace registry file")
        cls.registry_path = registry
        cls.state_dir = tempfile.mkdtemp(prefix="uam_operator_e2e_")
        cls.gw = MiddlewareGateway(registry_path=registry, state_dir=cls.state_dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.state_dir, ignore_errors=True)

    def test_operator_registry_lists_workspaces(self):
        result = self.gw.list_workspaces()
        self.assertIn("workspaces", result)
        self.assertGreaterEqual(len(result["workspaces"]), 1)


if __name__ == "__main__":
    unittest.main()
