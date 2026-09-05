import json
import tempfile
import unittest
from pathlib import Path

from universal_agent_middleware.workspace import WorkspaceReader, WorkspaceRegistry


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name, "repo")
        root.mkdir()
        Path(root, "README.md").write_text("alpha\nbeta target\ngamma\n", encoding="utf-8")
        Path(root, ".env").write_text("SECRET=x", encoding="utf-8")
        registry = Path(self.tmp.name, "workspaces.json")
        registry.write_text(json.dumps({"registry_version": "uam-workspace-registry-v1", "workspaces": [{"workspace_id": "x", "root": str(root), "kind": "git-repository", "capabilities": ["filesystem.read", "git.observe"]}]}))
        self.spec = WorkspaceRegistry(registry).get("x")
        self.reader = WorkspaceReader(self.spec)

    def tearDown(self):
        self.tmp.cleanup()

    def test_registry_version_and_unknown_fields_fail_closed(self):
        root = Path(self.spec.root)
        bad = Path(self.tmp.name, "bad-registry.json")
        bad.write_text(json.dumps({"workspaces": [{"workspace_id": "z", "root": str(root), "kind": "git-repository", "capabilities": ["filesystem.read", "git.observe"]}]}))
        with self.assertRaises(Exception):
            WorkspaceRegistry(bad)
        bad.write_text(json.dumps({
            "registry_version": "uam-workspace-registry-v1",
            "workspaces": [{"workspace_id": "z", "root": str(root), "kind": "git-repository", "capabilities": ["filesystem.read", "git.observe"], "vendor_magic": True}]
        }))
        with self.assertRaises(Exception):
            WorkspaceRegistry(bad)
        bad.write_text(json.dumps({
            "registry_version": "uam-workspace-registry-v1",
            "workspaces": [{"workspace_id": "z", "root": str(root), "kind": "git-repository"}]
        }))
        with self.assertRaises(Exception):
            WorkspaceRegistry(bad)

    def test_tree_hides_secret(self):
        paths = {entry["path"] for entry in self.reader.tree()["entries"]}
        self.assertIn("README.md", paths)
        self.assertNotIn(".env", paths)

    def test_read_range(self):
        result = self.reader.read_file("README.md", start_line=2, end_line=2)
        self.assertEqual(result["content"], "beta target")

    def test_search(self):
        result = self.reader.search_text("TARGET")
        self.assertEqual(result["results"][0]["line"], 2)

    def test_tree_and_search_skip_symlink_escape(self):
        outside = Path(self.tmp.name, "outside.txt")
        outside.write_text("EXTERNAL_NEEDLE", encoding="utf-8")
        link = Path(self.spec.root, "escape-link.txt")
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        paths = {entry["path"] for entry in self.reader.tree()["entries"]}
        self.assertNotIn("escape-link.txt", paths)
        result = self.reader.search_text("EXTERNAL_NEEDLE")
        self.assertEqual(result["results"], [])


if __name__ == "__main__":
    unittest.main()
