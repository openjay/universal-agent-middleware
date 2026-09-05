import json
import unittest
from pathlib import Path


class AgentPluginPackageTests(unittest.TestCase):
    def setUp(self):
        self.root = Path("adapters/agent-plugin/universal-agent-middleware")

    def test_manifest_targets_agent_plugins_1_0_0_closed_core(self):
        manifest = json.loads((self.root / "plugin.json").read_text())
        self.assertEqual(manifest["$schema"], "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json")
        self.assertEqual(manifest["name"], "universal-agent-middleware")
        self.assertTrue(set(manifest).issubset({"$schema", "name", "version", "description", "author", "homepage", "repository", "license", "keywords", "extensions"}))

    def test_mcp_manifest_has_no_embedded_secret(self):
        mcp = json.loads((self.root / "mcp.json").read_text())
        self.assertEqual(mcp["$schema"], "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json")
        server = mcp["mcpServers"]["universal-agent-middleware"]
        self.assertEqual(server["type"], "streamable-http")
        self.assertEqual(server["url"], "http://127.0.0.1:8765/mcp")
        self.assertNotIn("headers", server, "portable package must not embed auth secrets")

    def test_skill_conforms_to_portable_floor(self):
        text = (self.root / "skills/uam-research-handoff/SKILL.md").read_text()
        self.assertTrue(text.startswith("---\n"))
        self.assertIn("name: uam-research-handoff", text)
        self.assertIn("description:", text)


if __name__ == "__main__":
    unittest.main()
