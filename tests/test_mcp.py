import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.mcp import MCPDispatcher, MCP_PROTOCOL_VERSION


class MCPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        repo = Path(self.tmp.name, "repo")
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "UAM MCP Test"], check=True)
        Path(repo, "README.md").write_text("hello middleware\nneedle\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
        registry = Path(self.tmp.name, "workspaces.json")
        registry.write_text(json.dumps({"registry_version": "uam-workspace-registry-v1", "workspaces": [{"workspace_id": "w", "root": str(repo), "kind": "git-repository", "capabilities": ["filesystem.read", "git.observe"]}]}))
        self.dispatcher = MCPDispatcher(MiddlewareGateway(str(registry), str(Path(self.tmp.name, "state"))))

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, method, params=None, request_id=1):
        params = dict(params or {})
        meta = dict(params.get("_meta", {}))
        meta.update({
            "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "1"},
            "io.modelcontextprotocol/clientCapabilities": {},
        })
        params["_meta"] = meta
        return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}

    def test_discover(self):
        out = self.dispatcher.dispatch(self.request("server/discover"))
        self.assertEqual(out["result"]["supportedVersions"], [MCP_PROTOCOL_VERSION])
        self.assertEqual(out["result"]["resultType"], "complete")
        self.assertEqual(out["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "universal-agent-middleware")

    def test_tools_list_is_deterministic(self):
        a = self.dispatcher.dispatch(self.request("tools/list", request_id=1))["result"]["tools"]
        b = self.dispatcher.dispatch(self.request("tools/list", request_id=2))["result"]["tools"]
        self.assertEqual([x["name"] for x in a], [x["name"] for x in b])
        self.assertIn("uam.workspace.read", {x["name"] for x in a})
        self.assertIn("uam.contract.create", {x["name"] for x in a})

    def test_tool_call(self):
        out = self.dispatcher.dispatch(self.request("tools/call", {
            "name": "uam.workspace.search",
            "arguments": {"workspace_id": "w", "query": "needle"},
        }))
        self.assertFalse(out["result"]["isError"])
        self.assertEqual(out["result"]["structuredContent"]["results"][0]["line"], 2)

    def test_missing_envelope_fails_closed(self):
        out = self.dispatcher.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        self.assertEqual(out["error"]["code"], -32022)
        self.assertIsNone(out["error"]["data"]["requested"])

    def test_unsupported_protocol_version_is_structured(self):
        request = self.request("tools/list")
        request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = "2099-01-01"
        out = self.dispatcher.dispatch(request)
        self.assertEqual(out["error"]["code"], -32022)
        self.assertEqual(out["error"]["data"]["supported"], [MCP_PROTOCOL_VERSION])
        self.assertEqual(out["error"]["data"]["requested"], "2099-01-01")


if __name__ == "__main__":
    unittest.main()
