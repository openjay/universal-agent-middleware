import json
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.mcp import MCP_PROTOCOL_VERSION
from universal_agent_middleware.server import Handler, UAMHTTPServer


class MCPHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        repo = Path(cls.tmp.name, "repo")
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "UAM HTTP Test"], check=True)
        Path(repo, "README.md").write_text("hello\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
        registry = Path(cls.tmp.name, "workspaces.json")
        registry.write_text(json.dumps({"registry_version": "uam-workspace-registry-v1", "workspaces": [{"workspace_id": "w", "root": str(repo), "kind": "git-repository", "capabilities": ["filesystem.read", "git.observe"]}]}))
        cls.token = "m" * 48
        server = UAMHTTPServer(
            ("127.0.0.1", 0),
            Handler,
            gateway=MiddlewareGateway(str(registry), str(Path(cls.tmp.name, "state"))),
            bearer_token=cls.token,
            allowed_origins={"https://client.example"},
        )
        cls.server = server
        cls.port = server.server_address[1]
        cls.thread = threading.Thread(target=server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.tmp.cleanup()

    def post(self, body, *, method_header=None, name_header=None, origin="https://client.example"):
        data = json.dumps(body).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/mcp", data=data, method="POST")
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        req.add_header("MCP-Protocol-Version", MCP_PROTOCOL_VERSION)
        req.add_header("Mcp-Method", method_header or body["method"])
        if name_header is not None:
            req.add_header("Mcp-Name", name_header)
        if origin is not None:
            req.add_header("Origin", origin)
        with urllib.request.urlopen(req, timeout=3) as response:
            return response.status, json.loads(response.read())

    @staticmethod
    def envelope(method, params=None):
        params = dict(params or {})
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {"name": "http-test", "version": "1"},
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}

    def test_tools_list_http(self):
        status, body = self.post(self.envelope("tools/list"))
        self.assertEqual(status, 200)
        self.assertTrue(body["result"]["tools"])

    def test_header_mismatch_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.post(self.envelope("tools/list"), method_header="tools/call")
        self.assertEqual(ctx.exception.code, 400)
        payload = json.loads(ctx.exception.read())
        self.assertEqual(payload["error"]["code"], -32020)

    def test_bad_origin_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.post(self.envelope("tools/list"), origin="https://evil.example")
        self.assertEqual(ctx.exception.code, 403)

    def test_tool_name_header_binding(self):
        body = self.envelope("tools/call", {"name": "uam.workspaces.list", "arguments": {}})
        status, result = self.post(body, name_header="uam.workspaces.list")
        self.assertEqual(status, 200)
        self.assertFalse(result["result"]["isError"])

    def test_wrong_content_type_rejected(self):
        body = self.envelope("tools/list")
        data = json.dumps(body).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/mcp", data=data, method="POST")
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Content-Type", "text/plain")
        req.add_header("Accept", "application/json, text/event-stream")
        req.add_header("MCP-Protocol-Version", MCP_PROTOCOL_VERSION)
        req.add_header("Mcp-Method", "tools/list")
        req.add_header("Origin", "https://client.example")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 415)

    def test_mcp_get_requires_auth_then_returns_405(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/mcp", method="GET")
        req.add_header("Origin", "https://client.example")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 401)
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/mcp", method="GET")
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Origin", "https://client.example")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 405)
        self.assertEqual(ctx.exception.headers.get("Allow"), "POST")

    def test_body_protocol_version_mismatch_returns_http_400(self):
        body = self.envelope("tools/list")
        body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = "2099-01-01"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.post(body)
        self.assertEqual(ctx.exception.code, 400)
        payload = json.loads(ctx.exception.read())
        self.assertEqual(payload["error"]["code"], -32022)
        self.assertEqual(payload["error"]["data"]["supported"], [MCP_PROTOCOL_VERSION])

    def test_header_protocol_version_mismatch_has_supported_data(self):
        body = self.envelope("tools/list")
        data = json.dumps(body).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/mcp", data=data, method="POST")
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        req.add_header("MCP-Protocol-Version", "2099-01-01")
        req.add_header("Mcp-Method", "tools/list")
        req.add_header("Origin", "https://client.example")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 400)
        payload = json.loads(ctx.exception.read())
        self.assertEqual(payload["error"]["code"], -32022)
        self.assertEqual(payload["error"]["data"]["requested"], "2099-01-01")


if __name__ == "__main__":
    unittest.main()
