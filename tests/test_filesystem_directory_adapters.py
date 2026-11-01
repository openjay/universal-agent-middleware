"""The refusal diagnostics of the ``filesystem-directory`` kind reach every northbound adapter.

Three adapters format errors differently (official SDK, HTTP, stdio MCP). Each must carry the
machine-readable ``diagnostic`` next to its existing message, and must stay byte-compatible
for errors that have none.
"""
from __future__ import annotations

import asyncio
import json
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.mcp import MCP_PROTOCOL_VERSION, MCPDispatcher
from universal_agent_middleware.server import Handler, UAMHTTPServer

from directory_fixtures import PLAIN_ID, WorldTestCase, static_directory

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:
    create_session_read_server = None  # type: ignore[assignment]

DIRECTORY_KIND = "filesystem-directory"


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class TestSdkAdapter(WorldTestCase):
    def _tools(self, **scope_overrides: bool) -> dict[str, Any]:
        self.world.write_scope_file(**scope_overrides)
        self.world.write_registry([static_directory("plain-static", self.world.plain)])
        server = create_session_read_server(
            registry_path=str(self.world.registry_path), state_dir=str(self.world.state),
        )
        return server._tool_manager._tools

    @staticmethod
    def _call(tools: dict[str, Any], name: str, **kwargs: Any) -> dict[str, Any]:
        return json.loads(asyncio.run(tools[name].fn(**kwargs, ctx=None)))

    def test_read_tools_serve_derived_and_static_directory_workspaces(self) -> None:
        tools = self._tools()
        listing = self._call(tools, "uam_tree", workspace_id=PLAIN_ID)
        self.assertIn("README.md", {entry["path"] for entry in listing["entries"]})
        self.assertIn(
            "needle-markdown",
            self._call(tools, "uam_read_file", workspace_id=PLAIN_ID, path="README.md")["content"],
        )
        found = self._call(tools, "uam_search_text", workspace_id="plain-static", query="needle")
        self.assertIn("README.md", {hit["path"] for hit in found["results"]})

    def test_git_dependent_tools_refuse_with_the_diagnostic(self) -> None:
        tools = self._tools()
        for name in ("uam_git_status", "uam_git_diff", "uam_git_log",
                     "uam_workspace_snapshot", "uam_session_bootstrap"):
            for workspace_id in (PLAIN_ID, "plain-static"):
                with self.subTest(tool=name, workspace=workspace_id):
                    payload = self._call(tools, name, workspace_id=workspace_id)
                    self.assertIn(DIRECTORY_KIND, payload["error"])
                    self.assertEqual(payload["diagnostic"]["status"], "UNSUPPORTED_CAPABILITY")
                    self.assertEqual(payload["diagnostic"]["workspace_kind"], DIRECTORY_KIND)

    def test_default_off_refusal_names_the_owner_actions(self) -> None:
        tools = self._tools(directory_admit=False)
        payload = self._call(tools, "uam_tree", workspace_id=PLAIN_ID)
        self.assertEqual(payload["diagnostic"]["status"], "UNSUPPORTED_WORKSPACE_KIND")
        self.assertEqual(payload["diagnostic"]["reason"], "NON_GIT_DIRECTORY")
        self.assertIn("ENABLE_DIRECTORY_ADMISSION", payload["diagnostic"]["suggested_actions"])

    def test_errors_without_a_diagnostic_keep_their_exact_shape(self) -> None:
        tools = self._tools()
        payload = self._call(tools, "uam_read_file", workspace_id=PLAIN_ID, path=".env")
        self.assertEqual(set(payload), {"error"})

    def test_listing_shows_the_kind_and_no_host_paths(self) -> None:
        tools = self._tools()
        listing = self._call(tools, "uam_list_workspaces")
        registered = {w["workspace_id"]: w for w in listing["registered"]}
        self.assertEqual(registered["plain-static"]["kind"], DIRECTORY_KIND)
        self.assertEqual(registered["plain-static"]["capabilities"], ["filesystem.read"])
        self.assertEqual(listing["coverage"]["basis"], "registered_workspaces")
        self.assertNotIn(str(self.world.root), json.dumps(listing))


class TestHttpAdapter(WorldTestCase):
    TOKEN = "x" * 48

    def setUp(self) -> None:
        super().setUp()
        self.gateway = self.world.gateway([static_directory("plain-static", self.world.plain)])
        self._serve(self.gateway)

    def _serve(self, gateway: MiddlewareGateway) -> None:
        server = UAMHTTPServer(("127.0.0.1", 0), Handler, gateway=gateway, bearer_token=self.TOKEN)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.port = server.server_address[1]

        def stop() -> None:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.addCleanup(stop)

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, method=method)
        request.add_header("Content-Type", "application/json")
        request.add_header("Authorization", f"Bearer {self.TOKEN}")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_read_and_tree_work_for_a_derived_directory(self) -> None:
        quoted = urllib.parse.quote(PLAIN_ID, safe="")
        status, tree = self._request("GET", f"/v1/tree?workspace_id={quoted}&depth=1")
        self.assertEqual(status, 200)
        self.assertIn("README.md", {entry["path"] for entry in tree["entries"]})
        status, read = self._request("POST", "/v1/read", {"workspace_id": PLAIN_ID, "path": "tool.py"})
        self.assertEqual(status, 200)
        self.assertIn("needle-python", read["content"])

    def test_git_endpoint_refuses_with_the_diagnostic(self) -> None:
        status, body = self._request("GET", "/v1/git/status?workspace_id=plain-static")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "WorkspaceError")
        self.assertIn("git.observe", body["message"])
        self.assertEqual(body["diagnostic"]["status"], "UNSUPPORTED_CAPABILITY")

    def test_errors_without_a_diagnostic_keep_their_exact_shape(self) -> None:
        status, body = self._request("POST", "/v1/read", {"workspace_id": PLAIN_ID, "path": ".env"})
        self.assertEqual(status, 400)
        self.assertEqual(set(body), {"error", "message"})

    def test_default_off_refusal_is_reported_over_http(self) -> None:
        gateway = self.world.gateway(scope=self.world.scope(directory_admit=False))
        self._serve(gateway)
        quoted = urllib.parse.quote(PLAIN_ID, safe="")
        status, body = self._request("GET", f"/v1/tree?workspace_id={quoted}")
        self.assertEqual(status, 400)
        self.assertEqual(body["diagnostic"]["reason"], "NON_GIT_DIRECTORY")


class TestStdioMcpAdapter(WorldTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.dispatcher = MCPDispatcher(
            self.world.gateway([static_directory("plain-static", self.world.plain)])
        )

    @staticmethod
    def _request(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": name, "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "1"},
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        }

    def test_git_tool_refusal_carries_the_diagnostic(self) -> None:
        result = self.dispatcher.dispatch(
            self._request("uam.git.status", {"workspace_id": "plain-static"})
        )["result"]
        self.assertTrue(result["isError"])
        payload = result["structuredContent"]
        self.assertEqual(payload["error"], "WorkspaceError")
        self.assertEqual(payload["diagnostic"]["workspace_kind"], DIRECTORY_KIND)
        self.assertEqual(json.loads(result["content"][0]["text"]), payload)

    def test_read_tool_serves_a_directory_and_plain_errors_keep_their_shape(self) -> None:
        ok = self.dispatcher.dispatch(
            self._request("uam.workspace.read", {"workspace_id": "plain-static", "path": "README.md"})
        )["result"]
        self.assertFalse(ok["isError"])
        failed = self.dispatcher.dispatch(
            self._request("uam.workspace.read", {"workspace_id": "plain-static", "path": ".env"})
        )["result"]
        self.assertEqual(set(failed["structuredContent"]), {"error", "message"})


if __name__ == "__main__":
    unittest.main()
