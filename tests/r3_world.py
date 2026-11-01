"""Shared harness of the r3 security-closure tests: a disposable world, a server over it, two ways to call a tool.

A tool is reached the way a client reaches it:

* ``call_direct`` runs the tool body (what a client's request ends up executing) and reports an exception that escapes
  the body as ``RAISED <ExceptionType>``: a body that raises instead of answering is a finding, not a crash of the test;
* ``call_protocol`` goes through a real MCP client session over the SDK's in-memory transport, so the JSON-RPC framing,
  the tool result envelope and the SDK's own error handling are part of what is observed.

Everything in a world is synthetic: fictional markers, a private registry, a private state directory, nothing inherited.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from directory_fixtures import authority_dict, static_repository
from synthetic_fixtures import init_git_repo, write_workspace_registry

try:
    from mcp.client import Client
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:  # the MCP SDK is an optional extra
    Client = None  # type: ignore[assignment,misc]
    create_session_read_server = None  # type: ignore[assignment]

SCOPE_ID = "data-scope"
STATIC_ID = "static-repo"
DERIVED_REPO = f"derived:{SCOPE_ID}:repo"

DEFAULT_FILES = {
    "README.md": "# repo\nvisible readme line\n",
    "notes.txt": "visible note\n",
    "other.txt": "other visible text\n",
    "src/app.py": "def main():\n    return 'visible'\n",
}


class ProtocolWorld:
    """``<base>/data/repo`` (a Git repository, registered as ``static-repo``) inside the scope ``data-scope``."""

    def __init__(
        self,
        *,
        files: dict[str, str] | None = None,
        extra_workspaces: Iterable[dict[str, Any]] = (),
        with_scope: bool = True,
        scope_authority: dict[str, bool] | None = None,
    ) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="uam-r3-world-")
        self.base = Path(self._tmp.name).resolve()
        self.data = self.base / "data"
        self.repo = self.data / "repo"
        self.config = self.base / "config"
        self.runs = 0
        self.config.mkdir(parents=True)
        init_git_repo(self.repo, files=files if files is not None else dict(DEFAULT_FILES))
        if with_scope:
            (self.config / "root_scopes.json").write_text(json.dumps({
                "schema_version": "root-scope-registry-v1",
                "scopes": [{
                    "scope_id": SCOPE_ID, "root": str(self.data),
                    "authority": scope_authority or authority_dict(), "description": "r3 scope",
                }],
                "overrides": {},
            }, indent=2), encoding="utf-8")
        self.registry_path = write_workspace_registry(
            self.config / "workspaces.json", [static_repository(STATIC_ID, self.repo), *extra_workspaces],
        )

    def cleanup(self) -> None:
        self._tmp.cleanup()

    def server(self):
        """A fresh server over this world with a fresh state directory (no cache survives between servers)."""
        self.runs += 1
        state = self.base / f"state-{self.runs}"
        state.mkdir()
        return create_session_read_server(registry_path=str(self.registry_path), state_dir=str(state))


async def call_direct(server, name: str, **arguments: Any) -> str:
    function = server._tool_manager._tools[name].fn
    try:
        return await function(ctx=None, **arguments)
    except Exception as exc:
        return f"RAISED {type(exc).__name__}"


async def call_protocol(server, name: str, **arguments: Any) -> tuple[bool, str]:
    """``(is_error, text)`` of one tool call made through an MCP client session."""
    async with Client(server) as client:
        result = await client.call_tool(name, arguments)
    text = "\n".join(getattr(block, "text", "") for block in result.content)
    return bool(result.is_error), text


def run(coro):
    return asyncio.run(coro)


def decode(output: str) -> dict[str, Any]:
    """The JSON object a tool answered with; a non-JSON answer (an exception marker, free text) fails loudly."""
    try:
        value = json.loads(output)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"the tool did not answer with JSON: {output[:160]!r}") from exc
    if not isinstance(value, dict):
        raise AssertionError(f"the tool did not answer with a JSON object: {output[:160]!r}")
    return value
