"""S1-TOOL-SURFACE-MATRIX: all 20 MCP tools, through the real server, against a world full of protected objects.

The unit tests next to each fix prove one mechanism. This module proves the property a client relies on, at the
boundary a client uses (the MCP tool bodies, which go through gateway, resolver, reader, Git observer, discovery,
exploration and the reality index):

    A protected object (a dotenv-family file, a credential directory, a tracked or untracked secret, a link to one,
    a remote URL that embeds a token) contributes NOTHING to what any tool returns.

Two checks, both over every tool:

* taint: no tool output (success or error) contains a marker that exists only inside a protected object;
* metamorphic: changing ONLY the fictional body of the protected objects (same names, same places) changes no tool
  output. A value that leaks through a count, a digest, a modified/unmodified flag or a snippet makes this fail even
  when the marker itself never appears.

Each run uses a fresh server and a fresh state directory so a cache from the previous run cannot hide a difference.
Controls keep the checks honest: two runs of the unchanged world must agree (so the normalisation covers all noise),
and a change to a VISIBLE file must be seen (so the comparison is not blind).

The module uses only the public server factory and the policy's own ``should_hide_path``, so it also runs against
an older release: that run is the old-version counterexample (it fails there by design).
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from universal_agent_middleware.policy import should_hide_path

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:  # the MCP SDK is an optional extra
    create_session_read_server = None  # type: ignore[assignment]

from directory_fixtures import authority_dict, static_repository
from synthetic_fixtures import init_git_repo, write_workspace_registry

SCOPE_ID = "data-scope"
STATIC_ID = "static-repo"
DERIVED_REPO = f"derived:{SCOPE_ID}:repo"
DERIVED_PLAIN = f"derived:{SCOPE_ID}:plain"

BODY_A = "S1_MATRIX_PROTECTED_BODY_A_0042"
BODY_B = "S1_MATRIX_PROTECTED_BODY_B_0042"
BODY_COMMITTED = "S1_MATRIX_COMMITTED_SECRET_0042"
REMOTE_TOKEN = "ghp_S1MatrixFictionalRemoteToken0042"
MARKERS = (BODY_A, BODY_B, BODY_COMMITTED, REMOTE_TOKEN)
# What the search tools are asked for. A response echoes its query, so a query must never BE a full marker: these are
# prefixes, and only a returned line (or a name, or a snippet) can contain a whole marker.
QUERIES = ("S1_MATRIX_PROTECTED_BODY", "S1_MATRIX_COMMITTED", "ghp_S1Matrix", "SECRET_VALUE", "visible")

VISIBLE_NOTE = "S1_MATRIX_VISIBLE_NOTE_LINE\n"

# Protected places, relative to the data root. ``tracked`` ones are committed (so a later body change is a Git
# modification); the others only exist in the working tree.
TRACKED_PROTECTED = ("repo/.env.production", "repo/cfg/.env")
UNTRACKED_PROTECTED = (
    "repo/.secrets.env", "repo/.env.local", "repo/.ssh/config",
    "plain/.env", "plain/.aws/credentials",
)
LINKS = {"repo/link-to-secret": ".secrets.env"}

# Keys whose value is a clock reading, an identity of this server process or a cache state: they differ between two
# runs of an identical world and carry no information about protected content.
VOLATILE_KEYS = frozenset({
    "observed_at", "generated_at", "timestamp", "started_at", "uptime_since", "cache_age_ms", "duration_ms",
    "elapsed_ms", "pid", "instance_id", "writer_instance_id", "index_generation", "age_sec", "ts", "time",
    "expires_in_ms", "served_at", "loaded_at", "request_id",
})
# Tools whose output counts server-side events (each call is itself an audit event): taint-checked, not compared.
NOT_COMPARABLE = frozenset({"uam_verify_audit"})

ALL_TOOLS = frozenset({
    "uam_list_workspaces", "uam_workspace_snapshot", "uam_session_bootstrap", "uam_tree", "uam_read_file",
    "uam_file_digest", "uam_search_text", "uam_git_status", "uam_git_diff", "uam_git_log", "uam_verify_audit",
    "uam_project_reality", "uam_list_project_instances", "uam_list_scopes", "uam_discover_projects",
    "uam_scope_inventory", "uam_search_scope", "uam_explain_coverage", "uam_what_am_i_missing", "uam_explore",
})


def scrub(value: Any) -> Any:
    """The JSON value without volatile keys, so that two runs of the same world compare equal."""
    if isinstance(value, dict):
        return {key: scrub(item) for key, item in sorted(value.items()) if key not in VOLATILE_KEYS}
    if isinstance(value, list):
        return [scrub(item) for item in value]
    return value


def normalise(output: str) -> Any:
    try:
        return scrub(json.loads(output))
    except json.JSONDecodeError:
        return output


class ToolWorld:
    """One disposable world and the means to start a fresh server over it."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="uam-s1-matrix-")
        self.base = Path(self._tmp.name).resolve()
        self.data = self.base / "data"
        self.config = self.base / "config"
        self.repo = self.data / "repo"
        self.plain = self.data / "plain"
        self.runs = 0
        self._build()

    def cleanup(self) -> None:
        self._tmp.cleanup()

    def _build(self) -> None:
        self.config.mkdir(parents=True)
        self.plain.mkdir(parents=True)
        init_git_repo(self.repo, files={
            "README.md": "# repo\nvisible readme line\n",
            "notes.txt": VISIBLE_NOTE,
            "src/app.py": "def main():\n    return 'visible'\n",
            ".env.production": f"DB_PASSWORD={BODY_COMMITTED}\n",
            "cfg/.env": f"API_TOKEN={BODY_COMMITTED}\n",
        })
        subprocess.run(
            ["git", "remote", "add", "origin", f"https://octo:{REMOTE_TOKEN}@github.com/acme/widget.git"],
            cwd=str(self.repo), check=True, capture_output=True, timeout=10,
        )
        (self.plain / "docs.md").write_text("plain visible document\n", encoding="utf-8")
        for rel in (*TRACKED_PROTECTED, *UNTRACKED_PROTECTED):
            (self.data / rel).parent.mkdir(parents=True, exist_ok=True)
        self.write_protected(BODY_A)
        for rel, target in LINKS.items():
            os.symlink(target, self.data / rel)
        (self.config / "root_scopes.json").write_text(json.dumps({
            "schema_version": "root-scope-registry-v1",
            "scopes": [{
                "scope_id": SCOPE_ID, "root": str(self.data),
                "authority": authority_dict(), "description": "matrix scope",
            }],
            "overrides": {},
        }, indent=2), encoding="utf-8")
        self.registry_path = write_workspace_registry(
            self.config / "workspaces.json", [static_repository(STATIC_ID, self.repo)],
        )

    def write_protected(self, body: str) -> None:
        """Replace the body of every protected object, keeping every name and place."""
        for rel in (*TRACKED_PROTECTED, *UNTRACKED_PROTECTED):
            (self.data / rel).write_text(f"SECRET_VALUE={body}\n", encoding="utf-8")

    def restore_tracked_protected(self) -> None:
        """Put the tracked protected files back to their committed bytes: Git then sees them as unmodified."""
        relative = [Path(rel).relative_to("repo").as_posix() for rel in TRACKED_PROTECTED]
        subprocess.run(
            ["git", "checkout", "--", *relative], cwd=str(self.repo), check=True, capture_output=True, timeout=10,
        )

    def protected_paths(self) -> list[Path]:
        return [self.data / rel for rel in (*TRACKED_PROTECTED, *UNTRACKED_PROTECTED)]

    def server(self):
        self.runs += 1
        state = self.base / f"state-{self.runs}"
        state.mkdir()
        return create_session_read_server(registry_path=str(self.registry_path), state_dir=str(state))


async def call(server, name: str, **arguments: Any) -> str:
    function = server._tool_manager._tools[name].fn
    try:
        return await function(ctx=None, **arguments)
    except Exception as exc:  # a tool that raises instead of reporting is a finding, not a crash of the matrix
        return f"RAISED {type(exc).__name__}"


async def run_matrix(server) -> dict[str, str]:
    """Every tool, several targets each (static workspace, derived repository, derived plain directory, scope)."""
    out: dict[str, str] = {}

    async def record(label: str, tool: str, **arguments: Any) -> str:
        out[f"{tool}|{label}"] = result = await call(server, tool, **arguments)
        return result

    await record("-", "uam_list_workspaces")
    await record("-", "uam_list_scopes")
    for workspace in (STATIC_ID, DERIVED_REPO):
        await record(workspace, "uam_workspace_snapshot", workspace_id=workspace)
        await record(workspace, "uam_session_bootstrap", workspace_id=workspace, intent="inspect secrets and env")
        await record(workspace, "uam_git_status", workspace_id=workspace)
        await record(f"{workspace}|whole", "uam_git_diff", workspace_id=workspace)
        await record(f"{workspace}|dot", "uam_git_diff", workspace_id=workspace, path=".")
        await record(f"{workspace}|denied", "uam_git_diff", workspace_id=workspace, path=".env.production")
        await record(f"{workspace}|dir", "uam_git_diff", workspace_id=workspace, path="cfg")  # a directory holding one
        await record(workspace, "uam_git_log", workspace_id=workspace, limit=5)
    for workspace in (STATIC_ID, DERIVED_REPO, DERIVED_PLAIN):
        await record(workspace, "uam_tree", workspace_id=workspace, path=".", depth=4)
    for workspace, visible in ((STATIC_ID, "notes.txt"), (DERIVED_REPO, "notes.txt"), (DERIVED_PLAIN, "docs.md")):
        await record(f"{workspace}|{visible}", "uam_read_file", workspace_id=workspace, path=visible)
        await record(f"{workspace}|{visible}", "uam_file_digest", workspace_id=workspace, path=visible)
    for workspace, denied in (
        (STATIC_ID, ".secrets.env"), (STATIC_ID, ".env.production"), (STATIC_ID, "cfg/.env"),
        (STATIC_ID, "link-to-secret"), (DERIVED_REPO, ".secrets.env"), (DERIVED_REPO, "link-to-secret"),
        (DERIVED_REPO, ".ssh/config"), (DERIVED_PLAIN, ".env"), (DERIVED_PLAIN, ".aws/credentials"),
    ):
        await record(f"{workspace}|{denied}", "uam_read_file", workspace_id=workspace, path=denied)
        await record(f"{workspace}|{denied}", "uam_file_digest", workspace_id=workspace, path=denied)
    for workspace in (STATIC_ID, DERIVED_REPO, DERIVED_PLAIN):
        for query in QUERIES:
            await record(f"{workspace}|{query}", "uam_search_text", workspace_id=workspace, query=query)
    await record("-", "uam_verify_audit")

    discovered = await record(SCOPE_ID, "uam_discover_projects", scope_id=SCOPE_ID)
    await record(SCOPE_ID, "uam_scope_inventory", scope_id=SCOPE_ID)
    projects = json.loads(discovered).get("projects", []) if discovered.startswith("{") else []
    project_ids = [project["project_id"] for project in projects if isinstance(project, dict) and "project_id" in project]
    for project_id in project_ids or ["widget"]:
        await record(project_id, "uam_project_reality", project_id=project_id)
        await record(project_id, "uam_list_project_instances", project_id=project_id)
        await record(project_id, "uam_explain_coverage", scope_id=SCOPE_ID, project_id=project_id)
    for query in QUERIES:
        await record(query, "uam_search_scope", scope_id=SCOPE_ID, query=query)
    await record(SCOPE_ID, "uam_what_am_i_missing", scope_id=SCOPE_ID)
    await record(SCOPE_ID, "uam_explore", scope_id=SCOPE_ID, intent="env secrets credentials")
    return out


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class ToolSurfaceMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.world = ToolWorld()
        cls.addClassCleanup(cls.world.cleanup)
        cls.run_a1 = asyncio.run(run_matrix(cls.world.server()))
        cls.run_a2 = asyncio.run(run_matrix(cls.world.server()))
        cls.world.write_protected(BODY_B)  # ONLY the bodies of the protected objects change
        cls.run_b = asyncio.run(run_matrix(cls.world.server()))
        cls.world.restore_tracked_protected()  # ...and back to the committed bytes: a "modified" flag must not exist
        cls.run_c = asyncio.run(run_matrix(cls.world.server()))

    @staticmethod
    def tool_of(key: str) -> str:
        return key.split("|", 1)[0]

    def test_the_matrix_covers_every_tool_of_the_profile(self) -> None:
        server = self.world.server()
        self.assertEqual(set(server._tool_manager._tools), set(ALL_TOOLS))
        covered = {self.tool_of(key) for key in self.run_a1}
        self.assertEqual(covered, set(ALL_TOOLS))

    def test_the_fixture_really_contains_protected_objects(self) -> None:
        for path in self.world.protected_paths():
            self.assertTrue(path.is_file(), path)
            self.assertTrue(should_hide_path(self.world.data, path), f"{path} is not protected by the name policy")

    def test_no_tool_output_contains_what_only_a_protected_object_holds(self) -> None:
        for label, run in (("A1", self.run_a1), ("A2", self.run_a2), ("B", self.run_b), ("C", self.run_c)):
            for key, output in run.items():
                for marker in MARKERS:
                    self.assertNotIn(marker, output, f"run {label}: {key} returned protected content")

    def test_changing_only_protected_bodies_changes_no_tool_output(self) -> None:
        differing = []
        for key in sorted(self.run_a2):
            if self.tool_of(key) in NOT_COMPARABLE:
                continue
            for label, run in (("B", self.run_b), ("C", self.run_c)):
                if normalise(self.run_a2[key]) != normalise(run[key]):
                    differing.append(f"{key} (A vs {label})")
        self.assertEqual(differing, [], "outputs depend on the content of protected objects")

    def test_control_two_runs_of_an_unchanged_world_agree(self) -> None:
        differing = [
            key for key in sorted(self.run_a1)
            if self.tool_of(key) not in NOT_COMPARABLE and normalise(self.run_a1[key]) != normalise(self.run_a2[key])
        ]
        self.assertEqual(differing, [], "the comparison is noisy: extend VOLATILE_KEYS or fix the nondeterminism")

    def test_control_every_tool_actually_answered(self) -> None:
        raised = [key for key, output in self.run_a1.items() if output.startswith("RAISED")]
        self.assertEqual(raised, [])
        for key, output in self.run_a1.items():
            self.assertTrue(output.strip(), f"{key} returned nothing")


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class MatrixPowerTests(unittest.TestCase):
    """The comparison is not blind: it sees a change it is ALLOWED to see."""

    def test_a_change_to_a_visible_file_is_visible_in_the_outputs(self) -> None:
        world = ToolWorld()
        self.addCleanup(world.cleanup)
        before = asyncio.run(run_matrix(world.server()))
        (world.repo / "notes.txt").write_text("a different visible line\n", encoding="utf-8")
        after = asyncio.run(run_matrix(world.server()))
        changed = {
            key.split("|", 1)[0] for key in before
            if key.split("|", 1)[0] not in NOT_COMPARABLE and normalise(before[key]) != normalise(after[key])
        }
        self.assertIn("uam_read_file", changed)
        self.assertIn("uam_file_digest", changed)

    def test_a_protected_marker_would_be_caught_by_the_taint_check(self) -> None:
        world = ToolWorld()
        self.addCleanup(world.cleanup)
        (world.repo / "notes.txt").write_text(f"{BODY_A} placed in a VISIBLE file\n", encoding="utf-8")
        run = asyncio.run(run_matrix(world.server()))
        tainted = [key for key, output in run.items() if BODY_A in output]
        self.assertTrue(tainted, "the markers are never searched for or never returned: the taint check proves nothing")
        self.assertTrue(any(key.startswith("uam_read_file|") for key in tainted))


if __name__ == "__main__":
    unittest.main()
