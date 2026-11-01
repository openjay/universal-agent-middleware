"""UAM-01: a registered workspace whose root is gone must degrade alone.

Before this change `WorkspaceRegistry` resolved every root with `strict=True` at load, so
one missing directory aborted gateway initialisation and took every healthy workspace
down with it. The registry now keeps the declaration, refuses to serve it, and reports the
gap explicitly. These tests pin the safety properties of that degradation:

- healthy workspaces keep working and nothing is served that was not served before;
- the unavailable identity stays reserved, so it can never be silently rebound to another
  directory through the derived / bare-name resolution paths;
- the gap is visible (coverage, project reality, status endpoint) and never reads as complete.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from test_hardening import runtime_fixture  # noqa: F401  (pytest fixture import)
from synthetic_fixtures import init_git_repo, write_workspace_registry

from universal_agent_middleware import installer
from universal_agent_middleware import runtime as rt
from universal_agent_middleware.errors import WorkspaceError, WorkspaceUnavailableError
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.git_readonly import ReadOnlyGit
from universal_agent_middleware.project import _compute_coverage
from universal_agent_middleware.resolver import ResolutionError
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority
from universal_agent_middleware.server import Handler, UAMHTTPServer
from universal_agent_middleware.workspace import WorkspaceRegistry

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:  # pragma: no cover - MCP SDK is an optional test dependency
    create_session_read_server = None  # type: ignore[assignment]

HEALTHY_IDS = {"atlas", "ledger", "uam", "freshness"}
STALE_IDS = {"atlas-main", "atlas-pr7"}


def _entry(
    workspace_id: str,
    root: Path,
    *,
    project_id: str,
    role: str,
    lifecycle: str | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "workspace_id": workspace_id,
        "project_id": project_id,
        "role": role,
        "label": workspace_id,
        "root": str(root),
        "kind": "git-repository",
        "capabilities": ["filesystem.read", "git.observe"],
    }
    if lifecycle:
        entry["lifecycle"] = lifecycle
    return entry


class ProductionShapedRegistry(unittest.TestCase):
    """Two registrations whose roots no longer exist next to four valid ones."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="uam-unavailable-")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        for name in HEALTHY_IDS:
            init_git_repo(self.base / name, files={"README.md": f"# {name}\n"})
        self.gone_main = self.base / "gone" / "atlas-main"
        self.gone_pr = self.base / "gone" / "atlas-pr7"
        self.registry_path = write_workspace_registry(
            self.base / "config" / "workspaces.json",
            [
                _entry("atlas-main", self.gone_main, project_id="atlas", role="canonical-main"),
                _entry("atlas", self.base / "atlas", project_id="atlas", role="review-carrier"),
                _entry(
                    "atlas-pr7", self.gone_pr,
                    project_id="atlas", role="candidate", lifecycle="active",
                ),
                _entry("ledger", self.base / "ledger", project_id="ledger", role="canonical-main"),
                _entry("uam", self.base / "uam", project_id="uam", role="canonical-main"),
                _entry("freshness", self.base / "freshness", project_id="freshness", role="canonical-main"),
            ],
        )
        self.state_dir = self.base / "state"
        self.gw = MiddlewareGateway(str(self.registry_path), str(self.state_dir))


class RegistryDegradationTests(ProductionShapedRegistry):
    def test_gateway_initialises_and_serves_only_valid_workspaces(self) -> None:
        served = {w["workspace_id"] for w in self.gw.registry.list()}
        self.assertEqual(served, HEALTHY_IDS)

    def test_unavailable_workspaces_are_reported_with_reason(self) -> None:
        unavailable = {item["workspace_id"]: item for item in self.gw.registry.unavailable()}
        self.assertEqual(set(unavailable), STALE_IDS)
        for item in unavailable.values():
            self.assertEqual(item["reason"], "root_missing")

    def test_coverage_is_incomplete_and_does_not_leak_roots(self) -> None:
        coverage = self.gw.registry.coverage()
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["registered"], 6)
        self.assertEqual(coverage["available"], 4)
        self.assertEqual({item["workspace_id"] for item in coverage["unavailable"]}, STALE_IDS)
        self.assertNotIn(str(self.base), json.dumps(coverage))
        self.assertNotIn("root", {key for item in coverage["unavailable"] for key in item})

    def test_valid_workspaces_stay_readable(self) -> None:
        self.assertIn("# atlas", self.gw.read_file("atlas", "README.md")["content"])
        self.assertTrue(self.gw.git_status("uam")["head"])
        self.assertTrue(self.gw.tree("ledger")["entries"])

    def test_unavailable_workspace_fails_explicitly_not_as_unknown(self) -> None:
        for call in (
            lambda: self.gw.read_file("atlas-main", "README.md"),
            lambda: self.gw.git_status("atlas-main"),
            lambda: self.gw.tree("atlas-pr7"),
        ):
            with self.assertRaises(WorkspaceUnavailableError) as ctx:
                call()
            self.assertEqual(ctx.exception.reason, "root_missing")
            self.assertNotIn(str(self.base), str(ctx.exception))

    def test_unknown_workspace_is_still_a_plain_workspace_error(self) -> None:
        with self.assertRaises(WorkspaceError) as ctx:
            self.gw.registry.get("never-registered")
        self.assertNotIsInstance(ctx.exception, WorkspaceUnavailableError)

    def test_unavailable_identity_is_registered_but_not_usable(self) -> None:
        registry = self.gw.registry
        self.assertTrue(registry.is_registered("atlas-main"))
        self.assertFalse(registry.has("atlas-main"))
        self.assertFalse(registry.is_registered("never-registered"))

    def test_unavailable_workspace_is_excluded_from_the_listing(self) -> None:
        listing = self.gw.list_workspaces()
        self.assertEqual({w["workspace_id"] for w in listing["registered"]}, HEALTHY_IDS)
        self.assertEqual(
            {item["workspace_id"] for item in listing["coverage"]["unavailable"]}, STALE_IDS,
        )

    def test_project_instances_marks_unavailable_instances(self) -> None:
        result = self.gw.project_instances("atlas")
        by_id = {item["workspace_id"]: item for item in result["instances"]}
        self.assertIs(by_id["atlas-main"]["available"], False)
        self.assertEqual(by_id["atlas-main"]["unavailable_reason"], "root_missing")
        self.assertIs(by_id["atlas-pr7"]["available"], False)
        self.assertNotIn("available", by_id["atlas"])


class RootStateTransitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="uam-root-state-")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)

    def _registry(self, entries: list[dict[str, Any]]) -> Path:
        return write_workspace_registry(self.base / "workspaces.json", entries)

    def test_root_that_is_a_file_is_unavailable(self) -> None:
        (self.base / "not-a-dir").write_text("x", encoding="utf-8")
        path = self._registry([
            _entry("file-root", self.base / "not-a-dir", project_id="p", role="canonical-main"),
        ])
        registry = WorkspaceRegistry(path)
        self.assertEqual(registry.list(), [])
        self.assertEqual(registry.unavailable()[0]["reason"], "root_not_directory")

    def test_unresolvable_root_is_unavailable(self) -> None:
        path = self._registry([
            _entry("locked", self.base / "locked", project_id="p", role="canonical-main"),
        ])
        with mock.patch("pathlib.Path.resolve", side_effect=PermissionError("denied")):
            registry = WorkspaceRegistry(path)
        self.assertEqual(registry.list(), [])
        self.assertEqual(registry.unavailable()[0]["reason"], "root_unresolvable")

    def test_root_removed_after_load_stops_being_served_without_a_reload(self) -> None:
        init_git_repo(self.base / "temp-repo")
        path = self._registry([
            _entry("temp-repo", self.base / "temp-repo", project_id="p", role="canonical-main"),
        ])
        registry = WorkspaceRegistry(path)
        self.assertTrue(registry.has("temp-repo"))
        shutil.rmtree(self.base / "temp-repo")
        self.assertFalse(registry.has("temp-repo"))
        self.assertEqual(registry.list(), [])
        with self.assertRaises(WorkspaceUnavailableError):
            registry.get("temp-repo")
        self.assertFalse(registry.coverage()["complete"])

    def test_root_missing_at_load_is_not_promoted_until_the_registry_reloads(self) -> None:
        # The served root is pinned when the registry loads. A directory that appears later
        # must not be adopted without a reload, otherwise the resolved target would be
        # decided at access time instead of at load time.
        root = self.base / "later"
        path = self._registry([_entry("later", root, project_id="p", role="canonical-main")])
        registry = WorkspaceRegistry(path)
        init_git_repo(root)
        self.assertFalse(registry.has("later"))
        path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        self.assertTrue(registry.has("later"))
        self.assertTrue(registry.coverage()["complete"])

    def test_schema_violations_still_reject_the_whole_registry(self) -> None:
        init_git_repo(self.base / "ok")
        good = _entry("ok", self.base / "ok", project_id="p", role="canonical-main")
        bad_variants = {
            "capability": {**good, "workspace_id": "bad", "capabilities": ["filesystem.write"]},
            "kind": {**good, "workspace_id": "bad", "kind": "bare-directory"},
            "duplicate": {**good},
            "grammar": {**good, "workspace_id": "../escape"},
            "field": {**good, "workspace_id": "bad", "surprise": True},
        }
        for name, bad in bad_variants.items():
            with self.subTest(violation=name):
                path = self._registry([good, bad])
                with self.assertRaises(WorkspaceError):
                    WorkspaceRegistry(path)


class NoSilentRebindTests(unittest.TestCase):
    """An unavailable registered identity must never resolve to a look-alike directory."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="uam-rebind-")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.scope_root = self.base / "scope"
        self.decoy = self.scope_root / "atlas-main"
        init_git_repo(self.decoy, files={"DECOY.txt": "not the registered root\n"})

    def _gateway(self, entries: list[dict[str, Any]], name: str) -> MiddlewareGateway:
        registry = write_workspace_registry(self.base / f"{name}.json", entries)
        gw = MiddlewareGateway(str(registry), str(self.base / f"state-{name}"))
        gw.scopes.add_scope(RootScope(
            scope_id="scope",
            root=str(self.scope_root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=True,
                text_search=True, git_observe=True, auto_admit=True,
            ),
        ))
        return gw

    def test_control_unregistered_name_does_resolve_to_the_decoy(self) -> None:
        # Establishes that the decoy is reachable through bare-name resolution, so the
        # next test can only pass because the registered identity blocks that path.
        gw = self._gateway([], "control")
        resolved = gw.resolver.resolve("atlas-main")
        self.assertEqual(Path(resolved.spec.root), self.decoy.resolve())

    def test_registered_but_unavailable_identity_never_falls_through_to_the_decoy(self) -> None:
        gw = self._gateway(
            [_entry("atlas-main", self.base / "gone", project_id="atlas", role="canonical-main")],
            "stale",
        )
        with self.assertRaises(ResolutionError) as ctx:
            gw.resolver.resolve("atlas-main")
        self.assertEqual(ctx.exception.kind, "UNAVAILABLE")
        with self.assertRaises(WorkspaceUnavailableError):
            gw.read_file("atlas-main", "DECOY.txt")

    def test_state_directory_inside_an_unavailable_root_is_still_rejected(self) -> None:
        ghost = self.base / "ghost"
        registry = write_workspace_registry(
            self.base / "isolation.json",
            [_entry("ghost", ghost, project_id="p", role="canonical-main")],
        )
        with self.assertRaises(WorkspaceError):
            MiddlewareGateway(str(registry), str(ghost / "state"))


class ReadOnlyGitMissingRootTests(unittest.TestCase):
    def test_missing_root_is_a_workspace_error_not_a_raw_oserror(self) -> None:
        with tempfile.TemporaryDirectory(prefix="uam-git-missing-") as tmp:
            with self.assertRaises(WorkspaceError):
                ReadOnlyGit(str(Path(tmp) / "gone"))


class ProjectCoverageHonestyTests(ProductionShapedRegistry):
    def test_unobservable_main_and_candidate_never_read_as_absent_or_complete(self) -> None:
        snapshot = self.gw.project_reality("atlas")
        by_id = {item["workspace_id"]: item for item in snapshot["instances"]}
        self.assertIs(by_id["atlas-main"]["observable"], False)
        self.assertIs(by_id["atlas-pr7"]["observable"], False)
        self.assertIs(by_id["atlas"]["observable"], True)
        coverage = snapshot["coverage"]
        self.assertNotEqual(coverage["status"], "COMPLETE")
        self.assertEqual(coverage["surfaces"]["canonical_source"], "not_observed")
        self.assertEqual(coverage["surfaces"]["active_candidate"], "not_observed")
        self.assertTrue(any(w.startswith("UNOBSERVABLE_INSTANCES") for w in coverage["warnings"]))

    def test_worktree_discovery_skips_unreadable_instances_without_raising(self) -> None:
        self.assertIsInstance(self.gw.projects.discover_worktrees("atlas"), list)

    def test_compute_coverage_marks_registered_unobservable_surfaces(self) -> None:
        coverage = _compute_coverage(
            {"review-carrier"}, [], False, None,
            unobservable_instances=[
                {"workspace_id": "m", "role": "canonical-main"},
                {"workspace_id": "c", "role": "candidate"},
            ],
        )
        self.assertEqual(coverage["surfaces"]["canonical_source"], "not_observed")
        self.assertEqual(coverage["surfaces"]["active_candidate"], "not_observed")

    def test_compute_coverage_default_semantics_are_unchanged(self) -> None:
        coverage = _compute_coverage({"review-carrier"}, [], False, None)
        self.assertEqual(coverage["surfaces"]["canonical_source"], "not_registered")
        self.assertEqual(coverage["surfaces"]["active_candidate"], "not_applicable")
        self.assertFalse(any(w.startswith("UNOBSERVABLE") for w in coverage["warnings"]))


class StatusEndpointTests(ProductionShapedRegistry):
    def setUp(self) -> None:
        super().setUp()
        self.server = UAMHTTPServer(
            ("127.0.0.1", 0), Handler, gateway=self.gw, bearer_token="x" * 48,
        )
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def _get(self, path: str) -> tuple[int, dict[str, Any]]:
        url = f"http://127.0.0.1:{self.server.server_address[1]}{path}"
        with urllib.request.urlopen(url, timeout=3) as resp:
            return resp.status, json.loads(resp.read())

    def test_status_reports_degraded_with_counts_only(self) -> None:
        before = self.gw.audit.verify()["records"]
        code, body = self._get("/status")
        self.assertEqual(code, 200)
        self.assertEqual(body["status"], "degraded")
        self.assertEqual(body["workspace_count"], 4)
        self.assertEqual(
            body["coverage"],
            {"complete": False, "registered": 6, "available": 4, "unavailable_count": 2},
        )
        text = json.dumps(body)
        for hidden in (*STALE_IDS, str(self.base), "instance_id", "pid"):
            self.assertNotIn(hidden, text)
        self.assertEqual(self.gw.audit.verify()["records"], before)

    def test_readiness_is_unchanged_by_partial_coverage(self) -> None:
        code, body = self._get("/readyz")
        self.assertEqual((code, body["status"]), (200, "ready"))


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class McpSurfaceTests(ProductionShapedRegistry):
    def setUp(self) -> None:
        super().setUp()
        self.server = create_session_read_server(
            str(self.registry_path), str(self.base / "mcp-state"),
        )

    def _call(self, name: str, **kwargs: Any) -> dict[str, Any]:
        tool = self.server._tool_manager._tools[name].fn
        return json.loads(asyncio.run(tool(ctx=None, **kwargs)))

    def test_list_workspaces_reports_coverage_instance_and_request_id(self) -> None:
        payload = self._call("uam_list_workspaces")
        self.assertEqual({w["workspace_id"] for w in payload["workspaces"]}, HEALTHY_IDS)
        self.assertFalse(payload["coverage"]["complete"])
        self.assertEqual(
            {item["workspace_id"] for item in payload["coverage"]["unavailable"]}, STALE_IDS,
        )
        self.assertTrue(payload["request_id"])
        self.assertTrue(payload["instance"]["instance_id"])
        self.assertNotIn(str(self.base), json.dumps(payload))

    def test_snapshot_of_unavailable_workspace_is_an_explicit_error(self) -> None:
        payload = self._call("uam_workspace_snapshot", workspace_id="atlas-main")
        self.assertIn("workspace unavailable: atlas-main (root_missing)", payload["error"])

    def test_project_reality_survives_stale_instances(self) -> None:
        payload = self._call("uam_project_reality", project_id="atlas")
        self.assertNotIn("error", payload)
        self.assertNotEqual(payload["coverage"]["status"], "COMPLETE")

    def test_project_instances_marks_unavailable_instances(self) -> None:
        payload = self._call("uam_list_project_instances", project_id="atlas")
        flagged = {
            item["workspace_id"] for item in payload["instances"] if item.get("available") is False
        }
        self.assertEqual(flagged, STALE_IDS)


def _add_stale_registration(runtime: dict[str, Any], base: Path) -> None:
    registry_file = Path(runtime["registry_file"])
    registry = json.loads(registry_file.read_text())
    registry["workspaces"].append({
        "workspace_id": "stale-main", "root": str(base / "gone" / "stale-main"),
        "kind": "git-repository", "capabilities": ["filesystem.read"]})
    registry_file.write_text(json.dumps(registry))


def test_runtime_validation_tolerates_a_stale_registration(runtime_fixture, tmp_path):
    r, _, _ = runtime_fixture
    _add_stale_registration(r, tmp_path)
    rt.validate_configs(r)


def test_release_gate_still_rejects_a_stale_registration(runtime_fixture, tmp_path):
    r, _, _ = runtime_fixture
    rt.validate_configs(r, require_complete_registry=True)
    _add_stale_registration(r, tmp_path)
    with pytest.raises(ValueError, match=r"stale-main \(root_missing\)"):
        rt.validate_configs(r, require_complete_registry=True)


def test_activation_refuses_a_stale_registration_before_touching_the_host(runtime_fixture, tmp_path):
    # A coverage gap must stop activation before `current` is switched or launchd is touched;
    # otherwise it would only surface as a non-READY Doctor after activation and latch FROZEN.
    r, manifest, home = runtime_fixture
    _add_stale_registration(r, tmp_path)
    current = Path(r["uam_home"]) / "current"
    target_before = current.readlink()
    with mock.patch.object(installer.subprocess, "run", side_effect=AssertionError("host touched")):
        with pytest.raises(ValueError, match="unavailable workspaces"):
            installer.activate(manifest, home)
    assert current.readlink() == target_before
    assert not (Path(r["recovery_root"]) / "FROZEN.json").exists()


if __name__ == "__main__":
    unittest.main()
