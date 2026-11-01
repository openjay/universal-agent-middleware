"""Tests for UAM v0.6 RealityIndex (R4-R6)."""
from __future__ import annotations

import json
import multiprocessing
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from universal_agent_middleware.discovery import DiscoveryEngine
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.reality_index import (
    RealityIndex,
    SCHEMA_VERSION,
)
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry

from tests.synthetic_fixtures import init_git_repo, write_workspace_registry


def _make_scope_registry(root: Path, scope_id: str = "test-scope") -> RootScopeRegistry:
    registry = RootScopeRegistry()
    registry.add_scope(RootScope(
        scope_id=scope_id,
        root=str(root),
        authority=RootScopeAuthority(
            discover=True,
            metadata_read=True,
            content_read=True,
            text_search=True,
            git_observe=True,
            auto_admit=True,
            index=True,
        ),
    ))
    return registry


class TestRealityIndexCore(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._state = Path(self._tmp.name) / "state"
        self._root = Path(self._tmp.name) / "code"
        self._root.mkdir()
        init_git_repo(self._root / "sample-app", files={"README.md": "# hi\n"})
        self.registry = _make_scope_registry(self._root)
        self.index = RealityIndex(self._state)
        self.engine = DiscoveryEngine(self.registry, reality_index=self.index)

    def tearDown(self):
        self._tmp.cleanup()

    def test_schema_and_integrity(self):
        health = self.index.check_integrity()
        self.assertTrue(health["valid"])
        self.assertEqual(health["schema_version"], SCHEMA_VERSION)

    def test_write_and_read_snapshot(self):
        inv = self.engine.discover_scope("test-scope", enrich_git=False)
        gen = self.index.write_snapshot("test-scope", inv, self.registry.policy_generation)
        self.assertTrue(len(gen) > 0)

        cached = self.index.get_active_snapshot("test-scope", self.registry.policy_generation)
        self.assertIsNotNone(cached)
        self.assertEqual(cached["total_projects"], inv["total_projects"])
        self.assertEqual(cached["freshness"]["source"], "reality_index")

    def test_policy_generation_invalidation(self):
        inv = self.engine.discover_scope("test-scope", enrich_git=False)
        self.index.write_snapshot("test-scope", inv, self.registry.policy_generation)
        stale = self.index.get_active_snapshot("test-scope", "deadbeef00000000")
        self.assertIsNone(stale)

    def test_alias_lookup_by_basename(self):
        inv = self.engine.discover_scope("test-scope", enrich_git=False)
        self.index.write_snapshot("test-scope", inv, self.registry.policy_generation)
        matches = self.index.lookup_by_alias(
            "sample-app",
            policy_generation=self.registry.policy_generation,
        )
        self.assertEqual(len(matches), 1)
        self.assertTrue(matches[0].workspace_id.startswith("derived:"))

    def test_corruption_recovery(self):
        inv = self.engine.discover_scope("test-scope", enrich_git=False)
        self.index.write_snapshot("test-scope", inv, self.registry.policy_generation)
        db_path = self.index.db_path
        db_path.write_bytes(b"not a sqlite database")
        self.index._corrupt = True
        health = self.index.check_integrity()
        self.assertFalse(health["valid"])
        self.index.rebuild()
        self.assertFalse(self.index.is_corrupt)
        self.index.write_snapshot("test-scope", inv, self.registry.policy_generation)
        self.assertIsNotNone(
            self.index.get_active_snapshot("test-scope", self.registry.policy_generation)
        )


def _index_writer(state_dir: str, root: str) -> None:
    registry = _make_scope_registry(Path(root))
    index = RealityIndex(state_dir)
    engine = DiscoveryEngine(registry, reality_index=index)
    inv = engine.discover_scope("test-scope", enrich_git=False)
    index.write_snapshot("test-scope", inv, registry.policy_generation)


class TestRealityIndexConcurrency(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._state = Path(self._tmp.name) / "state"
        self._root = Path(self._tmp.name) / "code"
        self._root.mkdir()
        for name in ("alpha", "beta", "gamma"):
            init_git_repo(self._root / name, files={"README.md": f"# {name}\n"})

    def tearDown(self):
        self._tmp.cleanup()

    def test_cross_process_concurrent_writes(self):
        ctx = multiprocessing.get_context("spawn")
        procs = [
            ctx.Process(target=_index_writer, args=(str(self._state), str(self._root)))
            for _ in range(4)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(30)
            self.assertEqual(p.exitcode, 0)

        index = RealityIndex(self._state)
        health = index.check_integrity()
        self.assertTrue(health["valid"])
        snapshot = index.get_active_snapshot("test-scope", _make_scope_registry(self._root).policy_generation)
        self.assertIsNotNone(snapshot)
        self.assertGreaterEqual(snapshot["total_repositories"], 1)


class TestDiscoveryIndexIntegration(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name) / "code"
        self._root.mkdir()
        init_git_repo(self._root / "fast-repo", files={"README.md": "# fast\n"})
        self._state = tempfile.TemporaryDirectory(prefix="uam-idx-")
        registry_path = write_workspace_registry(Path(self._tmp.name) / "workspaces.json", [])
        self.gw = MiddlewareGateway(str(registry_path), self._state.name)
        self.gw.scopes.add_scope(RootScope(
            scope_id="idx-scope",
            root=str(self._root),
            authority=RootScopeAuthority(
                discover=True, content_read=True, git_observe=True, auto_admit=True,
                index=True,
            ),
        ))

    def tearDown(self):
        self._state.cleanup()
        self._tmp.cleanup()

    def test_scope_inventory_index_fast_path(self):
        self.gw.index_scope("idx-scope")
        start = time.perf_counter()
        result = self.gw.scope_inventory("idx-scope")
        elapsed_ms = (time.perf_counter() - start) * 1000
        self.assertNotIn("error", result)
        self.assertLess(elapsed_ms, 50.0, f"index fast path took {elapsed_ms:.1f}ms")
        self.assertEqual(result["freshness"]["source"], "reality_index")

    def test_resolver_uses_index_for_bare_name(self):
        self.gw.index_scope("idx-scope")
        resolution = self.gw.resolve_workspace("fast-repo")
        self.assertEqual(resolution.resolution_kind, "project_name")

    def test_list_workspaces_includes_discovered(self):
        self.gw.index_scope("idx-scope")
        result = self.gw.list_workspaces(view="all")
        self.assertIn("discovered", result)
        self.assertGreaterEqual(len(result["discovered"]), 1)

    def test_project_reality_from_index(self):
        self.gw.index_scope("idx-scope")
        result = self.gw.project_reality("fast-repo")
        self.assertEqual(result["source"], "reality_index")
        self.assertGreaterEqual(len(result["instances"]), 1)

    def test_project_instances_from_index(self):
        self.gw.index_scope("idx-scope")
        result = self.gw.project_instances("fast-repo")
        self.assertEqual(result["source"], "reality_index")


class TestDoctorRealityIndex(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        registry_path = write_workspace_registry(Path(self._tmp.name) / "workspaces.json", [])
        self._state = tempfile.TemporaryDirectory(prefix="uam-doc-")
        self.registry_path = str(registry_path)
        self.state_dir = self._state.name

    def tearDown(self):
        self._state.cleanup()
        self._tmp.cleanup()

    def test_doctor_reports_index_health(self):
        from universal_agent_middleware.doctor import run_doctor

        report = run_doctor(self.registry_path, self.state_dir, include_canary=False)
        self.assertIn("reality_index", report["checks"])
        idx = report["checks"]["reality_index"]
        self.assertIn(idx["status"], ("PASS", "DEGRADED"))
        self.assertIn("integrity", idx)
        self.assertIn("record_counts", idx)

    def test_doctor_does_not_run_blocking_index_refresh(self):
        """F1 fix: Doctor must not trigger any refresh (daemon threads die with caller)."""
        from unittest import mock

        from universal_agent_middleware.doctor import run_doctor

        with mock.patch(
            "universal_agent_middleware.discovery.DiscoveryEngine.index_scope",
        ) as index_mock, mock.patch(
            "universal_agent_middleware.discovery.DiscoveryEngine.discover_scope",
        ) as discover_mock:
            run_doctor(self.registry_path, self.state_dir, include_canary=False)

        index_mock.assert_not_called()
        discover_mock.assert_not_called()


    def test_doctor_includes_phase_timing(self):
        """F3 fix: Doctor output must include all 7 phase timings."""
        from universal_agent_middleware.doctor import run_doctor

        report = run_doctor(self.registry_path, self.state_dir, include_canary=False)
        self.assertIn("_timing", report)
        timing = report["_timing"]
        expected_phases = (
            "runtime_checks", "audit_chain_check", "core_init",
            "mcp_contract", "workspace_canary_check", "tunnel_check",
            "reality_index_check",
        )
        for phase in expected_phases:
            self.assertIn(phase, timing, f"missing phase: {phase}")
            self.assertIsInstance(timing[phase], int)
            self.assertGreaterEqual(timing[phase], 0)
        self.assertEqual(len(expected_phases), 7)
        self.assertIn("total_duration_ms", report)
        self.assertIsInstance(report["total_duration_ms"], int)

    def test_health_report_detects_missing_enabled_scope(self):
        """F2 fix: health_report must DEGRADE if an enabled scope has no snapshot."""
        from unittest import mock

        mock_scope_registry = mock.MagicMock()
        mock_scope_registry.list_scopes.return_value = [
            {"scope_id": "test-scope", "authority": {"discover": True, "index": True}},
        ]
        mock_scope_registry.policy_generation = "gen-1"

        from universal_agent_middleware.reality_index import RealityIndex

        idx = RealityIndex(self.state_dir)
        report = idx.health_report(mock_scope_registry)
        self.assertEqual(report["status"], "DEGRADED")
        self.assertEqual(report["failure_class"], "reality_index_missing")
        scope_ids = [s["scope_id"] for s in report["scopes"]]
        self.assertIn("test-scope", scope_ids)
        missing = [s for s in report["scopes"] if s["scope_id"] == "test-scope"][0]
        self.assertEqual(missing["status"], "missing")
        self.assertTrue(missing["stale"])
        self.assertEqual(missing["obligation"], "required")

    def test_health_report_orphaned_scope_not_readiness_blocker(self):
        """F2 closure: revoked scope in DB must not block PASS for required scopes."""
        from unittest import mock
        from universal_agent_middleware.reality_index import RealityIndex

        idx = RealityIndex(self.state_dir)
        idx.write_snapshot("old-scope", {
            "total_repositories": 1,
            "total_projects": 1,
            "projects": [],
        }, "gen-old")

        mock_scope_registry = mock.MagicMock()
        mock_scope_registry.list_scopes.return_value = []
        mock_scope_registry.policy_generation = "gen-new"

        report = idx.health_report(mock_scope_registry)
        orphans = [s for s in report.get("scopes", []) if s.get("obligation") == "orphaned"]
        self.assertEqual(len(orphans), 1)
        self.assertEqual(orphans[0]["scope_id"], "old-scope")
        self.assertEqual(report["status"], "PASS")

    def test_health_report_failure_class_on_integrity_errors(self):
        """F4 closure: DB-level failures must emit specific failure_class."""
        from unittest import mock
        from universal_agent_middleware.reality_index import RealityIndex

        idx = RealityIndex(self.state_dir)
        with mock.patch.object(idx, "check_integrity",
                               return_value={"valid": False, "status": "INCOMPATIBLE",
                                              "reason": "newer schema"}):
            report = idx.health_report(None)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure_class"], "reality_index_schema_incompatible")

        with mock.patch.object(idx, "check_integrity",
                               return_value={"valid": True, "status": "LOCKED",
                                              "reason": "busy"}):
            report = idx.health_report(None)
        self.assertEqual(report["status"], "DEGRADED")
        self.assertEqual(report["failure_class"], "reality_index_locked")

    def test_doctor_survives_incompatible_index_schema(self):
        """v2 closure: incompatible index must not kill Gateway; Doctor must classify correctly."""
        from universal_agent_middleware.doctor import run_doctor
        from universal_agent_middleware.reality_index import RealityIndex, SCHEMA_VERSION

        idx = RealityIndex(self.state_dir)
        with idx._connect(write=True) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION + 100)),
            )
            conn.commit()

        report = run_doctor(self.registry_path, self.state_dir, include_canary=False)
        self.assertEqual(report["checks"]["core"]["status"], "PASS")
        idx_check = report["checks"]["reality_index"]
        self.assertEqual(idx_check["status"], "FAIL")
        self.assertEqual(idx_check["failure_class"], "reality_index_schema_incompatible")


class TestLockContentionHandling(unittest.TestCase):
    """GAP-03: BUSY/LOCKED must not mark the index as corrupt."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._state = Path(self._tmp.name) / "state"
        self._root = Path(self._tmp.name) / "code"
        self._root.mkdir()
        init_git_repo(self._root / "repo-a", files={"README.md": "# a\n"})
        self.registry = _make_scope_registry(self._root)
        self.index = RealityIndex(self._state)
        engine = DiscoveryEngine(self.registry, reality_index=self.index)
        inv = engine.discover_scope("test-scope", enrich_git=False)
        self.index.write_snapshot("test-scope", inv, self.registry.policy_generation)

    def tearDown(self):
        self._tmp.cleanup()

    def test_locked_db_not_marked_corrupt(self):
        holder = sqlite3.connect(self.index.db_path, timeout=30.0)
        holder.execute("BEGIN IMMEDIATE")
        try:
            reader = RealityIndex(self._state)
            health = reader.check_integrity()
            self.assertFalse(reader.is_corrupt)
            self.assertIn(health["status"], ("LOCKED", "OK"))
            if health["status"] == "LOCKED":
                self.assertFalse(health["valid"])
        finally:
            holder.rollback()
            holder.close()

        reopened = RealityIndex(self._state)
        health = reopened.check_integrity()
        self.assertTrue(health["valid"])
        self.assertFalse(reopened.is_corrupt)


class TestIncompatibleSchema(unittest.TestCase):
    """GAP-05: future schema versions must be rejected, not downgraded."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._state = Path(self._tmp.name) / "state"
        self.index = RealityIndex(self._state)

    def tearDown(self):
        self._tmp.cleanup()

    def test_newer_schema_marks_incompatible(self):
        with sqlite3.connect(self.index.db_path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES (?, ?)",
                ("schema_version", "999"),
            )
            conn.commit()

        idx = RealityIndex(self._state)
        self.assertTrue(idx.schema_incompatible)
        report = idx.health_report(None)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure_class"], "reality_index_schema_incompatible")

        reader = RealityIndex.__new__(RealityIndex)
        reader._state_dir = self._state
        reader._db_path = self._state / "reality_index.db"
        reader._corrupt = False
        reader._schema_incompatible = True
        reader._incompatible_schema_version = 999
        health = reader.check_integrity()
        self.assertEqual(health["status"], "INCOMPATIBLE")
        self.assertFalse(health["valid"])


class TestCLIBackgroundIndex(unittest.TestCase):
    """GAP-07: CLI --background must spawn a detached worker, not a daemon thread."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        init_git_repo(self._root / "bg-repo", files={"README.md": "# bg\n"})
        self.registry_path = write_workspace_registry(self._root / "workspaces.json", [])
        self.scopes_path = self._root / "root_scopes.json"
        self.scopes_path.write_text(json.dumps({
            "scopes": [{
                "scope_id": "bg-scope",
                "root": str(self._root),
                "authority": RootScopeAuthority(
                    discover=True, content_read=True, auto_admit=True,
                    index=True,
                ).to_dict(),
            }],
        }), encoding="utf-8")
        self._state = Path(self._tmp.name) / "state"

    def tearDown(self):
        self._tmp.cleanup()

    def test_background_index_spawns_detached_worker(self):
        import subprocess
        import sys

        proc = subprocess.run(
            [
                sys.executable, "-m", "universal_agent_middleware.cli", "index",
                "--registry", str(self.registry_path),
                "--state-dir", str(self._state),
                "--scope", "bg-scope",
                "--background",
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["mode"], "detached_process")
        self.assertEqual(payload["scopes"][0]["status"], "spawned")
        self.assertIsInstance(payload["scopes"][0]["pid"], int)

        deadline = time.time() + 15.0
        while time.time() < deadline:
            index = RealityIndex(self._state)
            snap = index.get_active_snapshot(
                "bg-scope",
                RootScopeRegistry(self.scopes_path).policy_generation,
            )
            if snap is not None:
                break
            time.sleep(0.25)
        self.assertIsNotNone(snap, "detached worker did not complete indexing")


class TestEnrichmentMonotonicity(unittest.TestCase):
    """Quality monotonicity: enriched index must not be downgraded by non-enriched writes."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._state = Path(self._tmp.name) / "state"
        self._root = Path(self._tmp.name) / "code"
        self._root.mkdir()
        init_git_repo(self._root / "alpha", files={"main.py": "# alpha\n"})
        init_git_repo(self._root / "beta", files={"lib.py": "# beta\n"})
        self._registry = _make_scope_registry(self._root.resolve())
        self._index = RealityIndex(self._state)
        self._discovery = DiscoveryEngine(
            self._registry, reality_index=self._index, cache_ttl=0.1,
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_non_enriched_write_does_not_replace_enriched(self):
        enriched_result = self._discovery.discover_scope("test-scope", enrich_git=True)
        gen1 = self._index.write_snapshot(
            "test-scope", enriched_result, self._registry.policy_generation,
            git_enriched=True,
        )

        fast_result = self._discovery.discover_scope("test-scope", enrich_git=False)
        gen2 = self._index.write_snapshot(
            "test-scope", fast_result, self._registry.policy_generation,
            git_enriched=False,
        )

        self.assertEqual(gen1, gen2, "non-enriched write should return existing enriched generation")

        snap = self._index.get_active_snapshot(
            "test-scope", self._registry.policy_generation, max_age_sec=60
        )
        self.assertIsNotNone(snap)
        self.assertTrue(snap["freshness"]["git_enriched"])

    def test_enriched_write_replaces_non_enriched(self):
        fast = self._discovery.discover_scope("test-scope", enrich_git=False)
        gen1 = self._index.write_snapshot(
            "test-scope", fast, self._registry.policy_generation,
            git_enriched=False,
        )

        enriched = self._discovery.discover_scope("test-scope", enrich_git=True)
        gen2 = self._index.write_snapshot(
            "test-scope", enriched, self._registry.policy_generation,
            git_enriched=True,
        )

        self.assertNotEqual(gen1, gen2)
        snap = self._index.get_active_snapshot(
            "test-scope", self._registry.policy_generation, max_age_sec=60
        )
        self.assertTrue(snap["freshness"]["git_enriched"])

    def test_background_refresh_inherits_enrichment(self):
        enriched = self._discovery.discover_scope("test-scope", enrich_git=True)
        self._index.write_snapshot(
            "test-scope", enriched, self._registry.policy_generation,
            git_enriched=True,
        )

        self._discovery._refresh_index("test-scope")

        snap = self._index.get_active_snapshot(
            "test-scope", self._registry.policy_generation, max_age_sec=60
        )
        self.assertIsNotNone(snap)
        self.assertTrue(snap["freshness"]["git_enriched"])

    def test_doctor_detects_missing_enrichment(self):
        fast = self._discovery.discover_scope("test-scope", enrich_git=False)
        self._index.write_snapshot(
            "test-scope", fast, self._registry.policy_generation,
            git_enriched=False,
        )

        report = self._index.health_report(scope_registry=self._registry)
        self.assertEqual(report["status"], "DEGRADED")
        self.assertIn("not_enriched", report.get("failure_class", ""))


class TestEnrichmentCompleteness(unittest.TestCase):
    """Enrichment completeness must be structured, not a bare boolean."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name) / "code"
        self._root.mkdir()
        for i in range(5):
            init_git_repo(self._root / f"repo{i}", files={"README.md": f"# repo {i}\n"})
        self._state = Path(self._tmp.name) / "state"
        self._registry = _make_scope_registry(self._root.resolve())
        self._index = RealityIndex(self._state)
        self._discovery = DiscoveryEngine(
            self._registry, reality_index=self._index, cache_ttl=0.1,
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_discover_scope_returns_git_enrichment_struct(self):
        result = self._discovery.discover_scope("test-scope", enrich_git=True, git_budget=50)
        enrichment = result.get("git_enrichment")
        self.assertIsNotNone(enrichment)
        self.assertTrue(enrichment["requested"])
        self.assertGreater(enrichment["total_instances"], 0)
        self.assertGreaterEqual(enrichment["enriched_instances"], 0)
        self.assertIn("partial", enrichment)
        self.assertIn("complete", enrichment)

    def test_fast_scan_enrichment_not_requested(self):
        result = self._discovery.discover_scope("test-scope", enrich_git=False)
        enrichment = result.get("git_enrichment")
        self.assertIsNotNone(enrichment)
        self.assertFalse(enrichment["requested"])
        self.assertEqual(enrichment["budget"], 0)
        self.assertEqual(enrichment["enriched_instances"], 0)

    def test_partial_enrichment_when_budget_exceeded(self):
        result = self._discovery.discover_scope("test-scope", enrich_git=True, git_budget=2)
        enrichment = result.get("git_enrichment")
        self.assertIsNotNone(enrichment)
        if enrichment["total_instances"] > 2:
            self.assertTrue(enrichment["partial"])
            self.assertFalse(enrichment["complete"])


if __name__ == "__main__":
    unittest.main()
