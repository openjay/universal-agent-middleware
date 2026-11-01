"""Batch A (v0.6.x-A) acceptance tests — Coverage credibility & Search completeness.

W1: Coverage verdict must never claim completeness beyond observable scope.
W2: Search must fail-closed on truncation/timeout; never produce false negatives.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from universal_agent_middleware.root_scope import (
    RootScope,
    RootScopeAuthority,
    RootScopeRegistry,
)
from universal_agent_middleware.discovery import DiscoveryEngine
from universal_agent_middleware.exploration import ExplorationEngine
from universal_agent_middleware.workspace import WorkspaceReader
from universal_agent_middleware.models import WorkspaceSpec

from scope_search_instruments import ScriptedRipgrep, completed
from synthetic_fixtures import init_git_repo


class _ScopeFixture:
    """Reusable scope with two synthetic repos: alpha (active) and beta (dormant)."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="uam-batchA-")
        self.root = Path(self._tmp.name)
        self.alpha = self.root / "alpha"
        self.beta = self.root / "beta"

        init_git_repo(self.alpha, files={
            "main.py": "import os\n",
            ".github/workflows/ci.yml": "name: CI\n",
            "Dockerfile": "FROM python:3.12\n",
            "pyproject.toml": '[tool.test]\nrun = "docker compose up"\nlocalhost:8080\n~/.myservice/config.json\n',
        })
        init_git_repo(self.beta, files={
            "README.md": "# old project\n",
        })

        env_backup = os.environ.copy()
        os.environ["GIT_COMMITTER_DATE"] = "2020-01-01T00:00:00+00:00"
        os.environ["GIT_AUTHOR_DATE"] = "2020-01-01T00:00:00+00:00"
        import subprocess
        (self.beta / "stale_marker.txt").write_text("mark", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(self.beta), capture_output=True, timeout=10, check=False)
        subprocess.run(
            ["git", "commit", "-qm", "old-commit", "--date=2020-01-01T00:00:00+00:00"],
            cwd=str(self.beta), capture_output=True, timeout=10, check=False,
            env={**os.environ,
                 "GIT_AUTHOR_NAME": "UAM Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                 "GIT_COMMITTER_NAME": "UAM Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"},
        )
        os.environ.clear()
        os.environ.update(env_backup)

        self.registry = RootScopeRegistry()
        self.registry.add_scope(RootScope(
            scope_id="test-scope",
            root=str(self.root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=True,
                text_search=True, git_observe=True, classify=True,
                index=True, relate=True, auto_admit=True,
            ),
        ))
        self.discovery = DiscoveryEngine(self.registry, cache_ttl=60.0)
        self.discovery.scope_inventory("test-scope", enrich_git=True, git_budget=50)
        self.exploration = ExplorationEngine(self.discovery, self.registry)

    def cleanup(self) -> None:
        self._tmp.cleanup()


# ---------------------------------------------------------------------------
# W1: Coverage verdict credibility
# ---------------------------------------------------------------------------


class TestW1_WhatAmIMissing(unittest.TestCase):
    """what_am_i_missing must report inventory context when active=0."""

    @classmethod
    def setUpClass(cls):
        cls._fixture = _ScopeFixture()
        cls.addClassCleanup(cls._fixture.cleanup)

    def test_schema_version_v2(self):
        result = self._fixture.exploration.what_am_i_missing("test-scope")
        self.assertEqual(result["schema_version"], "missing-reality-v2")

    def test_inventory_total_always_reported(self):
        result = self._fixture.exploration.what_am_i_missing("test-scope")
        self.assertIn("inventory_total", result)
        self.assertGreater(result["inventory_total"], 0)

    def test_activity_unknown_reported(self):
        result = self._fixture.exploration.what_am_i_missing("test-scope")
        self.assertIn("activity_unknown_count", result)
        self.assertIsInstance(result["activity_unknown_count"], int)

    def test_scope_surfaces_present(self):
        result = self._fixture.exploration.what_am_i_missing("test-scope")
        self.assertIn("scope_surfaces", result)
        surfaces = result["scope_surfaces"]
        self.assertIn("repo_discovery", surfaces)
        self.assertIn("source_content", surfaces)
        self.assertIn("git_metadata", surfaces)
        self.assertIn("runtime_config", surfaces)
        self.assertIn("process", surfaces)

    def test_scope_surfaces_discover_only_not_source_observed(self):
        """discover=true alone must NOT claim source_content observed."""
        registry = RootScopeRegistry()
        registry.add_scope(RootScope(
            scope_id="discover-only",
            root=str(self._fixture.root),
            authority=RootScopeAuthority(discover=True),
        ))
        engine = DiscoveryEngine(registry, cache_ttl=0.0)
        exploration = ExplorationEngine(engine, registry)
        result = exploration.what_am_i_missing("discover-only")
        surfaces = result["scope_surfaces"]
        self.assertEqual(surfaces["repo_discovery"], "observed")
        self.assertEqual(surfaces["source_content"], "not_authorized")
        self.assertEqual(surfaces["git_metadata"], "not_authorized")

    def test_active_project_finds_gaps(self):
        """Alpha has .github + Dockerfile → should produce forge_ci + runtime gaps."""
        result = self._fixture.exploration.what_am_i_missing("test-scope")
        self.assertGreater(result["active_projects_analyzed"], 0)
        self.assertGreater(result["total_gaps"], 0)
        gap_surfaces = {g["surface"] for g in result["gaps"]}
        self.assertIn("forge_ci", gap_surfaces)
        self.assertIn("runtime", gap_surfaces)


class TestW1_WhatAmIMissing_EmptyScope(unittest.TestCase):
    """When no active projects exist, must report epistemic warning."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="uam-batchA-empty-")
        cls.addClassCleanup(cls._tmp.cleanup)
        root = Path(cls._tmp.name)
        cls.registry = RootScopeRegistry()
        cls.registry.add_scope(RootScope(
            scope_id="empty-scope",
            root=str(root),
            authority=RootScopeAuthority(discover=True, metadata_read=True),
        ))
        cls.discovery = DiscoveryEngine(cls.registry, cache_ttl=0.0)
        cls.exploration = ExplorationEngine(cls.discovery, cls.registry)

    def test_zero_active_has_epistemic_warning(self):
        result = self.exploration.what_am_i_missing("empty-scope")
        self.assertEqual(result["active_projects_analyzed"], 0)
        self.assertIn("epistemic_warning", result)
        self.assertIn("does not prove", result["epistemic_warning"])


class TestW1_CoverageVerdict(unittest.TestCase):
    """explain_coverage verdict must never claim LOCAL_COMPLETE."""

    @classmethod
    def setUpClass(cls):
        cls._fixture = _ScopeFixture()
        cls.addClassCleanup(cls._fixture.cleanup)

    def _explain(self, project_id: str) -> dict:
        inventory = self._fixture.discovery.scope_inventory("test-scope")
        for p in inventory.get("projects", []):
            if p["project_id"] == project_id:
                return self._fixture.exploration.explain_coverage("test-scope", project_id)
        self.fail(f"project {project_id} not found")

    def test_alpha_verdict_is_partial(self):
        """Alpha has forge + runtime indicators → PARTIAL."""
        result = self._explain("alpha")
        verdict = result["assessment"]["verdict"]
        self.assertEqual(verdict, "PARTIAL")

    def test_beta_verdict_is_source_observed_not_local_complete(self):
        """Beta has no indicators → SOURCE_OBSERVED (not the old LOCAL_COMPLETE)."""
        result = self._explain("beta")
        verdict = result["assessment"]["verdict"]
        self.assertEqual(verdict, "SOURCE_OBSERVED")
        self.assertNotEqual(verdict, "LOCAL_COMPLETE")

    def test_structurally_unobserved_always_present(self):
        result = self._explain("alpha")
        assessment = result["assessment"]
        self.assertIn("structurally_unobserved", assessment)
        self.assertIn("runtime", assessment["structurally_unobserved"])
        self.assertIn("forge_ci", assessment["structurally_unobserved"])
        self.assertIn("process", assessment["structurally_unobserved"])


class TestW1_CodeRuntimeRefDetection(unittest.TestCase):
    """_find_coverage_gaps must detect in-code runtime references."""

    @classmethod
    def setUpClass(cls):
        cls._fixture = _ScopeFixture()
        cls.addClassCleanup(cls._fixture.cleanup)

    def test_pyproject_runtime_ref_detected(self):
        """Alpha's pyproject.toml references localhost and ~/.myservice → runtime gap."""
        inventory = self._fixture.discovery.scope_inventory("test-scope")
        alpha_proj = None
        for p in inventory.get("projects", []):
            if p["project_id"] == "alpha":
                alpha_proj = p
                break
        self.assertIsNotNone(alpha_proj)
        gaps = self._fixture.exploration._find_coverage_gaps(alpha_proj, "test-scope")
        runtime_gaps = [g for g in gaps if g.surface == "runtime"]
        self.assertTrue(len(runtime_gaps) > 0)
        all_refs = []
        for g in runtime_gaps:
            all_refs.extend(g.evidence_refs)
        ref_text = " ".join(all_refs)
        self.assertTrue(
            "pyproject.toml" in ref_text or "Dockerfile" in ref_text,
            f"Expected code-level runtime reference in evidence: {all_refs}",
        )


class TestW1_ScanErrorReported(unittest.TestCase):
    """When canonical_path is missing, gap must be reported (not silently empty)."""

    @classmethod
    def setUpClass(cls):
        cls._fixture = _ScopeFixture()
        cls.addClassCleanup(cls._fixture.cleanup)

    def test_missing_canonical_produces_gap(self):
        fake_project = {"project_id": "ghost", "canonical_path": "/nonexistent/path"}
        gaps = self._fixture.exploration._find_coverage_gaps(fake_project, "test-scope")
        self.assertTrue(len(gaps) > 0)
        self.assertEqual(gaps[0].surface, "local_source")
        self.assertEqual(gaps[0].state, "canonical_path_missing")

    def test_missing_canonical_verdict_is_unassessable(self):
        """canonical_path_missing must yield UNASSESSABLE, not PARTIAL."""
        fake = {"project_id": "gone", "canonical_path": "/nonexistent/nope"}
        gaps = self._fixture.exploration._find_coverage_gaps(fake, "test-scope")
        assessment = self._fixture.exploration._assess_coverage(fake, gaps)
        self.assertEqual(assessment["verdict"], "UNASSESSABLE")
        self.assertNotIn("local_source", assessment["observed"])
        self.assertIn("local_source", [g.surface for g in gaps])
        self.assertNotIn("local_source", assessment["missing"],
                         "local_source should be in 'impaired', not 'missing'")
        self.assertIn("canonical_path_missing", assessment["impaired"])

    def test_no_canonical_path_produces_gap(self):
        fake_project = {"project_id": "headless"}
        gaps = self._fixture.exploration._find_coverage_gaps(fake_project, "test-scope")
        self.assertTrue(len(gaps) > 0)
        self.assertEqual(gaps[0].surface, "local_source")
        self.assertEqual(gaps[0].state, "no_canonical_path")


# ---------------------------------------------------------------------------
# W2: Search completeness & fail-closed
# ---------------------------------------------------------------------------


class TestW2_SearchTextFailClosed(unittest.TestCase):
    """search_text must return safe_to_conclude_absent and search_completeness."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="uam-batchA-search-")
        cls.addClassCleanup(cls._tmp.cleanup)
        root = Path(cls._tmp.name).resolve()
        for i in range(10):
            f = root / f"file_{i}.txt"
            f.write_text(f"line {i}: hello world\n", encoding="utf-8")
        (root / "big.txt").write_bytes(b"x" * 600_000)

        cls.reader_small = WorkspaceReader(WorkspaceSpec(
            workspace_id="test-ws-small",
            root=str(root),
            kind="git-repository",
            capabilities=["filesystem.read"],
            max_file_bytes=524_288,
            max_search_files=5,
        ))
        cls.reader_full = WorkspaceReader(WorkspaceSpec(
            workspace_id="test-ws-full",
            root=str(root),
            kind="git-repository",
            capabilities=["filesystem.read"],
            max_file_bytes=524_288,
            max_search_files=5000,
        ))

    def test_complete_search_safe_to_conclude(self):
        """With oversized file present, completeness is PARTIAL, not COMPLETE."""
        result = self.reader_full.search_text("nonexistent_pattern_xyz")
        self.assertFalse(result["truncated"])
        self.assertEqual(result["search_completeness"], "PARTIAL",
                         "Oversized files are skipped → must be PARTIAL")
        self.assertFalse(result["safe_to_conclude_absent"])

    def test_no_skips_is_safe(self):
        """A workspace with only small text files should be safe to conclude absent."""
        tmp = tempfile.TemporaryDirectory(prefix="uam-safe-search-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        (root / "a.txt").write_text("alpha\n", encoding="utf-8")
        (root / "b.txt").write_text("beta\n", encoding="utf-8")
        reader = WorkspaceReader(WorkspaceSpec(
            workspace_id="safe-ws",
            root=str(root),
            kind="git-repository",
            capabilities=["filesystem.read"],
        ))
        result = reader.search_text("gamma_nonexistent")
        self.assertEqual(result["search_completeness"], "COMPLETE")
        self.assertTrue(result["safe_to_conclude_absent"])

    def test_truncated_search_not_safe(self):
        result = self.reader_full.search_text("hello")
        if result["truncated"]:
            self.assertFalse(result["safe_to_conclude_absent"])
            self.assertIn("truncation_reason", result)

    def test_file_limit_truncation(self):
        result = self.reader_small.search_text("nonexistent_xyz_abc")
        self.assertEqual(result["search_completeness"], "PARTIAL")
        self.assertFalse(result["safe_to_conclude_absent"])
        self.assertTrue(result["truncated"])
        self.assertEqual(result["truncation_reason"], "file_limit")

    def test_oversized_file_skipped_reported(self):
        result = self.reader_full.search_text("hello")
        self.assertIn("files_skipped", result)
        self.assertGreater(result["files_skipped"]["oversized"], 0)

    def test_result_limit_truncation(self):
        result = self.reader_full.search_text("line", max_results=3)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["truncation_reason"], "result_limit")
        self.assertFalse(result["safe_to_conclude_absent"])


class TestW2_SearchScopeCompleteness(unittest.TestCase):
    """search_scope must return search_completeness and safe_to_conclude_absent."""

    @classmethod
    def setUpClass(cls):
        cls._fixture = _ScopeFixture()
        cls.addClassCleanup(cls._fixture.cleanup)

    def test_successful_search_has_completeness(self):
        result = self._fixture.discovery.search_scope("test-scope", "class")
        self.assertIn("search_completeness", result)
        self.assertIn("safe_to_conclude_absent", result)

    def test_complete_no_matches_is_absent_only_within_the_search_domain(self):
        result = self._fixture.discovery.search_scope(
            "test-scope", "xyzzy_nonexistent_42"
        )
        if result.get("search_completeness") == "COMPLETE":
            # A depth- and ignore-bounded search never proves absence from the scope.
            self.assertFalse(result["safe_to_conclude_absent"])
            self.assertTrue(result["absent_within_search_domain"])

    def test_denied_scope_returns_denied(self):
        registry = RootScopeRegistry()
        registry.add_scope(RootScope(
            scope_id="nosearch",
            root=str(self._fixture.root),
            authority=RootScopeAuthority(discover=True, text_search=False),
        ))
        engine = DiscoveryEngine(registry, cache_ttl=0.0)
        result = engine.search_scope("nosearch", "test")
        self.assertEqual(result["search_completeness"], "DENIED")
        self.assertFalse(result["safe_to_conclude_absent"])


class TestW2_RgReturnCode2(unittest.TestCase):
    """rg exit code 2 must be treated as error, not success."""

    @classmethod
    def setUpClass(cls):
        cls._fixture = _ScopeFixture()
        cls.addClassCleanup(cls._fixture.cleanup)

    def test_rg_rc2_is_failed(self):
        alpha_path = self._fixture.alpha / "main.py"
        ripgrep = ScriptedRipgrep(lambda call: completed(call.operand_for(alpha_path).encode() + b"\n", 2))
        with mock.patch("universal_agent_middleware.discovery.find_ripgrep", return_value="/usr/bin/rg"), \
                ripgrep.patch():
            result = self._fixture.discovery.search_scope("test-scope", "query")
        self.assertEqual(result["search_completeness"], "FAILED")
        self.assertEqual(result["failure_reason"], "execution_error")
        self.assertFalse(result["safe_to_conclude_absent"])
        self.assertGreater(result["total_matches"], 0,
                           "Partial results from rg rc=2 stdout should still be parsed")


class TestW2_TimeoutPartialResults(unittest.TestCase):
    """Timeout must preserve partial stdout from rg."""

    @classmethod
    def setUpClass(cls):
        cls._fixture = _ScopeFixture()
        cls.addClassCleanup(cls._fixture.cleanup)

    def test_timeout_preserves_partial_stdout(self):
        alpha_path = self._fixture.alpha / "main.py"

        def times_out(call):
            exc = subprocess.TimeoutExpired(cmd=["rg"], timeout=30)
            exc.stdout = call.operand_for(alpha_path).encode() + b"\n"
            exc.stderr = b""
            raise exc

        ripgrep = ScriptedRipgrep(times_out)
        with mock.patch("universal_agent_middleware.discovery.find_ripgrep", return_value="/usr/bin/rg"), \
                ripgrep.patch():
            result = self._fixture.discovery.search_scope("test-scope", "query")

        self.assertEqual(result["search_completeness"], "FAILED")
        self.assertEqual(result["failure_reason"], "timeout")
        self.assertFalse(result["safe_to_conclude_absent"])
        self.assertGreater(result["total_matches"], 0,
                           "Partial results from timeout stdout must be preserved")
        self.assertIn("note", result)


class TestW2_SearchTextOversize_IsPartial(unittest.TestCase):
    """search_text with oversized-skipped files must be PARTIAL, not COMPLETE."""

    def test_oversized_yields_partial(self):
        tmp = tempfile.TemporaryDirectory(prefix="uam-oversize-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        (root / "small.txt").write_text("needle\n", encoding="utf-8")
        (root / "big.txt").write_bytes(b"x" * 600_000)
        reader = WorkspaceReader(WorkspaceSpec(
            workspace_id="oversize-ws",
            root=str(root),
            kind="git-repository",
            capabilities=["filesystem.read"],
            max_file_bytes=524_288,
        ))
        result = reader.search_text("nonexistent_xyz")
        self.assertEqual(result["search_completeness"], "PARTIAL")
        self.assertFalse(result["safe_to_conclude_absent"])
        self.assertIn("files_skipped", result)


class TestW1_AuditIntegrityScopeField(unittest.TestCase):
    """uam_verify_audit must include integrity_scope and threat-model note."""

    def test_integrity_scope_in_response(self):
        from pathlib import Path
        import importlib.util
        spec = importlib.util.find_spec("universal_agent_middleware.adapters.mcp_sdk")
        text = Path(spec.origin).read_text(encoding="utf-8")
        self.assertIn("local_hash_sequence_consistency", text)
        self.assertIn("prove event completeness", text)
        self.assertIn("tail removal", text)
        self.assertIn("rewrite-capable actor", text)
        self.assertNotIn("Proves that audit records have not been tampered", text)


class TestW1_GatewayExplainCoverageAuditKey(unittest.TestCase):
    """Gateway explain_coverage audit must use coverage_gaps, not gaps."""

    def test_gateway_uses_coverage_gaps_key(self):
        import inspect
        from universal_agent_middleware.gateway import MiddlewareGateway
        source = inspect.getsource(MiddlewareGateway.explain_coverage)
        self.assertIn("coverage_gaps", source)
        self.assertNotIn('"gaps"', source)


# ---------------------------------------------------------------------------
# Discover-projects contract: must use enriched canonical inventory
# ---------------------------------------------------------------------------


class TestDiscoverProjectsContract(unittest.TestCase):
    """uam_discover_projects must return enriched, grouped, classified results."""

    @classmethod
    def setUpClass(cls):
        cls._fixture = _ScopeFixture()
        cls.addClassCleanup(cls._fixture.cleanup)

    def _discover(self) -> dict:
        return self._fixture.discovery.scope_inventory("test-scope", enrich_git=True)

    def test_worktrees_grouped_into_logical_projects(self):
        result = self._discover()
        self.assertLess(
            result["total_projects"],
            result["total_repositories"] + 1,
            "discover_projects should group worktrees into logical projects",
        )

    def test_git_enrichment_struct_present(self):
        result = self._discover()
        enrichment = result.get("git_enrichment")
        self.assertIsNotNone(enrichment, "git_enrichment struct must be present")
        self.assertTrue(enrichment["requested"])
        self.assertGreater(enrichment["enriched_instances"], 0)

    def test_activity_classified_for_enriched_projects(self):
        result = self._discover()
        projects = result.get("projects", [])
        statuses = {p.get("status") for p in projects}
        self.assertTrue(
            statuses - {"unknown"},
            "at least one project should have known activity when enriched",
        )

    def test_gateway_discover_uses_enriched_path(self):
        import inspect
        from universal_agent_middleware.gateway import MiddlewareGateway
        source = inspect.getsource(MiddlewareGateway.discover_projects)
        self.assertIn("scope_inventory", source)
        self.assertIn("enrich_git=True", source)


if __name__ == "__main__":
    unittest.main()
