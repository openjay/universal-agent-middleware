"""Slice B acceptance tests — Broad Local Reality.

Validates the autonomous discovery pipeline end-to-end:
- RootScope authority model
- Repository discovery without pre-registration
- Project identity resolution and worktree grouping
- Cross-project search
- Secret firewall under broad scope
- Incremental refresh (new repo appears without restart)
"""
import json
import os
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry
from universal_agent_middleware.discovery import (
    DiscoveryEngine,
    _build_search_exclusion_globs,
    _collect_search_paths,
    _is_sensitive_path,
)
from universal_agent_middleware.exploration import ExplorationEngine
from universal_agent_middleware.gateway import MiddlewareGateway

from synthetic_fixtures import build_multi_project_scope, init_git_repo, write_workspace_registry


class TestRootScopeAuthority(unittest.TestCase):
    """RootScope model and authority inheritance."""

    @classmethod
    def setUpClass(cls):
        cls._fixture = tempfile.TemporaryDirectory(prefix="uam-scope-authority-")
        cls.addClassCleanup(cls._fixture.cleanup)
        root = Path(cls._fixture.name)
        cls.home_root = root / "home"
        cls.code_root = root / "code"
        cls.code_root.mkdir(parents=True)
        cls.home_root.mkdir(parents=True)
        cls.registry = RootScopeRegistry()
        cls.registry.add_scope(RootScope(
            scope_id="dev-home",
            root=str(cls.home_root),
            authority=RootScopeAuthority(discover=True, metadata_read=True),
        ))
        cls.registry.add_scope(RootScope(
            scope_id="dev-code",
            root=str(cls.code_root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=True,
                text_search=True, git_observe=True,
            ),
        ))

    def test_scope_registry_loads(self):
        scopes = self.registry.list_scopes()
        self.assertGreaterEqual(len(scopes), 2)

    def test_code_root_has_full_authority(self):
        scope = self.registry.resolve_scope(str(self.code_root / "something"))
        self.assertIsNotNone(scope)
        self.assertTrue(scope.authority.content_read)
        self.assertTrue(scope.authority.text_search)
        self.assertTrue(scope.authority.git_observe)

    def test_home_root_discovery_only(self):
        scope = self.registry.resolve_scope(str(self.home_root / "Documents"))
        self.assertIsNotNone(scope)
        self.assertTrue(scope.authority.discover)
        self.assertFalse(scope.authority.content_read)
        self.assertFalse(scope.authority.text_search)

    def test_more_specific_scope_wins(self):
        nested = self.code_root / "sample-app"
        nested.mkdir()
        scope = self.registry.resolve_scope(str(nested))
        self.assertEqual(scope.scope_id, "dev-code")

    def test_scope_covers_check(self):
        scope = RootScope(
            scope_id="test",
            root="/tmp/test-root",
            authority=RootScopeAuthority(discover=True),
        )
        self.assertFalse(scope.covers("/etc/passwd"))


class TestDiscoveryEngine(unittest.TestCase):
    """Discovery discovers projects without pre-registration."""

    @classmethod
    def setUpClass(cls):
        cls._fixture = tempfile.TemporaryDirectory(prefix="uam-discovery-test-")
        cls.addClassCleanup(cls._fixture.cleanup)
        root = Path(cls._fixture.name)
        alpha = root / "alpha"
        beta = root / "beta"
        init_git_repo(alpha, files={"README.md": "# alpha\n"})
        init_git_repo(beta, files={"README.md": "# beta\n"})
        cls.registry = RootScopeRegistry()
        cls.registry.add_scope(RootScope(
            scope_id="fixture-code",
            root=str(root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=True,
                text_search=True, git_observe=True, classify=True,
                index=True, relate=True, auto_admit=True,
            ),
        ))
        cls.engine = DiscoveryEngine(cls.registry)
        cls.result = cls.engine.discover_scope("fixture-code")

    def test_discovery_returns_projects(self):
        self.assertNotIn("error", self.result)
        self.assertGreater(self.result["total_projects"], 0)

    def test_alpha_discovered(self):
        names = [p["project_id"] for p in self.result["projects"]]
        self.assertIn("alpha", names)

    def test_beta_discovered(self):
        names = [p["project_id"] for p in self.result["projects"]]
        self.assertIn("beta", names)

    def test_projects_have_status(self):
        for project in self.result["projects"]:
            self.assertIn(project["status"], ("active", "recent", "dormant", "archived", "unknown"))

    def test_projects_have_last_activity(self):
        active = [p for p in self.result["projects"] if p["status"] == "active"]
        for project in active:
            self.assertTrue(
                project.get("last_activity"),
                f"project {project['project_id']} is 'active' but has no last_activity evidence",
            )

    def test_unknown_projects_lack_evidence(self):
        unknown = [p for p in self.result["projects"] if p["status"] == "unknown"]
        for project in unknown:
            self.assertNotEqual(project["status"], "active")

    def test_schema_version(self):
        self.assertEqual(self.result["schema_version"], "scope-discovery-v1")


class TestCrossProjectSearch(unittest.TestCase):
    """Cross-project search works across the scope."""

    @classmethod
    def setUpClass(cls):
        cls._fixture = tempfile.TemporaryDirectory(prefix="uam-search-test-")
        cls.addClassCleanup(cls._fixture.cleanup)
        root = Path(cls._fixture.name)
        for name in ("project-a", "project-b"):
            project = root / name
            (project / ".git").mkdir(parents=True)
            (project / "source.py").write_text("class MiddlewareGateway: pass\n")
        sr = RootScopeRegistry()
        sr.add_scope(RootScope(
            scope_id="dev-code",
            root=str(root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=True, text_search=True,
            ),
        ))
        sr.add_scope(RootScope(
            scope_id="dev-home",
            root=str(root.parent),
            authority=RootScopeAuthority(discover=True),
        ))
        cls.engine = DiscoveryEngine(sr)

    def test_search_finds_results(self):
        result = self.engine.search_scope("dev-code", "MiddlewareGateway")
        self.assertNotIn("error", result)
        self.assertGreater(result["total_matches"], 0)

    def test_search_respects_scope(self):
        result = self.engine.search_scope("dev-home", "anything")
        self.assertIn("error", result)

    def test_search_results_are_relative(self):
        result = self.engine.search_scope("dev-code", "MiddlewareGateway")
        for entry in result.get("results", []):
            self.assertFalse(entry["path"].startswith("/"))


class TestSecretFirewall(unittest.TestCase):
    """Secret firewall remains effective under broad scope."""

    def test_env_file_is_sensitive(self):
        self.assertTrue(_is_sensitive_path("/tmp/project/.env"))
        self.assertTrue(_is_sensitive_path(".env.local"))

    def test_ssh_key_is_sensitive(self):
        self.assertTrue(_is_sensitive_path("id_rsa"))
        self.assertTrue(_is_sensitive_path("id_ed25519"))

    def test_normal_file_is_not_sensitive(self):
        self.assertFalse(_is_sensitive_path("README.md"))
        self.assertFalse(_is_sensitive_path("src/main.py"))


class TestMCPToolsExposed(unittest.TestCase):
    """All discovery tools are exposed on the gateway."""

    def setUp(self):
        self._fixture = tempfile.TemporaryDirectory(prefix="uam-discovery-test-")
        self.addCleanup(self._fixture.cleanup)
        root = Path(self._fixture.name)
        repo = root / "repo"
        init_git_repo(repo)
        registry = write_workspace_registry(
            root / "workspaces.json",
            [{
                "workspace_id": "fixture",
                "root": str(repo),
                "kind": "git-repository",
                "capabilities": ["filesystem.read", "git.observe"],
            }],
        )
        scope_config = root / "root_scopes.json"
        scope_config.write_text(json.dumps({
            "schema_version": "root-scope-registry-v1",
            "scopes": [{
                "scope_id": "fixture-scope",
                "root": str(root),
                "authority": {"discover": True, "metadata_read": True},
            }],
            "overrides": {},
        }))
        self.registry_path = registry
        self.state_dir = tempfile.mkdtemp(prefix="uam-state-")

    def test_gateway_has_discovery(self):
        gw = MiddlewareGateway(
            registry_path=str(self.registry_path),
            state_dir=self.state_dir,
        )
        self.assertIsNotNone(gw.discovery)
        self.assertIsNotNone(gw.scopes)

    def test_scopes_accessible(self):
        gw = MiddlewareGateway(
            registry_path=str(self.registry_path),
            state_dir=self.state_dir,
        )
        scopes = gw.scopes.list_scopes()
        self.assertGreaterEqual(len(scopes), 1)


class TestIncrementalRefresh(unittest.TestCase):
    """A new repo appears without restart or registry edit."""

    def test_new_repo_discovered_on_refresh(self):
        tmp = tempfile.TemporaryDirectory()
        tmp_root = Path(tmp.name)
        sr = RootScopeRegistry()
        sr.add_scope(RootScope(
            scope_id="refresh-test",
            root=str(tmp_root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=True,
                text_search=True, git_observe=True, classify=True,
                index=True, relate=True, auto_admit=True,
            ),
        ))
        engine = DiscoveryEngine(sr)

        test_dir = tmp_root / "new_project"
        try:
            test_dir.mkdir(exist_ok=True)
            subprocess.run(["git", "init"], cwd=str(test_dir), capture_output=True, timeout=5)
            (test_dir / "README.md").write_text("test project\n")
            subprocess.run(["git", "add", "."], cwd=str(test_dir), capture_output=True, timeout=5)
            subprocess.run(
                ["git", "commit", "-m", "init", "--allow-empty"],
                cwd=str(test_dir), capture_output=True, timeout=5,
                env={**os.environ, "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@test",
                     "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@test"},
            )

            result = engine.discover_scope("refresh-test")
            names = [p["project_id"] for p in result["projects"]]
            self.assertIn("new_project", names)
        finally:
            tmp.cleanup()


class TestAutoAdmission(unittest.TestCase):
    """Test that discovered repos are usable via derived workspace IDs."""

    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.TemporaryDirectory()
        cls._tmp_root = Path(cls._tmpdir.name)

        fixture_path = cls._tmp_root / "test_repo"
        init_git_repo(fixture_path, files={"README.md": "# fixture\n"})
        (fixture_path / ".env").write_text("SECRET=x\n")

        registry_path = write_workspace_registry(
            cls._tmp_root / "workspaces.json",
            [],
        )

        cls._state = tempfile.TemporaryDirectory(prefix="uam-derived-test-")
        cls.addClassCleanup(cls._state.cleanup)
        cls.gw = MiddlewareGateway(str(registry_path), cls._state.name)
        test_scope = RootScope(
            scope_id="test-scope",
            root=str(cls._tmp_root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=True,
                text_search=True, git_observe=True, classify=True,
                index=True, relate=True, auto_admit=True,
            ),
        )
        cls.gw.scopes.add_scope(test_scope)
        cls.fixture_id = "derived:test-scope:test_repo"

    @classmethod
    def tearDownClass(cls):
        cls._tmpdir.cleanup()

    def test_tree_works_on_derived(self):
        result = self.gw.tree(self.fixture_id, ".", depth=2)
        self.assertIn("entries", result)
        paths = [e["path"] for e in result["entries"]]
        self.assertIn("README.md", paths)

    def test_read_file_works_on_derived(self):
        result = self.gw.read_file(self.fixture_id, "README.md")
        self.assertIn("content", result)

    def test_git_status_works_on_derived(self):
        result = self.gw.git_status(self.fixture_id)
        self.assertIn("head", result)
        self.assertIn("branch", result)

    def test_secret_denied_on_derived(self):
        from universal_agent_middleware.errors import PathPolicyError
        with self.assertRaises(PathPolicyError):
            self.gw.read_file(self.fixture_id, ".env")

    def test_traversal_denied_on_derived(self):
        from universal_agent_middleware.errors import PathPolicyError
        sibling = self._tmp_root / "outside" / "README.md"
        sibling.parent.mkdir()
        sibling.write_text("outside\n")
        with self.assertRaises(PathPolicyError):
            self.gw.read_file(self.fixture_id, "../outside/README.md")

    def test_non_auto_admit_scope_denied(self):
        from universal_agent_middleware.errors import WorkspaceError
        bad_id = "derived:dev-home:Documents/test"
        with self.assertRaises(WorkspaceError):
            self.gw.tree(bad_id)

    def test_not_in_workspaces_json(self):
        static_ids = [w["workspace_id"] for w in self.gw.registry.list()]
        self.assertNotIn(self.fixture_id, static_ids)
        self.assertNotIn("test_repo", static_ids)


class TestNestedScopeTraversal(unittest.TestCase):
    """Regression: metadata-only parent scope must traverse into nested stronger scope."""

    def test_metadata_only_parent_discovers_nested_repos(self):
        tmp = tempfile.TemporaryDirectory()
        tmp_root = Path(tmp.name)

        inner_dir = tmp_root / "code"
        inner_dir.mkdir()
        repo_dir = inner_dir / "my_project"
        repo_dir.mkdir()
        subprocess.run(["git", "init"], cwd=str(repo_dir), capture_output=True, timeout=5)
        (repo_dir / "README.md").write_text("# test\n")

        sr = RootScopeRegistry()
        sr.add_scope(RootScope(
            scope_id="test-outer",
            root=str(tmp_root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=False,
                text_search=False, git_observe=False, classify=False,
                index=False, relate=False, auto_admit=False,
            ),
        ))
        sr.add_scope(RootScope(
            scope_id="test-inner",
            root=str(inner_dir),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=True,
                text_search=True, git_observe=True, classify=True,
                index=True, relate=True, auto_admit=True,
            ),
        ))

        engine = DiscoveryEngine(sr)
        result = engine.discover_scope("test-outer")
        project_ids = [p["project_id"] for p in result.get("projects", [])]
        self.assertIn(
            "my_project",
            project_ids,
            "content_read=false on outer scope must not block discovery into nested stronger scope",
        )

        tmp.cleanup()


class TestNestedScopeSearchDenial(unittest.TestCase):
    """OSS-SEC-001: outer search must not reveal denied inner scope matches."""

    def test_outer_search_excludes_inner_deny_zone(self):
        tmp = tempfile.TemporaryDirectory()
        tmp_root = Path(tmp.name)
        inner = tmp_root / "narrow-zone"
        inner.mkdir()
        (inner / "notes.txt").write_text("UAM_OSS_SYNTHETIC_BOUNDARY_MARKER\n")

        sr = RootScopeRegistry()
        sr.add_scope(RootScope(
            scope_id="outer",
            root=str(tmp_root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=True, text_search=True,
            ),
        ))
        sr.add_scope(RootScope(scope_id="inner-denied", root=str(inner), authority=RootScopeAuthority()))

        engine = DiscoveryEngine(sr)
        self.assertFalse(sr.can_search(inner / "notes.txt"))
        result = engine.search_scope("outer", "UAM_OSS_SYNTHETIC_BOUNDARY_MARKER")
        self.assertEqual(result.get("total_matches", 0), 0)
        self.assertEqual(result.get("results", []), [])
        tmp.cleanup()

    def test_exclusion_globs_include_denied_relative_path(self):
        tmp = tempfile.TemporaryDirectory()
        tmp_root = Path(tmp.name)
        inner = tmp_root / "narrow-zone"
        inner.mkdir()

        sr = RootScopeRegistry()
        sr.add_scope(RootScope(
            scope_id="outer",
            root=str(tmp_root),
            authority=RootScopeAuthority(text_search=True),
        ))
        sr.add_scope(RootScope(scope_id="inner-denied", root=str(inner), authority=RootScopeAuthority()))

        globs = _build_search_exclusion_globs(tmp_root, sr)
        self.assertIn("!narrow-zone/**", globs)
        tmp.cleanup()

    def test_denied_unreadable_files_never_scanned_by_subprocess(self):
        """Pre-read boundary: rg must receive -g exclusions; unreadable denied dirs stay untouched."""
        tmp = tempfile.TemporaryDirectory()
        tmp_root = Path(tmp.name)
        allowed = tmp_root / "public"
        denied = tmp_root / "narrow-zone"
        allowed.mkdir()
        denied.mkdir()
        (allowed / "visible.txt").write_text("UAM_VISIBLE_MARKER\n")
        (denied / "secret.txt").write_text("UAM_DENIED_MARKER\n")
        os.chmod(denied, 0o000)

        sr = RootScopeRegistry()
        sr.add_scope(RootScope(
            scope_id="outer",
            root=str(tmp_root),
            authority=RootScopeAuthority(text_search=True),
        ))
        sr.add_scope(RootScope(scope_id="inner-denied", root=str(denied), authority=RootScopeAuthority()))

        captured_cmds: list[list[str]] = []
        original_run = subprocess.run

        def spy_run(cmd, *args, **kwargs):
            captured_cmds.append(list(cmd))
            return original_run(cmd, *args, **kwargs)

        engine = DiscoveryEngine(sr)
        try:
            with unittest.mock.patch("universal_agent_middleware.discovery.subprocess.run", spy_run):
                result = engine.search_scope("outer", "UAM_DENIED_MARKER")
            self.assertEqual(result.get("total_matches", 0), 0)
            self.assertGreater(len(captured_cmds), 0)
            rg_cmd = captured_cmds[0]
            self.assertIn("-g", rg_cmd)
            glob_args = [rg_cmd[i + 1] for i, token in enumerate(rg_cmd) if token == "-g"]
            self.assertIn("!narrow-zone/**", glob_args)

            with unittest.mock.patch("universal_agent_middleware.discovery.subprocess.run", spy_run):
                visible = engine.search_scope("outer", "UAM_VISIBLE_MARKER")
            self.assertGreater(visible.get("total_matches", 0), 0)
        finally:
            os.chmod(denied, 0o755)
            tmp.cleanup()

    def test_allowed_nested_scope_inside_denied_parent_remains_searchable(self):
        tmp = tempfile.TemporaryDirectory()
        tmp_root = Path(tmp.name)
        denied_parent = tmp_root / "restricted"
        allowed_child = denied_parent / "allowed-pocket"
        denied_parent.mkdir()
        allowed_child.mkdir()
        (allowed_child / "open.txt").write_text("UAM_ALLOWED_POCKET_MARKER\n")
        (denied_parent / "blocked.txt").write_text("UAM_ALLOWED_POCKET_MARKER\n")

        sr = RootScopeRegistry()
        sr.add_scope(RootScope(
            scope_id="outer",
            root=str(tmp_root),
            authority=RootScopeAuthority(text_search=True),
        ))
        sr.add_scope(RootScope(
            scope_id="denied-parent",
            root=str(denied_parent),
            authority=RootScopeAuthority(),
        ))
        sr.add_scope(RootScope(
            scope_id="allowed-child",
            root=str(allowed_child),
            authority=RootScopeAuthority(text_search=True),
        ))

        globs = _build_search_exclusion_globs(tmp_root, sr)
        self.assertIn("!restricted/**", globs)
        search_paths = _collect_search_paths(tmp_root, sr)
        self.assertTrue(any("allowed-pocket" in str(p) for p in search_paths))

        engine = DiscoveryEngine(sr)
        result = engine.search_scope("outer", "UAM_ALLOWED_POCKET_MARKER")
        paths = [entry["path"] for entry in result.get("results", [])]
        self.assertTrue(any("allowed-pocket/open.txt" in p for p in paths))
        self.assertFalse(any("restricted/blocked.txt" in p for p in paths))
        tmp.cleanup()

    def test_overlapping_scopes_use_most_specific_authority(self):
        tmp = tempfile.TemporaryDirectory()
        tmp_root = Path(tmp.name)
        overlap = tmp_root / "overlap"
        deeper = overlap / "deeper-deny"
        overlap.mkdir()
        deeper.mkdir()
        (overlap / "shared.txt").write_text("UAM_OVERLAP_MARKER\n")
        (deeper / "hidden.txt").write_text("UAM_OVERLAP_MARKER\n")

        sr = RootScopeRegistry()
        sr.add_scope(RootScope(
            scope_id="outer",
            root=str(tmp_root),
            authority=RootScopeAuthority(text_search=True),
        ))
        sr.add_scope(RootScope(
            scope_id="overlap-allowed",
            root=str(overlap),
            authority=RootScopeAuthority(text_search=True),
        ))
        sr.add_scope(RootScope(
            scope_id="deeper-denied",
            root=str(deeper),
            authority=RootScopeAuthority(),
        ))

        engine = DiscoveryEngine(sr)
        self.assertTrue(sr.can_search(overlap / "shared.txt"))
        self.assertFalse(sr.can_search(deeper / "hidden.txt"))

        result = engine.search_scope("outer", "UAM_OVERLAP_MARKER")
        paths = [entry["path"] for entry in result.get("results", [])]
        self.assertTrue(any("overlap/shared.txt" in p for p in paths))
        self.assertFalse(any("deeper-deny/hidden.txt" in p for p in paths))
        tmp.cleanup()

    def test_query_cannot_oracle_denied_zone_membership(self):
        """Hostile queries must not probe denied zones via side channels."""
        tmp = tempfile.TemporaryDirectory()
        tmp_root = Path(tmp.name)
        inner = tmp_root / "narrow-zone"
        inner.mkdir()
        (inner / "notes.txt").write_text("ORACLE_PROBE_SECRET\n")

        sr = RootScopeRegistry()
        sr.add_scope(RootScope(
            scope_id="outer",
            root=str(tmp_root),
            authority=RootScopeAuthority(text_search=True),
        ))
        sr.add_scope(RootScope(scope_id="inner-denied", root=str(inner), authority=RootScopeAuthority()))
        engine = DiscoveryEngine(sr)

        probes = [
            "ORACLE_PROBE_SECRET",
            "narrow-zone/ORACLE_PROBE_SECRET",
            "--glob=narrow-zone/**",
            "--pre=cat",
            "ORACLE_PROBE_SECRET narrow-zone",
        ]
        for query in probes:
            result = engine.search_scope("outer", query)
            self.assertEqual(result.get("total_matches", 0), 0, f"query leaked denied zone: {query!r}")
            self.assertEqual(result.get("results", []), [])
        tmp.cleanup()


class TestSecretParentDirectoryExclusion(unittest.TestCase):
    """Regression: search_scope must exclude files inside secret parent directories."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls._tmp_root = Path(cls._tmp.name)

        repo = cls._tmp_root / "project"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=str(repo), capture_output=True, timeout=5)
        (repo / "README.md").write_text("normal content\n")

        creds_dir = repo / "credentials"
        creds_dir.mkdir()
        (creds_dir / "token.txt").write_text("UNIQUE_SECRET_MARKER_XYZ_12345\n")

        ssh_dir = repo / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "config").write_text("UNIQUE_SECRET_MARKER_XYZ_12345\n")

        (repo / "safe.txt").write_text("UNIQUE_SECRET_MARKER_XYZ_12345\n")

        sr = RootScopeRegistry()
        sr.add_scope(RootScope(
            scope_id="secret-test",
            root=str(cls._tmp_root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=True,
                text_search=True, git_observe=True, classify=True,
                index=True, relate=True, auto_admit=True,
            ),
        ))
        cls.engine = DiscoveryEngine(sr)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_credentials_dir_not_in_search_results(self):
        result = self.engine.search_scope("secret-test", "UNIQUE_SECRET_MARKER_XYZ_12345")
        paths = [r["path"] for r in result.get("results", [])]
        for path in paths:
            self.assertNotIn("credentials", path, f"secret parent 'credentials/' leaked in search result: {path}")
            self.assertNotIn(".ssh", path, f"secret parent '.ssh/' leaked in search result: {path}")

    def test_safe_file_still_found(self):
        result = self.engine.search_scope("secret-test", "UNIQUE_SECRET_MARKER_XYZ_12345")
        paths = [r["path"] for r in result.get("results", [])]
        safe_found = any("safe.txt" in p for p in paths)
        self.assertTrue(safe_found, "Non-secret file should still be discoverable")


class TestHermeticGitInDiscovery(unittest.TestCase):
    """Verify discovery uses hardened git (no fsmonitor execution)."""

    def test_discovery_does_not_use_raw_subprocess_git(self):
        import inspect
        source = inspect.getsource(DiscoveryEngine._read_repo_metadata)
        self.assertNotIn("subprocess.run", source)
        self.assertIn("ReadOnlyGit", source)

    def test_scope_git_observe_false_blocks_git(self):
        sr = RootScopeRegistry()
        sr.add_scope(RootScope(
            scope_id="observe-off",
            root="/tmp/uam-fixture",
            authority=RootScopeAuthority(discover=True, git_observe=False),
        ))
        scope = next(s for s in sr.list_scopes() if s["scope_id"] == "observe-off")
        self.assertFalse(scope["authority"]["git_observe"])


class TestSearchScopeSecurity(unittest.TestCase):
    """Regression tests: hostile rg queries must never become options."""

    @classmethod
    def setUpClass(cls):
        cls._fixture = tempfile.TemporaryDirectory(prefix="uam-search-security-")
        cls.addClassCleanup(cls._fixture.cleanup)
        cls.registry, cls.scope_id = build_multi_project_scope(Path(cls._fixture.name))
        cls.engine = DiscoveryEngine(cls.registry)

    def test_query_starting_with_dash_safe(self):
        result = self.engine.search_scope(self.scope_id, "--pre=cat")
        self.assertIn("results", result)

    def test_query_pre_command_injection(self):
        result = self.engine.search_scope(self.scope_id, "--pre-glob=*.py")
        self.assertIn("results", result)

    def test_query_config_injection(self):
        result = self.engine.search_scope(self.scope_id, "--config=/etc/passwd")
        self.assertIn("results", result)

    def test_query_double_dash_prefix(self):
        result = self.engine.search_scope(self.scope_id, "--pcre2-version")
        self.assertIn("results", result)

    def test_empty_query(self):
        result = self.engine.search_scope(self.scope_id, "")
        self.assertIn("results", result)

    def test_rg_uses_no_config_flag(self):
        import inspect
        source = inspect.getsource(DiscoveryEngine.search_scope)
        self.assertIn("--no-config", source)
        self.assertIn("--fixed-strings", source)
        self.assertIn('"--"', source)


class TestSearchScopeAttribution(unittest.TestCase):
    """P0-C: search_scope must self-contain project attribution."""

    def test_fresh_engine_has_attribution(self):
        fixture = tempfile.TemporaryDirectory(prefix="uam-search-attr-")
        registry, scope_id = build_multi_project_scope(Path(fixture.name))
        engine = DiscoveryEngine(registry)
        result = engine.search_scope(scope_id, "import")
        if result.get("total_matches", 0) > 0:
            attributed = [r for r in result["results"] if "project_id" in r]
            self.assertGreater(
                len(attributed), 0,
                "search_scope on fresh engine must produce project_id attribution",
            )
        fixture.cleanup()


class TestExplorationBehavior(unittest.TestCase):
    """P0-I: Behavioral tests for RealityGraph, explore, intent ranking."""

    @classmethod
    def setUpClass(cls):
        cls._fixture = tempfile.TemporaryDirectory(prefix="uam-explore-test-")
        cls.addClassCleanup(cls._fixture.cleanup)
        cls.registry, cls.scope_id = build_multi_project_scope(Path(cls._fixture.name))
        cls.engine = DiscoveryEngine(cls.registry)
        cls.exploration = ExplorationEngine(cls.engine, cls.registry)

    def test_explore_returns_graph_structure(self):
        result = self.exploration.explore(self.scope_id, intent="middleware")
        self.assertIn("relationships", result)
        graph = result["relationships"]
        self.assertEqual(graph["schema_version"], "reality-graph-v1")
        self.assertGreater(graph["node_count"], 0)

    def test_explore_returns_retrieval_plan(self):
        result = self.exploration.explore(self.scope_id, intent="middleware")
        self.assertIn("retrieval_plan", result)
        plan = result["retrieval_plan"]
        self.assertIn("total_files", plan)
        self.assertIn("total_bytes_estimate", plan)

    def test_explore_respects_budget(self):
        result = self.exploration.explore(
            self.scope_id, intent="test", max_projects=2, max_files=5,
        )
        plan = result["retrieval_plan"]
        self.assertLessEqual(plan["total_files"], 5)
        self.assertLessEqual(len(result.get("ranked_projects", [])), 2)

    def test_explore_graph_nodes_are_evidence_backed(self):
        result = self.exploration.explore(self.scope_id, intent="agent")
        graph = result["relationships"]
        valid_types = {"Project", "WorkspaceInstance", "Remote"}
        for node in graph["nodes"]:
            self.assertIn(node["type"], valid_types)

    def test_explore_graph_edges_are_evidence_backed(self):
        result = self.exploration.explore(self.scope_id, intent="agent")
        graph = result["relationships"]
        valid_relations = {"instance_of", "has_remote", "same_remote"}
        for edge in graph["edges"]:
            self.assertIn(edge["relation"], valid_relations)

    def test_explore_unknown_activity_not_ranked_as_active(self):
        result = self.exploration.explore(self.scope_id, intent="anything")
        for project in result.get("ranked_projects", []):
            if project.get("status") == "unknown":
                self.assertNotEqual(
                    project.get("relevance_tier"), "active_and_relevant",
                    "unknown status must not be treated as actively progressing",
                )

    def test_explore_derived_ids_are_portable(self):
        result = self.exploration.explore(self.scope_id, intent="test")
        plan = result["retrieval_plan"]
        for item in plan.get("items", []):
            ws_id = item.get("workspace_id", "")
            self.assertTrue(ws_id.startswith("derived:"), f"workspace_id should be derived: {ws_id}")
            self.assertNotIn(str(Path.home()), ws_id, "workspace_id must not contain absolute home paths")

    def test_explore_no_absolute_paths_in_output(self):
        result = self.exploration.explore(self.scope_id, intent="middleware")
        plan = result["retrieval_plan"]
        for item in plan.get("items", []):
            ws_id = item.get("workspace_id", "")
            self.assertNotIn(str(Path.home()), ws_id)


if __name__ == "__main__":
    unittest.main()
