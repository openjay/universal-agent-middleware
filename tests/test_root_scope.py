"""R1 security regression tests for UAM v0.6 authorization hardening.

Covers:
- P0-A: derived admission respects most-specific inner deny scopes
- P0-B: revocation invalidates cached derived access
- R2: unified resolver for snapshot/bootstrap on derived workspaces
- R2: ambiguous name disambiguation
- R3: fast discovery vs lazy git enrichment
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from universal_agent_middleware.discovery import DiscoveryEngine
from universal_agent_middleware.errors import WorkspaceError
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.resolver import ResolutionError
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry

from scope_search_instruments import ScriptedRipgrep, completed, handed_relative_paths
from synthetic_fixtures import init_git_repo, write_workspace_registry


class TestMostSpecificDeny(unittest.TestCase):
    """P0-A: inner scope deny must block derived admission even when outer permits."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)

        outer = self._root / "outer"
        inner = outer / "denied-repo"
        outer.mkdir()
        inner.mkdir()
        init_git_repo(inner, files={"secret.txt": "INNER DENIED CONTENT\n"})

        allowed = outer / "allowed-repo"
        init_git_repo(allowed, files={"README.md": "# allowed\n"})

        registry_path = write_workspace_registry(self._root / "workspaces.json", [])
        self._state = tempfile.TemporaryDirectory(prefix="uam-deny-test-")
        self.gw = MiddlewareGateway(str(registry_path), self._state.name)

        self.gw.scopes.add_scope(RootScope(
            scope_id="outer-scope",
            root=str(outer),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=True,
                text_search=True, git_observe=True, auto_admit=True,
            ),
        ))
        self.gw.scopes.add_scope(RootScope(
            scope_id="inner-deny",
            root=str(inner),
            authority=RootScopeAuthority(
                discover=False, metadata_read=False, content_read=False,
                text_search=False, git_observe=False, auto_admit=False,
            ),
        ))

        self.allowed_id = "derived:outer-scope:allowed-repo"
        self.denied_id = "derived:outer-scope:denied-repo"

    def tearDown(self):
        self._state.cleanup()
        self._tmp.cleanup()

    def test_outer_scope_can_read_allowed_repo(self):
        result = self.gw.read_file(self.allowed_id, "README.md")
        self.assertIn("content", result)

    def test_inner_deny_blocks_derived_read(self):
        with self.assertRaises((WorkspaceError, ResolutionError)):
            self.gw.read_file(self.denied_id, "secret.txt")

    def test_inner_deny_blocks_derived_tree(self):
        with self.assertRaises((WorkspaceError, ResolutionError)):
            self.gw.tree(self.denied_id)

    def test_inner_deny_blocks_derived_git(self):
        with self.assertRaises((WorkspaceError, ResolutionError)):
            self.gw.git_status(self.denied_id)

    def test_scopes_can_read_reflects_inner_deny(self):
        self.assertFalse(self.gw.scopes.can_read(self._root / "outer" / "denied-repo" / "secret.txt"))
        self.assertTrue(self.gw.scopes.can_read(self._root / "outer" / "allowed-repo" / "README.md"))


class TestRevocationInvalidation(unittest.TestCase):
    """P0-B: policy revocation must invalidate previously admitted derived access."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        repo = self._root / "revoke-me"
        init_git_repo(repo, files={"data.txt": "REVOCABLE CONTENT\n"})

        registry_path = write_workspace_registry(self._root / "workspaces.json", [])
        self._state = tempfile.TemporaryDirectory(prefix="uam-revoke-test-")
        self.gw = MiddlewareGateway(str(registry_path), self._state.name)

        self.scope = RootScope(
            scope_id="revoke-scope",
            root=str(self._root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=True,
                text_search=True, git_observe=True, auto_admit=True,
            ),
        )
        self.gw.scopes.add_scope(self.scope)
        self.ws_id = "derived:revoke-scope:revoke-me"

    def tearDown(self):
        self._state.cleanup()
        self._tmp.cleanup()

    def test_read_succeeds_before_revocation(self):
        result = self.gw.read_file(self.ws_id, "data.txt")
        self.assertIn("REVOCABLE", result["content"])

    def test_read_denied_after_revocation(self):
        self.gw.read_file(self.ws_id, "data.txt")

        revoked_scope = RootScope(
            scope_id="revoke-scope",
            root=str(self._root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=False,
                text_search=False, git_observe=False, auto_admit=False,
            ),
        )
        self.gw.scopes.replace_scopes([revoked_scope])
        self.gw.discovery.invalidate_cache()

        with self.assertRaises((WorkspaceError, ResolutionError)):
            self.gw.read_file(self.ws_id, "data.txt")

    def test_no_stale_capability_cache(self):
        """Capabilities must be recomputed on each access, not cached permanently."""
        self.gw.read_file(self.ws_id, "data.txt")

        revoked_scope = RootScope(
            scope_id="revoke-scope",
            root=str(self._root),
            authority=RootScopeAuthority(
                discover=True, content_read=False, auto_admit=False,
            ),
        )
        self.gw.scopes.replace_scopes([revoked_scope])

        caps = self.gw.resolver.admission._capabilities_for_path(
            (self._root / "revoke-me").resolve()
        )
        self.assertEqual(caps, [])


class TestUnifiedResolver(unittest.TestCase):
    """R2: unified resolution for derived handles, names, and snapshot/bootstrap."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        repo = self._root / "sample-app"
        init_git_repo(repo, files={"README.md": "# sample-app\n"})

        registry_path = write_workspace_registry(self._root / "workspaces.json", [])
        self._state = tempfile.TemporaryDirectory(prefix="uam-resolver-test-")
        self.gw = MiddlewareGateway(str(registry_path), self._state.name)

        self.gw.scopes.add_scope(RootScope(
            scope_id="dev-code",
            root=str(self._root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=True,
                text_search=True, git_observe=True, auto_admit=True,
            ),
        ))
        self.derived_id = "derived:dev-code:sample-app"

    def tearDown(self):
        self._state.cleanup()
        self._tmp.cleanup()

    def test_resolve_derived_handle(self):
        resolution = self.gw.resolve_workspace(self.derived_id)
        self.assertEqual(resolution.resolution_kind, "derived")
        self.assertEqual(resolution.workspace_id, self.derived_id)

    def test_resolve_by_project_name(self):
        resolution = self.gw.resolve_workspace("sample-app")
        self.assertEqual(resolution.resolution_kind, "project_name")
        self.assertTrue(resolution.workspace_id.startswith("derived:"))

    def test_read_via_project_name(self):
        result = self.gw.read_file("sample-app", "README.md")
        self.assertIn("sample-app", result["content"])

    def test_read_via_derived_handle(self):
        result = self.gw.read_file(self.derived_id, "README.md")
        self.assertIn("sample-app", result["content"])

    def test_resolve_includes_policy_generation(self):
        resolution = self.gw.resolve_workspace(self.derived_id)
        self.assertTrue(len(resolution.policy_generation) > 0)


class TestAmbiguousResolution(unittest.TestCase):
    """R2: ambiguous project names return structured disambiguation errors."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)

        scope_a = self._root / "scope-a"
        scope_b = self._root / "scope-b"
        scope_a.mkdir()
        scope_b.mkdir()

        init_git_repo(scope_a / "sample-app", files={"README.md": "# scope A\n"})
        init_git_repo(scope_b / "sample-app", files={"README.md": "# scope B\n"})

        registry_path = write_workspace_registry(self._root / "workspaces.json", [])
        self._state = tempfile.TemporaryDirectory(prefix="uam-ambig-test-")
        self.gw = MiddlewareGateway(str(registry_path), self._state.name)

        for sid, sroot in [("scope-a", scope_a), ("scope-b", scope_b)]:
            self.gw.scopes.add_scope(RootScope(
                scope_id=sid,
                root=str(sroot),
                authority=RootScopeAuthority(
                    discover=True, content_read=True, git_observe=True, auto_admit=True,
                ),
            ))

    def tearDown(self):
        self._state.cleanup()
        self._tmp.cleanup()

    def test_ambiguous_name_raises_with_candidates(self):
        with self.assertRaises(ResolutionError) as ctx:
            self.gw.resolver.resolve("sample-app")
        exc = ctx.exception
        self.assertEqual(exc.kind, "AMBIGUOUS")
        self.assertGreaterEqual(len(exc.candidates), 2)


class TestFastDiscovery(unittest.TestCase):
    """R3: fast discovery decoupled from git enrichment."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        for name in ("alpha", "beta", "gamma"):
            init_git_repo(self._root / name, files={"README.md": f"# {name}\n"})

        self.registry = RootScopeRegistry()
        self.registry.add_scope(RootScope(
            scope_id="fast-test",
            root=str(self._root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=True,
                git_observe=True, auto_admit=True,
            ),
        ))
        self.engine = DiscoveryEngine(self.registry)

    def tearDown(self):
        self._tmp.cleanup()

    def test_fast_scan_finds_repos_without_git(self):
        start = time.time()
        result = self.engine.discover_scope("fast-test", enrich_git=False)
        elapsed = time.time() - start

        self.assertNotIn("error", result)
        self.assertEqual(result["total_repositories"], 3)
        self.assertFalse(result.get("git_enriched", True))
        self.assertLess(elapsed, 5.0, "fast scan should complete quickly without git subprocesses")

    def test_fast_scan_instances_have_workspace_id(self):
        result = self.engine.discover_scope("fast-test", enrich_git=False)
        for project in result["projects"]:
            for inst in project["instances"]:
                self.assertTrue(
                    inst.get("workspace_id", "").startswith("derived:"),
                    f"instance missing workspace_id: {inst}",
                )

    def test_enriched_scan_populates_git_metadata(self):
        result = self.engine.discover_scope("fast-test", enrich_git=True)
        self.assertTrue(result.get("git_enriched"))
        has_head = any(
            inst.get("head")
            for p in result["projects"]
            for inst in p["instances"]
        )
        self.assertTrue(has_head, "enriched scan should populate git HEAD")

    def test_multi_scope_cache_independent(self):
        other_root = self._root.parent / "other-scope"
        other_root.mkdir(exist_ok=True)
        init_git_repo(other_root / "delta", files={"README.md": "# delta\n"})
        self.registry.add_scope(RootScope(
            scope_id="other-scope",
            root=str(other_root),
            authority=RootScopeAuthority(discover=True, git_observe=True),
        ))

        self.engine.scope_inventory("fast-test")
        self.engine.scope_inventory("other-scope")

        self.assertEqual(len(self.engine._cache), 2)

    def test_cache_ttl_from_observation_completion(self):
        result1 = self.engine.scope_inventory("fast-test")
        self.assertFalse(result1["freshness"]["cache_hit"])

        result2 = self.engine.scope_inventory("fast-test")
        self.assertTrue(result2["freshness"]["cache_hit"])
        self.assertGreaterEqual(result2["freshness"]["cache_age_ms"], 0)

    def test_policy_change_invalidates_cache(self):
        self.engine.scope_inventory("fast-test")
        self.assertEqual(len(self.engine._cache), 1)

        self.registry.add_scope(RootScope(
            scope_id="new-inner",
            root=str(self._root / "alpha"),
            authority=RootScopeAuthority(content_read=False),
        ))
        self.engine.invalidate_cache()

        key = self.engine._cache_key("fast-test")
        self.assertNotIn(key, self.engine._cache)


class TestDerivedSnapshotBootstrap(unittest.TestCase):
    """R2: snapshot and bootstrap work on derived workspaces via unified resolver."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        repo = self._root / "bootstrap-test"
        init_git_repo(repo, files={"README.md": "# bootstrap test\n", "AGENTS.md": "# agents\n"})

        registry_path = write_workspace_registry(self._root / "workspaces.json", [])
        self._state = tempfile.TemporaryDirectory(prefix="uam-bootstrap-test-")
        self.gw = MiddlewareGateway(str(registry_path), self._state.name)

        self.gw.scopes.add_scope(RootScope(
            scope_id="test-scope",
            root=str(self._root),
            authority=RootScopeAuthority(
                discover=True, content_read=True, git_observe=True, auto_admit=True,
            ),
        ))
        self.ws_id = "derived:test-scope:bootstrap-test"

    def tearDown(self):
        self._state.cleanup()
        self._tmp.cleanup()

    def test_resolve_workspace_for_derived(self):
        resolution = self.gw.resolve_workspace(self.ws_id)
        self.assertEqual(resolution.resolution_kind, "derived")
        self.assertIn("filesystem.read", resolution.spec.capabilities)

    def test_git_status_on_derived_via_resolver(self):
        result = self.gw.git_status(self.ws_id)
        self.assertIn("head", result)
        self.assertIn("branch", result)


class TestStaticRegistryPriority(unittest.TestCase):
    """Static workspaces.json entries retain priority over derived resolution."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        repo = self._root / "primary"
        init_git_repo(repo, files={"README.md": "# static primary\n"})

        registry_path = write_workspace_registry(
            self._root / "workspaces.json",
            [{
                "workspace_id": "primary",
                "root": str(repo),
                "kind": "git-repository",
                "capabilities": ["filesystem.read", "git.observe"],
            }],
        )
        self._state = tempfile.TemporaryDirectory(prefix="uam-static-test-")
        self.gw = MiddlewareGateway(str(registry_path), self._state.name)

    def tearDown(self):
        self._state.cleanup()
        self._tmp.cleanup()

    def test_static_id_resolves_as_static(self):
        resolution = self.gw.resolve_workspace("primary")
        self.assertEqual(resolution.resolution_kind, "static")

    def test_static_read_works(self):
        result = self.gw.read_file("primary", "README.md")
        self.assertIn("static primary", result["content"])


class TestStaticCapabilityDenial(unittest.TestCase):
    """GAP-02: static registry IDs must not fall through to dynamic resolution."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        static_repo = self._root / "static-only"
        dynamic_repo = self._root / "conflict-name"
        init_git_repo(static_repo, files={"README.md": "# static\n"})
        init_git_repo(dynamic_repo, files={"README.md": "# dynamic\n"})

        registry_path = write_workspace_registry(
            self._root / "workspaces.json",
            [{
                "workspace_id": "conflict-name",
                "root": str(static_repo),
                "kind": "git-repository",
                "capabilities": ["filesystem.read"],
            }],
        )
        self._state = tempfile.TemporaryDirectory(prefix="uam-static-deny-")
        self.gw = MiddlewareGateway(str(registry_path), self._state.name)
        self.gw.scopes.add_scope(RootScope(
            scope_id="auto-scope",
            root=str(self._root),
            authority=RootScopeAuthority(
                discover=True, content_read=True, git_observe=True, auto_admit=True,
                index=True,
            ),
        ))
        self.gw.index_scope("auto-scope")

    def tearDown(self):
        self._state.cleanup()
        self._tmp.cleanup()

    def test_missing_capability_returns_denied_not_dynamic(self):
        with self.assertRaises(ResolutionError) as ctx:
            self.gw.resolver.resolve("conflict-name", capability="git.observe")
        self.assertEqual(ctx.exception.kind, "DENIED")

    def test_static_filesystem_read_still_works(self):
        result = self.gw.read_file("conflict-name", "README.md")
        self.assertIn("static", result["content"])


class TestDynamicConfigReload(unittest.TestCase):
    """GAP-01: on-disk policy changes must take effect without process restart."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        repo = self._root / "reload-me"
        init_git_repo(repo, files={"data.txt": "BEFORE REVOKE\n"})

        self.registry_path = write_workspace_registry(self._root / "workspaces.json", [])
        self.scopes_path = self._root / "root_scopes.json"
        self.scopes_path.write_text(json.dumps({
            "scopes": [{
                "scope_id": "reload-scope",
                "root": str(self._root),
                "authority": RootScopeAuthority(
                    discover=True, content_read=True, git_observe=True, auto_admit=True,
                ).to_dict(),
            }],
        }), encoding="utf-8")

        self._state = tempfile.TemporaryDirectory(prefix="uam-reload-test-")
        self.gw = MiddlewareGateway(str(self.registry_path), self._state.name)
        self.ws_id = "derived:reload-scope:reload-me"
        self.gen_before = self.gw.scopes.policy_generation

    def tearDown(self):
        self._state.cleanup()
        self._tmp.cleanup()

    def test_scope_file_reload_updates_policy_generation(self):
        self.gw.read_file(self.ws_id, "data.txt")
        self.scopes_path.write_text(json.dumps({
            "scopes": [{
                "scope_id": "reload-scope",
                "root": str(self._root),
                "authority": RootScopeAuthority(
                    discover=True, content_read=False, auto_admit=False,
                ).to_dict(),
            }],
        }), encoding="utf-8")
        time.sleep(0.05)
        if hasattr(os, "utime"):
            os.utime(self.scopes_path, None)

        self.assertNotEqual(self.gw.scopes.policy_generation, self.gen_before)

    def test_revocation_via_file_reload_denies_access(self):
        self.gw.read_file(self.ws_id, "data.txt")
        self.scopes_path.write_text(json.dumps({
            "scopes": [{
                "scope_id": "reload-scope",
                "root": str(self._root),
                "authority": RootScopeAuthority(
                    discover=True, content_read=False, auto_admit=False,
                ).to_dict(),
            }],
        }), encoding="utf-8")
        if hasattr(os, "utime"):
            os.utime(self.scopes_path, None)

        with self.assertRaises((WorkspaceError, ResolutionError)):
            self.gw.read_file(self.ws_id, "data.txt")

    def test_scope_file_deletion_revokes_access(self):
        self.gw.read_file(self.ws_id, "data.txt")
        self.scopes_path.unlink()
        self.assertEqual(len(self.gw.scopes.list_scopes()), 0)
        with self.assertRaises((WorkspaceError, ResolutionError)):
            self.gw.read_file(self.ws_id, "data.txt")

    def test_scope_file_mtime_preserving_replacement_revokes(self):
        self.gw.read_file(self.ws_id, "data.txt")
        deny_payload = json.dumps({
            "scopes": [{
                "scope_id": "reload-scope",
                "root": str(self._root),
                "authority": RootScopeAuthority(
                    discover=True, content_read=False, auto_admit=False,
                ).to_dict(),
            }],
        }, separators=(",", ":"))
        stat = self.scopes_path.stat()
        self.scopes_path.write_text(deny_payload, encoding="utf-8")
        os.utime(self.scopes_path, ns=(stat.st_mtime_ns, stat.st_mtime_ns))
        self.assertNotEqual(self.gw.scopes.policy_generation, self.gen_before)
        with self.assertRaises((WorkspaceError, ResolutionError)):
            self.gw.read_file(self.ws_id, "data.txt")


class TestMetadataOnlyAuthorizationLabels(unittest.TestCase):
    """Discovered metadata-only instances must not appear as content-authorized."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        outer = self._root / "outer"
        inner = outer / "metadata-repo"
        outer.mkdir()
        init_git_repo(inner, files={"secret.txt": "METADATA ONLY\n"})

        registry_path = write_workspace_registry(self._root / "workspaces.json", [])
        self.scopes_path = self._root / "root_scopes.json"
        self.scopes_path.write_text(json.dumps({
            "scopes": [
                {
                    "scope_id": "outer-scope",
                    "root": str(outer),
                    "authority": RootScopeAuthority(
                        discover=True, metadata_read=True, content_read=False,
                        auto_admit=False, index=True,
                    ).to_dict(),
                },
                {
                    "scope_id": "inner-scope",
                    "root": str(inner),
                    "authority": RootScopeAuthority(
                        discover=True, content_read=False, auto_admit=False,
                        index=True,
                    ).to_dict(),
                },
            ],
        }), encoding="utf-8")

        self._state = tempfile.TemporaryDirectory(prefix="uam-meta-labels-")
        self.gw = MiddlewareGateway(str(registry_path), self._state.name)
        self.gw.index_scope("outer-scope")

    def tearDown(self):
        self._state.cleanup()
        self._tmp.cleanup()

    def test_read_denied_for_metadata_only_discovered(self):
        with self.assertRaises((WorkspaceError, ResolutionError)):
            self.gw.read_file("metadata-repo", "secret.txt")

    def test_list_workspaces_labels_metadata_only(self):
        result = self.gw.list_workspaces(view="all")
        discovered = {
            d["workspace_id"]: d for d in result.get("discovered", [])
            if d.get("project_id") == "metadata-repo"
        }
        self.assertGreaterEqual(len(discovered), 1)
        for entry in discovered.values():
            self.assertFalse(entry.get("content_authorized", True))
            self.assertTrue(entry.get("metadata_only"))
            self.assertEqual(entry.get("capabilities"), [])
        self.assertEqual(
            [d for d in result.get("eligible", []) if d.get("project_id") == "metadata-repo"],
            [],
        )

    def test_project_instances_content_authorized_false(self):
        result = self.gw.project_instances("metadata-repo")
        self.assertEqual(result["source"], "reality_index")
        for inst in result["instances"]:
            self.assertFalse(inst.get("content_authorized", True))
            self.assertTrue(inst.get("metadata_only"))


class TestEligiblePathDeduplication(unittest.TestCase):
    """Eligible list must deduplicate static and discovered entries by realpath."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        repo = self._root / "dup-repo"
        init_git_repo(repo, files={"README.md": "# dup\n"})

        registry_path = write_workspace_registry(
            self._root / "workspaces.json",
            [{
                "workspace_id": "static-dup",
                "root": str(repo),
                "kind": "git-repository",
                "capabilities": ["filesystem.read", "git.observe"],
            }],
        )
        self.scopes_path = self._root / "root_scopes.json"
        self.scopes_path.write_text(json.dumps({
            "scopes": [{
                "scope_id": "dup-scope",
                "root": str(self._root),
                "authority": RootScopeAuthority(
                    discover=True, content_read=True, git_observe=True, auto_admit=True,
                    index=True,
                ).to_dict(),
            }],
        }), encoding="utf-8")

        self._state = tempfile.TemporaryDirectory(prefix="uam-dedup-")
        self.gw = MiddlewareGateway(str(registry_path), self._state.name)
        self.gw.index_scope("dup-scope")

    def tearDown(self):
        self._state.cleanup()
        self._tmp.cleanup()

    def test_eligible_deduplicates_by_realpath(self):
        result = self.gw.list_workspaces(view="all")
        eligible_ids = [e["workspace_id"] for e in result.get("eligible", [])]
        self.assertIn("static-dup", eligible_ids)
        derived = [wid for wid in eligible_ids if wid.startswith("derived:") and "dup-repo" in wid]
        self.assertEqual(derived, [])


class TestWorkspaceRegistryRevocation(unittest.TestCase):
    """Deleting workspaces.json must revoke static grants on reload."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        repo = self._root / "static-revoke"
        init_git_repo(repo, files={"data.txt": "STATIC CONTENT\n"})
        self.registry_path = write_workspace_registry(
            self._root / "workspaces.json",
            [{
                "workspace_id": "static-revoke",
                "root": str(repo),
                "kind": "git-repository",
                "capabilities": ["filesystem.read", "git.observe"],
            }],
        )
        self._state = tempfile.TemporaryDirectory(prefix="uam-ws-revoke-")
        self.gw = MiddlewareGateway(str(self.registry_path), self._state.name)

    def tearDown(self):
        self._state.cleanup()
        self._tmp.cleanup()

    def test_registry_deletion_revokes_static_read(self):
        self.gw.read_file("static-revoke", "data.txt")
        Path(self.registry_path).unlink()
        self.assertEqual(self.gw.registry.list(), [])
        with self.assertRaises(WorkspaceError):
            self.gw.read_file("static-revoke", "data.txt")


class TestSearchScopeTccExclusions(unittest.TestCase):
    """macOS TCC/system directories are never entered, so ripgrep is never handed a file from them."""

    SYSTEM_FILES = (
        "Library/Containers/secret.txt", "Library/note.txt", "Applications/app.txt", ".Trash/old.txt",
        "Pictures/photo.txt", "Music/song.txt", "Movies/film.txt",
    )

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._root = Path(self._tmp.name)
        init_git_repo(self._root / "code" / "app", files={"needle.txt": "findme\n"})
        for rel in self.SYSTEM_FILES:
            (self._root / rel).parent.mkdir(parents=True, exist_ok=True)
            (self._root / rel).write_text("findme\n")

        registry_path = write_workspace_registry(self._root / "workspaces.json", [])
        self._state = tempfile.TemporaryDirectory(prefix="uam-search-tcc-")
        self.gw = MiddlewareGateway(str(registry_path), self._state.name)
        self.gw.scopes.add_scope(RootScope(
            scope_id="home-search",
            root=str(self._root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=False,
                text_search=True,
            ),
        ))
        self.engine = self.gw.discovery

    def tearDown(self):
        self._state.cleanup()
        self._tmp.cleanup()

    def test_search_scope_never_hands_ripgrep_a_file_from_a_system_directory(self):
        ripgrep = ScriptedRipgrep(lambda call: completed(b"", 1))
        with mock.patch("universal_agent_middleware.discovery.find_ripgrep", return_value="/usr/bin/rg"), \
                ripgrep.patch():
            result = self.engine.search_scope("home-search", "findme")

        self.assertNotIn("error", result)
        searched = handed_relative_paths(ripgrep, self._root)
        self.assertIn("code/app/needle.txt", searched)
        for rel in self.SYSTEM_FILES:
            with self.subTest(rel=rel):
                self.assertNotIn(rel, searched)
        self.assertIn("system_directories", result["search_domain"]["not_covered"])


if __name__ == "__main__":
    unittest.main()
