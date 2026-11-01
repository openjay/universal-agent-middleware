"""Conformance tests for the ``filesystem-directory`` workspace kind (SSOT invariant 16).

The kind lets an authorized ordinary (non-Git) directory be read through the existing
``tree`` / ``read_file`` / ``search`` operations. It exists next to ``git-repository``;
it never replaces the ``.git`` requirement of repository admission. The numbered
``test_rowN_*`` cases mirror the eight acceptance rows of the review that registered the gap.
"""
from __future__ import annotations

import json
import os
import threading
import unittest
from pathlib import Path

from universal_agent_middleware.errors import PathPolicyError, WorkspaceError
from universal_agent_middleware.resolver import ResolutionError
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry
from universal_agent_middleware.workspace import WorkspaceRegistry

from directory_fixtures import (
    OUTSIDE_SECRET, PLAIN, PLAIN_ID, SCOPE_ID, DirectoryWorld, WorldTestCase, derived_id,
    static_directory, static_repository,
)
from synthetic_fixtures import write_workspace_registry

DIRECTORY_KIND = "filesystem-directory"
GIT_KIND = "git-repository"


class TestAcceptanceRows(WorldTestCase):
    """The eight acceptance rows, against explicit-path (derived/absolute) admission."""

    def setUp(self) -> None:
        super().setUp()
        self.gw = self.world.gateway()

    def test_row1_authorized_directory_without_git_is_readable_by_explicit_derived_path(self) -> None:
        resolution = self.gw.resolve_workspace(PLAIN_ID)
        self.assertEqual(resolution.spec.kind, DIRECTORY_KIND)
        self.assertEqual(resolution.spec.capabilities, ["filesystem.read"])
        self.assertEqual(resolution.resolution_kind, "derived")
        paths = {entry["path"] for entry in self.gw.tree(PLAIN_ID, ".", depth=2)["entries"]}
        self.assertIn("README.md", paths)
        self.assertIn("notes/nested.md", paths)

    def test_row1_explicit_absolute_path_also_admits_the_directory(self) -> None:
        resolution = self.gw.resolve_workspace(str(self.world.plain))
        self.assertEqual(resolution.resolution_kind, "absolute_path")
        self.assertEqual(resolution.spec.kind, DIRECTORY_KIND)
        self.assertIn("needle-markdown", self.gw.read_file(str(self.world.plain), "README.md")["content"])

    def test_row2_markdown_python_and_json_are_readable(self) -> None:
        self.assertIn("needle-markdown", self.gw.read_file(PLAIN_ID, "README.md")["content"])
        self.assertIn("needle-python", self.gw.read_file(PLAIN_ID, "tool.py")["content"])
        self.assertEqual(
            json.loads(self.gw.read_file(PLAIN_ID, "config.json")["content"]), {"key": "needle-json"},
        )
        self.assertIn("needle-nested", self.gw.read_file(PLAIN_ID, "notes/nested.md")["content"])

    def test_row2_search_reaches_text_files_and_reports_what_it_skipped(self) -> None:
        result = self.gw.search(PLAIN_ID, "needle")
        found = {hit["path"] for hit in result["results"]}
        self.assertEqual(found, {"README.md", "tool.py", "config.json", "notes/nested.md"})
        # The oversized and the binary file were not searched: absence must not be concluded.
        self.assertEqual(result["files_skipped"]["oversized"], 1)
        self.assertEqual(result["files_skipped"]["binary"], 1)
        self.assertEqual(result["search_completeness"], "PARTIAL")
        self.assertFalse(result["safe_to_conclude_absent"])

    def test_row3_git_operations_are_refused_as_unsupported_capability(self) -> None:
        for operation in (self.gw.git_status, self.gw.git_diff, self.gw.git_log):
            with self.subTest(operation=operation.__name__):
                with self.assertRaises(WorkspaceError) as ctx:
                    operation(PLAIN_ID)
                diagnostic = self.diagnostic_of(ctx.exception)
                self.assertEqual(diagnostic["status"], "UNSUPPORTED_CAPABILITY")
                self.assertEqual(diagnostic["reason"], "CAPABILITY_NOT_SUPPORTED_BY_WORKSPACE_KIND")
                self.assertEqual(diagnostic["capability"], "git.observe")
                self.assertEqual(diagnostic["workspace_kind"], DIRECTORY_KIND)
                self.assertEqual(diagnostic["supported_capabilities"], ["filesystem.read"])
                self.assertIn("git.observe", str(ctx.exception))
                self.assertIn(DIRECTORY_KIND, str(ctx.exception))

    def test_row4_target_outside_every_scope_is_denied_without_an_existence_oracle(self) -> None:
        existing, missing = "../outside", "../does-not-exist"
        messages = []
        for rel in (existing, missing):
            with self.assertRaises(WorkspaceError) as ctx:
                self.gw.tree(derived_id(rel))
            self.assertIsNone(getattr(ctx.exception, "diagnostic", None))
            messages.append(str(ctx.exception).replace(rel, "<rel>"))
        self.assertEqual(messages[0], messages[1])
        self.assertIn("not within any authorized scope", messages[0])

        absolute_messages = []
        for target in (self.world.outside, self.world.outside / "secret.txt", self.world.outside / "missing"):
            with self.assertRaises(WorkspaceError) as ctx:
                self.gw.tree(str(target))
            self.assertIsNone(getattr(ctx.exception, "diagnostic", None))
            self.assertNotIn(str(self.world.root), str(ctx.exception))
            absolute_messages.append(str(ctx.exception))
        self.assertEqual(len(set(absolute_messages)), 1)

    def test_row5_symlink_escape_is_denied_at_the_root_and_inside(self) -> None:
        with self.assertRaises(WorkspaceError):
            self.gw.tree(derived_id(f"{PLAIN}/link-out"))
        for rel in ("link-out/secret.txt", "link-file"):
            with self.subTest(path=rel), self.assertRaises(PathPolicyError):
                self.gw.read_file(PLAIN_ID, rel)
        listed = {entry["path"] for entry in self.gw.tree(PLAIN_ID, ".", depth=3)["entries"]}
        self.assertFalse({"link-out", "link-file", "link-in"} & listed)
        leaked = self.gw.search(PLAIN_ID, OUTSIDE_SECRET)
        self.assertEqual(leaked["results"], [])

    def test_row6_secret_firewall_still_applies_inside_a_directory_workspace(self) -> None:
        for rel in (".env", ".ssh/config", "server.pem"):
            with self.subTest(path=rel), self.assertRaises(PathPolicyError):
                self.gw.read_file(PLAIN_ID, rel)
        listed = {entry["path"] for entry in self.gw.tree(PLAIN_ID, ".", depth=3)["entries"]}
        self.assertFalse({".env", ".ssh", "server.pem"} & listed)
        for token in ("do-not-leak", "leaked-host"):
            self.assertEqual(self.gw.search(PLAIN_ID, token)["results"], [], token)

    def test_row6_a_root_whose_own_path_is_protected_is_never_admitted(self) -> None:
        for rel in (".ssh", f"{PLAIN}/.ssh", "vault.key"):
            with self.subTest(rel=rel), self.assertRaises(WorkspaceError) as ctx:
                self.gw.tree(derived_id(rel))
            self.assertIn("protected", str(ctx.exception))

    def test_row6_a_more_specific_scope_still_denies_what_the_outer_scope_would_admit(self) -> None:
        self.gw.scopes.add_scope(RootScope(
            scope_id="inner-deny", root=str(self.world.data / "restricted"),
            authority=RootScopeAuthority(),
        ))
        with self.assertRaises(WorkspaceError):
            self.gw.read_file(derived_id("restricted"), "secret.txt")
        self.assertIn("needle-markdown", self.gw.read_file(PLAIN_ID, "README.md")["content"])

    def test_row7_existing_git_workspaces_are_unaffected(self) -> None:
        repo_id = derived_id("git-repo")
        resolution = self.gw.resolve_workspace(repo_id)
        self.assertEqual(resolution.spec.kind, GIT_KIND)
        self.assertEqual(resolution.spec.capabilities, ["filesystem.read", "git.observe"])
        self.assertEqual(len(self.gw.git_status(repo_id)["head"]), 40)
        self.assertIn("# repo", self.gw.read_file(repo_id, "README.md")["content"])

    def test_row8_the_target_is_left_byte_identical(self) -> None:
        before = self.world.target_fingerprint()
        gw = self.gw
        gw.tree(PLAIN_ID, ".", depth=4)
        gw.read_file(PLAIN_ID, "README.md")
        gw.search(PLAIN_ID, "needle")
        gw.tree(str(self.world.plain), ".", depth=2)
        for attempt in (
            lambda: gw.read_file(PLAIN_ID, ".env"),
            lambda: gw.read_file(PLAIN_ID, "link-out/secret.txt"),
            lambda: gw.git_status(PLAIN_ID),
            lambda: gw.tree(derived_id(".ssh")),
            lambda: gw.tree(derived_id("restricted/../../outside")),
            lambda: gw.tree(derived_id("../outside")),
        ):
            with self.assertRaises((WorkspaceError, PathPolicyError)):
                attempt()
        gw.list_workspaces()
        self.assertEqual(self.world.target_fingerprint(), before)

    def test_successful_reads_are_audited_under_the_derived_identity(self) -> None:
        self.gw.read_file(PLAIN_ID, "README.md")
        self.gw.tree(PLAIN_ID)
        self.gw.search(PLAIN_ID, "needle")
        records = [
            json.loads(line)
            for line in (self.world.state / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        mine = [r for r in records if r["workspace_id"] == PLAIN_ID]
        self.assertEqual([r["action"] for r in mine], ["read_file", "tree", "search"])
        self.assertTrue(all(r["outcome"] == "PASS" for r in mine))
        self.assertTrue(self.gw.audit.verify()["valid"])


class TestDefaultOffAndDiagnostics(WorldTestCase):
    """Directory admission is opt-in per scope, and every refusal says why."""

    def test_directory_admission_is_off_unless_the_scope_enables_it(self) -> None:
        gw = self.world.gateway(scope=self.world.scope(directory_admit=False))
        with self.assertRaises(WorkspaceError) as ctx:
            gw.tree(PLAIN_ID)
        diagnostic = self.diagnostic_of(ctx.exception)
        self.assertEqual(diagnostic["schema_version"], "workspace-diagnostic-v1")
        self.assertEqual(diagnostic["status"], "UNSUPPORTED_WORKSPACE_KIND")
        self.assertEqual(diagnostic["reason"], "NON_GIT_DIRECTORY")
        self.assertIs(diagnostic["path_exists"], True)
        self.assertIs(diagnostic["scope_authorized"], True)
        self.assertEqual(diagnostic["scope_id"], SCOPE_ID)
        self.assertEqual(diagnostic["directory_admission"], "NOT_ENABLED")
        self.assertEqual(
            diagnostic["suggested_actions"],
            ["REGISTER_FILESYSTEM_DIRECTORY", "ENABLE_DIRECTORY_ADMISSION"],
        )
        self.assertIn(PLAIN, str(ctx.exception))

    def test_diagnostics_carry_no_host_paths(self) -> None:
        gw = self.world.gateway(scope=self.world.scope(directory_admit=False))
        with self.assertRaises(WorkspaceError) as refused:
            gw.tree(str(self.world.plain))
        with self.assertRaises(WorkspaceError) as unsupported:
            self.world.gateway(scope=True).git_status(PLAIN_ID)
        for exc in (refused.exception, unsupported.exception):
            text = json.dumps(self.diagnostic_of(exc)) + str(exc)
            self.assertNotIn(str(self.world.root), text)

    def test_default_off_still_denies_every_read_path(self) -> None:
        gw = self.world.gateway(scope=self.world.scope(directory_admit=False))
        for call in (
            lambda: gw.tree(PLAIN_ID),
            lambda: gw.read_file(PLAIN_ID, "README.md"),
            lambda: gw.search(PLAIN_ID, "needle"),
            lambda: gw.tree(str(self.world.plain)),
        ):
            with self.assertRaises(WorkspaceError):
                call()

    def test_a_scope_without_any_admission_bit_gives_a_uniform_denial_with_no_git_oracle(self) -> None:
        gw = self.world.gateway(scope=self.world.scope(auto_admit=False, directory_admit=False))
        messages = set()
        for rel in (PLAIN, "git-repo", "does-not-exist"):
            with self.assertRaises(WorkspaceError) as ctx:
                gw.tree(derived_id(rel))
            self.assertIsNone(getattr(ctx.exception, "diagnostic", None))
            messages.add(str(ctx.exception).replace(rel, "<rel>"))
        self.assertEqual(len(messages), 1, messages)

    def test_directory_admission_needs_content_read(self) -> None:
        gw = self.world.gateway(scope=self.world.scope(content_read=False))
        with self.assertRaises(WorkspaceError) as ctx:
            gw.tree(PLAIN_ID)
        self.assertIn("content_read", str(ctx.exception))

    def test_directory_admission_alone_does_not_admit_a_git_repository(self) -> None:
        gw = self.world.gateway(scope=self.world.scope(auto_admit=False))
        with self.assertRaises(WorkspaceError) as ctx:
            gw.tree(derived_id("git-repo"))
        self.assertIn("auto-admission", str(ctx.exception))
        self.assertIn("needle-markdown", gw.read_file(PLAIN_ID, "README.md")["content"])

    def test_revocation_takes_effect_on_the_very_next_call(self) -> None:
        gw = self.world.gateway()
        self.assertIn("needle-markdown", gw.read_file(PLAIN_ID, "README.md")["content"])
        gw.scopes.replace_scopes([self.world.scope(directory_admit=False)])
        with self.assertRaises(WorkspaceError):
            gw.read_file(PLAIN_ID, "README.md")
        gw.scopes.replace_scopes([self.world.scope()])
        self.assertIn("needle-markdown", gw.read_file(PLAIN_ID, "README.md")["content"])

    def test_nested_scope_without_the_bit_overrides_an_outer_scope_with_it(self) -> None:
        gw = self.world.gateway()
        gw.scopes.add_scope(RootScope(
            scope_id="inner-no-dirs", root=str(self.world.plain / "notes"),
            authority=RootScopeAuthority(content_read=True, auto_admit=True, discover=True),
        ))
        with self.assertRaises(WorkspaceError) as ctx:
            gw.tree(derived_id(f"{PLAIN}/notes"))
        self.assertEqual(self.diagnostic_of(ctx.exception)["scope_id"], "inner-no-dirs")
        # The outer directory would reach into the inner scope, so it is refused too (see
        # TestScopeBoundaries); a directory that does not reach into it is unaffected.
        with self.assertRaises(WorkspaceError) as spanning:
            gw.read_file(PLAIN_ID, "README.md")
        self.assertIn("nested scope inner-no-dirs", str(spanning.exception))
        self.assertIn("restricted content", gw.read_file(derived_id("restricted"), "secret.txt")["content"])

    def test_resolution_error_serializes_its_diagnostic(self) -> None:
        gw = self.world.gateway(scope=self.world.scope(directory_admit=False))
        with self.assertRaises(ResolutionError) as ctx:
            gw.resolve_workspace(PLAIN_ID)
        self.assertEqual(ctx.exception.kind, "UNSUPPORTED")
        payload = ctx.exception.to_dict()
        self.assertEqual(payload["kind"], "UNSUPPORTED")
        self.assertEqual(payload["diagnostic"]["reason"], "NON_GIT_DIRECTORY")


class TestControlPlaneDisjointness(WorldTestCase):
    """SSOT invariant 10 also holds for on-demand admission."""

    control_plane_inside_data = True

    def test_state_and_config_directories_are_never_admitted(self) -> None:
        gw = self.world.gateway()
        (self.world.state / "anything").mkdir(parents=True, exist_ok=True)
        for rel in ("uam-state", "uam-config", "uam-state/anything"):
            with self.subTest(rel=rel), self.assertRaises(WorkspaceError) as ctx:
                gw.tree(derived_id(rel))
            self.assertIn("control plane", str(ctx.exception))

    def test_a_directory_that_contains_the_control_plane_is_not_admitted(self) -> None:
        gw = self.world.gateway()
        for selector in (derived_id("."), str(self.world.data)):
            with self.subTest(selector=selector), self.assertRaises(WorkspaceError) as ctx:
                gw.tree(selector)
            self.assertIn("control plane", str(ctx.exception))

    def test_unrelated_directories_remain_admissible(self) -> None:
        gw = self.world.gateway()
        self.assertIn("needle-markdown", gw.read_file(PLAIN_ID, "README.md")["content"])


class TestScopeBoundaries(WorldTestCase):
    """A directory workspace never reaches across a scope boundary into a more specific scope.

    Directories can be admitted at any level, so without this rule a client could read a
    subtree that a more specific scope denies simply by admitting one of its ancestors.
    """

    def _deny_scope(self) -> RootScope:
        return RootScope(
            scope_id="inner-deny", root=str(self.world.data / "restricted"),
            authority=RootScopeAuthority(),
        )

    def test_an_ancestor_directory_cannot_be_admitted_over_a_nested_deny_scope(self) -> None:
        gw = self.world.gateway()
        gw.scopes.add_scope(self._deny_scope())
        for selector in (derived_id("."), str(self.world.data)):
            with self.subTest(selector=selector), self.assertRaises(WorkspaceError) as ctx:
                gw.read_file(selector, "restricted/secret.txt")
            self.assertIn("nested scope inner-deny", str(ctx.exception))
            self.assertNotIn("restricted content", str(ctx.exception))

    def test_siblings_stay_readable_and_the_nested_scope_itself_stays_denied(self) -> None:
        gw = self.world.gateway()
        gw.scopes.add_scope(self._deny_scope())
        self.assertIn("needle-markdown", gw.read_file(PLAIN_ID, "README.md")["content"])
        with self.assertRaises(WorkspaceError):
            gw.read_file(derived_id("restricted"), "secret.txt")

    def test_the_refusal_follows_the_live_scope_set(self) -> None:
        gw = self.world.gateway()
        gw.scopes.add_scope(self._deny_scope())
        with self.assertRaises(WorkspaceError):
            gw.tree(derived_id("."))
        gw.scopes.replace_scopes([self.world.scope()])
        self.assertIn(
            "restricted content", gw.read_file(derived_id("."), "restricted/secret.txt")["content"],
        )

    def test_a_scope_does_not_count_as_nested_in_itself(self) -> None:
        # A scope rooted exactly at the admitted directory is that directory's own authority.
        gw = self.world.gateway(scope=self.world.scope())
        gw.scopes.add_scope(RootScope(
            scope_id="plain-own", root=str(self.world.plain),
            authority=RootScopeAuthority(content_read=True, directory_admit=True),
        ))
        self.assertIn("needle-markdown", gw.read_file(PLAIN_ID, "README.md")["content"])


class TestStaticRegistryKind(WorldTestCase):
    def test_a_static_registration_is_the_owners_explicit_authority_not_narrowed_by_scopes(self) -> None:
        # Same as static Git workspaces: the registry grants, RootScopes govern derived admission.
        gw = self.world.gateway([static_directory("plain-static", self.world.plain)], scope=False)
        gw.scopes.add_scope(RootScope(
            scope_id="inner-deny", root=str(self.world.plain / "notes"), authority=RootScopeAuthority(),
        ))
        self.assertIn("nested", gw.read_file("plain-static", "notes/nested.md")["content"])

    def test_a_static_directory_workspace_is_served_without_any_root_scope(self) -> None:
        gw = self.world.gateway([static_directory("plain-static", self.world.plain)], scope=False)
        self.assertIn("needle-markdown", gw.read_file("plain-static", "README.md")["content"])
        listed = {w["workspace_id"]: w for w in gw.list_workspaces()["registered"]}
        self.assertEqual(listed["plain-static"]["kind"], DIRECTORY_KIND)
        self.assertEqual(listed["plain-static"]["capabilities"], ["filesystem.read"])

    def test_a_static_directory_workspace_keeps_the_secret_firewall_and_confinement(self) -> None:
        gw = self.world.gateway([static_directory("plain-static", self.world.plain)], scope=False)
        for rel in (".env", "link-out/secret.txt", "../outside/secret.txt"):
            with self.subTest(path=rel), self.assertRaises(PathPolicyError):
                gw.read_file("plain-static", rel)

    def test_a_static_directory_workspace_refuses_git_with_a_diagnostic(self) -> None:
        gw = self.world.gateway([static_directory("plain-static", self.world.plain)], scope=False)
        for operation in (gw.git_status, gw.git_diff, gw.git_log):
            with self.subTest(operation=operation.__name__), self.assertRaises(WorkspaceError) as ctx:
                operation("plain-static")
            diagnostic = self.diagnostic_of(ctx.exception)
            self.assertEqual(diagnostic["status"], "UNSUPPORTED_CAPABILITY")
            self.assertEqual(diagnostic["workspace_kind"], DIRECTORY_KIND)

    def test_a_directory_workspace_cannot_carry_a_repository_change_contract(self) -> None:
        gw = self.world.gateway([static_directory("plain-static", self.world.plain)], scope=False)
        with self.assertRaises(WorkspaceError) as ctx:
            gw.create_contract({"workspace_id": "plain-static", "profile": "repository-change-v1"})
        self.assertEqual(self.diagnostic_of(ctx.exception)["status"], "UNSUPPORTED_CAPABILITY")
        self.assertFalse((self.world.state / "contracts").exists() and any((self.world.state / "contracts").iterdir()))

    def test_the_kind_cannot_declare_git_observe(self) -> None:
        path = write_workspace_registry(self.world.registry_path, [
            static_directory("bad", self.world.plain) | {"capabilities": ["filesystem.read", "git.observe"]},
        ])
        with self.assertRaises(WorkspaceError) as ctx:
            WorkspaceRegistry(path)
        self.assertIn("git.observe", str(ctx.exception))
        self.assertIn(DIRECTORY_KIND, str(ctx.exception))

    def test_git_only_registry_fields_are_rejected_for_the_kind(self) -> None:
        for field, value in (("repository_identity", "org/repo"), ("discovery", {"git_worktrees": True})):
            with self.subTest(field=field):
                path = write_workspace_registry(self.world.registry_path, [
                    static_directory("bad", self.world.plain) | {field: value},
                ])
                with self.assertRaises(WorkspaceError) as ctx:
                    WorkspaceRegistry(path)
                self.assertIn(field, str(ctx.exception))

    def test_kinds_stay_closed_world(self) -> None:
        path = write_workspace_registry(self.world.registry_path, [
            static_directory("bad", self.world.plain) | {"kind": "database"},
        ])
        with self.assertRaises(WorkspaceError) as ctx:
            WorkspaceRegistry(path)
        self.assertIn("unsupported workspace kind", str(ctx.exception))
        path = write_workspace_registry(self.world.registry_path, [
            static_directory("bad", self.world.plain) | {"kind": ["git-repository"]},
        ])
        with self.assertRaises(WorkspaceError):
            WorkspaceRegistry(path)

    def test_the_git_kind_still_declares_both_capabilities(self) -> None:
        path = write_workspace_registry(self.world.registry_path, [
            static_repository("repo", self.world.repo),
            static_repository("repo-readonly", self.world.repo) | {"capabilities": ["filesystem.read"]},
        ])
        registry = WorkspaceRegistry(path)
        self.assertEqual(registry.get("repo").capabilities, ["filesystem.read", "git.observe"])
        self.assertEqual(registry.get("repo-readonly").capabilities, ["filesystem.read"])

    def test_a_missing_directory_root_is_one_unavailable_workspace_not_a_fatal_registry(self) -> None:
        gw = self.world.gateway([
            static_directory("gone", self.world.root / "does-not-exist"),
            static_directory("plain-static", self.world.plain),
        ], scope=False)
        coverage = gw.list_workspaces()["coverage"]
        self.assertEqual(coverage["registered"], 2)
        self.assertEqual(coverage["available"], 1)
        self.assertEqual(coverage["unavailable"][0]["workspace_id"], "gone")
        self.assertFalse(coverage["complete"])
        self.assertIn("needle-markdown", gw.read_file("plain-static", "README.md")["content"])

    def test_a_static_directory_overlapping_the_control_plane_is_refused_when_resolved(self) -> None:
        gw = self.world.gateway([static_directory("cfg", self.world.config)], scope=False)
        with self.assertRaises(WorkspaceError) as ctx:
            gw.read_file("cfg", "workspaces.json")
        self.assertIn("control plane", str(ctx.exception))

    def test_the_directory_kind_may_share_a_project_with_other_workspaces(self) -> None:
        path = write_workspace_registry(self.world.registry_path, [
            static_directory("carrier", self.world.plain, project_id="shared", role="review-carrier"),
        ])
        self.assertEqual(WorkspaceRegistry(path).get("carrier").kind, DIRECTORY_KIND)


class TestCoverageSemantics(WorldTestCase):
    def test_coverage_says_its_basis_is_the_registered_workspaces(self) -> None:
        path = write_workspace_registry(self.world.registry_path, [
            static_directory("plain-static", self.world.plain),
            static_repository("repo", self.world.repo),
        ])
        coverage = WorkspaceRegistry(path).coverage()
        self.assertEqual(coverage["schema_version"], "workspace-coverage-v1")
        self.assertEqual(coverage["basis"], "registered_workspaces")
        self.assertEqual(coverage["unregistered_root_scope_paths"], "not_assessed")
        self.assertEqual((coverage["registered"], coverage["available"]), (2, 2))
        self.assertTrue(coverage["complete"])

    def test_a_complete_registry_says_nothing_about_unregistered_scope_paths(self) -> None:
        gw = self.world.gateway(scope=self.world.scope(directory_admit=False))
        coverage = gw.list_workspaces()["coverage"]
        self.assertTrue(coverage["complete"])
        self.assertEqual(coverage["registered"], 0)
        self.assertEqual(coverage["unregistered_root_scope_paths"], "not_assessed")

    def test_discovery_coverage_states_that_only_git_repositories_are_discovered(self) -> None:
        gw = self.world.gateway()
        discovery = gw.list_workspaces()["discovery"]["coverage"]
        self.assertEqual(discovery["discovers"], "git-repositories")
        self.assertEqual(discovery["non_git_directories"], "not_discovered")
        self.assertTrue(discovery["not_exhaustive"])


class TestNeverDiscovered(WorldTestCase):
    """Directory workspaces are admitted by explicit selector only."""

    def test_an_admissible_directory_is_not_discovered_indexed_or_listed(self) -> None:
        gw = self.world.gateway()
        gw.read_file(PLAIN_ID, "README.md")
        for result in (gw.discover_projects(SCOPE_ID), gw.scope_inventory(SCOPE_ID), gw.list_workspaces()):
            self.assertNotIn(PLAIN, json.dumps(result))
        self.assertTrue(any("git-repo" in json.dumps(p) for p in gw.discover_projects(SCOPE_ID)["projects"]))

    def test_a_bare_name_never_resolves_to_a_directory(self) -> None:
        gw = self.world.gateway()
        with self.assertRaises(ResolutionError) as ctx:
            gw.resolve_workspace(PLAIN)
        self.assertEqual(ctx.exception.kind, "NOT_FOUND")


class TestPolicyGenerationCompatibility(unittest.TestCase):
    """A config that does not use the new bit keeps its exact ``policy_generation``."""

    # Computed with the release before the bit existed (see CHANGELOG, "Compatibility").
    BASELINE_GENERATION = "b2cf291ecb94399a"
    EMPTY_GENERATION = "fa0408064ec44f74"

    @staticmethod
    def _baseline_registry() -> RootScopeRegistry:
        registry = RootScopeRegistry()
        registry.add_scope(RootScope(
            scope_id="golden-code", root="/srv/uam-golden/code", description="golden",
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=True, text_search=True,
                git_observe=True, classify=True, index=True, relate=True, auto_admit=True,
            ),
        ))
        registry.add_scope(RootScope(
            scope_id="golden-cursor", root="/srv/uam-golden/cursor",
            authority=RootScopeAuthority(discover=True, content_read=True),
        ))
        return registry

    def test_existing_configurations_keep_their_generation(self) -> None:
        self.assertEqual(self._baseline_registry().policy_generation, self.BASELINE_GENERATION)
        self.assertEqual(RootScopeRegistry().policy_generation, self.EMPTY_GENERATION)

    def test_enabling_the_bit_changes_the_generation(self) -> None:
        registry = self._baseline_registry()
        registry.replace_scopes([
            RootScope(
                scope_id="golden-code", root="/srv/uam-golden/code", description="golden",
                authority=RootScopeAuthority(
                    discover=True, metadata_read=True, content_read=True, text_search=True,
                    git_observe=True, classify=True, index=True, relate=True, auto_admit=True,
                    directory_admit=True,
                ),
            ),
            RootScope(
                scope_id="golden-cursor", root="/srv/uam-golden/cursor",
                authority=RootScopeAuthority(discover=True, content_read=True),
            ),
        ])
        self.assertNotEqual(registry.policy_generation, self.BASELINE_GENERATION)

    def test_listed_scopes_always_expose_the_bit_defaulting_to_false(self) -> None:
        listed = self._baseline_registry().list_scopes()
        self.assertTrue(all(entry["authority"]["directory_admit"] is False for entry in listed))

    def test_a_scope_file_may_enable_the_bit_and_old_files_still_load(self) -> None:
        world = DirectoryWorld()
        self.addCleanup(world.cleanup)
        enabled = world.write_scope_file()
        self.assertTrue(RootScopeRegistry(enabled).effective_authority(world.plain).directory_admit)
        disabled = world.write_scope_file(directory_admit=False)
        self.assertFalse(RootScopeRegistry(disabled).effective_authority(world.plain).directory_admit)
        legacy = json.loads(disabled.read_text(encoding="utf-8"))
        del legacy["scopes"][0]["authority"]["directory_admit"]
        disabled.write_text(json.dumps(legacy), encoding="utf-8")
        self.assertFalse(RootScopeRegistry(disabled).effective_authority(world.plain).directory_admit)


class TestReaderHardening(WorldTestCase):
    """Properties that matter more once arbitrary directories can be read."""

    def test_a_fifo_cannot_block_search_or_read(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo unavailable")
        fifo = self.world.plain / "pipe"
        os.mkfifo(fifo)
        gw = self.world.gateway()
        outcome: dict[str, object] = {}

        def search() -> None:
            outcome["result"] = gw.search(PLAIN_ID, "needle")

        worker = threading.Thread(target=search, daemon=True)
        worker.start()
        worker.join(timeout=15)
        blocked = worker.is_alive()
        if blocked:
            # Unblock the reader so the daemon thread does not outlive the test.
            try:
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
            except OSError:
                pass
            worker.join(timeout=5)
        self.assertFalse(blocked, "text search blocked on a FIFO")
        self.assertIn("README.md", {hit["path"] for hit in outcome["result"]["results"]})
        with self.assertRaises(WorkspaceError):
            gw.read_file(PLAIN_ID, "pipe")

    def test_size_and_binary_limits_apply(self) -> None:
        gw = self.world.gateway()
        with self.assertRaises(WorkspaceError) as big:
            gw.read_file(PLAIN_ID, "big.txt")
        self.assertIn("max_file_bytes", str(big.exception))
        with self.assertRaises(WorkspaceError) as binary:
            gw.read_file(PLAIN_ID, "blob.bin")
        self.assertIn("binary", str(binary.exception))


class TestProjectLevelGitIsolation(WorldTestCase):
    """A directory workspace never lends its enclosing repository to project-level Git tools."""

    def setUp(self) -> None:
        super().setUp()
        self.docs = self.world.repo / "docs"
        self.gw = self.world.gateway([
            static_directory("repo-docs", self.docs, project_id="repo-docs"),
            static_repository("repo-main", self.world.repo, project_id="repo-project", role="canonical-main"),
            static_directory("repo-carrier", self.docs, project_id="repo-project", role="review-carrier"),
        ], scope=False)

    def test_git_is_refused_even_though_the_directory_sits_inside_a_repository(self) -> None:
        with self.assertRaises(WorkspaceError) as ctx:
            self.gw.git_status("repo-docs")
        self.assertEqual(self.diagnostic_of(ctx.exception)["status"], "UNSUPPORTED_CAPABILITY")
        self.assertIn("guide needle-guide", self.gw.read_file("repo-docs", "guide.md")["content"])

    def test_project_instances_report_the_kind_and_discover_no_worktrees_for_a_directory(self) -> None:
        result = self.gw.project_instances("repo-docs")
        self.assertEqual(result["discovered_worktrees"], [])
        self.assertEqual(result["instances"][0]["kind"], DIRECTORY_KIND)

    def test_git_instances_keep_their_exact_shape(self) -> None:
        instances = {i["workspace_id"]: i for i in self.gw.project_instances("repo-project")["instances"]}
        self.assertNotIn("kind", instances["repo-main"])
        self.assertEqual(instances["repo-carrier"]["kind"], DIRECTORY_KIND)

    def test_project_reality_never_reports_git_facts_for_a_directory(self) -> None:
        reality = self.gw.project_reality("repo-docs")
        (instance,) = reality["instances"]
        self.assertEqual(instance["kind"], DIRECTORY_KIND)
        self.assertIs(instance["observable"], False)
        self.assertNotIn("head", instance)
        self.assertNotIn("branch", instance)
        self.assertIn("not applicable", instance["error"])
        self.assertTrue(any(w.startswith("UNOBSERVABLE_INSTANCES") for w in reality["coverage"]["warnings"]))

    def test_a_mixed_project_still_observes_its_git_instance(self) -> None:
        reality = self.gw.project_reality("repo-project")
        by_id = {i["workspace_id"]: i for i in reality["instances"]}
        self.assertEqual(len(by_id["repo-main"]["head"]), 40)
        self.assertIs(by_id["repo-carrier"]["observable"], False)
        self.assertEqual(reality["coverage"]["surfaces"]["canonical_source"], "observed")


if __name__ == "__main__":
    unittest.main()
