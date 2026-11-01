"""Project-level Git runs only under the capability each instance holds right now.

A project groups registered workspaces and asks every instance for its Git state (worktrees,
status, head). That used to start Git in the root remembered when the registry was first read,
whatever the instance may do today: an instance registered with ``filesystem.read`` alone was
handed to Git, a revoked or removed registration kept being observed, and a registration moved to
another directory was still observed where it used to be. Each question below is answered by
counting the Git processes UAM really starts, per repository root.

Static registrations stay independent contracts (a RootScope never narrows them). Derived
instances are verified by the live resolver. An identity that fails either check is never looked
up under another name, because a same-named derived workspace is a different workspace.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest import mock

from synthetic_fixtures import init_git_repo, write_workspace_registry

from universal_agent_middleware import git_readonly
from universal_agent_middleware.discovery import DiscoveryEngine
from universal_agent_middleware.errors import WorkspaceError
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.project import ProjectRegistry, WorkspaceInstance
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry
from universal_agent_middleware.workspace import WorkspaceRegistry

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:  # pragma: no cover - the MCP SDK is an optional test dependency
    create_session_read_server = None  # type: ignore[assignment]

CAPABILITIES = ["filesystem.read", "git.observe"]
FULL_SCOPE = RootScopeAuthority(
    discover=True, metadata_read=True, content_read=True, text_search=True, git_observe=True, auto_admit=True,
)


class GitLaunches:
    """The Git processes UAM starts, by repository root. The real Git still runs."""

    def __init__(self) -> None:
        self.roots: list[str] = []
        self._real = subprocess.run

    def _run(self, command: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(command, list) and command[:1] == ["git"] and "-C" in command:
            self.roots.append(command[command.index("-C") + 1])
        return self._real(command, *args, **kwargs)

    @contextmanager
    def watching(self) -> Iterator[GitLaunches]:
        with mock.patch.object(git_readonly.subprocess, "run", side_effect=self._run):
            yield self

    def in_root(self, root: Path) -> int:
        return self.roots.count(os.path.realpath(root))


def unborn_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=path, capture_output=True, timeout=10, check=True)
    return path


def head_of(root: Path) -> str:
    done = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=10, check=True,
    )
    return done.stdout.strip()


class ProjectFixture(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="uam-project-git-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.registry_path = self.base / "config" / "workspaces.json"
        self.launches = GitLaunches()

    def repo(self, name: str, parent: Path | None = None) -> Path:
        root = (parent or self.base) / name
        init_git_repo(root, files={"README.md": f"# {name}\n", f"{name}.txt": f"{name}\n"})
        return root

    @staticmethod
    def entry(
        workspace_id: str, root: Path, *, capabilities: list[str] | None = None,
        kind: str = "git-repository", role: str = "development", lifecycle: str = "active",
    ) -> dict[str, Any]:
        return {
            "workspace_id": workspace_id, "project_id": "proj", "role": role, "lifecycle": lifecycle,
            "label": workspace_id, "root": str(root), "kind": kind,
            "capabilities": CAPABILITIES if capabilities is None else capabilities,
        }

    def publish(self, entries: list[dict[str, Any]]) -> None:
        write_workspace_registry(self.registry_path, entries)

    def gateway(self, entries: list[dict[str, Any]]) -> MiddlewareGateway:
        self.publish(entries)
        return MiddlewareGateway(str(self.registry_path), str(self.base / "state"))

    @staticmethod
    def by_id(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {item["workspace_id"]: item for item in snapshot["instances"]}


class EveryProjectEntryPointTests(ProjectFixture):
    """An instance registered without ``git.observe`` is never handed to Git, whichever way it is asked."""

    def setUp(self) -> None:
        super().setUp()
        self.main = self.repo("main")
        self.viewer = self.repo("viewer")
        self.gw = self.gateway([
            self.entry("main", self.main, role="canonical-main"),
            self.entry("viewer", self.viewer, capabilities=["filesystem.read"]),
        ])

    def entry_points(self) -> dict[str, Callable[[], Any]]:
        return {
            "ProjectRegistry.project_reality_snapshot": lambda: self.gw.projects.project_reality_snapshot("proj"),
            "ProjectRegistry.discover_worktrees": lambda: self.gw.projects.discover_worktrees("proj"),
            "gateway.project_reality": lambda: self.gw.project_reality("proj"),
            "gateway.project_instances": lambda: self.gw.project_instances("proj"),
        }

    def test_the_instance_without_the_capability_is_never_handed_to_git(self) -> None:
        for name, call in self.entry_points().items():
            with self.subTest(entry_point=name):
                launches = GitLaunches()
                with launches.watching():
                    call()
                self.assertGreater(launches.in_root(self.main), 0, "control: the granted instance is observed")
                self.assertEqual(launches.in_root(self.viewer), 0, "Git was started without git.observe")

    def test_it_is_reported_as_not_observed_and_never_as_clean_or_without_history(self) -> None:
        snapshot = self.gw.project_reality("proj")
        viewer = self.by_id(snapshot)["viewer"]
        self.assertIs(viewer["observable"], False)
        for claim in ("clean", "changed_count", "head", "head_state", "history_available", "branch"):
            self.assertNotIn(claim, viewer, f"an unobserved instance must not carry {claim}")
        coverage = snapshot["coverage"]
        self.assertNotEqual(coverage["status"], "COMPLETE")
        self.assertTrue(any(w.startswith("UNOBSERVABLE_INSTANCES") and "viewer" in w for w in coverage["warnings"]))

    def test_the_instance_with_the_capability_is_observed_as_before(self) -> None:
        main = self.by_id(self.gw.project_reality("proj"))["main"]
        self.assertIs(main["observable"], True)
        self.assertEqual(main["head"], head_of(self.main))
        self.assertEqual((main["head_state"], main["history_available"], main["clean"]), ("attached", True, True))

    def test_worktree_discovery_says_which_instances_it_could_not_ask(self) -> None:
        report = self.gw.project_instances("proj")["worktree_discovery"]
        self.assertEqual(report, {"complete": False, "not_observed_instances": ["viewer"]})
        self.assertEqual({w["path"] for w in self.gw.project_instances("proj")["discovered_worktrees"]},
                         {str(self.main)})

    def test_a_project_that_was_asked_everywhere_says_so(self) -> None:
        solo = self.gateway([self.entry("main", self.main, role="canonical-main")])
        self.assertEqual(solo.project_instances("proj")["worktree_discovery"],
                         {"complete": True, "not_observed_instances": []})

    @unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
    def test_the_session_bootstrap_pack_does_not_start_git_for_a_sibling_without_the_capability(self) -> None:
        server = create_session_read_server(registry_path=str(self.registry_path), state_dir=str(self.base / "sdk-state"))
        tool = server._tool_manager._tools["uam_session_bootstrap"].fn
        launches = GitLaunches()
        with launches.watching():
            pack = json.loads(asyncio.run(tool(ctx=None, workspace_id="main")))
        self.assertGreater(launches.in_root(self.main), 0)
        self.assertEqual(launches.in_root(self.viewer), 0)
        siblings = {item["workspace_id"]: item for item in pack["project"]["other_instances"]}
        self.assertIs(siblings["viewer"]["observable"], False)
        self.assertNotEqual(pack["project"]["coverage"]["status"], "COMPLETE")


class TheRegistryAsItIsNowTests(ProjectFixture):
    """The project is read from the registry as it is now (v0.6.1, F-G2-2): what an instance may do, where it points, and whether it exists."""

    def setUp(self) -> None:
        super().setUp()
        self.main = self.repo("main")
        self.gw = self.gateway([self.entry("main", self.main, role="canonical-main")])

    def test_a_revoked_capability_takes_effect_without_a_restart(self) -> None:
        self.assertIs(self.by_id(self.gw.projects.project_reality_snapshot("proj"))["main"]["observable"], True)
        self.publish([self.entry("main", self.main, role="canonical-main", capabilities=["filesystem.read"])])
        with self.launches.watching():
            snapshot = self.gw.projects.project_reality_snapshot("proj")
            self.gw.projects.discover_worktrees("proj")
        self.assertIs(self.by_id(snapshot)["main"]["observable"], False)
        self.assertEqual(self.launches.in_root(self.main), 0)

    def test_a_removed_registration_is_neither_observed_nor_replaced_by_a_same_named_derived_workspace(self) -> None:
        decoy = self.repo("main", parent=self.base / "scope")
        self.gw.scopes.add_scope(RootScope(scope_id="scope", root=str(self.base / "scope"), authority=FULL_SCOPE))
        self.publish([])
        self.assertEqual(
            Path(self.gw.resolver.resolve("main").spec.root), decoy,
            "control: once unregistered, the bare name does resolve to the look-alike repository",
        )
        with self.launches.watching():
            # Before v0.6.1 the process kept answering with the revoked project and listed ``main`` as unobserved.
            # The revocation now removes the identity itself: the project is unknown, so nothing is asked of Git.
            for name, call in {
                "snapshot": lambda: self.gw.projects.project_reality_snapshot("proj"),
                "worktrees": lambda: self.gw.projects.discover_worktrees("proj"),
            }.items():
                with self.subTest(entry_point=name):
                    with self.assertRaises(WorkspaceError):
                        call()
        self.assertEqual(self.launches.in_root(self.main), 0)
        self.assertEqual(self.launches.in_root(decoy), 0, "the identity was rebound to a same-named derived repository")

    def test_a_root_that_vanished_is_not_observed(self) -> None:
        shutil.rmtree(self.main)
        with self.launches.watching():
            snapshot = self.gw.projects.project_reality_snapshot("proj")
        main = self.by_id(snapshot)["main"]
        self.assertIs(main["observable"], False)
        self.assertNotIn("clean", main)
        self.assertEqual(self.launches.in_root(self.main), 0)

    def test_a_registration_moved_to_another_root_is_observed_where_it_points_now(self) -> None:
        moved = self.repo("moved")
        self.publish([self.entry("main", moved, role="canonical-main")])
        with self.launches.watching():
            snapshot = self.gw.projects.project_reality_snapshot("proj")
            worktrees = self.gw.projects.discover_worktrees("proj")
        self.assertEqual(self.by_id(snapshot)["main"]["head"], head_of(moved))
        self.assertGreater(self.launches.in_root(moved), 0)
        self.assertEqual(self.launches.in_root(self.main), 0, "Git ran in the root remembered from startup")
        self.assertEqual({w["path"] for w in worktrees}, {str(moved)})

    def test_worktrees_are_registered_by_what_the_registry_serves_now(self) -> None:
        linked = self.base / "linked"
        subprocess.run(["git", "-C", str(self.main), "worktree", "add", "-q", "-b", "side", str(linked)],
                       capture_output=True, timeout=10, check=True)
        before = {w["path"]: w for w in self.gw.projects.discover_worktrees("proj")}
        self.assertEqual(before[str(self.main)]["registered_as"], "main")
        self.assertIsNone(before[str(linked)]["registered_as"])
        self.publish([self.entry("main", linked, role="canonical-main")])
        after = {w["path"]: w for w in self.gw.projects.discover_worktrees("proj")}
        self.assertEqual(after[str(linked)]["registered_as"], "main")
        self.assertIs(after[str(linked)]["content_authorized"], True)
        self.assertIsNone(after[str(self.main)]["registered_as"], "a root the registry no longer serves authorizes nothing")
        self.assertIs(after[str(self.main)]["content_authorized"], False)

    def test_a_worktree_whose_instance_cannot_read_content_is_not_content_authorized(self) -> None:
        linked = self.base / "linked"
        subprocess.run(["git", "-C", str(self.main), "worktree", "add", "-q", "-b", "side", str(linked)],
                       capture_output=True, timeout=10, check=True)
        gw = self.gateway([
            self.entry("main", self.main, role="canonical-main"),
            self.entry("observer", linked, capabilities=["git.observe"]),
        ])
        found = {w["path"]: w for w in gw.projects.discover_worktrees("proj")}
        self.assertEqual(found[str(linked)]["registered_as"], "observer")
        self.assertIs(found[str(linked)]["content_authorized"], False)
        self.assertIs(found[str(self.main)]["content_authorized"], True)

    def test_a_static_registration_is_still_independent_of_any_root_scope(self) -> None:
        self.gw.scopes.add_scope(RootScope(scope_id="deny-all", root=str(self.base), authority=RootScopeAuthority()))
        with self.launches.watching():
            snapshot = self.gw.projects.project_reality_snapshot("proj")
        self.assertIs(self.by_id(snapshot)["main"]["observable"], True)
        self.assertGreater(self.launches.in_root(self.main), 0)


class DerivedInstanceTests(ProjectFixture):
    """A derived instance is only as observable as the live RootScope that admitted it."""

    def setUp(self) -> None:
        super().setUp()
        self.main = self.repo("main")
        self.derived_root = self.repo("derived-repo", parent=self.base / "scope")
        self.gw = self.gateway([self.entry("main", self.main, role="canonical-main")])
        self.scope_root = self.base / "scope"
        self.gw.scopes.add_scope(RootScope(scope_id="scope", root=str(self.scope_root), authority=FULL_SCOPE))
        self.derived_id = "derived:scope:derived-repo"
        self.gw.projects.get_project("proj").instances.append(WorkspaceInstance(
            workspace_id=self.derived_id, project_id="proj", role="development", root=str(self.derived_root),
        ))

    def revoke_git(self) -> None:
        self.gw.scopes.replace_scopes([RootScope(
            scope_id="scope", root=str(self.scope_root),
            authority=RootScopeAuthority(discover=True, metadata_read=True, content_read=True, auto_admit=True),
        )])

    def test_control_the_admitted_derived_instance_is_observed(self) -> None:
        with self.launches.watching():
            snapshot = self.gw.projects.project_reality_snapshot("proj")
        self.assertIs(self.by_id(snapshot)[self.derived_id]["observable"], True)
        self.assertGreater(self.launches.in_root(self.derived_root), 0)

    def test_revoking_git_observe_stops_it_at_the_next_question(self) -> None:
        self.revoke_git()
        for name, call in {
            "snapshot": lambda: self.gw.projects.project_reality_snapshot("proj"),
            "worktrees": lambda: self.gw.projects.discover_worktrees("proj"),
        }.items():
            with self.subTest(entry_point=name):
                launches = GitLaunches()
                with launches.watching():
                    result = call()
                self.assertEqual(launches.in_root(self.derived_root), 0)
                if name == "snapshot":
                    self.assertIs(self.by_id(result)[self.derived_id]["observable"], False)
                    self.assertNotIn("clean", self.by_id(result)[self.derived_id])

    def test_a_project_registry_without_a_live_resolver_does_not_observe_derived_instances(self) -> None:
        standalone = ProjectRegistry(WorkspaceRegistry(str(self.registry_path)), self.registry_path)
        standalone.get_project("proj").instances.append(WorkspaceInstance(
            workspace_id=self.derived_id, project_id="proj", role="development", root=str(self.derived_root),
        ))
        with self.launches.watching():
            snapshot = standalone.project_reality_snapshot("proj")
        self.assertIs(self.by_id(snapshot)[self.derived_id]["observable"], False)
        self.assertEqual(self.launches.in_root(self.derived_root), 0)


class MixedProjectTests(ProjectFixture):
    """One instance's failure is its own: the others are still observed, and nothing reads as clean."""

    def setUp(self) -> None:
        super().setUp()
        self.ok = self.repo("ok")
        self.viewer = self.repo("viewer")
        self.gone = self.repo("gone")
        self.docs = self.base / "docs"
        self.docs.mkdir()
        (self.docs / "notes.txt").write_text("notes\n", encoding="utf-8")
        self.fresh = unborn_repo(self.base / "fresh")
        self.broken = self.base / "broken"
        (self.broken / ".git").mkdir(parents=True)
        (self.broken / ".git" / "HEAD").write_text("not a ref\n", encoding="utf-8")
        self.removed = self.repo("removed")
        entries = [
            self.entry("ok", self.ok, role="canonical-main"),
            self.entry("viewer", self.viewer, capabilities=["filesystem.read"]),
            self.entry("gone", self.gone),
            self.entry("docs", self.docs, kind="filesystem-directory", capabilities=["filesystem.read"]),
            self.entry("fresh", self.fresh, role="candidate"),
            self.entry("broken", self.broken),
            self.entry("removed", self.removed),
        ]
        self.gw = self.gateway(entries)
        shutil.rmtree(self.gone)
        self.publish([e for e in entries if e["workspace_id"] != "removed"])
        with self.launches.watching():
            self.snapshot = self.gw.projects.project_reality_snapshot("proj")
            self.report = self.gw.project_instances("proj")["worktree_discovery"]
        self.found = self.by_id(self.snapshot)

    def test_only_the_instances_that_may_be_observed_reach_git(self) -> None:
        for name in ("viewer", "docs", "gone", "removed"):
            with self.subTest(instance=name):
                self.assertEqual(self.launches.in_root(self.base / name), 0)
        for name in ("ok", "fresh"):
            with self.subTest(instance=name):
                self.assertGreater(self.launches.in_root(self.base / name), 0)

    def test_each_instance_is_reported_as_what_it_is(self) -> None:
        ok = self.found["ok"]
        self.assertEqual((ok["observable"], ok["head_state"], ok["history_available"], ok["clean"]),
                         (True, "attached", True, True))
        fresh = self.found["fresh"]
        self.assertEqual((fresh["observable"], fresh["head"], fresh["head_state"], fresh["history_available"]),
                         (True, None, "unborn", False))
        for name in ("viewer", "gone", "broken"):
            with self.subTest(instance=name):
                self.assertIs(self.found[name]["observable"], False)
                self.assertNotIn("clean", self.found[name])
                self.assertNotIn("head_state", self.found[name])
        self.assertNotIn("removed", self.found, "an instance the registry no longer serves is not exposed (F-G2-2)")
        docs = self.found["docs"]
        self.assertEqual((docs["observable"], docs["kind"]), (False, "filesystem-directory"))
        self.assertIn("not applicable", docs["error"])

    def test_the_aggregate_never_reads_the_unobserved_as_complete(self) -> None:
        coverage = self.snapshot["coverage"]
        self.assertNotEqual(coverage["status"], "COMPLETE")
        warning = next(w for w in coverage["warnings"] if w.startswith("UNOBSERVABLE_INSTANCES"))
        self.assertTrue(warning.startswith("UNOBSERVABLE_INSTANCES: 4 "), warning)
        for name in ("broken", "docs", "gone", "viewer"):
            self.assertIn(name, warning)
        self.assertNotIn("removed", warning, "an instance the registry no longer serves is not counted or named (F-G2-2)")
        self.assertEqual(self.report, {
            "complete": False, "not_observed_instances": ["broken", "gone", "viewer"],
        })

    def test_one_failing_instance_does_not_stop_the_others(self) -> None:
        found = {w["path"] for w in self.gw.projects.discover_worktrees("proj")}
        self.assertEqual(found, {str(self.ok), str(self.fresh)})


class IndexOnlyFallbackTests(ProjectFixture):
    """A project known only from the reality index was never asked: its empty worktree list proves nothing."""

    def setUp(self) -> None:
        super().setUp()
        code = self.base / "code"
        self.repo("fast-repo", parent=code)
        self.gw = self.gateway([])
        self.gw.scopes.add_scope(RootScope(
            scope_id="idx", root=str(code),
            authority=RootScopeAuthority(discover=True, content_read=True, git_observe=True, auto_admit=True, index=True),
        ))
        self.gw.index_scope("idx")

    def test_the_fallback_says_nobody_was_asked_and_starts_no_git(self) -> None:
        with self.launches.watching():
            instances = self.gw.project_instances("fast-repo")
            reality = self.gw.project_reality("fast-repo")
        self.assertEqual((instances["source"], reality["source"]), ("reality_index", "reality_index"))
        self.assertEqual(self.launches.roots, [])
        for payload in (instances, reality):
            report = payload["worktree_discovery"]
            self.assertIs(report["complete"], False)
            self.assertEqual(report["not_observed_instances"], ["derived:idx:fast-repo"])
        self.assertEqual(reality["coverage"]["status"], "PARTIAL")


class CachedInventoryEnrichmentTests(unittest.TestCase):
    """A cached fast scan remembers where repositories are, not what may be asked of them."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="uam-enrich-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.code = self.base / "code"
        self.alpha = self.code / "alpha"
        self.beta = self.code / "beta"
        for root in (self.alpha, self.beta):
            init_git_repo(root, files={"README.md": f"# {root.name}\n"})

    def engine(self, *scopes: RootScope) -> DiscoveryEngine:
        registry = RootScopeRegistry()
        for scope in scopes:
            registry.add_scope(scope)
        return DiscoveryEngine(registry)

    def code_scope(self, *, git_observe: bool) -> RootScope:
        return RootScope(
            scope_id="code", root=str(self.code),
            authority=RootScopeAuthority(discover=True, metadata_read=True, git_observe=git_observe),
        )

    def enriched(self, engine: DiscoveryEngine) -> tuple[dict[str, Any], GitLaunches]:
        engine.scope_inventory("code")  # the fast scan that fills the cache
        launches = GitLaunches()
        with launches.watching():
            inventory = engine.scope_inventory("code", enrich_git=True)
        return inventory, launches

    @staticmethod
    def instances(inventory: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {
            Path(inst["path"]).name: inst
            for project in inventory["projects"] for inst in project["instances"]
        }

    def test_a_scope_without_git_observe_is_not_asked_for_git_after_a_fast_scan(self) -> None:
        inventory, launches = self.enriched(self.engine(self.code_scope(git_observe=False)))
        self.assertEqual(launches.in_root(self.alpha) + launches.in_root(self.beta), 0)
        self.assertEqual({i["git_enriched"] for i in self.instances(inventory).values()}, {False})
        self.assertEqual(inventory["git_enrichment"]["enriched_instances"], 0)
        self.assertIs(inventory["git_enrichment"]["complete"], False)
        self.assertIs(inventory["git_enrichment"]["partial"], True)

    def test_a_scope_with_git_observe_is_enriched_after_a_fast_scan(self) -> None:
        inventory, launches = self.enriched(self.engine(self.code_scope(git_observe=True)))
        self.assertGreater(launches.in_root(self.alpha), 0)
        self.assertGreater(launches.in_root(self.beta), 0)
        found = self.instances(inventory)
        self.assertEqual(found["alpha"]["head"], head_of(self.alpha))
        self.assertEqual({i["git_enriched"] for i in found.values()}, {True})
        self.assertIs(inventory["git_enrichment"]["complete"], True)

    def test_a_nested_scope_that_withholds_git_observe_keeps_its_repository_out(self) -> None:
        nested = RootScope(
            scope_id="beta-only", root=str(self.beta),
            authority=RootScopeAuthority(discover=True, metadata_read=True, git_observe=False),
        )
        inventory, launches = self.enriched(self.engine(self.code_scope(git_observe=True), nested))
        found = self.instances(inventory)
        self.assertGreater(launches.in_root(self.alpha), 0)
        self.assertEqual(launches.in_root(self.beta), 0)
        self.assertIs(found["alpha"]["git_enriched"], True)
        self.assertIs(found["beta"]["git_enriched"], False)
        self.assertIs(inventory["git_enrichment"]["partial"], True)
        self.assertEqual(inventory["git_enrichment"]["enriched_instances"], 1)

    def test_an_outer_scope_without_git_observe_does_not_stop_a_nested_scope_that_grants_it(self) -> None:
        nested = RootScope(
            scope_id="beta-only", root=str(self.beta),
            authority=RootScopeAuthority(discover=True, metadata_read=True, git_observe=True),
        )
        inventory, launches = self.enriched(self.engine(self.code_scope(git_observe=False), nested))
        found = self.instances(inventory)
        self.assertEqual(launches.in_root(self.alpha), 0)
        self.assertGreater(launches.in_root(self.beta), 0)
        self.assertIs(found["alpha"]["git_enriched"], False)
        self.assertIs(found["beta"]["git_enriched"], True)


if __name__ == "__main__":
    unittest.main()
