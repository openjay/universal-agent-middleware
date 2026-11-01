"""F-G2-2 (v0.6.1): a project or instance the registry no longer declares is not answered by a running process.

Before v0.6.1 ``ProjectRegistry`` built its project list once. A process that had started before a revocation kept
returning the revoked project and instances (restarting only hid it for a while), because only the Git questions
re-checked authority. Each case below keeps ONE long-lived gateway and server, changes the registry file under it and
asks again: the very next answer must be the answer of a process that started after the change.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest import mock

from directory_fixtures import static_repository
from r3_world import call_direct, call_protocol, decode, run
from synthetic_fixtures import init_git_repo, write_workspace_registry

from universal_agent_middleware import git_readonly
from universal_agent_middleware.errors import WorkspaceError
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.project import ProjectRegistry, RegistryGenerationChanged
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority
from universal_agent_middleware.workspace import WorkspaceRegistry

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:  # pragma: no cover - the MCP SDK is an optional test dependency
    create_session_read_server = None  # type: ignore[assignment]

REGISTRY_VERSION = "uam-workspace-registry-v1"
PROJECT_OF = {"alpha-main": "alpha", "alpha-side": "alpha", "beta-main": "beta"}
ALL = ("alpha-main", "alpha-side", "beta-main")


class HotWorld(unittest.TestCase):
    """Three registered repositories in two projects, one gateway and one server that live through every change."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="uam-v061-revocation-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.registry_path = self.base / "config" / "workspaces.json"
        self.roots = {name: self.base / "repos" / name for name in ALL}
        for name, root in self.roots.items():
            init_git_repo(root, files={"README.md": f"# {name}\n"})
        self.publish(ALL)
        self.gateway = MiddlewareGateway(str(self.registry_path), str(self.base / "state-hot"))
        self.server = create_session_read_server(
            registry_path=str(self.registry_path), state_dir=str(self.base / "state-server"),
        ) if create_session_read_server is not None else None

    def entries(self, names: tuple[str, ...]) -> list[dict[str, Any]]:
        return [static_repository(name, self.roots[name], project_id=PROJECT_OF[name], role="development")
                for name in names]

    def publish(self, names: tuple[str, ...]) -> None:
        write_workspace_registry(self.registry_path, self.entries(names))

    def cold(self) -> MiddlewareGateway:
        """What a process that started after the change answers (a new state directory every time)."""
        self.cold_runs = getattr(self, "cold_runs", 0) + 1
        return MiddlewareGateway(str(self.registry_path), str(self.base / f"state-cold-{self.cold_runs}"))

    def instance_ids(self, gateway: MiddlewareGateway, project_id: str) -> set[str]:
        return {item["workspace_id"] for item in gateway.project_instances(project_id)["instances"]}

    def tool(self, name: str, **arguments: Any) -> str:
        return run(call_direct(self.server, name, **arguments))

    def every_answer_naming_an_identity(self) -> dict[str, str]:
        """The text of each entry point that can carry a project or instance identity (hot gateway and hot server)."""
        answers: dict[str, str] = {}
        calls: dict[str, Callable[[], Any]] = {
            "gateway.list_projects": lambda: self.gateway.list_projects(),
            "gateway.project_instances(alpha)": lambda: self.gateway.project_instances("alpha"),
            "gateway.project_reality(alpha)": lambda: self.gateway.project_reality("alpha"),
            "gateway.project_reality(beta)": lambda: self.gateway.project_reality("beta"),
            "projects.list_projects": lambda: self.gateway.projects.list_projects(),
        }
        for name, call in calls.items():
            try:
                answers[name] = json.dumps(call(), default=str)
            except WorkspaceError as exc:
                answers[name] = f"REFUSED {exc}"
        for tool, arguments in (
            ("uam_list_workspaces", {}),
            ("uam_project_reality", {"project_id": "alpha"}),
            ("uam_project_reality", {"project_id": "beta"}),
            ("uam_list_project_instances", {"project_id": "alpha"}),
            ("uam_list_project_instances", {"project_id": "beta"}),
        ):
            answers[f"{tool}{arguments}"] = self.tool(tool, **arguments)
        return answers


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class RevocationReachesARunningProcessTests(HotWorld):
    def test_control_the_registered_identities_are_answered_before_any_change(self) -> None:
        self.assertEqual(self.instance_ids(self.gateway, "alpha"), {"alpha-main", "alpha-side"})
        self.assertEqual(self.instance_ids(self.gateway, "beta"), {"beta-main"})
        answers = self.every_answer_naming_an_identity()
        self.assertIn("alpha-side", answers["gateway.list_projects"])
        self.assertIn("alpha-side", answers["uam_list_project_instances{'project_id': 'alpha'}"])

    def test_a_partial_revocation_removes_the_instance_at_the_next_call_and_keeps_the_rest(self) -> None:
        self.every_answer_naming_an_identity()  # the process has been serving all three
        self.publish(("alpha-main", "beta-main"))
        for entry_point, text in self.every_answer_naming_an_identity().items():
            with self.subTest(entry_point=entry_point):
                self.assertNotIn("alpha-side", text, "the revoked instance was answered by a running process")
        self.assertEqual(self.instance_ids(self.gateway, "alpha"), {"alpha-main"})
        self.assertEqual(self.instance_ids(self.gateway, "beta"), {"beta-main"})

    def test_a_full_revocation_of_a_project_makes_the_project_unknown(self) -> None:
        self.every_answer_naming_an_identity()
        self.publish(("beta-main",))
        listed = decode(self.tool("uam_list_workspaces"))
        self.assertEqual([project["project_id"] for project in listed["projects"]], ["beta"])
        for entry_point, text in self.every_answer_naming_an_identity().items():
            with self.subTest(entry_point=entry_point):
                self.assertNotIn("alpha-main", text)
                self.assertNotIn("alpha-side", text)
        for tool in ("uam_project_reality", "uam_list_project_instances"):
            with self.subTest(tool=tool):
                answer = decode(self.tool(tool, project_id="alpha"))
                self.assertIn("error", answer)
                self.assertNotIn("instances", answer)
        with self.assertRaises(WorkspaceError):
            self.gateway.projects.get_project("alpha")
        self.assertIsNone(self.gateway.projects.get_instance("alpha-main"))

    def test_the_same_holds_through_a_real_mcp_client_session(self) -> None:
        self.publish(("beta-main",))
        for tool in ("uam_project_reality", "uam_list_project_instances"):
            with self.subTest(tool=tool):
                is_error, text = run(call_protocol(self.server, tool, project_id="alpha"))
                self.assertFalse(is_error, "a refusal is an answer, not a tool failure")
                self.assertNotIn("alpha-main", text)
                self.assertNotIn("alpha-side", text)
                self.assertIn("error", decode(text))

    def test_a_regrant_brings_the_identity_back_at_the_next_call(self) -> None:
        self.publish(("beta-main",))
        self.assertNotIn("alpha-side", self.every_answer_naming_an_identity()["gateway.list_projects"])
        self.publish(ALL)
        self.assertEqual(self.instance_ids(self.gateway, "alpha"), {"alpha-main", "alpha-side"})
        self.assertIn("alpha-side", self.every_answer_naming_an_identity()["uam_list_project_instances{'project_id': 'alpha'}"])

    def test_a_registry_that_is_missing_serves_no_project(self) -> None:
        self.every_answer_naming_an_identity()
        os.remove(self.registry_path)
        self.assertEqual(self.gateway.projects.list_projects(), [])
        with self.assertRaises(WorkspaceError):
            self.gateway.projects.get_project("alpha")
        for entry_point, text in self.every_answer_naming_an_identity().items():
            with self.subTest(entry_point=entry_point):
                for identity in ALL:
                    self.assertNotIn(identity, text)
        self.publish(ALL)
        self.assertEqual(self.instance_ids(self.gateway, "alpha"), {"alpha-main", "alpha-side"})

    def test_a_registry_that_cannot_be_read_is_refused_and_never_answered_from_memory(self) -> None:
        valid = self.registry_path.read_text(encoding="utf-8")
        malformed = {
            "not json": "{ this is not json",
            "truncated": valid[: len(valid) // 2],
            "not an object": "[]",
            "unsupported version": json.dumps({"registry_version": "other", "workspaces": []}),
            "workspaces not a list": json.dumps({"registry_version": REGISTRY_VERSION, "workspaces": "alpha-main"}),
            "entry not an object": json.dumps({"registry_version": REGISTRY_VERSION, "workspaces": [7]}),
            "unknown field": json.dumps({"registry_version": REGISTRY_VERSION, "workspaces": [
                {**self.entries(("alpha-main",))[0], "surprise": True}]}),
        }
        for label, body in malformed.items():
            with self.subTest(registry=label):
                self.every_answer_naming_an_identity()  # warm every cache with the valid registry
                self.registry_path.write_text(body, encoding="utf-8")
                for entry_point, text in self.every_answer_naming_an_identity().items():
                    for identity in ALL:
                        self.assertNotIn(identity, text, f"{entry_point} answered from memory of the earlier registry")
                with self.assertRaises(WorkspaceError):
                    self.gateway.projects.list_projects()
                with self.assertRaises(WorkspaceError):
                    self.gateway.projects.get_instance("alpha-main")
                self.registry_path.write_text(valid, encoding="utf-8")
                self.assertEqual(self.instance_ids(self.gateway, "alpha"), {"alpha-main", "alpha-side"}, "no recovery")

    def test_a_declaration_of_the_wrong_type_is_read_as_absent_and_cannot_raise_or_add_a_project(self) -> None:
        declared = static_repository("alpha-main", self.roots["alpha-main"])
        declared.update({"project_id": 7, "role": ["x"], "lifecycle": {}, "repository_identity": 3, "discovery": "no"})
        write_workspace_registry(self.registry_path, [declared])
        projects = self.gateway.projects.list_projects()
        self.assertEqual([project["project_id"] for project in projects], ["alpha-main"])
        instance = projects[0]["instances"][0]
        self.assertEqual((instance["role"], instance["lifecycle"]), ("unspecified", "active"))

    def test_every_consecutive_call_is_the_answer_of_a_process_started_after_the_change(self) -> None:
        sequence = [
            ALL, ("alpha-main", "beta-main"), ("beta-main",), ("alpha-side", "beta-main"), (), ALL,
            ("alpha-side",), ALL,
        ]
        for step, names in enumerate(sequence):
            with self.subTest(step=step, registry=names):
                self.publish(names)
                hot, cold = self.gateway, self.cold()
                self.assertEqual(hot.projects.list_projects(), cold.projects.list_projects())
                for project_id in ("alpha", "beta", "alpha-side"):
                    try:
                        expected: set[str] | str = self.instance_ids(cold, project_id)
                    except WorkspaceError:
                        expected = "REFUSED"
                    try:
                        actual: set[str] | str = self.instance_ids(hot, project_id)
                    except WorkspaceError:
                        actual = "REFUSED"
                    self.assertEqual(actual, expected, project_id)

    def test_a_label_or_role_change_is_served_at_the_next_call(self) -> None:
        self.assertEqual(self.gateway.projects.get_instance("alpha-main").role, "development")
        entries = self.entries(ALL)
        entries[0]["role"] = "canonical-main"
        entries[0]["label"] = "renamed"
        write_workspace_registry(self.registry_path, entries)
        instance = self.gateway.projects.get_instance("alpha-main")
        self.assertEqual((instance.role, instance.label), ("canonical-main", "renamed"))


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class AnAnswerIsOneRegistryGenerationTests(HotWorld):
    """A registry replaced while an answer is being assembled drops that answer: it never mixes two generations."""

    def setUp(self) -> None:
        super().setUp()
        self.swapped = False

    def swapping_during(self, target: str, names: tuple[str, ...]):
        """Git's ``target`` answers normally; right after its first answer the registry is replaced by ``names``."""
        real = getattr(git_readonly.ReadOnlyGit, target)

        def replace_then_answer(git_self: Any, *args: Any, **kwargs: Any) -> Any:
            result = real(git_self, *args, **kwargs)
            if not self.swapped:
                self.swapped = True
                self.publish(names)  # the revocation lands while the answer is half built
            return result

        return mock.patch.object(git_readonly.ReadOnlyGit, target, replace_then_answer)

    def test_project_instances_is_dropped_when_the_registry_changes_underneath_it(self) -> None:
        with self.swapping_during("worktree_list", ("alpha-main", "beta-main")):
            with self.assertRaises(RegistryGenerationChanged):
                self.gateway.project_instances("alpha")
        self.assertEqual(self.instance_ids(self.gateway, "alpha"), {"alpha-main"}, "the next call is the new registry")

    def test_the_reality_snapshot_is_dropped_when_the_registry_changes_underneath_it(self) -> None:
        with self.swapping_during("status", ("alpha-main", "beta-main")):
            with self.assertRaises(RegistryGenerationChanged):
                self.gateway.project_reality("alpha")
        self.assertEqual({item["workspace_id"] for item in self.gateway.project_reality("alpha")["instances"]},
                         {"alpha-main"})

    def test_a_dropped_answer_is_an_error_and_the_next_call_refuses_the_revoked_project(self) -> None:
        # A generation change is not the "project unknown" case that ``project_instances`` completes from the index.
        with self.swapping_during("worktree_list", ("beta-main",)):
            with self.assertRaises(RegistryGenerationChanged):
                self.gateway.project_instances("alpha")
        with self.assertRaises(WorkspaceError):
            self.gateway.project_instances("alpha")

    def test_the_tool_answers_the_dropped_answer_as_an_error_not_as_a_half_revoked_list(self) -> None:
        with self.swapping_during("worktree_list", ("alpha-main", "beta-main")):
            text = self.tool("uam_list_project_instances", project_id="alpha")
        answer = decode(text)
        self.assertIn("error", answer)
        self.assertNotIn("alpha-side", text)


class IndexBackedAnswersTests(HotWorld):
    """The reality index is a second source of project identities: scope discovery, never the registry.

    A project the registry does not (or no longer does) declare can still be known from a RootScope that was
    indexed; ``project_instances`` / ``project_reality`` complete it from the index and say so (``source``). That is
    unchanged. What a revocation must guarantee is that the registered identities are not part of that answer and that
    a running process gives the answer a process started after the change gives.
    """

    def setUp(self) -> None:
        super().setUp()
        init_git_repo(self.base / "code" / "alpha", files={"README.md": "# a discovered repository named alpha\n"})
        self.state = self.base / "state-indexed"
        self.running = self.indexed_gateway()
        self.running.index_scope("idx")

    def indexed_gateway(self) -> MiddlewareGateway:
        """A gateway over the shared state directory (hence the shared index) with the scope that discovers ``code``."""
        gateway = MiddlewareGateway(str(self.registry_path), str(self.state))
        gateway.scopes.add_scope(RootScope(
            scope_id="idx", root=str(self.base / "code"),
            authority=RootScopeAuthority(discover=True, content_read=True, git_observe=True, auto_admit=True, index=True),
        ))
        return gateway

    def test_control_while_the_project_is_registered_it_is_answered_from_the_registry(self) -> None:
        answer = self.running.project_instances("alpha")
        self.assertEqual(answer["source"], "registered")
        self.assertEqual({item["workspace_id"] for item in answer["instances"]}, {"alpha-main", "alpha-side"})

    def test_a_revoked_project_is_never_completed_with_its_registered_identities(self) -> None:
        self.running.project_instances("alpha")
        self.publish(("beta-main",))
        for label, answer in (("project_instances", self.running.project_instances("alpha")),
                              ("project_reality", self.running.project_reality("alpha"))):
            with self.subTest(answer=label):
                self.assertEqual(answer["source"], "reality_index")
                self.assertEqual({item["workspace_id"] for item in answer["instances"]}, {"derived:idx:alpha"})
                text = json.dumps(answer, default=str)
                self.assertNotIn("alpha-main", text)
                self.assertNotIn("alpha-side", text)

    def test_the_index_backed_answer_is_the_answer_of_a_process_started_after_the_change(self) -> None:
        self.running.project_instances("alpha")
        for names in (("alpha-main", "beta-main"), ("beta-main",), (), ALL):
            with self.subTest(registry=names):
                self.publish(names)
                fresh = self.indexed_gateway()
                self.assertEqual(self.running.project_instances("alpha"), fresh.project_instances("alpha"))
                running, started_after = self.running.project_reality("alpha"), fresh.project_reality("alpha")
                for answer in (running, started_after):
                    answer.pop("observed_at", None)
                self.assertEqual(running, started_after)


class ProjectRegistryUnitTests(unittest.TestCase):
    """``ProjectRegistry`` on its own: the view follows the registry generation, and a derived id is not the registry's."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="uam-v061-projectregistry-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.root = self.base / "repo"
        init_git_repo(self.root, files={"README.md": "# repo\n"})
        self.path = self.base / "config" / "workspaces.json"
        write_workspace_registry(self.path, [static_repository("only", self.root, project_id="p")])

    def registry(self) -> ProjectRegistry:
        return ProjectRegistry(WorkspaceRegistry(str(self.path)), self.path)

    def test_the_generation_changes_exactly_when_the_registry_text_changes(self) -> None:
        projects = self.registry()
        first = projects.generation()
        self.assertEqual(projects.generation(), first)
        write_workspace_registry(self.path, [static_repository("only", self.root, project_id="q")])
        second = projects.generation()
        self.assertNotEqual(second, first)
        with self.assertRaises(RegistryGenerationChanged):
            projects.require_generation(first)
        projects.require_generation(second)

    def test_a_derived_identity_is_not_something_the_registry_can_answer(self) -> None:
        projects = self.registry()
        self.assertIsNone(projects.get_instance("derived:scope:anything"))
        self.path.write_text("{ broken", encoding="utf-8")
        self.assertIsNone(projects.get_instance("derived:scope:anything"), "a derived id never depended on the registry")
        with self.assertRaises(WorkspaceError):
            projects.get_instance("only")


if __name__ == "__main__":
    unittest.main()
