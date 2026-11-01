"""A Git repository that has no commit yet is an observable state, not an error.

``git rev-parse HEAD`` fails with ``fatal: ambiguous argument 'HEAD'`` while the current branch has
no commit, so the observation used to turn a freshly initialised repository (which is exactly what a
project is before its first commit) into a generic ``WorkspaceError``. The repository is not broken:
it is *unborn*. The observation says so in structured form (``head_state="unborn"``, no ``head``,
the branch Git itself recorded, ``history_available=false``) and everything that consumes a
snapshot keeps working. A repository that is genuinely broken is still an error: the unborn state is
recognised from Git's own answers, never assumed from a failure.
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
from unittest import mock

from universal_agent_middleware.discovery import DiscoveryEngine
from universal_agent_middleware.errors import ContractError, WorkspaceError
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.git_readonly import ReadOnlyGit
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry

from tests.synthetic_fixtures import init_git_repo, write_workspace_registry

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:
    create_session_read_server = None

GIT_ENV = {**os.environ, "GIT_AUTHOR_NAME": "UAM Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
           "GIT_COMMITTER_NAME": "UAM Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
CAPABILITIES = ["filesystem.read", "git.observe"]


def git(root: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                          timeout=20, env=GIT_ENV, check=False)
    assert done.returncode == 0, f"git {args} failed: {done.stderr}"
    return done.stdout


def unborn_repo(root: Path, *, branch: str = "trunk", files: dict[str, str] | None = None) -> Path:
    """``git init`` and nothing else: no commit, optionally with untracked files."""
    root.mkdir(parents=True, exist_ok=True)
    git(root, "init", "-q", "-b", branch)
    for rel, text in (files or {}).items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


class TemporaryCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()


class UnbornObservationTests(TemporaryCase):
    def test_status_of_a_repository_without_commits_is_structured(self) -> None:
        root = unborn_repo(self.base / "fresh", files={"notes.txt": "first\n"})
        status = ReadOnlyGit(str(root)).status()
        self.assertIsNone(status["head"])
        self.assertEqual(status["head_state"], "unborn")
        self.assertEqual(status["branch"], "trunk")
        self.assertIs(status["history_available"], False)
        self.assertIn("?? notes.txt", status["status"])

    def test_the_branch_is_what_git_recorded_not_a_guess(self) -> None:
        root = unborn_repo(self.base / "fresh", branch="release/2026")
        self.assertEqual(ReadOnlyGit(str(root)).status()["branch"], "release/2026")

    def test_staged_files_are_reported_while_the_branch_is_unborn(self) -> None:
        root = unborn_repo(self.base / "fresh", files={"notes.txt": "first\n"})
        git(root, "add", "notes.txt")
        status = ReadOnlyGit(str(root)).status()
        self.assertEqual(status["head_state"], "unborn")
        self.assertIn("A  notes.txt", status["status"])

    def test_an_empty_unborn_repository_has_a_clean_status(self) -> None:
        root = unborn_repo(self.base / "fresh")
        status = ReadOnlyGit(str(root)).status()
        self.assertEqual((status["head_state"], status["status"]), ("unborn", ""))

    def test_log_of_an_unborn_repository_is_empty_and_says_why(self) -> None:
        root = unborn_repo(self.base / "fresh", files={"notes.txt": "first\n"})
        log = ReadOnlyGit(str(root)).log(5)
        self.assertEqual(log["commits"], [])
        self.assertIs(log["history_available"], False)
        self.assertEqual(log["reason"], "unborn_head")

    def test_an_empty_directory_where_the_branch_ref_would_be_is_still_unborn(self) -> None:
        """What a deleted ``trunk/x`` branch leaves behind: Git itself still calls the branch unborn."""
        root = unborn_repo(self.base / "fresh")
        (root / ".git" / "refs" / "heads" / "trunk").mkdir(parents=True)
        observed = ReadOnlyGit(str(root))
        self.assertEqual(observed.status()["head_state"], "unborn")
        self.assertEqual(observed.log(3)["reason"], "unborn_head")

    def test_the_log_limit_is_still_validated_while_the_branch_is_unborn(self) -> None:
        root = unborn_repo(self.base / "fresh")
        with self.assertRaises(WorkspaceError):
            ReadOnlyGit(str(root)).log(0)

    def test_the_first_commit_ends_the_unborn_state(self) -> None:
        root = unborn_repo(self.base / "fresh", files={"notes.txt": "first\n"})
        git(root, "add", "notes.txt")
        git(root, "commit", "-qm", "first")
        observed = ReadOnlyGit(str(root))
        status = observed.status()
        self.assertEqual(status["head"], git(root, "rev-parse", "HEAD").strip())
        self.assertEqual((status["head_state"], status["branch"]), ("attached", "trunk"))
        self.assertIs(status["history_available"], True)
        log = observed.log(5)
        self.assertEqual([c["subject"] for c in log["commits"]], ["first"])
        self.assertIs(log["history_available"], True)
        self.assertNotIn("reason", log)


class BornStatesKeepTheirMeaningTests(TemporaryCase):
    def test_an_attached_repository_reports_history(self) -> None:
        root = self.base / "born"
        init_git_repo(root)
        status = ReadOnlyGit(str(root)).status()
        self.assertEqual(len(status["head"]), 40)
        self.assertEqual(status["head_state"], "attached")
        self.assertIs(status["history_available"], True)

    def test_a_detached_head_is_still_detached_and_has_history(self) -> None:
        root = self.base / "detached"
        init_git_repo(root)
        git(root, "checkout", "-q", "--detach", "HEAD")
        status = ReadOnlyGit(str(root)).status()
        self.assertEqual((status["head_state"], status["branch"]), ("detached", None))
        self.assertEqual(len(status["head"]), 40)
        self.assertIs(status["history_available"], True)


class BrokenIsNotUnbornTests(TemporaryCase):
    """The unborn state is recognised from Git's answers; a broken repository stays an error."""

    def test_a_branch_ref_that_holds_garbage_is_an_error(self) -> None:
        root = self.base / "broken"
        init_git_repo(root)
        branch = git(root, "branch", "--show-current").strip()
        (root / ".git" / "refs" / "heads" / branch).write_text("not-a-commit-id\n", encoding="utf-8")
        observed = ReadOnlyGit(str(root))
        with self.assertRaises(WorkspaceError):
            observed.status()
        with self.assertRaises(WorkspaceError):
            observed.log(5)

    def test_the_broken_ref_guard_does_not_rely_on_symbolic_ref_failing(self) -> None:
        """Git 2.51 fails ``symbolic-ref`` for a broken branch ref, which already stops the check
        above, but that is Git's behaviour and not its contract. Simulate a Git that answers it: this
        repository's ``status`` still succeeds, so only the loose-ref-file guard keeps it from being
        reported as an unborn branch."""
        root = self.base / "broken"
        init_git_repo(root)
        branch = git(root, "branch", "--show-current").strip()
        (root / ".git" / "refs" / "heads" / branch).write_text("not-a-commit-id\n", encoding="utf-8")
        observed = ReadOnlyGit(str(root))
        real_probe = observed._probe

        def lenient_symbolic_ref(args: list[str]) -> tuple[int, str]:
            if args[0] == "symbolic-ref":
                return 0, f"refs/heads/{branch}\n"
            return real_probe(args)

        with mock.patch.object(observed, "_probe", lenient_symbolic_ref):
            with self.assertRaisesRegex(WorkspaceError, "exists but does not resolve"):
                observed.status()
            with self.assertRaisesRegex(WorkspaceError, "exists but does not resolve"):
                observed.log(5)

    def test_a_branch_ref_naming_a_missing_object_is_an_error(self) -> None:
        root = self.base / "broken"
        init_git_repo(root)
        branch = git(root, "branch", "--show-current").strip()
        (root / ".git" / "refs" / "heads" / branch).write_text(
            "0123456789abcdef0123456789abcdef01234567\n", encoding="utf-8"
        )
        observed = ReadOnlyGit(str(root))
        with self.assertRaises(WorkspaceError):
            observed.status()
        with self.assertRaises(WorkspaceError):
            observed.log(5)

    def test_a_detached_head_that_names_no_object_is_an_error(self) -> None:
        root = self.base / "broken"
        init_git_repo(root)
        (root / ".git" / "HEAD").write_text("0123456789abcdef0123456789abcdef01234567\n", encoding="utf-8")
        observed = ReadOnlyGit(str(root))
        with self.assertRaises(WorkspaceError):
            observed.status()
        with self.assertRaises(WorkspaceError):
            observed.log(5)


class ConsumerTests(TemporaryCase):
    """Every caller of the observation survives a repository without commits."""

    def registry(self, workspaces: list[dict[str, Any]]) -> Path:
        return write_workspace_registry(self.base / "config" / "workspaces.json", workspaces)

    def entry(self, workspace_id: str, root: Path, **extra: Any) -> dict[str, Any]:
        return {"workspace_id": workspace_id, "root": str(root), "kind": "git-repository",
                "capabilities": CAPABILITIES, **extra}

    def gateway(self, workspaces: list[dict[str, Any]]) -> MiddlewareGateway:
        state = self.base / "state"
        state.mkdir(exist_ok=True)
        return MiddlewareGateway(str(self.registry(workspaces)), str(state))

    def test_the_gateway_serves_status_and_log_and_audits_them_as_passes(self) -> None:
        root = unborn_repo(self.base / "fresh", files={"notes.txt": "first\n"})
        gw = self.gateway([self.entry("fresh", root)])
        self.assertEqual(gw.git_status("fresh")["head_state"], "unborn")
        self.assertEqual(gw.git_log("fresh")["commits"], [])
        rows = [json.loads(line) for line in gw.audit.path.read_text().splitlines()]
        self.assertEqual([(r["action"], r["outcome"]) for r in rows[-2:]],
                         [("git_status", "PASS"), ("git_log", "PASS")])

    def test_a_contract_cannot_be_bound_to_a_head_that_does_not_exist(self) -> None:
        root = unborn_repo(self.base / "fresh")
        gw = self.gateway([self.entry("fresh", root)])
        with self.assertRaises(ContractError) as caught:
            gw.create_contract({"workspace_id": "fresh", "profile": "repository-change-v1",
                                "base_revision": "0" * 40})
        self.assertIn("no commit", str(caught.exception))

    def test_a_project_snapshot_observes_the_unborn_instance(self) -> None:
        main = self.base / "main"
        init_git_repo(main)
        fresh = unborn_repo(self.base / "fresh", files={"notes.txt": "first\n"})
        gw = self.gateway([
            self.entry("main", main, project_id="proj", role="canonical-main"),
            self.entry("fresh", fresh, project_id="proj", role="candidate", lifecycle="active"),
        ])
        snapshot = gw.projects.project_reality_snapshot("proj")
        observed = {i["workspace_id"]: i for i in snapshot["instances"]}["fresh"]
        self.assertIs(observed["observable"], True)
        self.assertIsNone(observed["head"])
        self.assertEqual(observed["head_state"], "unborn")
        self.assertIs(observed["history_available"], False)
        self.assertIs(observed["clean"], False)

    def test_discovery_enrichment_keeps_a_string_head_for_an_unborn_repository(self) -> None:
        fresh = unborn_repo(self.base / "code" / "fresh", files={"notes.txt": "first\n"})
        scopes = RootScopeRegistry()
        scopes.add_scope(RootScope(scope_id="code", root=str(self.base / "code"),
                                   authority=RootScopeAuthority(discover=True, metadata_read=True, git_observe=True)))
        meta = DiscoveryEngine(scopes)._read_repo_metadata(fresh)
        self.assertEqual(meta.head, "")
        self.assertEqual(meta.branch, "trunk")
        self.assertIs(meta.clean, False)


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class McpTests(TemporaryCase):
    def server(self, workspaces: list[dict[str, Any]]):
        registry = write_workspace_registry(self.base / "config" / "workspaces.json", workspaces)
        state = self.base / "state"
        state.mkdir(exist_ok=True)
        server = create_session_read_server(registry_path=str(registry), state_dir=str(state))
        return server._tool_manager._tools

    @staticmethod
    def call(tools: dict[str, Any], name: str, **kwargs: Any) -> dict[str, Any]:
        return json.loads(asyncio.run(tools[name].fn(ctx=None, **kwargs)))

    def entry(self, workspace_id: str, root: Path, **extra: Any) -> dict[str, Any]:
        return {"workspace_id": workspace_id, "root": str(root), "kind": "git-repository",
                "capabilities": CAPABILITIES, **extra}

    def test_status_log_snapshot_and_bootstrap_answer_for_an_unborn_workspace(self) -> None:
        root = unborn_repo(self.base / "fresh", files={"README.md": "# fresh\n"})
        tools = self.server([self.entry("fresh", root)])
        status = self.call(tools, "uam_git_status", workspace_id="fresh")
        self.assertNotIn("error", status)
        self.assertEqual((status["head"], status["head_state"], status["branch"]), (None, "unborn", "trunk"))
        log = self.call(tools, "uam_git_log", workspace_id="fresh")
        self.assertEqual((log["commits"], log["history_available"], log["reason"]), ([], False, "unborn_head"))
        snapshot = self.call(tools, "uam_workspace_snapshot", workspace_id="fresh")
        self.assertEqual(snapshot["repository"]["head_state"], "unborn")
        self.assertIs(snapshot["repository"]["history_available"], False)
        self.assertIsNone(snapshot["repository"]["head"])
        bootstrap = self.call(tools, "uam_session_bootstrap", workspace_id="fresh")
        self.assertEqual(bootstrap["repository"]["head_state"], "unborn")
        self.assertIs(bootstrap["repository"]["history_available"], False)
        self.assertEqual(bootstrap["repository"]["recent_commits"], [])

    def test_snapshot_and_bootstrap_of_a_born_workspace_say_the_history_is_available(self) -> None:
        root = self.base / "born"
        init_git_repo(root)
        tools = self.server([self.entry("born", root)])
        snapshot = self.call(tools, "uam_workspace_snapshot", workspace_id="born")
        bootstrap = self.call(tools, "uam_session_bootstrap", workspace_id="born")
        self.assertEqual((snapshot["repository"]["head_state"], snapshot["repository"]["history_available"]),
                         ("attached", True))
        self.assertIs(bootstrap["repository"]["history_available"], True)

    def test_bootstrapping_a_sibling_of_an_unborn_instance_does_not_fail(self) -> None:
        main = self.base / "main"
        init_git_repo(main)
        fresh = unborn_repo(self.base / "fresh", files={"notes.txt": "first\n"})
        tools = self.server([
            self.entry("main", main, project_id="proj", role="canonical-main"),
            self.entry("fresh", fresh, project_id="proj", role="candidate", lifecycle="active"),
        ])
        bootstrap = self.call(tools, "uam_session_bootstrap", workspace_id="main")
        self.assertNotIn("error", bootstrap)
        others = bootstrap["project"]["other_instances"]
        self.assertEqual([(o["workspace_id"], o["head"], o["head_state"]) for o in others],
                         [("fresh", "", "unborn")])


if __name__ == "__main__":
    unittest.main()
