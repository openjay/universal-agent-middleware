"""An answer is one registry generation: a mid-answer change is dropped, never completed from the reality index.

``MiddlewareGateway.project_instances`` and ``project_reality`` assemble a project answer from the registry and from Git. When
the registry is replaced while that happens, ``ProjectRegistry.require_generation`` raises ``RegistryGenerationChanged`` and the
answer is dropped: the caller asks again and gets the new registry's answer. ``RegistryGenerationChanged`` is a
``WorkspaceError``, and both tools complete a project from the reality index when a ``WorkspaceError`` says that the registry
does not know it. The ``except RegistryGenerationChanged: raise`` clause in front of that branch is therefore the only thing
that keeps an answer made from two generations from being finished from the index.

No other test failed without those two clauses. The "registry changes underneath the answer" cases of
``test_v061_project_revocation`` hold no index rows, so the index fallback finds nothing and re-raises the very same exception;
its index-backed cases never change the registry during an answer. The cases below put both together: a project that a RootScope
index knows (as ``derived:idx:alpha``) and a registry that is replaced mid-answer. A gateway without the two clauses fails the
two "dropped" cases here.

Behaviour pinned (the CHANGELOG, "Compatibility", says the same):
  * the project stays declared and an instance is revoked mid-answer -> the answer is dropped, for both tools;
  * ``project_instances``: the whole project is revoked mid-answer -> the answer is dropped as well;
  * ``project_reality``: the whole project is revoked while the instances are being observed -> ``get_project`` no longer knows
    the project and raises the plain unknown-project ``WorkspaceError`` before the generation is checked, so the answer is the NEW
    generation's index-backed answer: ``derived:`` identities only, no registered identity and no text of one. A process started
    after the change answers the same, so nothing of the old generation is served; it is pinned because it is the one place where
    "dropped" and "completed from the index" differ between the two tools. Without index rows the same timing ends in the plain
    unknown-project error.
"""
from __future__ import annotations

import json
from typing import Any
from unittest import mock

import test_v061_project_revocation as world
from synthetic_fixtures import init_git_repo

from universal_agent_middleware import git_readonly
from universal_agent_middleware.errors import WorkspaceError
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.project import RegistryGenerationChanged
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority

REGISTERED_IDENTITIES = ("alpha-main", "alpha-side")


class GenerationChangeWhileTheIndexKnowsTheProjectTests(world.HotWorld):
    """alpha is registered (two instances) AND indexed by a RootScope as ``derived:idx:alpha``."""

    def setUp(self) -> None:
        super().setUp()
        init_git_repo(self.base / "code" / "alpha", files={"README.md": "# a discovered repository named alpha\n"})
        self.state = self.base / "state-indexed"
        self.running = self.indexed_gateway()
        self.running.index_scope("idx")
        self.swapped = False

    def indexed_gateway(self) -> MiddlewareGateway:
        gateway = MiddlewareGateway(str(self.registry_path), str(self.state))
        gateway.scopes.add_scope(RootScope(
            scope_id="idx", root=str(self.base / "code"),
            authority=RootScopeAuthority(discover=True, content_read=True, git_observe=True, auto_admit=True, index=True),
        ))
        return gateway

    def swapping_during(self, target: str, names: tuple[str, ...]):
        """Git's ``target`` answers normally; right after its first answer the registry is replaced by ``names``."""
        real = getattr(git_readonly.ReadOnlyGit, target)

        def replace_then_answer(git_self: Any, *args: Any, **kwargs: Any) -> Any:
            result = real(git_self, *args, **kwargs)
            if not self.swapped:
                self.swapped = True
                self.publish(names)
            return result

        return mock.patch.object(git_readonly.ReadOnlyGit, target, replace_then_answer)

    def assert_nothing_registered_is_named(self, text: str) -> None:
        for identity in REGISTERED_IDENTITIES:
            self.assertNotIn(identity, text)

    def test_control_the_index_does_answer_for_alpha_once_the_registry_no_longer_declares_it(self) -> None:
        # The premise of the cases below: without the clauses, THIS is what a mid-answer change would return.
        self.publish(("beta-main",))
        answer = self.running.project_instances("alpha")
        self.assertEqual(answer["source"], "reality_index")
        self.assertEqual({item["workspace_id"] for item in answer["instances"]}, {"derived:idx:alpha"})

    def test_project_instances_is_dropped_not_completed_from_the_index(self) -> None:
        for names in (("alpha-main", "beta-main"), ("beta-main",)):
            with self.subTest(registry_after_the_change=names):
                self.swapped = False
                self.publish(world.ALL)
                with self.swapping_during("worktree_list", names):
                    with self.assertRaises(RegistryGenerationChanged) as dropped:
                        self.running.project_instances("alpha")
                self.assertTrue(self.swapped)
                self.assert_nothing_registered_is_named(str(dropped.exception))
                self.assertNotIn("derived:idx:alpha", str(dropped.exception))
                self.assertEqual(self.running.project_instances("alpha")["source"],
                                 "reality_index" if names == ("beta-main",) else "registered",
                                 "the next call is the new registry's answer")

    def test_project_reality_is_dropped_when_the_project_stays_declared_and_an_instance_is_revoked(self) -> None:
        with self.swapping_during("status", ("alpha-main", "beta-main")):
            with self.assertRaises(RegistryGenerationChanged) as dropped:
                self.running.project_reality("alpha")
        self.assertTrue(self.swapped)
        self.assert_nothing_registered_is_named(str(dropped.exception))
        self.assertNotIn("derived:idx:alpha", str(dropped.exception))
        after = self.running.project_reality("alpha")
        self.assertEqual(after["source"], "registered")
        self.assertEqual({item["workspace_id"] for item in after["instances"]}, {"alpha-main"})

    def test_project_reality_when_the_whole_project_is_revoked_mid_answer_is_the_new_generations_index_answer(self) -> None:
        # Characterisation of the shipped behaviour (not a dropped answer): nothing of the old generation is in it.
        with self.swapping_during("status", ("beta-main",)):
            answer = self.running.project_reality("alpha")
        self.assertTrue(self.swapped)
        self.assertEqual(answer["source"], "reality_index")
        self.assertEqual({item["workspace_id"] for item in answer["instances"]}, {"derived:idx:alpha"})
        self.assert_nothing_registered_is_named(json.dumps(answer, default=str))
        later = self.running.project_reality("alpha")
        for fresh in (answer, later):
            fresh.pop("observed_at", None)
        self.assertEqual(answer, later, "and it is what the next call answers")

    def test_project_reality_without_index_rows_is_the_unknown_project_error_when_the_whole_project_is_revoked_mid_answer(self) -> None:
        # The third shape of the CHANGELOG: nothing for the index to answer with, so the new registry's lookup error stands.
        # HotWorld's own gateway has no RootScope and therefore no index rows.
        with self.swapping_during("status", ("beta-main",)):
            with self.assertRaises(WorkspaceError) as refused:
                self.gateway.project_reality("alpha")
        self.assertTrue(self.swapped)
        self.assertNotIsInstance(refused.exception, RegistryGenerationChanged)
        self.assertIn("unknown project", str(refused.exception))
        self.assert_nothing_registered_is_named(str(refused.exception))
