"""Unit tests for ``PathPolicy`` and ``RootScopeRegistry.nested_scopes``.

The gateway-level behaviour is covered end to end in ``test_path_authority``; these pin the pure
rules (most specific wins, how each operation maps to authority flags, how a denied subtree is
turned into Git excludes) so a regression points at the rule rather than at a tool.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from universal_agent_middleware.errors import PathPolicyError, ScopeAuthorityError
from universal_agent_middleware.path_authority import PathPolicy
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry

FULL = RootScopeAuthority(
    discover=True, metadata_read=True, content_read=True, text_search=True,
    git_observe=True, classify=True, index=True, relate=True, auto_admit=True,
)
NONE = RootScopeAuthority()


def scope(scope_id: str, root: Path, authority: RootScopeAuthority) -> RootScope:
    return RootScope(scope_id=scope_id, root=str(root), authority=authority)


class PolicyCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.top = Path(tmp.name).resolve()
        self.ws = self.top / "ws"
        (self.ws / "a" / "b" / "c").mkdir(parents=True)
        (self.ws / "other").mkdir()

    def policy(self, *scopes: RootScope) -> PathPolicy:
        registry = RootScopeRegistry()
        registry.add_scope(scope("top", self.top, FULL))
        for item in scopes:
            registry.add_scope(item)
        return PathPolicy.beneath(registry, self.ws)


class NestedScopesTests(PolicyCase):
    def test_only_scopes_strictly_inside_the_root_are_nested_and_most_specific_comes_first(self) -> None:
        registry = RootScopeRegistry()
        for item in (
            scope("top", self.top, FULL),
            scope("same", self.ws, FULL),
            scope("a", self.ws / "a", NONE),
            scope("abc", self.ws / "a" / "b" / "c", FULL),
            scope("sibling", self.top / "ws-sibling", NONE),
        ):
            registry.add_scope(item)
        nested = [(s.scope_id, root) for root, s in registry.nested_scopes(self.ws)]
        self.assertEqual(nested, [("abc", self.ws / "a" / "b" / "c"), ("a", self.ws / "a")])

    def test_a_root_with_no_nested_scopes_is_unrestricted(self) -> None:
        self.assertFalse(self.policy().restricted)
        self.assertTrue(PathPolicy.unrestricted().allows("read", self.ws / "a" / "x"))


class OperationMappingTests(PolicyCase):
    def check(self, flags: dict[str, bool], **expected: bool) -> None:
        policy = self.policy(scope("a", self.ws / "a", RootScopeAuthority(**flags)))
        target = self.ws / "a" / "b" / "file.txt"
        got = {op: policy.allows(op, target) for op in ("read", "search", "enumerate")}
        self.assertEqual(got, expected, flags)

    def test_each_operation_maps_to_its_authority_flags(self) -> None:
        self.check({}, read=False, search=False, enumerate=False)
        self.check({"metadata_read": True}, read=False, search=False, enumerate=True)
        self.check({"content_read": True}, read=True, search=False, enumerate=True)
        self.check({"content_read": True, "text_search": True}, read=True, search=True, enumerate=True)
        # Search returns lines of content: the search permission alone is not enough.
        self.check({"text_search": True}, read=False, search=False, enumerate=False)

    def test_a_path_outside_every_nested_zone_is_governed_by_the_admitting_scope(self) -> None:
        policy = self.policy(scope("a", self.ws / "a", NONE))
        for operation in ("read", "search", "enumerate"):
            self.assertTrue(policy.allows(operation, self.ws / "other" / "x.txt"))  # type: ignore[arg-type]


class MostSpecificWinsTests(PolicyCase):
    def test_a_more_specific_zone_overrides_its_parent_in_both_directions(self) -> None:
        policy = self.policy(
            scope("a", self.ws / "a", NONE),
            scope("abc", self.ws / "a" / "b" / "c", FULL),
        )
        self.assertFalse(policy.allows("read", self.ws / "a" / "x.txt"))
        self.assertFalse(policy.allows("read", self.ws / "a" / "b" / "x.txt"))
        self.assertTrue(policy.allows("read", self.ws / "a" / "b" / "c" / "x.txt"))

    def test_a_zone_root_is_governed_by_the_zone_itself(self) -> None:
        policy = self.policy(scope("a", self.ws / "a", NONE))
        self.assertFalse(policy.allows("enumerate", self.ws / "a"))

    def test_require_names_the_operation_and_the_governing_scope(self) -> None:
        policy = self.policy(scope("a", self.ws / "a", NONE))
        with self.assertRaises(ScopeAuthorityError) as caught:
            policy.require("search", self.ws / "other", self.ws / "a" / "b")
        self.assertEqual((caught.exception.operation, caught.exception.scope_id), ("search", "a"))
        self.assertIsInstance(caught.exception, PathPolicyError)

    def test_require_checks_every_candidate_path(self) -> None:
        policy = self.policy(scope("a", self.ws / "a", NONE))
        policy.require("read", self.ws / "other")
        with self.assertRaises(ScopeAuthorityError):
            policy.require("read", self.ws / "other", self.ws / "a")


class DescendTests(PolicyCase):
    def test_a_denied_directory_is_not_entered_unless_an_allowed_zone_lies_beneath(self) -> None:
        plain = self.policy(scope("a", self.ws / "a", NONE))
        self.assertFalse(plain.descends("search", self.ws / "a"))
        self.assertTrue(plain.descends("search", self.ws / "other"))

        with_hole = self.policy(scope("a", self.ws / "a", NONE), scope("abc", self.ws / "a" / "b" / "c", FULL))
        self.assertTrue(with_hole.descends("search", self.ws / "a"))
        self.assertTrue(with_hole.descends("search", self.ws / "a" / "b"))
        self.assertFalse(with_hole.descends("search", self.ws / "a" / "z"))  # no allowed zone beneath it
        # a hole that grants read but not search does not make a search walk enter
        # (the walk would find nothing it may return)
        read_only = self.policy(
            scope("a", self.ws / "a", NONE),
            scope("abc", self.ws / "a" / "b" / "c", RootScopeAuthority(content_read=True)),
        )
        self.assertFalse(read_only.descends("search", self.ws / "a"))
        self.assertTrue(read_only.descends("read", self.ws / "a"))


class ExcludedSubtreeTests(PolicyCase):
    def test_denied_zones_become_workspace_relative_excludes(self) -> None:
        policy = self.policy(scope("a", self.ws / "a", NONE), scope("o", self.ws / "other", FULL))
        self.assertEqual(policy.excluded_subtrees("read", self.ws), ["a"])

    def test_a_zone_nested_in_an_excluded_one_is_not_listed_twice_and_a_hole_stays_excluded(self) -> None:
        policy = self.policy(
            scope("a", self.ws / "a", NONE),
            scope("ab", self.ws / "a" / "b", NONE),
            scope("abc", self.ws / "a" / "b" / "c", FULL),
        )
        self.assertEqual(policy.excluded_subtrees("read", self.ws), ["a"])

    def test_the_operation_decides_what_is_excluded(self) -> None:
        policy = self.policy(scope("a", self.ws / "a", RootScopeAuthority(metadata_read=True)))
        self.assertEqual(policy.excluded_subtrees("read", self.ws), ["a"])
        self.assertEqual(policy.excluded_subtrees("enumerate", self.ws), [])


if __name__ == "__main__":
    unittest.main()
