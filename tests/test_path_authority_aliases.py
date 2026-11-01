"""A denial decided from a path has to survive every other name for that path.

``test_path_authority`` proves that a RootScope nested inside a derived workspace narrows it, per
final path. Two kinds of alias remained, and both are chosen by whoever supplies the path:

* **Spelling.** The default macOS volume is case-insensitive and Unicode-normalization-insensitive:
  ``Evidence/raw.txt`` is the file ``evidence/raw.txt`` there, so a scope that denies ``evidence``
  was bypassed by changing the case of the name. The same held for the fixed secret names
  (``.SSH``, ``.Git``, ``ID_RSA``). The decision is now made on the path as spelled AND as a
  case-insensitive filesystem sees it, and both readings must allow it.
* **Hard links.** A regular file with several names is the same bytes under every name, while
  authority is decided from a name. While a nested scope denies the operation, such a file is
  refused: its other name may lie inside that scope.

The spelling tests decide from the path alone (no existence check), so they hold on a
case-sensitive volume too, where ``Evidence`` simply does not exist.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unicodedata
import unittest
from pathlib import Path
from typing import Any

from universal_agent_middleware.errors import PathPolicyError, ScopeAuthorityError, WorkspaceError
from universal_agent_middleware.path_authority import PathPolicy
from universal_agent_middleware.policy import ensure_relative_path, fold_name, resolve_safe_path, should_hide_path
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry

from tests.test_path_authority import DENIED_CODE, DENY_ALL, FULL, READ_NOT_SEARCH, NestedScopeCase

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:
    create_session_read_server = None

RESPELLED = ("Evidence", "EVIDENCE", "eViDeNcE")
NFC_NAME = "r\u00e9sum\u00e9"
NFD_NAME = unicodedata.normalize("NFD", NFC_NAME)


class SpellingTests(NestedScopeCase):
    def test_every_operation_denies_a_scope_spelled_in_another_case(self) -> None:
        for spelling in RESPELLED:
            with self.subTest(spelling=spelling):
                # raw.txt exists on a case-insensitive volume, absent.txt on none: one answer for both
                for name in ("raw.txt", "absent.txt"):
                    self.assert_denied("read", "evidence", self.gw.read_file, self.ws, f"{spelling}/{name}")
                self.assert_denied("enumerate", "evidence", self.gw.tree, self.ws, spelling)
                self.assert_denied("search", "evidence", self.gw.search, self.ws, "needle", path=spelling)
                self.assert_denied("read", "evidence", self.gw.git_diff, self.ws, f"{spelling}/raw.txt")

    def test_a_respelled_name_inside_a_denied_scope_is_not_opened_by_a_scope_nested_in_it(self) -> None:
        """``sub`` grants reading inside the denied ``evidence``. A path that reaches ``sub`` only
        through another case is governed by ``evidence`` as spelled and by ``sub`` as folded: both
        must allow it, so it is refused, where the exact spelling is read."""
        self.write_scopes(("evidence", "evidence", DENY_ALL), ("sub", "evidence/sub", FULL))
        self.assertIn("needle-denied deep", self.gw.read_file(self.ws, "evidence/sub/deep.txt")["content"])
        for spelling in ("evidence/SUB/deep.txt", "evidence/Sub/deep.txt"):
            with self.subTest(spelling=spelling):
                self.assert_denied("read", "evidence", self.gw.read_file, self.ws, spelling)

    def test_a_respelled_name_inside_a_granting_scope_is_still_judged_by_the_denying_scope_nested_in_it(self) -> None:
        self.write_scopes(("evidence", "evidence", FULL), ("sub", "evidence/sub", DENY_ALL))
        self.assert_denied("read", "sub", self.gw.read_file, self.ws, "evidence/sub/deep.txt")
        for spelling in ("evidence/SUB/deep.txt", "evidence/Sub/deep.txt"):
            with self.subTest(spelling=spelling):
                self.assert_denied("read", "sub", self.gw.read_file, self.ws, spelling)

    def test_a_scope_that_grants_reading_but_not_searching_is_honoured_in_every_spelling(self) -> None:
        self.write_scopes(("evidence", "evidence", READ_NOT_SEARCH))
        self.assertIn("needle-denied", self.gw.read_file(self.ws, "evidence/raw.txt")["content"])
        for spelling in ("evidence", "Evidence", "EVIDENCE"):
            with self.subTest(spelling=spelling):
                self.assert_denied("search", "evidence", self.gw.search, self.ws, "needle", path=spelling)

    def test_unicode_normalization_variants_of_a_scope_name_are_denied(self) -> None:
        directory = self.repo / NFC_NAME
        directory.mkdir()
        (directory / "secret.txt").write_text("needle-denied accent\n", encoding="utf-8")
        self.write_scopes(("accent", NFC_NAME, DENY_ALL))
        for name in (NFC_NAME, NFD_NAME):
            with self.subTest(form=("NFC" if name == NFC_NAME else "NFD")):
                self.assert_denied("read", "accent", self.gw.read_file, self.ws, f"{name}/secret.txt")

    def test_names_that_merely_start_like_a_scope_are_not_inside_it(self) -> None:
        (self.repo / "evidence2").mkdir()
        (self.repo / "evidence2" / "ok.txt").write_text("needle-ordinary sibling\n", encoding="utf-8")
        self.assertIn("needle-ordinary", self.gw.read_file(self.ws, "evidence2/ok.txt")["content"])
        self.assertIn("needle-public", self.gw.read_file(self.ws, "README.md")["content"])

    def test_a_derived_workspace_rooted_at_a_denied_scope_in_another_case_is_refused(self) -> None:
        with self.assertRaises(WorkspaceError) as caught:
            self.gw.read_file("derived:code:proj/Evidence", "raw.txt")
        self.assertNotIn("needle-denied", str(caught.exception))
        if (self.repo / "Evidence").exists():  # a case-insensitive volume: it IS the denied scope
            self.assertEqual(caught.exception.__cause__.kind, "DENIED")


class RegistrySpellingTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.code = Path(tmp.name).resolve() / "code"
        self.registry = RootScopeRegistry()
        self.registry.add_scope(RootScope("code", str(self.code), RootScopeAuthority(**FULL)))
        self.registry.add_scope(RootScope("evidence", str(self.code / "proj" / "evidence"), RootScopeAuthority(**DENY_ALL)))

    def test_a_scope_denying_a_name_denies_it_in_every_spelling(self) -> None:
        for spelling in ("evidence", "Evidence", "EVIDENCE"):
            with self.subTest(spelling=spelling):
                path = self.code / "proj" / spelling / "raw.txt"
                self.assertFalse(self.registry.can_read(path))
                self.assertFalse(self.registry.can_search(path))
                authority = self.registry.effective_authority(path)
                self.assertIsNotNone(authority)
                self.assertFalse(authority.content_read)

    def test_where_the_readings_disagree_only_what_both_scopes_grant_is_granted(self) -> None:
        self.registry.add_scope(RootScope("sub", str(self.code / "proj" / "evidence" / "sub"), RootScopeAuthority(**FULL)))
        self.assertTrue(self.registry.can_read(self.code / "proj" / "evidence" / "sub" / "x.txt"))
        self.assertFalse(self.registry.can_read(self.code / "proj" / "evidence" / "SUB" / "x.txt"))

    def test_a_path_that_no_scope_covers_as_spelled_stays_uncovered(self) -> None:
        self.assertIsNone(self.registry.effective_authority(self.code.parent / "CODE" / "proj" / "x"))
        self.assertFalse(self.registry.can_read(self.code.parent / "CODE" / "proj" / "x"))

    def test_the_governing_scope_is_unchanged_where_spelling_does_not_matter(self) -> None:
        authority = self.registry.effective_authority(self.code / "proj" / "src" / "app.py")
        self.assertEqual(authority, RootScopeAuthority(**FULL))

    def test_a_nested_scope_is_found_through_a_workspace_root_spelled_differently(self) -> None:
        for spelling in ("proj", "Proj", "PROJ"):
            with self.subTest(spelling=spelling):
                nested = [scope.scope_id for _, scope in self.registry.nested_scopes(self.code / spelling)]
                self.assertEqual(nested, ["evidence"])

    def test_the_same_directory_spelled_differently_is_not_nested_in_itself(self) -> None:
        for spelling in ("evidence", "Evidence"):
            with self.subTest(spelling=spelling):
                self.assertEqual(self.registry.nested_scopes(self.code / "proj" / spelling), [])

    def test_authority_meet_grants_a_flag_only_when_both_grant_it(self) -> None:
        both = RootScopeAuthority(content_read=True, metadata_read=True).meet(RootScopeAuthority(content_read=True))
        self.assertEqual(both, RootScopeAuthority(content_read=True))

    def test_the_policy_decides_a_respelled_path_by_both_readings(self) -> None:
        self.registry.add_scope(RootScope("sub", str(self.code / "proj" / "evidence" / "sub"), RootScopeAuthority(**FULL)))
        policy = PathPolicy.beneath(self.registry, self.code / "proj")
        evidence = self.code / "proj" / "evidence"
        self.assertTrue(policy.allows("read", self.code / "proj" / "src" / "app.py"))
        self.assertFalse(policy.allows("read", evidence / "raw.txt"))
        self.assertFalse(policy.allows("read", self.code / "proj" / "Evidence" / "raw.txt"))
        self.assertTrue(policy.allows("read", evidence / "sub" / "x.txt"))
        self.assertFalse(policy.allows("read", evidence / "SUB" / "x.txt"))


class ExcludedSubtreeTests(unittest.TestCase):
    """The pathspec Git is given for a denied subtree is taken below the workspace root by components."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        self.real = self.base / "deep" / "er" / "real"
        (self.real / "proj" / "evidence").mkdir(parents=True)
        self.registry = RootScopeRegistry()
        self.registry.add_scope(RootScope("evidence", str(self.real / "proj" / "evidence"), RootScopeAuthority(**DENY_ALL)))
        self.policy = PathPolicy.beneath(self.registry, self.real / "proj")

    def test_the_denied_subtree_is_named_relative_to_the_workspace_root(self) -> None:
        self.assertEqual(self.policy.excluded_subtrees("read", self.real / "proj"), ["evidence"])

    def test_a_workspace_root_reached_through_a_link_gives_the_same_answer(self) -> None:
        link = self.base / "link"
        link.symlink_to(self.real)
        self.assertEqual(self.policy.excluded_subtrees("read", link / "proj"), ["evidence"])

    def test_a_workspace_root_spelled_in_another_case_gives_the_same_answer(self) -> None:
        policy = PathPolicy.beneath(self.registry, self.real / "PROJ")
        self.assertEqual(policy.excluded_subtrees("read", self.real / "PROJ"), ["evidence"])

    def test_a_zone_that_is_not_beneath_the_root_is_never_turned_into_a_pathspec(self) -> None:
        with self.assertRaises(ValueError):
            self.policy.excluded_subtrees("read", self.base / "elsewhere")
        with self.assertRaises(ValueError):  # a zone that IS the root would name the whole repository
            self.policy.excluded_subtrees("read", self.real / "proj" / "evidence")


@unittest.skipUnless(hasattr(os, "link"), "hard links are unavailable")
class HardLinkPolicyTests(unittest.TestCase):
    """What ``PathPolicy`` itself says about a path with other names."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve() / "proj"
        (self.root / "evidence").mkdir(parents=True)
        (self.root / "evidence" / "raw.txt").write_text("raw\n", encoding="utf-8")
        os.link(self.root / "evidence" / "raw.txt", self.root / "linked.txt")
        (self.root / "single.txt").write_text("one name\n", encoding="utf-8")
        registry = RootScopeRegistry()
        registry.add_scope(RootScope("evidence", str(self.root / "evidence"), RootScopeAuthority(**DENY_ALL)))
        self.denying = PathPolicy.beneath(registry, self.root)
        self.unrestricted = PathPolicy.unrestricted()

    def test_a_file_with_other_names_is_refused_while_a_nested_scope_denies(self) -> None:
        self.assertTrue(self.denying.has_other_names("read", self.root / "linked.txt"))
        with self.assertRaises(ScopeAuthorityError) as caught:
            self.denying.require_single_name("read", self.root / "linked.txt")
        self.assertEqual((caught.exception.scope_id, caught.exception.reason), ("evidence", "hard_linked_file"))

    def test_a_file_with_one_name_and_a_directory_are_not_refused(self) -> None:
        for path in (self.root / "single.txt", self.root / "evidence", self.root):
            with self.subTest(path=path.name):
                self.assertFalse(self.denying.has_other_names("read", path))
                self.denying.require_single_name("read", path)

    def test_without_a_denying_scope_nothing_is_refused(self) -> None:
        self.assertFalse(self.unrestricted.has_other_names("read", self.root / "linked.txt"))
        self.unrestricted.require_single_name("read", self.root / "linked.txt")

    def test_a_path_that_cannot_be_inspected_is_left_to_the_caller(self) -> None:
        missing = self.root / "missing.txt"
        self.assertFalse(self.denying.has_other_names("read", missing))
        self.denying.require_single_name("read", missing)


class FirewallSpellingTests(unittest.TestCase):
    """The fixed secret names, matched the way the filesystem compares names."""

    DENIED = (
        ".ssh", ".SSH", ".Ssh", ".Git", ".GIT", ".AWS", ".GnuPG", ".KUBE", ".Docker", ".NPMRC", ".PyPiRC",
        ".NETRC", "ID_RSA", "Id_Ed25519", "Credentials", "CREDENTIALS.JSON", "Secrets.json",
        ".\u212aube",  # the Kelvin sign folds to "k": a name the volume may compare equal to ".kube"
    )
    ALLOWED = ("docs", "credential-model.md", "ssh_notes.md", "keys.md", "dotgit", "envelope.txt")

    def test_a_denied_name_is_refused_in_every_spelling(self) -> None:
        for name in self.DENIED:
            with self.subTest(name=name):
                with self.assertRaises(PathPolicyError):
                    ensure_relative_path(f"a/{name}/b")

    def test_names_that_merely_resemble_a_secret_stay_readable(self) -> None:
        for name in self.ALLOWED:
            with self.subTest(name=name):
                self.assertEqual(ensure_relative_path(f"a/{name}").name, name)

    def test_the_spellings_are_hidden_from_listings_and_refused_when_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for name in (".SSH", ".Git", "ID_RSA"):
                with self.subTest(name=name):
                    self.assertTrue(should_hide_path(root, root / name / "config"))
                    with self.assertRaises(PathPolicyError):
                        resolve_safe_path(root, f"{name}/config", must_exist=False)

    def test_folding_is_idempotent_and_decomposes(self) -> None:
        self.assertEqual(fold_name(fold_name("Ab\u00c9")), fold_name("Ab\u00c9"))
        self.assertEqual(fold_name(NFC_NAME), fold_name(NFD_NAME))


class FirewallThroughTheGatewayTests(NestedScopeCase):
    def test_a_respelled_git_directory_is_never_read(self) -> None:
        for spelling in (".GIT/config", ".Git/HEAD"):
            with self.subTest(spelling=spelling):
                with self.assertRaises(PathPolicyError):
                    self.gw.read_file(self.ws, spelling)

    @unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
    def test_the_mcp_guard_names_the_git_rule_for_every_spelling(self) -> None:
        server = create_session_read_server(str(self.registry_path), self.state_dir)
        tool = server._tool_manager._tools["uam_read_file"].fn
        for spelling in (".git/config", ".GIT/config", ".Git"):
            with self.subTest(spelling=spelling):
                payload: dict[str, Any] = json.loads(asyncio.run(tool(ctx=None, workspace_id=self.ws, path=spelling)))
                self.assertEqual(payload["error"], "direct .git/ reads are denied; use git observation tools")


@unittest.skipUnless(hasattr(os, "link"), "hard links are unavailable")
class HardLinkTests(NestedScopeCase):
    def setUp(self) -> None:
        super().setUp()
        os.link(self.repo / "evidence" / "raw.txt", self.repo / "src" / "hlink.txt")

    def test_a_hard_link_to_a_denied_file_is_not_a_way_around_the_denial(self) -> None:
        with self.assertRaises(ScopeAuthorityError) as caught:
            self.gw.read_file(self.ws, "src/hlink.txt")
        self.assertEqual((caught.exception.code, caught.exception.scope_id, caught.exception.reason),
                         (DENIED_CODE, "evidence", "hard_linked_file"))
        self.assertIn("reason=hard_linked_file", str(caught.exception))
        self.assertNotIn("needle-denied", str(caught.exception))

    def test_a_search_does_not_return_what_a_hard_link_exposes(self) -> None:
        found = self.gw.search(self.ws, "needle-denied")
        self.assertEqual(found["results"], [])
        self.assertIs(found["excluded_by_scope_authority"], True)
        self.assertEqual(found["search_completeness"], "PARTIAL")

    def test_a_path_scoped_git_diff_refuses_a_hard_link(self) -> None:
        with self.assertRaises(ScopeAuthorityError) as caught:
            self.gw.git_diff(self.ws, "src/hlink.txt")
        self.assertEqual(caught.exception.reason, "hard_linked_file")

    def test_a_file_with_one_name_is_unaffected(self) -> None:
        self.assertIn("needle_public", self.gw.read_file(self.ws, "src/app.py")["content"])
        self.assertTrue(self.gw.search(self.ws, "needle_public")["results"])

    def test_without_a_denying_nested_scope_a_hard_linked_file_is_readable(self) -> None:
        self.write_scopes()
        self.assertIn("needle-denied", self.gw.read_file(self.ws, "src/hlink.txt")["content"])
        found = self.gw.search(self.ws, "needle-denied")
        self.assertIn("src/hlink.txt", {hit["path"] for hit in found["results"]})
        self.assertNotIn("excluded_by_scope_authority", found)

    def test_a_scope_that_grants_reading_but_not_searching_refuses_only_the_search(self) -> None:
        self.write_scopes(("evidence", "evidence", READ_NOT_SEARCH))
        self.assertIn("needle-denied", self.gw.read_file(self.ws, "src/hlink.txt")["content"])
        found = self.gw.search(self.ws, "needle-denied")
        self.assertEqual(found["results"], [])
        self.assertIs(found["excluded_by_scope_authority"], True)

    def test_the_refusal_follows_the_live_policy(self) -> None:
        self.write_scopes()
        self.gw.read_file(self.ws, "src/hlink.txt")
        self.write_scopes(("evidence", "evidence", DENY_ALL))
        with self.assertRaises(ScopeAuthorityError):
            self.gw.read_file(self.ws, "src/hlink.txt")

    def test_a_directory_is_not_a_hard_linked_file(self) -> None:
        """Directories report several links by themselves; only regular files are judged by them."""
        listing = self.gw.tree(self.ws, "src")
        self.assertIn("src/app.py", [entry["path"] for entry in listing["entries"]])
        self.assertTrue(self.gw.search(self.ws, "needle_public", path="src")["results"])
        self.assertIn("diff", self.gw.git_diff(self.ws, "src"))


if __name__ == "__main__":
    unittest.main()
