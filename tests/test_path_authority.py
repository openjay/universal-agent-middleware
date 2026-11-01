"""A RootScope nested inside a derived workspace narrows what the workspace tools may touch.

Admission verifies the authority of the workspace ROOT only. Before the path guard existed, a
parent Git workspace that was readable made everything beneath it readable, enumerable and
searchable, including where a more specific RootScope (an evidence or preservation directory)
had ``content_read=false`` and ``text_search=false``. The scope-level search already honours that
nested denial ("most specific scope wins"), so the workspace tools must agree with it.

These tests drive the real gateway with a real Git repository and a live scope file. Nothing is
mocked: the point is what an MCP client would actually be able to read.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from universal_agent_middleware import workspace as workspace_module
from universal_agent_middleware.errors import PathPolicyError, ScopeAuthorityError
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.root_scope import RootScopeAuthority

from tests.synthetic_fixtures import init_git_repo, write_workspace_registry

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:
    create_session_read_server = None

PARENT = dict(
    discover=True, metadata_read=True, content_read=True, text_search=True,
    git_observe=True, classify=True, index=True, relate=True, auto_admit=True,
)
DENY_ALL: dict[str, bool] = {}
LIST_ONLY = {"metadata_read": True}
READ_NOT_SEARCH = {"metadata_read": True, "content_read": True}
FULL = dict(PARENT)

DENIED_CODE = "SCOPE_AUTHORITY_DENIED"


class NestedScopeCase(unittest.TestCase):
    """A readable parent Git project containing an ``evidence`` directory with its own scope."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        state = tempfile.TemporaryDirectory(prefix="uam-pathauth-state-")
        self.addCleanup(tmp.cleanup)
        self.addCleanup(state.cleanup)
        base = Path(tmp.name).resolve()
        self.code = base / "code"
        self.repo = self.code / "proj"
        init_git_repo(self.repo, files={
            "README.md": "# proj\nneedle-public readme\n",
            "src/app.py": "needle_public = 1\n",
            "evidence/raw.txt": "needle-denied raw\n",
            "evidence/sub/deep.txt": "needle-denied deep\n",
        })
        # Uncommitted work, so Git observations have something to say about every region.
        (self.repo / "src" / "app.py").write_text("needle_public = 2\n", encoding="utf-8")
        (self.repo / "evidence" / "raw.txt").write_text("needle-denied changed\n", encoding="utf-8")
        (self.repo / "evidence" / "new.txt").write_text("needle-denied untracked\n", encoding="utf-8")
        self.config = base / "config"
        self.state_dir = state.name
        self.registry_path = write_workspace_registry(self.config / "workspaces.json", [])
        self.write_scopes(("evidence", "evidence", DENY_ALL))
        self.gw = MiddlewareGateway(str(self.registry_path), self.state_dir)
        self.ws = "derived:code:proj"

    def write_scopes(self, *nested: tuple[str, str, dict[str, bool]]) -> None:
        """Rewrite the live scope file: the parent scope plus scopes nested under ``proj``."""
        scopes: list[dict[str, Any]] = [
            {"scope_id": "code", "root": str(self.code), "authority": RootScopeAuthority(**PARENT).to_dict()},
        ]
        for scope_id, rel, flags in nested:
            scopes.append({
                "scope_id": scope_id,
                "root": str(self.repo / rel),
                "authority": RootScopeAuthority(**flags).to_dict(),
            })
        (self.config / "root_scopes.json").write_text(
            json.dumps({"schema_version": "root-scope-registry-v1", "scopes": scopes}), encoding="utf-8",
        )

    def assert_denied(self, operation: str, scope_id: str, call, *args: Any, **kwargs: Any) -> None:
        with self.assertRaises(ScopeAuthorityError) as caught:
            call(*args, **kwargs)
        self.assertEqual(caught.exception.code, DENIED_CODE)
        self.assertEqual((caught.exception.operation, caught.exception.scope_id), (operation, scope_id))


class ReadTests(NestedScopeCase):
    def test_a_denied_nested_scope_cannot_be_read_even_when_the_file_is_absent(self) -> None:
        for rel in ("evidence/raw.txt", "evidence/sub/deep.txt", "evidence/not-there.txt"):
            with self.subTest(path=rel):
                self.assert_denied("read", "evidence", self.gw.read_file, self.ws, rel)

    def test_the_parent_stays_readable(self) -> None:
        self.assertIn("needle-public", self.gw.read_file(self.ws, "README.md")["content"])

    def test_a_scope_that_grants_reading_is_readable(self) -> None:
        self.write_scopes(("evidence", "evidence", READ_NOT_SEARCH))
        self.assertIn("needle-denied", self.gw.read_file(self.ws, "evidence/raw.txt")["content"])

    def test_metadata_only_is_not_content_access(self) -> None:
        self.write_scopes(("evidence", "evidence", LIST_ONLY))
        self.assert_denied("read", "evidence", self.gw.read_file, self.ws, "evidence/raw.txt")

    def test_the_absolute_path_selector_is_guarded_like_the_derived_handle(self) -> None:
        self.assert_denied("read", "evidence", self.gw.read_file, str(self.repo), "evidence/raw.txt")

    def test_a_denial_is_audited_without_the_file_content(self) -> None:
        with self.assertRaises(ScopeAuthorityError):
            self.gw.read_file(self.ws, "evidence/raw.txt")
        rows = [json.loads(line) for line in self.gw.audit.path.read_text().splitlines()]
        last = rows[-1]
        self.assertEqual((last["action"], last["outcome"]), ("read_file", "DENIED"))
        self.assertEqual(last["details"]["code"], DENIED_CODE)
        self.assertEqual(last["details"]["scope_id"], "evidence")
        self.assertNotIn("needle-denied", json.dumps(last))
        self.assertTrue(self.gw.audit.verify()["valid"])


class EnumerationTests(NestedScopeCase):
    def test_the_listing_hides_a_denied_scope_and_says_it_is_filtered(self) -> None:
        listing = self.gw.tree(self.ws, ".", depth=4)
        paths = [entry["path"] for entry in listing["entries"]]
        self.assertIn("src/app.py", paths)
        self.assertEqual([p for p in paths if p.split("/")[0] == "evidence"], [])
        self.assertIs(listing["excluded_by_scope_authority"], True)

    def test_a_denied_directory_cannot_be_listed_directly(self) -> None:
        self.assert_denied("enumerate", "evidence", self.gw.tree, self.ws, "evidence")

    def test_a_metadata_only_scope_is_listed_by_name(self) -> None:
        self.write_scopes(("evidence", "evidence", LIST_ONLY))
        listing = self.gw.tree(self.ws, ".", depth=4)
        self.assertIn("evidence/raw.txt", [entry["path"] for entry in listing["entries"]])
        self.assertNotIn("excluded_by_scope_authority", listing)

    def test_without_nested_scopes_the_listing_is_unchanged(self) -> None:
        self.write_scopes()
        listing = self.gw.tree(self.ws, ".", depth=4)
        self.assertIn("evidence/raw.txt", [entry["path"] for entry in listing["entries"]])
        self.assertNotIn("excluded_by_scope_authority", listing)


class SearchTests(NestedScopeCase):
    def test_search_skips_a_denied_scope_and_never_claims_absence(self) -> None:
        found = self.gw.search(self.ws, "needle")
        self.assertEqual({hit["path"] for hit in found["results"]}, {"README.md", "src/app.py"})
        self.assertEqual(found["files_scanned"], 2)  # a denied file is not even counted
        self.assertEqual(found["search_completeness"], "PARTIAL")
        self.assertIs(found["excluded_by_scope_authority"], True)

        absent = self.gw.search(self.ws, "needle-denied")
        self.assertEqual(absent["results"], [])
        self.assertIs(absent["safe_to_conclude_absent"], False)  # unexamined is not absent

    def test_a_denied_directory_cannot_be_searched_directly(self) -> None:
        self.assert_denied("search", "evidence", self.gw.search, self.ws, "needle", path="evidence")

    def test_readable_but_not_searchable_is_honoured(self) -> None:
        self.write_scopes(("evidence", "evidence", READ_NOT_SEARCH))
        found = self.gw.search(self.ws, "needle-denied")
        self.assertEqual(found["results"], [])
        self.assertIs(found["excluded_by_scope_authority"], True)

    def test_without_nested_scopes_search_is_unchanged(self) -> None:
        self.write_scopes()
        found = self.gw.search(self.ws, "needle-denied")
        self.assertEqual({hit["path"] for hit in found["results"]},
                         {"evidence/raw.txt", "evidence/new.txt", "evidence/sub/deep.txt"})
        self.assertEqual(found["search_completeness"], "COMPLETE")
        self.assertNotIn("excluded_by_scope_authority", found)
        self.assertIs(self.gw.search(self.ws, "no-such-token")["safe_to_conclude_absent"], True)


class SymlinkTests(NestedScopeCase):
    def test_an_alias_to_a_denied_file_is_denied_by_its_real_location(self) -> None:
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "alias.txt").symlink_to("../evidence/raw.txt")
        self.assert_denied("read", "evidence", self.gw.read_file, self.ws, "docs/alias.txt")

    def test_an_alias_to_a_denied_directory_cannot_be_listed_or_searched(self) -> None:
        (self.repo / "viewer").symlink_to("evidence")
        self.assert_denied("enumerate", "evidence", self.gw.tree, self.ws, "viewer")
        self.assert_denied("search", "evidence", self.gw.search, self.ws, "needle", path="viewer")

    def test_a_link_inside_a_denied_scope_is_denied_by_where_it_sits(self) -> None:
        (self.repo / "evidence" / "alias.txt").symlink_to("../README.md")
        self.assert_denied("read", "evidence", self.gw.read_file, self.ws, "evidence/alias.txt")

    def test_a_link_out_of_the_workspace_is_still_rejected_by_confinement(self) -> None:
        outside = self.code / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        (self.repo / "escape.txt").symlink_to(outside)
        with self.assertRaises(PathPolicyError) as caught:
            self.gw.read_file(self.ws, "escape.txt")
        self.assertNotIsInstance(caught.exception, ScopeAuthorityError)


class WalkPruningTests(NestedScopeCase):
    """A denied directory is not walked at all: no cost for what cannot be returned, and no
    traversal of a tree the caller is not allowed to see."""

    # S1 seam migration: the Reader no longer uses ``os.walk`` (it walks descriptors, see ``descriptor_io``), so
    # "which directories were entered" is observed where the Reader lists a directory, by the identity
    # (device, inode) of the directory that was listed. The contract under test is unchanged.
    def evidence_directories(self) -> set[tuple[int, int]]:
        identities = set()
        for current, _dirs, _files in os.walk(self.repo / "evidence"):
            info = os.stat(current)
            identities.add((info.st_dev, info.st_ino))
        return identities

    def listed(self, call) -> list[tuple[int, int]]:
        entered: list[tuple[int, int]] = []
        real_list_directory = workspace_module.list_directory

        def recording(dir_fd):
            info = os.fstat(dir_fd)
            entered.append((info.st_dev, info.st_ino))
            return real_list_directory(dir_fd)

        with mock.patch.object(workspace_module, "list_directory", recording):
            call()
        return entered

    def test_listing_and_search_do_not_walk_into_a_denied_directory(self) -> None:
        denied = self.evidence_directories()
        for name, call in (
            ("tree", lambda: self.gw.tree(self.ws, ".", depth=4)),
            ("search", lambda: self.gw.search(self.ws, "needle")),
        ):
            with self.subTest(tool=name):
                entered = self.listed(call)
                self.assertTrue(entered)
                self.assertEqual([identity for identity in entered if identity in denied], [])

    def test_without_nested_scopes_the_same_walk_does_enter_it(self) -> None:
        self.write_scopes()
        denied = self.evidence_directories()
        entered = self.listed(lambda: self.gw.tree(self.ws, ".", depth=4))
        self.assertTrue([identity for identity in entered if identity in denied])


class FixedSecretNameTests(NestedScopeCase):
    def test_fixed_secret_names_stay_denied_in_an_allowed_region(self) -> None:
        (self.repo / "src" / ".env").write_text("TOKEN=not-a-real-secret\n", encoding="utf-8")
        with self.assertRaises(PathPolicyError) as caught:
            self.gw.read_file(self.ws, "src/.env")
        self.assertNotIsInstance(caught.exception, ScopeAuthorityError)


class RevocationTests(NestedScopeCase):
    def test_revocation_and_regrant_apply_to_the_next_call(self) -> None:
        self.write_scopes(("evidence", "evidence", FULL))
        self.assertIn("needle-denied", self.gw.read_file(self.ws, "evidence/raw.txt")["content"])

        self.write_scopes(("evidence", "evidence", DENY_ALL))
        self.assert_denied("read", "evidence", self.gw.read_file, self.ws, "evidence/raw.txt")

        self.write_scopes()  # the nested scope is gone: the parent governs again
        self.assertIn("needle-denied", self.gw.read_file(self.ws, "evidence/raw.txt")["content"])


class NestedHoleTests(NestedScopeCase):
    """An allowed scope inside a denied one: the most specific scope wins, for reading by path."""

    def setUp(self) -> None:
        super().setUp()
        self.write_scopes(("evidence", "evidence", DENY_ALL), ("sub", "evidence/sub", FULL))

    def test_the_hole_is_readable_and_its_denied_parent_is_not(self) -> None:
        self.assertIn("needle-denied deep", self.gw.read_file(self.ws, "evidence/sub/deep.txt")["content"])
        self.assert_denied("read", "evidence", self.gw.read_file, self.ws, "evidence/raw.txt")

    def test_enumeration_and_search_reach_the_hole_but_not_its_denied_parent(self) -> None:
        paths = [entry["path"] for entry in self.gw.tree(self.ws, ".", depth=5)["entries"]]
        self.assertIn("evidence/sub/deep.txt", paths)
        self.assertNotIn("evidence/raw.txt", paths)
        self.assertNotIn("evidence", paths)
        hits = {hit["path"] for hit in self.gw.search(self.ws, "needle-denied")["results"]}
        self.assertEqual(hits, {"evidence/sub/deep.txt"})

    def test_git_observation_cannot_express_a_hole_so_it_excludes_the_whole_denied_subtree(self) -> None:
        self.assertNotIn("evidence", self.gw.git_diff(self.ws)["diff"])
        self.assertNotIn("evidence", self.gw.git_status(self.ws)["status"])


class GitObservationTests(NestedScopeCase):
    def test_diff_leaves_out_a_denied_subtree(self) -> None:
        diff = self.gw.git_diff(self.ws)["diff"]
        self.assertIn("src/app.py", diff)
        self.assertNotIn("evidence", diff)
        self.assertNotIn("needle-denied", diff)

    def test_diff_of_a_denied_path_is_denied(self) -> None:
        self.assert_denied("read", "evidence", self.gw.git_diff, self.ws, "evidence/raw.txt")

    def test_diff_of_a_denied_path_is_denied_even_when_it_does_not_exist(self) -> None:
        self.assert_denied("read", "evidence", self.gw.git_diff, self.ws, "evidence/not-there.txt")

    def test_diff_of_an_alias_of_a_denied_file_is_denied(self) -> None:
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "alias.txt").symlink_to("../evidence/raw.txt")
        self.assert_denied("read", "evidence", self.gw.git_diff, self.ws, "docs/alias.txt")

    def test_status_does_not_name_paths_in_a_denied_subtree(self) -> None:
        status = self.gw.git_status(self.ws)["status"]
        self.assertIn("src/app.py", status)
        self.assertNotIn("evidence", status)

    def test_a_metadata_scope_may_be_named_in_status_but_its_content_stays_out_of_diff(self) -> None:
        self.write_scopes(("evidence", "evidence", LIST_ONLY))
        self.assertIn("evidence", self.gw.git_status(self.ws)["status"])
        diff = self.gw.git_diff(self.ws)["diff"]
        self.assertNotIn("evidence", diff)
        self.assertNotIn("needle-denied", diff)

    def test_excludes_are_literal_for_a_denied_directory_with_glob_characters(self) -> None:
        # Read as a glob, "case[1]" would also match the unrelated, allowed file "case1" and hide it.
        (self.repo / "case[1]").mkdir()
        (self.repo / "case[1]" / "x.txt").write_text("needle-denied glob\n", encoding="utf-8")
        (self.repo / "case1").write_text("needle-public\n", encoding="utf-8")
        self.write_scopes(("evidence", "evidence", DENY_ALL), ("odd", "case[1]", DENY_ALL))
        lines = self.gw.git_status(self.ws)["status"].splitlines()
        self.assertNotIn("?? case[1]/", lines)
        self.assertIn("?? case1", lines)

    def test_without_nested_scopes_git_observation_is_unchanged(self) -> None:
        self.write_scopes()
        self.assertIn("needle-denied changed", self.gw.git_diff(self.ws)["diff"])
        self.assertIn("evidence", self.gw.git_status(self.ws)["status"])


class StaticRegistrationTests(NestedScopeCase):
    def test_a_static_registration_keeps_its_own_independent_contract(self) -> None:
        """Pins current behaviour; it is a declared compatibility boundary, not an endorsement.

        A static registration is a separately authorized contract. Making it honour nested scope
        denials would be an authorization-semantics change for existing deployments, so it needs an
        explicitly designed compatibility policy (recorded in the CHANGELOG as an owner decision).
        The same files stay guarded when addressed through a derived handle.
        """
        write_workspace_registry(self.config / "workspaces.json", [{
            "workspace_id": "proj-static", "root": str(self.repo), "kind": "git-repository",
            "capabilities": ["filesystem.read", "git.observe"],
        }])
        gw = MiddlewareGateway(str(self.registry_path), self.state_dir)
        self.assertIn("needle-denied", gw.read_file("proj-static", "evidence/raw.txt")["content"])
        self.assert_denied("read", "evidence", gw.read_file, self.ws, "evidence/raw.txt")


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class McpSurfaceTests(NestedScopeCase):
    def call(self, name: str, **kwargs: Any) -> dict[str, Any]:
        server = create_session_read_server(str(self.registry_path), self.state_dir)
        tool = server._tool_manager._tools[name].fn
        return json.loads(asyncio.run(tool(ctx=None, **kwargs)))

    def test_a_denied_read_is_a_machine_readable_error(self) -> None:
        payload = self.call("uam_read_file", workspace_id=self.ws, path="evidence/raw.txt")
        self.assertEqual(payload["error_code"], DENIED_CODE)
        self.assertNotIn("needle-denied", json.dumps(payload))

    def test_other_errors_carry_no_authority_code(self) -> None:
        payload = self.call("uam_read_file", workspace_id=self.ws, path="src")  # a directory
        self.assertIn("error", payload)
        self.assertNotIn("error_code", payload)

    def test_a_denied_search_and_listing_are_machine_readable_errors(self) -> None:
        listing = self.call("uam_tree", workspace_id=self.ws, path="evidence")
        search = self.call("uam_search_text", workspace_id=self.ws, query="needle", path="evidence")
        self.assertEqual((listing["error_code"], search["error_code"]), (DENIED_CODE, DENIED_CODE))


if __name__ == "__main__":
    unittest.main()
