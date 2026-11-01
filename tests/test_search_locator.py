"""A scope-search hit says where it can be read, and saying so grants nothing.

``uam_search_scope`` reports the scope-relative path of every file that contains a query, but the
file could only be read through a workspace, and nothing tied the two together: a hit in a plain
directory (or in a repository that was never registered) led nowhere. Each hit now carries a
``locator``: the derived workspace handle that contains it (the nearest Git repository inside the
scope, else the top-level directory, else the scope root) and the path inside that workspace.

The locator is a pointer, not a permission. Reading through it resolves the handle against live
authority like any other request, so a scope without ``directory_admit``, a revoked scope, a nested
scope that denies reading and a protected name all still refuse. These tests round-trip real
ripgrep hits through the real gateway and the MCP adapter, and then try to read what should stay
unreadable.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from typing import Any

from universal_agent_middleware.errors import PathPolicyError, ScopeAuthorityError, WorkspaceError
from universal_agent_middleware.root_scope import RootScope

from directory_fixtures import PLAIN, SCOPE_ID, WorldTestCase, authority, derived_id
from synthetic_fixtures import init_git_repo

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:
    create_session_read_server = None

GIT_KIND = "git-repository"
DIRECTORY_KIND = "filesystem-directory"


def hit_for(result: dict[str, Any], path: str) -> dict[str, Any]:
    matches = [hit for hit in result["results"] if hit["path"] == path]
    assert len(matches) == 1, f"expected exactly one hit for {path}, got {result['results']}"
    return matches[0]


class LocatorTestCase(WorldTestCase):
    def locate(self, gateway: Any, query: str, path: str) -> dict[str, str]:
        result = gateway.search_scope(SCOPE_ID, query)
        self.assertEqual(result["search_completeness"], "COMPLETE", result)
        return hit_for(result, path)["locator"]


class LocatorShapeTests(LocatorTestCase):
    def test_a_hit_in_a_plain_directory_locates_its_top_level_directory(self) -> None:
        locator = self.locate(self.world.gateway(), "needle-nested", f"{PLAIN}/notes/nested.md")
        self.assertEqual(locator, {
            "workspace_id": derived_id(PLAIN), "path": "notes/nested.md", "kind": DIRECTORY_KIND,
        })

    def test_a_hit_in_a_git_repository_locates_the_repository(self) -> None:
        locator = self.locate(self.world.gateway(), "needle-guide", "git-repo/docs/guide.md")
        self.assertEqual(locator, {
            "workspace_id": derived_id("git-repo"), "path": "docs/guide.md", "kind": GIT_KIND,
        })

    def test_a_hit_in_a_nested_repository_locates_the_nearest_repository(self) -> None:
        init_git_repo(self.world.data / "clients" / "acme" / "app", files={"src/main.py": "needle-deep\n"})
        locator = self.locate(self.world.gateway(), "needle-deep", "clients/acme/app/src/main.py")
        self.assertEqual(locator, {
            "workspace_id": derived_id("clients/acme/app"), "path": "src/main.py", "kind": GIT_KIND,
        })

    def test_a_scope_that_hides_its_metadata_does_not_reveal_a_git_entry_through_the_kind(self) -> None:
        hidden = self.world.data / "restricted"
        (hidden / ".git").mkdir()
        for overrides, expected_kind in (
            ({"metadata_read": False, "content_read": False}, DIRECTORY_KIND),
            ({"metadata_read": True, "content_read": False}, GIT_KIND),
            ({"metadata_read": False, "content_read": True}, GIT_KIND),
        ):
            with self.subTest(overrides=overrides):
                gateway = self.world.gateway()
                gateway.scopes.add_scope(RootScope(
                    scope_id="inner-scope", root=str(hidden), authority=authority(**overrides),
                ))
                locator = self.locate(gateway, "restricted content", "restricted/secret.txt")
                self.assertEqual(locator, {
                    "workspace_id": derived_id("restricted"), "path": "secret.txt", "kind": expected_kind,
                })

    def test_a_hit_directly_in_a_top_level_directory_locates_that_directory(self) -> None:
        locator = self.locate(self.world.gateway(), "needle-markdown", f"{PLAIN}/README.md")
        self.assertEqual(locator, {
            "workspace_id": derived_id(PLAIN), "path": "README.md", "kind": DIRECTORY_KIND,
        })

    def test_a_hit_in_a_repository_inside_a_repository_locates_the_inner_one(self) -> None:
        init_git_repo(self.world.repo / "libs" / "inner", files={"lib.py": "needle-inner\n"})
        locator = self.locate(self.world.gateway(), "needle-inner", "git-repo/libs/inner/lib.py")
        self.assertEqual(locator, {
            "workspace_id": derived_id("git-repo/libs/inner"), "path": "lib.py", "kind": GIT_KIND,
        })

    def test_a_repository_above_the_scope_root_is_never_named(self) -> None:
        # The default scope also covers the repository above ``docs-only``, so it is the bound at
        # the scope root, not a lack of authority over the repository, that keeps it out.
        gateway = self.world.gateway()
        gateway.scopes.add_scope(RootScope(
            scope_id="docs-only", root=str(self.world.repo / "docs"), authority=authority(),
        ))
        result = gateway.search_scope("docs-only", "needle-guide")
        locator = hit_for(result, "guide.md")["locator"]
        self.assertEqual(locator, {
            "workspace_id": "derived:docs-only:", "path": "guide.md", "kind": DIRECTORY_KIND,
        })
        self.assertIn("needle-guide", gateway.read_file(locator["workspace_id"], locator["path"])["content"])

    def test_a_scope_whose_root_is_a_symlink_locates_and_reads_its_hits(self) -> None:
        link = self.world.root / "scope-link"
        link.symlink_to(self.world.data, target_is_directory=True)
        gateway = self.world.gateway(scope=False)
        gateway.scopes.add_scope(RootScope(scope_id="link-scope", root=str(link), authority=authority()))
        result = gateway.search_scope("link-scope", "needle-nested")
        locator = hit_for(result, f"{PLAIN}/notes/nested.md")["locator"]
        self.assertEqual(locator, {
            "workspace_id": f"derived:link-scope:{PLAIN}", "path": "notes/nested.md", "kind": DIRECTORY_KIND,
        })
        self.assertNotIn(str(self.world.root), json.dumps(result))
        self.assertIn("needle-nested", gateway.read_file(locator["workspace_id"], locator["path"])["content"])

    def test_a_git_file_marks_a_checkout_like_a_git_directory(self) -> None:
        linked = self.world.data / "linked-checkout"
        linked.mkdir()
        (linked / ".git").write_text("gitdir: /nonexistent/elsewhere\n", encoding="utf-8")
        (linked / "readme.txt").write_text("needle-linked\n", encoding="utf-8")
        gateway = self.world.gateway()
        locator = self.locate(gateway, "needle-linked", "linked-checkout/readme.txt")
        self.assertEqual(locator["kind"], GIT_KIND)
        self.assertEqual(gateway.resolver.resolve(locator["workspace_id"]).spec.kind, GIT_KIND)

    def test_a_hit_directly_in_the_scope_root_locates_the_scope_root(self) -> None:
        (self.world.data / "top.txt").write_text("needle-top\n", encoding="utf-8")
        locator = self.locate(self.world.gateway(), "needle-top", "top.txt")
        self.assertEqual(locator, {
            "workspace_id": f"derived:{SCOPE_ID}:", "path": "top.txt", "kind": DIRECTORY_KIND,
        })

    def test_a_scope_that_is_itself_a_repository_locates_the_scope_root(self) -> None:
        gateway = self.world.gateway(scope=False)
        gateway.scopes.add_scope(RootScope(scope_id="repo-scope", root=str(self.world.repo), authority=authority()))
        result = gateway.search_scope("repo-scope", "needle-guide")
        self.assertEqual(hit_for(result, "docs/guide.md")["locator"], {
            "workspace_id": "derived:repo-scope:", "path": "docs/guide.md", "kind": GIT_KIND,
        })

    def test_the_locator_is_added_to_a_hit_that_keeps_its_other_fields(self) -> None:
        hit = hit_for(self.world.gateway().search_scope(SCOPE_ID, "needle-guide"), "git-repo/docs/guide.md")
        self.assertIs(hit["scope_relative"], True)
        self.assertEqual(set(hit["locator"]), {"workspace_id", "path", "kind"})

    def test_a_locator_names_no_host_path(self) -> None:
        result = self.world.gateway().search_scope(SCOPE_ID, "needle")
        self.assertTrue(result["results"])
        text = json.dumps(result)
        self.assertNotIn(str(self.world.root), text)
        for hit in result["results"]:
            locator = hit["locator"]
            self.assertTrue(locator["workspace_id"].startswith(f"derived:{SCOPE_ID}:"))
            self.assertFalse(locator["path"].startswith("/"))


class RoundTripTests(LocatorTestCase):
    def test_every_kind_of_hit_can_be_read_back_through_its_locator(self) -> None:
        init_git_repo(self.world.data / "clients" / "acme" / "app", files={"src/main.py": "needle-deep\n"})
        (self.world.data / "top.txt").write_text("needle-top\n", encoding="utf-8")
        gateway = self.world.gateway()
        cases = (
            ("needle-nested", f"{PLAIN}/notes/nested.md"),
            ("needle-guide", "git-repo/docs/guide.md"),
            ("needle-deep", "clients/acme/app/src/main.py"),
            ("needle-top", "top.txt"),
        )
        for query, path in cases:
            with self.subTest(path=path):
                locator = self.locate(gateway, query, path)
                content = gateway.read_file(locator["workspace_id"], locator["path"])["content"]
                self.assertIn(query, content)
                admitted = gateway.resolver.resolve(locator["workspace_id"]).spec
                self.assertEqual(admitted.kind, locator["kind"])

    def test_a_hit_can_also_be_digested_through_its_locator(self) -> None:
        gateway = self.world.gateway()
        for query, path in (("needle-nested", f"{PLAIN}/notes/nested.md"), ("needle-guide", "git-repo/docs/guide.md")):
            with self.subTest(path=path):
                locator = self.locate(gateway, query, path)
                digest = gateway.file_digest(locator["workspace_id"], locator["path"])
                self.assertIs(digest["complete"], True)
                self.assertEqual(len(digest["sha256"]), 64)

    def test_a_directory_hit_is_read_by_a_workspace_that_refuses_git(self) -> None:
        gateway = self.world.gateway()
        locator = self.locate(gateway, "needle-nested", f"{PLAIN}/notes/nested.md")
        with self.assertRaises(WorkspaceError) as caught:
            gateway.git_status(locator["workspace_id"])
        self.assertEqual(self.diagnostic_of(caught.exception)["status"], "UNSUPPORTED_CAPABILITY")

    def test_reading_through_a_locator_changes_nothing_in_the_target(self) -> None:
        gateway = self.world.gateway()
        before = self.world.target_fingerprint()
        locator = self.locate(gateway, "needle-nested", f"{PLAIN}/notes/nested.md")
        gateway.read_file(locator["workspace_id"], locator["path"])
        self.assertEqual(self.world.target_fingerprint(), before)
        self.assertFalse((self.world.plain / ".git").exists())


class LocatorGrantsNothingTests(LocatorTestCase):
    def test_a_scope_without_directory_admit_returns_the_locator_and_refuses_the_read(self) -> None:
        gateway = self.world.gateway(scope=self.world.scope(directory_admit=False))
        locator = self.locate(gateway, "needle-nested", f"{PLAIN}/notes/nested.md")
        with self.assertRaises(WorkspaceError) as caught:
            gateway.read_file(locator["workspace_id"], locator["path"])
        diagnostic = self.diagnostic_of(caught.exception)
        self.assertEqual((diagnostic["status"], diagnostic["directory_admission"]),
                         ("UNSUPPORTED_WORKSPACE_KIND", "NOT_ENABLED"))
        guide = self.locate(gateway, "needle-guide", "git-repo/docs/guide.md")
        self.assertIn("needle-guide", gateway.read_file(guide["workspace_id"], guide["path"])["content"])

    def test_revoking_the_scope_between_the_search_and_the_read_refuses_the_read(self) -> None:
        self.world.write_scope_file()
        gateway = self.world.gateway(scope=False)
        locator = self.locate(gateway, "needle-nested", f"{PLAIN}/notes/nested.md")
        self.assertIn("needle-nested", gateway.read_file(locator["workspace_id"], locator["path"])["content"])
        for revoked in ({"directory_admit": False}, {"content_read": False}):
            with self.subTest(revoked=revoked):
                self.world.write_scope_file(**revoked)
                with self.assertRaises(WorkspaceError):
                    gateway.read_file(locator["workspace_id"], locator["path"])
                self.world.write_scope_file()

    def test_a_hit_inside_a_nested_scope_that_denies_reading_stays_unreadable(self) -> None:
        gateway = self.world.gateway()
        gateway.scopes.add_scope(RootScope(
            scope_id="restricted-scope", root=str(self.world.data / "restricted"),
            authority=authority(content_read=False),
        ))
        locator = self.locate(gateway, "restricted content", "restricted/secret.txt")
        with self.assertRaises(WorkspaceError) as caught:
            gateway.read_file(locator["workspace_id"], locator["path"])
        self.assertIn("denies content_read", str(caught.exception))
        self.assertNotIn("restricted content", str(caught.exception))

    def test_a_hit_beneath_a_nested_scope_inside_a_directory_cannot_be_read_through_the_directory(self) -> None:
        gateway = self.world.gateway()
        gateway.scopes.add_scope(RootScope(
            scope_id="notes-scope", root=str(self.world.plain / "notes"), authority=authority(content_read=False),
        ))
        locator = self.locate(gateway, "needle-nested", f"{PLAIN}/notes/nested.md")
        self.assertEqual(locator["workspace_id"], derived_id(PLAIN))
        with self.assertRaises(WorkspaceError) as caught:
            gateway.read_file(locator["workspace_id"], locator["path"])
        self.assertIn("spans nested scope notes-scope", str(caught.exception))

    def test_a_hit_beneath_a_nested_scope_inside_a_repository_is_denied_by_path(self) -> None:
        gateway = self.world.gateway()
        gateway.scopes.add_scope(RootScope(
            scope_id="docs-scope", root=str(self.world.repo / "docs"), authority=authority(content_read=False),
        ))
        locator = self.locate(gateway, "needle-guide", "git-repo/docs/guide.md")
        self.assertEqual(locator["workspace_id"], derived_id("git-repo"))
        with self.assertRaises(ScopeAuthorityError) as caught:
            gateway.read_file(locator["workspace_id"], locator["path"])
        self.assertEqual((caught.exception.code, caught.exception.scope_id), ("SCOPE_AUTHORITY_DENIED", "docs-scope"))

    def test_a_protected_name_is_neither_a_hit_nor_readable(self) -> None:
        gateway = self.world.gateway()
        result = gateway.search_scope(SCOPE_ID, "do-not-leak")
        self.assertEqual(result["results"], [])
        locator = self.locate(gateway, "needle-markdown", f"{PLAIN}/README.md")
        for protected in (".env", ".ssh/config", "server.pem"):
            with self.subTest(path=protected):
                with self.assertRaises(PathPolicyError) as caught:
                    gateway.read_file(locator["workspace_id"], protected)
                self.assertNotIn("do-not-leak", str(caught.exception))

    def test_a_locator_does_not_open_a_path_outside_its_workspace(self) -> None:
        gateway = self.world.gateway()
        locator = self.locate(gateway, "needle-nested", f"{PLAIN}/notes/nested.md")
        for escape in ("../git-repo/README.md", "../../outside/secret.txt", "/etc/hosts"):
            with self.subTest(path=escape):
                with self.assertRaises(PathPolicyError):
                    gateway.read_file(locator["workspace_id"], escape)


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class McpRoundTripTests(LocatorTestCase):
    def call(self, name: str, **kwargs: Any) -> dict[str, Any]:
        server = create_session_read_server(str(self.world.registry_path), str(self.world.state))
        return json.loads(asyncio.run(server._tool_manager._tools[name].fn(ctx=None, **kwargs)))

    def test_the_tool_answer_leads_to_a_read_and_a_digest(self) -> None:
        self.world.write_scope_file()
        self.world.write_registry([])
        found = self.call("uam_search_scope", scope_id=SCOPE_ID, query="needle-nested")
        hit = hit_for(found, f"{PLAIN}/notes/nested.md")
        locator = hit["locator"]
        self.assertNotIn(str(self.world.root), json.dumps(found))
        read = self.call("uam_read_file", workspace_id=locator["workspace_id"], path=locator["path"])
        self.assertIn("needle-nested", read["content"])
        digest = self.call("uam_file_digest", workspace_id=locator["workspace_id"], path=locator["path"])
        self.assertIs(digest["complete"], True)

    def test_a_refused_read_through_a_locator_explains_itself(self) -> None:
        self.world.write_scope_file(directory_admit=False)
        self.world.write_registry([])
        found = self.call("uam_search_scope", scope_id=SCOPE_ID, query="needle-nested")
        locator = hit_for(found, f"{PLAIN}/notes/nested.md")["locator"]
        refused = self.call("uam_read_file", workspace_id=locator["workspace_id"], path=locator["path"])
        self.assertIn("error", refused)
        self.assertIsInstance(refused.get("diagnostic"), dict)
        self.assertNotIn(str(self.world.root), json.dumps(refused))
