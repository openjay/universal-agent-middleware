"""A reality index that cannot be trusted or read costs a listing one scope, never the listing.

``list_workspaces`` serves the index without waiting for a scan. Two ways the index can fail were not
covered, and both reached a consumer as the wrong answer:

* an index whose on-disk schema is newer than this release supports was refused by ``check_integrity``
  (``INCOMPATIBLE``) while the snapshot read path went on serving its rows, so the same listing said
  ``fresh``;
* an index that stayed locked past the retry budget raised ``IndexLockedError``, which the snapshot
  read path did not catch, so the whole listing failed, registered workspaces included.

The contract pinned here: every read path of the index answers "nothing indexed" when the index cannot
vouch for anything, a listing names the scope it could not read instead of failing, the registered
view never depends on the index, and a listing starts no scan whatever state the index is in.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from universal_agent_middleware import reality_index
from universal_agent_middleware.discovery import DiscoveryEngine
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.reality_index import RealityIndex

from tests.synthetic_fixtures import write_workspace_registry
from tests.test_list_workspaces_freshness import PAST_THE_LIMIT_SEC, ListedFreshnessCase

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:
    create_session_read_server = None

NEWER_SCHEMA = reality_index.SCHEMA_VERSION + 1
LOCK_MESSAGE = "database is locked"
SNAPSHOT = {"projects": [], "total_projects": 0, "total_repositories": 0}
POLICY = "policy-generation-under-test"


def set_schema_version(db_path: Path, version: int) -> None:
    """What a newer release does to the index file; the file stays otherwise readable."""
    with contextlib.closing(sqlite3.connect(db_path)) as conn, conn:
        conn.execute(
            "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', ?)",
            (str(version),),
        )


@contextlib.contextmanager
def index_locked_beyond_the_retry_budget():
    """Every connection attempt fails with 'database is locked'; the retries run without sleeping."""
    with mock.patch.object(reality_index.sqlite3, "connect",
                           side_effect=sqlite3.OperationalError(LOCK_MESSAGE)), \
            mock.patch.object(reality_index, "_retry_delay", return_value=0.0):
        yield


class SnapshotReadTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="uam-index-read-")
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "state"
        self.index = RealityIndex(self.state)
        self.index.write_snapshot("scope-a", SNAPSHOT, POLICY)

    def read(self, index: RealityIndex | None = None):
        return (index or self.index).get_active_snapshot("scope-a", POLICY, allow_stale=True)

    def test_a_compatible_index_serves_its_active_snapshot(self):
        snapshot = self.read()

        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot["freshness"]["source"], "reality_index")
        self.assertEqual(self.index.check_integrity()["status"], "OK")

    def test_a_newer_schema_is_not_served_as_a_snapshot(self):
        set_schema_version(self.index.db_path, NEWER_SCHEMA)
        reopened = RealityIndex(self.state)

        self.assertEqual(reopened.check_integrity()["status"], "INCOMPATIBLE")
        self.assertIsNone(self.read(reopened))

    def test_a_schema_bump_after_the_instance_opened_is_noticed_on_the_next_read(self):
        self.assertIsNotNone(self.read())
        set_schema_version(self.index.db_path, NEWER_SCHEMA)

        self.assertIsNone(self.read())
        self.assertTrue(self.index.schema_incompatible)
        self.assertEqual(self.index.check_integrity()["status"], "INCOMPATIBLE")

    def test_an_index_already_known_to_be_incompatible_is_not_opened_again(self):
        set_schema_version(self.index.db_path, NEWER_SCHEMA)
        self.assertIsNone(self.read(), "the first read after the bump notices it")

        with mock.patch.object(reality_index.sqlite3, "connect",
                               side_effect=AssertionError("the incompatible index was opened again")):
            self.assertIsNone(self.read())

    def test_lock_retry_exhaustion_is_a_miss_never_an_exception_or_corruption(self):
        with index_locked_beyond_the_retry_budget():
            self.assertIsNone(self.read())

        self.assertFalse(self.index.is_corrupt)
        self.assertIsNotNone(self.read(), "the snapshot is still there once the lock is gone")


class ListingIsolationTests(ListedFreshnessCase):
    def audit_details(self, result: dict) -> dict:
        rows = [json.loads(line) for line in self.gw.audit.path.read_text().splitlines()]
        return next(item for item in rows if item.get("request_id") == result["request_id"])["details"]

    def register_pinned_workspace(self) -> None:
        write_workspace_registry(self.registry_path, [{
            "workspace_id": "pinned",
            "root": str(self.roots["indexed"] / "fast-repo"),
            "kind": "git-repository",
            "capabilities": ["filesystem.read", "git.observe"],
        }])
        self.gw = MiddlewareGateway(str(self.registry_path), self._state.name)
        self.gw.index_scope("indexed")

    @staticmethod
    def registered_ids(result: dict) -> list[str]:
        return [entry["workspace_id"] for entry in result["registered"]]

    def test_an_index_with_a_newer_schema_never_reads_as_fresh(self):
        self.register_pinned_workspace()
        set_schema_version(self.gw.reality_index.db_path, NEWER_SCHEMA)
        self.gw = MiddlewareGateway(str(self.registry_path), self._state.name)

        result = self.gw.list_workspaces(view="all")

        scope = self.discovery_scope(result, "indexed")
        self.assertEqual(scope["status"], "unavailable")
        self.assertIn("schema", scope["reason"])
        self.assertEqual(result["discovered"], [])
        self.assertEqual(result["discovery"]["status"], "incomplete")
        self.assertEqual(self.registered_ids(result), ["pinned"])
        self.assertEqual(self.audit_details(result)["unavailable_scopes"], ["indexed"])

    def test_a_schema_bump_under_a_running_gateway_is_noticed_by_the_next_listing(self):
        self.register_pinned_workspace()
        self.assertEqual(self.discovery_scope(self.gw.list_workspaces(), "indexed")["status"], "fresh")
        set_schema_version(self.gw.reality_index.db_path, NEWER_SCHEMA)

        result = self.gw.list_workspaces()

        self.assertEqual(self.discovery_scope(result, "indexed")["status"], "unavailable")
        self.assertEqual(result["discovered"], [])

    def test_lock_exhaustion_costs_the_scope_not_the_listing(self):
        self.register_pinned_workspace()

        with index_locked_beyond_the_retry_budget():
            result = self.gw.list_workspaces(view="all")

        self.assertEqual(self.registered_ids(result), ["pinned"])
        self.assertEqual(self.discovery_scope(result, "indexed")["status"], "unavailable")
        self.assertEqual(result["discovered"], [])
        self.assertEqual(result["discovery"]["status"], "incomplete")
        self.assertEqual(self.audit_details(result)["unavailable_scopes"], ["indexed"])
        self.assertTrue(self.gw.audit.verify()["valid"])

    def test_the_registered_view_never_reads_the_index(self):
        self.register_pinned_workspace()

        with mock.patch.object(self.gw.reality_index, "get_active_snapshot",
                               side_effect=AssertionError("the registered view read the index")):
            result = self.gw.list_workspaces(view="registered")

        self.assertEqual(self.registered_ids(result), ["pinned"])
        self.assertNotIn("discovery", result)
        self.assertEqual(self.audit_details(result)["discovery_status"], "not_requested")
        self.assertEqual(self.audit_details(result)["unavailable_scopes"], [])

    def test_an_unexpected_failure_in_one_scope_leaves_the_other_scopes_and_the_registered_part(self):
        self.write_scopes("indexed", "cold")
        self.register_pinned_workspace()
        real_read = self.gw.reality_index.get_active_snapshot

        def read(scope_id, *args, **kwargs):
            if scope_id == "cold":
                raise RuntimeError(f"cannot read {self.roots['cold']}")
            return real_read(scope_id, *args, **kwargs)

        with mock.patch.object(self.gw.reality_index, "get_active_snapshot", side_effect=read):
            result = self.gw.list_workspaces(view="all")

        cold = self.discovery_scope(result, "cold")
        self.assertEqual(cold["status"], "unavailable")
        self.assertIn("RuntimeError", cold["reason"])
        self.assertNotIn(str(self.roots["cold"]), json.dumps(result),
                         "the failure text carries host paths and stays out of the response")
        self.assertEqual(self.discovery_scope(result, "indexed")["status"], "fresh")
        self.assertEqual({entry["scope_id"] for entry in result["discovered"]}, {"indexed"})
        self.assertEqual(self.registered_ids(result), ["pinned"])
        self.assertEqual(result["discovery"]["status"], "incomplete")

    def test_a_scope_whose_snapshot_cannot_be_turned_into_entries_is_unavailable_as_a_whole(self):
        self.write_scopes("indexed", "cold")
        self.gw.index_scope("indexed")
        self.gw.index_scope("cold")
        real_read = self.gw.reality_index.get_active_snapshot

        def read(scope_id, *args, **kwargs):
            snapshot = real_read(scope_id, *args, **kwargs)
            if scope_id == "cold" and snapshot is not None:
                # A well-formed project first: its entries exist before the malformed one raises.
                snapshot["projects"] = [*snapshot["projects"], {"instances": "not a list of instances"}]
            return snapshot

        with mock.patch.object(self.gw.reality_index, "get_active_snapshot", side_effect=read):
            result = self.gw.list_workspaces(view="all")

        self.assertEqual(self.discovery_scope(result, "cold")["status"], "unavailable")
        self.assertEqual({entry["scope_id"] for entry in result["discovered"]}, {"indexed"},
                         "half of a scope's entries must not be listed")


class SiblingReadPathTests(ListedFreshnessCase):
    """Bare-name resolution and the project lookups read the same index and must fail the same way."""

    READS = {
        "get_active_snapshot": lambda index, policy: index.get_active_snapshot(
            "indexed", policy, allow_stale=True),
        "lookup_by_alias": lambda index, policy: index.lookup_by_alias("fast-repo"),
        "list_projects": lambda index, policy: index.list_projects(),
        "get_project_instances": lambda index, policy: index.get_project_instances("fast-repo"),
    }

    def setUp(self):
        super().setUp()
        self.gw.index_scope("indexed")
        self.policy = self.gw.scopes.policy_generation

    def test_every_read_path_serves_a_healthy_index(self):
        for name, read in self.READS.items():
            with self.subTest(read=name):
                self.assertTrue(read(self.gw.reality_index, self.policy))

    def test_every_read_path_is_a_miss_on_an_index_with_a_newer_schema(self):
        set_schema_version(self.gw.reality_index.db_path, NEWER_SCHEMA)
        reopened = RealityIndex(self._state.name)

        for name, read in self.READS.items():
            with self.subTest(read=name):
                self.assertFalse(read(reopened, self.policy))

    def test_every_read_path_notices_a_schema_bump_after_the_instance_opened(self):
        set_schema_version(self.gw.reality_index.db_path, NEWER_SCHEMA)

        for name, read in self.READS.items():
            with self.subTest(read=name):
                self.assertFalse(read(self.gw.reality_index, self.policy))

    def test_every_read_path_is_a_miss_when_the_lock_outlasts_the_retries(self):
        for name, read in self.READS.items():
            with self.subTest(read=name), index_locked_beyond_the_retry_budget():
                self.assertFalse(read(self.gw.reality_index, self.policy))
        self.assertFalse(self.gw.reality_index.is_corrupt)


class BareNameResolutionTests(ListedFreshnessCase):
    """A bare project name is resolved through the alias index; losing the index loses only the shortcut."""

    def test_a_locked_index_falls_back_to_the_live_scan_for_a_bare_name(self):
        self.gw.index_scope("indexed")

        with index_locked_beyond_the_retry_budget():
            resolved = self.gw.resolver.resolve("fast-repo")

        self.assertEqual(resolved.resolution_kind, "project_name")
        self.assertTrue(resolved.workspace_id.endswith(":fast-repo"), resolved.workspace_id)


class ScopeInventoryIndexFailureTests(ListedFreshnessCase):
    """The index is a cache for ``scope_inventory``: losing it loses speed, not the answer."""

    def test_a_newer_index_schema_does_not_fail_the_read_it_only_loses_the_cache(self):
        self.gw.index_scope("indexed")
        set_schema_version(self.gw.reality_index.db_path, NEWER_SCHEMA)
        self.gw = MiddlewareGateway(str(self.registry_path), self._state.name)

        inventory = self.gw.scope_inventory("indexed")

        self.assertNotIn("error", inventory)
        self.assertGreaterEqual(inventory["total_repositories"], 1)
        self.assertEqual(inventory["freshness"]["source"], "live_scan")

    def test_a_locked_index_does_not_fail_the_read_either(self):
        with index_locked_beyond_the_retry_budget():
            inventory = self.gw.scope_inventory("indexed")

        self.assertNotIn("error", inventory)
        self.assertGreaterEqual(inventory["total_repositories"], 1)
        self.assertEqual(inventory["freshness"]["source"], "live_scan")

    def test_an_explicit_index_run_still_fails_loudly_on_an_index_it_cannot_write(self):
        self.gw.index_scope("indexed")
        set_schema_version(self.gw.reality_index.db_path, NEWER_SCHEMA)
        self.gw = MiddlewareGateway(str(self.registry_path), self._state.name)

        with self.assertRaises(reality_index.IncompatibleSchemaError):
            self.gw.index_scope("indexed")


class ListingStartsNoScanTests(ListedFreshnessCase):
    def fingerprint(self) -> tuple:
        with contextlib.closing(sqlite3.connect(self.gw.reality_index.db_path)) as conn:
            return (
                conn.execute("SELECT COUNT(*) FROM scope_snapshots").fetchone()[0],
                [tuple(row) for row in conn.execute(
                    "SELECT scope_id, generation_id FROM active_generation ORDER BY scope_id")],
            )

    def listed_without_scanning(self, view: str = "all") -> dict:
        forbidden = AssertionError("a listing started a scan or a write")
        with mock.patch.object(DiscoveryEngine, "discover_scope", side_effect=forbidden), \
                mock.patch.object(DiscoveryEngine, "scope_inventory", side_effect=forbidden), \
                mock.patch.object(DiscoveryEngine, "index_scope", side_effect=forbidden), \
                mock.patch.object(RealityIndex, "schedule_background_refresh", side_effect=forbidden), \
                mock.patch.object(RealityIndex, "write_snapshot", side_effect=forbidden):
            return self.gw.list_workspaces(view=view)

    def test_no_state_of_the_index_makes_a_listing_scan_or_write(self):
        self.write_scopes("indexed", "cold")
        self.gw.index_scope("indexed")
        before = self.fingerprint()
        states = {
            "fresh and never-indexed scopes": lambda: contextlib.nullcontext(),
            "stale": lambda: self.aged(),
            "locked": index_locked_beyond_the_retry_budget,
        }
        for label, enter in states.items():
            for view in ("all", "discovered", "registered"):
                with self.subTest(state=label, view=view), enter():
                    self.listed_without_scanning(view)

        set_schema_version(self.gw.reality_index.db_path, NEWER_SCHEMA)
        self.gw = MiddlewareGateway(str(self.registry_path), self._state.name)
        for view in ("all", "discovered", "registered"):
            with self.subTest(state="newer schema", view=view):
                self.listed_without_scanning(view)

        set_schema_version(self.gw.reality_index.db_path, reality_index.SCHEMA_VERSION)
        self.assertEqual(self.fingerprint(), before)

    @contextlib.contextmanager
    def aged(self):
        self.age_snapshot("indexed", PAST_THE_LIMIT_SEC)
        try:
            yield
        finally:
            self.age_snapshot("indexed", -PAST_THE_LIMIT_SEC)


class RevocationTests(ListedFreshnessCase):
    """What the policy no longer allows disappears from the listing, even though the snapshot is cached."""

    def test_revoking_discovery_removes_the_scope_and_every_entry(self):
        self.gw.index_scope("indexed")
        self.assertTrue(self.gw.list_workspaces()["discovered"])
        self.write_scopes()

        result = self.gw.list_workspaces()

        self.assertEqual(result["discovered"], [])
        self.assertEqual(result["discovery"]["scopes"], [])
        self.assertEqual(result["discovery"]["status"], "not_configured")

    def test_revoking_index_authority_turns_the_cached_scope_into_not_indexed(self):
        self.gw.index_scope("indexed")
        self.assertTrue(self.gw.list_workspaces()["discovered"])
        self.write_scopes("indexed", unindexed=("indexed",))

        result = self.gw.list_workspaces()

        self.assertEqual(self.discovery_scope(result, "indexed")["status"], "not_indexed")
        self.assertEqual(result["discovered"], [], "the cached entries must not outlive the authority")

    def test_revoking_content_read_removes_the_entries_instead_of_stripping_their_capabilities(self):
        self.gw.index_scope("indexed")
        self.write_scopes("indexed", content_read=False)

        result = self.gw.list_workspaces()

        self.assertEqual(self.discovery_scope(result, "indexed")["status"], "unavailable")
        self.assertEqual(result["discovered"], [])
        self.assertEqual([e for e in result["eligible"] if e.get("admission_state") == "discovered"], [])


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class McpIsolationTests(ListedFreshnessCase):
    def tool(self):
        server = create_session_read_server(str(self.registry_path), self._state.name)
        return server._tool_manager._tools["uam_list_workspaces"].fn

    @staticmethod
    def call(tool) -> dict:
        return json.loads(asyncio.run(tool(ctx=None)))

    def test_a_scope_without_index_authority_reads_not_indexed_through_the_connector(self):
        self.write_scopes("indexed", "cold", unindexed=("cold",))
        self.gw.index_scope("indexed")

        payload = self.call(self.tool())

        statuses = {item["scope_id"]: item["status"] for item in payload["discovery"]["scopes"]}
        self.assertEqual(statuses, {"indexed": "fresh", "cold": "not_indexed"})
        self.assertEqual(payload["discovery"]["status"], "incomplete")
        cold = next(item for item in payload["discovery"]["scopes"] if item["scope_id"] == "cold")
        self.assertIn("uam_scope_inventory", cold["reason"])
        self.assertNotIn(str(self.roots["cold"]), json.dumps(payload))

    def test_the_connector_answers_when_the_index_is_locked(self):
        write_workspace_registry(self.registry_path, [{
            "workspace_id": "pinned",
            "root": str(self.roots["indexed"] / "fast-repo"),
            "kind": "git-repository",
            "capabilities": ["filesystem.read", "git.observe"],
        }])
        self.gw = MiddlewareGateway(str(self.registry_path), self._state.name)
        self.gw.index_scope("indexed")
        tool = self.tool()

        with index_locked_beyond_the_retry_budget():
            payload = self.call(tool)

        self.assertEqual([entry["workspace_id"] for entry in payload["registered"]], ["pinned"])
        self.assertEqual(payload["discovery"]["status"], "incomplete")
        self.assertEqual(payload["discovery"]["scopes"][0]["status"], "unavailable")

    def test_the_connector_never_reports_a_newer_schema_index_as_fresh(self):
        self.gw.index_scope("indexed")
        set_schema_version(self.gw.reality_index.db_path, NEWER_SCHEMA)

        payload = self.call(self.tool())

        self.assertEqual(payload["discovery"]["scopes"][0]["status"], "unavailable")
        self.assertEqual(payload["discovered"], [])


if __name__ == "__main__":
    unittest.main()
