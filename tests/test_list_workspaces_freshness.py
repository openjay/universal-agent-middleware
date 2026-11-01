"""``list_workspaces`` serves the index even when it is old, so its answer must say how old.

The listing never blocks on a scan: it reads the active snapshot with ``allow_stale=True``. Before
this was carried into the response, a snapshot past its age limit produced exactly the same
``discovered`` list as a fresh one, and a scope without a usable snapshot simply contributed
nothing, so a consumer could not tell "not there" from "not looked at" or "five minutes old" from
"two hours old".
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from universal_agent_middleware.discovery import scan_coverage
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.reality_index import DEFAULT_MAX_AGE_SEC
from universal_agent_middleware.root_scope import RootScopeAuthority

from tests.synthetic_fixtures import init_git_repo, write_workspace_registry

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:
    create_session_read_server = None

MAX_AGE_MS = int(DEFAULT_MAX_AGE_SEC * 1000)
PAST_THE_LIMIT_SEC = DEFAULT_MAX_AGE_SEC * 4


class ListedFreshnessCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._state = tempfile.TemporaryDirectory(prefix="uam-freshness-state-")
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(self._state.cleanup)
        base = Path(self._tmp.name).resolve()
        self.roots = {"indexed": base / "indexed", "cold": base / "cold"}
        init_git_repo(self.roots["indexed"] / "fast-repo", files={"README.md": "# fast\n"})
        init_git_repo(self.roots["cold"] / "unseen-repo", files={"README.md": "# unseen\n"})
        self.config = base / "config"
        self.registry_path = write_workspace_registry(self.config / "workspaces.json", [])
        self.write_scopes("indexed")
        self.gw = MiddlewareGateway(str(self.registry_path), self._state.name)

    def write_scopes(
        self, *names: str, content_read: bool = True, unindexed: tuple[str, ...] = (),
    ) -> None:
        scopes = self.config / "root_scopes.json"
        scopes.write_text(json.dumps({
            "schema_version": "root-scope-registry-v1",
            "scopes": [{
                "scope_id": name,
                "root": str(self.roots[name]),
                "authority": RootScopeAuthority(
                    discover=True, metadata_read=True, content_read=content_read,
                    git_observe=True, auto_admit=content_read, index=name not in unindexed,
                ).to_dict(),
            } for name in names],
        }), encoding="utf-8")
        os.utime(scopes, None)

    def age_snapshot(self, scope_id: str, seconds: float) -> None:
        with contextlib.closing(sqlite3.connect(self.gw.reality_index.db_path)) as conn, conn:
            conn.execute(
                "UPDATE scope_snapshots SET observed_at = observed_at - ? WHERE scope_id = ?",
                (seconds, scope_id),
            )

    def discovery_scope(self, result: dict, scope_id: str) -> dict:
        return next(item for item in result["discovery"]["scopes"] if item["scope_id"] == scope_id)


class GatewayFreshnessTests(ListedFreshnessCase):
    def test_a_fresh_snapshot_is_reported_fresh_on_the_scope_and_on_every_entry(self):
        self.gw.index_scope("indexed")
        result = self.gw.list_workspaces(view="all")

        discovery = result["discovery"]
        self.assertEqual(discovery["status"], "fresh")
        self.assertEqual(discovery["max_age_ms"], MAX_AGE_MS)
        scope = self.discovery_scope(result, "indexed")
        self.assertEqual(scope["status"], "fresh")
        self.assertLess(scope["cache_age_ms"], MAX_AGE_MS)
        self.assertGreaterEqual(scope["total_repositories"], 1)
        self.assertTrue(result["discovered"])
        for entry in result["discovered"]:
            self.assertEqual(entry["source"], "reality_index")
            self.assertEqual(set(entry["freshness"]), {"stale", "cache_age_ms"})
            self.assertIs(entry["freshness"]["stale"], False)
            self.assertLess(entry["freshness"]["cache_age_ms"], MAX_AGE_MS)

    def test_a_snapshot_past_its_age_limit_is_still_listed_but_marked_stale(self):
        self.gw.index_scope("indexed")
        self.age_snapshot("indexed", PAST_THE_LIMIT_SEC)
        result = self.gw.list_workspaces(view="all")

        self.assertTrue(result["discovered"], "stale entries stay listed for compatibility")
        self.assertEqual(result["discovery"]["status"], "stale")
        scope = self.discovery_scope(result, "indexed")
        self.assertEqual(scope["status"], "stale")
        self.assertGreaterEqual(scope["cache_age_ms"], int(PAST_THE_LIMIT_SEC * 1000))
        for entry in result["discovered"]:
            self.assertIs(entry["freshness"]["stale"], True)
            self.assertGreaterEqual(entry["freshness"]["cache_age_ms"], int(PAST_THE_LIMIT_SEC * 1000))
        derived = [entry for entry in result["eligible"] if entry.get("admission_state") == "discovered"]
        self.assertTrue(derived)
        for entry in derived:
            self.assertIs(entry["freshness"]["stale"], True)

    def test_a_scope_without_a_usable_snapshot_is_named_instead_of_silently_missing(self):
        self.write_scopes("indexed", "cold")
        self.gw.index_scope("indexed")
        result = self.gw.list_workspaces(view="all")

        self.assertEqual(result["discovery"]["status"], "incomplete")
        cold = self.discovery_scope(result, "cold")
        self.assertEqual(cold["status"], "unavailable")
        self.assertTrue(cold["reason"])
        self.assertEqual(self.discovery_scope(result, "indexed")["status"], "fresh")
        self.assertEqual({entry["scope_id"] for entry in result["discovered"]}, {"indexed"})

    def test_a_discoverable_scope_without_index_authority_is_named_not_indexed(self):
        self.write_scopes("indexed", "cold", unindexed=("cold",))
        self.gw.index_scope("indexed")
        result = self.gw.list_workspaces(view="all")

        cold = self.discovery_scope(result, "cold")
        self.assertEqual(cold["status"], "not_indexed")
        self.assertIn("uam_scope_inventory", cold["reason"])
        self.assertEqual(self.discovery_scope(result, "indexed")["status"], "fresh")
        self.assertEqual(result["discovery"]["status"], "incomplete")
        self.assertEqual({entry["scope_id"] for entry in result["discovered"]}, {"indexed"})

    def test_a_policy_change_that_invalidates_the_snapshot_reads_as_unavailable_not_absent(self):
        self.gw.index_scope("indexed")
        self.assertTrue(self.gw.list_workspaces(view="all")["discovered"])
        self.write_scopes("indexed", content_read=False)
        result = self.gw.list_workspaces(view="all")

        self.assertEqual(result["discovered"], [])
        self.assertEqual(self.discovery_scope(result, "indexed")["status"], "unavailable")
        self.assertEqual(result["discovery"]["status"], "incomplete")

    def test_an_unavailable_scope_outranks_a_stale_one_in_the_overall_status(self):
        self.write_scopes("indexed", "cold")
        self.gw.index_scope("indexed")
        self.age_snapshot("indexed", PAST_THE_LIMIT_SEC)

        self.assertEqual(self.gw.list_workspaces(view="all")["discovery"]["status"], "incomplete")

    def test_the_scan_bounds_travel_with_the_answer(self):
        self.gw.index_scope("indexed")
        coverage = self.gw.list_workspaces(view="all")["discovery"]["coverage"]

        self.assertEqual(coverage, scan_coverage())
        self.assertEqual(coverage["mode"], "bounded")
        self.assertIs(coverage["not_exhaustive"], True)

    def test_no_discoverable_scope_is_not_configured_rather_than_fresh(self):
        self.write_scopes()
        result = self.gw.list_workspaces(view="all")

        self.assertEqual(result["discovered"], [])
        self.assertEqual(result["discovery"]["status"], "not_configured")
        self.assertEqual(result["discovery"]["scopes"], [])

    def test_the_registered_view_carries_no_discovery_block(self):
        self.gw.index_scope("indexed")
        result = self.gw.list_workspaces(view="registered")

        self.assertNotIn("discovered", result)
        self.assertNotIn("discovery", result)

    def test_the_audit_record_names_the_freshness_the_response_carried(self):
        self.write_scopes("indexed", "cold")
        self.gw.index_scope("indexed")
        self.age_snapshot("indexed", PAST_THE_LIMIT_SEC)
        result = self.gw.list_workspaces(view="all")

        details = self.audit_details(result)
        self.assertEqual(details["discovery_status"], "incomplete")
        self.assertEqual(details["stale_scopes"], ["indexed"])
        self.assertEqual(details["unavailable_scopes"], ["cold"])
        self.assertEqual(details["not_indexed_scopes"], [])
        self.assertTrue(self.gw.audit.verify()["valid"])

    def test_the_audit_record_tells_a_missing_snapshot_from_a_scope_that_is_never_indexed(self):
        self.write_scopes("indexed", "cold", unindexed=("cold",))
        self.gw.index_scope("indexed")
        details = self.audit_details(self.gw.list_workspaces(view="all"))

        self.assertEqual(details["not_indexed_scopes"], ["cold"])
        self.assertEqual(details["unavailable_scopes"], [])
        self.assertEqual(details["stale_scopes"], [])

    def audit_details(self, result: dict) -> dict:
        rows = [json.loads(line) for line in self.gw.audit.path.read_text().splitlines()]
        return next(item for item in rows if item.get("request_id") == result["request_id"])["details"]


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class McpFreshnessTests(ListedFreshnessCase):
    def call_tool(self) -> dict:
        server = create_session_read_server(str(self.registry_path), self._state.name)
        tool = server._tool_manager._tools["uam_list_workspaces"].fn
        return json.loads(asyncio.run(tool(ctx=None)))

    def test_the_connector_response_carries_the_staleness_the_gateway_knows(self):
        self.write_scopes("indexed", "cold")
        self.gw.index_scope("indexed")
        self.age_snapshot("indexed", PAST_THE_LIMIT_SEC)
        payload = self.call_tool()

        self.assertEqual(payload["discovery"]["status"], "incomplete")
        statuses = {item["scope_id"]: item["status"] for item in payload["discovery"]["scopes"]}
        self.assertEqual(statuses, {"indexed": "stale", "cold": "unavailable"})
        self.assertTrue(payload["discovered"])
        for entry in [*payload["discovered"], *payload["eligible"]]:
            self.assertIs(entry["freshness"]["stale"], True)

    def test_a_fresh_connector_response_says_so(self):
        self.gw.index_scope("indexed")
        payload = self.call_tool()

        self.assertEqual(payload["discovery"]["status"], "fresh")
        for entry in payload["discovered"]:
            self.assertIs(entry["freshness"]["stale"], False)

    def test_registered_entries_have_no_index_freshness_to_report(self):
        write_workspace_registry(self.registry_path, [{
            "workspace_id": "pinned",
            "root": str(self.roots["indexed"] / "fast-repo"),
            "kind": "git-repository",
            "capabilities": ["filesystem.read", "git.observe"],
        }])
        self.gw = MiddlewareGateway(str(self.registry_path), self._state.name)
        self.gw.index_scope("indexed")
        payload = self.call_tool()

        self.assertTrue(payload["registered"])
        for entry in payload["registered"]:
            self.assertNotIn("freshness", entry)

    def test_the_new_fields_expose_no_host_path(self):
        self.write_scopes("indexed", "cold")
        self.gw.index_scope("indexed")
        text = json.dumps(self.call_tool())

        self.assertNotIn(self._tmp.name, text)
        self.assertNotIn(str(self.roots["indexed"]), text)


if __name__ == "__main__":
    unittest.main()
