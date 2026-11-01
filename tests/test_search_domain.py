"""A scope search declares what it searched, and never claims more absence than that.

``uam_search_scope`` searches to a fixed depth, honours the repository ignore files, skips hidden and
binary files and symlinks, and leaves out a list of directories. A search that finished without a
match used to answer ``COMPLETE`` and ``safe_to_conclude_absent=true`` without saying any of that, so
a file six levels down (or in ``.gitignore``) was reported as absent from the scope. The search now
states its domain, ``safe_to_conclude_absent`` is never true for a bounded search, and the narrower
statement that *is* true (nothing matched within the declared domain) has its own field.

The declaration is checked against what the search actually did, not against a command line: the
scope search decides which files ripgrep is handed (as open descriptors), so "searched" means "the
object behind this name was handed to ripgrep".
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from universal_agent_middleware.discovery import DiscoveryEngine
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry
from universal_agent_middleware.scope_search import ScopeSearchLimits

from tests.scope_search_instruments import (
    OpenSpy,
    RunRecord,
    ScriptedRipgrep,
    completed,
    handed_relative_paths,
    identity_of,
)
from tests.synthetic_fixtures import init_git_repo, write_workspace_registry

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:
    create_session_read_server = None

FIND_RIPGREP = "universal_agent_middleware.discovery.find_ripgrep"
RESULT_CAP = "universal_agent_middleware.discovery._MAX_SEARCH_RESULTS"
FULL = RootScopeAuthority(
    discover=True, metadata_read=True, content_read=True, text_search=True,
    git_observe=True, classify=True, index=True, relate=True, auto_admit=True,
)
NO_SEARCH = RootScopeAuthority(discover=True, metadata_read=True, content_read=True)
EXCLUDED_NAMES = ["node_modules", ".git", ".venv", "__pycache__", "target", "dist", "build", "vendor"]


class ScopeFixture(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="uam-search-domain-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.alpha = self.root / "alpha"
        init_git_repo(self.alpha, files={"main.py": "needle\n", "evidence/raw.txt": "needle\n"})

    def engine(self, *nested: tuple[str, str, RootScopeAuthority], **kwargs: Any) -> DiscoveryEngine:
        registry = RootScopeRegistry()
        registry.add_scope(RootScope(scope_id="s", root=str(self.root), authority=FULL))
        for scope_id, rel, authority in nested:
            registry.add_scope(RootScope(scope_id=scope_id, root=str(self.root / rel), authority=authority))
        return DiscoveryEngine(registry, cache_ttl=60.0, **kwargs)

    def search(
        self, engine: DiscoveryEngine, hits: tuple[str, ...] = (), *, returncode: int | None = None,
        max_results: int = 50,
    ) -> tuple[dict[str, Any], ScriptedRipgrep]:
        """Search with ripgrep scripted to report ``hits`` (paths below the root) among what it is handed."""
        def reply(call: RunRecord) -> subprocess.CompletedProcess[Any]:
            printed = b"".join(call.operand_for(self.root / rel).encode() + b"\n" for rel in hits)
            return completed(printed, (0 if hits else 1) if returncode is None else returncode)

        ripgrep = ScriptedRipgrep(reply)
        with mock.patch(FIND_RIPGREP, return_value="/usr/bin/rg"), ripgrep.patch():
            result = engine.search_scope("s", "needle", max_results=max_results)
        return result, ripgrep

    def write(self, rel: str, text: str = "needle\n") -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def searched(self, ripgrep: ScriptedRipgrep) -> set[str]:
        return handed_relative_paths(ripgrep, self.root)


class AbsenceClaimTests(ScopeFixture):
    def test_a_complete_search_without_a_match_is_absent_within_its_domain_only(self) -> None:
        result, _ = self.search(self.engine())
        self.assertEqual(result["search_completeness"], "COMPLETE")
        self.assertIs(result["safe_to_conclude_absent"], False)
        self.assertIs(result["absent_within_search_domain"], True)
        self.assertIs(result["search_domain"]["exhaustive"], False)

    def test_a_match_is_never_an_absence(self) -> None:
        result, _ = self.search(self.engine(), ("alpha/main.py",))
        self.assertEqual(result["total_matches"], 1)
        self.assertIs(result["safe_to_conclude_absent"], False)
        self.assertIs(result["absent_within_search_domain"], False)

    def test_a_failed_search_is_not_absent_within_anything(self) -> None:
        def reply(call: RunRecord) -> subprocess.CompletedProcess[Any]:
            raise subprocess.TimeoutExpired(cmd=["rg"], timeout=30, output=None)

        ripgrep = ScriptedRipgrep(reply)
        with mock.patch(FIND_RIPGREP, return_value="/usr/bin/rg"), ripgrep.patch():
            result = self.engine().search_scope("s", "needle")
        self.assertEqual(result["search_completeness"], "FAILED")
        self.assertIs(result["absent_within_search_domain"], False)
        self.assertIs(result["safe_to_conclude_absent"], False)

    def test_a_scope_without_search_authority_answers_denied_with_the_same_claims(self) -> None:
        registry = RootScopeRegistry()
        registry.add_scope(RootScope(scope_id="s", root=str(self.root), authority=NO_SEARCH))
        result = DiscoveryEngine(registry, cache_ttl=60.0).search_scope("s", "needle")
        self.assertEqual(result["search_completeness"], "DENIED")
        self.assertIs(result["safe_to_conclude_absent"], False)
        self.assertIs(result["absent_within_search_domain"], False)

    def test_a_missing_ripgrep_answers_failed_with_the_same_claims(self) -> None:
        engine = self.engine()
        with mock.patch(FIND_RIPGREP, return_value=None):
            result = engine.search_scope("s", "needle")
        self.assertEqual((result["search_completeness"], result["failure_stage"]), ("FAILED", "launch"))
        self.assertIs(result["safe_to_conclude_absent"], False)
        self.assertIs(result["absent_within_search_domain"], False)

    def test_a_truncated_search_is_not_absent_within_anything(self) -> None:
        result, _ = self.search(self.engine(), ("alpha/main.py", "alpha/evidence/raw.txt"), max_results=1)
        self.assertEqual(result["search_completeness"], "PARTIAL")
        self.assertIs(result["absent_within_search_domain"], False)

    def test_a_hit_withheld_by_scope_authority_is_not_an_absence(self) -> None:
        engine = self.engine()
        root = self.root

        def allows_only_the_root(registry: RootScopeRegistry, path: str | Path) -> bool:
            return Path(path) == root

        with mock.patch.object(RootScopeRegistry, "can_search", autospec=True, side_effect=allows_only_the_root):
            result, _ = self.search(engine, ("alpha/main.py",))
        self.assertEqual(result["results"], [])
        self.assertIs(result["absent_within_search_domain"], False)
        self.assertIs(result["search_domain"]["scope_authority_exclusions"], True)
        self.assertIn("scope_authority", result["search_domain"]["not_covered"])

    def test_a_root_that_another_scope_governs_is_denied_before_anything_is_read(self) -> None:
        engine = self.engine()
        with mock.patch.object(RootScopeRegistry, "can_search", return_value=False):
            result, ripgrep = self.search(engine, ("alpha/main.py",))
        self.assertEqual(result["search_completeness"], "DENIED")
        self.assertEqual(ripgrep.ripgrep_calls, [])
        self.assertIs(result["absent_within_search_domain"], False)


class ResultBoundTests(ScopeFixture):
    """How many hits one search may return is the server's decision, not the caller's."""

    def test_a_caller_cannot_ask_for_more_results_than_the_server_returns(self) -> None:
        names = ("one", "two", "three")
        for name in names:
            self.write(f"alpha/{name}.txt")
        with mock.patch(RESULT_CAP, 2):
            result, _ = self.search(self.engine(), tuple(f"alpha/{name}.txt" for name in names), max_results=10**9)
        self.assertEqual(result["total_matches"], 2)
        self.assertEqual((result["search_completeness"], result["failure_reason"]), ("PARTIAL", "result_limit"))
        self.assertIs(result["absent_within_search_domain"], False)

    def test_a_request_for_no_results_or_fewer_still_returns_one_and_says_it_stopped(self) -> None:
        for asked in (0, -5):
            with self.subTest(max_results=asked):
                result, _ = self.search(
                    self.engine(), ("alpha/main.py", "alpha/evidence/raw.txt"), max_results=asked,
                )
                self.assertEqual(result["total_matches"], 1)
                self.assertEqual(result["failure_reason"], "result_limit")


class DeclaredDomainTests(ScopeFixture):
    def test_the_declared_depth_is_the_depth_the_walk_enforces(self) -> None:
        self.write("d1/d2/d3/d4/at_depth_five.txt")
        self.write("d1/d2/d3/d4/d5/at_depth_six.txt")
        result, ripgrep = self.search(self.engine())
        domain = result["search_domain"]
        self.assertEqual((domain["max_depth"], domain["max_depth_from"]), (5, "each search root"))
        searched = self.searched(ripgrep)
        self.assertIn("d1/d2/d3/d4/at_depth_five.txt", searched)
        self.assertNotIn("d1/d2/d3/d4/d5/at_depth_six.txt", searched)

    def test_every_declared_excluded_directory_is_never_searched(self) -> None:
        self.write("kept/control.txt")
        for name in EXCLUDED_NAMES:
            self.write(f"{name}/inside.txt")
            self.write(f"kept/{name}/inside.txt")
        result, ripgrep = self.search(self.engine())
        self.assertEqual(result["search_domain"]["excluded_directory_names"], EXCLUDED_NAMES)
        searched = self.searched(ripgrep)
        self.assertIn("kept/control.txt", searched)
        for name in EXCLUDED_NAMES:
            with self.subTest(name=name):
                self.assertNotIn(f"{name}/inside.txt", searched)
                self.assertNotIn(f"kept/{name}/inside.txt", searched)

    def test_the_walk_keeps_the_ignore_and_visibility_defaults_the_domain_declares(self) -> None:
        self.write("kept/control.txt")
        self.write(".hidden.txt")
        self.write(".config/inside.txt")
        self.write("kept/binary.dat", "needle\0\1\2")
        self.write("kept/ignored_by_ignore.txt")
        self.write("kept/.ignore", "ignored_by_ignore.txt\n")
        self.write("kept/ignored_by_rgignore.txt")
        self.write("kept/.rgignore", "ignored_by_rgignore.txt\n")
        self.write("alpha/ignored_by_gitignore.txt")
        self.write("alpha/.gitignore", "ignored_by_gitignore.txt\n")
        (self.root / "kept" / "link.txt").symlink_to(self.root / "kept" / "control.txt")
        result, ripgrep = self.search(self.engine())
        domain = result["search_domain"]
        searched = self.searched(ripgrep)
        self.assertIn("kept/control.txt", searched)
        self.assertIn("alpha/main.py", searched)
        for hidden in (".hidden.txt", ".config/inside.txt", "kept/.ignore", "kept/.rgignore", "alpha/.gitignore"):
            with self.subTest(hidden=hidden):
                self.assertNotIn(hidden, searched)
        for skipped in ("kept/binary.dat", "kept/ignored_by_ignore.txt", "kept/ignored_by_rgignore.txt",
                        "alpha/ignored_by_gitignore.txt"):
            with self.subTest(skipped=skipped):
                self.assertNotIn(skipped, searched)
        self.assertNotIn("kept/link.txt", searched)
        self.assertEqual(domain["ignore_files_honoured"], [".gitignore", ".ignore", ".rgignore"])
        for reason in ("beyond_max_depth", "ignored_by_ignore_files", "hidden_paths", "binary_files",
                       "symlinked_paths", "excluded_directory_names", "secret_firewall_paths",
                       "system_directories", "unreadable_paths"):
            with self.subTest(reason=reason):
                self.assertIn(reason, domain["not_covered"])

    def test_no_filter_is_left_to_the_ripgrep_command_line(self) -> None:
        """Filters live in the walk, where they are enforced before a file is opened, not in flags."""
        _, ripgrep = self.search(self.engine())
        (call,) = ripgrep.ripgrep_calls
        flags = call.argv[: call.argv.index("--")]
        for flag in ("--hidden", "--no-ignore", "--binary", "--follow", "-uu", "-uuu", "--text", "-a"):
            self.assertNotIn(flag, flags)
        for option in ("-g", "--glob", "--iglob", "--max-depth", "--ignore-file"):
            self.assertFalse(any(flag == option or flag.startswith(option + "=") for flag in flags), option)

    def test_a_search_with_hits_declares_the_same_domain_as_one_without(self) -> None:
        engine = self.engine()
        without, _ = self.search(engine)
        with_hit, _ = self.search(engine, ("alpha/main.py",))
        self.assertEqual(without["search_domain"], with_hit["search_domain"])

    def test_the_declared_limits_are_the_limits_in_force(self) -> None:
        limits = ScopeSearchLimits(max_entries=900, max_files=7, max_bytes=4096, deadline_seconds=12.0)
        result, _ = self.search(self.engine(search_limits=limits))
        self.assertEqual(result["search_domain"]["limits"], {
            "deadline_seconds": 12.0, "max_entries": 900, "max_files": 7, "max_bytes": 4096,
        })

    def test_the_domain_names_no_host_path_and_no_scope(self) -> None:
        result, _ = self.search(self.engine(("evidence", "alpha/evidence", RootScopeAuthority())))
        text = json.dumps(result["search_domain"])
        self.assertNotIn(str(self.root), text)
        self.assertNotIn("evidence", text)
        self.assertNotIn("alpha", text)


class ScopeAuthorityExclusionTests(ScopeFixture):
    def test_no_nested_denial_means_no_authority_exclusion(self) -> None:
        result, _ = self.search(self.engine())
        self.assertIs(result["search_domain"]["scope_authority_exclusions"], False)
        self.assertNotIn("scope_authority", result["search_domain"]["not_covered"])
        self.assertNotIn("hard_linked_files", result["search_domain"]["not_covered"])

    def test_a_nested_scope_that_denies_search_is_flagged_without_naming_or_counting_it(self) -> None:
        engine = self.engine(("evidence", "alpha/evidence", NO_SEARCH))
        spy = OpenSpy()
        with spy.patch():
            result, ripgrep = self.search(engine)
        denied = self.alpha / "evidence"
        self.assertNotIn(identity_of(denied), spy.listed, "a denied directory must not even be listed")
        self.assertNotIn(identity_of(denied / "raw.txt"), spy.opened)
        self.assertNotIn("alpha/evidence/raw.txt", self.searched(ripgrep))
        self.assertIn("alpha/main.py", self.searched(ripgrep))
        self.assertIs(result["search_domain"]["scope_authority_exclusions"], True)
        self.assertIn("scope_authority", result["search_domain"]["not_covered"])
        self.assertIn("hard_linked_files", result["search_domain"]["not_covered"])
        self.assertNotIn("evidence", json.dumps(result["search_domain"]))

    def test_a_nested_scope_that_allows_search_is_not_an_exclusion(self) -> None:
        result, ripgrep = self.search(self.engine(("evidence", "alpha/evidence", FULL)))
        self.assertIn("alpha/evidence/raw.txt", self.searched(ripgrep))
        self.assertIs(result["search_domain"]["scope_authority_exclusions"], False)


@unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
class McpSurfaceTests(ScopeFixture):
    def test_the_tool_returns_the_domain_and_the_narrowed_claim(self) -> None:
        config = self.root / "config"
        registry = write_workspace_registry(config / "workspaces.json", [])
        (config / "root_scopes.json").write_text(json.dumps({
            "schema_version": "root-scope-registry-v1",
            "scopes": [{"scope_id": "s", "root": str(self.root), "authority": FULL.to_dict()}],
        }), encoding="utf-8")
        state = self.root / "state"
        state.mkdir()
        server = create_session_read_server(str(registry), str(state))
        tool = server._tool_manager._tools["uam_search_scope"].fn
        ripgrep = ScriptedRipgrep(lambda call: completed(b"", 1))
        with mock.patch(FIND_RIPGREP, return_value="/usr/bin/rg"), ripgrep.patch():
            payload = json.loads(asyncio.run(tool(ctx=None, scope_id="s", query="needle")))
        self.assertNotIn("error", payload)
        self.assertIs(payload["safe_to_conclude_absent"], False)
        self.assertIs(payload["absent_within_search_domain"], True)
        self.assertEqual(payload["search_domain"]["max_depth"], 5)
        self.assertIn("beyond_max_depth", payload["search_domain"]["not_covered"])
        description = server._tool_manager._tools["uam_search_scope"].description
        self.assertIn("search_domain", description)
        self.assertIn("absent_within_search_domain", description)


if __name__ == "__main__":
    unittest.main()
