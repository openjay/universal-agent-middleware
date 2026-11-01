"""What crosses the ripgrep process boundary in cross-project search, and what the search makes of it.

The scope search hands ripgrep open descriptors and reads back ``/dev/fd/N`` records. CPython
reports ``TimeoutExpired.stdout`` as ``bytes`` even for ``text=True`` calls (and ``None`` when
nothing was captured), a timed-out process can leave a record cut off mid-number, and a
misbehaving or replaced ripgrep can print anything. These tests feed those real shapes through
``DiscoveryEngine.search_scope`` with ripgrep scripted, so no result depends on a particular
ripgrep build, and show that none of them becomes a hit, a crash or a claim of completeness.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

from scope_search_instruments import DESCRIPTOR_OPERAND, RunRecord, ScriptedRipgrep, completed, identity_of
from synthetic_fixtures import init_git_repo, write_workspace_registry

from universal_agent_middleware.audit import HashChainedAuditLog
from universal_agent_middleware.discovery import DiscoveryEngine
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry
from universal_agent_middleware.scope_search import ScopeSearchLimits, parse_hit_records

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:
    create_session_read_server = None  # type: ignore[assignment]

FIND_RIPGREP = "universal_agent_middleware.discovery.find_ripgrep"
_FULL_SEARCH = RootScopeAuthority(
    discover=True, metadata_read=True, content_read=True, text_search=True,
    git_observe=True, classify=True, index=True, relate=True, auto_admit=True,
)
Reply = Callable[[RunRecord], subprocess.CompletedProcess[Any]]


def _records(call: RunRecord, *paths: Path) -> bytes:
    return b"".join(call.operand_for(path).encode("utf-8") + b"\n" for path in paths)


def _prints(*paths: Path, returncode: int = 0) -> Reply:
    """Ripgrep reports each given file (which must have been handed over) and exits ``returncode``."""
    return lambda call: completed(_records(call, *paths), returncode)


def _times_out(*paths: Path, as_text: bool = False, cut_off: str = "") -> Reply:
    def reply(call: RunRecord) -> subprocess.CompletedProcess[Any]:
        printed: bytes | str = _records(call, *paths) + cut_off.encode("utf-8")
        if as_text:
            printed = printed.decode("utf-8")
        raise subprocess.TimeoutExpired(cmd=["rg"], timeout=30, output=printed)

    return reply


def _times_out_silently(call: RunRecord) -> subprocess.CompletedProcess[Any]:
    raise subprocess.TimeoutExpired(cmd=["rg"], timeout=30, output=None)


class _ExtraEntries:
    """A directory listing plus entries the directory does not really have."""

    def __init__(self, real: Any, extra: list[Any]) -> None:
        self._real = real
        self._extra = extra

    def __enter__(self) -> _ExtraEntries:
        self._real.__enter__()
        return self

    def __exit__(self, *exc_info: Any) -> Any:
        return self._real.__exit__(*exc_info)

    def __iter__(self) -> Any:
        yield from self._real
        yield from self._extra


def _listing_with_extra(directory: Path, *names: str) -> Any:
    """An ``os.scandir`` that lists ``directory`` (by descriptor) with extra regular-file entries."""
    real_scandir = os.scandir
    target = identity_of(directory)
    extra = [
        SimpleNamespace(
            name=name, is_symlink=lambda: False,
            is_dir=lambda follow_symlinks=True: False, is_file=lambda follow_symlinks=True: True,
        )
        for name in names
    ]

    def scandir(path: Any = None) -> Any:
        listing = real_scandir() if path is None else real_scandir(path)
        if isinstance(path, int):
            info = os.fstat(path)
            if (info.st_dev, info.st_ino) == target:
                return _ExtraEntries(listing, extra)
        return listing

    return scandir


class ParseHitRecordsTests(unittest.TestCase):
    def test_accepts_bytes_str_bytearray_and_none(self):
        for output in (b"/dev/fd/5\n/dev/fd/6\n", "/dev/fd/5\n/dev/fd/6\n", bytearray(b"/dev/fd/5\n/dev/fd/6\n")):
            with self.subTest(type=type(output).__name__):
                parsed = parse_hit_records(output, producer_finished=True)
                self.assertEqual(parsed.descriptors, [5, 6])
                self.assertEqual((parsed.unexpected, parsed.unterminated), (0, 0))
        self.assertEqual(parse_hit_records(None, producer_finished=False).descriptors, [])
        self.assertEqual(parse_hit_records(b"", producer_finished=True).descriptors, [])
        self.assertEqual(parse_hit_records("", producer_finished=False).descriptors, [])

    def test_blank_lines_are_ignored(self):
        parsed = parse_hit_records(b"/dev/fd/5\n\n  \n/dev/fd/7\n", producer_finished=True)
        self.assertEqual(parsed.descriptors, [5, 7])
        self.assertEqual(parsed.unexpected, 0)

    def test_a_record_that_is_not_a_descriptor_is_counted_and_dropped(self):
        parsed = parse_hit_records(
            b"/dev/fd/5\n/some/real/path.py\n/dev/fd/x\n/dev/fd/\n/dev/fd/-3\n\xff\xfe\n", producer_finished=True,
        )
        self.assertEqual(parsed.descriptors, [5])
        self.assertEqual(parsed.unexpected, 5)

    def test_unterminated_fragment_depends_on_producer_state(self):
        finished = parse_hit_records(b"/dev/fd/5\n/dev/fd/1", producer_finished=True)
        self.assertEqual(finished.descriptors, [5, 1])
        self.assertEqual(finished.unterminated, 0)

        cut_off = parse_hit_records(b"/dev/fd/5\n/dev/fd/1", producer_finished=False)
        self.assertEqual(cut_off.descriptors, [5])  # "/dev/fd/1" may have been "/dev/fd/12"
        self.assertEqual(cut_off.unterminated, 1)

    def test_rejects_unexpected_types_instead_of_guessing(self):
        with self.assertRaises(TypeError):
            parse_hit_records(12345, producer_finished=True)  # type: ignore[arg-type]


class CpythonTimeoutShapeTests(unittest.TestCase):
    def test_text_mode_timeout_still_reports_bytes_stdout(self):
        """Characterizes the premise of this boundary against the interpreter running the suite."""
        code = "import sys, time; sys.stdout.write('partial\\n'); sys.stdout.flush(); time.sleep(30)"
        with self.assertRaises(subprocess.TimeoutExpired) as ctx:
            subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=2)
        if ctx.exception.stdout is None:
            self.skipTest("child produced no output before the deadline")
        self.assertIsInstance(ctx.exception.stdout, bytes)


class SearchScopeBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory(prefix="uam-rg-boundary-")
        cls.addClassCleanup(tmp.cleanup)
        cls.root = Path(tmp.name).resolve()
        cls.alpha = cls.root / "alpha"
        cls.beta = cls.root / "beta"
        init_git_repo(cls.alpha, files={"main.py": "needle\n", "中文目录/说明.txt": "needle\n", "util.py": "needle\n"})
        init_git_repo(cls.beta, files={"README.md": "needle\n"})
        registry = RootScopeRegistry()
        registry.add_scope(RootScope(scope_id="s", root=str(cls.root), authority=_FULL_SEARCH))
        cls.registry = registry
        cls.engine = DiscoveryEngine(registry, cache_ttl=60.0)

    def search(
        self, reply: Reply, *, max_results: int = 50, engine: DiscoveryEngine | None = None,
    ) -> tuple[dict[str, Any], ScriptedRipgrep]:
        ripgrep = ScriptedRipgrep(reply)
        with mock.patch(FIND_RIPGREP, return_value="/usr/bin/rg"), ripgrep.patch():
            result = (engine or self.engine).search_scope("s", "needle", max_results=max_results)
        return result, ripgrep

    def assertIncomplete(self, result: dict, *, completeness: str, reason: str, stage: str) -> None:
        self.assertEqual(result["search_completeness"], completeness)
        self.assertEqual(result["failure_reason"], reason)
        self.assertEqual(result["failure_stage"], stage)
        self.assertTrue(result["incomplete"])
        self.assertFalse(result["safe_to_conclude_absent"])
        self.assertFalse(result["absent_within_search_domain"])

    def assertOnlyDescriptorsWereSearched(self, ripgrep: ScriptedRipgrep) -> None:
        self.assertTrue(ripgrep.ripgrep_calls, "ripgrep never ran")
        for operand in ripgrep.operands:
            self.assertIsNotNone(DESCRIPTOR_OPERAND.fullmatch(operand), operand)

    def test_timeout_with_bytes_partial_output_is_kept_and_marked_incomplete(self):
        result, _ = self.search(_times_out(self.alpha / "main.py"))
        self.assertNotIn("error", result)
        self.assertIncomplete(result, completeness="FAILED", reason="timeout", stage="timeout")
        self.assertEqual([r["path"] for r in result["results"]], ["alpha/main.py"])
        self.assertIn("remainder was not examined", result["note"])

    def test_timeout_with_text_partial_output_is_still_accepted(self):
        result, _ = self.search(_times_out(self.alpha / "main.py", as_text=True))
        self.assertIncomplete(result, completeness="FAILED", reason="timeout", stage="timeout")
        self.assertEqual(result["total_matches"], 1)

    def test_timeout_without_any_output_never_claims_absence(self):
        result, _ = self.search(_times_out_silently)
        self.assertIncomplete(result, completeness="FAILED", reason="timeout", stage="timeout")
        self.assertEqual(result["results"], [])
        self.assertEqual(result["total_matches"], 0)

    def test_timeout_drops_record_cut_off_mid_number(self):
        result, _ = self.search(_times_out(self.alpha / "main.py", cut_off="/dev/fd/1"))
        self.assertIncomplete(result, completeness="FAILED", reason="timeout", stage="timeout")
        self.assertEqual([r["path"] for r in result["results"]], ["alpha/main.py"])
        self.assertEqual(result["paths_skipped"], {"unterminated_records": 1})

    def test_clean_exit_keeps_final_record_without_newline(self):
        def reply(call: RunRecord) -> subprocess.CompletedProcess[Any]:
            return completed(call.operand_for(self.alpha / "main.py").encode("utf-8"), 0)

        result, _ = self.search(reply)
        self.assertEqual(result["search_completeness"], "COMPLETE")
        self.assertEqual(result["total_matches"], 1)
        self.assertNotIn("paths_skipped", result)

    def test_empty_output_with_no_match_exit_is_complete_and_absent_only_within_its_domain(self):
        result, _ = self.search(lambda call: completed(b"", 1))
        self.assertEqual(result["search_completeness"], "COMPLETE")
        # The search is depth- and ignore-bounded: it never proves absence from the scope itself.
        self.assertFalse(result["safe_to_conclude_absent"])
        self.assertTrue(result["absent_within_search_domain"])
        self.assertFalse(result["incomplete"])
        self.assertNotIn("failure_reason", result)
        self.assertNotIn("failure_stage", result)

    def test_none_stdout_from_a_finished_process_is_empty(self):
        result, _ = self.search(lambda call: completed(None, 1))
        self.assertEqual(result["search_completeness"], "COMPLETE")
        self.assertEqual(result["results"], [])

    def test_chinese_paths_round_trip(self):
        result, _ = self.search(_prints(self.alpha / "中文目录" / "说明.txt"))
        self.assertEqual([r["path"] for r in result["results"]], ["alpha/中文目录/说明.txt"])
        self.assertEqual(result["search_completeness"], "COMPLETE")
        json.dumps(result, ensure_ascii=False)

    def test_a_name_that_cannot_be_rendered_is_skipped_and_downgrades_to_partial(self):
        ripgrep = ScriptedRipgrep(_prints(self.alpha / "main.py"))
        listing = _listing_with_extra(self.alpha, "bad\udcff.py")
        with mock.patch(FIND_RIPGREP, return_value="/usr/bin/rg"), ripgrep.patch(), \
                mock.patch.object(os, "scandir", listing):
            result = self.engine.search_scope("s", "needle")
        self.assertIncomplete(result, completeness="PARTIAL", reason="unreadable_output", stage="decode")
        self.assertEqual([r["path"] for r in result["results"]], ["alpha/main.py"])
        self.assertEqual(result["paths_skipped"], {"undecodable_paths": 1})
        json.dumps(result)

    def test_only_unrenderable_names_never_claim_absence(self):
        ripgrep = ScriptedRipgrep(lambda call: completed(b"", 1))
        listing = _listing_with_extra(self.alpha, "\udcc3(.py")
        with mock.patch(FIND_RIPGREP, return_value="/usr/bin/rg"), ripgrep.patch(), \
                mock.patch.object(os, "scandir", listing):
            result = self.engine.search_scope("s", "needle")
        self.assertIncomplete(result, completeness="PARTIAL", reason="unreadable_output", stage="decode")
        self.assertEqual(result["results"], [])

    def test_multiple_workspaces_are_attributed_separately(self):
        result, _ = self.search(_prints(self.alpha / "main.py", self.beta / "README.md"))
        self.assertEqual(result["search_completeness"], "COMPLETE")
        by_path = {r["path"]: r.get("project_id") for r in result["results"]}
        self.assertEqual(set(by_path), {"alpha/main.py", "beta/README.md"})
        self.assertEqual(len({v for v in by_path.values() if v}), 2)

    def test_result_limit_is_partial_with_limit_stage(self):
        reply = _prints(self.alpha / "main.py", self.alpha / "util.py", self.beta / "README.md")
        result, _ = self.search(reply, max_results=2)
        self.assertEqual(result["search_completeness"], "PARTIAL")
        self.assertEqual(result["failure_reason"], "result_limit")
        self.assertEqual(result["failure_stage"], "limit")
        self.assertTrue(result["incomplete"])
        self.assertFalse(result["safe_to_conclude_absent"])
        self.assertEqual(result["total_matches"], 2)

    def test_access_denied_at_launch_reports_stage_without_leaking_message(self):
        denied = PermissionError(13, "Permission denied", "/secret/location/rg")

        def reply(call: RunRecord) -> subprocess.CompletedProcess[Any]:
            raise denied

        result, _ = self.search(reply)
        self.assertIncomplete(result, completeness="FAILED", reason="execution_error", stage="launch")
        self.assertEqual(result["error_type"], "PermissionError")
        self.assertNotIn("/secret/location", json.dumps(result))

    def test_exit_code_two_keeps_partial_output_and_reports_execute_stage(self):
        result, _ = self.search(_prints(self.alpha / "main.py", returncode=2))
        self.assertIncomplete(result, completeness="FAILED", reason="execution_error", stage="execute")
        self.assertEqual(result["total_matches"], 1)

    def test_any_other_exit_code_is_a_failure_and_its_output_is_not_trusted(self):
        result, _ = self.search(_prints(self.alpha / "main.py", returncode=101))
        self.assertIncomplete(result, completeness="FAILED", reason="execution_error", stage="execute")
        self.assertEqual(result["results"], [])

    def test_ripgrep_runs_in_bytes_mode_on_descriptors_in_a_closed_world(self):
        _, ripgrep = self.search(lambda call: completed(b"", 1))
        (call,) = ripgrep.ripgrep_calls
        self.assertNotIn("text", call.kwargs)
        self.assertNotIn("universal_newlines", call.kwargs)
        self.assertIs(call.kwargs["stdin"], subprocess.DEVNULL)
        self.assertTrue(0 < call.kwargs["timeout"] <= 30)
        self.assertEqual(set(call.kwargs["env"]), {"PATH", "LC_ALL", "HOME"})
        self.assertEqual(call.kwargs["env"]["LC_ALL"], "C")
        self.assertEqual(sorted(call.pass_fds), sorted(int(op.rsplit("/", 1)[1]) for op in call.operands))
        self.assertIn("--no-config", call.argv)
        self.assertIn("--fixed-strings", call.argv)
        self.assertIn("--no-mmap", call.argv)
        self.assertOnlyDescriptorsWereSearched(ripgrep)

    def test_an_unknown_descriptor_in_the_output_is_not_trusted(self):
        def reply(call: RunRecord) -> subprocess.CompletedProcess[Any]:
            return completed(_records(call, self.alpha / "main.py") + b"/dev/fd/9999\n", 0)

        result, _ = self.search(reply)
        self.assertIncomplete(result, completeness="PARTIAL", reason="unreadable_output", stage="decode")
        self.assertEqual([r["path"] for r in result["results"]], ["alpha/main.py"])
        self.assertEqual(result["paths_skipped"], {"unexpected_records": 1})

    def test_a_record_that_is_not_a_descriptor_is_dropped_and_counted(self):
        def reply(call: RunRecord) -> subprocess.CompletedProcess[Any]:
            return completed(_records(call, self.alpha / "main.py") + str(self.beta / "README.md").encode() + b"\n", 0)

        result, _ = self.search(reply)
        self.assertIncomplete(result, completeness="PARTIAL", reason="unreadable_output", stage="decode")
        self.assertEqual([r["path"] for r in result["results"]], ["alpha/main.py"])
        self.assertEqual(result["paths_skipped"], {"unexpected_records": 1})

    def test_a_ripgrep_failure_never_widens_the_search(self):
        def refuses(call: RunRecord) -> subprocess.CompletedProcess[Any]:
            raise OSError(5, "Input/output error")

        scripts = {
            "exit 2": _prints(returncode=2),
            "launch error": refuses,
            "timeout": _times_out_silently,
        }
        for label, reply in scripts.items():
            with self.subTest(label):
                result, ripgrep = self.search(reply)
                self.assertTrue(result["incomplete"])
                self.assertEqual(len(ripgrep.ripgrep_calls), 1, "a failed search must not be retried wider")
                self.assertOnlyDescriptorsWereSearched(ripgrep)

    def test_output_over_the_budget_fails_closed_instead_of_being_trusted(self):
        engine = DiscoveryEngine(self.registry, cache_ttl=60.0, search_limits=ScopeSearchLimits(max_output_bytes=8))
        result, _ = self.search(_prints(self.alpha / "main.py", self.alpha / "util.py"), engine=engine)
        self.assertIncomplete(result, completeness="FAILED", reason="execution_error", stage="execute")
        self.assertEqual(result["error_type"], "OutputBudget")
        self.assertEqual(result["results"], [])


class SearchScopeAuditAndMcpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory(prefix="uam-rg-boundary-gw-")
        state = tempfile.TemporaryDirectory(prefix="uam-rg-boundary-state-")
        cls.addClassCleanup(tmp.cleanup)
        cls.addClassCleanup(state.cleanup)
        cls.root = Path(tmp.name).resolve()
        cls.state_dir = state.name
        cls.repo = cls.root / "repo"
        init_git_repo(cls.repo, files={"main.py": "needle\n"})
        config = cls.root / "config"
        cls.registry_path = write_workspace_registry(config / "workspaces.json", [])
        (config / "root_scopes.json").write_text(json.dumps({
            "schema_version": "root-scope-registry-v1",
            "scopes": [{
                "scope_id": "s", "root": str(cls.root),
                "authority": {
                    "discover": True, "metadata_read": True, "content_read": True,
                    "text_search": True, "git_observe": True, "classify": True,
                    "index": True, "relate": True, "auto_admit": True,
                },
            }],
            "overrides": {},
        }), encoding="utf-8")

    def test_gateway_audit_records_incompleteness_of_a_timed_out_search(self):
        gateway = MiddlewareGateway(str(self.registry_path), self.state_dir)
        ripgrep = ScriptedRipgrep(_times_out(self.repo / "main.py"))
        with mock.patch(FIND_RIPGREP, return_value="/usr/bin/rg"), ripgrep.patch():
            result = gateway.search_scope("s", "needle")
        self.assertEqual(result["failure_reason"], "timeout")

        records = [json.loads(raw) for raw in Path(self.state_dir, "audit.jsonl").read_text().splitlines()]
        details = records[-1]["details"]
        self.assertEqual(records[-1]["action"], "search_scope")
        self.assertEqual(details["search_completeness"], "FAILED")
        self.assertEqual(details["failure_reason"], "timeout")
        self.assertEqual(details["failure_stage"], "timeout")
        self.assertTrue(HashChainedAuditLog(Path(self.state_dir, "audit.jsonl")).verify()["valid"])

    @unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
    def test_mcp_tool_returns_partial_result_instead_of_a_type_error(self):
        server = create_session_read_server(str(self.registry_path), self.state_dir)
        tool = server._tool_manager._tools["uam_search_scope"].fn
        ripgrep = ScriptedRipgrep(_times_out(self.repo / "main.py"))
        with mock.patch(FIND_RIPGREP, return_value="/usr/bin/rg"), ripgrep.patch():
            payload = json.loads(asyncio.run(tool(scope_id="s", query="needle", ctx=None)))
        self.assertNotIn("error", payload)
        self.assertEqual(payload["search_completeness"], "FAILED")
        self.assertEqual(payload["failure_reason"], "timeout")
        self.assertTrue(payload["incomplete"])
        self.assertEqual([r["path"] for r in payload["results"]], ["repo/main.py"])


if __name__ == "__main__":
    unittest.main()
