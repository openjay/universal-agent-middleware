"""R3-04: exploration states what it observed, per claim, and does not turn "could not look" into "nothing there".

r2 collapsed a file that was absent, oversized, refused by policy, refused by the operating system and changed under the
walk into one ``None``: "no hint". So a project whose ``README.md`` was unreadable, or whose scope grants no content
reading at all, still came out as ``SOURCE_OBSERVED`` with no runtime gap, which reads as "source observed, no runtime
dependency". The retrieval plan also sized a file by ``stat`` through a link, so the size of a protected target
(``README.md -> .secrets.env``) reached ``total_bytes_estimate``.

What r3 keeps: ``SOURCE_OBSERVED`` still means the project's source is accessible (the scope grants content reading and
the directory could be scanned); one unreadable OPTIONAL file does not by itself downgrade a project. What r3 fixes is
the granularity and the correspondence of the evidence: each claim ("runtime references", "source content") carries one
of ``DENIED``, ``UNREADABLE``, ``BUDGET_EXCEEDED``, ``NOT_OBSERVED``, ``OBSERVED_NO_FINDINGS``, ``OBSERVED_WITH_FINDINGS``,
and the verdict is a function of that evidence (checked below against an independent oracle over a grid of worlds).
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

from universal_agent_middleware.discovery import DiscoveryEngine
from universal_agent_middleware.exploration import ExplorationEngine
from universal_agent_middleware.root_scope import RootScope, RootScopeAuthority, RootScopeRegistry

from synthetic_fixtures import init_git_repo

SCOPE = "r3-scope"
PROJECT = "proj"
SECRET_A = "R3_SECRET_BODY_A_" + "a" * 40
SECRET_B = "R3_SECRET_BODY_B_" + "b" * 400  # a different SIZE as well as different bytes
CLEAN = "# project\nnothing about running anything\n"
WITH_REFERENCE = "# project\nrun: docker compose up\n"
OVERSIZED = "x" * 300_000

UNRESOLVED = {"DENIED", "UNREADABLE", "BUDGET_EXCEEDED", "NOT_OBSERVED"}
FIXED_FILES = ("pyproject.toml", "package.json", "Makefile", "docker-compose.yml", "docker-compose.yaml", "README.md")


class World:
    """A scope containing one Git project, with the engines over it."""

    def __init__(self, *, content_read: bool = True) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="uam-r3-expl-")
        self.root = Path(self._tmp.name).resolve()
        self.project = self.root / PROJECT
        init_git_repo(self.project, files={"main.py": "print('x')\n"})
        self.registry = RootScopeRegistry()
        self.registry.add_scope(RootScope(
            scope_id=SCOPE, root=str(self.root),
            authority=RootScopeAuthority(
                discover=True, metadata_read=True, content_read=content_read, text_search=True, git_observe=True,
                classify=True, index=True, relate=True,
            ),
        ))

    def cleanup(self) -> None:
        self._tmp.cleanup()

    def engine(self, *, enriched: bool = False) -> ExplorationEngine:
        """``enriched``: Git activity is observed first, so that the project counts as active (what_am_i_missing)."""
        if not enriched:
            return ExplorationEngine(DiscoveryEngine(self.registry, cache_ttl=0.0), self.registry)
        discovery = DiscoveryEngine(self.registry, cache_ttl=60.0)
        discovery.scope_inventory(SCOPE, enrich_git=True, git_budget=50)
        return ExplorationEngine(discovery, self.registry)

    def explain(self) -> dict[str, Any]:
        return self.engine().explain_coverage(SCOPE, PROJECT)

    def explore(self, intent: str = "") -> dict[str, Any]:
        return self.engine().explore(SCOPE, intent=intent)

    def put(self, name: str, text: str) -> Path:
        path = self.project / name
        path.write_text(text, encoding="utf-8")
        return path


def observed_surface(result: dict[str, Any]) -> dict[str, Any]:
    """The ``runtime_references`` claim of an ``explain_coverage`` result."""
    return result["assessment"]["evidence"]["runtime_references"]


class WorldCase(unittest.TestCase):
    content_read = True

    def setUp(self) -> None:
        self.world = World(content_read=self.content_read)
        self.addCleanup(self.world.cleanup)


class UnresolvedFileTests(WorldCase):
    def assertIncomplete(self, result: dict[str, Any], status: str, name: str) -> None:
        claim = observed_surface(result)
        self.assertEqual(claim["status"], status, claim)
        self.assertIn({"file": name, "status": status}, [
            {"file": item["file"], "status": item["status"]} for item in claim["unchecked"]
        ])
        gaps = [gap for gap in result["coverage_gaps"] if gap["state"] == "reference_check_incomplete"]
        self.assertEqual(len(gaps), 1, result["coverage_gaps"])
        self.assertEqual(gaps[0]["surface"], "runtime")
        self.assertIn(f"{name}: {status}", gaps[0]["evidence_refs"])

    def test_an_unreadable_file_is_not_observed_as_empty(self) -> None:
        path = self.world.put("README.md", WITH_REFERENCE)
        path.chmod(0)
        self.addCleanup(path.chmod, 0o600)
        result = self.world.explain()
        self.assertIncomplete(result, "UNREADABLE", "README.md")
        self.assertNotIn("OBSERVED_NO_FINDINGS", observed_surface(result)["status"])

    def test_a_file_over_the_read_budget_is_budget_exceeded_not_absent(self) -> None:
        self.world.put("README.md", OVERSIZED)
        self.assertIncomplete(self.world.explain(), "BUDGET_EXCEEDED", "README.md")

    def test_a_link_to_a_protected_name_is_denied_not_absent(self) -> None:
        self.world.put(".secrets.env", f"TOKEN={SECRET_A}\n")
        os.symlink(".secrets.env", self.world.project / "README.md")
        self.assertIncomplete(self.world.explain(), "DENIED", "README.md")

    def test_a_pipe_in_place_of_a_file_is_not_observed_and_never_opened(self) -> None:
        os.mkfifo(self.world.project / "README.md")
        self.assertIncomplete(self.world.explain(), "NOT_OBSERVED", "README.md")

    def test_mixed_reasons_are_all_listed_and_the_claim_is_not_observed(self) -> None:
        readme = self.world.put("README.md", CLEAN)
        readme.chmod(0)
        self.addCleanup(readme.chmod, 0o600)
        self.world.put("Makefile", OVERSIZED)
        result = self.world.explain()
        claim = observed_surface(result)
        self.assertEqual(claim["status"], "NOT_OBSERVED")
        self.assertEqual(
            {(item["file"], item["status"]) for item in claim["unchecked"]},
            {("README.md", "UNREADABLE"), ("Makefile", "BUDGET_EXCEEDED")},
        )

    def test_one_unreadable_optional_file_does_not_downgrade_a_readable_source_by_itself(self) -> None:
        readme = self.world.put("README.md", CLEAN)
        readme.chmod(0)
        self.addCleanup(readme.chmod, 0o600)
        assessment = self.world.explain()["assessment"]
        self.assertEqual(assessment["verdict"], "SOURCE_OBSERVED")
        self.assertIn("UNKNOWN", assessment["note"])  # the claim is scoped: those references are unknown, not absent
        self.assertIn("README.md", json.dumps(assessment["evidence"]))

    def test_an_absent_optional_file_is_an_observation_and_changes_nothing(self) -> None:
        result = self.world.explain()
        claim = observed_surface(result)
        self.assertEqual(claim["status"], "OBSERVED_NO_FINDINGS")
        self.assertEqual(claim["unchecked"], [])
        self.assertEqual(result["assessment"]["verdict"], "SOURCE_OBSERVED")
        self.assertEqual(result["total_gaps"], 0)

    def test_a_clean_readable_file_is_observed_no_findings(self) -> None:
        self.world.put("README.md", CLEAN)
        claim = observed_surface(self.world.explain())
        self.assertEqual((claim["status"], claim["unchecked"]), ("OBSERVED_NO_FINDINGS", []))

    def test_a_finding_is_still_a_runtime_gap_and_still_makes_the_project_partial(self) -> None:
        self.world.put("README.md", WITH_REFERENCE)
        result = self.world.explain()
        self.assertEqual(observed_surface(result)["status"], "OBSERVED_WITH_FINDINGS")
        self.assertEqual(result["assessment"]["verdict"], "PARTIAL")
        self.assertTrue(any(g["surface"] == "runtime" and g["state"] == "referenced_not_observed"
                            for g in result["coverage_gaps"]))

    def test_findings_and_unresolved_files_are_both_reported(self) -> None:
        self.world.put("package.json", '{"scripts": {"start": "launchctl load x"}}\n')
        readme = self.world.put("README.md", CLEAN)
        readme.chmod(0)
        self.addCleanup(readme.chmod, 0o600)
        result = self.world.explain()
        states = {gap["state"] for gap in result["coverage_gaps"] if gap["surface"] == "runtime"}
        self.assertEqual(states, {"referenced_not_observed", "reference_check_incomplete"})
        self.assertEqual(result["assessment"]["verdict"], "PARTIAL")


class ScopeWithoutContentReadTests(WorldCase):
    content_read = False

    def test_a_scope_that_does_not_grant_content_reading_is_not_source_observed(self) -> None:
        self.world.put("README.md", CLEAN)
        result = self.world.explain()
        assessment = result["assessment"]
        self.assertNotEqual(assessment["verdict"], "SOURCE_OBSERVED", assessment["note"])
        self.assertEqual(assessment["verdict"], "PARTIAL")
        self.assertEqual(assessment["evidence"]["source_content"]["status"], "DENIED")
        self.assertEqual(observed_surface(result)["status"], "DENIED")
        surfaces = {gap["surface"] for gap in result["coverage_gaps"]}
        self.assertIn("source_content", surfaces)

    def test_the_project_verdict_agrees_with_the_scope_surfaces_the_missing_report_states(self) -> None:
        self.world.put("README.md", CLEAN)
        missing = self.world.engine(enriched=True).what_am_i_missing(SCOPE)
        self.assertGreater(missing["active_projects_analyzed"], 0, "the project must count as active for this check")
        self.assertEqual(missing["scope_surfaces"]["source_content"], "not_authorized")
        self.assertIn("source_content", {gap["surface"] for gap in missing["gaps"]})
        self.assertIn("source_content", {item["surface"] for item in missing["scope_escalation_suggestions"]})


class RetrievalPlanTests(WorldCase):
    def plan_files(self, result: dict[str, Any]) -> list[str]:
        return [name for item in result["retrieval_plan"]["items"] for name in item["files"]]

    def test_the_size_of_a_protected_link_target_never_reaches_the_plan(self) -> None:
        estimates = []
        for body in (SECRET_A, SECRET_B):
            world = World()
            self.addCleanup(world.cleanup)
            (world.project / ".secrets.env").write_text(f"TOKEN={body}\n", encoding="utf-8")
            os.symlink(".secrets.env", world.project / "README.md")
            plan = world.explore()["retrieval_plan"]
            estimates.append((plan["total_files"], plan["total_bytes_estimate"], json.dumps(plan["items"])))
        self.assertEqual(estimates[0], estimates[1])
        self.assertEqual(estimates[0][0], 0, "a file the reader would refuse must not be planned for hydration")

    def test_a_file_that_cannot_be_read_is_not_planned_and_says_why(self) -> None:
        path = self.world.put("README.md", CLEAN)
        path.chmod(0)
        self.addCleanup(path.chmod, 0o600)
        result = self.world.explore()
        self.assertNotIn("README.md", self.plan_files(result))
        unplanned = [entry for item in result["retrieval_plan"]["items"] for entry in item.get("unplanned", [])]
        unplanned += result["retrieval_plan"].get("unplanned", [])
        self.assertIn({"file": "README.md", "status": "UNREADABLE"}, [
            {"file": entry["file"], "status": entry["status"]} for entry in unplanned
        ])

    def test_control_a_readable_file_is_planned_with_its_real_size(self) -> None:
        self.world.put("README.md", CLEAN)
        result = self.world.explore()
        self.assertIn("README.md", self.plan_files(result))
        self.assertEqual(result["retrieval_plan"]["total_bytes_estimate"], len(CLEAN.encode()))


class MetamorphicTests(unittest.TestCase):
    def test_changing_only_the_body_of_a_protected_target_changes_no_exploration_output(self) -> None:
        outputs = []
        for body in (SECRET_A, SECRET_B):
            world = World()
            self.addCleanup(world.cleanup)
            (world.project / ".secrets.env").write_text(f"TOKEN={body}\n", encoding="utf-8")
            os.symlink(".secrets.env", world.project / "README.md")
            explain = world.explain()
            explore = world.explore("secrets env")
            missing = world.engine().what_am_i_missing(SCOPE)
            for result in (explain, explore, missing):
                result.pop("observed_at", None)
            blob = json.dumps({"explain": explain, "explore": explore, "missing": missing}, sort_keys=True)
            self.assertNotIn(SECRET_A, blob)
            self.assertNotIn(SECRET_B, blob)
            outputs.append(blob.replace(str(world.root), "<ROOT>"))  # each world lives in its own temporary directory
        self.assertEqual(outputs[0], outputs[1])


README_STATES = ("absent", "clean", "reference", "unreadable", "oversized", "denied_link", "pipe")
PACKAGE_STATES = ("absent", "reference")


def oracle(content_read: bool, readme: str, package: str) -> dict[str, Any]:
    """What the evidence MUST say, written independently of the implementation."""
    per_file: dict[str, str] = {}
    findings = False
    for name, state in (("README.md", readme), ("package.json", package)):
        if state == "absent":
            continue
        if not content_read:
            per_file[name] = "DENIED"
        elif state == "clean":
            continue
        elif state == "reference":
            findings = True
        else:
            per_file[name] = {
                "unreadable": "UNREADABLE", "oversized": "BUDGET_EXCEEDED", "denied_link": "DENIED", "pipe": "NOT_OBSERVED",
            }[state]
    if not content_read:
        # every fixed file is unchecked in a scope that grants no content reading, present or not
        per_file = {name: "DENIED" for name in FIXED_FILES}
    if per_file:
        distinct = set(per_file.values())
        claim = distinct.pop() if len(distinct) == 1 else "NOT_OBSERVED"
    else:
        claim = "OBSERVED_WITH_FINDINGS" if findings else "OBSERVED_NO_FINDINGS"
    verdict = "PARTIAL" if (findings or not content_read) else "SOURCE_OBSERVED"
    return {"claim": claim, "unchecked": per_file, "verdict": verdict, "findings": findings and content_read}


class VerdictAgreementTests(unittest.TestCase):
    """The verdict and the per-claim evidence are one story, over a grid of worlds."""

    def build(self, world: World, readme: str, package: str) -> list[Path]:
        restore: list[Path] = []
        if readme == "clean":
            world.put("README.md", CLEAN)
        elif readme == "reference":
            world.put("README.md", WITH_REFERENCE)
        elif readme == "unreadable":
            restore.append(world.put("README.md", CLEAN))
            restore[-1].chmod(0)
        elif readme == "oversized":
            world.put("README.md", OVERSIZED)
        elif readme == "denied_link":
            world.put(".secrets.env", f"TOKEN={SECRET_A}\n")
            os.symlink(".secrets.env", world.project / "README.md")
        elif readme == "pipe":
            os.mkfifo(world.project / "README.md")
        if package == "reference":
            world.put("package.json", '{"scripts": {"start": "systemctl start x"}}\n')
        return restore

    def test_grid(self) -> None:
        for content_read in (True, False):
            for readme in README_STATES:
                for package in PACKAGE_STATES:
                    label = f"content_read={content_read} readme={readme} package={package}"
                    with self.subTest(world=label):
                        world = World(content_read=content_read)
                        self.addCleanup(world.cleanup)
                        for path in self.build(world, readme, package):
                            self.addCleanup(path.chmod, 0o600)
                        result = world.explain()
                        expected = oracle(content_read, readme, package)
                        claim = observed_surface(result)
                        self.assertEqual(claim["status"], expected["claim"], label)
                        self.assertEqual(
                            {item["file"]: item["status"] for item in claim["unchecked"]}, expected["unchecked"], label)
                        self.assertEqual(result["assessment"]["verdict"], expected["verdict"], label)
                        self.assertEqual(claim["findings"], expected["findings"], label)
                        if claim["unchecked"]:
                            self.assertNotEqual(claim["status"], "OBSERVED_NO_FINDINGS", label)


if __name__ == "__main__":
    unittest.main()
