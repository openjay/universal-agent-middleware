"""Release acceptance: an exact, declaration-driven judgement of the post-activation Doctor report.

Reports come from the real Doctor on a production-shaped fixture (four readable workspaces, two
registrations whose roots are gone, six canaries), so the predicate is tested against the shape
production actually produces rather than a hand-written approximation. Nothing is accepted unless
it was declared; a declaration describes the present state, it is not a tolerance.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from release_fixtures import (
    STALE, VALID, declaration, doctor_report, production_shaped, write_declaration,
)
from test_hardening import runtime_fixture  # noqa: F401  (pytest fixture import)

from universal_agent_middleware import release_acceptance as acceptance

CANARY_IDS = [*VALID, *STALE]


@pytest.fixture
def declared(tmp_path):
    return acceptance.load_declaration(write_declaration(tmp_path / "declaration.json"))


@pytest.fixture
def degraded(runtime_fixture, tmp_path):
    r, manifest, _ = runtime_fixture
    updated = production_shaped(r, manifest, tmp_path)
    return doctor_report(updated, manifest), Path(updated["current_release"]).name


def judge(report: Any, release_id: str, declaration_: dict[str, Any] | None, *, post_ok: bool = True,
          canary_ids: list[str] | None = None) -> dict[str, Any]:
    return acceptance.evaluate(report, declaration=declaration_, post_ok=post_ok, release_id=release_id,
                               canary_ids=CANARY_IDS if canary_ids is None else canary_ids)


def codes(verdict: dict[str, Any]) -> set[str]:
    return {item["code"] for item in verdict["violations"]}


def test_the_fixture_reproduces_the_production_report_shape(degraded):
    report, _ = degraded
    assert (report["overall"], report["severity"]) == ("DEGRADED", "P2")
    registry = report["checks"]["workspace_registry"]
    assert (registry["registered"], registry["available"]) == (6, 4)
    assert {item["workspace_id"]: item["reason"] for item in registry["unavailable"]} == {
        name: "root_missing" for name in STALE}
    results = report["checks"]["workspace_canary"]["results"]
    assert sum(item["status"] == "PASS" for item in results) == 4 and len(results) == 6


def test_exactly_the_declared_gaps_are_accepted(degraded, declared):
    report, release_id = degraded
    verdict = judge(report, release_id, declared)
    assert verdict["accepted"], verdict["violations"]
    assert verdict["mode"] == "declared_gaps"
    assert verdict["declaration"]["sha256"] == declared["sha256"]
    assert verdict["observed"]["gaps"] == [
        "registry:atlas-main:root_missing", "registry:atlas-pr7:root_missing",
        "canary:atlas-main:workspace_unavailable", "canary:atlas-pr7:workspace_unavailable"]


def test_the_same_report_is_rejected_without_a_declaration(degraded):
    report, release_id = degraded
    verdict = judge(report, release_id, None)
    assert not verdict["accepted"] and verdict["mode"] == "strict"
    assert codes(verdict) == {"unexpected_unavailable", "unexpected_canary_failure"}


def test_a_gap_free_report_is_accepted_strictly(runtime_fixture):
    r, manifest, _ = runtime_fixture
    report = doctor_report(r, manifest)
    verdict = judge(report, Path(r["current_release"]).name, None, canary_ids=["fixture"])
    assert report["overall"] == "READY"
    assert verdict["accepted"] and verdict["observed"]["gaps"] == []


def test_a_ready_doctor_does_not_override_failed_post_activation_steps(runtime_fixture):
    r, manifest, _ = runtime_fixture
    report = doctor_report(r, manifest)
    verdict = judge(report, Path(r["current_release"]).name, None, post_ok=False, canary_ids=["fixture"])
    assert report["overall"] == "READY"
    assert not verdict["accepted"] and codes(verdict) == {"post_steps_failed"}


def test_an_extra_unavailable_workspace_is_rejected(runtime_fixture, tmp_path, declared):
    r, manifest, _ = runtime_fixture
    updated = production_shaped(r, manifest, tmp_path, stale=(*STALE, "third-gone"))
    report = doctor_report(updated, manifest)
    verdict = judge(report, Path(r["current_release"]).name, declared, canary_ids=[*CANARY_IDS, "third-gone"])
    assert not verdict["accepted"]
    assert {"unexpected_unavailable", "registry_count_mismatch", "unexpected_canary_failure",
            "canary_total_mismatch"} <= codes(verdict)


def test_a_different_unavailable_reason_is_rejected(runtime_fixture, tmp_path, declared):
    r, manifest, _ = runtime_fixture
    updated = production_shaped(r, manifest, tmp_path)
    (tmp_path / "gone" / "atlas-main").parent.mkdir(parents=True)
    (tmp_path / "gone" / "atlas-main").write_text("a file where a directory belongs")
    report = doctor_report(updated, manifest)
    verdict = judge(report, Path(r["current_release"]).name, declared)
    assert not verdict["accepted"]
    assert {"unavailable_reason_mismatch", "canary_failure_not_root_gap"} <= codes(verdict)


def test_a_declared_gap_that_no_longer_exists_is_rejected(runtime_fixture, tmp_path, declared):
    r, manifest, _ = runtime_fixture
    updated = production_shaped(r, manifest, tmp_path)
    restored = tmp_path / "gone" / "atlas-main"
    restored.mkdir(parents=True)
    (restored / "README.md").write_text("restored\n")
    report = doctor_report(updated, manifest)
    verdict = judge(report, Path(r["current_release"]).name, declared)
    assert not verdict["accepted"]
    assert {"declared_gap_not_observed", "registry_count_mismatch",
            "declared_canary_gap_not_observed"} <= codes(verdict)


def test_a_failing_canary_of_a_readable_workspace_is_rejected(runtime_fixture, tmp_path, declared):
    r, manifest, _ = runtime_fixture
    updated = production_shaped(r, manifest, tmp_path)
    (tmp_path / "roots" / "ws-a" / "README.md").unlink()
    report = doctor_report(updated, manifest)
    verdict = judge(report, Path(r["current_release"]).name, declared)
    assert not verdict["accepted"] and codes(verdict) == {"unexpected_canary_failure"}
    assert verdict["violations"][0]["detail"].startswith("ws-a ")


@pytest.mark.parametrize("name,status", [
    ("mcp", "ERROR"), ("mcp", "FAIL"), ("core", "ERROR"), ("audit_chain", "FAIL"), ("credential", "FAIL"),
    ("release", "FAIL"), ("runtime_paths", "FAIL"), ("tunnel", "FAIL"), ("tunnel", "UNKNOWN"),
    ("reality_index", "UNKNOWN"), ("reality_index", "DEGRADED"),
])
def test_a_required_check_that_is_not_pass_rejects_even_with_declared_gaps(degraded, declared, name, status):
    report, release_id = degraded
    mutated = copy.deepcopy(report)
    mutated["checks"][name]["status"] = status
    verdict = judge(mutated, release_id, declared)
    assert not verdict["accepted"]
    assert {"code": "check_not_pass", "detail": f"{name}={status}"} in verdict["violations"]


def test_a_missing_required_check_rejects(degraded, declared):
    report, release_id = degraded
    mutated = copy.deepcopy(report)
    del mutated["checks"]["reality_index"]
    verdict = judge(mutated, release_id, declared)
    assert {"code": "check_missing", "detail": "reality_index"} in verdict["violations"]


def test_an_unlisted_failing_check_rejects(degraded, declared):
    report, release_id = degraded
    mutated = copy.deepcopy(report)
    mutated["checks"]["freeze_latch"] = {"status": "FAIL", "severity": "P0"}
    verdict = judge(mutated, release_id, declared)
    assert {"code": "check_not_pass", "detail": "freeze_latch=FAIL"} in verdict["violations"]


def test_the_report_must_describe_the_release_that_was_activated(degraded, declared):
    report, _ = degraded
    verdict = judge(report, "v9.9.9+" + "c" * 40, declared)
    assert codes(verdict) == {"release_identity_mismatch"}


@pytest.mark.parametrize("report", [None, {}, {"checks": []}, "READY"])
def test_an_unusable_doctor_report_is_rejected(report, declared):
    verdict = judge(report, "any", declared)
    assert not verdict["accepted"] and "doctor_report_invalid" in codes(verdict)


def test_unevaluated_coverage_evidence_is_rejected(degraded, declared):
    report, release_id = degraded
    mutated = copy.deepcopy(report)
    mutated["checks"]["workspace_registry"] = {"status": "ERROR", "reason": "boom"}
    mutated["checks"]["workspace_canary"]["status"] = "UNKNOWN"
    verdict = judge(mutated, release_id, declared)
    assert {"registry_not_evaluated", "canaries_not_evaluated"} <= codes(verdict)


def test_the_canary_results_must_cover_the_configured_canaries(degraded, declared):
    report, release_id = degraded
    verdict = judge(report, release_id, declared, canary_ids=CANARY_IDS[:-1])
    assert {"canary_set_mismatch", "canary_total_mismatch"} <= codes(verdict)


def test_the_doctor_verdict_must_agree_with_the_gaps(degraded, declared):
    report, release_id = degraded
    mutated = copy.deepcopy(report)
    mutated["overall"] = "READY"
    assert "doctor_overall_unexpected" in codes(judge(mutated, release_id, declared))
    mutated.update(overall="DEGRADED", severity="P1")
    assert "doctor_overall_unexpected" in codes(judge(mutated, release_id, declared))


@pytest.fixture
def ready(runtime_fixture):
    r, manifest, _ = runtime_fixture
    report = doctor_report(r, manifest)
    assert report["overall"] == "READY"
    return report, Path(r["current_release"]).name


def strict(report: Any, release_id: str) -> dict[str, Any]:
    return judge(report, release_id, None, canary_ids=["fixture"])


def test_a_summary_that_contradicts_the_canary_results_is_rejected(ready):
    report, release_id = ready
    assert strict(report, release_id)["accepted"]

    failing_summary = copy.deepcopy(report)
    failing_summary["checks"]["workspace_canary"]["status"] = "FAIL"
    verdict = strict(failing_summary, release_id)
    assert not verdict["accepted"] and codes(verdict) == {"canary_status_inconsistent"}

    passing_summary = copy.deepcopy(report)
    passing_summary["checks"]["workspace_canary"]["results"][0]["status"] = "FAIL"
    verdict = strict(passing_summary, release_id)
    assert not verdict["accepted"]
    assert {"canary_status_inconsistent", "unexpected_canary_failure"} <= codes(verdict)

    empty = copy.deepcopy(report)
    empty["checks"]["workspace_canary"]["results"] = []
    assert {"canary_status_inconsistent", "canary_set_mismatch"} <= codes(strict(empty, release_id))


def test_a_degraded_registry_summary_without_gaps_is_rejected(ready):
    report, release_id = ready
    mutated = copy.deepcopy(report)
    mutated["checks"]["workspace_registry"]["status"] = "DEGRADED"
    verdict = strict(mutated, release_id)
    assert not verdict["accepted"] and codes(verdict) == {"registry_status_inconsistent"}


def test_a_passing_registry_summary_over_listed_gaps_is_rejected(degraded, declared):
    report, release_id = degraded
    mutated = copy.deepcopy(report)
    mutated["checks"]["workspace_registry"]["status"] = "PASS"
    verdict = judge(mutated, release_id, declared)
    assert not verdict["accepted"] and "registry_status_inconsistent" in codes(verdict)


@pytest.mark.parametrize("registered,available,code", [
    (4, 9, "registry_counts_inconsistent"),
    (4, 3, "registry_counts_inconsistent"),
    (0, 1, "registry_counts_inconsistent"),
    (True, True, "registry_counts_invalid"),
    (4.0, 4.0, "registry_counts_invalid"),
    (-1, -1, "registry_counts_invalid"),
    ("4", "4", "registry_counts_invalid"),
    (None, None, "registry_counts_invalid"),
])
def test_registry_counts_must_be_non_negative_integers_that_agree_with_the_gap_list(
        ready, registered, available, code):
    report, release_id = ready
    mutated = copy.deepcopy(report)
    mutated["checks"]["workspace_registry"].update(registered=registered, available=available)
    verdict = strict(mutated, release_id)
    assert not verdict["accepted"] and code in codes(verdict), verdict["violations"]

    coverage = {**_coverage(1, []), "registered": registered, "available": available}
    assert code in {item["code"] for item in acceptance.check_coverage(coverage, None)}


def test_inconsistent_counts_are_rejected_in_declared_gap_mode_too(degraded, declared):
    report, release_id = degraded
    mutated = copy.deepcopy(report)
    mutated["checks"]["workspace_registry"].update(registered=6, available=9)
    verdict = judge(mutated, release_id, declared)
    assert not verdict["accepted"]
    assert {"registry_counts_inconsistent", "registry_count_mismatch"} <= codes(verdict)

    smuggled = copy.deepcopy(report)
    smuggled["checks"]["workspace_registry"].update(registered=True, available=True)
    assert "registry_counts_invalid" in codes(judge(smuggled, release_id, declared))


def test_malformed_unavailable_entries_are_not_evaluated(ready):
    report, release_id = ready
    for entry in ({"workspace_id": None, "reason": "root_missing"}, {"workspace_id": "a", "reason": None},
                  {"workspace_id": "", "reason": "root_missing"}, "a"):
        mutated = copy.deepcopy(report)
        mutated["checks"]["workspace_registry"]["unavailable"] = [entry]
        assert "registry_not_evaluated" in codes(strict(mutated, release_id)), entry


def test_the_coverage_gate_rejects_numbers_that_contradict_each_other(declared):
    assert acceptance.check_coverage(_coverage(6, list(STALE)), declared) == []

    def gate(coverage: dict[str, Any], declaration_=None) -> set[str]:
        return {item["code"] for item in acceptance.check_coverage(coverage, declaration_)}

    assert gate({**_coverage(4, []), "available": 9}) == {"registry_counts_inconsistent"}
    assert gate({**_coverage(6, list(STALE)), "available": 6}) == {"registry_counts_inconsistent",
                                                                    "unexpected_unavailable"}
    for complete in (False, "yes", None, 1):
        assert gate({**_coverage(6, []), "complete": complete}) == {"registry_complete_inconsistent"}
    assert gate({**_coverage(6, list(STALE)), "complete": True}, declared) == {"registry_complete_inconsistent"}
    without_complete = _coverage(6, [])
    del without_complete["complete"]
    assert gate(without_complete) == {"registry_complete_inconsistent"}


def test_the_declaration_records_the_digest_of_the_exact_bytes(tmp_path):
    path = write_declaration(tmp_path / "declaration.json")
    loaded = acceptance.load_declaration(path)
    assert loaded["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert loaded["registered"] == 6 and loaded["available"] == 4
    assert loaded["unavailable"] == {name: "root_missing" for name in STALE}
    assert loaded["canary_total"] == 6 and loaded["canary_failing"] == sorted(STALE)


def _mutate(path: str, value: Any):
    def apply(data: dict[str, Any]) -> None:
        target = data
        *parents, leaf = path.split(".")
        for key in parents:
            target = target[key]
        target[leaf] = value
    return apply


@pytest.mark.parametrize("mutation,message", [
    (_mutate("schema_version", "uam-release-acceptance-v0"), "unsupported declaration schema"),
    (_mutate("tolerance", 1), "exactly these keys"),
    (_mutate("registry.unavailable", [{"workspace_id": "a", "reason": "disk_full"}]), "unsupported unavailable reason"),
    (_mutate("registry.unavailable", [{"workspace_id": "a", "reason": "root_missing"}] * 2), "invalid or duplicate"),
    (_mutate("registry.unavailable", "none"), "must be a list"),
    (_mutate("registry.available", 5), "registry.available must equal"),
    (_mutate("registry.registered", -1), "non-negative integer"),
    (_mutate("registry.registered", True), "non-negative integer"),
    (_mutate("canaries.failing", ["atlas-main", "unknown-id"]), "canaries.failing must name unavailable"),
    (_mutate("canaries.total", 1), "canaries.failing must name unavailable"),
    (_mutate("canaries.failing", ["atlas-main", "atlas-main"]), "unique non-empty workspace ids"),
])
def test_a_malformed_declaration_is_rejected(tmp_path, mutation, message):
    data = declaration()
    mutation(data)
    path = write_declaration(tmp_path / "declaration.json", data)
    with pytest.raises(acceptance.AcceptanceError, match=message):
        acceptance.load_declaration(path)


def test_an_unreadable_or_non_json_declaration_is_rejected(tmp_path):
    with pytest.raises(acceptance.AcceptanceError, match="cannot read"):
        acceptance.load_declaration(tmp_path / "missing.json")
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    with pytest.raises(acceptance.AcceptanceError, match="not valid JSON"):
        acceptance.load_declaration(broken)


def _coverage(registered: int, unavailable: list[str]) -> dict[str, Any]:
    return {"schema_version": "workspace-coverage-v1", "registered": registered,
            "available": registered - len(unavailable),
            "unavailable": [{"workspace_id": name, "label": name, "reason": "root_missing"} for name in unavailable],
            "complete": not unavailable}


def test_the_pre_activation_coverage_gate_follows_the_declaration(declared):
    assert acceptance.check_coverage(_coverage(6, list(STALE)), declared) == []
    strict = acceptance.check_coverage(_coverage(6, list(STALE)), None)
    assert {item["code"] for item in strict} == {"unexpected_unavailable"}
    assert acceptance.check_coverage(_coverage(6, []), None) == []
    restored = acceptance.check_coverage(_coverage(6, []), declared)
    assert {item["code"] for item in restored} == {"registry_count_mismatch", "declared_gap_not_observed"}
    extra = acceptance.check_coverage(_coverage(7, [*STALE, "third"]), declared)
    assert {"registry_count_mismatch", "unexpected_unavailable"} <= {item["code"] for item in extra}


@pytest.mark.parametrize("coverage,code", [
    (None, "coverage_unavailable"), ("complete", "coverage_unavailable"),
    ({"registered": 1, "available": 1, "unavailable": "none"}, "coverage_invalid"),
    ({"registered": 1, "available": 0, "unavailable": [{"workspace_id": "a", "reason": "root_missing"}] * 2},
     "coverage_invalid"),
])
def test_unusable_coverage_evidence_blocks_activation(coverage, code, declared):
    assert [item["code"] for item in acceptance.check_coverage(coverage, declared)] == [code]
    assert [item["code"] for item in acceptance.check_coverage(coverage, None)] == [code]


def test_verdict_is_json_serialisable(degraded, declared):
    report, release_id = degraded
    json.dumps(judge(report, release_id, declared))
