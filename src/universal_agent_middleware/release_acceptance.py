"""Exact acceptance predicate for a release.

Nothing is accepted by default: every Doctor check must pass. A release that has to ship while
specific workspaces are unavailable declares those exact gaps in a reviewed file. The declaration
is a statement about the present state, not a tolerance: a different count, a different reason,
an extra gap or a gap that has disappeared are all violations, so a stale declaration cannot
cover for a changed environment.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "uam-release-acceptance-v1"
GAP_REASONS = frozenset({"root_missing", "root_not_directory", "root_unresolvable"})
CANARY_GAP_STAGE = "workspace_unavailable"
MUST_PASS = ("runtime_paths", "release", "credential", "audit_chain", "core", "mcp", "tunnel",
             "reality_index")
COVERAGE_CHECKS = ("workspace_registry", "workspace_canary")


class AcceptanceError(ValueError):
    """The acceptance declaration is unreadable or malformed."""


def _require_keys(value: object, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AcceptanceError(f"{label} must be an object with exactly these keys: {sorted(keys)}")
    return value


def _count(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise AcceptanceError(f"{label} must be a non-negative integer")
    return value


def _workspace_ids(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value) \
            or len(set(value)) != len(value):
        raise AcceptanceError(f"{label} must be a list of unique non-empty workspace ids")
    return list(value)


def load_declaration(path: str | Path) -> dict[str, Any]:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise AcceptanceError(f"cannot read acceptance declaration: {exc}") from exc
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise AcceptanceError(f"acceptance declaration is not valid JSON: {exc}") from exc
    data = _require_keys(data, {"schema_version", "registry", "canaries"}, "declaration")
    if data["schema_version"] != SCHEMA_VERSION:
        raise AcceptanceError(f"unsupported declaration schema: {data['schema_version']!r}")
    registry = _require_keys(data["registry"], {"registered", "available", "unavailable"}, "registry")
    registered = _count(registry["registered"], "registry.registered")
    available = _count(registry["available"], "registry.available")
    entries = registry["unavailable"]
    if not isinstance(entries, list):
        raise AcceptanceError("registry.unavailable must be a list")
    unavailable: dict[str, str] = {}
    for entry in entries:
        entry = _require_keys(entry, {"workspace_id", "reason"}, "registry.unavailable entry")
        workspace_id, reason = entry["workspace_id"], entry["reason"]
        if not isinstance(workspace_id, str) or not workspace_id or workspace_id in unavailable:
            raise AcceptanceError(f"invalid or duplicate unavailable workspace id: {workspace_id!r}")
        if reason not in GAP_REASONS:
            raise AcceptanceError(f"unsupported unavailable reason for {workspace_id}: {reason!r}")
        unavailable[workspace_id] = reason
    if available != registered - len(unavailable):
        raise AcceptanceError("registry.available must equal registry.registered minus the unavailable list")
    canaries = _require_keys(data["canaries"], {"total", "failing"}, "canaries")
    total = _count(canaries["total"], "canaries.total")
    failing = _workspace_ids(canaries["failing"], "canaries.failing")
    if not set(failing) <= set(unavailable) or len(failing) > total:
        raise AcceptanceError("canaries.failing must name unavailable workspaces and fit within canaries.total")
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "registered": registered,
            "available": available, "unavailable": unavailable, "canary_total": total,
            "canary_failing": sorted(failing)}


_ABSENT = object()


def _is_count(value: object) -> bool:
    return type(value) is int and value >= 0


def _coverage_consistency(registered: object, available: object, observed: Mapping[str, str], *,
                          complete: object = _ABSENT, status: object = _ABSENT) -> list[dict[str, str]]:
    """Reject a receipt whose own numbers and verdicts contradict each other.

    This holds in every mode: a declaration can only be compared with figures that first agree
    with themselves, and a strict run has nothing else to compare them with.
    """
    found: list[dict[str, str]] = []
    if not (_is_count(registered) and _is_count(available)):
        found.append({"code": "registry_counts_invalid",
                      "detail": f"registered={registered!r} available={available!r} must be non-negative integers"})
    elif available > registered or registered - available != len(observed):
        found.append({"code": "registry_counts_inconsistent",
                      "detail": f"registered={registered} available={available} with {len(observed)} unavailable listed"})
    gap_free = not observed
    if complete is not _ABSENT and (type(complete) is not bool or complete != gap_free):
        found.append({"code": "registry_complete_inconsistent",
                      "detail": f"complete={complete!r} with {len(observed)} unavailable listed"})
    if status is not _ABSENT and status != ("PASS" if gap_free else "DEGRADED"):
        found.append({"code": "registry_status_inconsistent",
                      "detail": f"workspace_registry={status!r} with {len(observed)} unavailable listed"})
    return found


def _registry_violations(registered: object, available: object, observed: Mapping[str, str],
                         declaration: Mapping[str, Any] | None, *, complete: object = _ABSENT,
                         status: object = _ABSENT) -> list[dict[str, str]]:
    declared = declaration["unavailable"] if declaration else {}
    found = _coverage_consistency(registered, available, observed, complete=complete, status=status)
    if declaration and (registered, available) != (declaration["registered"], declaration["available"]):
        found.append({"code": "registry_count_mismatch",
                      "detail": f"observed {registered} registered / {available} available, declared "
                                f"{declaration['registered']} / {declaration['available']}"})
    for workspace_id, reason in sorted(observed.items()):
        if workspace_id not in declared:
            found.append({"code": "unexpected_unavailable", "detail": f"{workspace_id} ({reason})"})
        elif declared[workspace_id] != reason:
            found.append({"code": "unavailable_reason_mismatch",
                          "detail": f"{workspace_id}: observed {reason}, declared {declared[workspace_id]}"})
    for workspace_id in sorted(set(declared) - set(observed)):
        found.append({"code": "declared_gap_not_observed", "detail": workspace_id})
    return found


def _unavailable_map(entries: object) -> dict[str, str] | None:
    if not isinstance(entries, list) or any(
            not isinstance(item, Mapping) or not isinstance(item.get("workspace_id"), str)
            or not item["workspace_id"] or not isinstance(item.get("reason"), str) for item in entries):
        return None
    mapping = {item["workspace_id"]: item["reason"] for item in entries}
    return mapping if len(mapping) == len(entries) else None


def check_coverage(coverage: object, declaration: Mapping[str, Any] | None) -> list[dict[str, str]]:
    """Pre-activation gate: the registry coverage the artifact reports must match the declaration.

    The artifact always reports ``complete``; leaving it out is treated as a contradiction rather
    than as permission to skip the cross-check.
    """
    if not isinstance(coverage, Mapping):
        return [{"code": "coverage_unavailable", "detail": "the artifact did not report workspace coverage"}]
    observed = _unavailable_map(coverage.get("unavailable"))
    if observed is None:
        return [{"code": "coverage_invalid", "detail": "unavailable entries are malformed or duplicated"}]
    return _registry_violations(coverage.get("registered"), coverage.get("available"), observed, declaration,
                                complete=coverage.get("complete"))


def _status(checks: Mapping[str, Any], name: str) -> object:
    entry = checks.get(name)
    return entry.get("status") if isinstance(entry, Mapping) else None


def _canary_violations(canary: Mapping[str, Any], declaration: Mapping[str, Any] | None,
                       canary_ids: Sequence[str]) -> tuple[list[dict[str, str]], list[str]]:
    results = canary.get("results")
    if canary.get("status") not in ("PASS", "FAIL") or not isinstance(results, list):
        return [{"code": "canaries_not_evaluated", "detail": f"workspace_canary={canary.get('status')}"}], []
    found: list[dict[str, str]] = []
    entries = [item if isinstance(item, Mapping) else {} for item in results]
    # The summary is a claim about the results, so it is checked against them instead of trusted.
    summary = "PASS" if entries and all(item.get("status") == "PASS" for item in entries) else "FAIL"
    if canary["status"] != summary:
        found.append({"code": "canary_status_inconsistent",
                      "detail": f"workspace_canary={canary['status']} but the {len(entries)} results imply {summary}"})
    if Counter(item.get("workspace_id") for item in entries) != Counter(canary_ids):
        found.append({"code": "canary_set_mismatch",
                      "detail": f"results cover {sorted(str(i.get('workspace_id')) for i in entries)}, "
                                f"runtime manifest declares {sorted(canary_ids)}"})
    if declaration and len(canary_ids) != declaration["canary_total"]:
        found.append({"code": "canary_total_mismatch",
                      "detail": f"runtime manifest has {len(canary_ids)} canaries, declared {declaration['canary_total']}"})
    declared_failing = set(declaration["canary_failing"]) if declaration else set()
    declared_reasons = declaration["unavailable"] if declaration else {}
    failing = {str(item.get("workspace_id")): item for item in entries if item.get("status") != "PASS"}
    for workspace_id, item in sorted(failing.items()):
        if workspace_id not in declared_failing:
            found.append({"code": "unexpected_canary_failure",
                          "detail": f"{workspace_id} stage={item.get('stage')}"})
        elif (item.get("stage"), item.get("unavailable_reason")) != (
                CANARY_GAP_STAGE, declared_reasons.get(workspace_id)):
            found.append({"code": "canary_failure_not_root_gap",
                          "detail": f"{workspace_id}: stage={item.get('stage')} "
                                    f"reason={item.get('unavailable_reason')}"})
    for workspace_id in sorted(declared_failing - set(failing)):
        found.append({"code": "declared_canary_gap_not_observed", "detail": workspace_id})
    return found, sorted(f"canary:{wid}:{item.get('stage')}" for wid, item in failing.items())


def evaluate(report: object, *, declaration: Mapping[str, Any] | None, post_ok: bool,
             release_id: str, canary_ids: Sequence[str]) -> dict[str, Any]:
    """Judge a post-activation Doctor report against the exact predicate."""
    violations: list[dict[str, str]] = []
    gaps: list[str] = []
    observed: dict[str, Any] = {"overall": None, "severity": None, "gaps": gaps}
    if not post_ok:
        violations.append({"code": "post_steps_failed",
                           "detail": "tunnel restart or index refresh did not complete"})
    checks = report.get("checks") if isinstance(report, Mapping) else None
    if not isinstance(checks, Mapping):
        violations.append({"code": "doctor_report_invalid", "detail": "Doctor did not return a report with checks"})
        return _verdict(violations, observed, declaration)
    observed.update(overall=report.get("overall"), severity=report.get("severity"))

    instance = report.get("instance")
    described = instance.get("release_id") if isinstance(instance, Mapping) else None
    if described != release_id:
        violations.append({"code": "release_identity_mismatch",
                           "detail": f"Doctor describes {described!r}, expected {release_id!r}"})
    for name in MUST_PASS:
        if name not in checks:
            violations.append({"code": "check_missing", "detail": name})
        elif _status(checks, name) != "PASS":
            violations.append({"code": "check_not_pass", "detail": f"{name}={_status(checks, name)}"})
    for name in sorted(set(checks) - set(MUST_PASS) - set(COVERAGE_CHECKS)):
        if _status(checks, name) != "PASS":
            violations.append({"code": "check_not_pass", "detail": f"{name}={_status(checks, name)}"})

    registry = checks.get("workspace_registry")
    if not isinstance(registry, Mapping):
        violations.append({"code": "check_missing", "detail": "workspace_registry"})
    else:
        unavailable = _unavailable_map(registry.get("unavailable"))
        if registry.get("status") not in ("PASS", "DEGRADED") or unavailable is None:
            violations.append({"code": "registry_not_evaluated",
                               "detail": f"workspace_registry={registry.get('status')}"})
        else:
            violations += _registry_violations(
                registry.get("registered"), registry.get("available"), unavailable, declaration,
                complete=registry.get("complete", _ABSENT), status=registry.get("status"))
            gaps += [f"registry:{wid}:{reason}" for wid, reason in sorted(unavailable.items())]
    canary = checks.get("workspace_canary")
    if not isinstance(canary, Mapping):
        violations.append({"code": "check_missing", "detail": "workspace_canary"})
    else:
        found, failing = _canary_violations(canary, declaration, canary_ids)
        violations += found
        gaps += failing

    if not violations:
        # Consistency guard only: every check above already passed, so Doctor's own roll-up must
        # say exactly what the accepted gaps imply. With violations present the roll-up is a
        # consequence of them and would only add noise (and hide which failure is transient).
        expected = "DEGRADED" if gaps else "READY"
        if observed["overall"] != expected or (gaps and observed["severity"] != "P2"):
            violations.append({"code": "doctor_overall_unexpected",
                               "detail": f"{observed['overall']}/{observed['severity']}, expected {expected}"})
    return _verdict(violations, observed, declaration)


def _verdict(violations: list[dict[str, str]], observed: dict[str, Any],
             declaration: Mapping[str, Any] | None) -> dict[str, Any]:
    return {
        "accepted": not violations,
        "mode": "declared_gaps" if declaration else "strict",
        "violations": violations,
        "observed": observed,
        "declaration": {"path": declaration["path"], "sha256": declaration["sha256"]} if declaration else None,
    }
