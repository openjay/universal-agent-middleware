"""UAM-03: a health verdict must say which instance and configuration it describes.

Doctor probes a fresh in-process gateway, which is a different instance from the long-lived
process serving clients. Without identity, "the old channel still reads" and "a new instance
fails to initialise" look like contradictory facts about one service. These tests pin:

- the report names the probe (pid, version, release, config digests) and carries a request id;
- liveness, initialisation, workspace readability and completeness are reported separately;
- a canary failure names its workspace and the stage that failed;
- a response from the gateway can be tied to the audit record it produced;
- none of this makes Doctor write to the ledger, and the supervisor still classifies a
  coverage gap as log-only `workspace_degraded` rather than a restart.
"""
from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from test_hardening import rt_validate, runtime_fixture  # noqa: F401  (pytest fixture import)
from synthetic_fixtures import init_git_repo, write_workspace_registry

from universal_agent_middleware import __version__
from universal_agent_middleware import runtime as rt
from universal_agent_middleware import supervisor as sup
from universal_agent_middleware.doctor import _check_tunnel, _derive_stages, run_doctor
from universal_agent_middleware.gateway import MiddlewareGateway


def _doctor(r, manifest, *, include_canary=True):
    with patch("universal_agent_middleware.runtime.validate_release",
               side_effect=lambda runtime: rt_validate(runtime, executing=False)), \
         patch("universal_agent_middleware.doctor._check_tunnel", return_value={"status": "PASS"}):
        return run_doctor(r["registry_file"], r["state_root"], include_canary=include_canary,
                          runtime_manifest=str(manifest))


def _add_stale_workspaces(r, manifest, base):
    registry = json.loads(Path(r["registry_file"]).read_text())
    for name in ("stale-main", "stale-pr"):
        registry["workspaces"].append({
            "workspace_id": name, "root": str(base / "gone" / name),
            "kind": "git-repository", "capabilities": ["filesystem.read"]})
    Path(r["registry_file"]).write_text(json.dumps(registry))
    updated = dict(r, canaries=[*r["canaries"],
                                {"workspace_id": "stale-main", "path": "README.md"},
                                {"workspace_id": "stale-pr", "path": "README.md"}])
    rt.atomic_json(manifest, updated)
    return updated


def test_report_names_probe_instance_config_and_request(runtime_fixture):
    r, manifest, _ = runtime_fixture
    ledger_before = Path(r["audit_file"]).read_bytes()
    report = _doctor(r, manifest)
    assert report["overall"] == "READY", report
    uuid.UUID(report["request_id"])
    instance = report["instance"]
    assert instance["pid"] == os.getpid()
    assert instance["uam_version"] == __version__
    assert instance["release_id"] == Path(r["current_release"]).name
    assert instance["config"]["registry_sha256"] == rt.sha256(Path(r["registry_file"]))
    assert instance["config"]["runtime_manifest_sha256"] == rt.sha256(manifest)
    gateway = instance["gateway"]
    assert gateway["registry"]["registry_sha256"] == instance["config"]["registry_sha256"]
    assert report["checks"]["mcp"]["contract_sha256"]
    # Doctor never writes to the ledger it inspects, so its writer identity cannot appear in it.
    assert Path(r["audit_file"]).read_bytes() == ledger_before
    writers = {json.loads(line)["writer_instance_id"] for line in ledger_before.decode().splitlines()}
    assert gateway["instance_id"] not in writers


def test_each_report_gets_its_own_request_id(runtime_fixture):
    r, manifest, _ = runtime_fixture
    assert _doctor(r, manifest)["request_id"] != _doctor(r, manifest)["request_id"]


def test_healthy_runtime_has_no_known_gaps(runtime_fixture):
    r, manifest, _ = runtime_fixture
    stages = _doctor(r, manifest)["stages"]
    assert {name: stage["status"] for name, stage in stages.items()} == {
        "process_alive": "PASS", "initialization": "PASS",
        "workspace_readable": "PASS", "result_completeness": "PASS"}
    assert stages["result_completeness"]["known_gaps"] == []


def test_skipped_canaries_leave_completeness_unknown(runtime_fixture):
    r, manifest, _ = runtime_fixture
    report = _doctor(r, manifest, include_canary=False)
    assert report["checks"]["workspace_canary"]["status"] == "UNKNOWN"
    assert report["stages"]["result_completeness"]["status"] == "UNKNOWN"


def test_stale_registrations_degrade_alone_and_name_their_stage(runtime_fixture, tmp_path):
    r, manifest, _ = runtime_fixture
    _add_stale_workspaces(r, manifest, tmp_path)
    report = _doctor(r, manifest)
    checks = report["checks"]
    assert checks["core"]["status"] == "PASS"
    assert checks["mcp"]["status"] == "PASS"
    registry = checks["workspace_registry"]
    assert registry["status"] == "DEGRADED"
    assert {item["workspace_id"] for item in registry["unavailable"]} == {"stale-main", "stale-pr"}
    assert checks["workspace_canary"]["status"] == "FAIL"
    by_id = {item["workspace_id"]: item for item in checks["workspace_canary"]["results"]}
    assert by_id["fixture"]["status"] == "PASS"
    for name in ("stale-main", "stale-pr"):
        assert by_id[name]["status"] == "FAIL"
        assert by_id[name]["stage"] == "workspace_unavailable"
        assert by_id[name]["unavailable_reason"] == "root_missing"
    assert (report["overall"], report["severity"]) == ("DEGRADED", "P2")
    stages = report["stages"]
    assert stages["process_alive"]["status"] == "PASS"
    assert stages["initialization"]["status"] == "PASS"
    assert stages["workspace_readable"]["status"] == "FAIL"
    completeness = stages["result_completeness"]
    assert completeness["status"] == "DEGRADED"
    assert {"registry:stale-main:root_missing", "canary:stale-main:workspace_unavailable"} <= set(
        completeness["known_gaps"])


def test_supervisor_accepts_the_report_and_keeps_a_coverage_gap_log_only(runtime_fixture, tmp_path):
    r, manifest, _ = runtime_fixture
    updated = _add_stale_workspaces(r, manifest, tmp_path)
    report = _doctor(updated, manifest)

    with patch.object(sup.subprocess, "run",
                      return_value=subprocess.CompletedProcess([], 1, json.dumps(report))):
        parsed = sup.doctor_process(str(manifest), updated, 5)
    assert parsed["overall"] == "DEGRADED"
    assert "failure_class" not in parsed

    with patch.object(sup, "validate_release", return_value={}), \
         patch.object(sup, "doctor_process", return_value=report), \
         patch.object(sup.subprocess, "run") as external:
        result = sup.run_cycle(str(manifest))
        external.assert_not_called()
    assert result["overall"] == "DEGRADED"
    assert result["request_id"] == report["request_id"]
    events = [json.loads(p.read_text()) for p in (Path(updated["log_root"]) / "incidents").glob("*.json")]
    assert [(e["failure_class"], e["action"]) for e in events] == [("workspace_degraded", "log_only")]
    assert events[0]["evidence"]["request_id"] == report["request_id"]
    status = json.loads((Path(updated["recovery_root"]) / "health_status.json").read_text())
    assert status["request_id"] == report["request_id"]


def test_stage_projection_tolerates_missing_checks():
    stages = _derive_stages({})
    assert {stage["status"] for stage in stages.values()} == {"UNKNOWN"}


HEALTHY_REGISTRY = {"status": "PASS", "registered": 1, "available": 1, "unavailable": []}
HEALTHY_CANARY = {"status": "PASS", "results": [{"workspace_id": "a", "status": "PASS"}]}
GAP_REGISTRY = {"status": "DEGRADED", "registered": 2, "available": 1,
                "unavailable": [{"workspace_id": "b", "reason": "root_missing"}]}
GAP_CANARY = {"status": "FAIL", "results": [
    {"workspace_id": "a", "status": "PASS"},
    {"workspace_id": "b", "status": "FAIL", "stage": "workspace_unavailable"}]}


def _completeness(registry, canary):
    return _derive_stages({"workspace_registry": registry, "workspace_canary": canary})["result_completeness"]


def test_complete_health_is_the_only_pass():
    completeness = _completeness(HEALTHY_REGISTRY, HEALTHY_CANARY)
    assert completeness["status"] == "PASS"
    assert completeness["known_gaps"] == [] and completeness["evidence_problems"] == []


@pytest.mark.parametrize("registry", [
    {"status": "ERROR", "reason": "registry unreadable"},
    {"status": "UNKNOWN", "reason": "gateway unavailable"},
    None,
])
def test_unusable_registry_evidence_is_not_pass_even_without_listed_gaps(registry):
    completeness = _completeness(registry, HEALTHY_CANARY)
    assert completeness["status"] == "UNKNOWN"
    assert completeness["known_gaps"] == []
    assert len(completeness["evidence_problems"]) == 1
    assert completeness["evidence_problems"][0].startswith("workspace_registry=")


@pytest.mark.parametrize("canary", [
    {"status": "UNKNOWN", "reason": "explicitly skipped"},
    {"status": "ERROR", "reason": "canary crashed"},
    None,
])
def test_unusable_canary_evidence_is_not_pass_even_without_listed_gaps(canary):
    completeness = _completeness(HEALTHY_REGISTRY, canary)
    assert completeness["status"] == "UNKNOWN"
    assert completeness["evidence_problems"][0].startswith("workspace_canary=")


def test_a_real_coverage_gap_is_degraded_and_named():
    completeness = _completeness(GAP_REGISTRY, GAP_CANARY)
    assert completeness["status"] == "DEGRADED" and completeness["evidence_problems"] == []
    assert completeness["known_gaps"] == ["registry:b:root_missing", "canary:b:workspace_unavailable"]


def test_a_failed_check_without_rows_is_degraded_not_pass():
    assert _completeness(HEALTHY_REGISTRY, {"status": "FAIL"})["status"] == "DEGRADED"
    assert _completeness({"status": "DEGRADED"}, HEALTHY_CANARY)["status"] == "DEGRADED"


def test_a_known_gap_outranks_evidence_that_could_not_be_evaluated():
    completeness = _completeness({"status": "ERROR", "reason": "boom"}, GAP_CANARY)
    assert completeness["status"] == "DEGRADED"
    assert completeness["known_gaps"] == ["canary:b:workspace_unavailable"]
    assert completeness["evidence_problems"] == ["workspace_registry=ERROR"]


@pytest.fixture
def tunnel(runtime_fixture):
    r, _, _ = runtime_fixture
    identity = {
        "pid": 4242, "process_identity": "Fri Oct  3 08:01:12 2026 tunnel-client",
        "release": r["current_release"],
        "config_sha256": rt.sha256(Path(r["tunnel_config"])),
        "executable_sha256": rt.sha256(Path(r["tunnel_client"])),
        "started_at": "2026-10-03T00:01:12Z"}
    (Path(r["recovery_root"]) / "tunnel-identity.json").write_text(json.dumps(identity))
    return r, identity


def _fake_run(process_identity, listener="p4242\n"):
    def run(cmd, **kwargs):
        stdout = process_identity + "\n" if cmd[0] == "ps" else listener
        return subprocess.CompletedProcess(cmd, 0, stdout, "")
    return run


def _urlopen(status):
    response = MagicMock()
    response.__enter__.return_value.status = status
    return MagicMock(return_value=response)


def test_tunnel_pass_is_bound_to_the_exact_process(tunnel):
    r, identity = tunnel
    with patch("subprocess.run", side_effect=_fake_run(identity["process_identity"])), \
         patch("urllib.request.urlopen", _urlopen(200)):
        result = _check_tunnel(r)
    assert result["status"] == "PASS"
    assert result["pid"] == 4242
    assert result["started_at"] == "2026-10-03T00:01:12Z"
    assert result["release_id"] == Path(r["current_release"]).name
    assert result["config_sha256"] == identity["config_sha256"]
    assert "stage" not in result


def test_tunnel_identity_mismatch_names_stage_and_keeps_evidence(tunnel):
    r, _ = tunnel
    with patch("subprocess.run", side_effect=_fake_run("Mon Jan  1 00:00:00 2024 other")):
        result = _check_tunnel(r)
    assert result["status"] == "FAIL"
    assert result["stage"] == "process_identity"
    assert result["pid"] == 4242 and result["started_at"] == "2026-10-03T00:01:12Z"


def test_tunnel_unhealthy_endpoint_names_stage(tunnel):
    r, identity = tunnel
    with patch("subprocess.run", side_effect=_fake_run(identity["process_identity"])), \
         patch("urllib.request.urlopen", _urlopen(503)):
        result = _check_tunnel(r)
    assert (result["status"], result["stage"]) == ("FAIL", "health_endpoint")


def test_tunnel_missing_identity_file_names_stage(runtime_fixture):
    r, _, _ = runtime_fixture
    result = _check_tunnel(r)
    assert (result["status"], result["stage"]) == ("FAIL", "identity_file")


def _slow_run(identity, *, slow):
    """`subprocess.run` that answers every probe except `slow`, which never answers in time."""
    answer = _fake_run(identity["process_identity"])

    def run(cmd, **kwargs):
        if os.path.basename(cmd[0]) == slow:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 5))
        return answer(cmd, **kwargs)
    return run


@pytest.mark.parametrize("slow,stage", [("ps", "process_identity"), ("lsof", "listener")])
def test_a_tunnel_subprocess_probe_that_times_out_is_uncertain_not_failed(tunnel, slow, stage):
    r, identity = tunnel
    with patch("subprocess.run", side_effect=_slow_run(identity, slow=slow)), \
         patch("urllib.request.urlopen", _urlopen(200)):
        result = _check_tunnel(r)
    assert (result["status"], result["uncertain"], result["stage"]) == ("UNKNOWN", True, stage)
    assert "uncertain" in result["reason"] and result["pid"] == 4242


@pytest.mark.parametrize("timeout", [TimeoutError("timed out"), urllib.error.URLError(TimeoutError("timed out"))])
def test_a_tunnel_health_probe_that_times_out_is_uncertain_not_failed(tunnel, timeout):
    r, identity = tunnel
    with patch("subprocess.run", side_effect=_fake_run(identity["process_identity"])), \
         patch("urllib.request.urlopen", side_effect=timeout):
        result = _check_tunnel(r)
    assert (result["status"], result["uncertain"], result["stage"]) == ("UNKNOWN", True, "health_endpoint")


def test_a_refused_health_connection_is_a_definite_failure(tunnel):
    r, identity = tunnel
    with patch("subprocess.run", side_effect=_fake_run(identity["process_identity"])), \
         patch("urllib.request.urlopen", side_effect=urllib.error.URLError(ConnectionRefusedError(61, "refused"))):
        result = _check_tunnel(r)
    assert (result["status"], result["stage"]) == ("FAIL", "health_endpoint")
    assert "uncertain" not in result


def test_a_tunnel_process_that_is_gone_is_a_definite_failure(tunnel):
    r, _ = tunnel
    gone = subprocess.CalledProcessError(1, ["ps"])
    with patch("subprocess.run", side_effect=gone):
        result = _check_tunnel(r)
    assert (result["status"], result["stage"]) == ("FAIL", "process_identity")
    assert "uncertain" not in result


def test_an_uncertain_tunnel_probe_makes_the_process_stage_unknown():
    stages = _derive_stages({"tunnel": {"status": "UNKNOWN", "uncertain": True}})
    assert stages["process_alive"]["status"] == "UNKNOWN"


def test_an_uncertain_tunnel_probe_degrades_the_report_instead_of_failing_it(runtime_fixture):
    r, manifest, _ = runtime_fixture
    uncertain = {"status": "UNKNOWN", "uncertain": True, "stage": "health_endpoint", "reason": "timed out"}
    with patch("universal_agent_middleware.runtime.validate_release",
               side_effect=lambda runtime: rt_validate(runtime, executing=False)), \
         patch("universal_agent_middleware.doctor._check_tunnel", return_value=uncertain):
        report = run_doctor(r["registry_file"], r["state_root"], runtime_manifest=str(manifest))
    assert (report["overall"], report["severity"]) == ("DEGRADED", "P2")
    assert report["checks"]["tunnel"]["uncertain"] is True


def _gateway(tmp_path, name):
    repo = tmp_path / "repo"
    if not repo.exists():
        init_git_repo(repo)
    registry = tmp_path / "workspaces.json"
    if not registry.exists():
        write_workspace_registry(registry, [{
            "workspace_id": "repo", "root": str(repo), "kind": "git-repository",
            "capabilities": ["filesystem.read", "git.observe"]}])
    return MiddlewareGateway(str(registry), str(tmp_path / f"state-{name}"))


def test_response_maps_to_instance_and_audit_record(tmp_path):
    gw = _gateway(tmp_path, "a")
    first, second = gw.list_workspaces(), gw.list_workspaces()
    assert first["instance"]["instance_id"] == second["instance"]["instance_id"]
    assert first["request_id"] != second["request_id"]
    records = [json.loads(line) for line in gw.audit.path.read_text().splitlines()]
    by_request = {row["request_id"]: row for row in records}
    row = by_request[first["request_id"]]
    assert row["action"] == "list_workspaces"
    assert row["writer_instance_id"] == first["instance"]["instance_id"]
    assert row["runtime_release"] == first["instance"]["runtime_release"]
    assert row["details"]["unavailable_count"] == 0
    assert gw.audit.verify()["valid"]


def test_two_instances_are_distinguishable_and_share_a_config_snapshot_only_when_equal(tmp_path):
    first, second = _gateway(tmp_path, "a"), _gateway(tmp_path, "b")
    a, b = first.instance_info(), second.instance_info()
    assert a["instance_id"] != b["instance_id"]
    assert a["registry"]["registry_sha256"] == b["registry"]["registry_sha256"]
    registry = tmp_path / "workspaces.json"
    registry.write_text(registry.read_text(encoding="utf-8").replace('"repo"', '"repo-renamed"', 1))
    assert first.instance_info()["registry"]["registry_sha256"] != a["registry"]["registry_sha256"]
    assert second.instance_info()["registry"]["registry_sha256"] == first.instance_info()["registry"]["registry_sha256"]
