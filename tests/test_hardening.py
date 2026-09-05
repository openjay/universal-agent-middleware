"""Failure injection uses temporary state and fake launchctl; never controls live UAM."""
import concurrent.futures
import hashlib
import json
import multiprocessing
import os
import signal
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from universal_agent_middleware.audit import HashChainedAuditLog, AuditIntegrityError, migrate_snapshot
from universal_agent_middleware import runtime as rt
from universal_agent_middleware import supervisor as sup
from universal_agent_middleware import installer as inst
from universal_agent_middleware.doctor import _check_audit, run_doctor
from universal_agent_middleware.service import mcp_command, validate_tunnel_config

ROOT = Path(__file__).resolve().parents[1]


def writer(path, count):
    log = HashChainedAuditLog(path)
    for i in range(count):
        log.append(action="parallel", workspace_id="fixture", outcome="PASS", details={"i": i})


def killed_writer(path):
    real_write = os.write
    def torn(fd, data):
        real_write(fd, data[:len(data)//2])
        os.kill(os.getpid(), signal.SIGKILL)
    with patch("universal_agent_middleware.audit.os.write", side_effect=torn):
        HashChainedAuditLog(path).append(action="torn", workspace_id=None, outcome="PASS")


def rehash(record):
    record = dict(record)
    record.pop("record_hash", None)
    return {**record, "record_hash": hashlib.sha256(HashChainedAuditLog._canonical(record)).hexdigest()}


def legacy(path):
    row = rehash({"timestamp": "legacy", "previous_hash": "GENESIS", "action": "a"})
    path.write_text(json.dumps(row) + "\n")
    return row


def test_process_writers_high_volume(tmp_path):
    path = tmp_path / "audit.jsonl"
    ctx = multiprocessing.get_context("spawn")
    jobs = [ctx.Process(target=writer, args=(path, 500)) for _ in range(6)]
    for p in jobs: p.start()
    for p in jobs:
        p.join(60)
        if p.is_alive(): p.kill(); p.join()
        assert p.exitcode == 0
    result = HashChainedAuditLog(path).verify()
    assert result["valid"] and result["records"] == 3000
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert len({r["chain_id"] for r in rows}) == 1
    assert len({r["writer_instance_id"] for r in rows}) == 6
    assert len({r["request_id"] for r in rows}) == 3000


def test_thread_writers_and_multiple_instances(tmp_path):
    path = tmp_path / "audit.jsonl"
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        list(pool.map(lambda _: writer(path, 50), range(8)))
    assert HashChainedAuditLog(path).verify()["records"] == 400
    assert HashChainedAuditLog(path).verify()["valid"]


@pytest.mark.parametrize("kind", ["MALFORMED_JSON", "TRUNCATED_RECORD", "MISSING_HASH",
                                   "BROKEN_PREVIOUS_HASH", "HASH_MISMATCH", "SEQUENCE_GAP"])
def test_failure_taxonomy_and_preservation(tmp_path, kind):
    path = tmp_path / "audit.jsonl"
    writer(path, 2)
    lines = path.read_bytes().splitlines(keepends=True)
    row = json.loads(lines[1])
    if kind == "MALFORMED_JSON": lines[1] = b"not-json\n"
    elif kind == "TRUNCATED_RECORD": lines[1] = lines[1][:-1]
    else:
        if kind == "MISSING_HASH": row.pop("record_hash")
        elif kind == "BROKEN_PREVIOUS_HASH": row["previous_hash"] = "GENESIS"
        elif kind == "HASH_MISMATCH": row["action"] = "tampered"
        elif kind == "SEQUENCE_GAP": row["sequence"] = 7; row = rehash(row)
        lines[1] = json.dumps(row).encode() + b"\n"
    path.write_bytes(b"".join(lines))
    before = path.read_bytes()
    result = HashChainedAuditLog(path).verify()
    assert result["failure_type"] == kind
    assert result["valid_records"] == 1 and result["first_invalid_line"] == 2
    assert result["head_hash"] == json.loads(lines[0])["record_hash"]
    with pytest.raises(AuditIntegrityError): writer(path, 1)
    assert path.read_bytes() == before
    doctor = _check_audit(str(tmp_path))
    assert doctor["severity"] == "P0" and doctor["failure_type"] == kind
    assert doctor["entries"] == 1 and doctor["error"]


def test_process_kill_preserves_torn_record_and_releases_lock(tmp_path):
    path = tmp_path / "audit.jsonl"
    writer(path, 1)
    ctx = multiprocessing.get_context("spawn")
    p = ctx.Process(target=killed_writer, args=(path,))
    p.start(); p.join(15)
    assert p.exitcode == -signal.SIGKILL
    assert HashChainedAuditLog(path).verify()["failure_type"] == "TRUNCATED_RECORD"
    with pytest.raises(AuditIntegrityError): writer(path, 1)


def test_tail_appends_do_not_rescan_history(tmp_path):
    log = HashChainedAuditLog(tmp_path / "audit.jsonl")
    log.append(action="a", workspace_id=None, outcome="PASS")
    with patch.object(log, "_verify_stream", side_effect=AssertionError("unexpected full scan")):
        for _ in range(10): log.append(action="b", workspace_id=None, outcome="PASS")
    assert log.verify()["records"] == 11


def test_historical_tampering_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    writer(path, 4)
    lines = path.read_text().splitlines()
    row = json.loads(lines[0]); row["outcome"] = "FAIL"; lines[0] = json.dumps(row)
    path.write_text("\n".join(lines) + "\n")
    assert HashChainedAuditLog(path).verify()["failure_type"] == "HASH_MISMATCH"


def test_legacy_migration_is_explicit_hash_bound_and_exclusive(tmp_path):
    source, dest = tmp_path / "legacy.jsonl", tmp_path / "new/audit.jsonl"
    legacy(source)
    before = source.read_bytes()
    digest = rt.sha256(source)
    with pytest.raises(AuditIntegrityError, match="MIGRATION_REQUIRED"): writer(source, 1)
    with pytest.raises(AuditIntegrityError, match="SHA256"):
        migrate_snapshot(source, dest, expected_sha256="wrong", incident_receipt_id="incident-1")
    assert not dest.exists()
    record = migrate_snapshot(source, dest, expected_sha256=digest, incident_receipt_id="incident-1")
    assert record["details"]["legacy_valid_prefix"] == 1
    assert record["details"]["legacy_file_sha256"] == digest
    assert source.read_bytes() == before
    assert HashChainedAuditLog(dest).verify()["valid"]
    with pytest.raises(FileExistsError):
        migrate_snapshot(source, dest, expected_sha256=digest, incident_receipt_id="incident-1")


def test_freeze_blocks_existing_writer(tmp_path):
    latch = tmp_path / "FROZEN.json"
    log = HashChainedAuditLog(tmp_path / "audit.jsonl", freeze_file=latch)
    log.append(action="a", workspace_id=None, outcome="PASS")
    latch.write_text("{}")
    with pytest.raises(AuditIntegrityError, match="FROZEN"):
        log.append(action="b", workspace_id=None, outcome="PASS")
    assert log.verify()["records"] == 1


@pytest.fixture
def runtime_fixture(tmp_path):
    home = tmp_path / "Fresh Home & Tests"
    uam = home / "Library/Application Support/OpenJay/UAM"
    release = uam / ("releases/v0.4.0+" + "a" * 40)
    config = uam / "config"
    state = home / "private/state"
    recovery = state.parent / "recovery"
    credential = state.parent / "credentials"
    for p in [release / "service", release / "venv/bin", release / "artifacts", config, state, recovery, credential]:
        p.mkdir(parents=True, exist_ok=True)
    credential.chmod(0o700)
    key = credential / "control_plane_api_key"; key.write_text("fixture-only"); key.chmod(0o600)
    workspace = tmp_path / "workspace"; workspace.mkdir(); (workspace / "README.md").write_text("fixture content\n")
    (config / "workspaces.json").write_text(json.dumps({"registry_version": "uam-workspace-registry-v1", "workspaces": [
        {"workspace_id": "fixture", "root": str(workspace), "kind": "git-repository", "capabilities": ["filesystem.read"]}]}))
    (config / "root_scopes.json").write_text(json.dumps({"schema_version": "root-scope-registry-v1", "scopes": []}))
    policy = release / "service/recovery_policies.yaml"
    policy.write_bytes((ROOT / "tools/system-service/config/recovery_policies.yaml").read_bytes())
    wheel = release / "artifacts/fixture.whl"; wheel.write_text("fixture only; not a wheel")
    (release / "venv/bin/python").write_text("fixture executable placeholder")
    client = home / "bin/tunnel-client"; client.parent.mkdir(); client.write_text("fixture"); client.chmod(0o700)
    config_path = home / ".config/tunnel-client/uam-chatgpt-read.yaml"; config_path.parent.mkdir(parents=True)
    r = {"schema_version": rt.SCHEMA, "uam_home": str(uam), "release_root": str(release.parent),
         "current_release": str(release), "config_root": str(config), "state_root": str(state),
         "audit_file": str(state / "audit.jsonl"), "recovery_root": str(recovery),
         "credential_root": str(credential), "log_root": str(home / "Library/Logs/UAM"),
         "registry_file": str(config / "workspaces.json"), "root_scopes_file": str(config / "root_scopes.json"),
         "tunnel_client": str(client), "tunnel_config": str(config_path), "tunnel_profile": "uam-chatgpt-read",
         "policy_file": str(policy), "canaries": [{"workspace_id": "fixture", "path": "README.md"}]}
    release_manifest = {"schema_version": "uam-release-v1", "source_commit": "a"*40, "source_tree": "b"*40,
        "source_dirty": False, "source_kind": "git_commit", "release_id": release.name, "package_version": "0.4.0",
        "wheel_file": "artifacts/fixture.whl", "wheel_sha256": rt.sha256(wheel),
        "tool_contract": json.loads((ROOT / "src/universal_agent_middleware/tool_contract.json").read_text()),
        "files": rt.release_files(release)}
    rt.atomic_json(release / "RELEASE_MANIFEST.json", release_manifest)
    r["release_manifest_sha256"] = rt.sha256(release / "RELEASE_MANIFEST.json")
    manifest = release / "runtime/uam-runtime.json"
    rt.atomic_json(manifest, r)
    (uam / "current").symlink_to(release)
    canonical = uam / "runtime/uam-runtime.json"; canonical.parent.mkdir(); canonical.symlink_to(uam / "current/runtime/uam-runtime.json")
    import shlex
    config_path.write_text(json.dumps({"mcp": {"commands": [{"command": shlex.join(mcp_command(r, str(canonical)))}]}}))
    writer(state / "audit.jsonl", 1)
    return r, manifest, home


def healthy_checks():
    return {name: {"status": "PASS"} for name in ["release", "runtime_paths", "credential", "audit_chain", "core", "mcp", "workspace_canary", "tunnel"]}


def test_runtime_paths_match_and_reject_split_brain(runtime_fixture):
    r, manifest, _ = runtime_fixture
    loaded = rt.load_runtime(manifest)
    rt.validate_paths(loaded, r["registry_file"], r["state_root"])
    with pytest.raises(ValueError, match="effective path"):
        rt.validate_paths(loaded, r["registry_file"], str(Path(r["state_root"]) / "other"))
    with pytest.raises(FileNotFoundError): rt.load_runtime(manifest.parent / "missing.json")
    bad = dict(r, audit_file=str(Path(r["state_root"]) / "wrong.jsonl"))
    rt.atomic_json(manifest, bad)
    with pytest.raises(ValueError, match="audit_file"): rt.load_runtime(manifest)


@pytest.mark.parametrize("damage", ["manifest", "file", "extra_file", "dangling", "wrong_current"])
def test_release_identity_rejects_damage(runtime_fixture, damage):
    r, _, _ = runtime_fixture
    assert rt.validate_release(r, executing=False)["source_dirty"] is False
    release = Path(r["current_release"])
    if damage == "manifest": (release / "RELEASE_MANIFEST.json").write_text("{}")
    elif damage == "file": (release / "venv/bin/python").write_text("tampered")
    elif damage == "extra_file": (release / "venv/injected.py").write_text("pass")
    else:
        current = Path(r["uam_home"]) / "current"; current.unlink()
        current.symlink_to(release.parent / "missing" if damage == "dangling" else release.parent)
    with pytest.raises((ValueError, FileNotFoundError)):
        rt.validate_release(r, executing=False)


def test_doctor_canaries_contract_and_no_audit_writes(runtime_fixture):
    r, manifest, _ = runtime_fixture
    before = Path(r["audit_file"]).read_bytes()
    with patch("universal_agent_middleware.runtime.validate_release", side_effect=lambda r: rt_validate(r, executing=False)), \
         patch("universal_agent_middleware.doctor._check_tunnel", return_value={"status": "PASS"}):
        report = run_doctor(r["registry_file"], r["state_root"], runtime_manifest=str(manifest))
    assert report["overall"] == "READY", report
    assert report["checks"]["workspace_canary"]["results"][0]["read_verified"]
    assert Path(r["audit_file"]).read_bytes() == before


rt_validate = rt.validate_release


def test_doctor_corruption_frozen(runtime_fixture):
    r, manifest, _ = runtime_fixture
    with Path(r["audit_file"]).open("ab") as f: f.write(b"torn")
    report = run_doctor(r["registry_file"], r["state_root"], runtime_manifest=str(manifest))
    assert report["overall"] == "FROZEN"
    assert report["checks"]["audit_chain"]["failure_type"] == "TRUNCATED_RECORD"


@pytest.mark.parametrize("failure", ["audit_chain", "credential", "release", "runtime_paths"])
def test_p0_freezes_before_any_restart_and_stays_latched(runtime_fixture, failure):
    r, manifest, _ = runtime_fixture
    checks = healthy_checks(); checks[failure] = {"status": "FAIL", "severity": "P0"}
    with patch.object(sup, "validate_release", return_value={}), \
         patch.object(sup, "doctor_process", return_value={"overall": "FROZEN", "checks": checks}), \
         patch.object(sup.subprocess, "run") as external:
        assert sup.run_cycle(str(manifest))["overall"] == "FROZEN"
        assert sup.run_cycle(str(manifest))["overall"] == "FROZEN"
        external.assert_not_called()
    assert (Path(r["recovery_root"]) / "FROZEN.json").is_file()
    assert len(list((Path(r["log_root"]) / "incidents").glob("*.json"))) == 2


def test_bounded_restart_then_storm_freezes(runtime_fixture):
    r, manifest, _ = runtime_fixture
    checks = healthy_checks(); checks["tunnel"] = {"status": "FAIL"}
    with patch.object(sup, "validate_release", return_value={}), \
         patch.object(sup, "doctor_process", return_value={"overall": "DEGRADED", "checks": checks}), \
         patch.object(sup.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as action:
        for _ in range(3): assert sup.run_cycle(str(manifest))["overall"] == "DEGRADED"
        assert sup.run_cycle(str(manifest))["overall"] == "FROZEN"
        assert action.call_count == 3
    events = [json.loads(p.read_text()) for p in (Path(r["log_root"]) / "incidents").glob("*.json")]
    assert len(events) == 4
    assert sorted(e["occurrence_count"] for e in events if e["failure_class"] == "tunnel_unavailable") == [1, 2, 3]


def test_invalid_budget_fail_closed(runtime_fixture):
    r, manifest, _ = runtime_fixture
    (Path(r["recovery_root"]) / "budget.json").write_text("broken")
    checks = healthy_checks(); checks["tunnel"] = {"status": "FAIL"}
    with patch.object(sup, "validate_release", return_value={}), \
         patch.object(sup, "doctor_process", return_value={"overall": "DEGRADED", "checks": checks}), \
         patch.object(sup.subprocess, "run") as action:
        assert sup.run_cycle(str(manifest))["overall"] == "FROZEN"
        action.assert_not_called()


def test_doctor_real_timeout_is_bounded(runtime_fixture, tmp_path):
    r, manifest, _ = runtime_fixture
    # A real sleeping process, not a timeout around a pipe consumer.
    executable = Path(r["current_release"]) / "venv/bin/python"
    executable.write_text('#!/bin/sh\nexec /bin/sleep 10\n'); executable.chmod(0o700)
    import time
    start = time.monotonic()
    assert sup.doctor_process(str(manifest), r, 1)["failure_class"] == "doctor_timeout"
    assert time.monotonic() - start < 3


def test_invalid_doctor_success_rejected(runtime_fixture):
    r, manifest, _ = runtime_fixture
    with patch.object(sup.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, '{"overall":"READY","checks":{}}')):
        assert sup.doctor_process(str(manifest), r, 1)["overall"] == "FAILED"


def test_fresh_home_plists_and_tunnel_round_trip(runtime_fixture, tmp_path):
    r, _, home = runtime_fixture
    canonical = Path(r["uam_home"]) / "runtime/uam-runtime.json"
    validate_tunnel_config(r, str(canonical))
    paths = inst.render_plists(ROOT / "tools/system-service/plists", tmp_path / "plists", home,
                              Path(r["uam_home"]), Path(r["log_root"]), canonical)
    import plistlib
    for path in paths:
        definition = plistlib.loads(path.read_bytes())
        assert definition["EnvironmentVariables"]["UAM_RUNTIME_MANIFEST"] == str(canonical)
        assert ".local/share/openjay" not in definition["ProgramArguments"][1]
        assert "KeepAlive" not in definition
    assert not (home / ".local/share/openjay/uam").exists()


def test_launch_failure_is_not_success(tmp_path):
    with patch.object(inst.subprocess, "run", side_effect=subprocess.CalledProcessError(5, ["launchctl"])):
        with pytest.raises(subprocess.CalledProcessError): inst.bootstrap_agents([tmp_path / "tunnel.plist"])


def test_atomic_current_failure_preserves_old_target(runtime_fixture):
    r, _, _ = runtime_fixture
    home = Path(r["uam_home"]); current = home / "current"; before = current.readlink()
    with patch.object(inst.os, "replace", side_effect=OSError("injected rename failure")):
        with pytest.raises(OSError): inst.switch_current(home, home / "releases/new")
    assert current.readlink() == before
    assert not list(home.glob(".current-*"))


def test_dirty_source_rejected_before_build():
    with patch.object(inst.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, " M source.py\n")):
        with pytest.raises(ValueError, match="dirty"): inst.clean_source(ROOT)


def test_same_release_id_rejected(runtime_fixture):
    r, _, _ = runtime_fixture
    release = Path(r["current_release"])
    before = (release / "RELEASE_MANIFEST.json").read_bytes()
    with pytest.raises(FileExistsError): release.mkdir()
    assert (release / "RELEASE_MANIFEST.json").read_bytes() == before


def test_config_validation_rejects_version_and_truthy_authority(runtime_fixture):
    r, _, _ = runtime_fixture
    rt.validate_configs(r)
    p = Path(r["root_scopes_file"])
    p.write_text(json.dumps({"schema_version":"root-scope-registry-v1", "scopes":[
        {"scope_id":"bad", "root":"/tmp", "authority":{"auto_admit":"false"}}]}))
    with pytest.raises(ValueError, match="booleans"): rt.validate_configs(r)
    p.write_text('{"schema_version":"v99","scopes":[]}')
    with pytest.raises(ValueError, match="schema"): rt.validate_configs(r)


def test_same_identity_stage_refuses_before_any_build(runtime_fixture):
    r, _, home = runtime_fixture
    import io, tarfile
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        data = b'[project]\nversion="0.4.0"\n'
        item = tarfile.TarInfo('pyproject.toml'); item.size = len(data); tar.addfile(item, io.BytesIO(data))
    canaries = home / "canaries.json"; canaries.write_text(json.dumps(r["canaries"]))
    identity = {"source_commit":"a"*40,"source_tree":"b"*40,"source_dirty":False}
    with patch.object(inst, "clean_source", return_value=identity), \
         patch.object(inst.subprocess, "run", return_value=subprocess.CompletedProcess([],0,archive.getvalue())) as run:
        with pytest.raises(FileExistsError):
            inst.stage(ROOT, home=home, state_root=Path(r["state_root"]), registry=Path(r["registry_file"]),
                scopes=Path(r["root_scopes_file"]), canaries=canaries,
                tunnel_config=Path(r["tunnel_config"]), tunnel_client=Path(r["tunnel_client"]))
        assert run.call_count == 1  # archive only, no build/install/current switch


def test_activation_launch_failure_latches_and_never_writes_success(runtime_fixture):
    r, manifest, home = runtime_fixture
    import shutil
    plan = manifest.parent
    shutil.copy2(r["tunnel_config"], plan / "tunnel-config.yaml")
    inst.render_plists(ROOT / "tools/system-service/plists", plan / "plists", home,
                      Path(r["uam_home"]), Path(r["log_root"]), Path(r["uam_home"]) / "runtime/uam-runtime.json")
    def run(cmd, **kw):
        if cmd[1] == "print": return subprocess.CompletedProcess(cmd, 113)
        raise subprocess.CalledProcessError(5, cmd)
    with patch.object(inst.subprocess, "run", side_effect=run):
        with pytest.raises(subprocess.CalledProcessError): inst.activate(manifest, home)
    assert (Path(r["recovery_root"]) / "FROZEN.json").exists()
    assert not (Path(r["recovery_root"]) / "INSTALL_RECEIPT.json").exists()


def test_mcp_schema_contract_mismatch_fails_doctor(runtime_fixture):
    r, manifest, _ = runtime_fixture
    release = rt.validate_release(r, executing=False)
    release["tool_contract"]["uam_list_workspaces"] = "different-schema"
    with patch("universal_agent_middleware.runtime.validate_release", return_value=release), \
         patch("universal_agent_middleware.doctor._check_tunnel", return_value={"status":"PASS"}):
        report = run_doctor(r["registry_file"],r["state_root"],runtime_manifest=str(manifest))
    assert report["overall"] != "READY"
    assert report["checks"]["mcp"]["schema_mismatch"] == ["uam_list_workspaces"]


def concurrent_cycle(manifest, queue):
    checks = healthy_checks(); checks["tunnel"] = {"status":"FAIL"}
    with patch.object(sup, "validate_release", return_value={}), \
         patch.object(sup, "doctor_process", return_value={"overall":"DEGRADED","checks":checks}), \
         patch.object(sup.subprocess, "run", return_value=subprocess.CompletedProcess([],0)):
        queue.put(sup.run_cycle(str(manifest))["overall"])


def test_concurrent_recovery_cycles_share_one_budget(runtime_fixture):
    r, manifest, _ = runtime_fixture
    ctx = multiprocessing.get_context("spawn"); queue = ctx.Queue()
    jobs = [ctx.Process(target=concurrent_cycle,args=(manifest,queue)) for _ in range(6)]
    for p in jobs: p.start()
    for p in jobs:
        p.join(15)
        if p.is_alive(): p.kill(); p.join()
        assert p.exitcode == 0
    states = [queue.get(timeout=1) for _ in jobs]
    assert states.count("DEGRADED") == 3 and states.count("FROZEN") == 3
    assert len(json.loads((Path(r["recovery_root"])/"budget.json").read_text())["tunnel_restarts"]) == 3


def test_doctor_missing_manifest_cli_is_frozen(capsys):
    from universal_agent_middleware.cli import main
    assert main(["doctor","--runtime-manifest","/nonexistent/uam-runtime.json","--json"]) == 1
    assert json.loads(capsys.readouterr().out)["overall"] == "FROZEN"


def test_audit_init_cli_never_resets_existing_chain(tmp_path, capsys):
    from universal_agent_middleware.cli import main
    path = tmp_path / "audit.jsonl"
    assert main(["audit-init","--destination",str(path)]) == 0
    before = path.read_bytes()
    assert main(["audit-init","--destination",str(path)]) == 1
    assert path.read_bytes() == before


def test_activation_waits_for_ready_but_never_retries_p0(runtime_fixture):
    r, manifest, _ = runtime_fixture
    with patch.object(sup, "doctor_process", side_effect=[{"overall":"DEGRADED"},{"overall":"READY"}]), \
         patch.object(inst.time, "sleep"):
        assert inst.wait_for_readiness(str(manifest),r)["overall"] == "READY"
    with patch.object(sup, "doctor_process", return_value={"overall":"FROZEN"}) as doctor:
        with pytest.raises(ValueError,match="integrity"): inst.wait_for_readiness(str(manifest),r)
        assert doctor.call_count == 1


def test_corrupt_incident_index_still_publishes_frozen_status(runtime_fixture):
    r, manifest, _ = runtime_fixture
    (Path(r["recovery_root"])/"incidents.json").write_text('broken')
    checks = healthy_checks(); checks["audit_chain"] = {"status":"FAIL","severity":"P0"}
    with patch.object(sup,"validate_release",return_value={}), \
         patch.object(sup,"doctor_process",return_value={"overall":"FROZEN","checks":checks}):
        result = sup.run_cycle(str(manifest))
    assert result["overall"] == "FROZEN" and "incident_write_error" in result
    assert json.loads((Path(r["recovery_root"])/"health_status.json").read_text())["overall"] == "FROZEN"


def test_wrapper_freeze_latch_gets_an_incident_on_next_cycle(runtime_fixture):
    r, manifest, _ = runtime_fixture
    rt.atomic_json(Path(r["recovery_root"])/"FROZEN.json",{"overall":"FROZEN","failure_class":"runtime_path_failure"})
    with patch.object(sup.subprocess,"run") as action:
        assert sup.run_cycle(str(manifest))["overall"] == "FROZEN"
        action.assert_not_called()
    receipts = list((Path(r["log_root"])/"incidents").glob('*.json'))
    assert len(receipts) == 1
    assert json.loads(receipts[0].read_text())["failure_class"] == "runtime_path_failure"


def test_whitespace_credential_is_security_failure(runtime_fixture):
    r, _, _ = runtime_fixture
    (Path(r["credential_root"])/"control_plane_api_key").write_text(' \n')
    assert rt.check_credential(r)["severity"] == "P0"


def test_credential_setup_uses_manifest_and_never_rotates(runtime_fixture):
    from universal_agent_middleware.service import setup_credential
    r, manifest, _ = runtime_fixture
    key = Path(r["credential_root"])/"control_plane_api_key"
    before = key.read_bytes()
    with pytest.raises(ValueError,match="already exists"): setup_credential(str(manifest))
    assert key.read_bytes() == before
    key.unlink()  # Fixture only.
    with patch("sys.stdin.isatty",return_value=True), patch("getpass.getpass",return_value="fixture-new-key"):
        setup_credential(str(manifest))
    assert key.read_bytes() == b"fixture-new-key"
    assert key.stat().st_mode & 0o777 == 0o600
