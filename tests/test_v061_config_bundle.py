"""F-REL-2 (v0.6.1): the Registry, the RootScopes and the canaries are one combination bound to the release.

Before this, a release was built against one Registry/RootScopes/canary triplet and activated against
whatever was on disk: ``installer stage`` kept an existing configuration file and silently ignored the
narrower one it was given (while embedding the supplied canaries), and no admission point compared
the files with what the release was built with. A mixed combination only surfaced after the switch,
when Doctor could do nothing but FROZEN.

Each case below changes exactly one part of the combination and asserts the specific violation, then
asserts that the host was not touched. The sealed cases run the real orchestrator and the real
``_stage_candidate``/``_switch_and_judge``; only the collaborators that touch the host are replaced.
"""
from __future__ import annotations

import io
import json
import subprocess
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from release_fixtures import ROOT
from test_hardening import runtime_fixture  # noqa: F401  (pytest fixture import)
from test_release_activation_guard import (  # noqa: F401  (pytest fixture imports)
    assert_refused_before_the_host_was_touched, run_sealed, world,
)
from test_release_contract import build_release, outcomes, source, stage  # noqa: F401
from test_release_guardrails import (  # noqa: F401  (pytest fixture imports)
    host_state, make_host, ready_host, run_release, step,
)

from universal_agent_middleware import installer as inst
from universal_agent_middleware import release
from universal_agent_middleware import runtime as rt
from universal_agent_middleware.release_config import (
    BUNDLE_SCHEMA, adopt_config_file, compute_bundle, config_violations, require_config_combination,
)
from universal_agent_middleware.release_seal import create_seal, write_seal

REGISTRY_VERSION = "uam-workspace-registry-v1"
SCOPES_VERSION = "root-scope-registry-v1"


def codes(problems: list[dict[str, str]]) -> set[str]:
    return {problem["code"] for problem in problems}


def bundled(runtime: dict[str, Any]) -> dict[str, Any]:
    return {**runtime, "config_bundle": compute_bundle(runtime)}


def another_workspace(r: dict[str, Any]) -> dict[str, Any]:
    root = Path(r["config_root"]).parent / "another-root"
    root.mkdir(exist_ok=True)
    return {"workspace_id": "another", "root": str(root), "kind": "git-repository",
            "capabilities": ["filesystem.read"]}


# --- ways the files and the canaries can change (each returns the runtime dict to verify) -----------

def registry_gains_a_workspace(r: dict[str, Any], runtime: dict[str, Any] | None = None) -> dict[str, Any]:
    registry = Path(r["registry_file"])
    data = json.loads(registry.read_text())
    data["workspaces"].append(another_workspace(r))
    registry.write_text(json.dumps(data))
    return runtime if runtime is not None else r


def registry_is_reformatted(r: dict[str, Any], runtime: dict[str, Any] | None = None) -> dict[str, Any]:
    registry = Path(r["registry_file"])
    registry.write_text(json.dumps(json.loads(registry.read_text()), indent=4))  # same meaning, other bytes
    return runtime if runtime is not None else r


def scopes_gain_a_scope(r: dict[str, Any], runtime: dict[str, Any] | None = None) -> dict[str, Any]:
    scopes = Path(r["root_scopes_file"])
    data = json.loads(scopes.read_text())
    data["scopes"].append({"scope_id": "extra", "root": str(Path(r["config_root"]).parent), "authority": {}})
    scopes.write_text(json.dumps(data))
    return runtime if runtime is not None else r


def canaries_point_elsewhere(r: dict[str, Any], runtime: dict[str, Any] | None = None) -> dict[str, Any]:
    return {**(runtime if runtime is not None else r),
            "canaries": [{"workspace_id": "fixture", "path": "docs/OTHER.md"}]}


def registry_and_scopes(r: dict[str, Any], runtime: dict[str, Any] | None = None) -> dict[str, Any]:
    registry_gains_a_workspace(r)
    return scopes_gain_a_scope(r, runtime)


def all_three(r: dict[str, Any], runtime: dict[str, Any] | None = None) -> dict[str, Any]:
    return canaries_point_elsewhere(r, registry_and_scopes(r, runtime))


REPLACED: dict[str, tuple[Callable[..., dict[str, Any]], set[str]]] = {
    "the registry gains a workspace": (registry_gains_a_workspace, {"registry_differs"}),
    "the registry is reformatted": (registry_is_reformatted, {"registry_differs"}),
    "the root scopes gain a scope": (scopes_gain_a_scope, {"root_scopes_differ"}),
    "the canaries point elsewhere": (canaries_point_elsewhere, {"canaries_differ"}),
    "registry and root scopes are replaced together": (registry_and_scopes, {"registry_differs", "root_scopes_differ"}),
    "the registry, the root scopes and the canaries are all replaced": (
        all_three, {"registry_differs", "root_scopes_differ", "canaries_differ"}),
}
# What can change on disk while a release waits: the canaries live in the release's own runtime manifest
# (pinned by the seal), so only the two configuration files are replaced from outside.
FILE_REPLACED = {name: REPLACED[name] for name in (
    "the registry gains a workspace", "the registry is reformatted", "the root scopes gain a scope",
    "registry and root scopes are replaced together")}


# --- the combination: a pure verdict ---------------------------------------------------------------

def test_the_bundle_is_the_digest_of_each_part(runtime_fixture):
    r, _, _ = runtime_fixture
    bundle = compute_bundle(r)
    assert bundle["schema_version"] == BUNDLE_SCHEMA
    assert bundle["registry_sha256"] == rt.sha256(Path(r["registry_file"]))
    assert bundle["root_scopes_sha256"] == rt.sha256(Path(r["root_scopes_file"]))
    assert len(bundle["canaries_sha256"]) == 64
    assert compute_bundle(r) == bundle
    assert compute_bundle({**r, "canaries": [{"workspace_id": "fixture", "path": "docs/OTHER.md"}]}) != bundle


def test_a_consistent_combination_has_no_violation(runtime_fixture):
    r, _, _ = runtime_fixture
    assert config_violations(bundled(r), require_bundle=True) == []
    assert config_violations(bundled(r), require_bundle=False) == []


@pytest.mark.parametrize("name", sorted(REPLACED))
def test_each_replaced_part_is_named_and_nothing_else(runtime_fixture, name):
    r, _, _ = runtime_fixture
    recorded = bundled(r)
    mutate, expected = REPLACED[name]
    changed = mutate(r, recorded)
    assert codes(config_violations(changed, require_bundle=True)) == expected


def test_restoring_the_recorded_combination_clears_every_violation(runtime_fixture):
    r, _, _ = runtime_fixture
    recorded = bundled(r)
    registry, scopes = Path(r["registry_file"]).read_bytes(), Path(r["root_scopes_file"]).read_bytes()
    registry_and_scopes(r)
    assert config_violations(recorded, require_bundle=True)
    Path(r["registry_file"]).write_bytes(registry)
    Path(r["root_scopes_file"]).write_bytes(scopes)
    assert config_violations(recorded, require_bundle=True) == []


def remove_registry(r: dict[str, Any]) -> dict[str, Any]:
    Path(r["registry_file"]).unlink()
    return r


def malformed_registry(r: dict[str, Any]) -> dict[str, Any]:
    Path(r["registry_file"]).write_text("{not json")
    return r


def unsupported_registry_version(r: dict[str, Any]) -> dict[str, Any]:
    Path(r["registry_file"]).write_text(json.dumps({"registry_version": "v0", "workspaces": []}))
    return r


def scopes_with_another_schema(r: dict[str, Any]) -> dict[str, Any]:
    Path(r["root_scopes_file"]).write_text(json.dumps({"schema_version": "root-scope-registry-v0", "scopes": []}))
    return r


def scopes_with_overrides(r: dict[str, Any]) -> dict[str, Any]:
    Path(r["root_scopes_file"]).write_text(json.dumps(
        {"schema_version": SCOPES_VERSION, "scopes": [], "overrides": [{"anything": 1}]}))
    return r


def canary_path_escapes(r: dict[str, Any]) -> dict[str, Any]:
    return {**r, "canaries": [{"workspace_id": "fixture", "path": "../outside.md"}]}


def canaries_are_not_a_list(r: dict[str, Any]) -> dict[str, Any]:
    return {**r, "canaries": {"workspace_id": "fixture", "path": "README.md"}}


INCOMPATIBLE: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "the registry is gone": remove_registry,
    "the registry is not JSON": malformed_registry,
    "the registry has an unsupported version": unsupported_registry_version,
    "the root scopes have another schema": scopes_with_another_schema,
    "the root scopes carry overrides this release does not enforce": scopes_with_overrides,
    "a canary path escapes the workspace": canary_path_escapes,
    "the canaries are not a list": canaries_are_not_a_list,
}


@pytest.mark.parametrize("name", sorted(INCOMPATIBLE))
def test_a_configuration_that_cannot_be_loaded_is_a_violation_never_an_exception(runtime_fixture, name):
    r, _, _ = runtime_fixture
    recorded = bundled(r)  # the digests were recorded for a configuration that was fine
    broken = INCOMPATIBLE[name]({**recorded})
    problems = config_violations(broken, require_bundle=True)
    assert codes(problems) == {"config_invalid"}, problems


def test_a_canary_for_a_workspace_the_registry_does_not_declare_is_incoherent_even_when_recorded(runtime_fixture):
    r, _, _ = runtime_fixture
    ghost = {**r, "canaries": [{"workspace_id": "fixture", "path": "README.md"},
                               {"workspace_id": "ghost", "path": "README.md"}]}
    problems = config_violations(bundled(ghost), require_bundle=True)  # the bundle matches: it is still refused
    assert codes(problems) == {"canary_workspace_unregistered"}
    assert "ghost" in problems[0]["detail"] and "fixture" not in problems[0]["detail"]


def test_a_missing_bundle_is_refused_only_where_a_bundle_is_required(runtime_fixture):
    r, _, _ = runtime_fixture
    assert codes(config_violations(r, require_bundle=True)) == {"config_bundle_missing"}
    assert config_violations(r, require_bundle=False) == []  # a release built before bundles existed


MALFORMED_BUNDLES: dict[str, Callable[[dict[str, str]], Any]] = {
    "not a mapping": lambda good: "not a mapping",
    "empty": lambda good: {},
    "only the schema": lambda good: {"schema_version": good["schema_version"]},
    "another schema": lambda good: {**good, "schema_version": "uam-config-bundle-v0"},
    "an extra key": lambda good: {**good, "extra": "x"},
    "a missing digest": lambda good: {key: value for key, value in good.items() if key != "canaries_sha256"},
}


@pytest.mark.parametrize("name", sorted(MALFORMED_BUNDLES))
def test_a_bundle_that_is_not_three_digests_is_malformed(runtime_fixture, name):
    r, _, _ = runtime_fixture
    recorded = MALFORMED_BUNDLES[name](compute_bundle(r))
    problems = config_violations({**r, "config_bundle": recorded}, require_bundle=False)
    assert codes(problems) == {"config_bundle_malformed"}, problems


@pytest.mark.parametrize("key", ["registry_sha256", "root_scopes_sha256", "canaries_sha256"])
@pytest.mark.parametrize("digest", ["abc", "G" * 64, "A" * 64, 7])
def test_a_digest_that_is_not_lowercase_sha256_hex_is_malformed(runtime_fixture, key, digest):
    r, _, _ = runtime_fixture
    problems = config_violations({**r, "config_bundle": {**compute_bundle(r), key: digest}}, require_bundle=False)
    assert codes(problems) == {"config_bundle_malformed"}


def test_require_config_combination_raises_a_message_that_names_the_codes(runtime_fixture):
    r, _, _ = runtime_fixture
    recorded = bundled(r)
    require_config_combination(recorded, require_bundle=True)
    registry_gains_a_workspace(r)
    with pytest.raises(ValueError, match="registry_differs"):
        require_config_combination(recorded, require_bundle=True)


def test_adopting_a_file_never_replaces_a_different_one(tmp_path):
    supplied, destination = tmp_path / "supplied.json", tmp_path / "config.json"
    supplied.write_text('{"narrow": true}')
    assert adopt_config_file(supplied, destination) == "created" and destination.read_bytes() == supplied.read_bytes()
    assert adopt_config_file(supplied, destination) == "identical"
    destination.write_text('{"wide": true}')
    with pytest.raises(ValueError, match="differs from the supplied file"):
        adopt_config_file(supplied, destination)
    assert destination.read_text() == '{"wide": true}'  # the existing file is untouched


# --- installer: stage and activate -------------------------------------------------------------------

IDENTITY = {"source_commit": "c" * 40, "source_tree": "d" * 40, "source_dirty": False, "source_kind": "git_commit"}
CONTRACT = json.loads((ROOT / "src/universal_agent_middleware/tool_contract.json").read_text())


def source_archive() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        def add(name: str, data: bytes) -> None:
            item = tarfile.TarInfo(name)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))

        add("pyproject.toml", b'[project]\nname = "uam-fixture"\nversion = "0.6.1"\n')
        add("tools/system-service/scripts/health.sh", b"#!/bin/sh\nexit 0\n")
        for relative in ("tools/system-service/config/recovery_policies.yaml",
                         "src/universal_agent_middleware/tool_contract.json"):
            add(relative, (ROOT / relative).read_bytes())
        for plist in sorted((ROOT / "tools/system-service/plists").glob("*.plist")):
            add(f"tools/system-service/plists/{plist.name}", plist.read_bytes())
    return buffer.getvalue()


class Toolchain:
    """The child processes ``stage`` runs, replaced by stand-ins that leave the same files behind."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, cmd: list[Any], **kwargs: Any) -> subprocess.CompletedProcess:
        self.calls.append([str(part) for part in cmd])
        if cmd[0] == "git":
            return subprocess.CompletedProcess(cmd, 0, stdout=source_archive(), stderr=b"")
        if cmd[1:3] == ["-m", "build"]:
            (Path(cmd[cmd.index("--outdir") + 1]) / "fixture-0.6.1-py3-none-any.whl").write_bytes(b"stand-in wheel")
        elif cmd[1:3] == ["-m", "venv"]:
            python = Path(cmd[3]) / "bin/python"
            python.parent.mkdir(parents=True)
            python.write_text("stand-in interpreter")
        elif len(cmd) > 1 and cmd[1] == "-I":
            return subprocess.CompletedProcess(
                cmd, 0, stdout=json.dumps({"version": "0.6.1", "contract": CONTRACT}), stderr="")
        elif cmd[1:3] != ["-m", "pip"]:
            raise AssertionError(f"unexpected child process: {cmd}")
        return subprocess.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")


def stage_plan(r: dict[str, Any], home: Path, toolchain: Toolchain, *, registry: Path | None = None,
               canaries: list[dict[str, str]] | None = None) -> Path:
    canaries_file = home / "canaries.json"
    canaries_file.write_text(json.dumps(r["canaries"] if canaries is None else canaries))
    with patch.object(inst, "clean_source", return_value=IDENTITY), \
         patch.object(inst.subprocess, "run", side_effect=toolchain):
        return inst.stage(ROOT, home=home, state_root=Path(r["state_root"]), registry=registry or Path(r["registry_file"]),
                          scopes=Path(r["root_scopes_file"]), canaries=canaries_file,
                          tunnel_config=Path(r["tunnel_config"]), tunnel_client=Path(r["tunnel_client"]))


def test_staging_records_the_combination_in_the_plan_and_the_receipt(runtime_fixture):
    r, _, home = runtime_fixture
    toolchain = Toolchain()
    plan = stage_plan(r, home, toolchain)
    recorded = json.loads(plan.read_text())
    assert recorded["config_bundle"] == compute_bundle(r)
    receipt = json.loads((plan.parent.parent / "STAGING_RECEIPT.json").read_text())
    assert receipt["config_bundle"] == recorded["config_bundle"] and receipt["state"] == "STAGED_NOT_ACTIVE"
    assert config_violations(recorded, require_bundle=True) == []


def test_staging_refuses_a_supplied_registry_that_differs_from_the_existing_one_before_any_child_process(
        runtime_fixture, tmp_path):
    r, _, home = runtime_fixture
    narrow = tmp_path / "narrow.json"
    narrow.write_text(json.dumps({"registry_version": REGISTRY_VERSION, "workspaces": []}))
    existing = Path(r["registry_file"]).read_bytes()
    toolchain = Toolchain()
    with pytest.raises(ValueError, match="workspaces.json already exists and differs"):
        stage_plan(r, home, toolchain, registry=narrow)
    assert toolchain.calls == []  # not even the archive was taken
    assert Path(r["registry_file"]).read_bytes() == existing
    assert not (Path(r["release_root"]) / f"v0.6.1+{'c' * 40}").exists()


def test_staging_refuses_canaries_for_a_workspace_the_registry_does_not_declare(runtime_fixture):
    r, _, home = runtime_fixture
    toolchain = Toolchain()
    with pytest.raises(ValueError, match="canary_workspace_unregistered"):
        stage_plan(r, home, toolchain, canaries=[{"workspace_id": "ghost", "path": "README.md"}])
    assert not [call for call in toolchain.calls if call[1:3] == ["-m", "build"]]  # nothing was built


def test_activation_refuses_a_plan_whose_registry_was_replaced_after_staging(runtime_fixture):
    r, _, home = runtime_fixture
    plan = stage_plan(r, home, Toolchain())
    registry_gains_a_workspace(r)
    with patch.object(inst.subprocess, "run", side_effect=AssertionError("nothing may run")):
        with pytest.raises(ValueError, match="registry_differs"):
            inst.activate(plan, home)
    recovery = Path(r["recovery_root"])
    assert not (recovery / "FROZEN.json").exists() and not (recovery / "INSTALL_RECEIPT.json").exists()


def test_activation_refuses_a_plan_that_records_no_combination(runtime_fixture):
    r, manifest, home = runtime_fixture
    with patch.object(inst.subprocess, "run", side_effect=AssertionError("nothing may run")):
        with pytest.raises(ValueError, match="config_bundle_missing"):
            inst.activate(manifest, home)
    assert not (Path(r["recovery_root"]) / "FROZEN.json").exists()


# --- release: the combination is recorded when built and verified at every admission point ---------

def test_building_records_the_combination_in_the_release_runtime_manifest(runtime_fixture, tmp_path):
    r, _, _ = runtime_fixture
    release_dir = tmp_path / "built"
    release_dir.mkdir()
    (release_dir / "RELEASE_MANIFEST.json").write_text("{}\n")
    stale = {"schema_version": BUNDLE_SCHEMA, "registry_sha256": "0" * 64, "root_scopes_sha256": "1" * 64,
             "canaries_sha256": "2" * 64}  # what the active release carried: never copied, always re-derived
    release._write_runtime_in_release(release_dir, {**r, "config_bundle": stale}, str(tmp_path / "unused.json"))
    written = json.loads((release_dir / "runtime/uam-runtime.json").read_text())
    assert written["config_bundle"] == compute_bundle(r) != stale
    assert written["canaries"] == r["canaries"]


def record_bundle(release_dir: Path) -> dict[str, Any]:
    planned = release_dir / "runtime/uam-runtime.json"
    data = json.loads(planned.read_text())
    data["config_bundle"] = compute_bundle(data)
    rt.atomic_json(planned, data)
    return data


def test_a_bundled_release_passes_staging_when_the_combination_is_unchanged(source):
    record_bundle(build_release(source.r, source.repo))
    candidate, run = stage(source)
    assert candidate is not None
    order = [name for name, _ in outcomes(run)]
    assert order.index("release_exists") + 1 == order.index("config_bundle") < order.index("reviewed_contract")
    gate = step({"steps": run.steps}, "config_bundle")
    assert gate["status"] == "OK" and gate["bundle"] == compute_bundle(source.r)
    assert run.result["config_bundle"] == {"recorded": True, "bundle": compute_bundle(source.r), "verified": True}


@pytest.mark.parametrize("name", sorted(FILE_REPLACED))
def test_a_release_is_refused_at_staging_when_the_files_changed_after_it_was_built(source, name):
    record_bundle(build_release(source.r, source.repo))
    FILE_REPLACED[name][0](source.r)
    candidate, run = stage(source)
    assert candidate is None and outcomes(run)[-1] == ("config_bundle", "FAIL")
    assert codes(run.steps[-1]["violations"]) == FILE_REPLACED[name][1]
    assert "tool_contract" not in [name for name, _ in outcomes(run)]  # the release's code was never probed
    assert run.result["config_bundle"]["verified"] is False


def test_staging_recovers_when_the_recorded_combination_is_restored(source):
    record_bundle(build_release(source.r, source.repo))
    registry = Path(source.r["registry_file"])
    original = registry.read_bytes()
    registry_gains_a_workspace(source.r)
    assert stage(source)[0] is None
    registry.write_bytes(original)
    candidate, run = stage(source)
    assert candidate is not None and ("config_bundle", "OK") in outcomes(run)


def test_a_release_without_a_recorded_bundle_is_only_checked_for_coherence(source):
    build_release(source.r, source.repo)  # built before bundles existed
    registry_gains_a_workspace(source.r)  # a change that cannot be proven or refuted without a record
    candidate, run = stage(source)
    assert candidate is not None
    gate = step({"steps": run.steps}, "config_bundle")
    assert gate["status"] == "OK" and gate["bundle"] == "not_recorded"
    assert run.result["config_bundle"]["recorded"] is False


def test_a_release_whose_canaries_name_an_unregistered_workspace_is_refused_even_without_a_bundle(source):
    build_release(source.r, source.repo)
    Path(source.r["registry_file"]).write_text(json.dumps(
        {"registry_version": REGISTRY_VERSION, "workspaces": [another_workspace(source.r)]}))
    candidate, run = stage(source)
    assert candidate is None and outcomes(run)[-1] == ("config_bundle", "FAIL")
    assert codes(run.steps[-1]["violations"]) == {"canary_workspace_unregistered"}


def test_an_unreadable_release_runtime_manifest_is_a_failed_step_not_an_exception(tmp_path):
    release_dir = tmp_path / "release"
    (release_dir / "runtime").mkdir(parents=True)
    (release_dir / "runtime/uam-runtime.json").write_text("{not json")
    run = release._Run("unused", False, [], {})
    assert release._guard_config_bundle(run, release._Candidate(release_dir, "release"), "config_bundle") is False
    assert (run.steps[-1]["name"], run.steps[-1]["status"]) == ("config_bundle", "FAIL")
    assert "unreadable" in run.steps[-1]["reason"]


# --- release: the authoritative check under the Supervisor lock, before anything is stopped --------

@pytest.mark.parametrize("moment", ["while the gates ran", "after the lock was taken"])
@pytest.mark.parametrize("name", sorted(FILE_REPLACED))
def test_a_replaced_configuration_is_refused_under_the_lock_before_the_service_is_touched(world, name, moment):
    runtime = world.host.runtime
    mutate, expected = FILE_REPLACED[name]
    before = host_state(world.host)
    if moment == "while the gates ran":
        result, calls = run_sealed(world, gates=lambda *a, **k: mutate(runtime) and True)
    else:
        result, calls = run_sealed(world, freeze_hook=lambda: mutate(runtime))
    assert_refused_before_the_host_was_touched(world, result, calls, before, "config_guard_pre_activate")
    guard = step(result, "config_guard_pre_activate")
    assert guard["under_lock"] is True and codes(guard["violations"]) == expected
    assert step(result, "supervisor_quiesce")["status"] == "OK"  # it was refused while the lock was held
    assert result["config_bundle"]["verified"] is False


def test_the_sealed_run_that_finds_the_recorded_combination_activates_and_receipts_it(world):
    result, calls = run_sealed(world)
    assert (result["overall"], result["accepted"]) == ("READY", True), result["steps"]
    guard = step(result, "config_guard_pre_activate")
    assert guard["under_lock"] is True and guard["bundle"] == compute_bundle(world.host.runtime)
    order = [item["name"] for item in result["steps"]]
    assert order.index("seal_guard_pre_activate") < order.index("config_guard_pre_activate") < order.index("tunnel_stop")
    assert result["config_bundle"] == {"recorded": True, "bundle": compute_bundle(world.host.runtime), "verified": True}
    json.dumps(result)
    calls.stop.assert_called_once()


def test_restoring_the_recorded_combination_is_the_recovery_after_a_refused_activation(world):
    registry = Path(world.host.runtime["registry_file"])
    original = registry.read_bytes()
    registry_gains_a_workspace(world.host.runtime)
    before = host_state(world.host)
    refused, calls = run_sealed(world)
    assert_refused_before_the_host_was_touched(world, refused, calls, before, "config_guard_pre_activate")
    registry.write_bytes(original)
    activated, calls = run_sealed(world)
    assert (activated["overall"], activated["accepted"]) == ("READY", True), activated["steps"]
    assert step(activated, "config_guard_pre_activate")["status"] == "OK"


def test_a_sealed_release_must_record_the_combination(world, tmp_path):
    planned = world.release_dir / "runtime/uam-runtime.json"
    data = json.loads(planned.read_text())
    del data["config_bundle"]
    planned.write_text(json.dumps(data, indent=2))
    world.seal_path = tmp_path / "unbundled-seal.json"
    write_seal(world.seal_path, create_seal(world.repo, world.release_dir))
    before = host_state(world.host)
    result, calls = run_sealed(world)
    assert_refused_before_the_host_was_touched(world, result, calls, before, "config_guard_pre_activate")
    assert codes(step(result, "config_guard_pre_activate")["violations"]) == {"config_bundle_missing"}


def test_an_unsealed_candidate_is_refused_when_the_registry_changes_after_staging(ready_host):
    record_bundle(ready_host.candidate.release_dir)
    before = host_state(ready_host)

    def staged_then_replaced(run, runtime):
        registry_gains_a_workspace(ready_host.runtime)
        return ready_host.candidate

    result, calls = run_release(ready_host, stage=staged_then_replaced)
    assert result["failure_stage"] == "config_guard_pre_activate" and result["overall"] == "FAILED"
    assert codes(step(result, "config_guard_pre_activate")["violations"]) == {"registry_differs"}
    assert host_state(ready_host) == before and result["activation"]["performed"] is False
    for untouched in (calls.stop, calls.start, calls.refresh, calls.doctor):
        untouched.assert_not_called()


def test_an_unsealed_candidate_with_the_recorded_combination_is_activated(ready_host):
    recorded = record_bundle(ready_host.candidate.release_dir)["config_bundle"]
    result, _ = run_release(ready_host)
    assert (result["overall"], result["accepted"]) == ("READY", True)
    assert step(result, "config_guard_pre_activate")["bundle"] == recorded
