"""The sealed launch of the ``task-continuity`` profile: admission under a runtime, a state directory of its own, and what the gateway then binds.

``python -m universal_agent_middleware.task_profile --runtime-manifest M`` admits the process as the current release M selects before it loads any code a launch names, keeps the
runtime's registry, refuses a state directory that is (or overlaps) the control plane, honours the runtime's FROZEN latch and stamps its audit records with the release. These tests
pin each of those, and that every other launch (no flag; the read-only service's own ``UAM_RUNTIME_MANIFEST`` binding) behaves as before.

Nothing here touches a live UAM install: runtimes are the production-shaped fixture of ``test_hardening`` under ``tmp_path``. In process the release check runs with
``executing=False`` (as the release tests do) because the test run is not inside a release; the real processes at the end do run it with ``executing=True``, once from the source
tree (refused: not the release) and once from a package copied INTO a fixture release (admitted, and refused again after one changed byte). The last ones start the entry the way
an installed release does (the release's own interpreter, ``-I -B``) in a real venv, with an ambient ``PYTHONPATH`` that names another copy of the package. The latch is an entry
NAMED ``FROZEN.json`` of any kind (a file, a symlink that points nowhere or at itself, a file that cannot be read): the release pipeline reads it with ``os.path.lexists``, so the
admission and every audit write of a bound gateway do too. The only verifier is the TEST STAND-IN of ``consumer_authority_factory.py``: not product, not an issuer, not a grant.
"""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import shutil
import subprocess
import sys
import sysconfig
import venv
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from mcp import Client

import universal_agent_middleware
from universal_agent_middleware import __version__, task_profile
from universal_agent_middleware import runtime as rt
from universal_agent_middleware.audit import AuditIntegrityError
from universal_agent_middleware.consumer import Refusal
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.runtime import AdmissionError

from coordination_fixtures import contract_v2
from synthetic_fixtures import init_git_repo, write_workspace_registry
from directory_fixtures import static_repository
from test_hardening import runtime_fixture  # noqa: F401  (pytest fixture import)
from test_mcp_task_control import Answer, invoke
from test_task_control import NEW_DOC, REQUESTER
from test_task_profile import STAND_IN_FACTORY, STAND_IN_SHA, send_arguments

PACKAGE = Path(universal_agent_middleware.__file__).resolve().parent
WORKSPACE = "sealed-ws"
SEALED_AWAY = "sealed-away"  # a directory whose permissions a latch kind removes (see make_latch)
_validate_release = rt.validate_release  # captured before any test patches the module attribute


@dataclass
class SealedWorld:
    r: dict[str, Any]
    canonical: Path
    registry: str
    state: str
    repo: Path
    home: Path

    @property
    def latch(self) -> Path:
        return Path(self.r["recovery_root"]) / "FROZEN.json"

    @property
    def release(self) -> Path:
        return Path(self.r["current_release"])

    def admit(self) -> dict[str, Any]:
        return rt.admit_dedicated_runtime(self.canonical, self.registry, self.state)

    def deliveries(self) -> list[Path]:
        return sorted((Path(self.state) / "task-control").glob("continuity/deliveries/dlv-*.json"))

    def audit_records(self) -> list[dict[str, Any]]:
        path = Path(self.state) / "audit.jsonl"
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


@pytest.fixture
def world(runtime_fixture, tmp_path):  # noqa: F811
    r, _, home = runtime_fixture
    repo = tmp_path / "repo"
    init_git_repo(repo, files={"README.md": "# sealed launch\n"})
    write_workspace_registry(Path(r["registry_file"]), [static_repository(WORKSPACE, repo)])
    canonical = Path(r["uam_home"]) / "runtime/uam-runtime.json"
    sealed = SealedWorld(r=r, canonical=canonical, registry=r["registry_file"], state=str(home / "task-state"), repo=repo, home=home)
    try:
        with patch("universal_agent_middleware.runtime.validate_release",
                   side_effect=lambda runtime: _validate_release(runtime, executing=False)):
            yield sealed
    finally:  # the latch kinds that take permissions away give them back, so the temporary tree can be removed
        # The directory first, and a link is never followed: the `unsearchable_target` latch is a link into the directory that kind makes
        # unsearchable, and `Path.exists()` follows a link (before 3.14 that raises PermissionError there; 3.14 reads it as absent).
        for locked in (home / SEALED_AWAY, sealed.latch):
            if not locked.is_symlink() and locked.exists():
                locked.chmod(0o700)


def call(server: Any, tool: str, **arguments: Any) -> Answer:
    async def once() -> Answer:
        async with Client(server) as client:
            return await invoke(client, tool, **arguments)

    return asyncio.run(once())


def sealed_contract(world: SealedWorld) -> dict[str, Any]:
    """A stored contract in the profile's own state, created through a sealed gateway so its audit record carries the release."""
    gateway = MiddlewareGateway(world.registry, world.state, sealed_runtime=world.admit())
    return gateway.create_contract(contract_v2("sealed-entry", WORKSPACE, authoritative=["README.md"], allowed=[NEW_DOC]))


# --- admission ----------------------------------------------------------------------------------------------------


def test_admission_returns_the_runtime_and_names_the_release_the_manifest_selects(world):
    runtime = world.admit()
    assert rt.release_id(runtime) == world.release.name
    assert runtime["release_manifest_sha256"] == world.r["release_manifest_sha256"]
    assert runtime["registry_file"] == world.registry


LATCH_KINDS = ("file", "dangling_symlink", "symlink_loop", "unsearchable_target", "unreadable_file")
LATCH_DAMAGES = {
    "frozen": "file", "frozen_dangling_symlink": "dangling_symlink", "frozen_symlink_loop": "symlink_loop",
    "frozen_unsearchable_target": "unsearchable_target", "frozen_unreadable_file": "unreadable_file",
}


def make_latch(world: SealedWorld, kind: str) -> None:
    """Put an entry named FROZEN.json into the runtime's recovery root. Besides a plain file there are the entries ``Path.exists`` reads as absent because it follows the link (a symlink that
    points nowhere, at itself, or into a directory that cannot be searched) and a file whose content cannot be read. The release pipeline reads the latch with ``os.path.lexists``, so each
    of them is a latch there; the ``world`` fixture gives the permissions back at teardown."""
    if kind == "file":
        world.latch.write_text("{}", encoding="utf-8")
    elif kind == "dangling_symlink":
        world.latch.symlink_to(world.home / "no-such-latch-target")
    elif kind == "symlink_loop":
        world.latch.symlink_to(world.latch.name)
    elif kind == "unsearchable_target":
        sealed_away = world.home / SEALED_AWAY
        sealed_away.mkdir()
        sealed_away.chmod(0)
        world.latch.symlink_to(sealed_away / "FROZEN.json")
    elif kind == "unreadable_file":
        world.latch.write_text("{}", encoding="utf-8")
        world.latch.chmod(0)
    else:
        raise AssertionError(kind)


def apply(world: SealedWorld, damage: str) -> tuple[str, str, str]:
    """Break one thing; return (manifest, registry, state) as a launch would name them."""
    manifest, registry, state = str(world.canonical), world.registry, world.state
    release, r = world.release, world.r
    if damage == "manifest_missing":
        manifest = str(world.home / "absent.json")
    elif damage == "manifest_not_json":
        broken = world.home / "broken.json"
        broken.write_text("{", encoding="utf-8")
        manifest = str(broken)
    elif damage == "release_file_changed":
        (release / "venv/bin/python").write_text("tampered", encoding="utf-8")
    elif damage == "release_file_injected":
        (release / "venv/injected.py").write_text("pass\n", encoding="utf-8")
    elif damage == "current_is_another_release":
        other = release.parent / ("v0.4.0+" + "b" * 40)
        (other / "runtime").mkdir(parents=True)
        shutil.copy(release / "runtime/uam-runtime.json", other / "runtime/uam-runtime.json")  # still readable through the canonical path
        current = Path(r["uam_home"]) / "current"
        current.unlink()
        current.symlink_to(other)
    elif damage == "registry_is_another_file":
        other = world.home / "other-workspaces.json"
        shutil.copy(registry, other)
        registry = str(other)
    elif damage == "state_is_the_runtimes_state":
        state = r["state_root"]
    elif damage == "state_inside_the_runtimes_state":
        state = str(Path(r["state_root"]) / "task")
    elif damage == "state_contains_the_runtimes_state":
        state = str(Path(r["state_root"]).parent)
    elif damage == "state_is_the_recovery_root":
        state = r["recovery_root"]
    elif damage == "state_inside_the_credential_root":
        state = str(Path(r["credential_root"]) / "task")
    elif damage == "state_inside_the_config_root":
        state = str(Path(r["config_root"]) / "task")
    elif damage == "state_is_the_log_root":
        state = r["log_root"]
    elif damage == "state_inside_a_release":
        state = str(release / "task")
    elif damage in LATCH_DAMAGES:
        make_latch(world, LATCH_DAMAGES[damage])
    else:
        raise AssertionError(damage)
    return manifest, registry, state


REFUSALS = {
    "manifest_missing": "RUNTIME_UNREADABLE",
    "manifest_not_json": "RUNTIME_UNREADABLE",
    "release_file_changed": "RELEASE_NOT_SEALED",
    "release_file_injected": "RELEASE_NOT_SEALED",
    "current_is_another_release": "RELEASE_NOT_SEALED",
    "registry_is_another_file": "REGISTRY_NOT_RUNTIMES",
    "state_is_the_runtimes_state": "STATE_NOT_DEDICATED",
    "state_inside_the_runtimes_state": "STATE_NOT_DEDICATED",
    "state_contains_the_runtimes_state": "STATE_NOT_DEDICATED",
    "state_is_the_recovery_root": "STATE_NOT_DEDICATED",
    "state_inside_the_credential_root": "STATE_NOT_DEDICATED",
    "state_inside_the_config_root": "STATE_NOT_DEDICATED",
    "state_is_the_log_root": "STATE_NOT_DEDICATED",
    "state_inside_a_release": "STATE_NOT_DEDICATED",
    **{damage: "RUNTIME_FROZEN" for damage in LATCH_DAMAGES},
}


@pytest.mark.parametrize("damage", sorted(REFUSALS))
def test_a_launch_the_runtime_does_not_admit_is_refused_with_one_exact_code(world, damage):
    manifest, registry, state = apply(world, damage)
    with pytest.raises(AdmissionError) as refused:
        rt.admit_dedicated_runtime(manifest, registry, state)
    assert refused.value.code == REFUSALS[damage]
    assert str(refused.value) == REFUSALS[damage], "the message is the code: no path and no value"
    with pytest.raises(Refusal) as profile:
        task_profile.admit_runtime(manifest, registry, state)
    assert profile.value.code == f"TASK_PROFILE_{REFUSALS[damage]}"
    assert not Path(world.state).exists(), "a refused launch creates no state"


def test_an_unsealed_launch_is_not_admitted_under_any_runtime(world):
    assert task_profile.admit_runtime(None, world.registry, world.state) is None


# --- the gateway the admitted runtime binds -------------------------------------------------------------------------------------


def test_a_sealed_gateway_stamps_the_release_keeps_the_latch_and_leaves_the_runtimes_state_alone(world):
    runtime = world.admit()
    production = Path(world.r["audit_file"]).read_bytes()
    gateway = MiddlewareGateway(world.registry, world.state, sealed_runtime=runtime)
    assert gateway.audit.runtime_release == rt.release_id(runtime)
    assert gateway.audit.freeze_file == world.latch
    assert gateway.state_dir == Path(world.state).resolve()
    record = gateway.audit.append(action="seal.test", workspace_id=None, outcome="PASS")
    assert record["runtime_release"] == rt.release_id(runtime)
    # The control plane is protected exactly as for the read-only service, and none of it was written to.
    assert {Path(world.r[key]) for key in ("state_root", "recovery_root", "credential_root", "config_root")} <= set(gateway._control_roots)
    assert Path(world.r["audit_file"]).read_bytes() == production
    assert not (Path(world.r["state_root"]) / "task-control").exists()
    world.latch.write_text("{}", encoding="utf-8")
    with pytest.raises(AuditIntegrityError, match="FROZEN"):
        gateway.audit.append(action="seal.after-latch", workspace_id=None, outcome="PASS")
    assert len(world.audit_records()) == 1, "nothing was written once the latch existed"


def test_the_gateway_itself_refuses_a_sealed_runtime_with_a_state_inside_the_control_plane(world):
    runtime = world.admit()
    with pytest.raises(AdmissionError) as refused:
        MiddlewareGateway(world.registry, world.r["state_root"], sealed_runtime=runtime)
    assert refused.value.code == "STATE_NOT_DEDICATED"


def test_the_environment_binding_of_the_read_only_service_is_unchanged(world, monkeypatch):
    runtime = world.admit()
    release = rt.release_id(runtime)
    # The read-only service's own way: registry and state are the runtime's, the audit stamp and the latch follow.
    monkeypatch.setenv("UAM_RUNTIME_MANIFEST", str(world.canonical))
    service = MiddlewareGateway(world.registry, world.r["state_root"])
    assert (service.audit.runtime_release, service.audit.freeze_file) == (release, world.latch)
    # ... and it still forces the runtime's own state: a dedicated one is refused, as before.
    with pytest.raises(ValueError, match="effective path differs from runtime manifest: state_root"):
        MiddlewareGateway(world.registry, world.state)
    # An explicit sealed runtime is the caller's decision; the variable is not consulted.
    sealed = MiddlewareGateway(world.registry, world.state, sealed_runtime=runtime)
    assert sealed.audit.runtime_release == release
    monkeypatch.delenv("UAM_RUNTIME_MANIFEST")
    plain = MiddlewareGateway(world.registry, str(world.home / "plain-state"))
    assert (plain.audit.runtime_release, plain.audit.freeze_file) == ("development-unverified", None)


@pytest.mark.parametrize("kind", LATCH_KINDS)
def test_every_kind_of_latch_entry_stops_the_audit_writes_of_a_sealed_gateway(world, kind):
    gateway = MiddlewareGateway(world.registry, world.state, sealed_runtime=world.admit())
    gateway.audit.append(action="seal.before-latch", workspace_id=None, outcome="PASS")  # control: it writes while no entry of that name exists
    written = world.audit_records()
    assert len(written) == 1
    make_latch(world, kind)
    with pytest.raises(AuditIntegrityError, match="FROZEN"):
        gateway.audit.append(action="seal.after-latch", workspace_id=None, outcome="PASS")
    assert world.audit_records() == written, "nothing was written once an entry of that name existed"


@pytest.mark.parametrize("kind", LATCH_KINDS)
def test_the_read_only_services_own_binding_reads_the_latch_the_same_way(world, monkeypatch, kind):
    monkeypatch.setenv("UAM_RUNTIME_MANIFEST", str(world.canonical))
    service = MiddlewareGateway(world.registry, world.r["state_root"])
    assert service.audit.freeze_file == world.latch
    service.audit.append(action="seal.service-before-latch", workspace_id=None, outcome="PASS")  # control: the runtime's own chain accepts a write
    make_latch(world, kind)
    with pytest.raises(AuditIntegrityError, match="FROZEN"):
        service.audit.append(action="seal.service-after-latch", workspace_id=None, outcome="PASS")


def test_the_gateway_signature_gains_one_optional_keyword_and_nothing_positional():
    parameters = inspect.signature(MiddlewareGateway.__init__).parameters
    assert [name for name, p in parameters.items() if p.kind is p.POSITIONAL_OR_KEYWORD] == ["self", "registry_path", "state_dir"]
    extra = parameters["sealed_runtime"]
    assert (extra.kind, extra.default) == (extra.KEYWORD_ONLY, None)


# --- the profile entry ------------------------------------------------------------------------------------------------------


def launch(world: SealedWorld, **options: Any):
    return task_profile.build_task_profile_server(
        registry=world.registry, state_dir=world.state, principal=REQUESTER, runtime_manifest=str(world.canonical), **options)


def test_a_sealed_launch_is_deny_all_says_which_release_it_runs_under_and_keeps_its_own_state(world):
    contract = sealed_contract(world)
    production = Path(world.r["audit_file"]).read_bytes()
    server, notice = launch(world)
    runtime = world.admit()
    assert notice == {
        "uam_profile": "task-continuity", "uam_version": __version__, "transport": "stdio", "principal": REQUESTER,
        "identity": task_profile.IDENTITY_STATEMENT, "authority": "DENY_ALL", "authority_factory_sha256": None,
        "legacy_deliver": False, "tools": 11,
        "runtime_release": rt.release_id(runtime), "release_manifest_sha256": runtime["release_manifest_sha256"],
    }
    refused = call(server, "uam_continuity_delivery_send", **send_arguments(contract))
    assert (refused.is_error, refused.body["error_code"]) == (True, "AUTHORITY_DENIED")
    assert world.deliveries() == []
    denials = [record for record in world.audit_records() if record["outcome"] == "DENY"]
    assert [(record["action"], record["details"]["reason"]) for record in denials] == [("task_control.deliver", "NO_AUTHORITY_PORT_CONFIGURED")]
    assert {record["runtime_release"] for record in world.audit_records()} == {rt.release_id(runtime)}
    assert Path(world.r["audit_file"]).read_bytes() == production
    assert not (Path(world.r["state_root"]) / "task-control").exists()


def test_the_frozen_latch_stops_a_launch_and_every_effect_of_a_running_process(world):
    contract = sealed_contract(world)
    server, _ = launch(world, authority_factory=STAND_IN_FACTORY, authority_factory_sha256=STAND_IN_SHA)
    sent = call(server, "uam_continuity_delivery_send", **send_arguments(contract))
    assert not sent.is_error, sent.text
    assert len(world.deliveries()) == 1
    audited = len(world.audit_records())
    world.latch.write_text("{}", encoding="utf-8")
    frozen = call(server, "uam_continuity_delivery_send", **send_arguments(contract, idempotency_key="entry-key-2", authority_ref="grant-0002"))
    assert (frozen.is_error, frozen.body["error_code"]) == (True, "AUTHORITY_DENIED")
    assert len(world.deliveries()) == 1, "no delivery was stored while the latch existed"
    assert len(world.audit_records()) == audited, "no audit record was written while the latch existed"
    with pytest.raises(Refusal) as stopped:
        launch(world)
    assert stopped.value.code == "TASK_PROFILE_RUNTIME_FROZEN"


def test_the_runtime_is_admitted_before_any_file_the_launch_names_is_executed(world, tmp_path):
    marker = tmp_path / "factory-ran"
    factory = tmp_path / "marking_factory.py"
    factory.write_text(
        "from pathlib import Path\n"
        "from consumer_authority_factory import stand_in_authority\n\n"
        f"def make(log=None):\n    Path({str(marker)!r}).write_text('ran', encoding='utf-8')\n    return stand_in_authority(log)\n",
        encoding="utf-8")
    pin = hashlib.sha256(factory.read_bytes()).hexdigest()
    options = {"authority_factory": f"{factory}:make", "authority_factory_sha256": pin}
    with patch.object(sys, "path", [str(Path(__file__).resolve().parent), *sys.path]):
        (world.release / "venv/bin/python").write_text("tampered", encoding="utf-8")
        with pytest.raises(Refusal) as refused:
            launch(world, **options)
        assert refused.value.code == "TASK_PROFILE_RELEASE_NOT_SEALED"
        assert not marker.exists(), "a refused sealed launch never loaded the factory"
        # Positive control: the same file IS executed by an unsealed launch, so the check above can fail.
        task_profile.build_task_profile_server(
            registry=world.registry, state_dir=str(world.home / "unsealed-state"), principal=REQUESTER, **options)
        assert marker.exists()


def test_serve_and_main_carry_the_flag_and_a_refusal_is_one_code_and_no_path(world, capsys):
    from_flag = task_profile.parser().parse_args([
        "--registry", world.registry, "--state-dir", world.state, "--principal", REQUESTER, "--runtime-manifest", str(world.canonical)])
    assert from_flag.runtime_manifest == str(world.canonical)
    options = {
        "registry": world.registry, "state_dir": world.state, "principal": REQUESTER, "endpoint_ref": None,
        "authority_factory": None, "authority_factory_sha256": None, "authority_factory_arg": None,
    }
    capsys.readouterr()
    for damage in ("manifest_missing", "release_file_changed", "registry_is_another_file", "state_is_the_runtimes_state"):
        manifest, registry, state = apply(world, damage)
        with patch("mcp.server.mcpserver.MCPServer.run") as run:
            code = task_profile.serve_task_profile(**{**options, "registry": registry, "state_dir": state}, runtime_manifest=manifest)
        err = capsys.readouterr().err
        assert code == 2 and run.call_count == 0, damage
        assert err == f"task-profile: refused (TASK_PROFILE_{REFUSALS[damage]})\n", err
        assert str(world.home) not in err
        # restore what the damage changed, so the next case starts from a sealed fixture
        if damage == "release_file_changed":
            (world.release / "venv/bin/python").write_text("fixture executable placeholder", encoding="utf-8")
    with patch("mcp.server.mcpserver.MCPServer.run") as run:
        assert task_profile.main([
            "--registry", world.registry, "--state-dir", world.state, "--principal", REQUESTER, "--runtime-manifest", str(world.canonical)]) == 0
    run.assert_called_once_with(transport="stdio")
    notice = json.loads(capsys.readouterr().err)
    assert (notice["authority"], notice["runtime_release"]) == ("DENY_ALL", world.release.name)


# --- real processes: the release check with executing=True -------------------------------------------------------------------


def bind_release(world: SealedWorld) -> None:
    """Re-bind the fixture's release manifest and runtime to what the release holds now and to THIS version of the package."""
    manifest_path = world.release / "RELEASE_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.update(package_version=__version__, files=rt.release_files(world.release))
    rt.atomic_json(manifest_path, manifest)
    runtime_path = world.release / "runtime/uam-runtime.json"
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    runtime["release_manifest_sha256"] = rt.sha256(manifest_path)
    rt.atomic_json(runtime_path, runtime)


def seal_package_into_release(world: SealedWorld) -> Path:
    """Copy this build of the package INTO the fixture release and bind the release to it."""
    site = world.release / "venv/lib/python3/site-packages"
    site.mkdir(parents=True)
    shutil.copytree(PACKAGE, site / "universal_agent_middleware", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    bind_release(world)
    return site


def run_entry(world: SealedWorld, cwd: Path, *, python_path: Path | None = None) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    environment.pop("UAM_RUNTIME_MANIFEST", None)
    if python_path is not None:
        environment["PYTHONPATH"] = os.pathsep.join(filter(None, [str(python_path), environment.get("PYTHONPATH", "")]))
    return subprocess.run(
        [sys.executable, "-B", "-m", "universal_agent_middleware.task_profile", "--runtime-manifest", str(world.canonical),
         "--registry", world.registry, "--state-dir", world.state, "--principal", REQUESTER],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, check=False, env=environment, cwd=str(cwd))


def test_a_process_that_is_not_the_release_it_names_is_refused(world, tmp_path):
    bind_release(world)  # inventory and version match this build, so the only thing left to refuse is "this process is not inside the release"
    done = run_entry(world, tmp_path)
    assert (done.returncode, done.stdout) == (2, "")
    assert done.stderr == "task-profile: refused (TASK_PROFILE_RELEASE_NOT_SEALED)\n"
    assert not Path(world.state).exists()


def test_a_process_running_from_inside_its_release_is_admitted_and_one_changed_byte_refuses_it(world, tmp_path):
    site = seal_package_into_release(world)
    done = run_entry(world, tmp_path, python_path=site)
    assert (done.returncode, done.stdout) == (0, ""), done.stderr
    notice = json.loads(done.stderr.strip().splitlines()[-1])
    manifest = json.loads((world.release / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
    assert (notice["runtime_release"], notice["release_manifest_sha256"], notice["authority"], notice["tools"]) == (
        world.release.name, rt.sha256(world.release / "RELEASE_MANIFEST.json"), "DENY_ALL", 11)
    assert manifest["release_id"] == world.release.name
    assert (Path(world.state) / "task-control").is_dir()
    assert not (Path(world.r["state_root"]) / "task-control").exists()
    with (site / "universal_agent_middleware/task_profile.py").open("a", encoding="utf-8") as handle:
        handle.write("# one changed byte after the release was sealed\n")
    drifted = run_entry(world, tmp_path, python_path=site)
    assert (drifted.returncode, drifted.stdout) == (2, "")
    assert drifted.stderr == "task-profile: refused (TASK_PROFILE_RELEASE_NOT_SEALED)\n"


# --- real processes started the way an installed release is: its own interpreter, ``-I -B``, no environment ---------------------------


def install_into_a_real_venv(world: SealedWorld) -> Path:
    """Turn the fixture release's venv into a real one (the interpreter is a link, as in an installed release), put THIS build of the package into its site-packages and bind the release.

    The fixture has no network, so the third-party packages (``mcp`` and its dependencies, never UAM) are reached through one ``.pth`` file in the release's site-packages; the
    launch itself needs no ``PYTHONPATH``. Returns the release's interpreter."""
    environment = world.release / "venv"
    (environment / "bin/python").unlink()  # the placeholder text of the shared fixture
    venv.EnvBuilder(system_site_packages=False, clear=False, symlinks=True, with_pip=False).create(environment)
    python = environment / "bin/python"
    purelib = Path(subprocess.run([str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
                                  capture_output=True, text=True, timeout=60, check=True).stdout.strip())
    shutil.copytree(PACKAGE, purelib / "universal_agent_middleware", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    dependencies = dict.fromkeys(sysconfig.get_path(name) for name in ("purelib", "platlib"))
    (purelib / "third-party.pth").write_text("\n".join(dependencies) + "\n", encoding="utf-8")
    bind_release(world)
    return python


def run_release_entry(world: SealedWorld, python: Path, cwd: Path, *, flags: tuple[str, ...], pythonpath: Path) -> subprocess.CompletedProcess[str]:
    """Start the Task entry with the release's interpreter. The only ambient influence is PYTHONPATH, always set (to a directory that holds a copy of the package)."""
    environment = {key: value for key, value in os.environ.items() if key not in {"UAM_RUNTIME_MANIFEST", "PYTHONPATH"}}
    environment["PYTHONPATH"] = str(pythonpath)
    return subprocess.run(
        [str(python), *flags, "-m", "universal_agent_middleware.task_profile", "--runtime-manifest", str(world.canonical),
         "--registry", world.registry, "--state-dir", world.state, "--principal", REQUESTER],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, check=False, env=environment, cwd=str(cwd))


def a_copy_of_the_package_outside_the_release(tmp_path: Path) -> Path:
    decoy = tmp_path / "ambient-pythonpath"
    shutil.copytree(PACKAGE, decoy / "universal_agent_middleware", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return decoy


def test_the_isolated_launch_of_an_installed_release_is_admitted_and_an_ambient_pythonpath_cannot_steer_it(world, tmp_path):
    python = install_into_a_real_venv(world)
    decoy = a_copy_of_the_package_outside_the_release(tmp_path)
    isolated = run_release_entry(world, python, tmp_path, flags=("-I", "-B"), pythonpath=decoy)
    assert (isolated.returncode, isolated.stdout) == (0, ""), isolated.stderr
    notice = json.loads(isolated.stderr.strip().splitlines()[-1])
    assert (notice["runtime_release"], notice["authority"], notice["tools"]) == (world.release.name, "DENY_ALL", 11)
    # Control: the same interpreter and the same environment without -I import the copy PYTHONPATH names, which is not the release, so the sealed launch refuses.
    steered = run_release_entry(world, python, tmp_path, flags=("-B",), pythonpath=decoy)
    assert (steered.returncode, steered.stdout) == (2, "")
    assert steered.stderr == "task-profile: refused (TASK_PROFILE_RELEASE_NOT_SEALED)\n"


def test_a_latch_entry_that_cannot_be_followed_refuses_the_isolated_launch_and_removing_it_admits_it_again(world, tmp_path):
    python = install_into_a_real_venv(world)
    decoy = a_copy_of_the_package_outside_the_release(tmp_path)
    world.latch.symlink_to(world.home / "no-such-latch-target")
    refused = run_release_entry(world, python, tmp_path, flags=("-I", "-B"), pythonpath=decoy)
    assert (refused.returncode, refused.stdout) == (2, "")
    assert refused.stderr == "task-profile: refused (TASK_PROFILE_RUNTIME_FROZEN)\n"
    assert not Path(world.state).exists()
    world.latch.unlink()  # control: the entry was the only thing in the way
    admitted = run_release_entry(world, python, tmp_path, flags=("-I", "-B"), pythonpath=decoy)
    assert (admitted.returncode, admitted.stdout) == (0, ""), admitted.stderr
    assert (Path(world.state) / "task-control").is_dir()
