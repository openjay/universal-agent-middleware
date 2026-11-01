"""Sealed activation: the release on disk must be exactly the sealed one, and a difference is
refused before anything is stopped.

The reviewed finding: a second ordinary ``uam release`` BUILDs when the release directory is
missing, has no way to require the already-verified artifact, and after taking the Supervisor lock
re-checks no fingerprint before the tunnel is stopped. ``--expect-seal`` closes exactly that.

The world below is synthetic but uses the real collaborators: a real Git repository and commit, a
real ``RELEASE_MANIFEST.json`` written by the pipeline's own function, a real wheel (zip) and a
venv-shaped tree. Only the collaborators that touch the host (the tunnel, the index refresh, the
Doctor) and the interpreter probe are replaced; nothing here addresses a LaunchAgent or a live
install.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from release_fixtures import ROOT
from synthetic_fixtures import init_git_repo
from test_hardening import runtime_fixture  # noqa: F401  (pytest fixture import)
from test_release_guardrails import (  # noqa: F401  (pytest fixture imports)
    OK, Host, doctor_run, host_state, make_host, ready_host, replacing, step,
)

from universal_agent_middleware import release
from universal_agent_middleware.cli import main
from universal_agent_middleware.release import StepResult
from universal_agent_middleware.release_seal import (
    SEAL_SCHEMA, SealError, create_seal, git_identity, load_seal, verify_seal, write_seal,
)

VERSION = "9.9.9"
PACKAGE_FILES = {
    "__init__.py": f'__version__ = "{VERSION}"\n',
    "core.py": "def observe():\n    return 'read-only'\n",
    "tool_contract.json": '{"tools": {}}\n',
    "adapters/__init__.py": "",
    "adapters/mcp_sdk.py": "def create_session_read_server():\n    return None\n",
}
SITE = "venv/lib/python3.14/site-packages"


def write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode())


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fingerprint(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): sha256_file(p) for p in sorted(root.rglob("*")) if p.is_file()}


def refresh_manifest(release_dir: Path) -> None:
    """Make the manifest agree with the files again: the forgery a naive inventory check accepts."""
    path = release_dir / "RELEASE_MANIFEST.json"
    manifest = json.loads(path.read_text())
    manifest["files"] = release._release_files(release_dir)
    manifest["wheel_sha256"] = sha256_file(release_dir / manifest["wheel_file"])
    path.write_text(json.dumps(manifest, indent=2))


def build_release_dir(runtime: dict[str, Any], manifest_path: Path, commit: str, tree: str,
                      *, salt: str = "") -> Path:
    """A release shaped like the pipeline's: wheel, venv with the installed package, service, runtime."""
    release_dir = Path(runtime["release_root"]) / f"v{VERSION}+{commit}"
    package = release_dir / SITE / "universal_agent_middleware"
    for rel, text in PACKAGE_FILES.items():
        write(package / rel, text)
    write(package / "__pycache__" / "core.cpython-314.pyc", b"bytecode is never fingerprinted")
    write(release_dir / SITE / "anyio/__init__.py", "# dependency code\n")
    for dist, version in (("universal_agent_middleware", VERSION), ("anyio", "4.0.0")):
        info = release_dir / SITE / f"{dist}-{version}.dist-info"
        write(info / "METADATA", f"Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\n\nbody\n")
        write(info / "RECORD", f"{dist}/__init__.py,sha256=abc,1\n")
    write(release_dir / "venv/pyvenv.cfg", "home = /opt/fake/bin\nversion = 3.14.0\n")
    write(release_dir / "venv/bin/python", "fake interpreter executable")
    wheel = release_dir / "artifacts" / f"universal_agent_middleware-{VERSION}-py3-none-any.whl"
    wheel.parent.mkdir(parents=True)
    with zipfile.ZipFile(wheel, "w") as archive:
        for rel, text in PACKAGE_FILES.items():
            archive.writestr(f"universal_agent_middleware/{rel}", text)
        archive.writestr(f"universal_agent_middleware-{VERSION}.dist-info/METADATA",
                         f"Metadata-Version: 2.1\nName: universal-agent-middleware\nVersion: {VERSION}\n\n{salt}")
    write(release_dir / "service/health.sh", "#!/bin/sh\nexit 0\n")
    shutil.copyfile(ROOT / "tools/system-service/config/recovery_policies.yaml",
                    release_dir / "service/recovery_policies.yaml")
    release._write_release_manifest(release_dir, commit, tree, VERSION, wheel.name)
    path = release_dir / "RELEASE_MANIFEST.json"
    manifest = json.loads(path.read_text())
    manifest["tool_contract"] = {"uam_read_file": "a" * 64}  # what the pre-activation gates record
    path.write_text(json.dumps(manifest, indent=2))
    release._write_runtime_in_release(release_dir, runtime, str(manifest_path))
    return release_dir


@dataclass
class World:
    host: Host
    repo: Path
    release_dir: Path
    seal_path: Path
    commit: str
    tree: str

    @property
    def package(self) -> Path:
        return self.release_dir / SITE / "universal_agent_middleware"

    @property
    def site(self) -> Path:
        return self.release_dir / SITE

    def seal(self) -> dict[str, Any]:
        return load_seal(self.seal_path)

    def verify(self, *, release_dir: Path | None = None) -> Any:
        return verify_seal(self.seal(), source_root=self.repo, release_dir=release_dir or self.release_dir)


@pytest.fixture
def world(ready_host, tmp_path):
    repo = tmp_path / "source"
    init_git_repo(repo, files={"pyproject.toml": "[project]\nname = 'fixture'\n",
                               **{f"src/universal_agent_middleware/{rel}": text for rel, text in PACKAGE_FILES.items()}})
    commit, tree = git_identity(repo)
    release_dir = build_release_dir(ready_host.runtime, ready_host.canonical, commit, tree)
    ready_host.report["instance"]["release_id"] = release_dir.name
    seal_path = tmp_path / "seal.json"
    write_seal(seal_path, create_seal(repo, release_dir))
    return World(ready_host, repo, release_dir, seal_path, commit, tree)


def commit_in(repo: Path, *, new_file: str | None = None) -> None:
    if new_file:
        write(repo / new_file, "new\n")
    env = {"GIT_AUTHOR_NAME": "UAM Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
           "GIT_COMMITTER_NAME": "UAM Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid", "PATH": "/usr/bin:/bin"}
    for args in (["add", "-A"], ["commit", "-q", "--allow-empty", "-m", "next"]):
        subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True, timeout=30)


# Every way the artifact, the source or the seal can drift, with the violation each must raise.
def edit_package_file(w: World) -> None:
    write(w.package / "core.py", "def observe():\n    return 'not what was sealed'\n")
    refresh_manifest(w.release_dir)


def add_package_file(w: World) -> None:
    write(w.package / "extra.py", "print('extra')\n")
    refresh_manifest(w.release_dir)


def remove_package_file(w: World) -> None:
    (w.package / "adapters/__init__.py").unlink()
    refresh_manifest(w.release_dir)


def replace_wheel(w: World) -> None:
    wheel = next((w.release_dir / "artifacts").glob("*.whl"))
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("universal_agent_middleware/__init__.py", "replaced")
    refresh_manifest(w.release_dir)


def rebuild_release(w: World) -> None:
    shutil.rmtree(w.release_dir)
    build_release_dir(w.host.runtime, w.host.canonical, w.commit, w.tree, salt="rebuilt")


def change_dependency_record(w: World) -> None:
    write(w.site / "anyio-4.0.0.dist-info/RECORD", "anyio/__init__.py,sha256=different,1\n")
    refresh_manifest(w.release_dir)


def change_dependency_version(w: World) -> None:
    write(w.site / "anyio-4.0.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: anyio\nVersion: 4.0.1\n\n")
    refresh_manifest(w.release_dir)


def add_dependency(w: World) -> None:
    write(w.site / "evil-1.0.dist-info/METADATA", "Name: evil\nVersion: 1.0\n\n")
    write(w.site / "evil-1.0.dist-info/RECORD", "evil.py,,\n")
    refresh_manifest(w.release_dir)


def change_service_file(w: World) -> None:
    write(w.release_dir / "service/health.sh", "#!/bin/sh\nexit 1\n")
    refresh_manifest(w.release_dir)


def change_runtime_manifest(w: World) -> None:
    path = w.release_dir / "runtime/uam-runtime.json"
    runtime = json.loads(path.read_text())
    runtime["registry_file"] = str(w.release_dir / "elsewhere.json")
    path.write_text(json.dumps(runtime, indent=2))


def replace_interpreter(w: World) -> None:
    write(w.release_dir / "venv/bin/python", "a different interpreter executable")
    refresh_manifest(w.release_dir)


def edit_manifest_only(w: World) -> None:
    path = w.release_dir / "RELEASE_MANIFEST.json"
    manifest = json.loads(path.read_text())
    manifest["build_timestamp"] = 1.0
    path.write_text(json.dumps(manifest, indent=2))


def move_head_with_new_content(w: World) -> None:
    commit_in(w.repo, new_file="docs-note.md")


def move_head_without_new_content(w: World) -> None:
    commit_in(w.repo)


def dirty_tracked_file(w: World) -> None:
    write(w.repo / "pyproject.toml", "[project]\nname = 'changed'\n")


def dirty_untracked_file(w: World) -> None:
    write(w.repo / "untracked.txt", "x\n")


# (mutation, violation codes that must all be reported)
RELEASE_DRIFT: dict[str, tuple[Callable[[World], None], set[str]]] = {
    "installed package file edited, manifest regenerated": (edit_package_file, {"package_files_differ", "manifest_differs"}),
    "installed package file added": (add_package_file, {"package_files_differ"}),
    "installed package file removed": (remove_package_file, {"package_files_differ"}),
    "wheel replaced, manifest regenerated": (replace_wheel, {"wheel_differs", "manifest_differs"}),
    "release rebuilt from the same commit": (rebuild_release, {"manifest_differs", "wheel_differs"}),
    "dependency RECORD changed": (change_dependency_record, {"dependencies_differ"}),
    "dependency version changed": (change_dependency_version, {"dependencies_differ"}),
    "dependency added": (add_dependency, {"dependencies_differ"}),
    "inherited service file changed": (change_service_file, {"service_files_differ"}),
    "runtime manifest changed": (change_runtime_manifest, {"runtime_manifest_differs"}),
    "interpreter executable replaced": (replace_interpreter, {"interpreter_differs"}),
    "manifest edited": (edit_manifest_only, {"manifest_differs"}),
}
SOURCE_DRIFT: dict[str, tuple[Callable[[World], None], set[str]]] = {
    "HEAD moved with new content": (move_head_with_new_content, {"commit_differs", "tree_differs"}),
    "HEAD moved, same tree": (move_head_without_new_content, {"commit_differs"}),
    "tracked file modified": (dirty_tracked_file, {"source_dirty"}),
    "untracked file present": (dirty_untracked_file, {"source_dirty"}),
}


def codes(verdict: Any) -> set[str]:
    return {item["code"] for item in verdict.violations}


# --- the seal itself --------------------------------------------------------------------------

def test_a_pristine_release_matches_its_seal(world):
    verdict = world.verify()
    assert verdict.ok and verdict.violations == []
    assert verdict.checked == {"package_files": len(PACKAGE_FILES), "dependencies": 2}
    seal = world.seal()
    assert seal["schema_version"] == SEAL_SCHEMA and seal["release_id"] == world.release_dir.name
    assert seal["source"] == {"commit": world.commit, "tree": world.tree}
    assert set(seal["package_files"]) == set(PACKAGE_FILES)  # bytecode is not a fingerprinted file
    assert seal["package_files"]["core.py"] == hashlib.sha256(PACKAGE_FILES["core.py"].encode()).hexdigest()


@pytest.mark.parametrize("name", RELEASE_DRIFT)
def test_every_artifact_difference_is_reported_by_the_seal(world, name):
    mutate, expected = RELEASE_DRIFT[name]
    mutate(world)
    verdict = world.verify()
    assert not verdict.ok
    assert expected <= codes(verdict), (name, verdict.violations)


@pytest.mark.parametrize("name", SOURCE_DRIFT)
def test_the_wrong_or_changed_source_is_reported_by_the_seal(world, name):
    mutate, expected = SOURCE_DRIFT[name]
    mutate(world)
    verdict = world.verify()
    assert not verdict.ok
    assert expected <= codes(verdict), (name, verdict.violations)


def test_an_unreadable_artifact_is_a_violation_never_a_pass(world):
    shutil.rmtree(world.release_dir / "venv")
    verdict = world.verify()
    assert not verdict.ok
    assert {"package_unreadable", "dependencies_unreadable", "interpreter_unreadable"} <= codes(verdict)


def test_a_missing_release_directory_is_reported(world):
    shutil.rmtree(world.release_dir)
    verdict = world.verify()
    assert not verdict.ok and "release_missing" in codes(verdict)


def test_the_same_bytes_in_another_directory_are_a_different_release(world, tmp_path):
    other = tmp_path / "elsewhere" / world.release_dir.name
    shutil.copytree(world.release_dir, other)
    assert "release_path_differs" in codes(world.verify(release_dir=other))
    renamed = world.release_dir.parent / f"{world.release_dir.name}-copy"
    shutil.copytree(world.release_dir, renamed)
    assert "release_path_differs" in codes(world.verify(release_dir=renamed))


def test_a_seal_forged_together_with_the_artifact_still_contradicts_git(world):
    """Edit the installed file AND the seal to agree: the Git blobs of the sealed commit disagree."""
    forged = "def observe():\n    return 'forged'\n"
    write(world.package / "core.py", forged)
    refresh_manifest(world.release_dir)
    seal = world.seal()
    seal["package_files"]["core.py"] = hashlib.sha256(forged.encode()).hexdigest()
    verdict = verify_seal(seal, source_root=world.repo, release_dir=world.release_dir)
    assert "package_files_differ" not in codes(verdict)  # artifact and seal agree...
    assert "seal_contradicts_git" in codes(verdict)       # ...and Git does not
    assert not verdict.ok


def test_a_seal_for_a_commit_the_repository_does_not_have_is_refused(world):
    seal = world.seal()
    seal["source"] = {"commit": "c" * 40, "tree": "d" * 40}
    verdict = verify_seal(seal, source_root=world.repo, release_dir=world.release_dir)
    assert not verdict.ok and {"commit_differs", "git_blobs_unreadable"} <= codes(verdict)


def test_every_difference_is_listed_not_just_the_first(world):
    edit_package_file(world)
    change_service_file(world)
    replace_interpreter(world)
    dirty_untracked_file(world)
    assert {"package_files_differ", "service_files_differ", "interpreter_differs", "source_dirty"} <= codes(world.verify())


def test_a_symlink_in_the_installed_package_is_never_accepted(world, tmp_path):
    """A link to a file that has the right bytes is still not the sealed file."""
    outside = tmp_path / "same-bytes.py"
    outside.write_text(PACKAGE_FILES["core.py"])
    (world.package / "core.py").unlink()
    (world.package / "core.py").symlink_to(outside)
    refresh_manifest(world.release_dir)
    assert "package_files_differ" in codes(world.verify())


def test_the_interpreter_is_pinned_by_where_its_link_resolves_and_by_its_bytes(world, tmp_path):
    """A real venv's python is a link into the toolchain: both the target path and its bytes are sealed."""
    real = tmp_path / "toolchain" / "python3.14"
    write(real, "interpreter bytes")
    link = world.release_dir / "venv/bin/python"
    link.unlink()
    link.symlink_to(real)
    refresh_manifest(world.release_dir)
    relinked = tmp_path / "relinked.json"
    write_seal(relinked, create_seal(world.repo, world.release_dir))
    sealed = load_seal(relinked)
    assert sealed["interpreter"]["realpath"] == str(real.resolve())
    assert verify_seal(sealed, source_root=world.repo, release_dir=world.release_dir).ok

    real.write_text("interpreter bytes, upgraded in place")
    assert codes(verify_seal(sealed, source_root=world.repo, release_dir=world.release_dir)) == {"interpreter_differs"}

    real.write_text("interpreter bytes")
    twin = tmp_path / "toolchain" / "python3.14-twin"
    write(twin, "interpreter bytes")
    link.unlink()
    link.symlink_to(twin)  # identical bytes, different executable
    assert codes(verify_seal(sealed, source_root=world.repo, release_dir=world.release_dir)) == {"interpreter_differs"}


def test_verification_executes_nothing_from_the_release(world):
    """The guard is static: a release whose interpreter and package would fail loudly is still just bytes."""
    write(world.package / "__init__.py", '__version__ = "9.9.9"\nraise SystemExit("must not run")\n')
    (world.release_dir / "venv/bin/python").chmod(0o644)  # not even executable
    verdict = world.verify()
    assert "package_files_differ" in codes(verdict)  # detected by hashing, never by importing


# --- creating a seal --------------------------------------------------------------------------

def test_sealing_refuses_a_release_built_from_another_commit(world):
    commit_in(world.repo, new_file="later.md")
    with pytest.raises(SealError, match="not built from this commit"):
        create_seal(world.repo, world.release_dir)


def test_sealing_refuses_an_installed_package_that_is_not_the_commit(world):
    write(world.package / "core.py", "def observe():\n    return 'tampered'\n")
    with pytest.raises(SealError, match=r"installed package differs from the Git blobs"):
        create_seal(world.repo, world.release_dir)


def test_sealing_refuses_a_wheel_that_is_not_the_commit(world):
    replace_wheel(world)
    with pytest.raises(SealError, match=r"wheel differs from the Git blobs"):
        create_seal(world.repo, world.release_dir)


def test_sealing_refuses_a_wheel_that_carries_more_than_the_commits_package(world):
    """The package directory can be exact while a module beside it (a stale build leftover) rides along."""
    wheel = next((world.release_dir / "artifacts").glob("*.whl"))
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("zombie.py", "ZOMBIE = True\n")
    refresh_manifest(world.release_dir)
    with pytest.raises(SealError, match=r"wheel holds more than the commit's package.*wheel_stray_member"):
        create_seal(world.repo, world.release_dir)


def test_sealing_refuses_a_release_that_has_not_passed_the_gates(world):
    path = world.release_dir / "RELEASE_MANIFEST.json"
    manifest = json.loads(path.read_text())
    manifest["tool_contract"] = {}
    path.write_text(json.dumps(manifest))
    with pytest.raises(SealError, match="pre-activation gates"):
        create_seal(world.repo, world.release_dir)


def test_sealing_refuses_a_missing_release(world, tmp_path):
    with pytest.raises(SealError, match="manifest unreadable"):
        create_seal(world.repo, tmp_path / "nothing-here")


def test_a_seal_is_never_overwritten(world, tmp_path):
    before = world.seal_path.read_bytes()
    with pytest.raises(SealError, match="already exists"):
        write_seal(world.seal_path, create_seal(world.repo, world.release_dir))
    assert world.seal_path.read_bytes() == before


@pytest.mark.parametrize("damage,pattern", [
    (lambda s: s.pop("package_files"), "keys must be exactly"),
    (lambda s: s.update(extra=1), "keys must be exactly"),
    (lambda s: s.update(schema_version="uam-release-seal-v0"), "schema_version"),
    (lambda s: s.update(release_dir="relative/path"), "absolute path"),
    (lambda s: s["source"].update(commit="abc"), "40-hex"),
    (lambda s: s.update(manifest_sha256="zz"), "manifest_sha256"),
    (lambda s: s["package_files"].update({"core.py": "short"}), "package_files"),
    (lambda s: s.update(package_files={}), "package_files"),
    (lambda s: s["dependencies"].update(anyio={"version": "1"}), "dependencies"),
    (lambda s: s.update(interpreter={"realpath": "/x"}), "interpreter"),
])
def test_a_malformed_seal_is_refused_before_anything_else_runs(world, tmp_path, damage, pattern):
    seal = json.loads(world.seal_path.read_text())
    damage(seal)
    broken = tmp_path / "broken.json"
    broken.write_text(json.dumps(seal))
    with pytest.raises(SealError, match=pattern):
        load_seal(broken)


@pytest.mark.parametrize("content", ["", "not json", "[]", "null"])
def test_an_unparseable_seal_is_refused(tmp_path, content):
    path = tmp_path / "seal.json"
    path.write_text(content)
    with pytest.raises(SealError):
        load_seal(path)
    with pytest.raises(SealError, match="unreadable"):
        load_seal(tmp_path / "missing.json")


# --- the orchestrator: negative controls, all before the service is touched --------------------

def run_sealed(world: World, *, dry_run: bool = False, seal: bool = True, stop: StepResult = OK,
               gates: Callable[..., bool] | None = None, freeze_hook: Callable[[], None] | None = None,
               ) -> tuple[dict[str, Any], SimpleNamespace]:
    """The real orchestrator and the real ``_stage_candidate``; only host-touching collaborators are replaced."""
    host = world.host
    real_guard = release._guard_not_frozen

    def guard(steps, runtime, name):
        if name == "freeze_guard_pre_activate" and freeze_hook:
            freeze_hook()  # runs with the Supervisor lock held, just before the sealed re-check
        return real_guard(steps, runtime, name)

    with patch.object(release, "_locate_source", return_value=(world.repo, "module")) as located, \
         patch.object(release, "_pre_activation_gates", side_effect=gates or (lambda *a, **k: True)) as gated, \
         patch.object(release, "_build_release", side_effect=AssertionError("must not build")) as built, \
         patch.object(release, "_guard_not_frozen", side_effect=guard), \
         replacing("_stop_tunnel", stop) as stopped, \
         replacing("_start_tunnel", OK) as started, \
         patch.object(release, "_refresh_index", return_value=OK) as refresh, \
         patch.object(release, "_run_doctor", side_effect=[doctor_run(host.report)]) as doctor, \
         patch.object(release.time, "sleep"):
        result = release.build_and_activate(
            str(host.canonical), dry_run=dry_run, seal_path=str(world.seal_path) if seal else None)
    return result, SimpleNamespace(located=located, gates=gated, build=built, stop=stopped, start=started,
                                   refresh=refresh, doctor=doctor)


def names(result: dict[str, Any]) -> list[str]:
    return [item["name"] for item in result["steps"]]


def assert_refused_before_the_host_was_touched(world: World, result: dict[str, Any], calls: SimpleNamespace,
                                                before: dict[str, Any], stage: str) -> None:
    assert (result["overall"], result["accepted"], result["exit_code"]) == ("FAILED", False, 1)
    assert result["failure_stage"] == stage
    assert result["activation"]["performed"] is False
    assert host_state(world.host) == before
    calls.build.assert_not_called()
    calls.stop.assert_not_called()
    calls.start.assert_not_called()
    calls.refresh.assert_not_called()
    calls.doctor.assert_not_called()
    assert "tunnel_stop" not in names(result) and "activate" not in names(result)


def test_the_sealed_release_passes_every_guard_and_is_activated_unchanged(world):
    before_files = fingerprint(world.release_dir)
    result, calls = run_sealed(world)
    assert (result["overall"], result["accepted"], result["exit_code"]) == ("READY", True, 0), result["steps"]
    order = names(result)
    assert order.index("seal_declaration") < order.index("freeze_guard") < order.index("seal_identity") \
        < order.index("release_exists") < order.index("seal_guard") < order.index("supervisor_quiesce") \
        < order.index("freeze_guard_pre_activate") < order.index("seal_guard_pre_activate") \
        < order.index("tunnel_stop") < order.index("activate")
    assert step(result, "release_exists")["status"] == "REUSE"
    assert step(result, "seal_guard")["under_lock"] is False
    assert step(result, "seal_guard_pre_activate")["under_lock"] is True
    assert step(result, "seal_guard_pre_activate")["package_files"] == len(PACKAGE_FILES)
    assert result["seal"]["sha256"] == sha256_file(world.seal_path)
    assert result["activation"]["active_release"]["release_id"] == world.release_dir.name
    calls.build.assert_not_called()
    calls.stop.assert_called_once()
    assert fingerprint(world.release_dir) == before_files  # a sealed release is never rewritten


def test_the_seal_is_checked_before_the_gates_execute_the_release(world):
    """The interpreter probe runs the release's code, so the bytes must be the sealed ones first."""
    seen: list[list[str]] = []

    def gates(run, *args):
        seen.append([item["name"] for item in run.steps])
        return True

    result, _ = run_sealed(world, gates=gates)
    assert result["accepted"], result["steps"]
    assert len(seen) == 1
    assert "seal_guard" in seen[0] and "seal_guard_pre_activate" not in seen[0]


@pytest.mark.parametrize("name", RELEASE_DRIFT)
def test_a_changed_artifact_is_refused_before_the_gates_or_the_service(world, name):
    before = host_state(world.host)
    RELEASE_DRIFT[name][0](world)
    result, calls = run_sealed(world)
    assert_refused_before_the_host_was_touched(world, result, calls, before, "seal_guard")
    calls.gates.assert_not_called()  # the release's own interpreter was never run
    assert RELEASE_DRIFT[name][1] <= {item["code"] for item in step(result, "seal_guard")["violations"]}


@pytest.mark.parametrize("name", RELEASE_DRIFT)
def test_an_artifact_changed_while_the_gates_ran_is_refused_under_the_lock(world, name):
    before = host_state(world.host)
    result, calls = run_sealed(world, gates=lambda *a, **k: RELEASE_DRIFT[name][0](world) or True)
    assert_refused_before_the_host_was_touched(world, result, calls, before, "seal_guard_pre_activate")
    assert step(result, "seal_guard_pre_activate")["under_lock"] is True
    assert RELEASE_DRIFT[name][1] <= {item["code"] for item in step(result, "seal_guard_pre_activate")["violations"]}
    calls.gates.assert_called_once()


def change_dependency_code(w: World) -> None:
    """Dependency code is covered by the manifest inventory, not by the seal's RECORD fingerprint."""
    write(w.site / "anyio/__init__.py", "# tampered dependency code\n")


def test_changed_dependency_code_is_refused_at_staging_by_the_inventory(world):
    before = host_state(world.host)
    change_dependency_code(world)
    result, calls = run_sealed(world)
    assert_refused_before_the_host_was_touched(world, result, calls, before, "release_exists")
    assert "hash mismatch: " + SITE + "/anyio/__init__.py" in step(result, "release_exists")["reason"]
    calls.gates.assert_not_called()


@pytest.mark.parametrize("moment", ["while the gates ran", "after the lock was taken"])
def test_changed_dependency_code_is_refused_under_the_lock_by_the_inventory(world, moment):
    before = host_state(world.host)
    if moment == "while the gates ran":
        result, calls = run_sealed(world, gates=lambda *a, **k: change_dependency_code(world) or True)
    else:
        result, calls = run_sealed(world, freeze_hook=lambda: change_dependency_code(world))
    assert_refused_before_the_host_was_touched(world, result, calls, before, "seal_guard_pre_activate")
    assert "release_invalid" in {item["code"] for item in step(result, "seal_guard_pre_activate")["violations"]}


@pytest.mark.parametrize("name", RELEASE_DRIFT)
def test_an_artifact_changed_after_the_lock_was_taken_is_refused_before_the_stop(world, name):
    before = host_state(world.host)
    result, calls = run_sealed(world, freeze_hook=lambda: RELEASE_DRIFT[name][0](world))
    assert_refused_before_the_host_was_touched(world, result, calls, before, "seal_guard_pre_activate")
    assert step(result, "supervisor_quiesce")["status"] == "OK"  # the lock was held when it was refused
    assert RELEASE_DRIFT[name][1] <= {item["code"] for item in step(result, "seal_guard_pre_activate")["violations"]}


def test_a_missing_release_directory_is_never_built(world):
    before = host_state(world.host)
    shutil.rmtree(world.release_dir)
    result, calls = run_sealed(world)
    assert_refused_before_the_host_was_touched(world, result, calls, before, "seal_identity")
    assert "release_missing" in {item["code"] for item in step(result, "seal_identity")["violations"]}
    assert not world.release_dir.exists()  # nothing was built in its place
    calls.gates.assert_not_called()
    assert "release_exists" not in names(result)


def test_a_release_that_vanishes_after_the_identity_check_is_still_never_built(world):
    before = host_state(world.host)
    original = release._sealed_target

    def vanish(seal, steps, commit_sha, tree_sha, release_dir):
        outcome = original(seal, steps, commit_sha, tree_sha, release_dir)
        shutil.rmtree(release_dir)
        return outcome

    with patch.object(release, "_sealed_target", side_effect=vanish):
        result, calls = run_sealed(world)
    assert_refused_before_the_host_was_touched(world, result, calls, before, "release_exists")
    assert "never builds" in step(result, "release_exists")["reason"]


@pytest.mark.parametrize("name", SOURCE_DRIFT)
def test_a_wrongly_selected_or_changed_source_is_refused(world, name):
    before = host_state(world.host)
    SOURCE_DRIFT[name][0](world)
    result, calls = run_sealed(world)
    stage = "git_clean" if "source_dirty" in SOURCE_DRIFT[name][1] else "seal_identity"
    assert_refused_before_the_host_was_touched(world, result, calls, before, stage)
    if stage == "seal_identity":
        assert SOURCE_DRIFT[name][1] <= {item["code"] for item in step(result, "seal_identity")["violations"]}
    calls.gates.assert_not_called()


def test_a_release_directory_with_the_right_bytes_but_not_the_sealed_path_is_refused(world, tmp_path):
    """Same commit, same bytes, but the runtime selects another release root: not the sealed release."""
    before = host_state(world.host)
    relocated = tmp_path / "other-releases"
    relocated.mkdir()
    shutil.copytree(world.release_dir, relocated / world.release_dir.name)
    shutil.rmtree(world.release_dir)
    runtime = json.loads(world.host.canonical.read_text())
    runtime["release_root"] = str(relocated)
    with patch.object(release, "load_runtime", return_value=runtime):
        result, calls = run_sealed(world)
    assert_refused_before_the_host_was_touched(world, result, calls, before, "seal_identity")
    assert "release_path_differs" in {item["code"] for item in step(result, "seal_identity")["violations"]}


@pytest.mark.parametrize("damage", ["missing", "garbage", "unknown-key"])
def test_an_unusable_seal_stops_the_run_before_any_other_step(world, damage):
    before = host_state(world.host)
    if damage == "missing":
        world.seal_path.unlink()
    elif damage == "garbage":
        world.seal_path.write_text("not json")
    else:
        world.seal_path.write_text(json.dumps({**json.loads(world.seal_path.read_text()), "extra": 1}))
    result, calls = run_sealed(world)
    assert_refused_before_the_host_was_touched(world, result, calls, before, "seal_declaration")
    assert names(result) == ["seal_declaration"]
    calls.located.assert_not_called()
    calls.gates.assert_not_called()


def test_a_dry_run_verifies_the_seal_without_the_lock_or_the_service(world):
    before = host_state(world.host)
    result, calls = run_sealed(world, dry_run=True)
    assert (result["overall"], result["exit_code"]) == ("DRY_RUN", 1)
    assert step(result, "seal_guard")["status"] == "OK"
    assert not {"supervisor_quiesce", "seal_guard_pre_activate", "tunnel_stop"} & set(names(result))
    calls.stop.assert_not_called()
    assert host_state(world.host) == before


def test_a_dry_run_refuses_a_changed_artifact(world):
    before = host_state(world.host)
    edit_package_file(world)
    result, calls = run_sealed(world, dry_run=True)
    assert_refused_before_the_host_was_touched(world, result, calls, before, "seal_guard")


def test_a_failed_stop_after_a_passing_guard_is_still_reported_by_the_stop(world):
    """Positive control for the order: the guard passed, so the stop was reached and is what failed."""
    result, calls = run_sealed(world, stop=StepResult(False, "launchctl refused"))
    assert result["failure_stage"] == "tunnel_stop"
    assert step(result, "seal_guard_pre_activate")["status"] == "OK"
    calls.stop.assert_called_once()
    assert result["activation"]["performed"] is False


# --- compatibility: without a seal nothing changes ---------------------------------------------

def test_without_a_seal_a_missing_release_is_still_built_as_before(world):
    """Characterisation of the retained default: this is the behaviour the seal exists to opt out of."""
    shutil.rmtree(world.release_dir)
    host = world.host
    with patch.object(release, "_locate_source", return_value=(world.repo, "module")), \
         patch.object(release, "_build_release", side_effect=release.ReleaseError("stop here")) as built, \
         patch.object(release, "_interpreter_identity", return_value={"path": "p", "version": "v"}):
        result = release.build_and_activate(str(host.canonical), dry_run=True)
    built.assert_called_once()
    assert "seal_declaration" not in names(result) and "seal" not in result


@pytest.mark.parametrize("sealed", [True, False])
def test_the_gates_are_told_not_to_rewrite_a_sealed_release(world, sealed):
    run = release._Run(str(world.host.canonical), True, [], {}, seal=world.seal() if sealed else None)
    candidate = release._Candidate(world.release_dir, world.release_dir.name)
    with patch.object(release, "_reviewed_contract", return_value={"uam_read_file": "c" * 64}), \
         patch.object(release, "_update_tool_contract", return_value=StepResult(False, "stop here")) as contract:
        assert release._pre_activation_gates(
            run, world.host.runtime, candidate, world.repo, world.commit, world.tree) is False
    assert contract.call_args.kwargs["rewrite_manifest"] is (not sealed)


def test_a_sealed_gate_never_rewrites_the_release_manifest(world):
    """The pre-activation gate repairs a missing tool contract in an ordinary release; never in a sealed one."""
    path = world.release_dir / "RELEASE_MANIFEST.json"
    probed = SimpleNamespace(
        data={"contract": {"uam_read_file": "b" * 64}}, error="",
        outcome=SimpleNamespace(receipt=lambda: {"stage": "candidate_probe"}))
    reviewed = {"uam_read_file": "b" * 64}
    original = path.read_bytes()
    with patch.object(release, "run_probe", return_value=probed):
        sealed = release._update_tool_contract(world.release_dir, world.host.runtime,
                                               reviewed_contract=reviewed, rewrite_manifest=False)
        assert not sealed.ok and "never rewritten" in sealed.reason
        assert path.read_bytes() == original
        repaired = release._update_tool_contract(world.release_dir, world.host.runtime,
                                                 reviewed_contract=reviewed)
    assert repaired.ok and path.read_bytes() != original


# --- the CLI -----------------------------------------------------------------------------------

def test_cli_release_seal_writes_a_seal_and_never_overwrites_it(world, tmp_path, capsys):
    out = tmp_path / "cli-seal.json"
    argv = ["release-seal", "--release-dir", str(world.release_dir), "--source-root", str(world.repo),
            "--out", str(out), "--json"]
    assert main(argv) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["sha256"] == sha256_file(out) and summary["commit"] == world.commit
    assert summary["package_files"] == len(PACKAGE_FILES) and summary["release_id"] == world.release_dir.name
    assert load_seal(out)["source"]["tree"] == world.tree
    written = out.read_bytes()
    assert main(argv) == 1
    assert "already exists" in capsys.readouterr().err
    assert out.read_bytes() == written


def test_cli_release_seal_refuses_a_release_that_is_not_the_commit(world, tmp_path, capsys):
    write(world.package / "core.py", "tampered\n")
    out = tmp_path / "never.json"
    assert main(["release-seal", "--release-dir", str(world.release_dir), "--source-root", str(world.repo),
                 "--out", str(out)]) == 1
    assert "release-seal refused" in capsys.readouterr().err
    assert not out.exists()


def test_cli_release_passes_the_seal_to_the_pipeline():
    with patch("universal_agent_middleware.release.build_and_activate",
               return_value={"overall": "FAILED", "accepted": False, "exit_code": 1, "steps": []}) as pipeline:
        assert main(["release", "--runtime-manifest", "m.json", "--expect-seal", "s.json"]) == 1
        pipeline.assert_called_once_with(manifest_path="m.json", dry_run=False, acceptance_path=None,
                                         seal_path="s.json")
        pipeline.reset_mock()
        main(["release", "--runtime-manifest", "m.json"])
        # the legacy invocation reaches the pipeline exactly as before: no new argument at all
        assert pipeline.call_args.kwargs == {"manifest_path": "m.json", "dry_run": False, "acceptance_path": None}
