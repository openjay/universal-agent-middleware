"""v0.6.1 F-REL-1: a release is built from the exact commit, never from the working tree.

The retired pipeline ran ``pip wheel <worktree>`` and then compared the installed package with that
same worktree. Ignored files (a stale ``build/lib``, a local override module) enter such a wheel
while ``git status`` stays clean, and the comparison cannot see them because it reads the same
files. These tests use real Git repositories, a real ``pip wheel`` (offline, without build
isolation) and a real venv; no service, Supervisor or launchd is involved.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import warnings
import zipfile
from pathlib import Path

import pytest
from synthetic_fixtures import init_git_repo

from universal_agent_middleware import release
from universal_agent_middleware.release_build import (
    BuildError, build_violations, export_commit, export_differences, tree_entries,
)
from universal_agent_middleware.release_seal import git_package_files, wheel_inventory_violations

VERSION = "9.9.9"
PYPROJECT = f"""[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "universal-agent-middleware"
version = "{VERSION}"
dependencies = []

[project.optional-dependencies]
service = []

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
universal_agent_middleware = ["tool_contract.json"]
"""
BROKEN_BACKEND = f"""[build-system]
requires = []
build-backend = "no.such.backend"

[project]
name = "universal-agent-middleware"
version = "{VERSION}"
"""
PACKAGE_FILES = {
    "__init__.py": f'__version__ = "{VERSION}"\n',
    "core.py": "VALUE = 1\n",
    "tool_contract.json": "{}\n",
}
DIST_INFO = f"universal_agent_middleware-{VERSION}.dist-info"
METADATA = f"Metadata-Version: 2.1\nName: universal-agent-middleware\nVersion: {VERSION}\n\n"
IGNORED = "build/\n*.egg-info/\nlocal_*.py\n"
PACKAGE = "src/universal_agent_middleware"


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def head(repo: Path) -> str:
    return git(repo, "rev-parse", "HEAD")


def make_project(base: Path, extra: dict[str, str] | None = None) -> Path:
    repo = base / "source"
    files = {"pyproject.toml": PYPROJECT, ".gitignore": IGNORED,
             **{f"{PACKAGE}/{rel}": text for rel, text in PACKAGE_FILES.items()}, **(extra or {})}
    init_git_repo(repo, files=files)
    assert head(repo)
    return repo


def exported_files(root: Path) -> set[str]:
    return {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file() or path.is_symlink()}


def blobs() -> dict[str, str]:
    return {rel: hashlib.sha256(text.encode()).hexdigest() for rel, text in PACKAGE_FILES.items()}


@pytest.fixture
def offline_pip(monkeypatch):
    """Real pip and venv, no index and no build isolation (the build needs no downloaded requirement)."""
    monkeypatch.setenv("PIP_NO_INDEX", "1")
    monkeypatch.setenv("PIP_NO_BUILD_ISOLATION", "0")
    monkeypatch.setenv("PIP_DISABLE_PIP_VERSION_CHECK", "1")
    monkeypatch.setattr(release, "_python", lambda source_root: sys.executable)


# --- the export is the commit, proved object by object -------------------------------------------

def test_the_export_is_the_commit_and_nothing_ignored_untracked_or_edited(tmp_path):
    repo = make_project(tmp_path)
    write(repo / f"{PACKAGE}/local_override.py", "OVERRIDE = True\n")  # ignored
    write(repo / "build/lib/universal_agent_middleware/zombie.py", "ZOMBIE = True\n")  # ignored
    write(repo / "notes.txt", "untracked\n")
    write(repo / f"{PACKAGE}/core.py", "VALUE = 'edited after the commit'\n")
    destination = tmp_path / "export"
    summary = export_commit(repo, head(repo), destination)
    assert exported_files(destination) == set(git(repo, "ls-tree", "-r", "--name-only", "HEAD").splitlines())
    assert (destination / PACKAGE / "core.py").read_text() == PACKAGE_FILES["core.py"]
    assert summary == {"commit": head(repo), "files": len(exported_files(destination))}


def test_a_benign_attribute_file_does_not_change_the_export(tmp_path):
    repo = make_project(tmp_path, {".gitattributes": "*.py text eol=lf\n"})
    export_commit(repo, head(repo), tmp_path / "export")


@pytest.mark.parametrize("attribute,name,content", [
    ("export-ignore", "note.txt", "tracked, but the archive would drop it\n"),
    ("export-subst", "stamp.txt", "$Format:%H$\n"),
    ("text eol=crlf", "lines.txt", "one\ntwo\n"),
])
def test_an_archive_that_differs_from_its_commit_is_refused(tmp_path, attribute, name, content):
    path = f"{PACKAGE}/{name}"
    repo = make_project(tmp_path, {".gitattributes": f"{path} {attribute}\n", path: content})
    with pytest.raises(BuildError, match="not the tree") as refused:
        export_commit(repo, head(repo), tmp_path / "export")
    assert refused.value.stage == "export_commit" and name in refused.value.reason


def test_a_submodule_entry_is_refused(tmp_path):
    repo = make_project(tmp_path)
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{head(repo)},vendor/sub")
    git(repo, "commit", "-qm", "gitlink")
    with pytest.raises(BuildError, match="submodules"):
        export_commit(repo, head(repo), tmp_path / "export")


def test_a_subdirectory_of_a_repository_is_not_a_source_root(tmp_path):
    repo = make_project(tmp_path)
    with pytest.raises(BuildError, match="not the root"):
        export_commit(repo / "src", head(repo), tmp_path / "export")


def test_an_unknown_commit_is_a_build_error_not_an_empty_export(tmp_path):
    repo = make_project(tmp_path)
    with pytest.raises(BuildError, match="git ls-tree"):
        export_commit(repo, "0" * 40, tmp_path / "export")
    assert not (tmp_path / "export").exists()


def test_the_export_check_sees_missing_extra_changed_and_mode_drift_and_symlinks(tmp_path):
    repo = make_project(tmp_path, {"tools/run.sh": "#!/bin/sh\n"})
    os.symlink("pyproject.toml", repo / "alias.toml")
    git(repo, "add", "--chmod=+x", "tools/run.sh")
    git(repo, "add", "alias.toml")
    git(repo, "commit", "-qm", "executable and link")
    destination = tmp_path / "export"
    export_commit(repo, head(repo), destination)
    entries = tree_entries(repo, head(repo))
    modes = {entry.path: entry.mode for entry in entries}
    assert modes["tools/run.sh"] == "100755" and modes["alias.toml"] == "120000"
    assert not any(export_differences(entries, destination).values())

    (destination / PACKAGE / "core.py").unlink()
    write(destination / PACKAGE / "extra.py", "x = 1\n")
    write(destination / PACKAGE / "__init__.py", "changed\n")
    (destination / "tools/run.sh").chmod(0o644)
    (destination / "alias.toml").unlink()
    write(destination / "alias.toml", "now a regular file\n")
    assert export_differences(entries, destination) == {
        "missing": [f"{PACKAGE}/core.py"],
        "unexpected": [f"{PACKAGE}/extra.py"],
        "changed": ["alias.toml", f"{PACKAGE}/__init__.py", "tools/run.sh"],
    }


# --- the wheel's whole inventory, not only its package directory ---------------------------------

def good_members() -> dict[str, str]:
    return {**{f"universal_agent_middleware/{rel}": text for rel, text in PACKAGE_FILES.items()},
            f"{DIST_INFO}/METADATA": METADATA, f"{DIST_INFO}/WHEEL": "Wheel-Version: 1.0\n",
            f"{DIST_INFO}/RECORD": ""}


def without(suffix: str) -> dict[str, str]:
    return {name: text for name, text in good_members().items() if not name.endswith(suffix)}


def write_wheel(path: Path, members: dict[str, str], *, again: dict[str, str] | None = None) -> Path:
    with warnings.catch_warnings(), zipfile.ZipFile(path, "w") as archive:
        warnings.simplefilter("ignore")  # a name stored twice is deliberate in one case
        for name, text in {**members}.items():
            archive.writestr(name, text)
        for name, text in (again or {}).items():
            archive.writestr(name, text)
    return path


WHEEL_CASES = {
    "faithful": (good_members(), set()),
    "a module beside the package": ({**good_members(), "zombie.py": "ZOMBIE = True\n"}, {"wheel_stray_member"}),
    "a stale module inside the package": (
        {**good_members(), "universal_agent_middleware/zombie.py": "ZOMBIE = True\n"}, {"wheel_package_differs"}),
    "an edited package file": (
        {**good_members(), "universal_agent_middleware/core.py": "VALUE = 'stale'\n"}, {"wheel_package_differs"}),
    "a missing package file": (without("/core.py"), {"wheel_package_differs"}),
    "bytecode shipped as a module": (
        {**good_members(), "universal_agent_middleware/zombie.pyc": "bytes"}, {"wheel_bytecode_member"}),
    "a stale dist-info of another version": (
        {**good_members(), "universal_agent_middleware-0.0.1.dist-info/METADATA": METADATA}, {"wheel_stray_member"}),
    "a wheel that declares another version": (
        {**good_members(), f"{DIST_INFO}/METADATA": METADATA.replace(VERSION, "9.9.8")}, {"wheel_version_differs"}),
    "a wheel without metadata": (without("/METADATA"), {"wheel_metadata_missing"}),
    "a member that leaves the wheel root": ({**good_members(), "../evil.py": "x"}, {"wheel_unsafe_member"}),
    "an absolute member": ({**good_members(), "/evil.py": "x"}, {"wheel_unsafe_member"}),
    "a backslash member": ({**good_members(), "pkg\\evil.py": "x"}, {"wheel_unsafe_member"}),
}


@pytest.mark.parametrize("label", sorted(WHEEL_CASES))
def test_the_wheel_inventory_accounts_for_every_member(tmp_path, label):
    members, expected_codes = WHEEL_CASES[label]
    wheel = write_wheel(tmp_path / "pkg.whl", members)
    codes = {item["code"] for item in wheel_inventory_violations(wheel, blobs(), version=VERSION)}
    assert codes == expected_codes


def test_a_member_stored_twice_is_a_violation_even_when_both_copies_are_the_commits(tmp_path):
    wheel = write_wheel(tmp_path / "twice.whl", good_members(),
                        again={"universal_agent_middleware/core.py": PACKAGE_FILES["core.py"]})
    codes = {item["code"] for item in wheel_inventory_violations(wheel, blobs(), version=VERSION)}
    assert codes == {"wheel_duplicate_member"}


def test_a_wheel_the_manifest_places_outside_the_release_is_refused(tmp_path):
    release_dir = tmp_path / "release"
    for rel, text in PACKAGE_FILES.items():
        write(release_dir / "venv/lib/python3.14/site-packages/universal_agent_middleware" / rel, text)
    write_wheel(tmp_path / "outside.whl", good_members())  # a faithful wheel, but not inside the release
    codes = {item["code"] for item in build_violations(blobs(), release_dir, "../outside.whl", version=VERSION)}
    assert codes == {"wheel_path_unsafe"}


# --- the real build: nothing outside the commit can enter it -------------------------------------

def build_in(tmp_path: Path, repo: Path, steps: list[dict]) -> Path:
    release_dir = tmp_path / "releases" / f"v{VERSION}+{head(repo)}"
    registry, scopes = tmp_path / "config/workspaces.json", tmp_path / "config/root_scopes.json"
    write(registry, json.dumps({"registry_version": "uam-workspace-registry-v1", "workspaces": []}))
    write(scopes, json.dumps({"schema_version": "root-scope-registry-v1", "scopes": []}))
    runtime = {"uam_home": str(tmp_path / "uam-home"), "registry_file": str(registry),
               "root_scopes_file": str(scopes), "canaries": []}
    release._build_release(release_dir, repo, runtime, head(repo), git(repo, "rev-parse", "HEAD^{tree}"),
                           VERSION, str(tmp_path / "uam-runtime.json"), steps)
    return release_dir


def installed_package(release_dir: Path) -> Path:
    (site,) = (release_dir / "venv/lib").glob("python3*/site-packages")
    return site / "universal_agent_middleware"


def test_a_real_build_cannot_pick_up_ignored_or_stale_files(tmp_path, offline_pip):
    repo = make_project(tmp_path)
    write(repo / f"{PACKAGE}/local_override.py", "OVERRIDE = True\n")  # ignored by .gitignore
    write(repo / "build/lib/universal_agent_middleware/zombie.py", "ZOMBIE = True\n")  # a stale leftover
    write(repo / "build/lib/stray_top_level.py", "STRAY = True\n")
    assert git(repo, "status", "--porcelain") == ""  # the clean check cannot see any of it

    steps: list[dict] = []
    release_dir = build_in(tmp_path, repo, steps)

    assert [(item["name"], item["status"]) for item in steps] == [
        ("export_commit", "OK"), ("build_wheel", "OK"), ("install_wheel", "OK"), ("verify_build", "OK"),
        ("copy_service", "SKIP"), ("release_manifest", "OK"), ("runtime_manifest", "OK")]
    (wheel,) = (release_dir / "artifacts").glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        members = {info.filename for info in archive.infolist()}
    assert {name for name in members if not name.startswith(f"{DIST_INFO}/")} == {
        f"universal_agent_middleware/{rel}" for rel in PACKAGE_FILES}
    installed = {path.relative_to(installed_package(release_dir)).as_posix()
                 for path in installed_package(release_dir).rglob("*")
                 if path.is_file() and "__pycache__" not in path.parts}
    assert installed == set(PACKAGE_FILES) == set(git_package_files(repo, head(repo)))
    manifest = json.loads((release_dir / "RELEASE_MANIFEST.json").read_text())
    assert manifest["wheel_file"] == f"artifacts/{wheel.name}" and manifest["source_commit"] == head(repo)
    assert git(repo, "status", "--porcelain") == ""  # building never touches the worktree
    assert (repo / "build/lib/universal_agent_middleware/zombie.py").exists()  # and never used or cleaned it


def test_the_retired_in_place_build_is_caught_before_the_manifest_exists(tmp_path, offline_pip, monkeypatch):
    """Defence in depth: even a build step that read the worktree again cannot get past ``verify_build``."""
    repo = make_project(tmp_path)
    write(repo / f"{PACKAGE}/local_override.py", "OVERRIDE = True\n")
    write(repo / "build/lib/universal_agent_middleware/zombie.py", "ZOMBIE = True\n")

    def in_place(export_root: Path, wheel_dir: Path, *, python: str) -> Path:
        subprocess.run([python, "-m", "pip", "wheel", "--no-deps", "-w", str(wheel_dir), str(repo)],
                       check=True, capture_output=True, timeout=120)
        return next(wheel_dir.glob("*.whl"))

    monkeypatch.setattr(release, "build_wheel", in_place)
    steps: list[dict] = []
    with pytest.raises(release.ReleaseError, match="build verification failed"):
        build_in(tmp_path, repo, steps)
    failed = steps[-1]
    assert (failed["name"], failed["status"]) == ("verify_build", "FAIL")
    assert {item["code"] for item in failed["violations"]} == {"wheel_package_differs", "installed_package_differs"}
    assert "local_override.py" in json.dumps(failed["violations"])
    release_dir = tmp_path / "releases" / f"v{VERSION}+{head(repo)}"
    assert not (release_dir / "RELEASE_MANIFEST.json").exists()  # nothing pinned the contaminated bytes


def test_a_build_that_fails_records_a_failed_step_and_raises(tmp_path, offline_pip):
    repo = make_project(tmp_path, {"pyproject.toml": BROKEN_BACKEND})
    steps: list[dict] = []
    with pytest.raises(release.ReleaseError, match="build_wheel failed"):
        build_in(tmp_path, repo, steps)
    assert [(item["name"], item["status"]) for item in steps] == [("export_commit", "OK"), ("build_wheel", "FAIL")]
    assert "pip wheel" in steps[-1]["reason"]


def test_the_commit_must_declare_the_version_the_release_is_named_after(tmp_path):
    repo = make_project(tmp_path)
    export = tmp_path / "export"
    export_commit(repo, head(repo), export)
    release._require_exported_version(export, VERSION)
    with pytest.raises(BuildError, match="declares"):
        release._require_exported_version(export, "9.9.8")
    write(export / "pyproject.toml", PYPROJECT.replace(f'version = "{VERSION}"', 'version = "9.9.7"'))
    with pytest.raises(BuildError, match="pyproject.toml"):
        release._require_exported_version(export, VERSION)
    write(export / "pyproject.toml", "not toml [[[")
    with pytest.raises(BuildError, match="cannot be read"):
        release._require_exported_version(export, VERSION)
