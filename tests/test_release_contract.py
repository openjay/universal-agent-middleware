"""Pre-activation verification: what is about to be activated must be what was reviewed.

The probe runs inside the release's own interpreter (here: a stand-in that serves this checkout's package
under the probe's own ``-I -B`` flags, so the real MCP server is listed) and its answers are compared with reviewed inputs: the
committed ``tool_contract.json`` and the source tree of the commit being released. A matching
tool *count* proves nothing, so these tests change names, digests and files while keeping counts.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from release_fixtures import (
    ROOT, STALE, canonical_manifest, declaration, executable, production_shaped, write_declaration,
)
from synthetic_fixtures import init_git_repo
from test_hardening import runtime_fixture  # noqa: F401  (pytest fixture import)

from universal_agent_middleware import release
from universal_agent_middleware import release_acceptance as acceptance
from universal_agent_middleware import release_probe as probe
from universal_agent_middleware import runtime as rt

REVIEWED = json.loads((ROOT / "src/universal_agent_middleware/tool_contract.json").read_text())
GIT_ENV = {**os.environ, "GIT_AUTHOR_NAME": "UAM Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
           "GIT_COMMITTER_NAME": "UAM Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
LAUNCHER = Path(__file__).with_name("release_probe_launcher.py")
CANDIDATE_SOURCE = ROOT / "src"  # the checkout under test: the package every fixture release interpreter serves


def candidate_interpreter() -> str:
    """Body of a fixture ``venv/bin/python``: it serves this checkout's package, under the flags the probe passes.

    The real probe runs ``<release python> -I -B -c SOURCE ...``. ``-I`` ignores ``PYTHONPATH``, so a stand-in that only
    ``exec``s the test interpreter imports whatever package that interpreter has installed, which on a machine with an
    older install is not the one under test (20 tools expected, 19 found, and every later negative test dies at the same
    comparison instead of at the gate it is about). The launcher puts this checkout's ``src`` first on ``sys.path`` and
    then runs the probe source unchanged; it refuses an invocation that is not ``-I -B -c`` (``release_probe_launcher``).
    """
    return f'exec "{sys.executable}" -I -B "{LAUNCHER}" "{CANDIDATE_SOURCE}" "$@"\n'


def digest(char: str) -> str:
    return char * 64


# --- pure comparisons --------------------------------------------------------------------------

@pytest.mark.parametrize("value", [None, [], {}, {"tool": "short"}, {"tool": 7}, {"": digest("a")},
                                   {"tool": digest("A")}])
def test_a_contract_must_be_a_nonempty_map_of_sha256_digests(value):
    with pytest.raises(ValueError):
        probe.validate_contract(value, label="contract")


def test_a_matching_count_with_different_names_is_not_a_match():
    reviewed = {"alpha": digest("a"), "beta": digest("b")}
    actual = {"alpha": digest("a"), "gamma": digest("b")}
    result = probe.compare_contract(reviewed, actual)
    assert not result["match"] and result["reviewed_count"] == result["actual_count"] == 2
    assert (result["missing"], result["unexpected"], result["changed"]) == (["beta"], ["gamma"], [])


def test_a_changed_digest_is_a_difference_even_with_identical_names():
    result = probe.compare_contract({"alpha": digest("a")}, {"alpha": digest("b")})
    assert not result["match"] and result["changed"] == ["alpha"]


def test_an_identical_contract_matches_and_its_digest_is_the_one_doctor_reports():
    result = probe.compare_contract(REVIEWED, dict(REVIEWED))
    assert result["match"] and result["tools"] == sorted(REVIEWED)
    assert result["contract_sha256"] == hashlib.sha256(json.dumps(REVIEWED, sort_keys=True).encode()).hexdigest()


def test_tool_metadata_differences_are_listed_by_tool_and_field():
    previous = {"search": {"description": digest("a"), "inputSchema": digest("b")},
                "read": {"description": digest("c")}, "gone": {"description": digest("d")}}
    candidate = {"search": {"description": digest("x"), "inputSchema": digest("b")},
                 "read": {"description": digest("c"), "annotations": digest("e")},
                 "fresh": {"description": digest("f")}}
    diff = probe.diff_tool_fields(previous, candidate)
    assert diff["changed"] == {"search": ["description"], "read": ["annotations"]}
    assert (diff["added"], diff["removed"]) == (["fresh"], ["gone"])
    assert diff["client_refresh_needed"] is True
    assert probe.diff_tool_fields(previous, previous)["client_refresh_needed"] is False


def test_package_files_are_compared_by_name_and_content():
    source = {"a.py": digest("1"), "b.py": digest("2"), "c.json": digest("3")}
    installed = {"a.py": digest("1"), "b.py": digest("9"), "extra.py": digest("4")}
    result = probe.compare_package_files(source, installed)
    assert not result["match"] and result["differences"] == 3
    assert (result["missing"], result["unexpected"], result["changed"]) == (["c.json"], ["extra.py"], ["b.py"])
    assert probe.compare_package_files(source, dict(source))["match"]


# --- the real probe ----------------------------------------------------------------------------

def make_source_repo(base: Path) -> Path:
    """A git repository whose package directory is byte-identical to the one under test."""
    repo = base / "source"
    shutil.copytree(ROOT / "src/universal_agent_middleware", repo / "src/universal_agent_middleware",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (repo / "pyproject.toml").write_text('[project]\nname = "universal-agent-middleware"\n')
    init_git_repo(repo)
    return repo


def commit_change(repo: Path, relative: str, transform) -> None:
    path = repo / relative
    path.write_text(transform(path.read_text()))
    subprocess.run(["git", "commit", "-qam", "change"], cwd=repo, env=GIT_ENV, check=True, capture_output=True)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def build_release(r: dict[str, Any], repo: Path, *, python_body: str | None = None,
                  wheel_extra: dict[str, str] | None = None,
                  installed_extra: dict[str, str] | None = None) -> Path:
    """An immutable release directory for the repo's HEAD whose interpreter runs the real code.

    ``wheel_extra`` and ``installed_extra`` add members to the wheel and files to the installed package
    that the commit does not hold (what a build from a worktree with ignored files produces).
    """
    commit, tree, version = git(repo, "rev-parse", "HEAD"), git(repo, "rev-parse", "HEAD^{tree}"), \
        release._package_version(repo)
    target = Path(r["release_root"]) / f"v{version}+{commit}"
    shutil.copytree(Path(r["current_release"]), target, symlinks=True)
    executable(target / "venv/bin/python", python_body or candidate_interpreter())
    # The commit's package installed in the venv and a real wheel of it: the pre-activation gate reads both.
    installed = target / "venv/lib/python3/site-packages/universal_agent_middleware"
    shutil.copytree(repo / "src/universal_agent_middleware", installed,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    with zipfile.ZipFile(target / "artifacts/fixture.whl", "w") as wheel:
        for path in sorted(installed.rglob("*")):
            if path.is_file():
                wheel.write(path, f"universal_agent_middleware/{path.relative_to(installed).as_posix()}")
        wheel.writestr(f"universal_agent_middleware-{version}.dist-info/METADATA",
                       f"Metadata-Version: 2.1\nName: universal-agent-middleware\nVersion: {version}\n\n")
        for name, text in (wheel_extra or {}).items():
            wheel.writestr(name, text)
    for relative, text in (installed_extra or {}).items():
        (installed / relative).write_text(text)
    manifest = {"schema_version": "uam-release-v1", "source_commit": commit, "source_tree": tree,
                "source_dirty": False, "source_kind": "git_commit", "release_id": target.name,
                "package_version": version, "build_timestamp": 0, "wheel_file": "artifacts/fixture.whl",
                "wheel_sha256": rt.sha256(target / "artifacts/fixture.whl"),
                "tool_contract": REVIEWED, "files": rt.release_files(target)}
    rt.atomic_json(target / "RELEASE_MANIFEST.json", manifest)
    runtime = json.loads((target / "runtime/uam-runtime.json").read_text())
    runtime.update(current_release=str(target), policy_file=str(target / "service/recovery_policies.yaml"),
                   release_manifest_sha256=rt.sha256(target / "RELEASE_MANIFEST.json"))
    rt.atomic_json(target / "runtime/uam-runtime.json", runtime)
    return target


@pytest.fixture
def source(runtime_fixture, tmp_path):
    r, manifest, _ = runtime_fixture
    # The active release can also be probed (for the tool-metadata comparison).
    executable(Path(r["current_release"]) / "venv/bin/python", candidate_interpreter())
    return SimpleNamespace(r=r, manifest=manifest, repo=make_source_repo(tmp_path), base=tmp_path)


def stage(s, *, declaration_path: str | None = None):
    """Run the real staging against the prepared source repo and release; returns (candidate, run)."""
    canonical = canonical_manifest(s.r)
    run = release._Run(str(canonical), False, [], {})
    run.previous = release._active_release(s.r)
    if declaration_path:
        run.declaration = acceptance.load_declaration(declaration_path)
    with patch.object(release, "_locate_source", return_value=(s.repo, "module")):
        return release._stage_candidate(run, s.r), run


def outcomes(run) -> list[tuple[str, str]]:
    return [(item["name"], item["status"]) for item in run.steps]


GREEN = [("find_source", "OK"), ("git_clean", "OK"), ("release_exists", "REUSE"), ("config_bundle", "OK"),
         ("reviewed_contract", "OK"), ("tool_contract", "OK"), ("coverage_gate", "OK"), ("artifact_verify", "OK"),
         ("tool_metadata", "OK")]


def test_the_fixture_release_interpreter_serves_this_checkouts_package_under_the_probe_flags(source):
    """What the gates compare is this checkout's package, however the test interpreter itself is installed."""
    target = build_release(source.r, source.repo)
    registry = source.base / "identity-registry.json"
    registry.write_text(json.dumps(probe.FIXTURE_REGISTRY))
    result = probe.run_probe(target / "venv/bin/python", str(registry), str(source.base / "identity-state"),
                             stage="fixture_identity")
    assert result.data is not None, result.error
    assert Path(result.data["package_root"]) == (CANDIDATE_SOURCE / "universal_agent_middleware").resolve()
    assert result.data["contract"] == REVIEWED
    assert result.data["version"] == release._package_version(source.repo)


def test_every_pre_activation_gate_passes_for_a_faithful_artifact(source):
    build_release(source.r, source.repo)
    candidate, run = stage(source)
    assert candidate is not None and outcomes(run) == GREEN
    assert run.result["tool_contract"]["match"] and run.result["tool_contract"]["actual_count"] == len(REVIEWED)
    assert run.result["source"]["commit"] == git(source.repo, "rev-parse", "HEAD")
    artifacts = run.result["artifacts"]
    assert artifacts["package_files_compared"] > 5 and len(artifacts["wheel_sha256"]) == 64
    assert run.result["tool_metadata_diff"]["client_refresh_needed"] is False
    assert run.result["coverage"]["complete"] is True


def test_the_release_manifest_records_the_reviewed_contract(source):
    build_release(source.r, source.repo)
    candidate, _ = stage(source)
    manifest = json.loads((candidate.release_dir / "RELEASE_MANIFEST.json").read_text())
    assert manifest["tool_contract"] == REVIEWED
    assert rt.sha256(candidate.release_dir / "RELEASE_MANIFEST.json") == json.loads(
        (candidate.release_dir / "runtime/uam-runtime.json").read_text())["release_manifest_sha256"]


def test_a_renamed_tool_with_an_unchanged_count_is_refused_before_the_switch(source):
    renamed = {("renamed_" + name if index == 0 else name): value for index, (name, value) in enumerate(REVIEWED.items())}
    commit_change(source.repo, "src/universal_agent_middleware/tool_contract.json",
                  lambda _: json.dumps(renamed, indent=2))
    build_release(source.r, source.repo)
    candidate, run = stage(source)
    assert candidate is None and outcomes(run)[-1] == ("tool_contract", "FAIL")
    failure = run.steps[-1]["reason"]
    assert "missing=['renamed_" in failure and "unexpected=[" in failure
    comparison = run.result["tool_contract"]
    assert comparison["reviewed_count"] == comparison["actual_count"] and not comparison["match"]


def test_a_changed_tool_schema_digest_is_refused(source):
    name = next(iter(REVIEWED))
    commit_change(source.repo, "src/universal_agent_middleware/tool_contract.json",
                  lambda text: json.dumps({**REVIEWED, name: digest("0")}, indent=2))
    build_release(source.r, source.repo)
    candidate, run = stage(source)
    assert candidate is None and run.result["tool_contract"]["changed"] == [name]


def test_an_unreadable_reviewed_contract_is_refused(source):
    commit_change(source.repo, "src/universal_agent_middleware/tool_contract.json", lambda _: "{}")
    build_release(source.r, source.repo)
    candidate, run = stage(source)
    assert candidate is None and outcomes(run)[-1] == ("reviewed_contract", "FAIL")


def test_code_that_differs_from_the_released_commit_is_refused(source):
    commit_change(source.repo, "src/universal_agent_middleware/errors.py", lambda text: text + "\n# drift\n")
    build_release(source.r, source.repo)
    candidate, run = stage(source)
    assert candidate is None and outcomes(run)[-1] == ("artifact_verify", "FAIL")
    assert "differs from the source commit" in run.steps[-1]["reason"]
    assert run.result["artifacts"]["package_differences"]["changed"] == ["errors.py"]


OVERRIDE = "OVERRIDE = True\n"


def probe_reporting(extra: dict[str, str], base: Path) -> str:
    """A release interpreter whose probe also reports ``extra`` package files (what an ignored file adds)."""
    wrapper = base / "probe_wrapper.py"
    wrapper.write_text(
        "import json, subprocess, sys\n"
        f"done = subprocess.run([{sys.executable!r}, '-I', '-B', {str(LAUNCHER)!r}, {str(CANDIDATE_SOURCE)!r},\n"
        "                       *sys.argv[1:]], capture_output=True, text=True, check=True)\n"
        "data = json.loads(done.stdout.strip().splitlines()[-1])\n"
        f"data['package_files'].update({extra!r})\n"
        "print(json.dumps(data))\n")
    return f'exec "{sys.executable}" "{wrapper}" "$@"\n'


def test_an_ignored_file_that_the_worktree_and_the_artifact_share_is_refused(source):
    """The retired check compared the artifact with the worktree, so a file both held (ignored by Git) matched."""
    repo = source.repo
    (repo / ".gitignore").write_text("local_*.py\n")
    for args in (["add", ".gitignore"], ["commit", "-qm", "ignore local overrides"]):
        subprocess.run(["git", *args], cwd=repo, env=GIT_ENV, check=True, capture_output=True)
    (repo / "src/universal_agent_middleware/local_override.py").write_text(OVERRIDE)
    assert git(repo, "status", "--porcelain") == ""  # the clean check cannot see it
    reported = {"local_override.py": hashlib.sha256(OVERRIDE.encode()).hexdigest()}
    build_release(source.r, repo, python_body=probe_reporting(reported, source.base),
                  installed_extra={"local_override.py": OVERRIDE})
    candidate, run = stage(source)
    assert candidate is None and outcomes(run)[-1] == ("artifact_verify", "FAIL")
    assert run.result["artifacts"]["package_differences"]["unexpected"] == ["local_override.py"]


@pytest.mark.parametrize("extra,code", [
    ({"wheel_extra": {"zombie.py": "ZOMBIE = True\n"}}, "wheel_stray_member"),
    ({"wheel_extra": {"universal_agent_middleware/zombie.py": "ZOMBIE = True\n"}}, "wheel_package_differs"),
    ({"installed_extra": {"hidden.py": "HIDDEN = True\n"}}, "installed_package_differs"),
])
def test_a_wheel_or_installed_file_outside_the_commit_is_refused_though_the_probe_is_satisfied(source, extra, code):
    build_release(source.r, source.repo, **extra)
    candidate, run = stage(source)
    assert candidate is None and outcomes(run)[-1] == ("artifact_verify", "FAIL")
    assert {item["code"] for item in run.result["artifacts"]["build_violations"]} == {code}
    assert "the wheel or the installed package is not the commit's" in run.steps[-1]["reason"]


@pytest.mark.parametrize("body", ["exit 1\n", "echo 'not json'\n", "echo '{\"contract\": []}'\n"])
def test_a_probe_that_fails_or_lies_about_its_shape_is_refused(source, body):
    build_release(source.r, source.repo, python_body=body)
    candidate, run = stage(source)
    assert candidate is None and outcomes(run)[-1] == ("tool_contract", "FAIL")
    assert run.steps[-1]["reason"].startswith("tool_contract probe failed")


def test_a_stale_release_manifest_hash_is_refused_at_verification(source):
    target = build_release(source.r, source.repo)
    runtime_path = target / "runtime/uam-runtime.json"
    runtime = json.loads(runtime_path.read_text())
    runtime["release_manifest_sha256"] = "0" * 64
    rt.atomic_json(runtime_path, runtime)
    candidate, run = stage(source)
    assert candidate is None and outcomes(run)[-1] == ("artifact_verify", "FAIL")
    assert "release manifest hash mismatch" in run.steps[-1]["reason"]


def test_incomplete_coverage_blocks_activation_unless_declared_exactly(source):
    production_shaped(source.r, source.manifest, source.base)
    build_release(source.r, source.repo)
    strict, strict_run = stage(source)
    assert strict is None and outcomes(strict_run)[-1] == ("coverage_gate", "FAIL")
    assert {item["code"] for item in strict_run.steps[-1]["violations"]} == {"unexpected_unavailable"}

    declared, declared_run = stage(source, declaration_path=str(write_declaration(source.base / "gaps.json")))
    assert declared is not None and ("coverage_gate", "OK") in outcomes(declared_run)
    assert declared_run.result["coverage"]["registered"] == 6 and declared_run.result["coverage"]["available"] == 4

    wrong = declaration(registry={"registered": 6, "available": 5, "unavailable": [
        {"workspace_id": STALE[0], "reason": "root_missing"}]}, canaries={"total": 6, "failing": [STALE[0]]})
    refused, refused_run = stage(source, declaration_path=str(write_declaration(source.base / "wrong.json", wrong)))
    assert refused is None and outcomes(refused_run)[-1] == ("coverage_gate", "FAIL")


def test_tool_metadata_differences_against_the_active_release_are_reported_not_blocking(source):
    build_release(source.r, source.repo)
    name = next(iter(REVIEWED))
    previous = f'echo \'{{"contract": {{"{name}": "{digest("a")}"}}, "fields": {{"{name}": {{"description": "{digest("b")}"}}}}}}\'\n'
    executable(Path(source.r["current_release"]) / "venv/bin/python", previous)
    candidate, run = stage(source)
    assert candidate is not None
    diff = run.result["tool_metadata_diff"]
    assert diff["status"] == "COMPARED" and diff["client_refresh_needed"] is True
    assert name in diff["changed"] and "description" in diff["changed"][name]
    assert len(diff["added"]) == len(REVIEWED) - 1


def test_an_active_release_that_cannot_be_probed_leaves_the_comparison_unavailable(source):
    build_release(source.r, source.repo)
    executable(Path(source.r["current_release"]) / "venv/bin/python", "exit 1\n")
    candidate, run = stage(source)
    assert candidate is not None
    assert run.result["tool_metadata_diff"]["status"] == "UNAVAILABLE"
    assert ("tool_metadata", "SKIP") in outcomes(run)
