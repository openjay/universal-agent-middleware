"""Single-command staged build + atomic activation + post-activation verification.

Usage:
    uam release --runtime-manifest /path/to/uam-runtime.json [--dry-run] [--json]
                [--acceptance declaration.json] [--expect-seal seal.json]

``--expect-seal`` (see ``release_seal``) turns the run into a sealed activation: it selects the
release by identity (exact commit and tree, fixed release path), never builds, never rewrites the
release, and re-derives the sealed fingerprints (manifest, wheel, installed package files against
the commit's Git blobs, dependencies, service files, runtime manifest, interpreter) before any
bytes of the release are executed and again under the Supervisor lock, before the tunnel is
stopped. Without it the pipeline behaves exactly as before, including building a missing release.

Pre-activation (the host is not changed until the symlink swap):
    1. Refuse while FROZEN.json exists; the pipeline never clears a freeze
    2. Source identity (git HEAD, clean worktree; git failures are fatal, never "clean")
    3. Export the commit into a private directory (proved equal to its tree), build the wheel from
       that export and never from the working tree, create an isolated venv, install wheel[service],
       and prove the wheel and the installed package are the commit's Git blobs before the manifest
       is written
    4. Copy service scripts from previous release, write RELEASE_MANIFEST.json and the
       release-internal runtime manifest, which records the configuration bundle: the digests of
       the Registry, the RootScopes and the canaries the release is built against
       (``release_config``)
    5. Verify that bundle against the files on disk (a combination that differs, or whose canaries
       name unregistered workspaces, is refused), probe the release's own interpreter and compare
       the tool contract it serves with the reviewed tool_contract.json of the source commit
       (names and digests, not a count)
    6. Gate the workspace coverage the artifact reports against the acceptance declaration
    7. Verify manifest, file hashes, and the wheel and the installed package against the commit's
       Git blobs (not against the working tree)
    8. List tool-metadata differences against the active release (informational)
    9. Re-check FROZEN.json; --dry-run stops before this point

Activation (the Supervisor is held off and the running service is stopped first):
   10. Take the Supervisor's cycle lock (waits for a running cycle, bounded; a Supervisor that
       starts meanwhile waits for the release to be judged), re-check FROZEN.json and the
       configuration bundle (and the seal, when sealed) before anything is stopped
   11. Stop the tunnel service and wait until launchd reports it unloaded and its process is gone
   12. Swap `current` symlink to new release
   13. Update global uam-runtime.json (a no-op when identical; never observable half-written)

Post-activation:
   14. Start the tunnel service
   15. Refresh reality index (using NEW release's Python)
   16. Run Doctor and judge it with the exact acceptance predicate; release the Supervisor's lock

The running tunnel service compares the sha256 of the runtime manifest and the target of `current`
with the values it started with every 0.5 s and writes FROZEN.json when either differs. Neither may
therefore change while it runs, which is why it is stopped before the switch and started after it.
The Supervisor validates the release and restarts a tunnel it finds down, so it must not run
while the install is half switched. Without ``--expect-seal`` a failure before the switch starts
the old service again.

A sealed activation is a secure recovery: the release it fails to replace may be exactly the one that
had to be taken out of service, so once it has stopped the service it fails closed. No step starts
the previous release, and any failure after the stop (the switch, the manifest update, the start,
the index refresh, a Doctor verdict that is not accepted, an unexpected error or an interruption)
stops whatever may be running and writes the FROZEN.json latch, which the Supervisor and the
service honour, so nothing restarts the install until an operator resolves the freeze with
explicit authorization. An existing latch is never replaced and nothing here clears one.

Every child process is bounded and its outcome recorded; the JSON receipt is complete on every
path, including the release that was actually active when the run ended. On post-activation
failure the new release stays active (no automatic rollback); a sealed run also isolates it.

Exit code: 0 only when a release was activated and accepted (READY, or ACCEPTED_KNOWN_GAPS under
an explicit declaration). Dry runs, DEGRADED and every failure exit 1.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from .release_acceptance import AcceptanceError, check_coverage, evaluate, load_declaration
from .release_build import BuildError, build_violations, build_wheel, export_commit
from .release_config import compute_bundle, config_violations
from .release_probe import (
    FIXTURE_REGISTRY, compare_contract, compare_package_files, diff_tool_fields, run_probe,
    validate_contract,
)
from .release_process import ProcessOutcome, diagnostic_text, run_bounded
from .release_seal import SealError, git_package_files, identity_violations, load_seal, verify_seal
from .runtime import SUPERVISOR_LOCK_NAME, load_runtime, validate_release

RECEIPT_SCHEMA = "uam-release-receipt-v1"
TUNNEL_LABEL = "com.openjay.uam.tunnel"
GIT_TIMEOUT = 30.0
LAUNCHCTL_TIMEOUT = 10.0
LAUNCHCTL_NOT_FOUND = 113
TUNNEL_UNLOAD_WAIT = 30.0
TUNNEL_UNLOAD_POLL = 0.5
# A Supervisor cycle is bounded by its own 240 s deadline, so waiting this long for it to finish is
# waiting for a cycle that is still allowed to be running, not for one that is stuck.
SUPERVISOR_LOCK_WAIT = 300.0
SUPERVISOR_LOCK_POLL = 0.5
INDEX_REFRESH_TIMEOUT = 120.0
DOCTOR_TIMEOUT = 30.0
POST_RESTART_DELAY = 3.0
READINESS_WINDOW = 60.0
READINESS_INTERVAL = 5.0
ACCEPTED_OUTCOMES = frozenset({"READY", "ACCEPTED_KNOWN_GAPS"})


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1 << 16)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _step(steps: list[dict], name: str, status: str, **extra: Any) -> None:
    entry: dict[str, Any] = {"name": name, "status": status, "t": time.time()}
    entry.update(extra)
    steps.append(entry)


class ReleaseError(Exception):
    pass


@dataclass
class StepResult:
    ok: bool
    reason: str = ""
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Run:
    manifest_path: str
    dry_run: bool
    steps: list[dict[str, Any]]
    result: dict[str, Any]
    runtime: dict[str, Any] | None = None
    declaration: dict[str, Any] | None = None
    previous: dict[str, Any] | None = None
    activated: bool = False
    seal: dict[str, Any] | None = None
    service_started: bool = False


@dataclass
class _Candidate:
    release_dir: Path
    release_id: str


@dataclass
class _DoctorRun:
    report: dict[str, Any] | None
    outcome: ProcessOutcome | None
    error: str


def build_and_activate(
    manifest_path: str,
    *,
    dry_run: bool = False,
    acceptance_path: str | None = None,
    seal_path: str | None = None,
) -> dict[str, Any]:
    """Build an immutable release from current HEAD and optionally activate it.

    With ``seal_path`` the run is a sealed activation instead: it never builds, and it refuses
    unless the sealed release is exactly what is on disk (see ``release_seal``).
    """
    started = time.monotonic()
    steps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA, "overall": "FAILED", "accepted": False,
        "dry_run": dry_run, "orchestrator": _orchestrator_identity(), "steps": steps,
    }
    run = _Run(manifest_path, dry_run, steps, result)
    try:
        _release_flow(run, acceptance_path, seal_path)
    except Exception as exc:  # the receipt must stay complete even when the pipeline itself breaks
        _step(steps, "unexpected_error", "FAIL",
              reason=diagnostic_text(f"{type(exc).__name__}: {exc}", limit=400))
    _finalize(run, started)
    return result


def _release_flow(run: _Run, acceptance_path: str | None, seal_path: str | None = None) -> None:
    steps = run.steps
    try:
        run.runtime = runtime = load_runtime(run.manifest_path)
    except (OSError, ValueError, KeyError) as exc:
        _step(steps, "load_runtime", "FAIL", reason=diagnostic_text(f"{type(exc).__name__}: {exc}", limit=400))
        return
    run.previous = _active_release(runtime)

    if acceptance_path is not None:
        try:
            run.declaration = load_declaration(acceptance_path)
        except AcceptanceError as exc:
            _step(steps, "acceptance_declaration", "FAIL", reason=str(exc))
            return
        declaration = run.declaration
        _step(steps, "acceptance_declaration", "OK", path=declaration["path"],
              sha256=declaration["sha256"], registered=declaration["registered"],
              available=declaration["available"], unavailable=declaration["unavailable"])
    if seal_path is not None:
        try:
            run.seal = load_seal(seal_path)
        except SealError as exc:
            _step(steps, "seal_declaration", "FAIL", reason=diagnostic_text(str(exc), limit=400))
            return
        run.result["seal"] = {"path": run.seal["path"], "sha256": run.seal["sha256"],
                              "release_id": run.seal["release_id"], "commit": run.seal["source"]["commit"]}
        _step(steps, "seal_declaration", "OK", **run.result["seal"])
    if not _guard_not_frozen(steps, runtime, "freeze_guard"):
        return

    candidate = _stage_candidate(run, runtime)
    if candidate is None:
        return
    if run.dry_run:
        run.result["overall"] = "DRY_RUN"
        _step(steps, "activate", "SKIP", reason="dry-run mode")
        return
    _activate_and_verify(run, runtime, candidate)


def _stage_candidate(run: _Run, runtime: dict[str, Any]) -> _Candidate | None:
    """Build or validate the release and pass every pre-activation gate."""
    steps, result = run.steps, run.result
    source_root, selected_by = _locate_source()
    if source_root is None:
        _step(steps, "find_source", "FAIL", reason="cannot locate UAM source root")
        return None
    _step(steps, "find_source", "OK", path=str(source_root), selected_by=selected_by)

    try:
        commit_sha = _git(source_root, "rev-parse", "HEAD")
        tree_sha = _git(source_root, "rev-parse", "HEAD^{tree}")
        dirty = _git(source_root, "status", "--porcelain").strip()
    except ReleaseError as exc:
        _step(steps, "git_identity", "FAIL", reason=str(exc))
        return None
    result["source"] = {"root": str(source_root), "selected_by": selected_by,
                        "commit": commit_sha, "tree": tree_sha}
    if dirty:
        _step(steps, "git_clean", "FAIL", reason="worktree is dirty; commit first",
              entries=len(dirty.splitlines()))
        return None
    _step(steps, "git_clean", "OK", commit=commit_sha, tree=tree_sha)

    version = _package_version(source_root)
    release_id = f"v{version}+{commit_sha}"
    release_dir = Path(runtime["release_root"]) / release_id
    result["release_id"] = release_id

    if run.seal is not None and not _sealed_target(run.seal, steps, commit_sha, tree_sha, release_dir):
        return None

    if release_dir.exists():
        validated = _validate_existing_release(release_dir, commit_sha, tree_sha, version)
        if not validated["valid"]:
            _step(steps, "release_exists", "FAIL",
                  reason=f"existing release directory is invalid: {validated['reason']}; "
                         "remove it manually before retrying")
            return None
        _step(steps, "release_exists", "REUSE",
              reason="existing release validated via manifest cryptographic check",
              file_count=validated.get("file_count", 0))
    else:
        if run.seal is not None:  # the release vanished after the identity check: still never build
            _step(steps, "release_exists", "FAIL",
                  reason="the sealed release disappeared; a sealed activation never builds")
            return None
        result["build"] = {"python": _interpreter_identity(_python(source_root))}
        try:
            _build_release(
                release_dir, source_root, runtime,
                commit_sha, tree_sha, version,
                run.manifest_path, steps,
            )
        except Exception as exc:  # any build failure removes the incomplete directory
            if release_dir.exists():
                shutil.rmtree(release_dir, ignore_errors=True)
                _step(steps, "cleanup", "OK", reason="removed incomplete release directory")
            if not isinstance(exc, ReleaseError):
                _step(steps, "build", "FAIL", reason=diagnostic_text(str(exc), limit=500))
            return None

    candidate = _Candidate(release_dir, release_id)
    # Before the gates: they execute the release's interpreter, so the bytes must be the sealed ones first.
    if run.seal is not None and not _guard_sealed_release(run, candidate, "seal_guard"):
        return None
    if not _pre_activation_gates(run, runtime, candidate, source_root, commit_sha, tree_sha):
        return None
    return candidate


def _pre_activation_gates(run: _Run, runtime: dict[str, Any], candidate: _Candidate,
                          source_root: Path, commit_sha: str, tree_sha: str) -> bool:
    steps, result = run.steps, run.result
    # First: the release's code is probed against these files, so they must already be its combination.
    if not _guard_config_bundle(run, candidate, "config_bundle"):
        return False
    try:
        reviewed = _reviewed_contract(source_root)
    except (OSError, ValueError) as exc:
        _step(steps, "reviewed_contract", "FAIL", reason=diagnostic_text(str(exc), limit=300))
        return False
    _step(steps, "reviewed_contract", "OK", tools=len(reviewed))

    contract = _update_tool_contract(candidate.release_dir, runtime, reviewed_contract=reviewed,
                                     rewrite_manifest=run.seal is None)
    comparison = contract.detail.get("contract")
    if comparison:
        result["tool_contract"] = comparison
    if not contract.ok:
        _step(steps, "tool_contract", "FAIL", reason=contract.reason,
              process=contract.detail.get("process"))
        return False
    probe = contract.detail["probe"]
    _step(steps, "tool_contract", "OK", tools=comparison["actual_count"],
          contract_sha256=comparison["contract_sha256"])
    result["coverage"] = probe.get("coverage")

    violations = check_coverage(probe.get("coverage"), run.declaration)
    if violations:
        _step(steps, "coverage_gate", "FAIL", violations=violations,
              reason="workspace coverage reported by the artifact does not match the acceptance "
                     "declaration" if run.declaration else
                     "workspace coverage is incomplete and no acceptance declaration was supplied")
        return False
    _step(steps, "coverage_gate", "OK", mode="declared_gaps" if run.declaration else "strict")

    verified = _verify_artifacts(candidate, commit_sha, tree_sha, source_root, probe)
    result["artifacts"] = verified.detail
    if not verified.ok:
        _step(steps, "artifact_verify", "FAIL", reason=verified.reason)
        return False
    _step(steps, "artifact_verify", "OK", files=verified.detail["file_count"],
          package_files=verified.detail["package_files_compared"])

    diff = _tool_metadata_diff(run.previous, probe["fields"])
    result["tool_metadata_diff"] = diff
    _step(steps, "tool_metadata", "OK" if diff["status"] == "COMPARED" else "SKIP",
          **{key: diff[key] for key in ("added", "removed", "client_refresh_needed", "reason") if key in diff},
          changed_tools=len(diff.get("changed", {})))
    return True


def _verify_artifacts(candidate: _Candidate, commit_sha: str, tree_sha: str, source_root: Path,
                      probe: dict[str, Any]) -> StepResult:
    """Re-hash what is about to be activated: manifest, every file, and the wheel and the installed package
    against the Git blobs of the commit (never against the working tree, which ignored files escape)."""
    release_dir = candidate.release_dir
    try:
        planned = load_runtime(release_dir / "runtime" / "uam-runtime.json")
        manifest = validate_release(planned, executing=False, require_current=False)
    except (OSError, KeyError, ValueError) as exc:
        return StepResult(False, f"release verification failed: {diagnostic_text(str(exc), limit=300)}")
    if (manifest.get("source_commit"), manifest.get("source_tree"), manifest.get("release_id")) != (
            commit_sha, tree_sha, candidate.release_id):
        return StepResult(False, "release manifest identity differs from the source being released")
    try:
        blobs = git_package_files(source_root, commit_sha)
    except SealError as exc:
        return StepResult(False, f"the Git blobs of the commit cannot be read: {diagnostic_text(str(exc), limit=300)}")
    packages = compare_package_files(blobs, probe.get("package_files") or {})
    detail = {
        "manifest_sha256": _sha256(release_dir / "RELEASE_MANIFEST.json"),
        "wheel": manifest["wheel_file"], "wheel_sha256": manifest["wheel_sha256"],
        "file_count": len(manifest["files"]), "package_files_compared": packages["compared"],
        "venv": _venv_identity(release_dir),
    }
    if not packages["match"]:
        detail["package_differences"] = {key: packages[key] for key in ("missing", "unexpected", "changed")}
        return StepResult(False, f"installed package differs from the source commit "
                                 f"({packages['differences']} file(s))", detail)
    problems = build_violations(blobs, release_dir, manifest["wheel_file"],
                                version=str(manifest.get("package_version")))
    if problems:
        detail["build_violations"] = problems
        return StepResult(False, "the wheel or the installed package is not the commit's: "
                                 + "; ".join(item["code"] for item in problems), detail)
    return StepResult(True, "", detail)


def _tool_metadata_diff(previous: dict[str, Any] | None, candidate_fields: dict[str, Any]) -> dict[str, Any]:
    """Compare the tool listing of the active release with the candidate's, using a fixture registry."""
    target = (previous or {}).get("target")
    python = Path(target) / "venv" / "bin" / "python" if target else None
    if python is None or not python.is_file():
        return {"status": "UNAVAILABLE", "reason": "no active release interpreter to compare with"}
    with tempfile.TemporaryDirectory(prefix="uam-release-metadata-") as scratch:
        registry = Path(scratch) / "workspaces.json"
        registry.write_text(json.dumps(FIXTURE_REGISTRY))
        probed = run_probe(python, str(registry), str(Path(scratch) / "state"), stage="previous_release_probe")
    if probed.data is None:
        return {"status": "UNAVAILABLE", "reason": f"active release probe failed: {probed.error}"}
    return {**diff_tool_fields(probed.data["fields"], candidate_fields),
            "previous_release": (previous or {}).get("release_id")}


def _activate_and_verify(run: _Run, runtime: dict[str, Any], candidate: _Candidate) -> None:
    lock, held = _hold_supervisor_lock(runtime)
    _record(run.steps, "supervisor_quiesce", held)
    if lock is None:
        return
    try:
        _switch_and_judge(run, runtime, candidate)
    finally:
        lock.close()


def _switch_and_judge(run: _Run, runtime: dict[str, Any], candidate: _Candidate) -> None:
    steps = run.steps
    # Checked under the lock: the Supervisor may have frozen the install while the lock was awaited.
    if not _guard_not_frozen(steps, runtime, "freeze_guard_pre_activate"):
        return
    # Authoritative sealed check: under the lock and strictly before the running service is touched.
    if run.seal is not None and not _guard_sealed_release(run, candidate, "seal_guard_pre_activate",
                                                          under_lock=True):
        return
    # The Registry/RootScopes may have been replaced while the gates ran or the lock was awaited.
    if not _guard_config_bundle(run, candidate, "config_guard_pre_activate", under_lock=True):
        return
    stopped = _stop_tunnel(runtime)
    _record(steps, "tunnel_stop", stopped)
    if not stopped.ok:
        return  # the state is uncertain: nothing is switched and nothing is started, sealed or not
    try:
        _switch_and_start(run, runtime, candidate)
    except BaseException as exc:  # an interruption (Ctrl-C, SIGTERM) must not leave a sealed install serving
        if run.seal is not None:
            try:
                _isolate(run, runtime, "sealed_activation_interrupted",
                         f"{type(exc).__name__}: {diagnostic_text(str(exc), limit=200)}", candidate)
            except Exception as isolation_error:  # never mask the failure being handled
                _step(steps, "isolation_error", "FAIL",
                      reason=diagnostic_text(f"{type(isolation_error).__name__}: {isolation_error}", limit=300))
        raise
    if run.seal is not None and run.result["overall"] not in ACCEPTED_OUTCOMES:
        _isolate(run, runtime, "sealed_activation_failed",
                 f"the sealed activation ended in {run.result['overall']}, not an accepted state", candidate)


def _switch_and_start(run: _Run, runtime: dict[str, Any], candidate: _Candidate) -> None:
    """Switch to the candidate and start the service on it; the service is stopped when this is entered."""
    steps = run.steps
    try:
        _activate(runtime, candidate.release_dir)
    except (ReleaseError, OSError) as exc:
        _step(steps, "activate", "FAIL", reason=diagnostic_text(str(exc), limit=300))
        if run.seal is None:
            # The release that was serving is started again. A sealed activation is a secure recovery
            # and never does that: the release it failed to replace may be the one that had to be
            # taken out of service, and the caller isolates the install instead.
            _record(steps, "tunnel_restore", _start_tunnel(runtime))
        return
    run.activated = True
    _step(steps, "activate", "OK", release_id=candidate.release_id,
          previous=(run.previous or {}).get("release_id"))

    try:
        _update_global_runtime(run.manifest_path, candidate.release_dir)
    except (OSError, ValueError) as exc:
        _step(steps, "update_runtime", "FAIL", reason=diagnostic_text(str(exc), limit=300),
              service="stopped; not started against a manifest that was not confirmed")
        return
    _step(steps, "update_runtime", "OK")

    post_ok = _post_activation(run, runtime, candidate)
    _verify_activation(run, candidate, post_ok)


def _isolate(run: _Run, runtime: dict[str, Any], failure_class: str, reason: str,
             candidate: _Candidate) -> None:
    """Fail closed after a sealed activation went wrong: stop what may be running, then latch the freeze.

    The Supervisor starts a tunnel it finds down unless FROZEN.json exists, and the release that was
    active before this run may be exactly the one that had to be taken out of service, so a service
    that is merely left stopped would be brought back by the next Supervisor cycle. The latch makes
    the isolation durable (a running service stops itself under it and a started one exits at once)
    and ends only when an operator resolves the freeze with explicit authorization; nothing here
    clears it. An existing latch is evidence and is never replaced.
    """
    steps = run.steps
    if not run.service_started:
        _step(steps, "isolation_stop", "SKIP", reason="this run never started the service")
    elif _freeze_evidence(runtime) is not None:
        _step(steps, "isolation_stop", "SKIP",
              reason="a freeze latch already exists: the service does not run under it")
    else:
        _record(steps, "isolation_stop", _stop_tunnel(runtime))
    latch = _write_freeze_latch(runtime, {
        "overall": "FROZEN", "severity": "P0", "failure_class": failure_class, "checked_at": time.time(),
        "evidence": {"source": "uam release --expect-seal", "reason": reason,
                     "candidate": candidate.release_id,
                     "previous_release": (run.previous or {}).get("release_id"),
                     "failed_steps": [step["name"] for step in steps if step["status"] == "FAIL"]}})
    _record(steps, "isolation_latch", latch)
    run.result["isolation"] = {"failure_class": failure_class, "reason": reason, "latch": latch.ok,
                               "service_may_have_run": run.service_started}


def _write_freeze_latch(runtime: dict[str, Any], payload: dict[str, Any]) -> StepResult:
    """Create FROZEN.json exclusively and durably; a latch that already exists is left exactly as it is."""
    latch = Path(runtime["recovery_root"]) / "FROZEN.json"
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".FROZEN-", dir=latch.parent)
    except OSError as exc:
        return StepResult(False, f"cannot create the freeze latch: {diagnostic_text(str(exc), limit=200)}")
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump(payload, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, latch)  # exclusive: fails when a latch is already there
    except FileExistsError:
        return StepResult(True, "", {"latch": "already_present", "path": str(latch)})
    except OSError as exc:
        return StepResult(False, f"cannot create the freeze latch: {diagnostic_text(str(exc), limit=200)}")
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return StepResult(True, "", {"latch": "written", "path": str(latch)})


def _post_activation(run: _Run, runtime: dict[str, Any], candidate: _Candidate) -> bool:
    """Start the tunnel on the new release and refresh the index. Returns True if both succeeded."""
    steps = run.steps
    run.service_started = True  # from this attempt on the service may be running, whatever it reports
    tunnel = _start_tunnel(runtime)
    _record(steps, "tunnel_start", tunnel)
    if "frozen" in tunnel.detail:
        _step(steps, "index_refresh", "SKIP", reason="FROZEN.json present; no further host changes")
        return False
    try:
        refreshed_runtime = load_runtime(run.manifest_path)
    except (OSError, ValueError, KeyError) as exc:
        _step(steps, "index_refresh", "FAIL", reason=f"runtime manifest unreadable: "
                                                    f"{diagnostic_text(str(exc), limit=300)}")
        return False
    index = _refresh_index(candidate.release_dir / "venv" / "bin" / "python", refreshed_runtime)
    _record(steps, "index_refresh", index)
    return tunnel.ok and index.ok


def _record(steps: list[dict[str, Any]], name: str, outcome: StepResult) -> None:
    extra = dict(outcome.detail)
    if outcome.reason:
        extra["reason"] = outcome.reason
    _step(steps, name, "OK" if outcome.ok else "FAIL", **extra)


def _verify_activation(run: _Run, candidate: _Candidate, post_ok: bool) -> None:
    """Judge the activated release with Doctor and the exact acceptance predicate."""
    steps, result = run.steps, run.result
    time.sleep(POST_RESTART_DELAY)
    deadline = time.monotonic() + READINESS_WINDOW
    attempts: list[dict[str, Any]] = []
    while True:
        doctor = _run_doctor(run.manifest_path)
        verdict = evaluate(doctor.report, declaration=run.declaration, post_ok=post_ok,
                           release_id=candidate.release_id, canary_ids=_canary_ids(run.manifest_path))
        attempts.append({
            "attempt": len(attempts) + 1,
            "doctor_overall": doctor.report.get("overall") if doctor.report else "ERROR",
            "violations": [item["code"] + ":" + item["detail"] for item in verdict["violations"]],
            "elapsed_seconds": round(doctor.outcome.elapsed_seconds, 3) if doctor.outcome else None,
        })
        if verdict["accepted"] or not _only_tunnel_pending(verdict) or time.monotonic() >= deadline:
            break
        time.sleep(READINESS_INTERVAL)

    report = doctor.report
    checks = report.get("checks") if report else None
    result["doctor_overall"] = report.get("overall", "UNKNOWN") if report else "ERROR"
    result["doctor_checks"] = {
        name: check.get("status", "UNKNOWN") if isinstance(check, dict) else "UNKNOWN"
        for name, check in (checks if isinstance(checks, dict) else {}).items()
    }
    result["doctor_attempts"] = attempts
    result["acceptance"] = verdict
    _step(steps, "doctor", result["doctor_overall"], attempts=len(attempts),
          **({"process": doctor.outcome.receipt()} if doctor.outcome else {}),
          **({"reason": doctor.error} if doctor.error else {}))
    if verdict["accepted"]:
        _step(steps, "acceptance", "OK", mode=verdict["mode"], gaps=verdict["observed"]["gaps"])
        result["overall"] = "ACCEPTED_KNOWN_GAPS" if verdict["observed"]["gaps"] else "READY"
        return
    _step(steps, "acceptance", "FAIL", mode=verdict["mode"], violations=verdict["violations"])
    degraded_only = post_ok and report is not None and report.get("overall") == "DEGRADED"
    result["overall"] = "DEGRADED" if degraded_only else "ACTIVATION_INCOMPLETE"


def _only_tunnel_pending(verdict: dict[str, Any]) -> bool:
    """A tunnel that is still starting is the one failure worth waiting for; nothing else is retried."""
    violations = verdict["violations"]
    return bool(violations) and all(
        item["code"] == "check_not_pass" and item["detail"].startswith("tunnel=") for item in violations)


def _canary_ids(manifest_path: str) -> list[str]:
    try:
        canaries = load_runtime(manifest_path).get("canaries", [])
    except (OSError, ValueError, KeyError):
        return []
    return [str(item.get("workspace_id")) for item in canaries if isinstance(item, dict)]


def _finalize(run: _Run, started: float) -> None:
    result = run.result
    if run.activated and result["overall"] == "FAILED":
        result["overall"] = "ACTIVATION_INCOMPLETE"
    result["accepted"] = result["overall"] in ACCEPTED_OUTCOMES
    result["exit_code"] = 0 if result["accepted"] else 1
    failed = [step["name"] for step in run.steps if step["status"] == "FAIL"]
    result["failure_stage"] = failed[0] if failed else None
    result["activation"] = {
        "performed": run.activated,
        "previous_release": (run.previous or {}).get("release_id"),
        "active_release": _active_release(run.runtime) if run.runtime else None,
    }
    result["duration_seconds"] = round(time.monotonic() - started, 3)


def _orchestrator_identity() -> dict[str, str]:
    return {"python": sys.executable, "python_version": platform.python_version(),
            "module": str(Path(__file__).resolve()), "cwd": str(Path.cwd())}


def _interpreter_identity(path: str) -> dict[str, Any]:
    outcome = run_bounded([path, "--version"], stage="interpreter_version", timeout=10.0)
    version = diagnostic_text(outcome.stdout or outcome.stderr, limit=60) if outcome.succeeded else None
    return {"path": path, "version": version}


def _venv_identity(release_dir: Path) -> dict[str, Any]:
    identity: dict[str, Any] = {"python": os.path.realpath(release_dir / "venv" / "bin" / "python")}
    try:
        for line in (release_dir / "venv" / "pyvenv.cfg").read_text().splitlines():
            key, _, value = line.partition("=")
            if key.strip() in ("home", "version"):
                identity[key.strip()] = value.strip()
    except OSError:
        pass
    return identity


def _active_release(runtime: dict[str, Any]) -> dict[str, Any]:
    try:
        target = (Path(runtime["uam_home"]) / "current").resolve(strict=True)
    except OSError:
        return {"release_id": None, "target": None}
    return {"release_id": target.name, "target": str(target)}


def _freeze_evidence(runtime: dict[str, Any]) -> dict[str, Any] | None:
    """Describe FROZEN.json without touching it; None when no latch exists."""
    latch = Path(runtime["recovery_root"]) / "FROZEN.json"
    if not os.path.lexists(latch):
        return None
    evidence: dict[str, Any] = {"path": str(latch)}
    try:
        data = latch.read_bytes()
    except OSError as exc:
        evidence["unreadable"] = type(exc).__name__
    else:
        evidence.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
    return evidence


def _guard_not_frozen(steps: list[dict[str, Any]], runtime: dict[str, Any], name: str) -> bool:
    frozen = _freeze_evidence(runtime)
    if frozen is None:
        _step(steps, name, "OK")
        return True
    _step(steps, name, "FAIL", frozen=frozen,
          reason="FROZEN.json present; release refused. Resolve the freeze through the incident "
                 "procedure with explicit authorization; the release pipeline never clears it")
    return False


def _sealed_target(seal: dict[str, Any], steps: list[dict[str, Any]], commit_sha: str, tree_sha: str,
                   release_dir: Path) -> bool:
    """A sealed activation names its release (exact commit, tree and directory) and never builds one."""
    problems = identity_violations(seal, commit=commit_sha, tree=tree_sha, release_dir=release_dir)
    if not release_dir.is_dir():
        problems.append({"code": "release_missing",
                         "detail": f"{release_dir} does not exist; a sealed activation never builds"})
    if problems:
        _step(steps, "seal_identity", "FAIL", violations=problems,
              reason="the release this run would activate is not the sealed release")
        return False
    _step(steps, "seal_identity", "OK", release_id=release_dir.name, commit=commit_sha, tree=tree_sha)
    return True


def _guard_sealed_release(run: _Run, candidate: _Candidate, name: str, *, under_lock: bool = False) -> bool:
    """Re-derive the sealed release from disk and Git; any difference refuses before anything is stopped."""
    steps, seal = run.steps, run.seal
    source = run.result.get("source") or {}
    if seal is None or "root" not in source:
        _step(steps, name, "FAIL", under_lock=under_lock,
              reason="the source identity is unknown; refusing to activate a sealed release")
        return False
    source_root = Path(source["root"])
    problems: list[dict[str, str]] = []
    inventory = _validate_existing_release(candidate.release_dir, seal["source"]["commit"],
                                           seal["source"]["tree"], _package_version(source_root))
    if not inventory["valid"]:
        problems.append({"code": "release_invalid", "detail": str(inventory["reason"])})
    verdict = verify_seal(seal, source_root=source_root, release_dir=candidate.release_dir)
    problems.extend(verdict.violations)
    if problems:
        _step(steps, name, "FAIL", under_lock=under_lock, violations=problems,
              reason="the release on disk is not the sealed release; nothing was stopped or switched")
        return False
    _step(steps, name, "OK", under_lock=under_lock, release_id=candidate.release_id,
          manifest_files=inventory["file_count"], **verdict.checked)
    return True


def _guard_config_bundle(run: _Run, candidate: _Candidate, name: str, *, under_lock: bool = False) -> bool:
    """The Registry, RootScopes and canaries on disk must be the combination the release was built with.

    A sealed activation requires the combination to be recorded. A release built before the bundle
    existed can only be checked for coherence: it is neither proven nor refuted to match.
    """
    steps = run.steps
    try:
        planned = load_runtime(candidate.release_dir / "runtime" / "uam-runtime.json")
    except (OSError, ValueError, KeyError) as exc:
        _step(steps, name, "FAIL", under_lock=under_lock,
              reason=f"the release's runtime manifest is unreadable: "
                     f"{diagnostic_text(f'{type(exc).__name__}: {exc}', limit=300)}")
        return False
    recorded = planned.get("config_bundle")
    problems = config_violations(planned, require_bundle=run.seal is not None)
    run.result["config_bundle"] = {"recorded": recorded is not None, "bundle": recorded, "verified": not problems}
    if problems:
        _step(steps, name, "FAIL", under_lock=under_lock, violations=problems,
              reason="the configuration on disk is not the combination this release was built with; "
                     "nothing was stopped or switched")
        return False
    _step(steps, name, "OK", under_lock=under_lock, bundle=recorded if recorded is not None else "not_recorded")
    return True


def _build_release(
    release_dir: Path,
    source_root: Path,
    runtime: dict[str, Any],
    commit_sha: str,
    tree_sha: str,
    version: str,
    manifest_path: str,
    steps: list[dict[str, Any]],
) -> None:
    """Build a complete release directory from the exact commit. Raises ReleaseError on failure.

    The wheel is built from a private export of ``commit_sha``, never from the working tree, which
    holds ignored and stale files that ``git status`` does not show (see ``release_build``).
    """
    release_dir.mkdir(parents=True)

    wheel_dir = release_dir / "artifacts"
    wheel_dir.mkdir()
    with tempfile.TemporaryDirectory(prefix="uam-release-export-", ignore_cleanup_errors=True) as scratch:
        export_root = Path(scratch) / "source"
        try:
            exported = export_commit(source_root, commit_sha, export_root)
            _step(steps, "export_commit", "OK", commit=commit_sha, files=exported["files"])
            _require_exported_version(export_root, version)
            wheel_file = build_wheel(export_root, wheel_dir, python=_python(source_root))
        except BuildError as exc:
            _step(steps, exc.stage, "FAIL", reason=diagnostic_text(exc.reason, limit=500))
            raise ReleaseError(f"{exc.stage} failed") from exc
    _step(steps, "build_wheel", "OK", wheel=wheel_file.name)

    venv_dir = release_dir / "venv"
    proc = subprocess.run(
        [_python(source_root), "-m", "venv", str(venv_dir)],
        capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        _step(steps, "create_venv", "FAIL", stderr=proc.stderr[:500])
        raise ReleaseError("venv creation failed")

    pip = str(venv_dir / "bin" / "pip")
    proc = subprocess.run(
        [pip, "install", "-q", str(wheel_file) + "[service]"],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        _step(steps, "install_wheel", "FAIL", stderr=proc.stderr[:500])
        raise ReleaseError("wheel install failed")
    _step(steps, "install_wheel", "OK")

    # Before the manifest exists: the manifest pins whatever is on disk, so it may only pin a verified build.
    try:
        blobs = git_package_files(source_root, commit_sha)
    except SealError as exc:
        _step(steps, "verify_build", "FAIL", reason=diagnostic_text(str(exc), limit=300))
        raise ReleaseError("build verification failed") from exc
    problems = build_violations(blobs, release_dir, f"artifacts/{wheel_file.name}", version=version)
    if problems:
        _step(steps, "verify_build", "FAIL", violations=problems,
              reason="the wheel or the installed package is not the commit's")
        raise ReleaseError("build verification failed")
    _step(steps, "verify_build", "OK", package_files=len(blobs))

    old_service = _find_service_dir(runtime)
    if old_service and old_service.is_dir():
        shutil.copytree(old_service, release_dir / "service")
        _step(steps, "copy_service", "OK")
    else:
        _step(steps, "copy_service", "SKIP", reason="no previous service dir found")

    _write_release_manifest(release_dir, commit_sha, tree_sha, version, wheel_file.name)
    _step(steps, "release_manifest", "OK")

    _write_runtime_in_release(release_dir, runtime, manifest_path)
    _step(steps, "runtime_manifest", "OK")


def _require_exported_version(export_root: Path, version: str) -> None:
    """The commit itself must declare the version the release is named after."""
    try:
        declared = {"pyproject.toml": tomllib.loads((export_root / "pyproject.toml").read_text())["project"]["version"],
                    "__init__.py": _package_version(export_root)}
    except (OSError, KeyError, ValueError) as exc:
        raise BuildError("export_commit", f"the version the commit declares cannot be read: "
                                          f"{type(exc).__name__}") from exc
    differing = {name: value for name, value in declared.items() if value != version}
    if differing:
        raise BuildError("export_commit", f"the commit declares {differing} but the release is named v{version}")


def _validate_existing_release(
    release_dir: Path, commit: str, tree: str, version: str
) -> dict[str, Any]:
    """Cryptographically validate an existing release directory."""
    manifest_path = release_dir / "RELEASE_MANIFEST.json"
    if not manifest_path.is_file():
        return {"valid": False, "reason": "RELEASE_MANIFEST.json missing"}
    try:
        manifest = json.loads(manifest_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        return {"valid": False, "reason": f"manifest unreadable: {exc}"}

    if manifest.get("source_commit") != commit:
        return {"valid": False, "reason": "source_commit mismatch"}
    if manifest.get("source_tree") != tree:
        return {"valid": False, "reason": "source_tree mismatch"}
    if manifest.get("package_version") != version:
        return {"valid": False, "reason": "package_version mismatch"}
    if manifest.get("schema_version") != "uam-release-v1":
        return {"valid": False, "reason": "schema_version mismatch"}
    if manifest.get("source_dirty") is not False:
        return {"valid": False, "reason": "source_dirty is not false"}

    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        return {"valid": False, "reason": "no file inventory in manifest"}

    for rel, expected_hash in files.items():
        p = release_dir / rel
        if not p.is_file():
            return {"valid": False, "reason": f"missing file: {rel}"}
        if _sha256(p) != expected_hash:
            return {"valid": False, "reason": f"hash mismatch: {rel}"}

    actual_files = _release_files(release_dir)
    if set(actual_files.keys()) != set(files.keys()):
        extra = set(actual_files.keys()) - set(files.keys())
        missing = set(files.keys()) - set(actual_files.keys())
        return {"valid": False,
                "reason": f"file inventory mismatch (extra={len(extra)}, missing={len(missing)})"}

    tc = manifest.get("tool_contract")
    if not isinstance(tc, dict) or not tc:
        return {"valid": False, "reason": "tool_contract missing or empty"}

    wheel_file = manifest.get("wheel_file", "")
    wheel_path = release_dir / wheel_file
    if not wheel_path.is_file():
        return {"valid": False, "reason": f"wheel missing: {wheel_file}"}
    if _sha256(wheel_path) != manifest.get("wheel_sha256"):
        return {"valid": False, "reason": "wheel hash mismatch"}

    return {"valid": True, "file_count": len(files)}


def _locate_source() -> tuple[Path | None, str | None]:
    """The source tree is the one this module was loaded from, then the working directory."""
    here = Path(__file__).resolve().parent
    for selected_by, candidate in (("module", here.parent.parent), ("cwd", Path.cwd())):
        if (candidate / "pyproject.toml").is_file() and (candidate / "src" / "universal_agent_middleware").is_dir():
            return candidate, selected_by
    return None, None


def _python(source_root: Path) -> str:
    venv = source_root / ".venv" / "bin" / "python"
    if venv.is_file():
        return str(venv)
    return "python3"


def _git(root: Path, *args: str) -> str:
    """Run git; a failure or timeout is an error, never an empty (and therefore 'clean') answer."""
    outcome = run_bounded(["git", *args], stage=f"git {args[0]}", timeout=GIT_TIMEOUT, cwd=root)
    if not outcome.succeeded:
        raise ReleaseError(f"git {args[0]} {outcome.describe_failure()}")
    return outcome.stdout.decode("utf-8", "replace").strip()


def _package_version(source_root: Path) -> str:
    init = source_root / "src" / "universal_agent_middleware" / "__init__.py"
    for line in init.read_text().splitlines():
        if line.startswith("__version__"):
            return line.split("=")[1].strip().strip('"').strip("'")
    return "0.0.0"


def _find_service_dir(runtime: dict[str, Any]) -> Path | None:
    current = Path(runtime["uam_home"]) / "current"
    if current.is_symlink():
        resolved = current.resolve()
        service = resolved / "service"
        if service.is_dir():
            return service
    return None


def _release_files(release: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for subdir in ("venv", "service", "artifacts"):
        root = release / subdir
        if not root.exists():
            continue
        for f in sorted(root.rglob("*")):
            if not f.is_file():
                continue
            if "__pycache__" in f.parts or f.suffix == ".pyc":
                continue
            rel = str(f.relative_to(release))
            result[rel] = _sha256(f)
    return result


def _write_release_manifest(
    release_dir: Path, commit: str, tree: str, version: str, wheel_name: str
) -> None:
    files = _release_files(release_dir)
    manifest = {
        "build_timestamp": time.time(),
        "files": files,
        "package_version": version,
        "release_id": release_dir.name,
        "schema_version": "uam-release-v1",
        "source_commit": commit,
        "source_dirty": False,
        "source_kind": "git_commit",
        "source_tree": tree,
        "tool_contract": {},
        "wheel_file": f"artifacts/{wheel_name}",
        "wheel_sha256": _sha256(release_dir / "artifacts" / wheel_name),
    }
    (release_dir / "RELEASE_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=False)
    )


def _reviewed_contract(source_root: Path) -> dict[str, str]:
    """The tool contract reviewed and committed with the source being released."""
    path = source_root / "src" / "universal_agent_middleware" / "tool_contract.json"
    return validate_contract(json.loads(path.read_text()), label="reviewed tool_contract.json")


def _update_tool_contract(
    release_dir: Path, runtime: dict[str, Any], *, reviewed_contract: dict[str, str] | None = None,
    rewrite_manifest: bool = True,
) -> StepResult:
    """Probe the release's own interpreter and require its tool contract to equal the reviewed one.

    The manifest is only written after the comparison passes, so the contract recorded for the
    release is the reviewed contract and not whatever the artifact reports about itself. A sealed
    release is never rewritten (``rewrite_manifest=False``): a recorded contract that differs from
    the one the artifact serves is a failure, not something to repair.
    """
    venv_python = release_dir / "venv" / "bin" / "python"
    if not venv_python.is_file():
        return StepResult(False, f"release venv python not found: {venv_python}")
    if not any((release_dir / "venv" / "lib").rglob("universal_agent_middleware/adapters/mcp_sdk.py")):
        return StepResult(False, "mcp_sdk.py not found in release venv")
    if reviewed_contract is None:
        return StepResult(False, "reviewed tool_contract.json is required to accept a release")

    probed = run_probe(venv_python, runtime["registry_file"], runtime["state_root"], stage="candidate_probe")
    process = {"process": probed.outcome.receipt()}
    if probed.data is None:
        return StepResult(False, f"tool_contract probe failed: {probed.error}", process)
    try:
        actual = validate_contract(probed.data["contract"], label="probed tool contract")
    except ValueError as exc:
        return StepResult(False, f"tool_contract {exc}", process)
    comparison = compare_contract(reviewed_contract, actual)
    detail = {"probe": probed.data, "contract": comparison, **process}
    if not comparison["match"]:
        return StepResult(False, "tool contract differs from the reviewed tool_contract.json: "
                                 f"missing={comparison['missing']} unexpected={comparison['unexpected']} "
                                 f"changed={comparison['changed']}", detail)

    manifest_path = release_dir / "RELEASE_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("tool_contract") != actual:
        if not rewrite_manifest:
            return StepResult(False, "the sealed release records a tool contract different from the one its "
                                     "artifact serves; a sealed release is never rewritten", detail)
        manifest["tool_contract"] = actual
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=False))
        _update_runtime_sha(release_dir)
    return StepResult(True, "", detail)


def _write_runtime_in_release(
    release_dir: Path, runtime: dict[str, Any], manifest_path: str
) -> None:
    rt_dir = release_dir / "runtime"
    rt_dir.mkdir(exist_ok=True)
    rt_data = dict(runtime)
    rt_data["current_release"] = str(release_dir)
    if "policy_file" in rt_data:
        rt_data["policy_file"] = str(release_dir / "service" / "recovery_policies.yaml")
    rt_data["release_manifest_sha256"] = _sha256(release_dir / "RELEASE_MANIFEST.json")
    # The combination this release is built against; every later admission point re-derives it.
    rt_data["config_bundle"] = compute_bundle(runtime)
    (rt_dir / "uam-runtime.json").write_text(json.dumps(rt_data, indent=2))


def _update_runtime_sha(release_dir: Path) -> None:
    rt_path = release_dir / "runtime" / "uam-runtime.json"
    if not rt_path.exists():
        return
    rt_data = json.loads(rt_path.read_text())
    rt_data["release_manifest_sha256"] = _sha256(release_dir / "RELEASE_MANIFEST.json")
    rt_path.write_text(json.dumps(rt_data, indent=2))


def _activate(runtime: dict[str, Any], release_dir: Path) -> None:
    """Atomically point `current` at the release. A freeze is evidence, never an obstacle to delete."""
    if _freeze_evidence(runtime) is not None:
        raise ReleaseError("FROZEN.json present; refusing to switch current")
    current_link = Path(runtime["uam_home"]) / "current"
    tmp_link = current_link.with_name("current.new")
    if tmp_link.exists() or tmp_link.is_symlink():
        tmp_link.unlink()
    tmp_link.symlink_to(release_dir)
    tmp_link.rename(current_link)


def _update_global_runtime(manifest_path: str, release_dir: Path) -> None:
    """Point the global uam-runtime.json at the new release.

    The global manifest is a symlink into ``current``, so after the switch this normally rewrites
    identical bytes: that is skipped, and any real change replaces the file atomically so a
    concurrent reader never sees it empty or truncated.
    """
    rt_path = Path(manifest_path)
    original = rt_path.read_text()
    rt_data = json.loads(original)
    rt_data["current_release"] = str(release_dir)
    rt_data["release_manifest_sha256"] = _sha256(release_dir / "RELEASE_MANIFEST.json")
    if "policy_file" in rt_data:
        policy = release_dir / "service" / "recovery_policies.yaml"
        if policy.exists():
            rt_data["policy_file"] = str(policy)
    updated = json.dumps(rt_data, indent=2)
    if updated != original:
        _replace_text(rt_path.resolve(strict=True), updated)


def _replace_text(target: Path, text: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, target.stat().st_mode & 0o777)
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _tunnel_plist(label: str, plist: Path | None) -> Path:
    return plist or Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"


def _recorded_tunnel_process(runtime: dict[str, Any]) -> tuple[int, str] | None:
    """The pid and ``ps`` identity the running service recorded for its tunnel-client."""
    try:
        identity = json.loads((Path(runtime["recovery_root"]) / "tunnel-identity.json").read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(identity, dict):
        return None
    pid, described = identity.get("pid"), identity.get("process_identity")
    if type(pid) is int and pid > 0 and isinstance(described, str) and described:
        return pid, described
    return None


def _hold_supervisor_lock(
    runtime: dict[str, Any], *, wait_seconds: float = SUPERVISOR_LOCK_WAIT,
    poll_seconds: float = SUPERVISOR_LOCK_POLL,
) -> tuple[IO[bytes] | None, StepResult]:
    """Take the Supervisor's cycle lock so that it decides nothing while the install changes.

    The Supervisor validates the release and restarts a tunnel it finds down; run in the middle
    of a switch it would see a service that is stopped on purpose, or a manifest and a ``current``
    that disagree for a moment, and could restart or freeze the install. A cycle that is already
    running is waited for; one that starts meanwhile blocks on the same lock and reads the new
    runtime once the release is judged. Closing the returned file releases the lock. Without it
    nothing has been changed.
    """
    lock_path = Path(runtime["recovery_root"]) / SUPERVISOR_LOCK_NAME
    try:
        lock = lock_path.open("a+b")
    except OSError as exc:
        return None, StepResult(False, f"cannot open {lock_path}: {diagnostic_text(str(exc), limit=200)}")
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lock, StepResult(True, "", {"lock": str(lock_path)})
        except BlockingIOError:
            if time.monotonic() >= deadline:
                lock.close()
                return None, StepResult(
                    False, f"a Supervisor cycle still holds {lock_path} after {wait_seconds:g}s; "
                           "nothing was changed")
            time.sleep(poll_seconds)
        except OSError as exc:
            lock.close()
            return None, StepResult(False, f"cannot lock {lock_path}: {diagnostic_text(str(exc), limit=200)}")


def _wait_for_process_exit(
    pid: int, described: str, *, timeout: float, wait_seconds: float, poll_seconds: float,
) -> StepResult:
    """Wait until the recorded tunnel-client is gone.

    launchd stops listing the job before its child has finished exiting. A tunnel-client that is
    still shutting down keeps answering the health probes and keeps the port, so a service started
    in that window finds the port taken and exits at once. A pid that now describes another
    process (reuse) counts as gone.
    """
    deadline = time.monotonic() + wait_seconds
    while True:
        probe = run_bounded(["ps", "-p", str(pid), "-o", "lstart=", "-o", "comm="],
                            stage="tunnel_process_exit", timeout=timeout)
        detail = {"process_exit_check": probe.receipt()}
        if not probe.completed or probe.returncode not in (0, 1):
            return StepResult(False, f"ps {probe.describe_failure()}; the service state is "
                                     "uncertain and nothing was switched", detail)
        if probe.returncode == 1 or probe.stdout.decode("utf-8", "replace").strip() != described:
            return StepResult(True, "", detail)
        if time.monotonic() >= deadline:
            return StepResult(False, f"tunnel process {pid} is still running {wait_seconds:g}s after "
                                     "bootout; nothing was switched", detail)
        time.sleep(poll_seconds)


def _stop_tunnel(
    runtime: dict[str, Any], *, plist: Path | None = None, label: str = TUNNEL_LABEL,
    launchctl: str = "launchctl", timeout: float = LAUNCHCTL_TIMEOUT,
    wait_seconds: float = TUNNEL_UNLOAD_WAIT, poll_seconds: float = TUNNEL_UNLOAD_POLL,
) -> StepResult:
    """Unload the tunnel LaunchAgent and wait until launchd no longer knows it and the process is gone.

    While the service runs it freezes the whole install the moment the runtime manifest or the
    target of ``current`` differs from what it started with, so both may only change after this
    succeeded. Refuses under a freeze, and a timeout or unexpected answer is an uncertain state in
    which nothing may be switched.

    ``label`` and ``launchctl`` are parameters so tests exercise a real child process without
    ever addressing the user's LaunchAgent.
    """
    frozen = _freeze_evidence(runtime)
    if frozen is not None:
        return StepResult(False, "FROZEN.json present; tunnel stop refused", {"frozen": frozen})
    plist = _tunnel_plist(label, plist)
    if not plist.is_file():
        return StepResult(False, f"plist not found: {plist}")

    recorded = _recorded_tunnel_process(runtime)
    target = f"gui/{os.getuid()}/{label}"
    bootout = run_bounded([launchctl, "bootout", target], stage="tunnel_bootout", timeout=timeout)
    detail: dict[str, Any] = {"bootout": bootout.receipt()}
    if not bootout.completed:
        return StepResult(False, f"launchctl bootout {bootout.describe_failure()}; the service state is "
                                 "uncertain and nothing was switched", detail)
    deadline = time.monotonic() + wait_seconds
    while True:
        probe = run_bounded([launchctl, "print", target], stage="tunnel_unload_check", timeout=timeout)
        detail["unload_check"] = probe.receipt()
        if not probe.completed or probe.returncode not in (0, LAUNCHCTL_NOT_FOUND):
            return StepResult(False, f"launchctl print {probe.describe_failure()}; the service state is "
                                     "uncertain and nothing was switched", detail)
        if probe.returncode == LAUNCHCTL_NOT_FOUND:
            if recorded is None:
                return StepResult(True, "", detail)
            exited = _wait_for_process_exit(*recorded, timeout=timeout, wait_seconds=wait_seconds,
                                            poll_seconds=poll_seconds)
            return StepResult(exited.ok, exited.reason, {**detail, **exited.detail})
        if time.monotonic() >= deadline:
            return StepResult(False, f"the service is still loaded {wait_seconds:g}s after bootout; "
                                     "nothing was switched", detail)
        time.sleep(poll_seconds)


def _start_tunnel(
    runtime: dict[str, Any], *, plist: Path | None = None, label: str = TUNNEL_LABEL,
    launchctl: str = "launchctl", timeout: float = LAUNCHCTL_TIMEOUT,
) -> StepResult:
    """Bootstrap the tunnel LaunchAgent; refuses under a freeze, where the service would only exit 78."""
    frozen = _freeze_evidence(runtime)
    if frozen is not None:
        return StepResult(False, "FROZEN.json present; tunnel start refused", {"frozen": frozen})
    plist = _tunnel_plist(label, plist)
    if not plist.is_file():
        return StepResult(False, f"plist not found: {plist}")
    bootstrap = run_bounded([launchctl, "bootstrap", f"gui/{os.getuid()}", str(plist)],
                            stage="tunnel_bootstrap", timeout=timeout)
    detail = {"bootstrap": bootstrap.receipt()}
    if not bootstrap.succeeded:
        return StepResult(False, f"bootstrap failed ({bootstrap.describe_failure()})", detail)
    return StepResult(True, "", detail)


def _refresh_index(
    venv_python: Path, runtime: dict[str, Any], *, timeout: float = INDEX_REFRESH_TIMEOUT,
) -> StepResult:
    """Refresh reality index using the specified Python interpreter.

    Always includes --enrich-git to maintain activity classification quality.
    """
    outcome = run_bounded(
        [str(venv_python), "-I", "-m", "universal_agent_middleware.cli",
         "index", "--registry", runtime["registry_file"], "--state-dir", runtime["state_root"],
         "--enrich-git", "--json"],
        stage="index_refresh", timeout=timeout)
    detail = {"process": outcome.receipt()}
    if not outcome.succeeded:
        return StepResult(False, f"index refresh failed ({outcome.describe_failure()})", detail)
    try:
        payload = json.loads(outcome.stdout.decode("utf-8"))
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        return StepResult(False, "index refresh failed (output is not a JSON object)", detail)
    return StepResult(True, "", detail)


def _run_doctor(manifest_path: str, *, timeout: float = DOCTOR_TIMEOUT) -> _DoctorRun:
    try:
        runtime = load_runtime(manifest_path)
    except (OSError, ValueError, KeyError) as exc:
        return _DoctorRun(None, None, f"runtime manifest unreadable: {diagnostic_text(str(exc), limit=300)}")
    venv = Path(runtime["current_release"]) / "venv" / "bin" / "python"
    outcome = run_bounded(
        [str(venv), "-I", "-m", "universal_agent_middleware.cli",
         "doctor", "--runtime-manifest", manifest_path, "--json"],
        stage="doctor", timeout=timeout)
    if not outcome.completed or outcome.returncode not in (0, 1):
        return _DoctorRun(None, outcome, f"Doctor {outcome.describe_failure()}")
    try:
        report = json.loads(outcome.stdout.decode("utf-8"))
    except ValueError:
        report = None
    if not isinstance(report, dict):
        return _DoctorRun(None, outcome, "Doctor output is not a JSON object")
    return _DoctorRun(report, outcome, "")
