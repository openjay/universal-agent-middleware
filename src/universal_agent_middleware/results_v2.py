"""Versioned executor results that do not require a commit (``uam-result-v2``).

The v1 result (``uam-executor-result-v1``, ``results.py``) records a final Git revision and treats an
unchanged revision as a blocker, so it can only describe committed work. v2 describes what actually
happened without inventing a revision, forcing a commit or demanding a change:

    working-tree-diff-v1    uncommitted changes in a Git workspace, delivered as a patch
    document-artifact-v1    non-code artifacts (documents, data) in a directory workspace
    no-change-v1            a justified claim that the baseline already satisfies the contract

Every kind is bound to its contract by id **and** digest and to the baseline UAM observed when it
admitted the contract. UAM then re-observes the live workspace through its own read path
(``Readback``) and compares the claim with that observation. Three evidence classes stay separate
in every review: ``artifact_readback`` is UAM's own observation and is independent of the
executor; ``verification_receipts`` and ``executor_identity`` are what the executor says about
itself. A match between receipts and the contract proves conformance, not that a hostile executor
ran anything; only the readback is independent. The review is a machine review: business
acceptance stays with the task owner (``business_acceptance``), and a protocol status or an
executor summary can never substitute for it.

The v1 store, validators and tests are unchanged. v2 results live in their own directory, and the v1
store cannot bind a result to a successor-schema contract (see ``ContractStore.get``).

Fixed by this schema (the "frozen successor" the coordination SSOT asks for before implementation):

* ``result_version`` is exactly ``uam-result-v2``; unknown fields are refused, per kind.
* ``blockers`` are computed by UAM and stored with the result; a submitter cannot supply them.
* ``working-tree-diff-v1`` adds ``post_image_digests`` to the SSOT sketch (one entry per changed
  path, ``{absent: true}`` for a deletion). A patch alone cannot be re-observed in a live worktree
  (UAM's own diff covers tracked changes only), whereas the post-image of each changed file can.
"""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Protocol

from . import statefile
from .contracts import (
    BASELINE_FILE_DIGESTS,
    BASELINE_GIT_HEAD,
    CONTRACT_V2,
    ContractBinding,
    ContractStore,
    canonical_digest,
    normalize_file_path,
    validate_baseline,
    validate_file_states,
)
from .errors import ContractError
from .git_readonly import unquote_git_path

RESULT_V2 = "uam-result-v2"
KIND_PATCH = "working-tree-diff-v1"
KIND_DOCUMENT = "document-artifact-v1"
KIND_NO_CHANGE = "no-change-v1"
RESULT_KINDS = (KIND_PATCH, KIND_DOCUMENT, KIND_NO_CHANGE)

VERIFIER_GIT = "uam-git-state-and-file-digest-readback-v1"
VERIFIER_FILES = "uam-file-digest-readback-v1"

MAX_PATCH_BYTES = 512 * 1024
MAX_PATHS = 200
MAX_RECEIPTS = 100

# Readback states of a review and states of an observation of the baseline.
READBACK_MATCH = "MATCH"
READBACK_MISMATCH = "MISMATCH"
READBACK_INCOMPLETE = "INCOMPLETE"
READBACK_UNOBSERVABLE = "UNOBSERVABLE"
READBACK_NOT_PERFORMED = "NOT_PERFORMED"
BASELINE_UNCHANGED = "UNCHANGED"
BASELINE_CHANGED = "CHANGED"

PRESENT = "PRESENT"
ABSENT = "ABSENT"
INCOMPLETE = "INCOMPLETE"

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$")
_ATTEMPT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ARTIFACT_REF = re.compile(r"^sha256:([0-9a-f]{64})$")

_COMMON_FIELDS = {
    "result_version", "result_kind", "result_id", "business_task_ref", "task_revision", "attempt_ref",
    "contract_id", "contract_digest", "workspace_instance", "executor", "verification_receipts",
    "unresolved_risks",
}
_KIND_FIELDS = {
    KIND_PATCH: {"base_revision", "patch", "patch_digest", "changed_paths", "post_image_digests"},
    KIND_DOCUMENT: {"source_digests", "artifacts"},
    KIND_NO_CHANGE: {"rationale", "baseline"},
}


@dataclass(frozen=True)
class FileObservation:
    """What UAM's own reader says about one file right now."""

    state: str  # PRESENT (hashed in full), ABSENT, or INCOMPLETE (a digest could not be claimed)
    sha256: str | None = None
    size_bytes: int | None = None
    reason: str | None = None


@dataclass(frozen=True)
class GitObservation:
    """What UAM's own Git observer says about a repository workspace right now."""

    head: str | None
    changed_paths: frozenset[str]  # files, every untracked directory already expanded
    complete: bool = True
    incomplete_reason: str | None = None


class Readback(Protocol):
    """UAM's independent observation of a workspace (the gateway supplies the real one)."""

    def git_observation(self, workspace_id: str) -> GitObservation: ...

    def file_observation(self, workspace_id: str, path: str) -> FileObservation: ...


def parse_status_paths(status: str) -> tuple[list[str], list[str]]:
    """The paths a ``git status --short`` listing (renames off) names: ``(files, untracked_directories)``.

    ``--untracked-files=normal`` reports an untracked directory as one ``dir/`` entry, so a caller
    that needs every file must enumerate those directories itself. A line this parser does not
    recognise raises ``ValueError``: an observation that cannot be read is not an empty one.
    """
    files: list[str] = []
    directories: list[str] = []
    for line in status.splitlines():
        if not line.strip():
            continue
        if len(line) < 4 or line[2] != " ":
            raise ValueError("unrecognised status line")
        path = unquote_git_path(line[3:])
        (directories if path.endswith("/") else files).append(path)
    return files, directories


def _failure_reason(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    return f"{type(exc).__name__}:{code}" if isinstance(code, str) else type(exc).__name__


def _attempt(call: Callable[..., Any], *args: Any) -> tuple[Any, str | None]:
    """``(value, None)``, or ``(None, reason)`` where the reason carries no message (it could carry a path)."""
    try:
        return call(*args), None
    except Exception as exc:  # an observation that fails is an unobserved fact, never a pass
        return None, _failure_reason(exc)


def _compare_file(
    readback: Readback, workspace_id: str, path: str, expected: dict[str, Any]
) -> tuple[str, str]:
    """``("MATCH" | "DIFFERENT" | "UNKNOWN", detail)`` for one file against an expected state."""
    observed, failure = _attempt(readback.file_observation, workspace_id, path)
    if observed is None:
        return "UNKNOWN", failure or "unobserved"
    if observed.state == INCOMPLETE:
        return "UNKNOWN", observed.reason or "incomplete"
    if expected == {"absent": True}:
        return ("MATCH", "") if observed.state == ABSENT else ("DIFFERENT", "present")
    if observed.state == ABSENT:
        return "DIFFERENT", "absent"
    same = observed.sha256 == expected["sha256"] and observed.size_bytes == expected["size_bytes"]
    return ("MATCH", "") if same else ("DIFFERENT", "content")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def observe_baseline(binding: ContractBinding, readback: Readback) -> dict[str, Any]:
    """Compare the live workspace with the contract's baseline (no result involved).

    ``UNCHANGED`` is trusted evidence that no governed effect has reached the observed workspace;
    ``CHANGED`` is evidence of a partial or complete effect; ``UNOBSERVABLE`` is neither, and a caller
    must treat it as an unknown effect state. A directory workspace has no change observer, so
    ``UNCHANGED`` there covers only the files named by the baseline (``limits`` says so).
    """
    baseline = binding.baseline
    changed: list[str] = []
    unknown: list[str] = []
    limits: list[str] = []
    if baseline["kind"] == BASELINE_GIT_HEAD:
        git, failure = _attempt(readback.git_observation, binding.workspace_id)
        if git is None:
            return {"state": READBACK_UNOBSERVABLE, "reason": failure, "observed_at": _now()}
        if git.head != baseline["revision"]:
            changed.append("HEAD")
        changed.extend(sorted(git.changed_paths)[:50])
        if not git.complete:
            unknown.append(git.incomplete_reason or "git_state_incomplete")
    else:
        limits.append("changes outside the files named by the baseline are not observable in a directory workspace")
        for path, expected in sorted(baseline["files"].items()):
            verdict, _detail = _compare_file(readback, binding.workspace_id, path, expected)
            if verdict == "DIFFERENT":
                changed.append(path)
            elif verdict == "UNKNOWN":
                unknown.append(path)
    if changed:
        state = BASELINE_CHANGED
    elif unknown:
        state = READBACK_UNOBSERVABLE
    else:
        state = BASELINE_UNCHANGED
    return {
        "state": state,
        "changed": changed[:50],
        "unknown": unknown[:50],
        "limits": limits,
        "observed_at": _now(),
    }


# --- validation of a submission ------------------------------------------------------------------


def _require_fields(payload: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ContractError(f"unknown result fields: {', '.join(unknown)}")
    missing = sorted(allowed - set(payload))
    if missing:
        raise ContractError(f"missing result fields: {', '.join(missing)}")


def _bounded_text(value: Any, name: str, *, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ContractError(f"{name} must be a non-empty string of at most {limit} characters")
    return value


def _validate_receipts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_RECEIPTS:
        raise ContractError("verification_receipts must be a bounded list")
    receipts: list[dict[str, Any]] = []
    for item in value:
        valid = (
            isinstance(item, dict)
            and set(item) <= {"command", "exit_code", "evidence", "artifact_ref"}
            and isinstance(item.get("command"), str)
            and isinstance(item.get("exit_code"), int)
            and not isinstance(item.get("exit_code"), bool)
            and isinstance(item.get("evidence", ""), str)
            and (item.get("artifact_ref") is None or isinstance(item.get("artifact_ref"), str))
        )
        if not valid:
            raise ContractError(
                "each verification receipt needs command:string and exit_code:int "
                "(optional evidence:string, artifact_ref:string)"
            )
        artifact_ref = item.get("artifact_ref")
        if artifact_ref is not None and len(artifact_ref) > 500:
            raise ContractError("artifact_ref is oversized")
        receipts.append({
            "command": item["command"],
            "exit_code": item["exit_code"],
            "evidence": item.get("evidence", "")[:4_000],
            "artifact_ref": artifact_ref,
        })
    return receipts


def _validate_risks(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > 100
        or not all(isinstance(item, str) and len(item) <= 4_000 for item in value)
    ):
        raise ContractError("unresolved_risks must be a bounded list of strings")
    return value


def _validate_path_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_PATHS:
        raise ContractError(f"{name} must be a non-empty list of at most {MAX_PATHS} paths")
    paths = [normalize_file_path(item, name) for item in value]
    if len(set(paths)) != len(paths):
        raise ContractError(f"{name} contains a duplicate path")
    return paths


def _validate_patch(payload: dict[str, Any]) -> dict[str, Any]:
    revision = payload["base_revision"]
    if not isinstance(revision, str) or not _GIT_REVISION.fullmatch(revision):
        raise ContractError("base_revision must be a full lowercase hex Git revision")
    patch = payload["patch"]
    if not isinstance(patch, str) or not patch.strip():
        raise ContractError("patch must not be empty; a change that does not exist is reported as no-change-v1")
    encoded = patch.encode("utf-8")
    if len(encoded) > MAX_PATCH_BYTES:
        raise ContractError(f"patch exceeds {MAX_PATCH_BYTES} bytes")
    declared = payload["patch_digest"]
    if not isinstance(declared, str) or not _SHA256.fullmatch(declared):
        raise ContractError("patch_digest must be a lowercase hex SHA-256")
    if sha256(encoded).hexdigest() != declared:
        raise ContractError("patch_digest does not match the submitted patch")
    changed = _validate_path_list(payload["changed_paths"], "changed_paths")
    post_image = validate_file_states(payload["post_image_digests"], "post_image_digests")
    if set(post_image) != set(changed):
        raise ContractError("post_image_digests must cover exactly the changed_paths")
    return {
        "base_revision": revision,
        "patch": patch,
        "patch_digest": declared,
        "changed_paths": changed,
        "post_image_digests": post_image,
    }


def _validate_document(payload: dict[str, Any]) -> dict[str, Any]:
    sources = validate_file_states(payload["source_digests"], "source_digests")
    raw = payload["artifacts"]
    if not isinstance(raw, list) or not raw or len(raw) > MAX_PATHS:
        raise ContractError(f"artifacts must be a non-empty list of at most {MAX_PATHS} entries")
    artifacts: list[dict[str, Any]] = []
    for item in raw:
        valid = (
            isinstance(item, dict)
            and set(item) == {"path", "sha256", "size_bytes"}
            and isinstance(item["sha256"], str)
            and _SHA256.fullmatch(item["sha256"])
            and isinstance(item["size_bytes"], int)
            and not isinstance(item["size_bytes"], bool)
            and item["size_bytes"] >= 0
        )
        if not valid:
            raise ContractError("each artifact is exactly {path, sha256, size_bytes}")
        artifacts.append({
            "path": normalize_file_path(item["path"], "artifacts"),
            "sha256": item["sha256"],
            "size_bytes": item["size_bytes"],
        })
    if len({item["path"] for item in artifacts}) != len(artifacts):
        raise ContractError("artifacts contains a duplicate path")
    return {"source_digests": sources, "artifacts": artifacts}


def _validate_no_change(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "rationale": _bounded_text(payload["rationale"], "rationale", limit=4_000),
        "baseline": validate_baseline(payload["baseline"]),
    }


_KIND_VALIDATORS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    KIND_PATCH: _validate_patch,
    KIND_DOCUMENT: _validate_document,
    KIND_NO_CHANGE: _validate_no_change,
}


def stored_form(submission: dict[str, Any]) -> dict[str, Any]:
    """What is stored of a normalized submission: everything but the patch text, which is kept by its digest."""
    return {key: value for key, value in submission.items() if key != "patch"}


def validate_submission(payload: dict[str, Any]) -> dict[str, Any]:
    """The normalized submission, or ``ContractError``. Nothing is stored or observed here."""
    if not isinstance(payload, dict):
        raise ContractError("a result must be an object")
    if payload.get("result_version") != RESULT_V2:
        raise ContractError(f"unsupported result_version; this store accepts only {RESULT_V2}")
    kind = payload.get("result_kind")
    if kind not in _KIND_FIELDS:
        raise ContractError(f"unsupported result_kind; expected one of {', '.join(RESULT_KINDS)}")
    _require_fields(payload, _COMMON_FIELDS | _KIND_FIELDS[kind])
    if not _ID.fullmatch(str(payload["result_id"])):
        raise ContractError("invalid result_id")
    if not _ID.fullmatch(str(payload["contract_id"])):
        raise ContractError("invalid contract_id")
    if not isinstance(payload["attempt_ref"], str) or not _ATTEMPT.fullmatch(payload["attempt_ref"]):
        raise ContractError("invalid attempt_ref")
    digest = payload["contract_digest"]
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ContractError("contract_digest must be a lowercase hex SHA-256")
    task_ref, revision = payload["business_task_ref"], payload["task_revision"]
    if task_ref is None:
        if revision is not None:
            raise ContractError("task_revision requires a business_task_ref")
    else:
        _bounded_text(task_ref, "business_task_ref", limit=200)
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
            raise ContractError("task_revision must be a non-negative integer when a business_task_ref is given")
    submission: dict[str, Any] = {
        "result_version": RESULT_V2,
        "result_kind": kind,
        "result_id": str(payload["result_id"]),
        "business_task_ref": task_ref,
        "task_revision": revision,
        "attempt_ref": payload["attempt_ref"],
        "contract_id": str(payload["contract_id"]),
        "contract_digest": digest,
        "workspace_instance": _bounded_text(payload["workspace_instance"], "workspace_instance", limit=400),
        "executor": _bounded_text(payload["executor"], "executor", limit=200),
        "verification_receipts": _validate_receipts(payload["verification_receipts"]),
        "unresolved_risks": _validate_risks(payload["unresolved_risks"]),
    }
    submission.update(_KIND_VALIDATORS[kind](payload))
    return submission


# --- what a receiver has to submit: the same rules, written down where it reads the contract ---------------------

# One note per field, for ``describe_result_contract``. They describe what ``validate_submission`` and ``_static_blockers``
# enforce; ``tests/test_result_contract.py`` fails if a field of ``_COMMON_FIELDS`` / ``_KIND_FIELDS`` has no note here.
_FIELD_NOTES = {
    "result_version": f"exactly {RESULT_V2}",
    "result_kind": "one of the kinds in `kinds`; it decides which kind fields are required as well",
    "result_id": (
        "your own id: 3 to 80 characters of letters, digits, '.', '_' and '-', starting with a letter or digit; "
        "an id that already holds a different result is refused (RESULT_ID_CONFLICT)"
    ),
    "business_task_ref": "the delivery's business_task_ref, copied (null only when the delivery has none)",
    "task_revision": "the delivery's task_revision, copied (null only when business_task_ref is null)",
    "attempt_ref": "the attempt_ref that uam_attempt_start returned for your active attempt",
    "contract_id": "the contract's id, copied",
    "contract_digest": "the contract's digest (lowercase hex SHA-256), copied",
    "workspace_instance": "the contract's workspace_id, copied",
    "executor": "your own principal, the one this server acts as",
    "verification_receipts": (
        "a list (at most 100) of {command, exit_code, evidence?, artifact_ref?}: exactly one per command in the contract's "
        "verification_commands and none other; a missing or undeclared command, or an exit_code other than 0, puts the "
        "review on HOLD; [] when the contract declares none"
    ),
    "unresolved_risks": (
        "a list of strings (at most 100, each at most 4000 characters); anything in it puts the review on HOLD, "
        "so [] when nothing is open"
    ),
    "base_revision": "the contract baseline's Git revision, copied (full lowercase hex)",
    "patch": "the unified diff of your change: not empty, at most 524288 bytes as UTF-8",
    "patch_digest": "lowercase hex SHA-256 of the patch text encoded as UTF-8",
    "changed_paths": (
        "every file the patch changes: canonical workspace-relative paths (no absolute path, no '..'), at most 200, "
        "no duplicate, each inside allowed_change_paths"
    ),
    "post_image_digests": (
        "one entry per changed path and no other key: {sha256, size_bytes} of the file as it is now, or {absent: true} "
        "when the change deletes it"
    ),
    "source_digests": "the contract baseline's state of every authoritative path that the baseline lists, copied exactly",
    "artifacts": (
        "a non-empty list (at most 200) of exactly {path, sha256, size_bytes}, one per file you wrote and no path twice, "
        "each path inside allowed_change_paths; sha256 (lowercase hex) and size_bytes (integer) are those of the file as it is now"
    ),
    "rationale": "why nothing was changed: a non-empty string of at most 4000 characters",
    "baseline": (
        "the contract's baseline object, copied exactly; UAM reads the workspace back and reports WORKSPACE_NOT_UNCHANGED "
        "if it is no longer that baseline"
    ),
}
_KIND_USE_WHEN = {
    KIND_PATCH: "your change is uncommitted work in a Git workspace: deliver it as a patch, with the state of every changed file",
    KIND_DOCUMENT: "you wrote or changed files in a directory workspace: deliver the digest of every file you wrote",
    KIND_NO_CHANGE: (
        "nothing was changed and the workspace is still the contract baseline (a read-only task, or a baseline that "
        "already satisfies the contract): deliver your reason"
    ),
}
_NOT_APPLICABLE = {
    KIND_PATCH: "needs a git-head baseline; this contract's baseline is file-digests",
    KIND_DOCUMENT: "needs a file-digests baseline; this contract's baseline is git-head",
}


def _slot(what: str) -> str:
    """A template value that only the receiver can know. It is never a valid value, so an unedited template is refused."""
    return f"<{what}>"


def _holds_slot(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_holds_slot(key) or _holds_slot(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_holds_slot(item) for item in value)
    return isinstance(value, str) and value.startswith("<") and value.endswith(">")


def describe_result_contract(
    binding: ContractBinding,
    *,
    business_task_ref: str | None,
    task_revision: int | None,
    executor: str,
    attempt_ref: str | None = None,
    result_id: str | None = None,
) -> dict[str, Any]:
    """What a receiver has to submit for one contract, from the constants and rules the validator itself uses.

    A receiver that reads this next to the contract never has to learn the structure by being refused. It is a
    description, not a second protocol: ``validate_submission`` and the review are what decide, unchanged, and nothing
    here is accepted or defaulted on the receiver's behalf. Per applicable kind it gives the required fields with their
    rules and one template in which every value the delivery fixes is already filled in; what only the receiver can
    know is an explicit ``<...>`` slot, listed in ``fill_in``, and a slot is never a valid value.
    """
    baseline = binding.baseline
    applicable = {
        KIND_PATCH: baseline["kind"] == BASELINE_GIT_HEAD,
        KIND_DOCUMENT: baseline["kind"] == BASELINE_FILE_DIGESTS,
        KIND_NO_CHANGE: True,
    }
    common: dict[str, Any] = {
        "result_version": RESULT_V2,
        "result_id": result_id or _slot("your own result_id, not used before"),
        "business_task_ref": business_task_ref,
        "task_revision": task_revision,
        "attempt_ref": attempt_ref or _slot("attempt_ref returned by uam_attempt_start"),
        "contract_id": binding.contract_id,
        "contract_digest": binding.digest,
        "workspace_instance": binding.workspace_id,
        "executor": executor,
        "verification_receipts": [
            {
                "command": command,
                "exit_code": _slot("exit status of this command, an integer"),
                "evidence": _slot("what it showed, short"),
            }
            for command in binding.verification_commands
        ],
        "unresolved_risks": [],
    }
    files = baseline.get("files", {})
    kind_values: dict[str, dict[str, Any]] = {
        KIND_PATCH: {
            "base_revision": baseline.get("revision"),
            "patch": _slot("unified diff of your change"),
            "patch_digest": _slot("sha256 of the patch text, UTF-8"),
            "changed_paths": [_slot("a changed file")],
            "post_image_digests": {
                _slot("a changed file"): {"sha256": _slot("sha256 of it now"), "size_bytes": _slot("its size, an integer")},
            },
        },
        KIND_DOCUMENT: {
            "source_digests": {path: copy.deepcopy(files[path]) for path in binding.authoritative_paths if path in files},
            "artifacts": [{
                "path": _slot("a file you wrote, one of allowed_change_paths"),
                "sha256": _slot("sha256 of that file now"),
                "size_bytes": _slot("its size, an integer"),
            }],
        },
        KIND_NO_CHANGE: {
            "rationale": _slot("why nothing was changed"),
            "baseline": copy.deepcopy(baseline),
        },
    }
    kinds = [kind for kind in RESULT_KINDS if applicable[kind]]
    templates = {kind: {**common, "result_kind": kind, **kind_values[kind]} for kind in kinds}

    def notes(names: set[str]) -> dict[str, str]:
        return {name: _FIELD_NOTES.get(name, "see results_v2.validate_submission") for name in sorted(names)}

    return {
        "describes": RESULT_V2,
        "how_to_use": [
            "Pick the kind in `kinds` that says what you did, copy templates[<kind>] and replace every '<...>' slot listed "
            "in fill_in[<kind>]; keep every other value as given. Send the object as `result` of uam_attempt_result.",
            "Validation is strict and fills in nothing: every field of the kind is required, an unknown field is refused, "
            "and a refused result is not stored.",
            "UAM reads the workspace back itself and computes the review (`blockers`); your receipts and your summary are "
            "not evidence, and business acceptance stays with the task owner.",
        ],
        "kinds": {
            kind: {"use_when": _KIND_USE_WHEN[kind], "fields": notes(_KIND_FIELDS[kind])} for kind in kinds
        },
        "not_applicable_kinds": {kind: _NOT_APPLICABLE[kind] for kind in RESULT_KINDS if not applicable[kind]},
        "common_fields": notes(_COMMON_FIELDS),
        "templates": templates,
        "fill_in": {
            kind: sorted(name for name, value in template.items() if _holds_slot(value))
            for kind, template in templates.items()
        },
    }


# --- review ---------------------------------------------------------------------------------------


def _static_blockers(record: dict[str, Any], binding: ContractBinding) -> set[str]:
    """Conformance of a result with its contract: deterministic, repeatable on every read."""
    blockers: set[str] = set()
    if binding.readiness_state != "READY":
        blockers.add("CONTRACT_NOT_READY")
    if record["contract_digest"] != binding.digest:
        blockers.add("CONTRACT_DIGEST_MISMATCH")
    if record["workspace_instance"] != binding.workspace_id:
        blockers.add("WORKSPACE_MISMATCH")
    baseline = binding.baseline
    allowed = set(binding.allowed_change_paths)
    kind = record["result_kind"]
    if kind == KIND_PATCH:
        if baseline["kind"] != BASELINE_GIT_HEAD:
            blockers.add("RESULT_KIND_NOT_APPLICABLE_TO_BASELINE")
        elif record["base_revision"] != baseline["revision"]:
            blockers.add("BASELINE_MISMATCH")
        if set(record["changed_paths"]) - allowed:
            blockers.add("CHANGED_PATH_OUTSIDE_CONTRACT")
    elif kind == KIND_DOCUMENT:
        if baseline["kind"] != BASELINE_FILE_DIGESTS:
            blockers.add("RESULT_KIND_NOT_APPLICABLE_TO_BASELINE")
        else:
            expected_sources = {
                path: baseline["files"][path]
                for path in binding.authoritative_paths
                if path in baseline["files"]
            }
            if record["source_digests"] != expected_sources:
                blockers.add("BASELINE_MISMATCH")
        if {item["path"] for item in record["artifacts"]} - allowed:
            blockers.add("ARTIFACT_PATH_OUTSIDE_CONTRACT")
    else:  # KIND_NO_CHANGE: it restates the baseline it was judged against, and that must be the contract's
        if record["baseline"] != baseline:
            blockers.add("BASELINE_MISMATCH")
    declared = set(binding.verification_commands)
    reported = {item["command"] for item in record["verification_receipts"]}
    if declared - reported:
        blockers.add("DECLARED_VERIFICATION_MISSING")
    if reported - declared:
        blockers.add("UNDECLARED_VERIFICATION_REPORTED")
    if any(item["exit_code"] != 0 for item in record["verification_receipts"]):
        blockers.add("VERIFICATION_FAILED")
    if record["unresolved_risks"]:
        blockers.add("UNRESOLVED_RISKS_PRESENT")
    return blockers


def _readback_state(blockers: list[str], *, definitive: frozenset[str]) -> str:
    if any(blocker in definitive for blocker in blockers):
        return READBACK_MISMATCH
    if "READBACK_UNOBSERVABLE" in blockers:
        return READBACK_UNOBSERVABLE
    if "READBACK_INCOMPLETE" in blockers:
        return READBACK_INCOMPLETE
    return READBACK_MATCH


def _readback_patch(
    record: dict[str, Any], binding: ContractBinding, readback: Readback
) -> tuple[str, list[str], dict[str, Any]]:
    definitive = frozenset({"BASE_REVISION_MOVED", "LIVE_CHANGED_PATHS_MISMATCH", "POST_IMAGE_MISMATCH"})
    git, failure = _attempt(readback.git_observation, binding.workspace_id)
    if git is None:
        return READBACK_UNOBSERVABLE, ["READBACK_UNOBSERVABLE"], {"git_state": failure}
    blockers: list[str] = []
    checks: dict[str, Any] = {}
    claimed = set(record["changed_paths"])
    moved = git.head != binding.baseline["revision"]
    checks["head_matches_baseline"] = not moved
    if moved:
        blockers.append("BASE_REVISION_MOVED")
    unclaimed = sorted(git.changed_paths - claimed)
    if unclaimed:
        blockers.append("LIVE_CHANGED_PATHS_MISMATCH")
        checks["live_changes_not_claimed"] = unclaimed[:50]
    if git.complete:
        unchanged = sorted(claimed - git.changed_paths)
        if unchanged:
            if "LIVE_CHANGED_PATHS_MISMATCH" not in blockers:
                blockers.append("LIVE_CHANGED_PATHS_MISMATCH")
            checks["claimed_but_not_changed_live"] = unchanged[:50]
    else:
        blockers.append("READBACK_INCOMPLETE")
        checks["git_incomplete_reason"] = git.incomplete_reason
    different: list[str] = []
    unknown: list[str] = []
    for path, expected in sorted(record["post_image_digests"].items()):
        verdict, _detail = _compare_file(readback, binding.workspace_id, path, expected)
        if verdict == "DIFFERENT":
            different.append(path)
        elif verdict == "UNKNOWN":
            unknown.append(path)
    if different:
        blockers.append("POST_IMAGE_MISMATCH")
        checks["post_image_differs"] = different[:50]
    if unknown:
        blockers.append("READBACK_INCOMPLETE")
        checks["post_image_unobserved"] = unknown[:50]
    return _readback_state(blockers, definitive=definitive), sorted(set(blockers)), checks


def _readback_document(
    record: dict[str, Any], binding: ContractBinding, readback: Readback
) -> tuple[str, list[str], dict[str, Any]]:
    definitive = frozenset({
        "ARTIFACT_DIGEST_MISMATCH", "AUTHORITATIVE_SOURCE_CHANGED", "UNCLAIMED_PATH_CHANGED",
    })
    blockers: list[str] = []
    checks: dict[str, Any] = {
        "collateral_changes": "not observable in a directory workspace: only the contract's observed files are compared",
    }
    artifact_paths = {item["path"] for item in record["artifacts"]}
    different: list[str] = []
    unknown: list[str] = []
    for item in record["artifacts"]:
        verdict, _detail = _compare_file(
            readback, binding.workspace_id, item["path"],
            {"sha256": item["sha256"], "size_bytes": item["size_bytes"]},
        )
        if verdict == "DIFFERENT":
            different.append(item["path"])
        elif verdict == "UNKNOWN":
            unknown.append(item["path"])
    if different:
        blockers.append("ARTIFACT_DIGEST_MISMATCH")
        checks["artifacts_differ"] = different[:50]
    sources_changed: list[str] = []
    others_changed: list[str] = []
    for path, expected in sorted(binding.baseline["files"].items()):
        if path in artifact_paths:
            continue
        verdict, _detail = _compare_file(readback, binding.workspace_id, path, expected)
        if verdict == "DIFFERENT":
            (sources_changed if path in binding.authoritative_paths else others_changed).append(path)
        elif verdict == "UNKNOWN":
            unknown.append(path)
    if sources_changed:
        blockers.append("AUTHORITATIVE_SOURCE_CHANGED")
        checks["authoritative_changed"] = sources_changed[:50]
    if others_changed:
        blockers.append("UNCLAIMED_PATH_CHANGED")
        checks["unclaimed_changed"] = others_changed[:50]
    if unknown:
        blockers.append("READBACK_INCOMPLETE")
        checks["unobserved"] = unknown[:50]
    return _readback_state(blockers, definitive=definitive), sorted(set(blockers)), checks


def _readback_no_change(
    record: dict[str, Any], binding: ContractBinding, readback: Readback
) -> tuple[str, list[str], dict[str, Any]]:
    observation = observe_baseline(binding, readback)
    state = observation["state"]
    if state == BASELINE_UNCHANGED:
        return READBACK_MATCH, [], observation
    if state == BASELINE_CHANGED:
        return READBACK_MISMATCH, ["WORKSPACE_NOT_UNCHANGED"], observation
    return READBACK_UNOBSERVABLE, ["READBACK_UNOBSERVABLE"], observation


_READBACKS = {
    KIND_PATCH: (_readback_patch, VERIFIER_GIT),
    KIND_DOCUMENT: (_readback_document, VERIFIER_FILES),
    KIND_NO_CHANGE: (_readback_no_change, VERIFIER_GIT),
}


def _evidence_classes() -> dict[str, str]:
    return {
        "artifact_readback": "INDEPENDENT_UAM_OBSERVATION",
        "verification_receipts": "SELF_REPORTED",
        "executor_identity": "DECLARED_NOT_AUTHENTICATED",
    }


class ResultV2Store:
    """Immutable store of ``uam-result-v2`` results, reviewed against their contract and the live workspace."""

    def __init__(
        self,
        state_dir: str | Path,
        contracts: ContractStore,
        readback: Readback | None = None,
    ):
        self.root = Path(state_dir) / "results-v2"
        self.artifacts = Path(state_dir) / "artifacts" / "sha256"
        # Neither directory is created here. Every gateway builds this store, including the read-only session server's, and building it must not
        # write to the state directory: ``statefile.write_new`` creates the parents of the first result or patch it stores, and a reader
        # of a directory that does not exist yet finds no result.
        self.contracts = contracts
        self._readback = readback

    def put(self, payload: dict[str, Any]) -> dict[str, Any]:
        submission = validate_submission(payload)
        path = self.root / f"{submission['result_id']}.json"
        if path.exists():
            raise ContractError("result_id already exists; executor results are immutable")
        # Contract existence is part of result admission; the contract is also what the live check is judged by.
        binding = self.contracts.binding(submission["contract_id"])
        if binding.contract_version != CONTRACT_V2:
            # Each result schema pairs with one contract schema: a v1 contract is fulfilled by a v1 result.
            raise ContractError(
                f"a {RESULT_V2} result binds a {CONTRACT_V2} contract; this contract uses the v1 result schema"
            )
        record = stored_form(submission)
        record["submission_digest"] = canonical_digest(record)
        if submission["result_kind"] == KIND_PATCH:
            record["patch_artifact_ref"] = self._store_patch(submission["patch"], submission["patch_digest"])
        blockers = set(_static_blockers(record, binding))
        record["verifier"] = _READBACKS[submission["result_kind"]][1]
        record["readback"] = self._observe(record, binding, blockers)
        record["blockers"] = sorted(blockers | set(record["readback"].pop("blockers")))
        record["completed_at"] = _now()
        try:
            statefile.write_new(path, json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        except FileExistsError as exc:
            raise ContractError("result_id already exists; executor results are immutable") from exc
        return {**record, "review": self._review(record, binding)}

    def submission_digest(self, payload: dict[str, Any]) -> str:
        """The digest ``put`` would store for ``payload``: how a resubmission is told from a different result.

        Validation only: nothing is observed or written. A retried submission whose digest equals a stored
        result's is the same submission; the same ``result_id`` with another digest is a conflict.
        """
        return canonical_digest(stored_form(validate_submission(payload)))

    def get(self, result_id: str) -> dict[str, Any]:
        record = self._load(result_id)
        return {**record, "review": self._review(record, self._binding_or_none(record))}

    def read_patch(self, result_id: str) -> str:
        """The patch text of a ``working-tree-diff-v1`` result, verified against its digest on every read."""
        record = self._load(result_id)
        if record["result_kind"] != KIND_PATCH:
            raise ContractError("this result carries no patch")
        text = self._read_artifact(record["patch_artifact_ref"])
        if sha256(text.encode("utf-8")).hexdigest() != record["patch_digest"]:
            raise ContractError("stored patch does not match its digest")
        return text

    def observe_baseline(self, contract_id: str) -> dict[str, Any]:
        """The live workspace compared with a contract's baseline (see ``observe_baseline``)."""
        binding = self.contracts.binding(contract_id)
        if self._readback is None:
            return {"state": READBACK_UNOBSERVABLE, "reason": "no_readback_configured", "observed_at": _now()}
        return observe_baseline(binding, self._readback)

    # -- internals ---------------------------------------------------------------------------

    def _load(self, result_id: str) -> dict[str, Any]:
        if not _ID.fullmatch(result_id):
            raise ContractError("invalid result_id")
        path = self.root / f"{result_id}.json"
        if not path.exists():
            raise ContractError("executor result not found")
        return json.loads(path.read_text(encoding="utf-8"))

    def _binding_or_none(self, record: dict[str, Any]) -> ContractBinding | None:
        try:
            return self.contracts.binding(record["contract_id"])
        except ContractError:
            return None

    def _store_patch(self, patch: str, digest: str) -> str:
        path = self.artifacts / digest
        try:
            statefile.write_new(path, patch)
        except FileExistsError:
            pass  # content-addressed: the same digest names the same bytes, verified on every read
        return f"sha256:{digest}"

    def _read_artifact(self, ref: str) -> str:
        match = _ARTIFACT_REF.fullmatch(ref)
        if match is None:
            raise ContractError("unsupported artifact reference")
        path = self.artifacts / match.group(1)
        if not path.is_file():
            raise ContractError("artifact not found")
        text = path.read_text(encoding="utf-8")
        if sha256(text.encode("utf-8")).hexdigest() != match.group(1):
            raise ContractError("stored artifact does not match its reference")
        return text

    def _observe(
        self, record: dict[str, Any], binding: ContractBinding, static_blockers: set[str]
    ) -> dict[str, Any]:
        observed_at = _now()
        if "RESULT_KIND_NOT_APPLICABLE_TO_BASELINE" in static_blockers:
            return {"state": READBACK_NOT_PERFORMED, "reason": "result_kind_not_applicable_to_baseline",
                    "observed_at": observed_at, "blockers": []}
        if self._readback is None:
            return {"state": READBACK_NOT_PERFORMED, "reason": "no_readback_configured",
                    "observed_at": observed_at, "blockers": ["INDEPENDENT_READBACK_MISSING"]}
        check, _verifier = _READBACKS[record["result_kind"]]
        state, blockers, checks = check(record, binding, self._readback)
        return {"state": state, "observed_at": observed_at, "checks": checks, "blockers": blockers}

    def _review(self, record: dict[str, Any], binding: ContractBinding | None) -> dict[str, Any]:
        blockers = set(record["blockers"])
        if binding is None:
            blockers.add("CONTRACT_MISSING")
        else:
            blockers |= _static_blockers(record, binding)
        if record["result_kind"] == KIND_PATCH:
            try:
                self.read_patch(record["result_id"])
            except ContractError:
                blockers.add("PATCH_ARTIFACT_UNVERIFIABLE")
        readback = record["readback"]
        passed = not blockers and readback["state"] == READBACK_MATCH
        return {
            "state": "PASS" if passed else "HOLD",
            "blockers": sorted(blockers),
            "readback": readback,
            "evidence_classes": _evidence_classes(),
            "business_acceptance": "NOT_DETERMINED_BY_UAM",
        }
