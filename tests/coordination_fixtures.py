"""Payload builders shared by the workspace-change-v2 contract, result-v2 and task-control tests."""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any

CONTRACT_PROFILE_V2 = "workspace-change-v2"
RESULT_V2 = "uam-result-v2"


def sha(data: str | bytes) -> str:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def file_state(text: str) -> dict[str, Any]:
    """The ``{sha256, size_bytes}`` state of a file holding exactly ``text`` (UTF-8)."""
    encoded = text.encode("utf-8")
    return {"sha256": sha(encoded), "size_bytes": len(encoded)}


def contract_v2(
    contract_id: str,
    workspace_id: str,
    *,
    authoritative: Sequence[str] = (),
    allowed: Sequence[str] = (),
    verification: Sequence[str] = ("true",),
    **overrides: Any,
) -> dict[str, Any]:
    """A complete ``workspace-change-v2`` creation payload (no ``baseline``/``admission``: UAM observes those)."""
    payload: dict[str, Any] = {
        "profile": CONTRACT_PROFILE_V2,
        "contract_id": contract_id,
        "workspace_id": workspace_id,
        "objective": "Produce the requested change",
        "non_goals": ["anything outside the allowed paths"],
        "authoritative_paths": list(authoritative),
        "allowed_change_paths": list(allowed),
        "constraints": ["stay inside the allowed paths"],
        "implementation_decision": "Write the files named by allowed_change_paths",
        "expected_changes": ["the allowed paths hold the new content"],
        "acceptance_criteria": ["a reviewer can read the result"],
        "verification_commands": list(verification),
        "risk_notes": [],
        "rollback": ["restore the baseline"],
        "open_questions": [],
    }
    payload.update(overrides)
    return payload


def receipts(commands: Sequence[str] = ("true",), *, exit_code: int = 0) -> list[dict[str, Any]]:
    return [{"command": command, "exit_code": exit_code, "evidence": "ran"} for command in commands]


def _common(contract: Mapping[str, Any], result_id: str, kind: str) -> dict[str, Any]:
    return {
        "result_version": RESULT_V2,
        "result_kind": kind,
        "result_id": result_id,
        "business_task_ref": None,
        "task_revision": None,
        "attempt_ref": "attempt-0001",
        "contract_id": contract["contract_id"],
        "contract_digest": contract["contract_digest"],
        "workspace_instance": contract["workspace_id"],
        "executor": "test-executor",
        "verification_receipts": receipts(contract["verification_commands"]),
        "unresolved_risks": [],
    }


def document_result(
    contract: Mapping[str, Any], result_id: str, written: Mapping[str, str], **overrides: Any
) -> dict[str, Any]:
    """A ``document-artifact-v1`` result for ``written`` (path -> the text the executor wrote there)."""
    files = contract["baseline"]["files"]
    payload = _common(contract, result_id, "document-artifact-v1")
    payload["source_digests"] = {
        path: files[path] for path in contract["authoritative_paths"] if path in files
    }
    payload["artifacts"] = [{"path": path, **file_state(text)} for path, text in written.items()]
    payload.update(overrides)
    return payload


def patch_result(
    contract: Mapping[str, Any],
    result_id: str,
    patch: str,
    post_images: Mapping[str, str | None],
    **overrides: Any,
) -> dict[str, Any]:
    """A ``working-tree-diff-v1`` result; ``post_images`` maps each changed path to its new text (None = deleted)."""
    payload = _common(contract, result_id, "working-tree-diff-v1")
    payload["base_revision"] = contract["baseline"].get("revision", "a" * 40)
    payload["patch"] = patch
    payload["patch_digest"] = sha(patch)
    payload["changed_paths"] = list(post_images)
    payload["post_image_digests"] = {
        path: ({"absent": True} if text is None else file_state(text)) for path, text in post_images.items()
    }
    payload.update(overrides)
    return payload


def no_change_result(
    contract: Mapping[str, Any], result_id: str, rationale: str = "the baseline already satisfies the contract",
    **overrides: Any,
) -> dict[str, Any]:
    payload = _common(contract, result_id, "no-change-v1")
    payload["rationale"] = rationale
    payload["baseline"] = contract["baseline"]
    payload.update(overrides)
    return payload
