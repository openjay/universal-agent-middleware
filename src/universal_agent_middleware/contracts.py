from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import statefile
from .errors import ContractError, PathPolicyError
from .models import (
    KIND_FILESYSTEM_DIRECTORY,
    KIND_GIT_REPOSITORY,
    ExecutionContract,
    ExecutionContractV2,
)
from .policy import ensure_relative_path

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$")

CONTRACT_V1 = "uam-execution-contract-v1"
CONTRACT_V2 = "uam-execution-contract-v2"
PROFILE_REPOSITORY_CHANGE_V1 = "repository-change-v1"
PROFILE_WORKSPACE_CHANGE_V2 = "workspace-change-v2"
BASELINE_GIT_HEAD = "git-head"
BASELINE_FILE_DIGESTS = "file-digests"
MAX_BASELINE_FILES = 200

# The closed set of the v1 validator. A v2 profile is deliberately not in it: a v1 payload that names
# the successor profile is refused exactly as before, and the successor has its own entry point.
_SUPPORTED_PROFILES = {PROFILE_REPOSITORY_CHANGE_V1}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_RESOLUTION_KINDS = frozenset({"static", "derived", "absolute_path", "project_name"})
_WORKSPACE_KINDS = frozenset({KIND_GIT_REPOSITORY, KIND_FILESYSTEM_DIRECTORY})


def canonical_digest(data: Mapping[str, Any]) -> str:
    """SHA-256 of ``data`` as canonical JSON: sorted keys, no insignificant whitespace, UTF-8.

    The one definition of a contract digest. It is computed over the persisted contract record
    (never over the derived ``readiness`` or ``executor_prompt``), so it is stable for as long as
    the contract is immutable and any change to a stored contract changes it.
    """
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class ContractBinding:
    """What a result needs to know about the contract it is bound to, whatever the contract version.

    A v1 contract's baseline is its Git revision; a v2 contract states its baseline explicitly. The
    result reviewer reads this view so it never needs to know which schema version produced it.
    """

    contract_id: str
    contract_version: str
    profile: str
    workspace_id: str
    baseline: dict[str, Any]
    authoritative_paths: tuple[str, ...]
    allowed_change_paths: tuple[str, ...]
    verification_commands: tuple[str, ...]
    readiness_state: str
    readiness_blockers: tuple[str, ...]
    digest: str


class ContractStore:
    def __init__(self, state_dir: str | Path):
        self.root = Path(state_dir) / "contracts"
        self.root.mkdir(parents=True, exist_ok=True)

    def validate(self, payload: dict[str, Any]) -> ExecutionContract:
        required = [
            "profile",
            "contract_id",
            "workspace_id",
            "base_revision",
            "objective",
            "non_goals",
            "authoritative_paths",
            "allowed_change_paths",
            "constraints",
            "implementation_decision",
            "expected_changes",
            "acceptance_criteria",
            "verification_commands",
            "risk_notes",
            "rollback",
            "open_questions",
        ]
        allowed = set(required) | {"created_by"}
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise ContractError(f"unknown contract fields: {', '.join(unknown)}")
        missing = [name for name in required if name not in payload]
        if missing:
            raise ContractError(f"missing required fields: {', '.join(missing)}")
        if not _ID.fullmatch(str(payload["contract_id"])):
            raise ContractError("invalid contract_id")
        profile = str(payload["profile"])
        if profile not in _SUPPORTED_PROFILES:
            raise ContractError(f"unsupported contract profile: {profile}")
        contract = ExecutionContract(
            contract_version="uam-execution-contract-v1",
            profile=profile,
            contract_id=str(payload["contract_id"]),
            workspace_id=str(payload["workspace_id"]),
            base_revision=str(payload["base_revision"]),
            objective=str(payload["objective"]),
            non_goals=_string_list(payload.get("non_goals", []), "non_goals"),
            authoritative_paths=_string_list(
                payload.get("authoritative_paths", []), "authoritative_paths"
            ),
            allowed_change_paths=_string_list(
                payload.get("allowed_change_paths", []), "allowed_change_paths"
            ),
            constraints=_string_list(payload.get("constraints", []), "constraints"),
            implementation_decision=str(payload["implementation_decision"]),
            expected_changes=_string_list(
                payload.get("expected_changes", []), "expected_changes"
            ),
            acceptance_criteria=_string_list(
                payload["acceptance_criteria"], "acceptance_criteria"
            ),
            verification_commands=_string_list(
                payload.get("verification_commands", []), "verification_commands"
            ),
            risk_notes=_string_list(payload.get("risk_notes", []), "risk_notes"),
            rollback=_string_list(payload.get("rollback", []), "rollback"),
            open_questions=_string_list(
                payload.get("open_questions", []), "open_questions"
            ),
            created_at=datetime.now(timezone.utc).isoformat(),
            created_by=str(payload.get("created_by", "uam")),
        )
        if len(contract.objective) > 4_000 or len(contract.implementation_decision) > 8_000:
            raise ContractError("contract prose exceeds size limit")
        return contract

    def put(self, payload: dict[str, Any]) -> dict[str, Any]:
        contract = self.validate(payload)
        json_path = self.root / f"{contract.contract_id}.json"
        md_path = self.root / f"{contract.contract_id}.md"
        if json_path.exists() or md_path.exists():
            raise ContractError("contract_id already exists; contracts are immutable")
        data = contract.to_dict()
        json_path.write_text(
            json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        md_path.write_text(render_markdown(contract), encoding="utf-8")
        return {
            **data,
            "readiness": assess_readiness(contract),
            "executor_prompt": render_executor_prompt(contract),
        }

    def _load_raw(self, contract_id: str) -> dict[str, Any]:
        if not _ID.fullmatch(contract_id):
            raise ContractError("invalid contract_id")
        path = self.root / f"{contract_id}.json"
        if not path.exists():
            raise ContractError("contract not found")
        return json.loads(path.read_text(encoding="utf-8"))

    def get(self, contract_id: str) -> dict[str, Any]:
        """A v1 contract. A successor-schema contract is refused here and read with ``get_record``.

        Keeping ``get`` v1-only is what stops the legacy result store from binding a result to a
        contract whose baseline it cannot interpret.
        """
        data = self._load_raw(contract_id)
        if data.get("contract_version") == CONTRACT_V2:
            raise ContractError(
                f"contract uses the successor schema {CONTRACT_V2}; read it with get_record"
            )
        contract = ExecutionContract(**data)
        return {
            **data,
            "readiness": assess_readiness(contract),
            "executor_prompt": render_executor_prompt(contract),
        }

    def get_model(self, contract_id: str) -> ExecutionContract:
        data = self.get(contract_id)
        return ExecutionContract(
            **{k: data[k] for k in ExecutionContract.__dataclass_fields__}
        )

    def get_record(self, contract_id: str) -> dict[str, Any]:
        """A contract of either schema version, with its readiness and executor prompt.

        A v2 record also carries ``contract_digest`` so a caller can bind a result to exactly this
        contract. v1 records are returned exactly as ``get`` returns them.
        """
        data = self._load_raw(contract_id)
        if data.get("contract_version") != CONTRACT_V2:
            return self.get(contract_id)
        contract = ExecutionContractV2(**data)
        digest = canonical_digest(data)
        return {
            **data,
            "contract_digest": digest,
            "readiness": assess_readiness_v2(contract),
            "executor_prompt": render_executor_prompt_v2(contract, digest),
        }

    def digest(self, contract_id: str) -> str:
        """The ``canonical_digest`` of the persisted contract record (either schema version)."""
        return canonical_digest(self._load_raw(contract_id))

    def binding(self, contract_id: str) -> ContractBinding:
        """The version-neutral view of a stored contract that results are checked against."""
        data = self._load_raw(contract_id)
        digest = canonical_digest(data)
        if data.get("contract_version") == CONTRACT_V2:
            contract_v2 = ExecutionContractV2(**data)
            readiness = assess_readiness_v2(contract_v2)
            return ContractBinding(
                contract_id=contract_v2.contract_id,
                contract_version=contract_v2.contract_version,
                profile=contract_v2.profile,
                workspace_id=contract_v2.workspace_id,
                baseline=contract_v2.baseline,
                authoritative_paths=tuple(contract_v2.authoritative_paths),
                allowed_change_paths=tuple(contract_v2.allowed_change_paths),
                verification_commands=tuple(contract_v2.verification_commands),
                readiness_state=readiness["state"],
                readiness_blockers=tuple(readiness["blockers"]),
                digest=digest,
            )
        contract = ExecutionContract(**data)
        readiness = assess_readiness(contract)
        return ContractBinding(
            contract_id=contract.contract_id,
            contract_version=contract.contract_version,
            profile=contract.profile,
            workspace_id=contract.workspace_id,
            baseline={"kind": BASELINE_GIT_HEAD, "revision": contract.base_revision},
            authoritative_paths=tuple(contract.authoritative_paths),
            allowed_change_paths=tuple(contract.allowed_change_paths),
            verification_commands=tuple(contract.verification_commands),
            readiness_state=readiness["state"],
            readiness_blockers=tuple(readiness["blockers"]),
            digest=digest,
        )

    def validate_v2(
        self,
        payload: dict[str, Any],
        *,
        baseline: dict[str, Any],
        admission: dict[str, Any],
    ) -> ExecutionContractV2:
        """Validate a successor-schema payload.

        ``baseline`` and ``admission`` are observed by the caller (the gateway) and passed beside the
        payload, never inside it: a payload carrying either key is refused as an unknown field, so a
        requester cannot forge the baseline a later result is judged against.
        """
        required = [
            "profile",
            "contract_id",
            "workspace_id",
            "objective",
            "non_goals",
            "authoritative_paths",
            "allowed_change_paths",
            "constraints",
            "implementation_decision",
            "expected_changes",
            "acceptance_criteria",
            "verification_commands",
            "risk_notes",
            "rollback",
            "open_questions",
        ]
        allowed = set(required) | {"created_by"}
        unknown = sorted(set(payload) - allowed)
        if unknown:
            raise ContractError(f"unknown contract fields: {', '.join(unknown)}")
        missing = [name for name in required if name not in payload]
        if missing:
            raise ContractError(f"missing required fields: {', '.join(missing)}")
        if not _ID.fullmatch(str(payload["contract_id"])):
            raise ContractError("invalid contract_id")
        if str(payload["profile"]) != PROFILE_WORKSPACE_CHANGE_V2:
            raise ContractError(f"unsupported contract profile: {payload['profile']}")
        contract = ExecutionContractV2(
            contract_version=CONTRACT_V2,
            profile=PROFILE_WORKSPACE_CHANGE_V2,
            contract_id=str(payload["contract_id"]),
            workspace_id=str(payload["workspace_id"]),
            baseline=validate_baseline(baseline),
            admission=_validate_admission(admission),
            objective=str(payload["objective"]),
            non_goals=_string_list(payload["non_goals"], "non_goals"),
            authoritative_paths=_file_paths(payload["authoritative_paths"], "authoritative_paths"),
            allowed_change_paths=_file_paths(payload["allowed_change_paths"], "allowed_change_paths"),
            constraints=_string_list(payload["constraints"], "constraints"),
            implementation_decision=str(payload["implementation_decision"]),
            expected_changes=_string_list(payload["expected_changes"], "expected_changes"),
            acceptance_criteria=_string_list(payload["acceptance_criteria"], "acceptance_criteria"),
            verification_commands=_string_list(payload["verification_commands"], "verification_commands"),
            risk_notes=_string_list(payload["risk_notes"], "risk_notes"),
            rollback=_string_list(payload["rollback"], "rollback"),
            open_questions=_string_list(payload["open_questions"], "open_questions"),
            created_at=datetime.now(timezone.utc).isoformat(),
            created_by=str(payload.get("created_by", "uam")),
        )
        if len(contract.objective) > 4_000 or len(contract.implementation_decision) > 8_000:
            raise ContractError("contract prose exceeds size limit")
        return contract

    def put_v2(
        self,
        payload: dict[str, Any],
        *,
        baseline: dict[str, Any],
        admission: dict[str, Any],
    ) -> dict[str, Any]:
        """Persist an immutable successor-schema contract and return it with its digest."""
        contract = self.validate_v2(payload, baseline=baseline, admission=admission)
        json_path = self.root / f"{contract.contract_id}.json"
        md_path = self.root / f"{contract.contract_id}.md"
        if json_path.exists() or md_path.exists():
            raise ContractError("contract_id already exists; contracts are immutable")
        data = contract.to_dict()
        try:
            # Atomic and exclusive: a reader never sees a partial record, and two writers cannot both win.
            statefile.write_new(json_path, json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        except FileExistsError as exc:
            raise ContractError("contract_id already exists; contracts are immutable") from exc
        statefile.replace(md_path, render_markdown_v2(contract))
        digest = canonical_digest(data)
        return {
            **data,
            "contract_digest": digest,
            "readiness": assess_readiness_v2(contract),
            "executor_prompt": render_executor_prompt_v2(contract, digest),
        }


def _string_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ContractError(f"{name} must be a list of strings")
    if len(value) > 100:
        raise ContractError(f"{name} exceeds item limit")
    if any(len(item) > 4_000 for item in value):
        raise ContractError(f"{name} contains an oversized item")
    return value


def assess_readiness(contract: ExecutionContract) -> dict[str, Any]:
    blockers: list[str] = []
    if contract.profile not in _SUPPORTED_PROFILES:
        blockers.append("UNSUPPORTED_PROFILE")
    if contract.open_questions:
        blockers.append("OPEN_QUESTIONS_PRESENT")
    if not contract.authoritative_paths:
        blockers.append("NO_AUTHORITATIVE_PATHS")
    if contract.profile == "repository-change-v1":
        if not contract.allowed_change_paths:
            blockers.append("NO_ALLOWED_CHANGE_PATHS")
        if not contract.verification_commands:
            blockers.append("NO_VERIFICATION_COMMANDS")
        if not contract.rollback:
            blockers.append("NO_ROLLBACK")
    return {"state": "READY" if not blockers else "HOLD", "blockers": blockers}


def render_markdown(contract: ExecutionContract) -> str:
    def bullet(items: list[str]) -> str:
        return "\n".join(f"- {item}" for item in items) if items else "- none"

    return f"""# Execution Contract — {contract.contract_id}

- version: `{contract.contract_version}`
- profile: `{contract.profile}`
- workspace: `{contract.workspace_id}`
- base revision: `{contract.base_revision}`
- created by: `{contract.created_by}`
- created at: `{contract.created_at}`

## Objective
{contract.objective}

## Non-goals
{bullet(contract.non_goals)}

## Authoritative paths
{bullet(contract.authoritative_paths)}

## Allowed change paths
{bullet(contract.allowed_change_paths)}

## Constraints
{bullet(contract.constraints)}

## Implementation decision
{contract.implementation_decision}

## Expected changes
{bullet(contract.expected_changes)}

## Acceptance criteria
{bullet(contract.acceptance_criteria)}

## Verification commands
{bullet(contract.verification_commands)}

## Risk notes
{bullet(contract.risk_notes)}

## Rollback
{bullet(contract.rollback)}

## Open questions
{bullet(contract.open_questions)}
"""


def render_executor_prompt(contract: ExecutionContract) -> str:
    return (
        f"Consume UAM contract {contract.contract_id} ({contract.profile}) for workspace "
        f"{contract.workspace_id} at exact base revision {contract.base_revision}. "
        "Treat the contract as the complete bounded handoff. Do not broaden scope, "
        "change the objective, or infer missing authority from prior conversation. "
        "Return an Executor Result bound to this contract with actual changed paths, "
        "final revision, verification evidence, and unresolved risks."
    )


# --- successor schema (uam-execution-contract-v2) -------------------------------------------------


def normalize_file_path(raw: Any, name: str) -> str:
    """A workspace-relative file path in its one canonical spelling, or ``ContractError``.

    The same confinement rules every other UAM path goes through (no absolute path, no traversal, no
    sensitive-name component), plus a canonical spelling so that two spellings of one path can never
    be compared as two different paths.
    """
    if not isinstance(raw, str) or not raw or len(raw) > 1_024:
        raise ContractError(f"{name} must contain non-empty path strings")
    try:
        relative = ensure_relative_path(raw)
    except PathPolicyError as exc:
        raise ContractError(f"{name} contains a path outside the confinement policy: {exc}") from exc
    if relative.as_posix() != raw or raw == ".":
        raise ContractError(f"{name} must use canonical workspace-relative file paths")
    return raw


def _file_paths(value: Any, name: str) -> list[str]:
    paths = [normalize_file_path(item, name) for item in _string_list(value, name)]
    if len(set(paths)) != len(paths):
        raise ContractError(f"{name} contains a duplicate path")
    return paths


def _validate_file_state(entry: Any) -> dict[str, Any]:
    if isinstance(entry, dict) and entry == {"absent": True}:
        return {"absent": True}
    if (
        isinstance(entry, dict)
        and set(entry) == {"sha256", "size_bytes"}
        and isinstance(entry["sha256"], str)
        and _SHA256.fullmatch(entry["sha256"])
        and isinstance(entry["size_bytes"], int)
        and not isinstance(entry["size_bytes"], bool)
        and entry["size_bytes"] >= 0
    ):
        return {"sha256": entry["sha256"], "size_bytes": entry["size_bytes"]}
    raise ContractError("a file state is {absent: true} or {sha256, size_bytes}")


def validate_file_states(files: Any, name: str) -> dict[str, dict[str, Any]]:
    """A bounded map of canonical relative path to file state (``absent`` or ``sha256`` + ``size_bytes``)."""
    if not isinstance(files, dict) or len(files) > MAX_BASELINE_FILES:
        raise ContractError(f"{name} must be a map of at most {MAX_BASELINE_FILES} files")
    return {normalize_file_path(path, name): _validate_file_state(entry) for path, entry in files.items()}


def validate_baseline(baseline: Any) -> dict[str, Any]:
    if not isinstance(baseline, dict):
        raise ContractError("baseline must be an object")
    kind = baseline.get("kind")
    if kind == BASELINE_GIT_HEAD:
        revision = baseline.get("revision")
        if set(baseline) != {"kind", "revision"} or not isinstance(revision, str) or not _GIT_REVISION.fullmatch(revision):
            raise ContractError("a git-head baseline is exactly {kind, revision} with a full lowercase hex revision")
        return {"kind": BASELINE_GIT_HEAD, "revision": revision}
    if kind == BASELINE_FILE_DIGESTS:
        if set(baseline) != {"kind", "files"}:
            raise ContractError("a file-digests baseline is exactly {kind, files}")
        return {"kind": BASELINE_FILE_DIGESTS, "files": validate_file_states(baseline["files"], "baseline files")}
    raise ContractError("unsupported baseline kind")


def _validate_admission(admission: Any) -> dict[str, Any]:
    keys = {"resolution_kind", "workspace_kind", "scope_id", "policy_generation"}
    if not isinstance(admission, dict) or set(admission) != keys:
        raise ContractError(f"admission is exactly {{{', '.join(sorted(keys))}}}")
    if admission["resolution_kind"] not in _RESOLUTION_KINDS:
        raise ContractError("unsupported admission resolution_kind")
    if admission["workspace_kind"] not in _WORKSPACE_KINDS:
        raise ContractError("unsupported admission workspace_kind")
    for key in ("scope_id", "policy_generation"):
        if not isinstance(admission[key], str) or len(admission[key]) > 200:
            raise ContractError(f"admission {key} must be a bounded string")
    return {key: admission[key] for key in sorted(keys)}


def assess_readiness_v2(contract: ExecutionContractV2) -> dict[str, Any]:
    """Readiness of a successor contract. Verification commands are optional: a document task is
    verified by independent readback, not by a command the executor runs."""
    blockers: list[str] = []
    if contract.profile != PROFILE_WORKSPACE_CHANGE_V2:
        blockers.append("UNSUPPORTED_PROFILE")
    if contract.open_questions:
        blockers.append("OPEN_QUESTIONS_PRESENT")
    if not contract.allowed_change_paths:
        blockers.append("NO_ALLOWED_CHANGE_PATHS")
    if not contract.acceptance_criteria:
        blockers.append("NO_ACCEPTANCE_CRITERIA")
    if not contract.rollback:
        blockers.append("NO_ROLLBACK")
    return {"state": "READY" if not blockers else "HOLD", "blockers": blockers}


def _describe_baseline(baseline: dict[str, Any]) -> str:
    if baseline["kind"] == BASELINE_GIT_HEAD:
        return f"git HEAD `{baseline['revision']}`, clean worktree"
    return f"{len(baseline['files'])} file state(s) observed by UAM"


def render_markdown_v2(contract: ExecutionContractV2) -> str:
    def bullet(items: list[str]) -> str:
        return "\n".join(f"- {item}" for item in items) if items else "- none"

    return f"""# Execution Contract — {contract.contract_id}

- version: `{contract.contract_version}`
- profile: `{contract.profile}`
- workspace: `{contract.workspace_id}` ({contract.admission['workspace_kind']}, admitted as {contract.admission['resolution_kind']})
- baseline: {_describe_baseline(contract.baseline)}
- created by: `{contract.created_by}`
- created at: `{contract.created_at}`

## Objective
{contract.objective}

## Non-goals
{bullet(contract.non_goals)}

## Authoritative paths
{bullet(contract.authoritative_paths)}

## Allowed change paths
{bullet(contract.allowed_change_paths)}

## Constraints
{bullet(contract.constraints)}

## Implementation decision
{contract.implementation_decision}

## Expected changes
{bullet(contract.expected_changes)}

## Acceptance criteria
{bullet(contract.acceptance_criteria)}

## Verification commands
{bullet(contract.verification_commands)}

## Risk notes
{bullet(contract.risk_notes)}

## Rollback
{bullet(contract.rollback)}

## Open questions
{bullet(contract.open_questions)}
"""


def render_executor_prompt_v2(contract: ExecutionContractV2, digest: str) -> str:
    return (
        f"Consume UAM contract {contract.contract_id} ({contract.profile}, digest {digest}) for workspace "
        f"{contract.workspace_id} at the baseline UAM observed when it admitted the contract. "
        "Treat the contract as the complete bounded handoff. Do not broaden scope, "
        "change the objective, or infer missing authority from prior conversation. "
        "Do not commit, publish or apply anything beyond the allowed change paths. "
        "Return a uam-result-v2 bound to this contract id and digest: a patch, a document artifact "
        "or a justified no-change, with the declared verification evidence and unresolved risks. "
        "UAM verifies the result against the live workspace; your own summary is not evidence."
    )
