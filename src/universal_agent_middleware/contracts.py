from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import ContractError
from .models import ExecutionContract

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$")
_SUPPORTED_PROFILES = {"repository-change-v1"}


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

    def get(self, contract_id: str) -> dict[str, Any]:
        if not _ID.fullmatch(contract_id):
            raise ContractError("invalid contract_id")
        path = self.root / f"{contract_id}.json"
        if not path.exists():
            raise ContractError("contract not found")
        data = json.loads(path.read_text(encoding="utf-8"))
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
