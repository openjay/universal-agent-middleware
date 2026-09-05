from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .contracts import ContractStore, assess_readiness
from .errors import ContractError
from .models import ExecutorResult

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$")


class ExecutorResultStore:
    def __init__(self, state_dir: str | Path, contracts: ContractStore):
        self.root = Path(state_dir) / "results"
        self.root.mkdir(parents=True, exist_ok=True)
        self.contracts = contracts

    def put(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = self._validate(payload)
        path = self.root / f"{result.result_id}.json"
        if path.exists():
            raise ContractError("result_id already exists; executor results are immutable")
        path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        return {**result.to_dict(), "review": self.review_model(result)}

    def get(self, result_id: str) -> dict[str, Any]:
        if not _ID.fullmatch(result_id):
            raise ContractError("invalid result_id")
        path = self.root / f"{result_id}.json"
        if not path.exists():
            raise ContractError("executor result not found")
        result = ExecutorResult(**json.loads(path.read_text(encoding="utf-8")))
        return {**result.to_dict(), "review": self.review_model(result)}

    def _validate(self, payload: dict[str, Any]) -> ExecutorResult:
        required = [
            "result_id",
            "contract_id",
            "workspace_id",
            "base_revision",
            "final_revision",
            "changed_paths",
            "verification",
            "unresolved_risks",
            "executor",
        ]
        unknown = sorted(set(payload) - set(required))
        if unknown:
            raise ContractError(f"unknown executor result fields: {', '.join(unknown)}")
        missing = [k for k in required if k not in payload]
        if missing:
            raise ContractError(f"missing executor result fields: {', '.join(missing)}")
        if not _ID.fullmatch(str(payload["result_id"])):
            raise ContractError("invalid result_id")
        changed_paths = _string_list(payload.get("changed_paths", []), "changed_paths")
        unresolved_risks = _string_list(payload.get("unresolved_risks", []), "unresolved_risks")
        verification = payload.get("verification", [])
        if not isinstance(verification, list) or len(verification) > 100:
            raise ContractError("verification must be a bounded list")
        normalized = []
        for item in verification:
            if not isinstance(item, dict) or not isinstance(item.get("command"), str) or not isinstance(item.get("exit_code"), int):
                raise ContractError("each verification item needs command:string and exit_code:int")
            normalized.append({
                "command": item["command"],
                "exit_code": item["exit_code"],
                "evidence": str(item.get("evidence", ""))[:4_000],
            })
        # Contract existence is part of result admission.
        self.contracts.get(str(payload["contract_id"]))
        return ExecutorResult(
            result_version="uam-executor-result-v1",
            result_id=str(payload["result_id"]),
            contract_id=str(payload["contract_id"]),
            workspace_id=str(payload["workspace_id"]),
            base_revision=str(payload["base_revision"]),
            final_revision=str(payload["final_revision"]),
            changed_paths=changed_paths,
            verification=normalized,
            unresolved_risks=unresolved_risks,
            executor=str(payload["executor"]),
            completed_at=datetime.now(timezone.utc).isoformat(),
        )

    def review_model(self, result: ExecutorResult) -> dict[str, Any]:
        contract = self.contracts.get_model(result.contract_id)
        blockers: list[str] = []
        contract_ready = assess_readiness(contract)
        if contract_ready["state"] != "READY":
            blockers.append("CONTRACT_NOT_READY")
        if result.workspace_id != contract.workspace_id:
            blockers.append("WORKSPACE_MISMATCH")
        if result.base_revision != contract.base_revision:
            blockers.append("BASE_REVISION_MISMATCH")
        if result.final_revision == result.base_revision:
            blockers.append("FINAL_REVISION_UNCHANGED")
        allowed = set(contract.allowed_change_paths)
        changed = set(result.changed_paths)
        if not changed:
            blockers.append("NO_CHANGED_PATHS")
        extra = sorted(changed - allowed)
        if extra:
            blockers.append("CHANGED_PATH_OUTSIDE_CONTRACT")
        declared_commands = set(contract.verification_commands)
        observed_commands = [item["command"] for item in result.verification]
        missing_commands = sorted(declared_commands - set(observed_commands))
        undeclared_commands = sorted(set(observed_commands) - declared_commands)
        if missing_commands:
            blockers.append("DECLARED_VERIFICATION_MISSING")
        if undeclared_commands:
            blockers.append("UNDECLARED_VERIFICATION_REPORTED")
        if any(item["exit_code"] != 0 for item in result.verification):
            blockers.append("VERIFICATION_FAILED")
        if result.unresolved_risks:
            blockers.append("UNRESOLVED_RISKS_PRESENT")
        return {
            "state": "PASS" if not blockers else "HOLD",
            "blockers": blockers,
            "extra_changed_paths": extra,
            "missing_verification_commands": missing_commands,
            "undeclared_verification_commands": undeclared_commands,
        }


def _string_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ContractError(f"{name} must be a list of strings")
    if len(value) > 100:
        raise ContractError(f"{name} exceeds item limit")
    return value
