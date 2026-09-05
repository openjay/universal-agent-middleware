"""Local executor adapter for UAM.

Executes a repository-change-v1 contract in the workspace where it was
observed. The executor:

1. Validates base_revision matches current HEAD
2. Checks out exact base (already there if HEAD matches)
3. Performs the bounded change
4. Runs declared verification commands
5. Commits the change
6. Produces an Executor Result

This is the simplest closed-loop executor — no external API, no
network, no credentials. The change function is injected as a callable
so the adapter itself contains no business logic.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass
class ExecutionOutcome:
    success: bool
    result_id: str
    contract_id: str
    workspace_id: str
    base_revision: str
    final_revision: str
    changed_paths: list[str]
    verification: list[dict[str, Any]]
    unresolved_risks: list[str]
    executor: str
    error: str = ""

    def to_result_payload(self) -> dict[str, Any]:
        return {
            "result_id": self.result_id,
            "contract_id": self.contract_id,
            "workspace_id": self.workspace_id,
            "base_revision": self.base_revision,
            "final_revision": self.final_revision,
            "changed_paths": self.changed_paths,
            "verification": self.verification,
            "unresolved_risks": self.unresolved_risks,
            "executor": self.executor,
        }


@dataclass
class LocalExecutorConfig:
    workspace_root: str
    executor_name: str = "uam-local-executor-v1"
    commit_message_prefix: str = "[uam-executor]"
    timeout_seconds: int = 30


class LocalExecutor:
    """Bounded local executor for repository-change-v1 contracts."""

    def __init__(self, config: LocalExecutorConfig):
        self.config = config
        self.root = Path(config.workspace_root).resolve()
        if not self.root.is_dir():
            raise ValueError(f"workspace root not found: {self.root}")

    def execute(
        self,
        contract: dict[str, Any],
        change_fn: Callable[[Path], list[str]],
        *,
        result_id: str,
    ) -> ExecutionOutcome:
        contract_id = contract["contract_id"]
        workspace_id = contract["workspace_id"]
        base_revision = contract["base_revision"]
        allowed_paths = set(contract["allowed_change_paths"])
        verification_commands = contract["verification_commands"]

        current_head = self._git_head()
        if current_head != base_revision:
            return self._fail(
                result_id=result_id,
                contract_id=contract_id,
                workspace_id=workspace_id,
                base_revision=base_revision,
                error=f"HEAD {current_head} != contract base {base_revision}",
            )

        try:
            actual_changed = change_fn(self.root)
        except Exception as e:
            return self._fail(
                result_id=result_id,
                contract_id=contract_id,
                workspace_id=workspace_id,
                base_revision=base_revision,
                error=f"change_fn failed: {e}",
            )

        out_of_scope = sorted(set(actual_changed) - allowed_paths)
        if out_of_scope:
            return self._fail(
                result_id=result_id,
                contract_id=contract_id,
                workspace_id=workspace_id,
                base_revision=base_revision,
                error=f"out-of-scope paths: {out_of_scope}",
            )

        verification_results = []
        for cmd in verification_commands:
            vr = self._run_verification(cmd)
            verification_results.append(vr)

        all_passed = all(v["exit_code"] == 0 for v in verification_results)

        if not all_passed:
            return ExecutionOutcome(
                success=False,
                result_id=result_id,
                contract_id=contract_id,
                workspace_id=workspace_id,
                base_revision=base_revision,
                final_revision=base_revision,
                changed_paths=actual_changed,
                verification=verification_results,
                unresolved_risks=["verification commands failed"],
                executor=self.config.executor_name,
                error="verification failed",
            )

        commit_msg = (
            f"{self.config.commit_message_prefix} "
            f"execute {contract_id}"
        )
        self._git_commit(actual_changed, commit_msg)
        final_revision = self._git_head()

        return ExecutionOutcome(
            success=True,
            result_id=result_id,
            contract_id=contract_id,
            workspace_id=workspace_id,
            base_revision=base_revision,
            final_revision=final_revision,
            changed_paths=actual_changed,
            verification=verification_results,
            unresolved_risks=[],
            executor=self.config.executor_name,
        )

    def _git_head(self) -> str:
        return self._run_git(["rev-parse", "HEAD"]).strip()

    def _git_commit(self, paths: list[str], message: str) -> None:
        for p in paths:
            self._run_git(["add", "--", p])
        self._run_git(["commit", "-m", message])

    def _run_git(self, args: list[str]) -> str:
        cmd = ["git", "-C", str(self.root)] + args
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.config.timeout_seconds,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"git {args[0]} failed: {proc.stderr.strip()[:200]}")
        return proc.stdout

    def _run_verification(self, command: str) -> dict[str, Any]:
        try:
            proc = subprocess.run(
                ["sh", "-c", command],
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
                cwd=str(self.root),
            )
            return {
                "command": command,
                "exit_code": proc.returncode,
                "evidence": (proc.stdout + proc.stderr).strip()[:2000],
            }
        except subprocess.TimeoutExpired:
            return {
                "command": command,
                "exit_code": -1,
                "evidence": "timeout",
            }
        except Exception as e:
            return {
                "command": command,
                "exit_code": -1,
                "evidence": str(e)[:200],
            }

    def _fail(
        self,
        *,
        result_id: str,
        contract_id: str,
        workspace_id: str,
        base_revision: str,
        error: str,
    ) -> ExecutionOutcome:
        return ExecutionOutcome(
            success=False,
            result_id=result_id,
            contract_id=contract_id,
            workspace_id=workspace_id,
            base_revision=base_revision,
            final_revision=base_revision,
            changed_paths=[],
            verification=[],
            unresolved_risks=[error],
            executor=self.config.executor_name,
            error=error,
        )
