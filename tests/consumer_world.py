"""Test-world helpers for the Consumer (no unittest here): one workspace, a state directory, contracts and deliveries.

A world is what ``seed_local_task.py`` of the local-owner pilot builds, without its scope pins: a registry with static
``filesystem-directory`` workspaces, a UAM state directory bound to one ``endpoint_ref`` and a gateway over them. The
requester side (``create_contract``, ``deliver``) is a TEST DRIVER that calls the library; it is not a Dispatcher and
decides nothing: it only does what a native client would do through the MCP tools.
"""
from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.task_continuity_control import ContinuityControl
from universal_agent_middleware.task_control import AuthorityVerifier

from consumer_authority_factory import StandInAuthority
from coordination_fixtures import contract_v2

ENDPOINT = "endpoint-consumer-test"
OWNER = "owner-x"
REQUESTER = "requester-a"
CONSUMER = "consumer-1"
TESTS_DIR = Path(__file__).resolve().parent
WORKER_SCRIPT = TESTS_DIR / "consumer_worker.py"
SOURCE_DIR = TESTS_DIR.parent / "src"


@dataclass(frozen=True)
class World:
    root: Path
    workspace_ids: tuple[str, ...]
    registry: Path
    state: Path
    gateway: MiddlewareGateway

    def workspace(self, workspace_id: str = "ws-main") -> Path:
        return self.root / "workspaces" / workspace_id


def write_json_private(path: Path, document: Any) -> Path:
    """Operator-owned input file: the current user's, mode 0600 (the Consumer refuses anything group/world writable)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def build_world(
    root: Path, *, workspace_ids: Sequence[str] = ("ws-main",), seed: Mapping[str, str] | None = None,
) -> World:
    root.mkdir(parents=True, exist_ok=True)
    entries = []
    for workspace_id in workspace_ids:
        workspace = root / "workspaces" / workspace_id
        for relative, text in {"inputs/spec.md": "# spec\n", **(seed or {})}.items():
            (workspace / relative).parent.mkdir(parents=True, exist_ok=True)
            (workspace / relative).write_text(text, encoding="utf-8")
        entries.append({
            "workspace_id": workspace_id, "root": str(workspace), "kind": "filesystem-directory",
            "capabilities": ["filesystem.read"],
        })
    registry = write_json_private(root / "config" / "workspaces.json", {
        "registry_version": "uam-workspace-registry-v1", "workspaces": entries,
    })
    state = root / "state"
    state.mkdir(parents=True, exist_ok=True)
    return World(root, tuple(workspace_ids), registry, state, MiddlewareGateway(str(registry), str(state)))


def make_control(world: World, authority: AuthorityVerifier | None = None, **options: Any) -> ContinuityControl:
    gateway = world.gateway
    return ContinuityControl(
        gateway.state_dir, contracts=gateway.contracts, results=gateway.results_v2, authority=authority,
        audit=gateway.audit, endpoint_ref=options.pop("endpoint_ref", ENDPOINT), **options,
    )


def stand_in_control(world: World, log: str | None = None, **options: Any) -> ContinuityControl:
    return make_control(world, StandInAuthority(log), **options)


def create_contract(
    world: World, contract_id: str, *, authoritative: Sequence[str] = ("inputs/spec.md",), allowed: Sequence[str],
    verification: Sequence[str] = ("true",), workspace_id: str = "ws-main",
) -> dict[str, Any]:
    return world.gateway.create_contract(contract_v2(
        contract_id, workspace_id, authoritative=authoritative, allowed=allowed, verification=verification,
    ))


def deliver(
    control: ContinuityControl, contract: Mapping[str, Any], *, task: str, requester: str = REQUESTER,
    recipient: str = CONSUMER, owner: str = OWNER, revision: int = 1, authority_ref: str = "grant-0001",
) -> dict[str, Any]:
    return control.deliver_continuity(
        requester, contract_id=contract["contract_id"], contract_digest=contract["contract_digest"],
        recipient=recipient, authority_ref=authority_ref, idempotency_key=f"key-{contract['contract_id']}",
        owner_ref=owner, business_task_ref=task, task_revision=revision, data_scope_ref="scope-ref-1",
    )


def worker_env(evidence: Path, **extra: str) -> dict[str, str]:
    """The environment a registered test worker is given (the adapter adds only PATH, LANG and the job paths)."""
    return {"PYTHONPATH": f"{SOURCE_DIR}:{TESTS_DIR}", "UAM_TEST_EVIDENCE_DIR": str(evidence), **extra}


def worker_document(name_to_env: Mapping[str, Mapping[str, str]], *, max_seconds: float = 60.0) -> dict[str, Any]:
    """A ``--workers`` file: every registered worker is the test worker script run by this interpreter."""
    return {"workers": {
        name: {"argv": [sys.executable, str(WORKER_SCRIPT)], "max_seconds": max_seconds, "env": dict(env)}
        for name, env in name_to_env.items()
    }}


def policy_document(rules: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {"schema": "uam-consumer-policy-v1", "rules": [dict(rule) for rule in rules]}


def rule_for(world: World, task: str, worker: str, *, workspace_id: str = "ws-main", **extra: Any) -> dict[str, Any]:
    return {
        "adapter": "local-command", "worker": worker, "cwd": str(world.workspace(workspace_id).resolve()),
        "business_task_ref": task, "owner_ref": OWNER, "verification_allowlist": ["true"],
        "lease_seconds": 120, "max_seconds": 60, **extra,
    }
