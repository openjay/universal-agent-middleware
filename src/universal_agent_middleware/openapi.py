from __future__ import annotations

import os
from typing import Any

from . import __version__


def _string_array(description: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {"type": "array", "items": {"type": "string"}}
    if description:
        out["description"] = description
    return out


def contract_input_schema() -> dict[str, Any]:
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
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": {
            "profile": {
                "type": "string",
                "enum": ["repository-change-v1"],
                "description": "Contract semantic profile. UAM v0.2 implements repository-change-v1 only.",
            },
            "contract_id": {"type": "string"},
            "workspace_id": {"type": "string"},
            "base_revision": {"type": "string"},
            "objective": {"type": "string"},
            "non_goals": _string_array(),
            "authoritative_paths": _string_array(
                "Workspace-relative sources that establish task truth."
            ),
            "allowed_change_paths": _string_array(
                "Closed allowlist for the repository-change-v1 executor."
            ),
            "constraints": _string_array(),
            "implementation_decision": {"type": "string"},
            "expected_changes": _string_array(),
            "acceptance_criteria": _string_array(),
            "verification_commands": _string_array(
                "Inert command strings for a separate executor. UAM never executes them."
            ),
            "risk_notes": _string_array(),
            "rollback": _string_array(),
            "open_questions": _string_array(),
            "created_by": {"type": "string"},
        },
    }


def result_input_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "result_id",
            "contract_id",
            "workspace_id",
            "base_revision",
            "final_revision",
            "changed_paths",
            "verification",
            "unresolved_risks",
            "executor",
        ],
        "properties": {
            "result_id": {"type": "string"},
            "contract_id": {"type": "string"},
            "workspace_id": {"type": "string"},
            "base_revision": {"type": "string"},
            "final_revision": {"type": "string"},
            "changed_paths": _string_array(),
            "verification": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["command", "exit_code", "evidence"],
                    "properties": {
                        "command": {"type": "string"},
                        "exit_code": {"type": "integer"},
                        "evidence": {"type": "string"},
                    },
                },
            },
            "unresolved_risks": _string_array(),
            "executor": {"type": "string"},
        },
    }


def schema() -> dict[str, Any]:
    base_url = os.environ.get(
        "UAM_PUBLIC_BASE_URL", "https://REPLACE_WITH_YOUR_UAM_HOST"
    )
    bearer = [{"BearerAuth": []}]
    ok = {"200": {"description": "OK"}}
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Universal Agent Middleware",
            "version": __version__,
            "description": (
                "Vendor-neutral middleware for read-only workspace observation, "
                "immutable execution-contract handoff, executor evidence ingestion, "
                "and machine review. Target workspace content is untrusted data."
            ),
        },
        "servers": [{"url": base_url}],
        "components": {
            "securitySchemes": {
                "BearerAuth": {"type": "http", "scheme": "bearer"}
            }
        },
        "paths": {
            "/v1/workspaces": {
                "get": {
                    "operationId": "listWorkspaces",
                    "summary": "List registered workspaces and capability profiles",
                    "security": bearer,
                    "responses": ok,
                }
            },
            "/v1/tree": {
                "get": {
                    "operationId": "listWorkspaceTree",
                    "summary": "List a bounded workspace tree",
                    "security": bearer,
                    "parameters": [
                        {"name": "workspace_id", "in": "query", "required": True, "schema": {"type": "string"}},
                        {"name": "path", "in": "query", "required": False, "schema": {"type": "string", "default": "."}},
                        {"name": "depth", "in": "query", "required": False, "schema": {"type": "integer", "default": 3, "minimum": 0, "maximum": 8}},
                    ],
                    "responses": ok,
                }
            },
            "/v1/read": {
                "post": {
                    "operationId": "readWorkspaceFile",
                    "summary": "Read a bounded UTF-8 file range",
                    "security": bearer,
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["workspace_id", "path"],
                            "properties": {
                                "workspace_id": {"type": "string"},
                                "path": {"type": "string"},
                                "start_line": {"type": "integer", "minimum": 1},
                                "end_line": {"type": ["integer", "null"], "minimum": 1},
                            },
                        }}},
                    },
                    "responses": ok,
                }
            },
            "/v1/search": {
                "post": {
                    "operationId": "searchWorkspaceText",
                    "summary": "Search text within a workspace",
                    "security": bearer,
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["workspace_id", "query"],
                            "properties": {
                                "workspace_id": {"type": "string"},
                                "query": {"type": "string"},
                                "path": {"type": "string", "default": "."},
                                "max_results": {"type": "integer", "default": 100, "minimum": 1, "maximum": 500},
                            },
                        }}},
                    },
                    "responses": ok,
                }
            },
            "/v1/git/status": {
                "get": {
                    "operationId": "getGitStatus",
                    "summary": "Observe Git HEAD, branch, and status",
                    "security": bearer,
                    "parameters": [{"name": "workspace_id", "in": "query", "required": True, "schema": {"type": "string"}}],
                    "responses": ok,
                }
            },
            "/v1/git/diff": {
                "get": {
                    "operationId": "getGitDiff",
                    "summary": "Observe working-tree Git diff",
                    "security": bearer,
                    "parameters": [
                        {"name": "workspace_id", "in": "query", "required": True, "schema": {"type": "string"}},
                        {"name": "path", "in": "query", "required": False, "schema": {"type": "string"}},
                    ],
                    "responses": ok,
                }
            },
            "/v1/git/log": {
                "get": {
                    "operationId": "getGitLog",
                    "summary": "Observe recent Git commits",
                    "security": bearer,
                    "parameters": [
                        {"name": "workspace_id", "in": "query", "required": True, "schema": {"type": "string"}},
                        {"name": "limit", "in": "query", "required": False, "schema": {"type": "integer", "default": 20, "minimum": 1, "maximum": 100}},
                    ],
                    "responses": ok,
                }
            },
            "/v1/contracts": {
                "post": {
                    "operationId": "createExecutionContract",
                    "summary": "Persist an immutable bounded execution handoff outside the target workspace",
                    "security": bearer,
                    "requestBody": {"required": True, "content": {"application/json": {"schema": contract_input_schema()}}},
                    "responses": ok,
                }
            },
            "/v1/contracts/{contract_id}": {
                "get": {
                    "operationId": "getExecutionContract",
                    "summary": "Read an immutable execution contract",
                    "security": bearer,
                    "parameters": [{"name": "contract_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": ok,
                }
            },
            "/v1/results": {
                "post": {
                    "operationId": "recordExecutorResult",
                    "summary": "Record immutable executor evidence and machine-review it against its contract",
                    "security": bearer,
                    "requestBody": {"required": True, "content": {"application/json": {"schema": result_input_schema()}}},
                    "responses": ok,
                }
            },
            "/v1/results/{result_id}": {
                "get": {
                    "operationId": "getExecutorResult",
                    "summary": "Read executor evidence plus machine review",
                    "security": bearer,
                    "parameters": [{"name": "result_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": ok,
                }
            },
            "/v1/audit/verify": {
                "get": {
                    "operationId": "verifyAuditChain",
                    "summary": "Verify the local append-only audit hash chain",
                    "security": bearer,
                    "responses": ok,
                }
            },
        },
    }
