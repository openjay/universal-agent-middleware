from __future__ import annotations

from typing import Any


class UAMError(Exception):
    """Base error for Universal Agent Middleware.

    ``diagnostic`` is an optional machine-readable explanation (``workspace-diagnostic-v1``)
    that northbound adapters attach next to the human-readable message. It states what kind
    of refusal this is and what could change it; it never carries host paths or file content.
    """

    diagnostic: dict[str, Any] | None = None


class WorkspaceError(UAMError):
    pass


class WorkspaceUnavailableError(WorkspaceError):
    """A registered workspace cannot be served right now (for example its root is gone).

    Distinct from an unknown workspace: the registry still declares the identity,
    so callers must not substitute a different workspace for it.
    """

    def __init__(self, workspace_id: str, reason: str):
        super().__init__(f"workspace unavailable: {workspace_id} ({reason})")
        self.workspace_id = workspace_id
        self.reason = reason


class PathPolicyError(UAMError):
    pass


class ScopeAuthorityError(PathPolicyError):
    """The RootScope that governs a path does not grant the requested operation.

    Raised by the workspace Reader and Git observer for a path inside a RootScope that is nested
    under the workspace root and narrower than the scope that admitted the workspace. ``code`` is
    stable and machine-readable so a caller can tell an authority denial from a missing file.
    """

    code = "SCOPE_AUTHORITY_DENIED"

    def __init__(self, operation: str, scope_id: str, *, reason: str = "scope_governs_path"):
        """``reason`` is ``scope_governs_path`` or ``hard_linked_file`` (a file with other names)."""
        suffix = "" if reason == "scope_governs_path" else f" reason={reason}"
        super().__init__(f"denied by root scope authority: operation={operation} scope={scope_id}{suffix}")
        self.operation = operation
        self.scope_id = scope_id
        self.reason = reason


class ContractError(UAMError):
    pass


class ProtocolError(UAMError):
    pass


def error_diagnostic(exc: BaseException) -> dict[str, Any] | None:
    """The diagnostic an error carries, or None. Adapters add it only when present."""
    diagnostic = getattr(exc, "diagnostic", None)
    return diagnostic if isinstance(diagnostic, dict) and diagnostic else None


def error_body(exc: BaseException) -> dict[str, Any]:
    """JSON error payload shared by the HTTP and stdio MCP adapters."""
    body: dict[str, Any] = {"error": type(exc).__name__, "message": str(exc)}
    diagnostic = error_diagnostic(exc)
    if diagnostic is not None:
        body["diagnostic"] = diagnostic
    return body
