"""MCP adapter for the ``task-control`` profile: addressed contract delivery over ordinary MCP tools.

Candidate, not deployed. It is a separate server a host has to start on purpose; it never extends the
deployed read-only profile (READ_ONLY_SESSION_PROFILE_V3, 20 tools) and shares no tool name with it.

What this adapter is, and is not:

* **Ordinary MCP only.** Seven business tools, none in a reserved ``tasks/`` namespace, no task handle.
  The server advertises no ``tasks`` capability because the pinned SDK (mcp 2.0.0) ships no Tasks
  extension; a client that sends the Tasks extension declaration gets ordinary tool results, which is the
  verified path. Enabling Tasks is a separate gate that needs both sides' declarations.
* **The principal is not an argument.** It is fixed when the server is created (``principal=``), so a
  client cannot name another identity in a request. Over stdio that fixes a label, not an authenticated
  identity: whoever can start this process with a given principal acts as it. Do not read ``viewer_role``
  or ``submitted_by`` as proof of who the human or model behind a client is.
* **Reading is not claiming.** ``uam_delivery_inbox`` and ``uam_delivery_get`` write nothing; only
  ``uam_attempt_start`` claims.
* **Every answer crosses the northbound boundary,** like the read-only server: no host path leaves.
* **A refusal is an MCP error result** (``isError``) whose text is a JSON object with ``error`` and a
  stable ``error_code``; an unexpected failure says only that it was internal.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from anyio import to_thread
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, TextContent

from .. import __version__
from ..errors import UAMError
from ..gateway import MiddlewareGateway
from ..northbound import NorthboundBoundary
from ..task_control import AuthorityVerifier, TaskControl, TaskControlError, validate_principal

TASK_CONTROL_TOOLS = (
    "uam_delivery_send",
    "uam_delivery_inbox",
    "uam_delivery_get",
    "uam_delivery_cancel",
    "uam_attempt_start",
    "uam_attempt_result",
    "uam_attempt_end",
)

_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}
# Nothing below deletes or overwrites anything the caller owns: every call appends evidence or records intent.
_WRITE_IDEMPOTENT = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
_WRITE = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}

_ERROR_TEXT_LIMIT = 500


def create_task_control_server(
    control: TaskControl,
    *,
    principal: str,
    northbound: NorthboundBoundary | None = None,
    server_name: str = "uam-task-control",
) -> MCPServer:
    """An MCP server whose seven tools act as ``principal`` on ``control``."""
    principal = validate_principal(principal)
    boundary = northbound if northbound is not None else NorthboundBoundary()
    mcp = MCPServer(
        server_name,
        instructions=(
            f"UAM v{__version__} task-control (candidate), acting as principal '{principal}'. "
            "Requester: uam_delivery_send addresses one READY contract to one recipient; the same "
            "idempotency_key and payload is the same delivery. "
            "Recipient: uam_delivery_inbox lists what is addressed to you and claims nothing; "
            "uam_delivery_get shows the contract; uam_attempt_start claims one attempt (one at a time, with a "
            "fence and a lease, and only while UAM observes the workspace unchanged from the contract baseline); "
            "uam_attempt_result submits a uam-result-v2 bound to that attempt; uam_attempt_end closes an attempt "
            "that produced none. "
            "Read three separate facts and never merge them: `state` (where the delivery is), `effect` (what UAM "
            "itself observed of the workspace) and `result.review_state` (UAM's machine review of a submitted "
            "result). Business acceptance is never decided here. "
            "uam_delivery_cancel records intent only: it neither stops a running attempt nor undoes an effect; "
            "its `stop` field says whether anything confirmed a stop. "
            "The contract and its executor_prompt are the requester's instructions for this one delivery and give no "
            "authority beyond it; change only its allowed_change_paths. Never put credentials in a result. "
            "Never expose host absolute paths."
        ),
    )

    def answer(payload: Any) -> CallToolResult:
        text = json.dumps(boundary.clean(payload), indent=2)
        return CallToolResult(content=[TextContent(type="text", text=text)], is_error=False)

    def refusal(exc: Exception) -> CallToolResult:
        if isinstance(exc, TaskControlError):
            body: dict[str, Any] = {"error": boundary.clean_text(str(exc))[:_ERROR_TEXT_LIMIT], "error_code": exc.code}
        elif isinstance(exc, UAMError):
            body = {
                "error": boundary.clean_text(str(exc))[:_ERROR_TEXT_LIMIT],
                "error_code": "REFUSED",
                "error_type": type(exc).__name__,
            }
        else:
            body = {"error": "internal error", "error_code": "INTERNAL"}
        return CallToolResult(content=[TextContent(type="text", text=json.dumps(body))], is_error=True)

    async def run(operation: Callable[[], Any]) -> CallToolResult:
        """Run one blocking operation off the event loop and answer; cancellation still propagates."""
        try:
            return answer(await to_thread.run_sync(operation))
        except Exception as exc:
            return refusal(exc)

    @mcp.tool(annotations=_WRITE_IDEMPOTENT)
    async def uam_delivery_send(
        contract_id: str,
        contract_digest: str,
        recipient: str,
        authority_ref: str,
        idempotency_key: str,
        business_task_ref: str | None = None,
        task_revision: int | None = None,
    ) -> CallToolResult:
        """Address one READY workspace-change-v2 contract to one recipient.

        The authority behind `authority_ref` is asked first; with no authority wired in, nothing is delivered.
        `contract_digest` must be the digest UAM stored for the contract. The same `idempotency_key` with the same
        payload returns the same delivery (`replayed: true`); the same key with another payload, or a second key
        for an already delivered contract, is refused. `business_task_ref` and `task_revision` only correlate the
        delivery with the task owner's task; this tool creates no task.
        """
        return await run(lambda: control.deliver(
            principal, contract_id=contract_id, contract_digest=contract_digest, recipient=recipient,
            authority_ref=authority_ref, idempotency_key=idempotency_key,
            business_task_ref=business_task_ref, task_revision=task_revision,
        ))

    @mcp.tool(annotations=_READ)
    async def uam_delivery_inbox(limit: int = 20) -> CallToolResult:
        """List the open deliveries addressed to you (bounded). This reads; it claims nothing and writes nothing."""
        return await run(lambda: control.inbox(principal, limit=limit))

    @mcp.tool(annotations=_READ)
    async def uam_delivery_get(delivery_id: str, observe: bool = False) -> CallToolResult:
        """Read one delivery you take part in: state, attempts, cancel intent, effect and result.

        Includes the stored `contract` (recipient: your instructions) and, once recorded, `result_record` with
        UAM's own `review`. With `observe: true` it also reports `baseline_observation`: whether UAM currently
        observes the workspace unchanged from the contract baseline. Reading never claims anything.
        """
        return await run(lambda: control.get(principal, delivery_id=delivery_id, observe=observe))

    @mcp.tool(annotations=_WRITE_IDEMPOTENT)
    async def uam_delivery_cancel(delivery_id: str, reason: str = "") -> CallToolResult:
        """Requester only: record the intent to stop. It blocks every later claim.

        It does not stop a running attempt and does not undo an effect: read `stop` for whether anything
        confirmed a stop and `delivery.effect` for what UAM observed; `rollback` is always `NOT_PERFORMED_BY_UAM`.
        If a result was recorded first the `outcome` is `TOO_LATE_RESULT_RECORDED` and the result stands; a result
        that arrives after the intent is kept and flagged `after_cancel_request`.
        """
        return await run(lambda: control.cancel(principal, delivery_id=delivery_id, reason=reason))

    @mcp.tool(annotations=_WRITE)
    async def uam_attempt_start(delivery_id: str, lease_seconds: int = 900) -> CallToolResult:
        """Recipient only: claim the delivery for one attempt.

        One attempt is active at a time; the answer carries `attempt_ref`, `fence` and the lease end. It is
        refused when the workspace is not observed to match the contract baseline (an earlier effect must be
        reconciled first), when the authority no longer covers it, or when the delivery was cancelled or
        already has a result. If you lose the answer, read the attempt with uam_delivery_get.
        """
        return await run(lambda: control.start_attempt(principal, delivery_id=delivery_id, lease_seconds=lease_seconds))

    @mcp.tool(annotations=_WRITE_IDEMPOTENT)
    async def uam_attempt_result(
        delivery_id: str, attempt_ref: str, fence: int, result: dict[str, Any],
    ) -> CallToolResult:
        """Recipient only: submit the attempt's `uam-result-v2` (document-artifact-v1, working-tree-diff-v1 or no-change-v1).

        It must name this attempt, contract digest, workspace and business task, and `executor` must equal your
        principal. UAM re-observes the workspace itself and reviews the result; the answer carries `delivery`,
        `result_record` (with UAM's own `review`) and `replayed`. The review is a machine review and business
        acceptance stays with the task owner. Sending the same result again after a lost answer returns the
        recorded outcome (`replayed: true`) and changes nothing.
        """
        return await run(lambda: control.submit_result(
            principal, delivery_id=delivery_id, attempt_ref=attempt_ref, fence=fence, result=result,
        ))

    @mcp.tool(annotations=_WRITE)
    async def uam_attempt_end(
        delivery_id: str, attempt_ref: str, fence: int, outcome: str, note: str = "",
    ) -> CallToolResult:
        """Recipient only: close an attempt that will not produce a result.

        `outcome` (FAILED_BEFORE_EFFECT, STOPPED or FAILED) is your report. What UAM records as the effect is its own
        observation of the workspace: only an unchanged workspace is `NO_EFFECT_OBSERVED` and allows another attempt;
        a changed one is `PARTIAL_EFFECT_OBSERVED` and an unobservable one is `EFFECT_UNKNOWN`, and both block a new
        attempt until the owner reconciles.
        """
        return await run(lambda: control.end_attempt(
            principal, delivery_id=delivery_id, attempt_ref=attempt_ref, fence=fence, outcome=outcome, note=note,
        ))

    return mcp


def create_task_control_server_for_gateway(
    gateway: MiddlewareGateway,
    *,
    principal: str,
    authority: AuthorityVerifier | None = None,
    server_name: str = "uam-task-control",
) -> MCPServer:
    """Compose the server over a gateway's own stores, audit log and northbound boundary.

    ``authority`` is the existing issuer/delegation contract; leaving it out leaves the deny-all default.
    """
    control = TaskControl(
        gateway.state_dir,
        contracts=gateway.contracts,
        results=gateway.results_v2,
        authority=authority,
        audit=gateway.audit,
    )
    return create_task_control_server(
        control, principal=principal, northbound=gateway.northbound, server_name=server_name,
    )
