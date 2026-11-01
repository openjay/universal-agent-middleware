"""MCP adapter for the successor profile ``task-control-continuity`` (candidate, not deployed).

A separate server a host has to start on purpose, next to (never inside) ``task-control``: it keeps the
seven ``task-control`` tools exactly as they are (they come from the unchanged first-batch factory, with
the same names, schemas, descriptions and annotations) and adds four tools for the successor contract.

* ``uam_continuity_delivery_send``: a delivery inside a namespace (``owner_ref``), bound to a task
  revision and a data scope, that has to name every earlier delivery of the task whose effect is open.
* ``uam_continuity_handover``: hand the requester or the recipient role to another principal as one
  exactly bound transfer (the holder pushes, or the successor pulls).
* ``uam_continuity_context_package``: the minimal Context Package of one delivery (references and digests).
* ``uam_continuity_deliveries_for_task``: read-only locating of the caller's deliveries of one task.

Already existing delivery tools work on both delivery versions: ``uam_delivery_get`` shows a version-2
delivery with four separate facts (evidence ingestion, UAM's own read-back, business acceptance, permission
for a new effect), and gives its contract and result content only if ``dereference`` is authorised.
``uam_attempt_result`` and ``uam_attempt_end`` accept the executor's *late* receipt or stop report.

What this adapter is not: not Tasks/A2A (no ``tasks`` capability, no task handle), not an authenticated
identity (the principal is fixed when the server is created, as in ``task-control``), not an issuer, and
not a way to fence an effect. The version-1 ``uam_delivery_send`` is **closed by default** on this profile
(``LEGACY_DELIVER_DISABLED``; the tool is still listed because the seven first-batch tool definitions are
kept byte-for-byte): a version-1 delivery has no namespace, so the successor's guarantees cannot cover it.
``legacy_deliver=True`` re-opens it as an explicit, bounded legacy entry that carries none of them; the
independent ``task-control`` profile remains the home of version 1.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from anyio import to_thread
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, TextContent

from ..errors import UAMError
from ..gateway import MiddlewareGateway
from ..northbound import NorthboundBoundary
from ..task_continuity import ContinuityRefusal
from ..task_continuity_control import ContinuityControl
from ..task_control import AuthorityVerifier, TaskControlError, validate_principal
from .mcp_task_control import (
    _ERROR_TEXT_LIMIT,
    _READ,
    _WRITE_IDEMPOTENT,
    TASK_CONTROL_TOOLS,
    create_task_control_server,
)

CONTINUITY_TOOLS = (
    "uam_continuity_delivery_send",
    "uam_continuity_handover",
    "uam_continuity_context_package",
    "uam_continuity_deliveries_for_task",
)
TASK_CONTINUITY_TOOLS = TASK_CONTROL_TOOLS + CONTINUITY_TOOLS


def create_task_continuity_server(
    control: ContinuityControl,
    *,
    principal: str,
    northbound: NorthboundBoundary | None = None,
    server_name: str = "uam-task-continuity",
) -> MCPServer:
    """The seven ``task-control`` tools plus four continuity tools, all acting as ``principal`` on ``control``."""
    principal = validate_principal(principal)
    boundary = northbound if northbound is not None else NorthboundBoundary()
    mcp = create_task_control_server(control, principal=principal, northbound=boundary, server_name=server_name)

    def answer(payload: Any) -> CallToolResult:
        text = json.dumps(boundary.clean(payload), indent=2)
        return CallToolResult(content=[TextContent(type="text", text=text)], is_error=False)

    def refusal(exc: Exception) -> CallToolResult:
        if isinstance(exc, TaskControlError):
            body: dict[str, Any] = {"error": boundary.clean_text(str(exc))[:_ERROR_TEXT_LIMIT], "error_code": exc.code}
            if isinstance(exc, ContinuityRefusal):
                body["details"] = boundary.clean(exc.details)
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
    async def uam_continuity_delivery_send(
        contract_id: str,
        contract_digest: str,
        recipient: str,
        authority_ref: str,
        idempotency_key: str,
        owner_ref: str,
        business_task_ref: str,
        task_revision: int,
        data_scope_ref: str,
        declared_region: str | None = None,
        continues: list[str] | None = None,
    ) -> CallToolResult:
        """Address one READY workspace-change-v2 contract inside a namespace, bound to a task revision and a data scope.

        Like `uam_delivery_send`, but the delivery belongs to `owner_ref` (a label you declare; UAM does not verify
        who may act for an owner, the authority does), carries the task revision and an opaque `data_scope_ref`, and
        every authority question about it is a version-2 request that names who, what, which attempt and which scope.
        `declared_region` is your claim and is recorded as `DECLARED_NOT_VERIFIED`; UAM verifies no region.
        If an earlier delivery of the same task (same owner, same `business_task_ref`) has an effect that is still
        open (partial, unknown, an attempt whose executor never said it stopped), this is refused as
        `PRIOR_UNRESOLVED_EFFECT_UNLINKED` unless every such delivery is named in `continues`; the earlier delivery
        must already be finished or cancelled. Naming it hands its evidence to the authority; it does not settle it.
        The same `idempotency_key` with the same payload is the same delivery (`replayed: true`).
        """
        return await run(lambda: control.deliver_continuity(
            principal, contract_id=contract_id, contract_digest=contract_digest, recipient=recipient,
            authority_ref=authority_ref, idempotency_key=idempotency_key, owner_ref=owner_ref,
            business_task_ref=business_task_ref, task_revision=task_revision, data_scope_ref=data_scope_ref,
            declared_region=declared_region, continues=continues,
        ))

    @mcp.tool(annotations=_WRITE_IDEMPOTENT)
    async def uam_continuity_handover(
        delivery_id: str, role: str, to_principal: str, authority_ref: str,
    ) -> CallToolResult:
        """Hand the `requester` or the `recipient` role of a version-2 delivery to `to_principal`.

        The current holder pushes, or the successor pulls (for example when the previous coordinator is gone); both
        ask the authority the same exactly bound question, and `authority_ref` must be the reference that covers
        this transfer: holding an older reference carries no right. A recipient handover closes an active attempt as
        `HANDED_OVER`, which is not evidence that its executor stopped: nobody can start another attempt until that
        executor reports (late) or the owner decides, and the former executor keeps the right to report on its own
        attempt only. Someone who takes no part in the delivery gets `NOT_FOUND` for every refusal.
        """
        return await run(lambda: control.handover(
            principal, delivery_id=delivery_id, role=role, to_principal=to_principal, authority_ref=authority_ref,
        ))

    @mcp.tool(annotations=_READ)
    async def uam_continuity_context_package(delivery_id: str) -> CallToolResult:
        """The minimal Context Package of one version-2 delivery you take part in: references and digests only.

        It names the namespace, task and revision, the contract and baseline by digest, the participants and every
        handover, what each attempt did and whether its executor stopped, the consumption that is never reset, and
        `new_effect_permission` (what the record alone says; the live baseline and a fresh authority are still
        required). It holds no secret, no original conversation, no transferable grant and no contract or result
        text; holding it, or an `authority_ref`, gives no right to read content (`dereference` is authorised
        separately). Receiving it asks the authority (`context_receive`).
        """
        return await run(lambda: control.context_package(principal, delivery_id=delivery_id))

    @mcp.tool(annotations=_READ)
    async def uam_continuity_deliveries_for_task(
        owner_ref: str, business_task_ref: str, limit: int = 20,
    ) -> CallToolResult:
        """Find your version-2 deliveries of one task (bounded): state, effect, `unresolved` and `new_effect_permission`.

        A read of metadata only: it asks no authority, claims nothing and writes nothing, and it lists only
        deliveries you take part in. It is not a task list and not a task state: the task stays with its owner.
        """
        return await run(lambda: control.deliveries_for_task(
            principal, owner_ref=owner_ref, business_task_ref=business_task_ref, limit=limit,
        ))

    return mcp


def create_task_continuity_server_for_gateway(
    gateway: MiddlewareGateway,
    *,
    principal: str,
    authority: AuthorityVerifier | None = None,
    endpoint_ref: str | None = None,
    legacy_deliver: bool = False,
    server_name: str = "uam-task-continuity",
) -> MCPServer:
    """Compose the successor server over a gateway's own stores, audit log and northbound boundary.

    ``authority`` is the existing issuer/delegation contract and must declare ``request_version = 2`` to be
    asked about version-2 deliveries; leaving it out leaves the deny-all default. ``legacy_deliver`` defaults to
    closed; ``True`` is the bounded legacy entry (create and start version-1 deliveries) without the
    successor's guarantees.
    """
    control = ContinuityControl(
        gateway.state_dir,
        contracts=gateway.contracts,
        results=gateway.results_v2,
        authority=authority,
        audit=gateway.audit,
        endpoint_ref=endpoint_ref,
        legacy_deliver=legacy_deliver,
    )
    return create_task_continuity_server(
        control, principal=principal, northbound=gateway.northbound, server_name=server_name,
    )
