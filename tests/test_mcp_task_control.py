"""The task-control MCP adapter, exercised through the SDK's real client.

Two layers, both with ``mcp.Client``:

* in memory, one server per principal over one control object: the tool surface, what a client can and
  cannot say, how a refusal looks on the wire;
* over the real stdio transport with real operating-system processes (``task_control_stdio_server.py``):
  two principals, one state directory, and a reconnect that is a new process.

Both sides here are the SDK's own client and server. That shows the profile works over the standard
protocol; it does not show that Cursor, Codex or any other harness can attach, and nothing in this file
claims it does.
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import threading
import unittest
from contextlib import AsyncExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest import mock

from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.mcpserver import MCPServer

from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
from universal_agent_middleware.adapters.mcp_task_control import (
    TASK_CONTROL_TOOLS,
    create_task_control_server,
    create_task_control_server_for_gateway,
)
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.task_control import TaskControl, TaskControlError

from coordination_fixtures import contract_v2, document_result
from directory_fixtures import PLAIN_ID, WorldTestCase
from synthetic_fixtures import SyntheticRegistryBundle
from test_task_control import EXECUTOR, NEW_DOC, NEW_TEXT, REQUESTER, STRANGER, FakeClock, ScriptedAuthority, snapshot

LAUNCHER = Path(__file__).resolve().parent / "task_control_stdio_server.py"

EXPECTED_ARGUMENTS = {
    "uam_delivery_send": {
        "contract_id", "contract_digest", "recipient", "authority_ref", "idempotency_key",
        "business_task_ref", "task_revision",
    },
    "uam_delivery_inbox": {"limit"},
    "uam_delivery_get": {"delivery_id", "observe"},
    "uam_delivery_cancel": {"delivery_id", "reason"},
    "uam_attempt_start": {"delivery_id", "lease_seconds"},
    "uam_attempt_result": {"delivery_id", "attempt_ref", "fence", "result"},
    "uam_attempt_end": {"delivery_id", "attempt_ref", "fence", "outcome", "note"},
}
READ_TOOLS = {"uam_delivery_inbox", "uam_delivery_get"}
# Names a client could use to say who it is. None may be a tool argument: the principal is fixed at launch.
IDENTITY_ARGUMENTS = {"principal", "requester", "actor", "identity", "user", "viewer", "submitted_by", "as_principal"}


@dataclass(frozen=True)
class Answer:
    is_error: bool
    body: dict[str, Any]
    text: str


@dataclass(frozen=True)
class Surface:
    tools: dict[str, Any]
    capabilities: Any
    instructions: str | None
    protocol_version: str


def answer_of(result: Any) -> Answer:
    text = result.content[0].text
    return Answer(bool(result.is_error), json.loads(text), text)


async def invoke(client: Client, tool: str, **arguments: Any) -> Answer:
    return answer_of(await client.call_tool(tool, arguments))


async def inspect_surface(server: MCPServer) -> Surface:
    async with Client(server) as client:
        listing = await client.list_tools()
        return Surface(
            tools={tool.name: tool for tool in listing.tools},
            capabilities=client.server_capabilities,
            instructions=client.instructions,
            protocol_version=client.protocol_version,
        )


class AdapterWorld(WorldTestCase):
    """One gateway, one control object, one in-memory server per principal."""

    def setUp(self) -> None:
        super().setUp()
        self.gw = self.world.gateway()
        self.authority = ScriptedAuthority()
        self.control = TaskControl(
            self.gw.state_dir, contracts=self.gw.contracts, results=self.gw.results_v2,
            authority=self.authority, clock=FakeClock(), audit=self.gw.audit,
        )
        self.requester = self.server_for(REQUESTER)
        self.executor = self.server_for(EXECUTOR)
        self.stranger = self.server_for(STRANGER)
        self.contract = self.gw.create_contract(
            contract_v2("mcp-task", PLAIN_ID, authoritative=["README.md"], allowed=[NEW_DOC]),
        )

    def server_for(self, principal: str) -> MCPServer:
        return create_task_control_server(self.control, principal=principal, northbound=self.gw.northbound)

    def call(self, server: MCPServer, tool: str, **arguments: Any) -> Answer:
        async def once() -> Answer:
            async with Client(server) as client:  # a new connection per call: nothing rides on a session
                return await invoke(client, tool, **arguments)

        return asyncio.run(once())

    def send(self, **overrides: Any) -> Answer:
        arguments: dict[str, Any] = {
            "contract_id": self.contract["contract_id"], "contract_digest": self.contract["contract_digest"],
            "recipient": EXECUTOR, "authority_ref": "grant-0001", "idempotency_key": "mcp-key-1",
            "business_task_ref": "task-42", "task_revision": 3,
        }
        arguments.update(overrides)
        return self.call(self.requester, "uam_delivery_send", **arguments)

    def delivered(self) -> str:
        sent = self.send()
        self.assertFalse(sent.is_error, sent.text)
        return sent.body["delivery_id"]

    def started(self) -> tuple[str, dict[str, Any]]:
        delivery_id = self.delivered()
        began = self.call(self.executor, "uam_attempt_start", delivery_id=delivery_id)
        self.assertFalse(began.is_error, began.text)
        return delivery_id, began.body["attempts"][-1]

    def result_payload(self, delivery_id: str, attempt: dict[str, Any], **overrides: Any) -> dict[str, Any]:
        fetched = self.call(self.executor, "uam_delivery_get", delivery_id=delivery_id)
        payload = document_result(
            fetched.body["contract"], "mcp-result-1", {NEW_DOC: NEW_TEXT},
            attempt_ref=attempt["attempt_ref"], executor=EXECUTOR, business_task_ref="task-42", task_revision=3,
        )
        payload.update(overrides)
        return payload

    def write_document(self, text: str = NEW_TEXT) -> None:
        (self.world.plain / NEW_DOC).write_text(text, encoding="utf-8")

    def control_audit_outcomes(self) -> list[tuple[str, str]]:
        lines = (self.gw.state_dir / "audit.jsonl").read_text("utf-8").splitlines()
        entries = [json.loads(line) for line in lines if line.strip()]
        return [(entry["action"], entry["outcome"]) for entry in entries if entry["action"].startswith("task_control.")]

    def control_audit_actions(self) -> list[str]:
        return [action for action, _ in self.control_audit_outcomes()]


class TestSurface(AdapterWorld):
    def test_exactly_seven_business_tools_are_exposed(self) -> None:
        surface = asyncio.run(inspect_surface(self.requester))
        self.assertEqual(set(surface.tools), set(TASK_CONTROL_TOOLS))
        self.assertEqual(len(surface.tools), 7)

    def test_each_tool_takes_exactly_the_documented_arguments(self) -> None:
        surface = asyncio.run(inspect_surface(self.requester))
        for name, expected in EXPECTED_ARGUMENTS.items():
            with self.subTest(name):
                self.assertEqual(set(surface.tools[name].input_schema["properties"]), expected)

    def test_no_tool_lets_a_client_name_the_acting_principal(self) -> None:
        surface = asyncio.run(inspect_surface(self.requester))
        for name, tool in surface.tools.items():
            with self.subTest(name):
                self.assertFalse(IDENTITY_ARGUMENTS & set(tool.input_schema["properties"]))

    def test_the_principal_is_fixed_when_the_server_is_created(self) -> None:
        mine = self.send()
        self.assertEqual((mine.body["requester"], mine.body["viewer_role"]), (REQUESTER, "requester"))
        other = self.gw.create_contract(
            contract_v2("mcp-task-2", PLAIN_ID, authoritative=["README.md"], allowed=["notes/two.md"]),
        )
        # The identical call through the executor's server is made as the executor: nothing in the call can change that.
        theirs = self.call(
            self.executor, "uam_delivery_send", contract_id="mcp-task-2", contract_digest=other["contract_digest"],
            recipient=STRANGER, authority_ref="grant-0002", idempotency_key="mcp-key-2",
        )
        self.assertFalse(theirs.is_error, theirs.text)
        self.assertEqual((theirs.body["requester"], theirs.body["viewer_role"]), (EXECUTOR, "requester"))
        self.assertEqual([request.principal for request in self.authority.asked("deliver")], [REQUESTER, EXECUTOR])

    def test_annotations_say_which_tools_only_read(self) -> None:
        surface = asyncio.run(inspect_surface(self.requester))
        for name, tool in surface.tools.items():
            annotations = tool.annotations
            with self.subTest(name):
                self.assertIs(annotations.read_only_hint, name in READ_TOOLS)
                self.assertIs(annotations.destructive_hint, False)
                self.assertIs(annotations.open_world_hint, False)

    def test_no_tasks_capability_extension_or_handle_is_advertised_or_returned(self) -> None:
        surface = asyncio.run(inspect_surface(self.requester))
        self.assertIsNone(surface.capabilities.tasks)
        self.assertIsNone(surface.capabilities.extensions)
        self.assertFalse([name for name in surface.tools if name.startswith("tasks")])
        sent = self.send()
        self.assertFalse({"task", "taskId", "task_id", "handle"} & set(sent.body))

    def test_the_server_says_who_it_acts_as_and_keeps_the_planes_apart(self) -> None:
        surface = asyncio.run(inspect_surface(self.executor))
        self.assertIn(f"principal '{EXECUTOR}'", surface.instructions)
        for phrase in ("claims nothing", "Business acceptance is never decided here", "intent only"):
            self.assertIn(phrase, surface.instructions)

    def test_the_deployed_read_only_profile_is_neither_widened_nor_shared(self) -> None:
        bundle = SyntheticRegistryBundle()
        self.addCleanup(bundle.cleanup)
        state = tempfile.TemporaryDirectory(prefix="uam-ro-state-")
        self.addCleanup(state.cleanup)
        read_only = create_session_read_server(registry_path=str(bundle.registry_path), state_dir=state.name)
        read_only_surface = asyncio.run(inspect_surface(read_only))
        task_surface = asyncio.run(inspect_surface(self.requester))
        self.assertEqual(len(read_only_surface.tools), 20)
        self.assertIn("uam_file_digest", read_only_surface.tools)
        self.assertFalse(set(read_only_surface.tools) & set(task_surface.tools))
        self.assertFalse([name for name in read_only_surface.tools if name.startswith(("uam_delivery", "uam_attempt"))])
        self.assertFalse([name for name in task_surface.tools if name in read_only_surface.tools])

    def test_an_invalid_principal_cannot_start_a_server(self) -> None:
        for bad in ("", "has space", "x" * 200, "semi;colon"):
            with self.subTest(bad):
                with self.assertRaises(TaskControlError) as raised:
                    create_task_control_server(self.control, principal=bad)
                self.assertEqual(raised.exception.code, "INVALID_ARGUMENT")


class TestExchange(AdapterWorld):
    def test_a_delivery_is_addressed_to_its_recipient_only(self) -> None:
        delivery_id = self.delivered()
        inbox = self.call(self.executor, "uam_delivery_inbox")
        self.assertEqual([item["delivery_id"] for item in inbox.body["items"]], [delivery_id])
        self.assertIs(inbox.body["claims_nothing"], True)
        self.assertEqual(self.call(self.requester, "uam_delivery_inbox").body["items"], [])
        self.assertEqual(self.call(self.stranger, "uam_delivery_inbox").body["items"], [])
        hidden = self.call(self.stranger, "uam_delivery_get", delivery_id=delivery_id)
        self.assertTrue(hidden.is_error)
        self.assertEqual(hidden.body["error_code"], "NOT_FOUND")

    def test_the_same_send_is_the_same_delivery(self) -> None:
        first = self.send()
        again = self.send()
        self.assertEqual((again.body["delivery_id"], again.body["replayed"]), (first.body["delivery_id"], True))
        self.assertEqual(len(self.authority.asked("deliver")), 1)

    def test_reading_writes_nothing(self) -> None:
        delivery_id = self.delivered()
        before = snapshot(self.control.root)
        actions_before = self.control_audit_actions()
        self.call(self.executor, "uam_delivery_inbox")
        self.call(self.executor, "uam_delivery_get", delivery_id=delivery_id)
        self.call(self.executor, "uam_delivery_get", delivery_id=delivery_id, observe=True)
        self.call(self.requester, "uam_delivery_get", delivery_id=delivery_id)
        self.assertEqual(snapshot(self.control.root), before)
        # The gateway audits its own workspace reads (observe=True); task control audits only its effects.
        self.assertEqual(self.control_audit_actions(), actions_before)

    def test_observe_reports_the_baseline_without_claiming(self) -> None:
        delivery_id = self.delivered()
        fetched = self.call(self.executor, "uam_delivery_get", delivery_id=delivery_id, observe=True)
        self.assertEqual(fetched.body["baseline_observation"]["state"], "UNCHANGED")
        self.assertEqual((fetched.body["state"], fetched.body["attempts"]), ("DELIVERED", []))

    def test_roles_are_enforced_on_the_wire(self) -> None:
        delivery_id = self.delivered()
        for server, tool, arguments in (
            (self.requester, "uam_attempt_start", {"delivery_id": delivery_id}),
            (self.stranger, "uam_attempt_start", {"delivery_id": delivery_id}),
            (self.executor, "uam_delivery_cancel", {"delivery_id": delivery_id}),
        ):
            with self.subTest(tool):
                refused = self.call(server, tool, **arguments)
                self.assertTrue(refused.is_error)
                self.assertIn(refused.body["error_code"], {"WRONG_ROLE", "NOT_FOUND"})
        self.assertEqual(self.call(self.executor, "uam_delivery_get", delivery_id=delivery_id).body["attempts"], [])

    def test_a_full_delivery_survives_reconnects_and_never_repeats_the_effect(self) -> None:
        delivery_id, attempt = self.started()
        self.assertEqual((attempt["fence"], attempt["state"]), (1, "ACTIVE"))
        again = self.call(self.executor, "uam_attempt_start", delivery_id=delivery_id)
        self.assertEqual(again.body["error_code"], "ATTEMPT_ACTIVE")

        self.write_document()
        payload = self.result_payload(delivery_id, attempt)
        recorded = self.call(
            self.executor, "uam_attempt_result", delivery_id=delivery_id, attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], result=payload,
        )
        self.assertFalse(recorded.is_error, recorded.text)
        self.assertEqual(recorded.body["delivery"]["state"], "RESULT_RECORDED")
        self.assertEqual(recorded.body["result_record"]["review"]["state"], "PASS")
        self.assertEqual(recorded.body["delivery"]["business_acceptance"], "NOT_DETERMINED_BY_UAM")
        self.assertIs(recorded.body["replayed"], False)

        lost_ack = self.call(
            self.executor, "uam_attempt_result", delivery_id=delivery_id, attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], result=payload,
        )
        self.assertIs(lost_ack.body["replayed"], True)

        # Reconnect: every call above already used a new connection; the state is the files, not the session.
        for server in (self.executor, self.requester):
            seen = self.call(server, "uam_delivery_get", delivery_id=delivery_id)
            self.assertEqual(seen.body["state"], "RESULT_RECORDED")
            self.assertEqual(seen.body["result"]["result_id"], "mcp-result-1")
        restarted = self.call(self.executor, "uam_attempt_start", delivery_id=delivery_id)
        self.assertEqual(restarted.body["error_code"], "RESULT_ALREADY_RECORDED")
        self.assertEqual((self.world.plain / NEW_DOC).read_text(encoding="utf-8"), NEW_TEXT)

        late = self.call(self.requester, "uam_delivery_cancel", delivery_id=delivery_id)
        self.assertEqual(late.body["outcome"], "TOO_LATE_RESULT_RECORDED")
        self.assertEqual(late.body["rollback"], "NOT_PERFORMED_BY_UAM")
        self.assertEqual((self.world.plain / NEW_DOC).read_text(encoding="utf-8"), NEW_TEXT)

    def test_a_result_that_names_another_executor_is_refused(self) -> None:
        delivery_id, attempt = self.started()
        self.write_document()
        forged = self.result_payload(delivery_id, attempt, executor=REQUESTER)
        refused = self.call(
            self.executor, "uam_attempt_result", delivery_id=delivery_id, attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], result=forged,
        )
        self.assertTrue(refused.is_error)
        self.assertEqual(refused.body["error_code"], "RESULT_BINDING_MISMATCH")
        self.assertEqual(self.call(self.executor, "uam_delivery_get", delivery_id=delivery_id).body["state"], "ATTEMPT_ACTIVE")

    def test_cancel_is_intent_and_never_a_confirmed_stop(self) -> None:
        delivery_id, _ = self.started()
        cancelled = self.call(self.requester, "uam_delivery_cancel", delivery_id=delivery_id, reason="no longer needed")
        self.assertFalse(cancelled.is_error, cancelled.text)
        self.assertEqual(cancelled.body["outcome"], "CANCEL_INTENT_RECORDED_ATTEMPT_ACTIVE")
        self.assertEqual(cancelled.body["intent"], "RECORDED")
        self.assertEqual(cancelled.body["stop"], "ATTEMPT_ACTIVE_NOT_CONFIRMED")
        self.assertEqual(cancelled.body["rollback"], "NOT_PERFORMED_BY_UAM")
        self.assertEqual(cancelled.body["delivery"]["state"], "ATTEMPT_ACTIVE")

    def test_the_receivers_report_does_not_stand_for_what_uam_observed(self) -> None:
        delivery_id, attempt = self.started()
        self.write_document()
        ended = self.call(
            self.executor, "uam_attempt_end", delivery_id=delivery_id, attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], outcome="FAILED_BEFORE_EFFECT", note="gave up",
        )
        self.assertFalse(ended.is_error, ended.text)
        self.assertEqual(ended.body["effect"], "PARTIAL_EFFECT_OBSERVED")
        blocked = self.call(self.executor, "uam_attempt_start", delivery_id=delivery_id)
        self.assertEqual(blocked.body["error_code"], "BASELINE_CHANGED")


class TestWire(AdapterWorld):
    def test_a_refusal_is_an_error_result_with_a_stable_code(self) -> None:
        refused = self.send(contract_digest="0" * 64)
        self.assertTrue(refused.is_error)
        self.assertEqual(set(refused.body), {"error", "error_code"})
        self.assertEqual(refused.body["error_code"], "CONTRACT_MISMATCH")
        self.assertEqual(self.authority.asked("deliver"), [])

    def test_an_unexpected_failure_says_only_that_it_was_internal(self) -> None:
        boom = RuntimeError("exploded near /Users/private/secret/path with token abc123")
        with mock.patch.object(self.control, "inbox", side_effect=boom):
            result = self.call(self.executor, "uam_delivery_inbox")
        self.assertTrue(result.is_error)
        self.assertEqual(result.body, {"error": "internal error", "error_code": "INTERNAL"})
        for leaked in ("exploded", "private", "abc123"):
            self.assertNotIn(leaked, result.text)

    def test_blocking_work_runs_off_the_event_loop_thread(self) -> None:
        seen: dict[str, int] = {}
        original = self.control.inbox

        def spy(principal: str, **kwargs: Any) -> dict[str, Any]:
            seen["worker"] = threading.get_ident()
            return original(principal, **kwargs)

        async def once() -> int:
            async with Client(self.executor) as client:
                await invoke(client, "uam_delivery_inbox")
            return threading.get_ident()

        with mock.patch.object(self.control, "inbox", side_effect=spy):
            loop_thread = asyncio.run(once())
        self.assertNotEqual(seen["worker"], loop_thread)

    def test_no_host_path_leaves_in_an_answer_while_the_stored_contract_keeps_its_text(self) -> None:
        host_path = str(self.world.plain)
        contract = self.gw.create_contract(contract_v2(
            "mcp-path-task", PLAIN_ID, authoritative=["README.md"], allowed=["notes/other.md"],
            objective=f"Write the note that explains {host_path}/README.md",
        ))
        sent = self.send(contract_id="mcp-path-task", contract_digest=contract["contract_digest"], idempotency_key="path-key")
        fetched = self.call(self.executor, "uam_delivery_get", delivery_id=sent.body["delivery_id"])
        self.assertNotIn(str(self.world.root), fetched.text)
        self.assertNotIn(host_path, fetched.text)
        self.assertIn(host_path, self.gw.contracts.get_record("mcp-path-task")["objective"])

    def test_without_a_wired_authority_nothing_is_delivered(self) -> None:
        server = create_task_control_server_for_gateway(self.gw, principal=REQUESTER)
        refused = self.call(
            server, "uam_delivery_send", contract_id=self.contract["contract_id"],
            contract_digest=self.contract["contract_digest"], recipient=EXECUTOR, authority_ref="grant-0001",
            idempotency_key="deny-key",
        )
        self.assertTrue(refused.is_error)
        self.assertEqual(refused.body["error_code"], "AUTHORITY_DENIED")
        self.assertFalse(list((self.gw.state_dir / "task-control" / "deliveries").glob("dlv-*.json")))
        self.assertEqual(self.control_audit_outcomes(), [("task_control.deliver", "DENY")])

    def test_the_gateway_composition_shares_the_gateways_stores_and_audit_log(self) -> None:
        server = create_task_control_server_for_gateway(self.gw, principal=REQUESTER, authority=self.authority)
        sent = self.call(
            server, "uam_delivery_send", contract_id=self.contract["contract_id"],
            contract_digest=self.contract["contract_digest"], recipient=EXECUTOR, authority_ref="grant-0001",
            idempotency_key="audit-key",
        )
        self.assertFalse(sent.is_error, sent.text)
        self.assertEqual(self.control_audit_outcomes(), [("task_control.deliver", "PASS")])
        self.assertNotIn("grant-0001", (self.gw.state_dir / "audit.jsonl").read_text("utf-8"))
        chain = self.gw.audit.verify()
        self.assertTrue(chain["valid"], chain)
        self.assertEqual(self.authority.asked("deliver")[0].authority_ref, "grant-0001")


class StdioProcessTests(WorldTestCase):
    """Real processes, real stdio framing, one state directory: concurrency and reconnect are not simulated."""

    def parameters(self, principal: str, authority: str = "allow-all") -> StdioServerParameters:
        return StdioServerParameters(command=sys.executable, args=[
            str(LAUNCHER), "--registry", str(self.world.registry_path), "--state-dir", str(self.world.state),
            "--principal", principal, "--authority", authority,
        ])

    def prepare(self) -> dict[str, Any]:
        self.world.write_registry()
        self.world.write_scope_file()
        gateway = MiddlewareGateway(str(self.world.registry_path), str(self.world.state))
        return gateway.create_contract(
            contract_v2("stdio-task", PLAIN_ID, authoritative=["README.md"], allowed=[NEW_DOC]),
        )

    def test_two_processes_share_one_state_and_a_new_process_resumes_it(self) -> None:
        contract = self.prepare()

        async def scenario() -> dict[str, Any]:
            seen: dict[str, Any] = {}
            async with AsyncExitStack() as stack:
                requester = await stack.enter_async_context(Client(stdio_client(self.parameters(REQUESTER))))
                executor = await stack.enter_async_context(Client(stdio_client(self.parameters(EXECUTOR))))
                seen["tasks_capability"] = (requester.server_capabilities.tasks, executor.server_capabilities.tasks)
                seen["protocol_version"] = executor.protocol_version
                sent = await invoke(
                    requester, "uam_delivery_send", contract_id=contract["contract_id"],
                    contract_digest=contract["contract_digest"], recipient=EXECUTOR, authority_ref="grant-0001",
                    idempotency_key="stdio-key", business_task_ref="task-77", task_revision=1,
                )
                seen["sent"] = sent
                delivery_id = sent.body["delivery_id"]
                seen["inbox"] = await invoke(executor, "uam_delivery_inbox")
                seen["requester_inbox"] = await invoke(requester, "uam_delivery_inbox")
                began = await invoke(executor, "uam_attempt_start", delivery_id=delivery_id)
                seen["started"] = began
                attempt = began.body["attempts"][-1]
                seen["requester_view"] = await invoke(requester, "uam_delivery_get", delivery_id=delivery_id)
                (self.world.plain / NEW_DOC).write_text(NEW_TEXT, encoding="utf-8")
                payload = document_result(
                    seen["requester_view"].body["contract"], "stdio-result-1", {NEW_DOC: NEW_TEXT},
                    attempt_ref=attempt["attempt_ref"], executor=EXECUTOR, business_task_ref="task-77", task_revision=1,
                )
                seen["recorded"] = await invoke(
                    executor, "uam_attempt_result", delivery_id=delivery_id, attempt_ref=attempt["attempt_ref"],
                    fence=attempt["fence"], result=payload,
                )
            # Both processes are gone. A brand-new process for the same principal reads what they left.
            async with Client(stdio_client(self.parameters(EXECUTOR))) as resumed:
                seen["resumed_view"] = await invoke(resumed, "uam_delivery_get", delivery_id=delivery_id)
                seen["restart"] = await invoke(resumed, "uam_attempt_start", delivery_id=delivery_id)
                seen["replay"] = await invoke(
                    resumed, "uam_attempt_result", delivery_id=delivery_id, attempt_ref=attempt["attempt_ref"],
                    fence=attempt["fence"], result=payload,
                )
            return seen

        seen = asyncio.run(scenario())
        self.assertEqual(seen["tasks_capability"], (None, None))
        self.assertEqual(seen["sent"].body["state"], "DELIVERED", seen["sent"].text)
        self.assertEqual([item["delivery_id"] for item in seen["inbox"].body["items"]], [seen["sent"].body["delivery_id"]])
        self.assertEqual(seen["requester_inbox"].body["items"], [])
        self.assertEqual(seen["started"].body["state"], "ATTEMPT_ACTIVE", seen["started"].text)
        # The requester's process sees what the executor's process did: one state, two processes.
        self.assertEqual(seen["requester_view"].body["viewer_role"], "requester")
        self.assertEqual(seen["requester_view"].body["attempts"][-1]["state"], "ACTIVE")
        self.assertEqual(seen["recorded"].body["result_record"]["review"]["state"], "PASS", seen["recorded"].text)
        self.assertEqual(seen["resumed_view"].body["state"], "RESULT_RECORDED")
        self.assertEqual(seen["restart"].body["error_code"], "RESULT_ALREADY_RECORDED")
        self.assertIs(seen["replay"].body["replayed"], True)
        self.assertEqual((self.world.plain / NEW_DOC).read_text(encoding="utf-8"), NEW_TEXT)

    def test_two_processes_of_one_principal_cannot_both_claim_the_delivery(self) -> None:
        contract = self.prepare()

        async def scenario() -> list[Answer]:
            async with AsyncExitStack() as stack:
                requester = await stack.enter_async_context(Client(stdio_client(self.parameters(REQUESTER))))
                first = await stack.enter_async_context(Client(stdio_client(self.parameters(EXECUTOR))))
                second = await stack.enter_async_context(Client(stdio_client(self.parameters(EXECUTOR))))
                sent = await invoke(
                    requester, "uam_delivery_send", contract_id=contract["contract_id"],
                    contract_digest=contract["contract_digest"], recipient=EXECUTOR, authority_ref="grant-0001",
                    idempotency_key="race-key",
                )
                delivery_id = sent.body["delivery_id"]
                return list(await asyncio.gather(
                    invoke(first, "uam_attempt_start", delivery_id=delivery_id),
                    invoke(second, "uam_attempt_start", delivery_id=delivery_id),
                ))

        answers = asyncio.run(scenario())
        winners = [answer for answer in answers if not answer.is_error]
        losers = [answer for answer in answers if answer.is_error]
        self.assertEqual((len(winners), len(losers)), (1, 1), [answer.text for answer in answers])
        self.assertEqual(losers[0].body["error_code"], "ATTEMPT_ACTIVE")
        self.assertEqual(winners[0].body["attempts"][-1]["fence"], 1)

    def test_a_server_started_without_an_authority_denies_every_effect(self) -> None:
        contract = self.prepare()

        async def scenario() -> Answer:
            async with Client(stdio_client(self.parameters(REQUESTER, authority="deny"))) as requester:
                return await invoke(
                    requester, "uam_delivery_send", contract_id=contract["contract_id"],
                    contract_digest=contract["contract_digest"], recipient=EXECUTOR, authority_ref="grant-0001",
                    idempotency_key="deny-key",
                )

        refused = asyncio.run(scenario())
        self.assertTrue(refused.is_error)
        self.assertEqual(refused.body["error_code"], "AUTHORITY_DENIED")


if __name__ == "__main__":
    unittest.main()
