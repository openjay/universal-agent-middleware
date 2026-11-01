"""The successor MCP profile ``task-continuity``, exercised through the SDK's real client.

Three layers, all with ``mcp.Client``:

* the surface: the seven ``task-control`` tools must reach a client exactly as the first batch shipped them
  (compared with digests frozen from the pristine first-batch tree), plus four new tools and nothing else;
* in memory, one server per principal over one control object: what the new tools say and refuse on the wire;
* over the real stdio transport with real operating-system processes (``task_continuity_stdio_server.py``):
  a requester, an executor and a successor against one state directory, a hand-over between processes, and a
  new process that resumes after the others are gone.

Both sides here are the SDK's own client and server, and the verifier is a stand-in that only checks what the
port carries. That shows the profile works over the standard protocol; it does not show that Cursor, Codex or
any other harness can attach, that a real issuer exists, or that an effect can be fenced. Nothing in this file
claims any of that.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import tempfile
import threading
import unittest
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any
from unittest import mock

from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.mcpserver import MCPServer

from universal_agent_middleware import __version__
from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
from universal_agent_middleware.adapters.mcp_task_continuity import (
    CONTINUITY_TOOLS,
    TASK_CONTINUITY_TOOLS,
    create_task_continuity_server,
    create_task_continuity_server_for_gateway,
)
from universal_agent_middleware.adapters.mcp_task_control import TASK_CONTROL_TOOLS, create_task_control_server
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.task_continuity import DELIVERY_SCHEMA_V2
from universal_agent_middleware.task_control import TaskControlError

from continuity_support import (
    ENDPOINT,
    EXECUTOR,
    NEW_DOC,
    NEW_TEXT,
    OWNER,
    REQUESTER,
    STRANGER,
    SUCCESSOR,
    TASK,
    ContinuityWorld,
    PortAuthority,
)
from coordination_fixtures import contract_v2, document_result
from directory_fixtures import PLAIN_ID, WorldTestCase
from synthetic_fixtures import SyntheticRegistryBundle
from test_mcp_task_control import IDENTITY_ARGUMENTS, READ_TOOLS, Answer, inspect_surface, invoke

LAUNCHER = Path(__file__).resolve().parent / "task_continuity_stdio_server.py"
THIRD = "executor-f"

# The surface of the seven first-batch tools as a client sees it, measured on the pristine first-batch tree
# (name, description, input schema, annotations and every other field the SDK reports; `exclude_none`,
# canonical JSON, SHA-256) with the acting principal `requester-a`. A change here is a change of what a
# client that already attached to `task-control` is told: it has to be a decision, not a side effect. The
# SDK version in use (mcp 2.0.0) is part of the measurement: if the SDK reports a tool differently, this
# fails and the surface has to be measured again on both trees.
FROZEN_FIRST_BATCH_TOOLS = {
    "uam_attempt_end": "e27d3802e79fc9fa0d36455af81faf43b38e9ea7512a28731c921de98afad23a",
    "uam_attempt_result": "8f5fbde9f0bdcec9083dfd26cb9db6d3dc34892e106784a9af9b51efaf1c8e20",
    "uam_attempt_start": "c016486457766ea88c99a0bcfff1d83bf86a45c939194828e8daa2df80da634f",
    "uam_delivery_cancel": "0b7293ee45c32471462bc63a8ff1d85d4ab6ddea5dd8a9e6e6665b3b71db24a1",
    "uam_delivery_get": "0456731a14cd5edf950085014ff39f68b81249412a80e8eaf2ccb18b3e7d6d7d",
    "uam_delivery_inbox": "5517e4e376488696d58237e93da6462cc8f6d3a4e78489ac64762526b0625235",
    "uam_delivery_send": "932e4a73f66b5463da082a660948a388d2e3ad16c5c5c0ca7d06ea107ec828d7",
}
# The first-batch ``instructions`` text names the package version ("UAM v<version> task-control ..."), so the digest below is of the text as it read at the version it was
# measured at. A version change is a decision of its own: the test puts the measured version back for that one token and compares everything else byte for byte.
FROZEN_MEASURED_VERSION = "0.6.1"
FROZEN_FIRST_BATCH_INSTRUCTIONS = "1f49d54fcc880003efbb2f112d58f60c9419a3b57b885a1968005f146d6393d4"

EXPECTED_NEW_ARGUMENTS = {
    "uam_continuity_delivery_send": {
        "contract_id", "contract_digest", "recipient", "authority_ref", "idempotency_key", "owner_ref",
        "business_task_ref", "task_revision", "data_scope_ref", "declared_region", "continues",
    },
    "uam_continuity_handover": {"delivery_id", "role", "to_principal", "authority_ref"},
    "uam_continuity_context_package": {"delivery_id"},
    "uam_continuity_deliveries_for_task": {"owner_ref", "business_task_ref", "limit"},
}
NEW_READ_TOOLS = {"uam_continuity_context_package", "uam_continuity_deliveries_for_task"}
# `to_principal` names the successor the caller wants; it is never who is acting.
SUCCESSOR_ARGUMENTS = IDENTITY_ARGUMENTS | {"initiator", "from_principal", "holder", "original_executor"}


def canonical(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_of(tool: Any) -> str:
    return hashlib.sha256(canonical(tool.model_dump(mode="json", exclude_none=True)).encode("utf-8")).hexdigest()


class ContinuityAdapterWorld(ContinuityWorld):
    """One gateway, one successor control object, one in-memory server per principal."""

    def setUp(self) -> None:
        super().setUp()
        self.requester = self.server_for(REQUESTER)
        self.executor = self.server_for(EXECUTOR)
        self.successor = self.server_for(SUCCESSOR)
        self.stranger = self.server_for(STRANGER)

    def server_for(self, principal: str) -> MCPServer:
        return create_task_continuity_server(self.control, principal=principal, northbound=self.gw.northbound)

    def call(self, server: MCPServer, tool: str, **arguments: Any) -> Answer:
        async def once() -> Answer:
            async with Client(server) as client:  # a new connection per call: nothing rides on a session
                return await invoke(client, tool, **arguments)

        return asyncio.run(once())

    def send(self, **overrides: Any) -> Answer:
        arguments: dict[str, Any] = {
            "contract_id": self.contract["contract_id"], "contract_digest": self.contract["contract_digest"],
            "recipient": EXECUTOR, "authority_ref": "grant-0001", "idempotency_key": "mcp-cont-key-1",
            "owner_ref": OWNER, "business_task_ref": TASK, "task_revision": 3, "data_scope_ref": "scope-ref-1",
        }
        arguments.update(overrides)
        return self.call(self.requester, "uam_continuity_delivery_send", **arguments)

    def delivered(self, **overrides: Any) -> str:
        sent = self.send(**overrides)
        self.assertFalse(sent.is_error, sent.text)
        return sent.body["delivery_id"]

    def started(self) -> tuple[str, dict[str, Any]]:
        delivery_id = self.delivered()
        began = self.call(self.executor, "uam_attempt_start", delivery_id=delivery_id)
        self.assertFalse(began.is_error, began.text)
        return delivery_id, began.body["attempts"][-1]

    def handed_over(self, delivery_id: str, to: str = SUCCESSOR, role: str = "recipient") -> Answer:
        server = self.executor if role == "recipient" else self.requester
        return self.call(
            server, "uam_continuity_handover", delivery_id=delivery_id, role=role, to_principal=to,
            authority_ref="grant-handover-1",
        )


class TestSurface(ContinuityAdapterWorld):
    def test_the_seven_first_batch_tools_reach_a_client_exactly_as_the_first_batch_shipped_them(self) -> None:
        successor = asyncio.run(inspect_surface(self.requester))
        first_batch = asyncio.run(inspect_surface(
            create_task_control_server(self.control, principal=REQUESTER, northbound=self.gw.northbound),
        ))
        for label, surface in (("the first-batch server", first_batch), ("the successor server", successor)):
            with self.subTest(label):
                self.assertEqual(
                    {name: digest_of(surface.tools[name]) for name in TASK_CONTROL_TOOLS}, FROZEN_FIRST_BATCH_TOOLS,
                )
                instructions = surface.instructions or ""
                self.assertTrue(instructions.startswith(f"UAM v{__version__} task-control (candidate), "), instructions[:80])
                as_measured = instructions.replace(f"UAM v{__version__} ", f"UAM v{FROZEN_MEASURED_VERSION} ", 1)
                self.assertEqual(hashlib.sha256(as_measured.encode("utf-8")).hexdigest(), FROZEN_FIRST_BATCH_INSTRUCTIONS)

    def test_the_first_batch_profile_does_not_gain_a_tool(self) -> None:
        first_batch = asyncio.run(inspect_surface(
            create_task_control_server(self.control, principal=REQUESTER, northbound=self.gw.northbound),
        ))
        self.assertEqual(set(first_batch.tools), set(TASK_CONTROL_TOOLS))
        self.assertEqual(len(first_batch.tools), 7)
        self.assertFalse(set(first_batch.tools) & set(CONTINUITY_TOOLS))

    def test_exactly_four_tools_are_added_and_nothing_else(self) -> None:
        surface = asyncio.run(inspect_surface(self.requester))
        self.assertEqual(set(surface.tools), set(TASK_CONTINUITY_TOOLS))
        self.assertEqual(len(surface.tools), 11)
        self.assertEqual(set(surface.tools) - set(TASK_CONTROL_TOOLS), set(CONTINUITY_TOOLS))
        self.assertEqual(set(TASK_CONTINUITY_TOOLS), set(TASK_CONTROL_TOOLS) | set(CONTINUITY_TOOLS))

    def test_each_new_tool_takes_exactly_the_documented_arguments(self) -> None:
        surface = asyncio.run(inspect_surface(self.requester))
        self.assertEqual(set(EXPECTED_NEW_ARGUMENTS), set(CONTINUITY_TOOLS))
        for name, expected in EXPECTED_NEW_ARGUMENTS.items():
            with self.subTest(name):
                self.assertEqual(set(surface.tools[name].input_schema["properties"]), expected)

    def test_no_tool_lets_a_client_name_the_acting_principal(self) -> None:
        surface = asyncio.run(inspect_surface(self.requester))
        for name, tool in surface.tools.items():
            with self.subTest(name):
                self.assertFalse(SUCCESSOR_ARGUMENTS & set(tool.input_schema["properties"]))

    def test_the_principal_is_fixed_when_the_server_is_created(self) -> None:
        mine = self.send()
        self.assertEqual((mine.body["requester"], mine.body["viewer_role"]), (REQUESTER, "requester"))
        other = self.new_contract("cont-two", allowed=["notes/two.md"])
        theirs = self.call(
            self.executor, "uam_continuity_delivery_send", contract_id="cont-two",
            contract_digest=other["contract_digest"], recipient=STRANGER, authority_ref="grant-0002",
            idempotency_key="mcp-cont-key-2", owner_ref=OWNER, business_task_ref="task-other", task_revision=1,
            data_scope_ref="scope-ref-2",
        )
        self.assertFalse(theirs.is_error, theirs.text)
        self.assertEqual((theirs.body["requester"], theirs.body["viewer_role"]), (EXECUTOR, "requester"))
        self.assertEqual([request.principal for request in self.authority.asked("deliver")], [REQUESTER, EXECUTOR])

    def test_annotations_say_which_new_tools_only_read_and_match_the_kind_of_tool_they_resemble(self) -> None:
        surface = asyncio.run(inspect_surface(self.requester))
        for name in CONTINUITY_TOOLS:
            annotations = surface.tools[name].annotations
            with self.subTest(name):
                self.assertIs(annotations.read_only_hint, name in NEW_READ_TOOLS)
                self.assertIs(annotations.destructive_hint, False)
                self.assertIs(annotations.open_world_hint, False)
        self.assertEqual(surface.tools["uam_continuity_delivery_send"].annotations, surface.tools["uam_delivery_send"].annotations)
        self.assertEqual(surface.tools["uam_continuity_handover"].annotations, surface.tools["uam_delivery_send"].annotations)
        self.assertEqual(surface.tools["uam_continuity_context_package"].annotations, surface.tools["uam_delivery_get"].annotations)
        for name in READ_TOOLS:
            self.assertIs(surface.tools[name].annotations.read_only_hint, True)

    def test_no_tasks_capability_extension_or_handle_is_advertised_or_returned(self) -> None:
        surface = asyncio.run(inspect_surface(self.requester))
        self.assertIsNone(surface.capabilities.tasks)
        self.assertIsNone(surface.capabilities.extensions)
        self.assertFalse([name for name in surface.tools if name.startswith("tasks")])
        for answer in (self.send(), self.call(self.requester, "uam_continuity_deliveries_for_task", owner_ref=OWNER, business_task_ref=TASK)):
            self.assertFalse({"task", "taskId", "task_id", "handle"} & set(answer.body))

    def test_the_new_tools_say_what_they_are_not(self) -> None:
        surface = asyncio.run(inspect_surface(self.requester))
        handover = " ".join(surface.tools["uam_continuity_handover"].description.split())
        for phrase in ("not evidence that its executor stopped", "NOT_FOUND"):
            self.assertIn(phrase, handover)
        package = surface.tools["uam_continuity_context_package"].description
        for phrase in ("references and digests only", "no right to read content"):
            self.assertIn(phrase, " ".join(package.split()))
        sent = " ".join(surface.tools["uam_continuity_delivery_send"].description.split())
        for phrase in ("DECLARED_NOT_VERIFIED", "PRIOR_UNRESOLVED_EFFECT_UNLINKED", "does not settle it"):
            self.assertIn(phrase, sent)
        locating = " ".join(surface.tools["uam_continuity_deliveries_for_task"].description.split())
        self.assertIn("not a task list", locating)

    def test_the_deployed_read_only_profile_is_neither_widened_nor_shared(self) -> None:
        bundle = SyntheticRegistryBundle()
        self.addCleanup(bundle.cleanup)
        state = tempfile.TemporaryDirectory(prefix="uam-ro-state-")
        self.addCleanup(state.cleanup)
        read_only = create_session_read_server(registry_path=str(bundle.registry_path), state_dir=state.name)
        read_only_surface = asyncio.run(inspect_surface(read_only))
        successor_surface = asyncio.run(inspect_surface(self.requester))
        self.assertEqual(len(read_only_surface.tools), 20)
        self.assertFalse(set(read_only_surface.tools) & set(successor_surface.tools))

    def test_an_invalid_principal_cannot_start_a_server(self) -> None:
        for bad in ("", "has space", "x" * 200, "semi;colon"):
            with self.subTest(bad):
                with self.assertRaises(TaskControlError) as raised:
                    create_task_continuity_server(self.control, principal=bad)
                self.assertEqual(raised.exception.code, "INVALID_ARGUMENT")


class TestExchange(ContinuityAdapterWorld):
    def test_a_namespaced_delivery_is_read_by_the_old_tools_and_says_what_a_version_two_delivery_says(self) -> None:
        sent = self.send(declared_region="eu-west-1")
        self.assertFalse(sent.is_error, sent.text)
        self.assertEqual(sent.body["schema"], DELIVERY_SCHEMA_V2)
        self.assertEqual((sent.body["owner_ref"], sent.body["endpoint_ref"]), (OWNER, ENDPOINT))
        self.assertEqual(sent.body["data_scope"]["declared_region"], "eu-west-1")
        self.assertEqual(sent.body["data_scope"]["declared_region_status"], "DECLARED_NOT_VERIFIED")
        delivery_id = sent.body["delivery_id"]
        inbox = self.call(self.executor, "uam_delivery_inbox")
        self.assertEqual([item["delivery_id"] for item in inbox.body["items"]], [delivery_id])
        self.assertEqual(inbox.body["items"][0]["schema"], DELIVERY_SCHEMA_V2)
        read = self.call(self.executor, "uam_delivery_get", delivery_id=delivery_id)
        self.assertEqual(read.body["new_effect_permission"]["effect_fencing"], "NOT_PROVIDED")
        self.assertEqual(read.body["business_acceptance"], "NOT_DETERMINED_BY_UAM")
        self.assertEqual(read.body["contract"]["contract_id"], self.contract["contract_id"])

    def test_the_same_send_is_the_same_delivery(self) -> None:
        first = self.send()
        again = self.send()
        self.assertEqual((again.body["delivery_id"], again.body["replayed"]), (first.body["delivery_id"], True))
        self.assertEqual(len(self.authority.asked("deliver")), 1)
        changed = self.send(task_revision=4)
        self.assertEqual(changed.body["error_code"], "IDEMPOTENCY_CONFLICT")

    def test_a_refusal_has_the_same_shape_as_in_the_first_batch(self) -> None:
        refused = self.send(contract_digest="0" * 64)
        self.assertTrue(refused.is_error)
        self.assertEqual(set(refused.body), {"error", "error_code"})
        self.assertEqual(refused.body["error_code"], "CONTRACT_MISMATCH")
        self.assertEqual(self.authority.asked("deliver"), [])

    def test_an_open_effect_is_named_in_the_refusal_without_saying_how_many_there_are(self) -> None:
        delivery_id, attempt = self.started()
        self.write_document()
        ended = self.call(
            self.executor, "uam_attempt_end", delivery_id=delivery_id, attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], outcome="FAILED_BEFORE_EFFECT",
        )
        self.assertEqual(ended.body["effect"], "PARTIAL_EFFECT_OBSERVED", ended.text)
        second = self.new_contract("cont-second", allowed=["notes/second.md"])
        refused = self.send(
            contract_id="cont-second", contract_digest=second["contract_digest"], idempotency_key="mcp-cont-key-2",
        )
        self.assertTrue(refused.is_error)
        self.assertEqual(refused.body["error_code"], "PRIOR_UNRESOLVED_EFFECT_UNLINKED")
        self.assertEqual(set(refused.body), {"error", "error_code", "details"})
        self.assertEqual(refused.body["details"], {"unresolved_unlinked": True, "your_predecessors": [delivery_id]})
        cancelled = self.call(self.requester, "uam_delivery_cancel", delivery_id=delivery_id)
        self.assertFalse(cancelled.is_error, cancelled.text)
        linked = self.send(
            contract_id="cont-second", contract_digest=second["contract_digest"], idempotency_key="mcp-cont-key-2",
            continues=[delivery_id],
        )
        self.assertFalse(linked.is_error, linked.text)
        self.assertEqual(linked.body["continues"], [delivery_id])
        self.assertIsNotNone(linked.body["continuation_evidence_digest"])

    def test_a_recipient_handover_is_one_call_and_the_old_tools_then_see_the_new_roles(self) -> None:
        delivery_id, attempt = self.started()
        self.write_document()
        handed = self.handed_over(delivery_id)
        self.assertFalse(handed.is_error, handed.text)
        self.assertEqual(handed.body["handover"]["to"], SUCCESSOR)
        self.assertEqual(handed.body["handover"]["stop_at_handover"], "NOT_CONFIRMED_HANDED_OVER")
        seen = self.call(self.successor, "uam_delivery_get", delivery_id=delivery_id)
        self.assertEqual((seen.body["viewer_role"], seen.body["recipient"]), ("recipient", SUCCESSOR))
        self.assertEqual(
            self.call(self.successor, "uam_delivery_inbox").body["items"][0]["delivery_id"], delivery_id,
        )
        self.assertEqual(self.call(self.executor, "uam_delivery_inbox").body["items"], [])
        for tool, server in (("uam_delivery_get", self.executor), ("uam_continuity_context_package", self.executor)):
            with self.subTest(tool):
                hidden = self.call(server, tool, delivery_id=delivery_id)
                self.assertEqual((hidden.is_error, hidden.body["error_code"]), (True, "NOT_FOUND"))
        # Nobody may start another attempt until the former executor reports or somebody decides otherwise.
        blocked = self.call(self.successor, "uam_attempt_start", delivery_id=delivery_id)
        self.assertEqual(blocked.body["error_code"], "STOP_NOT_CONFIRMED")
        late_stop = self.call(
            self.executor, "uam_attempt_end", delivery_id=delivery_id, attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], outcome="STOPPED",
        )
        self.assertFalse(late_stop.is_error, late_stop.text)
        self.assertEqual(late_stop.body["stop_evidence"], "SELF_REPORTED_LATE")
        self.assertEqual(late_stop.body["viewer_role"], "former_recipient")
        # The report lifts the stop gate and nothing else: the live baseline still has the document in it.
        still = self.call(self.successor, "uam_attempt_start", delivery_id=delivery_id)
        self.assertEqual(still.body["error_code"], "BASELINE_CHANGED")

    def test_a_late_receipt_from_the_former_executor_is_ingested_and_nothing_else_is_decided(self) -> None:
        delivery_id, attempt = self.started()
        self.write_document()
        self.assertFalse(self.handed_over(delivery_id).is_error)
        fetched = self.call(self.successor, "uam_delivery_get", delivery_id=delivery_id)
        payload = document_result(
            fetched.body["contract"], "mcp-cont-result-1", {NEW_DOC: NEW_TEXT}, attempt_ref=attempt["attempt_ref"],
            executor=EXECUTOR, business_task_ref=TASK, task_revision=3,
        )
        recorded = self.call(
            self.executor, "uam_attempt_result", delivery_id=delivery_id, attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], result=payload,
        )
        self.assertFalse(recorded.is_error, recorded.text)
        self.assertEqual(recorded.body["result_record"]["review"]["state"], "PASS")
        self.assertIs(recorded.body["replayed"], False)
        again = self.call(
            self.executor, "uam_attempt_result", delivery_id=delivery_id, attempt_ref=attempt["attempt_ref"],
            fence=attempt["fence"], result=payload,
        )
        self.assertIs(again.body["replayed"], True)
        view = self.call(self.requester, "uam_delivery_get", delivery_id=delivery_id)
        self.assertEqual(view.body["state"], "RESULT_RECORDED")
        self.assertEqual(view.body["result"]["late_after_attempt_end"], "HANDED_OVER")
        self.assertEqual([item["kind"] for item in view.body["evidence_ingestion"]], ["LATE_RECEIPT"])
        self.assertEqual(view.body["business_acceptance"], "NOT_DETERMINED_BY_UAM")
        self.assertIs(view.body["new_effect_permission"]["record_permits_new_attempt"], False)

    def test_somebody_who_takes_no_part_is_told_nothing_by_any_new_tool(self) -> None:
        delivery_id = self.delivered()
        self.authority.effects.discard("handover")
        for tool, arguments in (
            ("uam_continuity_context_package", {"delivery_id": delivery_id}),
            ("uam_continuity_handover", {
                "delivery_id": delivery_id, "role": "recipient", "to_principal": THIRD, "authority_ref": "grant-9",
            }),
        ):
            with self.subTest(tool):
                refused = self.call(self.stranger, tool, **arguments)
                self.assertEqual((refused.is_error, refused.body["error_code"]), (True, "NOT_FOUND"))
        listing = self.call(self.stranger, "uam_continuity_deliveries_for_task", owner_ref=OWNER, business_task_ref=TASK)
        self.assertEqual(listing.body["items"], [])
        self.assertEqual(self.call(self.stranger, "uam_delivery_inbox").body["items"], [])

    def test_locating_a_task_lists_only_what_the_caller_takes_part_in_and_asks_nobody(self) -> None:
        delivery_id = self.delivered()
        self.authority.forget()
        mine = self.call(self.requester, "uam_continuity_deliveries_for_task", owner_ref=OWNER, business_task_ref=TASK)
        self.assertEqual([item["delivery_id"] for item in mine.body["items"]], [delivery_id])
        self.assertEqual((mine.body["claims_nothing"], mine.body["writes_nothing"]), (True, True))
        self.assertEqual(self.authority.requests, [])
        wrong = self.call(self.requester, "uam_continuity_deliveries_for_task", owner_ref=OWNER, business_task_ref=TASK, limit=0)
        self.assertEqual(wrong.body["error_code"], "INVALID_ARGUMENT")

    def test_the_context_package_comes_over_the_wire_as_references_and_digests(self) -> None:
        delivery_id, _ = self.started()
        self.write_document()
        self.assertFalse(self.handed_over(delivery_id).is_error)
        package = self.call(self.successor, "uam_continuity_context_package", delivery_id=delivery_id)
        self.assertFalse(package.is_error, package.text)
        self.assertEqual(package.body["schema"], "uam-context-package-v1")
        self.assertEqual(package.body["participants"]["recipient"], SUCCESSOR)
        self.assertEqual(package.body["effect"]["new_effect_permission"]["blockers"], ["STOP_NOT_CONFIRMED_HANDED_OVER"])
        for leaked in (NEW_DOC, NEW_TEXT.strip(), str(self.world.root), "password"):
            self.assertNotIn(leaked, package.text)
        asked = self.authority.asked("context_receive")
        self.assertEqual([(request.principal, request.role) for request in asked], [(SUCCESSOR, "recipient")])

    def test_receiving_the_package_and_reading_content_are_two_rights_over_the_wire(self) -> None:
        delivery_id = self.delivered()
        self.authority.effects.discard("dereference")
        withheld = self.call(self.executor, "uam_delivery_get", delivery_id=delivery_id)
        self.assertFalse(withheld.is_error, withheld.text)
        self.assertNotIn("contract", withheld.body)
        self.assertEqual(withheld.body["content_withheld"]["code"], "AUTHORITY_DENIED")
        self.assertEqual(withheld.body["state"], "DELIVERED")
        # Without the right to read content, the package (references and digests) is still receivable ...
        package = self.call(self.executor, "uam_continuity_context_package", delivery_id=delivery_id)
        self.assertFalse(package.is_error, package.text)
        # ... and with the right to read content but not to receive the package, it is not.
        self.authority.effects.add("dereference")
        self.authority.effects.discard("context_receive")
        refused = self.call(self.executor, "uam_continuity_context_package", delivery_id=delivery_id)
        self.assertEqual((refused.is_error, refused.body["error_code"]), (True, "AUTHORITY_DENIED"))
        readable = self.call(self.executor, "uam_delivery_get", delivery_id=delivery_id)
        self.assertEqual(readable.body["contract"]["contract_id"], self.contract["contract_id"])

    def test_version_one_deliveries_still_work_through_the_successor_server_and_say_nothing_new(self) -> None:
        # Only through the bounded legacy entry, which a host has to open on purpose (it is closed by default).
        legacy = create_task_continuity_server(
            self.legacy_control(), principal=REQUESTER, northbound=self.gw.northbound,
        )
        sent = self.call(
            legacy, "uam_delivery_send", contract_id=self.contract["contract_id"],
            contract_digest=self.contract["contract_digest"], recipient=EXECUTOR, authority_ref="grant-0001",
            idempotency_key="mcp-v1-key", business_task_ref="task-v1", task_revision=1,
        )
        self.assertFalse(sent.is_error, sent.text)
        self.assertNotIn("schema", sent.body)
        self.assertNotIn("new_effect_permission", sent.body)
        self.assertEqual([request.request_version for request in self.authority.asked("deliver")], [1])
        refused = self.call(self.executor, "uam_continuity_context_package", delivery_id=sent.body["delivery_id"])
        self.assertEqual(refused.body["error_code"], "NOT_FOUND")

    def test_the_legacy_send_is_closed_by_default_so_the_same_task_guard_is_the_only_way_in(self) -> None:
        arguments: dict[str, Any] = {
            "contract_id": self.contract["contract_id"], "contract_digest": self.contract["contract_digest"],
            "recipient": EXECUTOR, "authority_ref": "grant-0001", "idempotency_key": "mcp-v1-key",
            "business_task_ref": "task-v1", "task_revision": 1,
        }
        # The control object every test server shares was built without the option: this is the default.
        refused = self.call(self.requester, "uam_delivery_send", **arguments)
        self.assertEqual((refused.is_error, refused.body["error_code"]), (True, "LEGACY_DELIVER_DISABLED"))
        self.assertEqual(list((self.control.root / "deliveries").glob("dlv-*.json")), [])
        self.assertEqual(self.authority.asked("deliver"), [])
        allowed = self.call(
            self.requester, "uam_continuity_delivery_send", contract_id=self.contract["contract_id"],
            contract_digest=self.contract["contract_digest"], recipient=EXECUTOR, authority_ref="grant-0001",
            idempotency_key="mcp-cont-key-1", owner_ref=OWNER, business_task_ref=TASK, task_revision=3,
            data_scope_ref="scope-ref-1",
        )
        self.assertFalse(allowed.is_error, allowed.text)

    def test_the_gateway_factory_closes_the_legacy_send_unless_it_is_told_to_open_it(self) -> None:
        arguments: dict[str, Any] = {
            "contract_id": self.contract["contract_id"], "contract_digest": self.contract["contract_digest"],
            "recipient": EXECUTOR, "authority_ref": "grant-0001", "idempotency_key": "mcp-v1-key",
            "business_task_ref": "task-v1", "task_revision": 1,
        }
        closed = create_task_continuity_server_for_gateway(
            self.gw, principal=REQUESTER, authority=self.authority, endpoint_ref=ENDPOINT,
        )
        refused = self.call(closed, "uam_delivery_send", **arguments)
        self.assertEqual((refused.is_error, refused.body["error_code"]), (True, "LEGACY_DELIVER_DISABLED"))
        opened = create_task_continuity_server_for_gateway(
            self.gw, principal=REQUESTER, authority=self.authority, endpoint_ref=ENDPOINT, legacy_deliver=True,
        )
        accepted = self.call(opened, "uam_delivery_send", **arguments)
        self.assertFalse(accepted.is_error, accepted.text)
        # The closed server still finishes what the legacy entry started: only the start of version-1 work is shut.
        started = self.call(self.executor, "uam_attempt_start", delivery_id=accepted.body["delivery_id"])
        self.assertEqual((started.is_error, started.body["error_code"]), (True, "LEGACY_DELIVER_DISABLED"))
        cancelled = self.call(self.requester, "uam_delivery_cancel", delivery_id=accepted.body["delivery_id"])
        self.assertFalse(cancelled.is_error, cancelled.text)


class TestWire(ContinuityAdapterWorld):
    def test_an_unexpected_failure_says_only_that_it_was_internal(self) -> None:
        boom = RuntimeError("exploded near /Users/private/secret/path with token abc123")
        delivery_id = self.delivered()
        for tool, method, arguments in (
            ("uam_continuity_context_package", "context_package", {"delivery_id": delivery_id}),
            ("uam_continuity_deliveries_for_task", "deliveries_for_task", {"owner_ref": OWNER, "business_task_ref": TASK}),
            ("uam_continuity_handover", "handover", {
                "delivery_id": delivery_id, "role": "recipient", "to_principal": THIRD, "authority_ref": "grant-1",
            }),
            ("uam_continuity_delivery_send", "deliver_continuity", {
                "contract_id": "x", "contract_digest": "0" * 64, "recipient": EXECUTOR, "authority_ref": "grant-1",
                "idempotency_key": "boom-key-0001", "owner_ref": OWNER, "business_task_ref": TASK, "task_revision": 1,
                "data_scope_ref": "scope-1",
            }),
        ):
            with self.subTest(tool), mock.patch.object(self.control, method, side_effect=boom):
                result = self.call(self.requester, tool, **arguments)
                self.assertTrue(result.is_error)
                self.assertEqual(result.body, {"error": "internal error", "error_code": "INTERNAL"})
                for leaked in ("exploded", "private", "abc123"):
                    self.assertNotIn(leaked, result.text)

    def test_blocking_work_runs_off_the_event_loop_thread(self) -> None:
        seen: dict[str, int] = {}
        original = self.control.deliveries_for_task

        def spy(principal: str, **kwargs: Any) -> dict[str, Any]:
            seen["worker"] = threading.get_ident()
            return original(principal, **kwargs)

        async def once() -> int:
            async with Client(self.requester) as client:
                await invoke(client, "uam_continuity_deliveries_for_task", owner_ref=OWNER, business_task_ref=TASK)
            return threading.get_ident()

        with mock.patch.object(self.control, "deliveries_for_task", side_effect=spy):
            loop_thread = asyncio.run(once())
        self.assertNotEqual(seen["worker"], loop_thread)

    def test_no_host_path_leaves_in_an_answer_while_the_stored_contract_keeps_its_text(self) -> None:
        host_path = str(self.world.plain)
        contract = self.new_contract(
            "cont-path-task", allowed=["notes/other.md"], objective=f"Write the note that explains {host_path}/README.md",
        )
        delivery_id = self.delivered(
            contract_id="cont-path-task", contract_digest=contract["contract_digest"], idempotency_key="path-key-0001",
        )
        fetched = self.call(self.executor, "uam_delivery_get", delivery_id=delivery_id)
        package = self.call(self.executor, "uam_continuity_context_package", delivery_id=delivery_id)
        for answer in (fetched, package):
            self.assertNotIn(str(self.world.root), answer.text)
            self.assertNotIn(host_path, answer.text)
        self.assertIn(host_path, self.gw.contracts.get_record("cont-path-task")["objective"])

    def test_without_a_wired_authority_nothing_is_delivered(self) -> None:
        server = create_task_continuity_server_for_gateway(self.gw, principal=REQUESTER, endpoint_ref=ENDPOINT)
        refused = self.call(
            server, "uam_continuity_delivery_send", contract_id=self.contract["contract_id"],
            contract_digest=self.contract["contract_digest"], recipient=EXECUTOR, authority_ref="grant-0001",
            idempotency_key="deny-key-0001", owner_ref=OWNER, business_task_ref=TASK, task_revision=3,
            data_scope_ref="scope-ref-1",
        )
        self.assertTrue(refused.is_error)
        self.assertEqual(refused.body["error_code"], "AUTHORITY_DENIED")
        self.assertFalse(list((self.control._v2_deliveries).glob("dlv-*.json")))
        self.assertEqual(self.audit_outcomes("deliver"), ["DENY"])

    def test_a_verifier_written_for_version_one_is_refused_before_it_is_asked_and_the_refusal_says_why(self) -> None:
        class VersionOneVerifier:
            asked = 0

            def verify(self, request: Any) -> Any:
                VersionOneVerifier.asked += 1
                raise AssertionError("a version-1 verifier must not be asked a version-2 question")

        server = create_task_continuity_server_for_gateway(
            self.gw, principal=REQUESTER, authority=VersionOneVerifier(), endpoint_ref=ENDPOINT,
        )
        refused = self.call(
            server, "uam_continuity_delivery_send", contract_id=self.contract["contract_id"],
            contract_digest=self.contract["contract_digest"], recipient=EXECUTOR, authority_ref="grant-0001",
            idempotency_key="old-verifier-1", owner_ref=OWNER, business_task_ref=TASK, task_revision=3,
            data_scope_ref="scope-ref-1",
        )
        self.assertTrue(refused.is_error)
        self.assertEqual(refused.body["error_code"], "AUTHORITY_DENIED")
        self.assertIn("AUTHORITY_PORT_VERSION", refused.body["error"])
        self.assertEqual(VersionOneVerifier.asked, 0)

    def test_the_gateway_composition_shares_the_gateways_stores_and_audit_log(self) -> None:
        server = create_task_continuity_server_for_gateway(
            self.gw, principal=REQUESTER, authority=self.authority, endpoint_ref=ENDPOINT,
        )
        sent = self.call(
            server, "uam_continuity_delivery_send", contract_id=self.contract["contract_id"],
            contract_digest=self.contract["contract_digest"], recipient=EXECUTOR, authority_ref="grant-0001",
            idempotency_key="audit-key-0001", owner_ref=OWNER, business_task_ref=TASK, task_revision=3,
            data_scope_ref="scope-ref-1",
        )
        self.assertFalse(sent.is_error, sent.text)
        self.assertEqual(self.audit_outcomes("deliver_continuity"), ["PASS"])
        self.assertNotIn("grant-0001", (self.gw.state_dir / "audit.jsonl").read_text("utf-8"))
        chain = self.gw.audit.verify()
        self.assertTrue(chain["valid"], chain)
        request = self.authority.asked("deliver")[0]
        self.assertEqual((request.request_version, request.endpoint_ref, request.owner_ref), (2, ENDPOINT, OWNER))
        self.assertIsNotNone(request.binding_digest)


class StdioProcessTests(WorldTestCase):
    """Real processes, real stdio framing, one state directory: concurrency, hand-over and reconnect are not simulated."""

    def parameters(self, principal: str, authority: str = "port", **extra: str) -> StdioServerParameters:
        arguments = [
            str(LAUNCHER), "--registry", str(self.world.registry_path), "--state-dir", str(self.world.state),
            "--principal", principal, "--authority", authority, "--endpoint-ref", ENDPOINT,
        ]
        for name, value in extra.items():
            arguments += [f"--{name.replace('_', '-')}", value]
        return StdioServerParameters(command=sys.executable, args=arguments)

    def prepare(self) -> dict[str, Any]:
        self.world.write_registry()
        self.world.write_scope_file()
        gateway = MiddlewareGateway(str(self.world.registry_path), str(self.world.state))
        return gateway.create_contract(
            contract_v2("stdio-cont-task", PLAIN_ID, authoritative=["README.md"], allowed=[NEW_DOC]),
        )

    @staticmethod
    def send_arguments(contract: dict[str, Any], **overrides: Any) -> dict[str, Any]:
        arguments: dict[str, Any] = {
            "contract_id": contract["contract_id"], "contract_digest": contract["contract_digest"],
            "recipient": EXECUTOR, "authority_ref": "grant-0001", "idempotency_key": "stdio-cont-key",
            "owner_ref": OWNER, "business_task_ref": "task-77", "task_revision": 1, "data_scope_ref": "scope-77",
        }
        arguments.update(overrides)
        return arguments

    def test_three_processes_share_one_state_a_role_moves_between_them_and_a_new_process_resumes(self) -> None:
        contract = self.prepare()

        async def scenario() -> dict[str, Any]:
            seen: dict[str, Any] = {}
            async with AsyncExitStack() as stack:
                requester = await stack.enter_async_context(Client(stdio_client(self.parameters(REQUESTER))))
                executor = await stack.enter_async_context(Client(stdio_client(self.parameters(EXECUTOR))))
                successor = await stack.enter_async_context(Client(stdio_client(self.parameters(SUCCESSOR))))
                seen["tasks_capability"] = tuple(client.server_capabilities.tasks for client in (requester, executor, successor))
                seen["tool_names"] = sorted(tool.name for tool in (await requester.list_tools()).tools)
                sent = await invoke(requester, "uam_continuity_delivery_send", **self.send_arguments(contract, declared_region="eu-west-1"))
                seen["sent"] = sent
                delivery_id = sent.body["delivery_id"]
                began = await invoke(executor, "uam_attempt_start", delivery_id=delivery_id)
                seen["started"] = began
                attempt = began.body["attempts"][-1]
                (self.world.plain / NEW_DOC).write_text(NEW_TEXT, encoding="utf-8")
                seen["handed"] = await invoke(
                    executor, "uam_continuity_handover", delivery_id=delivery_id, role="recipient",
                    to_principal=SUCCESSOR, authority_ref="grant-handover-1",
                )
                seen["package"] = await invoke(successor, "uam_continuity_context_package", delivery_id=delivery_id)
                seen["former_package"] = await invoke(executor, "uam_continuity_context_package", delivery_id=delivery_id)
                seen["successor_start"] = await invoke(successor, "uam_attempt_start", delivery_id=delivery_id)
                requester_view = await invoke(requester, "uam_delivery_get", delivery_id=delivery_id)
                seen["requester_view"] = requester_view
                payload = document_result(
                    requester_view.body["contract"], "stdio-cont-result-1", {NEW_DOC: NEW_TEXT},
                    attempt_ref=attempt["attempt_ref"], executor=EXECUTOR, business_task_ref="task-77", task_revision=1,
                )
                seen["late"] = await invoke(
                    executor, "uam_attempt_result", delivery_id=delivery_id, attempt_ref=attempt["attempt_ref"],
                    fence=attempt["fence"], result=payload,
                )
                seen["listing"] = await invoke(
                    requester, "uam_continuity_deliveries_for_task", owner_ref=OWNER, business_task_ref="task-77",
                )
            # Every process above is gone. A brand-new process for the successor reads what they left.
            async with Client(stdio_client(self.parameters(SUCCESSOR))) as resumed:
                seen["resumed_view"] = await invoke(resumed, "uam_delivery_get", delivery_id=delivery_id)
                seen["restart"] = await invoke(resumed, "uam_attempt_start", delivery_id=delivery_id)
            return seen

        seen = asyncio.run(scenario())
        self.assertEqual(seen["tasks_capability"], (None, None, None))
        self.assertEqual(seen["tool_names"], sorted(TASK_CONTINUITY_TOOLS))
        self.assertEqual(seen["sent"].body["schema"], DELIVERY_SCHEMA_V2, seen["sent"].text)
        self.assertEqual(seen["sent"].body["data_scope"]["declared_region_status"], "DECLARED_NOT_VERIFIED")
        self.assertEqual(seen["started"].body["state"], "ATTEMPT_ACTIVE", seen["started"].text)
        self.assertEqual(seen["handed"].body["handover"]["to"], SUCCESSOR, seen["handed"].text)
        self.assertEqual(seen["package"].body["participants"]["recipient"], SUCCESSOR, seen["package"].text)
        self.assertEqual(seen["package"].body["effect"]["effect"], "PARTIAL_EFFECT_OBSERVED")
        self.assertEqual(seen["former_package"].body["error_code"], "NOT_FOUND")
        self.assertEqual(seen["successor_start"].body["error_code"], "STOP_NOT_CONFIRMED")
        self.assertEqual(seen["late"].body["result_record"]["review"]["state"], "PASS", seen["late"].text)
        self.assertEqual([item["state"] for item in seen["listing"].body["items"]], ["RESULT_RECORDED"])
        self.assertEqual(seen["resumed_view"].body["state"], "RESULT_RECORDED")
        self.assertEqual(seen["resumed_view"].body["result"]["late_after_attempt_end"], "HANDED_OVER")
        self.assertEqual(seen["resumed_view"].body["viewer_role"], "recipient")
        self.assertEqual(seen["restart"].body["error_code"], "RESULT_ALREADY_RECORDED")
        self.assertEqual((self.world.plain / NEW_DOC).read_text(encoding="utf-8"), NEW_TEXT)

    def test_two_processes_of_one_holder_cannot_hand_the_same_role_to_two_successors(self) -> None:
        contract = self.prepare()

        async def scenario() -> list[Answer]:
            async with AsyncExitStack() as stack:
                requester = await stack.enter_async_context(Client(stdio_client(self.parameters(REQUESTER))))
                first = await stack.enter_async_context(Client(stdio_client(self.parameters(EXECUTOR))))
                second = await stack.enter_async_context(Client(stdio_client(self.parameters(EXECUTOR))))
                sent = await invoke(requester, "uam_continuity_delivery_send", **self.send_arguments(contract))
                delivery_id = sent.body["delivery_id"]
                return list(await asyncio.gather(
                    invoke(first, "uam_continuity_handover", delivery_id=delivery_id, role="recipient",
                           to_principal=SUCCESSOR, authority_ref="grant-handover-1"),
                    invoke(second, "uam_continuity_handover", delivery_id=delivery_id, role="recipient",
                           to_principal=THIRD, authority_ref="grant-handover-2"),
                ))

        answers = asyncio.run(scenario())
        winners = [answer for answer in answers if not answer.is_error]
        losers = [answer for answer in answers if answer.is_error]
        self.assertEqual((len(winners), len(losers)), (1, 1), [answer.text for answer in answers])
        # The loser is no longer anybody's recipient: it is told nothing.
        self.assertEqual(losers[0].body["error_code"], "NOT_FOUND")
        self.assertEqual(winners[0].body["handover"]["seq"], 1)

    def test_a_server_whose_verifier_was_written_for_version_one_refuses_version_two_and_keeps_version_one(self) -> None:
        contract = self.prepare()

        async def scenario() -> dict[str, Answer]:
            async with Client(stdio_client(self.parameters(REQUESTER, authority="allow-all", legacy_deliver="yes"))) as requester:
                return {
                    "continuity": await invoke(requester, "uam_continuity_delivery_send", **self.send_arguments(contract)),
                    "legacy": await invoke(
                        requester, "uam_delivery_send", contract_id=contract["contract_id"],
                        contract_digest=contract["contract_digest"], recipient=EXECUTOR, authority_ref="grant-0001",
                        idempotency_key="stdio-v1-key", business_task_ref="task-v1", task_revision=1,
                    ),
                }

        seen = asyncio.run(scenario())
        self.assertEqual(seen["continuity"].body["error_code"], "AUTHORITY_DENIED")
        self.assertIn("AUTHORITY_PORT_VERSION", seen["continuity"].body["error"])
        self.assertFalse(seen["legacy"].is_error, seen["legacy"].text)
        self.assertEqual(seen["legacy"].body["state"], "DELIVERED")

    def test_a_server_started_without_an_authority_denies_every_effect(self) -> None:
        contract = self.prepare()

        async def scenario() -> Answer:
            async with Client(stdio_client(self.parameters(REQUESTER, authority="deny"))) as requester:
                return await invoke(requester, "uam_continuity_delivery_send", **self.send_arguments(contract))

        refused = asyncio.run(scenario())
        self.assertTrue(refused.is_error)
        self.assertEqual(refused.body["error_code"], "AUTHORITY_DENIED")

    def test_the_legacy_send_is_closed_by_default_and_by_the_launch_option_and_the_continuity_send_is_not(self) -> None:
        contract = self.prepare()
        legacy_arguments: dict[str, Any] = {
            "contract_id": contract["contract_id"], "contract_digest": contract["contract_digest"],
            "recipient": EXECUTOR, "authority_ref": "grant-0001", "idempotency_key": "stdio-v1-key",
            "business_task_ref": "task-v1", "task_revision": 1,
        }

        async def scenario() -> dict[str, Answer]:
            seen: dict[str, Answer] = {}
            # No option at all (the default) and the explicit option say the same thing.
            async with Client(stdio_client(self.parameters(REQUESTER))) as by_default:
                seen["default"] = await invoke(by_default, "uam_delivery_send", **legacy_arguments)
            async with Client(stdio_client(self.parameters(REQUESTER, legacy_deliver="no"))) as requester:
                seen["legacy"] = await invoke(requester, "uam_delivery_send", **legacy_arguments)
                seen["continuity"] = await invoke(requester, "uam_continuity_delivery_send", **self.send_arguments(contract))
            return seen

        seen = asyncio.run(scenario())
        self.assertEqual(seen["default"].body["error_code"], "LEGACY_DELIVER_DISABLED")
        self.assertEqual(seen["legacy"].body["error_code"], "LEGACY_DELIVER_DISABLED")
        self.assertFalse(seen["continuity"].is_error, seen["continuity"].text)


    def test_two_executor_processes_over_stdio_cannot_both_start_sibling_deliveries_of_one_task(self) -> None:
        first_contract = self.prepare()
        second_contract = MiddlewareGateway(str(self.world.registry_path), str(self.world.state)).create_contract(
            contract_v2("stdio-cont-task-2", PLAIN_ID, authoritative=["README.md"], allowed=["notes/stdio-2.md"]),
        )

        async def scenario() -> dict[str, Any]:
            seen: dict[str, Any] = {}
            async with AsyncExitStack() as stack:
                requester = await stack.enter_async_context(Client(stdio_client(self.parameters(REQUESTER))))
                first = await stack.enter_async_context(Client(stdio_client(self.parameters(EXECUTOR))))
                second = await stack.enter_async_context(Client(stdio_client(self.parameters(THIRD))))
                sent_first = await invoke(requester, "uam_continuity_delivery_send", **self.send_arguments(first_contract))
                sent_second = await invoke(requester, "uam_continuity_delivery_send", **self.send_arguments(
                    second_contract, recipient=THIRD, idempotency_key="stdio-cont-key-2",
                ))
                first_id, second_id = sent_first.body["delivery_id"], sent_second.body["delivery_id"]
                # Both executors ask at the same moment, each from its own process.
                racing = await asyncio.gather(
                    invoke(first, "uam_attempt_start", delivery_id=first_id),
                    invoke(second, "uam_attempt_start", delivery_id=second_id),
                )
                seen["racing"] = racing
                winner_client, winner_id, loser_client, loser_id = (
                    (first, first_id, second, second_id) if not racing[0].is_error else (second, second_id, first, first_id)
                )
                won = racing[0] if not racing[0].is_error else racing[1]
                attempt = won.body["attempts"][-1]
                seen["retry_while_active"] = await invoke(loser_client, "uam_attempt_start", delivery_id=loser_id)
                seen["end"] = await invoke(
                    winner_client, "uam_attempt_end", delivery_id=winner_id, attempt_ref=attempt["attempt_ref"],
                    fence=attempt["fence"], outcome="FAILED_BEFORE_EFFECT",
                )
                seen["retry_after_stop"] = await invoke(loser_client, "uam_attempt_start", delivery_id=loser_id)
                seen["winner_cannot_start_again"] = await invoke(winner_client, "uam_attempt_start", delivery_id=winner_id)
            return seen

        seen = asyncio.run(scenario())
        racing = seen["racing"]
        self.assertEqual(sorted(answer.is_error for answer in racing), [False, True], [answer.text for answer in racing])
        refused = next(answer for answer in racing if answer.is_error)
        self.assertEqual(refused.body["error_code"], "SAME_TASK_ATTEMPT_ACTIVE", refused.text)
        # The unchanged first-batch tool carries no structured details, and the message names no delivery.
        self.assertEqual(set(refused.body), {"error", "error_code"})
        self.assertNotIn("dlv-", refused.text)
        self.assertEqual(seen["retry_while_active"].body["error_code"], "SAME_TASK_ATTEMPT_ACTIVE")
        self.assertFalse(seen["end"].is_error, seen["end"].text)
        self.assertFalse(seen["retry_after_stop"].is_error, seen["retry_after_stop"].text)
        self.assertEqual(seen["retry_after_stop"].body["state"], "ATTEMPT_ACTIVE")
        self.assertEqual(seen["winner_cannot_start_again"].body["error_code"], "SAME_TASK_ATTEMPT_ACTIVE")


if __name__ == "__main__":
    unittest.main()
