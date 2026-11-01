"""The opt-in ``task-continuity`` product entry: its declared surface, its launch binding, its refusals, and the read-only profile it must leave alone.

Three layers:

* in process, over ``task_profile.build_task_profile_server`` and the SDK's ``mcp.Client``: the declared contract against the live tool list, deny-all by default, the
  pinned authority factory as the only way to allow an effect, and what a refused launch says;
* the command line: the argument rules of the module entry, the fact that ``uam mcp-sdk-stdio`` still offers only ``session-read``, and that the read-only process never loads a
  task module;
* real operating-system processes started the way a host starts them (``python -m universal_agent_middleware.task_profile``): the notice on stderr, deny-all over stdio, exit
  code 2 for a refusal, and the default profile process unchanged.

The only verifier here is ``consumer_authority_factory.py``, a TEST STAND-IN: not product, not an issuer, not a grant. It shows that the verifier port is the one way an effect is
allowed; it proves nothing about a real authority. Both sides of every connection are the SDK's own client and server, so nothing here shows that a particular harness can attach.
"""
from __future__ import annotations

import ast
import asyncio
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.mcpserver import MCPServer

import universal_agent_middleware
from universal_agent_middleware import __version__, cli, task_profile
from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
from universal_agent_middleware.adapters.mcp_task_continuity import TASK_CONTINUITY_TOOLS
from universal_agent_middleware.consumer import Refusal
from universal_agent_middleware.doctor import tool_contract
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.task_control import TaskControlError

from continuity_support import OWNER, TASK
from coordination_fixtures import contract_v2
from directory_fixtures import PLAIN_ID, WorldTestCase
from test_mcp_task_control import IDENTITY_ARGUMENTS, Answer, inspect_surface, invoke
from test_task_control import EXECUTOR, NEW_DOC, REQUESTER

TESTS = Path(__file__).resolve().parent
PACKAGE = Path(universal_agent_middleware.__file__).resolve().parent
STAND_IN = TESTS / "consumer_authority_factory.py"
STAND_IN_FACTORY = f"{STAND_IN}:stand_in_authority"
STAND_IN_SHA = hashlib.sha256(STAND_IN.read_bytes()).hexdigest()
TASK_STATE_DIRECTORIES = {"task-control", "results-v2", "artifacts"}
TASK_READ_TOOLS = {"uam_continuity_context_package", "uam_continuity_deliveries_for_task", "uam_delivery_get", "uam_delivery_inbox"}
# What a process that serves only the read-only profile must never have imported (the gateway's own stores, results_v2 and statefile, are shared and may be).
TASK_MODULES = {
    "task_profile", "task_control", "task_continuity", "task_continuity_control", "consumer", "consumer_cli", "harness_adapter",
    "adapters.mcp_task_control", "adapters.mcp_task_continuity",
}
ISOLATION_PROBE = """
import json, sys
import universal_agent_middleware.cli
from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
create_session_read_server(sys.argv[1], sys.argv[2])
prefix = "universal_agent_middleware."
print(json.dumps(sorted(name[len(prefix):] for name in sys.modules if name.startswith(prefix))))
"""
# The modules the entry may import: the accepted task code, the declared contract helper, the gateway, the SDK server type. Nothing of a trial (a ready barrier, a scope, a
# world, an activation, a local owner) is a product dependency.
ENTRY_MAY_IMPORT = {
    "__future__", "argparse", "asyncio", "json", "sys", "importlib", "typing", "mcp.server.mcpserver",
    "universal_agent_middleware", "universal_agent_middleware.adapters.mcp_task_continuity", "universal_agent_middleware.consumer",
    "universal_agent_middleware.consumer_cli", "universal_agent_middleware.doctor", "universal_agent_middleware.errors",
    "universal_agent_middleware.gateway", "universal_agent_middleware.runtime", "universal_agent_middleware.task_control",
}


def send_arguments(contract: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "contract_id": contract["contract_id"], "contract_digest": contract["contract_digest"], "recipient": EXECUTOR,
        "authority_ref": "grant-0001", "idempotency_key": "entry-key-1", "owner_ref": OWNER, "business_task_ref": TASK,
        "task_revision": 1, "data_scope_ref": "scope-entry-1",
    }
    arguments.update(overrides)
    return arguments


def legacy_arguments(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "contract_id": contract["contract_id"], "contract_digest": contract["contract_digest"], "recipient": EXECUTOR,
        "authority_ref": "grant-0001", "idempotency_key": "entry-v1-key", "business_task_ref": TASK, "task_revision": 1,
    }


def process_environment() -> dict[str, str]:
    """What a child needs to import the same build of the package as this test run (the SDK client passes only a few variables by itself)."""
    environment = {"PYTHONDONTWRITEBYTECODE": "1"}
    if "PYTHONPATH" in os.environ:
        environment["PYTHONPATH"] = os.environ["PYTHONPATH"]
    return environment


class EntryWorld(WorldTestCase):
    """A registry, a RootScope file and one stored contract, as the entry finds them on disk."""

    def setUp(self) -> None:
        super().setUp()
        self.world.write_registry()
        self.world.write_scope_file()
        self.registry = str(self.world.registry_path)
        self.state = str(self.world.state)
        gateway = MiddlewareGateway(self.registry, self.state)
        self.contract = gateway.create_contract(contract_v2("profile-entry", PLAIN_ID, authoritative=["README.md"], allowed=[NEW_DOC]))

    def launch(self, principal: str = REQUESTER, **options: Any) -> tuple[MCPServer, dict[str, Any]]:
        return task_profile.build_task_profile_server(registry=self.registry, state_dir=self.state, principal=principal, **options)

    @staticmethod
    def call(server: MCPServer, tool: str, **arguments: Any) -> Answer:
        async def once() -> Answer:
            async with Client(server) as client:
                return await invoke(client, tool, **arguments)

        return asyncio.run(once())

    def delivery_files(self) -> list[Path]:
        """Every stored delivery, version 1 and version 2."""
        root = Path(self.state) / "task-control"
        return sorted(root.glob("deliveries/dlv-*.json")) + sorted(root.glob("continuity/deliveries/dlv-*.json"))


class DeclaredSurfaceTests(EntryWorld):
    def test_the_declared_contract_is_the_live_tool_list_item_by_item(self) -> None:
        server, _ = self.launch()
        live = tool_contract(asyncio.run(server.list_tools()))
        declared = task_profile.declared_contract()
        self.assertEqual(task_profile.contract_differences(declared, live), {"missing": [], "unexpected": [], "changed": []})
        self.assertEqual((sorted(live), len(live)), (sorted(TASK_CONTINUITY_TOOLS), 11))
        surface = asyncio.run(inspect_surface(server))
        self.assertEqual({name for name, tool in surface.tools.items() if tool.annotations.read_only_hint is True}, TASK_READ_TOOLS)
        for name, tool in surface.tools.items():
            with self.subTest(tool=name):
                self.assertFalse(IDENTITY_ARGUMENTS & set(tool.input_schema.get("properties", {})), "a client can name who it is")

    def test_the_two_profiles_share_no_tool_and_each_has_its_own_declared_contract(self) -> None:
        read_only = json.loads((PACKAGE / "tool_contract.json").read_text(encoding="utf-8"))
        self.assertEqual(len(read_only), 20)
        self.assertEqual(set(read_only) & set(task_profile.declared_contract()), set())
        server = create_session_read_server(self.registry, self.state)
        surface = asyncio.run(inspect_surface(server))
        self.assertEqual(tool_contract(list(surface.tools.values())), read_only)
        for name, tool in surface.tools.items():
            with self.subTest(tool=name):
                self.assertEqual(
                    (tool.annotations.read_only_hint, tool.annotations.destructive_hint, tool.annotations.open_world_hint), (True, False, False))

    def test_a_difference_is_reported_by_name_never_by_count(self) -> None:
        declared = {"a": "1", "b": "2", "c": "3"}
        self.assertEqual(
            task_profile.contract_differences(declared, {"a": "1", "b": "9", "d": "4"}),
            {"missing": ["c"], "unexpected": ["d"], "changed": ["b"]},
        )

    def test_a_changed_declared_contract_refuses_to_serve(self) -> None:
        declared = task_profile.declared_contract()
        name = sorted(declared)[0]
        broken = {
            "a changed digest": {**declared, name: "0" * 64},
            "a missing tool": {key: value for key, value in declared.items() if key != name},
            "an unexpected tool": {**declared, "uam_extra_tool": "0" * 64},
        }
        for label, contract in broken.items():
            with self.subTest(label), mock.patch.object(task_profile, "declared_contract", return_value=contract):
                with self.assertRaises(Refusal) as caught:
                    self.launch()
                self.assertEqual(caught.exception.code, "TASK_PROFILE_CONTRACT_MISMATCH")

    def test_the_entry_depends_on_the_accepted_task_code_and_on_nothing_of_a_trial(self) -> None:
        tree = ast.parse((PACKAGE / "task_profile.py").read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                base = "universal_agent_middleware" if node.level else (node.module or "")
                imported.add(base if not node.level or not node.module else f"{base}.{node.module}")
        self.assertEqual(imported - ENTRY_MAY_IMPORT, set())


class LaunchBindingTests(EntryWorld):
    def test_a_default_launch_is_deny_all_and_says_what_it_is_bound_to(self) -> None:
        server, notice = self.launch()
        self.assertEqual(notice, {
            "uam_profile": "task-continuity", "uam_version": __version__, "transport": "stdio", "principal": REQUESTER,
            "identity": "OPERATOR_BOUND_LABEL_NOT_AUTHENTICATED", "authority": "DENY_ALL", "authority_factory_sha256": None,
            "legacy_deliver": False, "tools": 11,
        })
        refused = self.call(server, "uam_continuity_delivery_send", **send_arguments(self.contract))
        self.assertEqual((refused.is_error, refused.body["error_code"]), (True, "AUTHORITY_DENIED"))
        self.assertEqual(self.delivery_files(), [])
        legacy = self.call(server, "uam_delivery_send", **legacy_arguments(self.contract))
        self.assertEqual((legacy.is_error, legacy.body["error_code"]), (True, "LEGACY_DELIVER_DISABLED"))
        self.assertEqual(self.delivery_files(), [])

    def test_a_pinned_authority_factory_is_the_only_way_an_effect_is_allowed(self) -> None:
        server, notice = self.launch(authority_factory=STAND_IN_FACTORY, authority_factory_sha256=STAND_IN_SHA)
        self.assertEqual((notice["authority"], notice["authority_factory_sha256"], notice["legacy_deliver"]), ("PINNED_FACTORY", STAND_IN_SHA, False))
        sent = self.call(server, "uam_continuity_delivery_send", **send_arguments(self.contract))
        self.assertFalse(sent.is_error, sent.text)
        self.assertEqual(len(self.delivery_files()), 1)
        refused = self.call(server, "uam_continuity_delivery_send", **send_arguments(self.contract, authority_ref="not-a-grant", idempotency_key="entry-key-2"))
        self.assertEqual((refused.is_error, refused.body["error_code"]), (True, "AUTHORITY_DENIED"))
        self.assertIn("REFERENCE_NOT_VALID", refused.body["error"])
        self.assertEqual(len(self.delivery_files()), 1)
        # A verifier does not open the version-1 entry: it has no flag.
        legacy = self.call(server, "uam_delivery_send", **legacy_arguments(self.contract))
        self.assertEqual(legacy.body["error_code"], "LEGACY_DELIVER_DISABLED")

    def test_a_launch_the_entry_cannot_bind_exactly_is_refused_before_anything_is_served(self) -> None:
        refusals = {
            "a pin that does not match the file": ({"authority_factory": STAND_IN_FACTORY, "authority_factory_sha256": "0" * 64}, "AUTHORITY_FACTORY_SHA_MISMATCH"),
            "no pin": ({"authority_factory": STAND_IN_FACTORY}, "AUTHORITY_FACTORY_INCOMPLETE"),
            "a relative path": (
                {"authority_factory": "relative.py:stand_in_authority", "authority_factory_sha256": STAND_IN_SHA}, "AUTHORITY_FACTORY_INCOMPLETE"),
            "a callable the file does not have": (
                {"authority_factory": f"{STAND_IN}:nothing_here", "authority_factory_sha256": STAND_IN_SHA}, "AUTHORITY_FACTORY_CALLABLE_MISSING"),
        }
        for label, (options, code) in refusals.items():
            with self.subTest(label), self.assertRaises(Refusal) as caught:
                self.launch(**options)
            self.assertEqual(caught.exception.code, code)
        for principal in ("", "Not A Label!", "x" * 300):
            with self.subTest(principal=principal), self.assertRaises(TaskControlError) as refused:
                self.launch(principal)
            self.assertEqual(refused.exception.code, "INVALID_ARGUMENT")
        self.assertEqual(self.delivery_files(), [])

    def test_serve_announces_the_binding_on_stderr_and_then_serves_stdio(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(MCPServer, "run") as run, contextlib.redirect_stderr(stderr):
            code = task_profile.serve_task_profile(
                registry=self.registry, state_dir=self.state, principal=REQUESTER, endpoint_ref=None,
                authority_factory=None, authority_factory_sha256=None, authority_factory_arg=None,
            )
        self.assertEqual(code, 0)
        run.assert_called_once_with(transport="stdio")
        notice = json.loads(stderr.getvalue())
        self.assertEqual((notice["authority"], notice["identity"], notice["principal"]), ("DENY_ALL", task_profile.IDENTITY_STATEMENT, REQUESTER))

    def test_a_refused_launch_exits_2_and_prints_one_code_and_no_path(self) -> None:
        missing_registry = str(Path(self.world.root) / "no-such-registry.json")
        cases = {
            "pin mismatch": ({"authority_factory": STAND_IN_FACTORY, "authority_factory_sha256": "0" * 64}, "AUTHORITY_FACTORY_SHA_MISMATCH"),
            "bad principal": ({"principal": "Not A Label!"}, "INVALID_ARGUMENT"),
            "bad factory argument": (
                {"authority_factory": STAND_IN_FACTORY, "authority_factory_sha256": STAND_IN_SHA, "authority_factory_arg": "{"}, "JSONDecodeError"),
            "unreadable registry": ({"registry": missing_registry}, None),
        }
        for label, (overrides, code) in cases.items():
            options: dict[str, Any] = {
                "registry": self.registry, "state_dir": self.state, "principal": REQUESTER, "endpoint_ref": None,
                "authority_factory": None, "authority_factory_sha256": None, "authority_factory_arg": None,
            }
            options.update(overrides)
            stderr = io.StringIO()
            with self.subTest(label), mock.patch.object(MCPServer, "run") as run, contextlib.redirect_stderr(stderr):
                self.assertEqual(task_profile.serve_task_profile(**options), 2)
            run.assert_not_called()
            text = stderr.getvalue()
            self.assertTrue(text.startswith("task-profile: refused (") and text.endswith(")\n") and text.count("\n") == 1, text)
            if code is not None:
                self.assertEqual(text, f"task-profile: refused ({code})\n")
            self.assertNotIn(str(self.world.root), text)


class CommandLineTests(EntryWorld):
    def test_uam_mcp_sdk_stdio_still_offers_only_session_read_and_cannot_start_the_task_tools(self) -> None:
        args = cli.parser().parse_args(["mcp-sdk-stdio", "--registry", self.registry])
        self.assertEqual(args.profile, "session-read")
        for argv in (["--profile", "task-continuity"], ["--profile", "task-control"], ["--principal", "p"], ["--authority-factory", "/f.py:x"]):
            stderr = io.StringIO()
            with self.subTest(argv=argv), contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as stopped:
                cli.parser().parse_args(["mcp-sdk-stdio", "--registry", self.registry, *argv])
            self.assertEqual(stopped.exception.code, 2)

    def test_the_entry_requires_its_launch_binding_and_knows_no_legacy_or_other_profile_flag(self) -> None:
        required = ["--registry", self.registry, "--state-dir", self.state, "--principal", REQUESTER]
        args = task_profile.parser().parse_args(required)
        self.assertEqual((args.registry, args.state_dir, args.principal), (self.registry, self.state, REQUESTER))
        for name in ("endpoint_ref", "authority_factory", "authority_factory_sha256", "authority_factory_arg", "runtime_manifest"):
            self.assertIsNone(getattr(args, name), name)
        for left_out in range(0, len(required), 2):
            argv = required[:left_out] + required[left_out + 2:]
            stderr = io.StringIO()
            with self.subTest(left_out=required[left_out]), contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as stopped:
                task_profile.parser().parse_args(argv)
            self.assertEqual(stopped.exception.code, 2)
        for extra in (["--legacy-deliver"], ["--legacy-deliver", "yes"], ["--profile", "session-read"], ["--no-authority"]):
            stderr = io.StringIO()
            with self.subTest(extra=extra), contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as stopped:
                task_profile.parser().parse_args([*required, *extra])
            self.assertEqual(stopped.exception.code, 2)

    def test_main_serves_what_the_arguments_bind(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(MCPServer, "run") as run, contextlib.redirect_stderr(stderr):
            code = task_profile.main(["--registry", self.registry, "--state-dir", self.state, "--principal", EXECUTOR, "--endpoint-ref", "endpoint-one"])
        self.assertEqual(code, 0)
        run.assert_called_once_with(transport="stdio")
        self.assertEqual(json.loads(stderr.getvalue())["principal"], EXECUTOR)

    def test_a_process_that_serves_only_the_read_only_profile_never_loads_a_task_module(self) -> None:
        done = subprocess.run(
            [sys.executable, "-B", "-c", ISOLATION_PROBE, self.registry, self.state],
            capture_output=True, text=True, timeout=120, check=False, env={**os.environ, "UAM_RUNTIME_MANIFEST": ""},
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        loaded = set(json.loads(done.stdout))
        self.assertIn("adapters.mcp_sdk", loaded)
        self.assertEqual(loaded & TASK_MODULES, set())

    def test_building_the_gateway_or_the_read_only_server_creates_no_task_state(self) -> None:
        state = Path(self.world.root) / "fresh-state"
        state.mkdir()
        MiddlewareGateway(self.registry, str(state))
        create_session_read_server(self.registry, str(state))
        self.assertEqual({entry.name for entry in state.iterdir()} & TASK_STATE_DIRECTORIES, set())
        # The Task server makes its own directory and no other: results and artifacts wait for the first stored result.
        task_profile.build_task_profile_server(registry=self.registry, state_dir=str(state), principal=REQUESTER)
        self.assertEqual({entry.name for entry in state.iterdir()} & TASK_STATE_DIRECTORIES, {"task-control"})


class RealProcessTests(EntryWorld):
    """The entry as a host starts it: ``python -m universal_agent_middleware.task_profile ...`` in a new process."""

    sessions = 0

    def arguments(self, *extra: str, principal: str | None = REQUESTER) -> list[str]:
        arguments = ["-B", "-m", "universal_agent_middleware.task_profile", "--registry", self.registry, "--state-dir", self.state]
        if principal is not None:
            arguments += ["--principal", principal]
        return arguments + list(extra)

    def parameters(self, *extra: str, **options: Any) -> StdioServerParameters:
        return StdioServerParameters(command=sys.executable, args=self.arguments(*extra, **options), env=process_environment())

    def session(self, parameters: StdioServerParameters, scenario: Any) -> tuple[Any, str]:
        """Run ``scenario(client)`` against a new process and return its result with everything that process wrote to stderr."""
        self.sessions += 1
        errlog_path = Path(self.world.root) / f"stderr-{self.sessions}.txt"

        async def run() -> Any:
            with errlog_path.open("w+", encoding="utf-8") as errlog:
                async with Client(stdio_client(parameters, errlog=errlog)) as client:
                    return await scenario(client)

        outcome = asyncio.run(run())
        return outcome, errlog_path.read_text(encoding="utf-8")

    def test_a_started_process_lists_the_declared_tools_and_denies_by_default(self) -> None:
        async def scenario(client: Client) -> dict[str, Any]:
            listing = (await client.list_tools()).tools
            return {
                "contract": tool_contract(list(listing)),
                "sent": await invoke(client, "uam_continuity_delivery_send", **send_arguments(self.contract)),
                "legacy": await invoke(client, "uam_delivery_send", **legacy_arguments(self.contract)),
            }

        seen, stderr = self.session(self.parameters(), scenario)
        self.assertEqual(seen["contract"], task_profile.declared_contract())
        self.assertEqual((seen["sent"].is_error, seen["sent"].body["error_code"]), (True, "AUTHORITY_DENIED"))
        self.assertEqual((seen["legacy"].is_error, seen["legacy"].body["error_code"]), (True, "LEGACY_DELIVER_DISABLED"))
        self.assertEqual(self.delivery_files(), [])
        notice = json.loads(stderr.splitlines()[0])
        self.assertEqual(notice, {
            "uam_profile": "task-continuity", "uam_version": __version__, "transport": "stdio", "principal": REQUESTER,
            "identity": "OPERATOR_BOUND_LABEL_NOT_AUTHENTICATED", "authority": "DENY_ALL", "authority_factory_sha256": None,
            "legacy_deliver": False, "tools": 11,
        })
        self.assertNotIn(str(self.world.root), stderr)

    def test_a_started_process_with_a_pinned_factory_allows_what_the_verifier_allows_and_no_more(self) -> None:
        async def scenario(client: Client) -> dict[str, Answer]:
            return {
                "sent": await invoke(client, "uam_continuity_delivery_send", **send_arguments(self.contract)),
                "refused": await invoke(
                    client, "uam_continuity_delivery_send", **send_arguments(self.contract, authority_ref="x", idempotency_key="entry-key-9")),
                "legacy": await invoke(client, "uam_delivery_send", **legacy_arguments(self.contract)),
            }

        parameters = self.parameters("--authority-factory", STAND_IN_FACTORY, "--authority-factory-sha256", STAND_IN_SHA)
        seen, stderr = self.session(parameters, scenario)
        self.assertFalse(seen["sent"].is_error, seen["sent"].text)
        self.assertEqual(seen["refused"].body["error_code"], "AUTHORITY_DENIED")
        self.assertEqual(seen["legacy"].body["error_code"], "LEGACY_DELIVER_DISABLED")
        self.assertEqual(len(self.delivery_files()), 1)
        notice = json.loads(stderr.splitlines()[0])
        self.assertEqual((notice["authority"], notice["authority_factory_sha256"]), ("PINNED_FACTORY", STAND_IN_SHA))

    def test_refused_launches_exit_2_with_nothing_on_stdout_and_a_code_on_stderr(self) -> None:
        wrong_pin = ["--authority-factory", STAND_IN_FACTORY, "--authority-factory-sha256", "0" * 64]
        cases = {
            "wrong pin": (self.arguments(*wrong_pin), "task-profile: refused (AUTHORITY_FACTORY_SHA_MISMATCH)\n"),
            "bad principal": (self.arguments(principal="Not A Label!"), "task-profile: refused (INVALID_ARGUMENT)\n"),
            "no principal": (self.arguments(principal=None), None),
            "the legacy flag the entry does not have": (self.arguments("--legacy-deliver"), None),
            "a runtime manifest flag the entry does not have": (self.arguments("--runtime-manifest", "/m.json"), None),
        }
        for label, (arguments, expected) in cases.items():
            with self.subTest(label):
                done = subprocess.run(
                    [sys.executable, *arguments], capture_output=True, text=True, timeout=120, check=False,
                    env={**os.environ, "UAM_RUNTIME_MANIFEST": ""},
                )
                self.assertEqual((done.returncode, done.stdout), (2, ""), done.stderr)
                if expected is not None:
                    self.assertEqual(done.stderr, expected)
        self.assertEqual(self.delivery_files(), [])

    def test_the_default_profile_process_still_serves_the_twenty_read_only_tools_and_writes_no_task_state(self) -> None:
        read_only = json.loads((PACKAGE / "tool_contract.json").read_text(encoding="utf-8"))
        for profile in (None, "session-read"):
            state = Path(self.world.root) / f"state-{profile or 'default'}"
            state.mkdir()
            parameters = StdioServerParameters(
                command=sys.executable, env=process_environment(),
                args=["-B", "-m", "universal_agent_middleware.cli", "mcp-sdk-stdio", "--registry", self.registry, "--state-dir", str(state)]
                + (["--profile", profile] if profile else []),
            )

            async def scenario(client: Client) -> tuple[dict[str, str], set[bool]]:
                listing = (await client.list_tools()).tools
                return tool_contract(list(listing)), {tool.annotations.read_only_hint for tool in listing}

            with self.subTest(profile=profile):
                (contract, read_only_hints), _ = self.session(parameters, scenario)
                self.assertEqual(contract, read_only)
                self.assertEqual(read_only_hints, {True})
                self.assertEqual({entry.name for entry in state.iterdir()} & TASK_STATE_DIRECTORIES, set())


if __name__ == "__main__":
    unittest.main()
