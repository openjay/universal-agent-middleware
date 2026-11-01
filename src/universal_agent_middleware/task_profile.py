"""Opt-in product entry of the ``task-continuity`` profile: ``python -m universal_agent_middleware.task_profile``.

The profile is the eleven tools of ``adapters.mcp_task_continuity`` (the seven ``task-control`` tools plus four continuity tools) served over MCP stdio. It is a separate
process a host has to start on purpose, like the Consumer (``python -m universal_agent_middleware.consumer_cli``). It is not a ``uam`` subcommand and not an option of
``uam mcp-sdk-stdio``, whose only profile stays ``session-read`` (``READ_ONLY_SESSION_PROFILE_V3``: 20 read-only tools, declared in ``tool_contract.json``); ``cli.py`` and the
service command that starts the tunnel do not know this module exists. The two profiles share no tool name, and each has its own declared contract
(``tool_contract.json`` and ``task_tool_contract.json``).

What the entry guarantees, and what it does not:

* **Explicit.** Nothing selects this profile by default and nothing starts it. ``--registry``, ``--state-dir`` and ``--principal`` are required: there is no default state
  directory, so task state is never written somewhere by accident.
* **A label, not an identity.** ``--principal`` is the label the operator binds when the process starts. Stdio carries no identity, so whoever can start this process with a
  given principal acts as that principal; the entry says so in the notice it prints on stderr and claims nothing more. A client can never name another principal in a request.
* **Deny-all by default.** Without ``--authority-factory`` there is no verifier and every effect is denied. A verifier enters only through the existing authority port: an absolute
  ``/file.py:callable`` pinned by ``--authority-factory-sha256`` (the same loader and flags as the Consumer command). Nothing in this package is an issuer, and nothing here turns
  a same-user pilot, a test stand-in or an activation file into one.
* **No legacy entry.** The version-1 ``uam_delivery_send`` stays closed; there is no flag that opens it.
* **Declared surface, checked before serving.** The live tool list must equal ``task_tool_contract.json`` (names, input and output schemas, annotations); otherwise the entry
  refuses to serve. Descriptions are not part of that digest.
* **Sealed when asked to be.** With ``--runtime-manifest`` the entry admits itself under that runtime before it loads any code a launch names: the package that is executing is the whole,
  current release the manifest selects (the check ``uam mcp-sdk-stdio`` makes), the registry is the runtime's, the state directory is outside every control-plane path (a state of its own,
  never the read-only service's), and the runtime's FROZEN latch is absent (any entry named ``FROZEN.json``, whatever it points at or holds, is the latch: ``os.path.lexists``, as in
  ``release.py``). The gateway then stamps its audit records with the release and refuses every audit write while the latch exists. A sealed launch is started with the release's own
  interpreter and ``-I -B``, as every launcher an installed release writes: ``-I`` keeps ``PYTHONPATH`` and the working directory out of ``sys.path``, so the executing package is the release's.
  Without the flag the launch is an unsealed development launch: the notice carries no ``runtime_release``, the audit records say ``development-unverified`` and no latch is wired.
* **Answers only a refusal code.** A refused launch prints ``task-profile: refused (CODE)`` and exits 2; it names no path and no value. The sealed admission answers
  ``TASK_PROFILE_RUNTIME_UNREADABLE``, ``TASK_PROFILE_RELEASE_NOT_SEALED``, ``TASK_PROFILE_REGISTRY_NOT_RUNTIMES``, ``TASK_PROFILE_STATE_NOT_DEDICATED`` or ``TASK_PROFILE_RUNTIME_FROZEN``.

Limits, stated so they are not mistaken for guarantees:

* The sha256 pin detects drift of the factory file. It does not defend against a process of the same operating-system user that replaces the file between the check and the
  load, nor does anything else here: stdio, the state directory and the audit log are same-user boundaries.
* The seal is checked when the process starts, as the read-only service checks it; only the FROZEN latch is looked at again, at every audit write. Like the pin, it detects drift and does
  not defend against a process of the same operating-system user.
* Without ``--runtime-manifest`` the entry does not verify that the installed package is a sealed release. If ``UAM_RUNTIME_MANIFEST`` is set in the environment the gateway
  applies its own rule as it does for every process: the registry and the state directory must be the manifest's, so that launch cannot name a dedicated ``--state-dir``. With
  ``--runtime-manifest`` the variable is not consulted.
* The audit chain of a dedicated state directory is not the one the production Doctor and supervisor verify: their health cycles cover the read-only service's state only.
* The tool list is checked, not the behaviour behind it; the behaviour is the task of ``tests/test_task_control.py`` and its neighbours.

Exit codes: 0 stdin closed normally, 2 refused before serving (including an unknown or missing argument).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from importlib import resources
from typing import Any

from mcp.server.mcpserver import MCPServer

from . import __version__
from .adapters.mcp_task_continuity import TASK_CONTINUITY_TOOLS, create_task_continuity_server_for_gateway
from .consumer import Refusal
from .consumer_cli import load_authority
from .doctor import tool_contract
from .errors import UAMError
from .gateway import MiddlewareGateway
from .runtime import AdmissionError, admit_dedicated_runtime, release_id
from .task_control import TaskControlError, validate_principal

PROFILE = "task-continuity"
CONTRACT_FILE = "task_tool_contract.json"
IDENTITY_STATEMENT = "OPERATOR_BOUND_LABEL_NOT_AUTHENTICATED"
EXIT_REFUSED = 2


def declared_contract() -> dict[str, str]:
    """The reviewed ``task_tool_contract.json``: exact tool name to the digest of its name, schemas and annotations."""
    raw = json.loads(resources.files(__package__).joinpath(CONTRACT_FILE).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not raw or not all(isinstance(key, str) and isinstance(value, str) for key, value in raw.items()):
        raise Refusal("TASK_PROFILE_CONTRACT_UNREADABLE")
    return raw


def contract_differences(declared: dict[str, str], actual: dict[str, str]) -> dict[str, list[str]]:
    """Exact names and digests, never a count: what is missing, unexpected or changed."""
    return {
        "missing": sorted(set(declared) - set(actual)),
        "unexpected": sorted(set(actual) - set(declared)),
        "changed": sorted(name for name in set(declared) & set(actual) if declared[name] != actual[name]),
    }


def admit_runtime(manifest: str | None, registry: str, state_dir: str) -> dict[str, Any] | None:
    """``None`` for an unsealed development launch; else the runtime this process is admitted under, or ``Refusal`` with ``TASK_PROFILE_<code>``."""
    if manifest is None:
        return None
    try:
        return admit_dedicated_runtime(manifest, registry, state_dir)
    except AdmissionError as refused:
        raise Refusal(f"TASK_PROFILE_{refused.code}") from None


def build_task_profile_server(
    *,
    registry: str,
    state_dir: str,
    principal: str,
    endpoint_ref: str | None = None,
    authority_factory: str | None = None,
    authority_factory_sha256: str | None = None,
    authority_factory_arg: str | None = None,
    runtime_manifest: str | None = None,
) -> tuple[MCPServer, dict[str, Any]]:
    """The checked server and the notice describing its binding. Raises ``Refusal``, ``TaskControlError`` or ``UAMError`` before anything is served.

    The runtime is admitted before the authority factory is loaded: a sealed launch does not execute a file it names until the release it runs from has been checked.
    """
    principal = validate_principal(principal)
    runtime = admit_runtime(runtime_manifest, registry, state_dir)
    authority = load_authority(authority_factory, authority_factory_sha256, authority_factory_arg or "{}")
    gateway = MiddlewareGateway(registry, state_dir, sealed_runtime=runtime)
    server = create_task_continuity_server_for_gateway(
        gateway, principal=principal, authority=authority, endpoint_ref=endpoint_ref, legacy_deliver=False,
    )
    actual = tool_contract(asyncio.run(server.list_tools()))
    differences = contract_differences(declared_contract(), actual)
    if any(differences.values()) or tuple(sorted(actual)) != tuple(sorted(TASK_CONTINUITY_TOOLS)):
        raise Refusal("TASK_PROFILE_CONTRACT_MISMATCH")
    notice = {
        "uam_profile": PROFILE,
        "uam_version": __version__,
        "transport": "stdio",
        "principal": principal,
        "identity": IDENTITY_STATEMENT,
        "authority": "DENY_ALL" if authority is None else "PINNED_FACTORY",
        "authority_factory_sha256": authority_factory_sha256 if authority is not None else None,
        "legacy_deliver": False,
        "tools": len(actual),
    }
    if runtime is not None:
        notice["runtime_release"] = release_id(runtime)
        notice["release_manifest_sha256"] = runtime["release_manifest_sha256"]
    return server, notice


def serve_task_profile(
    *,
    registry: str,
    state_dir: str,
    principal: str,
    endpoint_ref: str | None,
    authority_factory: str | None,
    authority_factory_sha256: str | None,
    authority_factory_arg: str | None,
    runtime_manifest: str | None = None,
) -> int:
    """Check, announce the binding on stderr, then serve MCP over stdio until stdin closes."""
    try:
        server, notice = build_task_profile_server(
            registry=registry, state_dir=state_dir, principal=principal, endpoint_ref=endpoint_ref,
            authority_factory=authority_factory, authority_factory_sha256=authority_factory_sha256,
            authority_factory_arg=authority_factory_arg, runtime_manifest=runtime_manifest,
        )
    except Refusal as refusal:
        print(f"task-profile: refused ({refusal.code})", file=sys.stderr)
        return EXIT_REFUSED
    except TaskControlError as exc:
        print(f"task-profile: refused ({exc.code})", file=sys.stderr)
        return EXIT_REFUSED
    except (UAMError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"task-profile: refused ({type(exc).__name__})", file=sys.stderr)
        return EXIT_REFUSED
    print(json.dumps(notice, sort_keys=True), file=sys.stderr)
    server.run(transport="stdio")
    return 0


def parser() -> argparse.ArgumentParser:
    entry = argparse.ArgumentParser(
        prog="python -m universal_agent_middleware.task_profile", allow_abbrev=False,
        description="Serve the eleven task-continuity tools over MCP stdio. Opt-in; deny-all until a pinned authority factory is given.",
    )
    entry.add_argument("--registry", required=True, help="the workspace registry file")
    entry.add_argument("--state-dir", required=True, help="the state directory (name a dedicated one to keep task state apart from the read-only service)")
    entry.add_argument("--principal", required=True, help="the label the operator binds to this process (not an authenticated identity)")
    entry.add_argument("--endpoint-ref", help="endpoint label named in authority questions")
    entry.add_argument("--authority-factory", help="/abs/file.py:callable returning the AuthorityVerifier (default: deny all)")
    entry.add_argument("--authority-factory-sha256", help="sha256 that pins the authority factory file")
    entry.add_argument("--authority-factory-arg", help="JSON object given to the factory (default {})")
    entry.add_argument(
        "--runtime-manifest",
        help="runtime manifest of the sealed release this process runs from: admit as that current release, keep the runtime's registry, "
             "a state directory outside its control plane and its FROZEN latch (default: an unsealed development launch)",
    )
    return entry


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return serve_task_profile(
        registry=args.registry, state_dir=args.state_dir, principal=args.principal, endpoint_ref=args.endpoint_ref,
        authority_factory=args.authority_factory, authority_factory_sha256=args.authority_factory_sha256,
        authority_factory_arg=args.authority_factory_arg, runtime_manifest=args.runtime_manifest,
    )


if __name__ == "__main__":
    sys.exit(main())
