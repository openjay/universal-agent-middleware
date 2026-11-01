"""Test support: one task-continuity MCP server over stdio for one principal.

This is NOT a product entry point. The product has no launcher yet because it has no real authority
verifier to wire in: a server started without one denies every effect, and nothing in this repository may
decide otherwise. This script exists so a test can start real operating-system processes, each acting as one
principal over the real stdio transport, against one state directory.

``--authority`` selects a test stand-in for the issuer/delegation contract; none of them is a policy:

* ``deny``       no verifier at all (the deny-all default of the control object);
* ``allow-all``  a verifier written for version 1: it allows everything and does not declare
                 ``request_version``, so a version-2 question must be refused before it is even put to it;
* ``port``       a version-2 verifier by port semantics only: it recomputes ``binding_digest`` from the request
                 and accepts a reference that starts with ``grant-``. It shows what the port carries.

``--legacy-deliver yes`` re-opens the bounded legacy entry (version-1 ``deliver`` and the start of version-1
deliveries). The successor profile closes it by default, and so does this launcher.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from universal_agent_middleware.adapters.mcp_task_continuity import create_task_continuity_server_for_gateway
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.task_continuity import compute_binding_digest
from universal_agent_middleware.task_control import AuthorityDecision, AuthorityRequest, AuthorityVerifier


class AllowAllAuthority:
    """Written for version 1: no ``request_version`` attribute."""

    def verify(self, request: AuthorityRequest) -> AuthorityDecision:
        return AuthorityDecision(True, "TEST_STAND_IN")


class BindingCheckingAuthority:
    request_version = 2

    def verify(self, request: AuthorityRequest) -> AuthorityDecision:
        if request.request_version >= 2 and request.binding_digest != compute_binding_digest(request):
            return AuthorityDecision(False, "BINDING_NOT_VERIFIABLE")
        if not request.authority_ref.startswith("grant-"):
            return AuthorityDecision(False, "REFERENCE_NOT_VALID")
        return AuthorityDecision(True, "TEST_STAND_IN")


def authority_for(name: str) -> AuthorityVerifier | None:
    if name == "allow-all":
        return AllowAllAuthority()
    if name == "port":
        return BindingCheckingAuthority()
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--principal", required=True)
    parser.add_argument("--authority", choices=("deny", "allow-all", "port"), default="deny")
    parser.add_argument("--endpoint-ref", default=None)
    parser.add_argument("--legacy-deliver", choices=("yes", "no"), default="no")
    args = parser.parse_args()
    gateway = MiddlewareGateway(args.registry, args.state_dir)
    server = create_task_continuity_server_for_gateway(
        gateway,
        principal=args.principal,
        authority=authority_for(args.authority),
        endpoint_ref=args.endpoint_ref,
        legacy_deliver=args.legacy_deliver == "yes",
    )
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
