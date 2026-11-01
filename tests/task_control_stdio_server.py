"""Test support: one task-control MCP server over stdio for one principal.

This is NOT a product entry point. The product has no launcher yet because it has no real authority
verifier to wire in: a server started without one denies every effect, and there is nothing in this
repository that may decide otherwise. This script exists so a test can start two real operating-system
processes, each acting as one principal over the real stdio transport, against one state directory.
``--authority allow-all`` is the test's stand-in for the issuer/delegation contract; it is not a policy.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from universal_agent_middleware.adapters.mcp_task_control import create_task_control_server_for_gateway
from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.task_control import AuthorityDecision, AuthorityRequest


class AllowAllAuthority:
    def verify(self, request: AuthorityRequest) -> AuthorityDecision:
        return AuthorityDecision(True, "TEST_STAND_IN")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--principal", required=True)
    parser.add_argument("--authority", choices=("deny", "allow-all"), default="deny")
    args = parser.parse_args()
    gateway = MiddlewareGateway(args.registry, args.state_dir)
    server = create_task_control_server_for_gateway(
        gateway,
        principal=args.principal,
        authority=AllowAllAuthority() if args.authority == "allow-all" else None,
    )
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
