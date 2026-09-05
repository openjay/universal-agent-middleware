from __future__ import annotations

import argparse
import json
import os
import secrets
import sys

from .gateway import MiddlewareGateway
from .mcp import serve_stdio
from .openapi import schema as openapi_schema
from .policy import is_loopback_host
from .server import Handler, UAMHTTPServer


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="uam", description="Universal Agent Middleware")
    sub = p.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run HTTP/OpenAPI and MCP adapters")
    serve.add_argument("--registry", required=True)
    serve.add_argument("--state-dir", default=".state")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--allow-non-loopback", action="store_true")

    stdio = sub.add_parser("mcp-stdio", help="serve MCP over stdio (custom impl)")
    stdio.add_argument("--registry", required=True)
    stdio.add_argument("--state-dir", default=".state")

    sdk_stdio = sub.add_parser("mcp-sdk-stdio", help="serve MCP over stdio (official SDK, session-read profile)")
    sdk_stdio.add_argument("--registry")
    sdk_stdio.add_argument("--state-dir")
    sdk_stdio.add_argument("--runtime-manifest")
    sdk_stdio.add_argument("--profile", default="session-read", choices=["session-read"])

    doctor = sub.add_parser("doctor", help="run unified health check")
    doctor.add_argument("--registry")
    doctor.add_argument("--state-dir")
    doctor.add_argument("--runtime-manifest")
    doctor.add_argument("--json", action="store_true", dest="json_output")
    doctor.add_argument("--no-canary", action="store_true")

    migrate = sub.add_parser("audit-migrate", help="create a new chain from an explicit offline evidence snapshot")
    migrate.add_argument("--snapshot", required=True)
    migrate.add_argument("--destination", required=True)
    migrate.add_argument("--expected-sha256", required=True)
    migrate.add_argument("--incident-receipt-id", required=True)
    initialize = sub.add_parser("audit-init", help="initialize an explicitly selected new ledger (never overwrite)")
    initialize.add_argument("--destination", required=True)

    sub.add_parser("token", help="generate a bearer token")
    openapi = sub.add_parser("openapi", help="print OpenAPI schema")
    openapi.add_argument(
        "--adapter", choices=["generic", "openai-actions"], default="generic"
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command in {"audit-migrate", "audit-init"}:
        from pathlib import Path
        from .audit import migrate_snapshot, initialize_chain
        try:
            if args.command == "audit-migrate":
                record = migrate_snapshot(Path(args.snapshot), Path(args.destination),
                    expected_sha256=args.expected_sha256, incident_receipt_id=args.incident_receipt_id)
            else:
                record = initialize_chain(Path(args.destination), action="chain_initialized", details={})
            print(json.dumps({"chain_id": record["chain_id"], "record_hash": record["record_hash"]}))
            return 0
        except Exception as exc:
            print(f"Audit operation refused: {exc}", file=sys.stderr)
            return 1
    if args.command in {"doctor", "mcp-sdk-stdio"}:
        manifest = args.runtime_manifest or os.environ.get("UAM_RUNTIME_MANIFEST")
        args.runtime_manifest = manifest
        if manifest:
            from .runtime import load_runtime, validate_paths, validate_release
            try:
                runtime = load_runtime(manifest)
                args.registry = args.registry or runtime["registry_file"]
                args.state_dir = args.state_dir or runtime["state_root"]
                if args.command != "doctor":
                    validate_paths(runtime, args.registry, args.state_dir)
                    validate_release(runtime)
                    os.environ["UAM_RUNTIME_MANIFEST"] = str(manifest)
            except Exception as exc:
                if args.command == "doctor":
                    print(json.dumps({"overall": "FROZEN", "severity": "P0", "checks": {
                        "runtime_paths": {"status": "FAIL", "severity": "P0", "reason": str(exc)}}}))
                else:
                    print(f"Runtime integrity failure: {exc}", file=sys.stderr)
                return 1
        args.state_dir = args.state_dir or ".state"
        if not args.registry:
            print("--registry or --runtime-manifest is required", file=sys.stderr)
            return 2
    if args.command == "token":
        print(secrets.token_urlsafe(48))
        return 0
    if args.command == "openapi":
        doc = openapi_schema()
        if args.adapter == "openai-actions":
            from .adapters.openai_actions import with_actions_extensions

            doc = with_actions_extensions(doc)
        print(json.dumps(doc, indent=2, ensure_ascii=False))
        return 0
    if args.command == "doctor":
        from .doctor import run_doctor

        report = run_doctor(
            args.registry, args.state_dir,
            include_canary=not args.no_canary,
            runtime_manifest=args.runtime_manifest,
        )
        if args.json_output:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            overall = report["overall"]
            print(f"UAM Doctor: {overall}")
            for name, check in report.get("checks", {}).items():
                status = check.get("status", "UNKNOWN")
                reason = check.get("reason", "")
                extra = f" — {reason}" if reason else ""
                print(f"  {name}: {status}{extra}")
        return 0 if report["overall"] == "READY" else 1
    if args.command == "mcp-stdio":
        return serve_stdio(MiddlewareGateway(args.registry, args.state_dir))
    if args.command == "mcp-sdk-stdio":
        from .adapters.mcp_sdk import create_session_read_server

        server = create_session_read_server(
            registry_path=args.registry,
            state_dir=args.state_dir,
        )
        server.run(transport="stdio")
        return 0
    if args.command == "serve":
        if not is_loopback_host(args.host) and not args.allow_non_loopback:
            print(
                "Refusing non-loopback bind without --allow-non-loopback",
                file=sys.stderr,
            )
            return 2
        token = os.environ.get("UAM_BEARER_TOKEN", "")
        if len(token) < 32:
            print(
                "UAM_BEARER_TOKEN must be set to at least 32 characters",
                file=sys.stderr,
            )
            return 2
        allowed_origins = {
            item.strip()
            for item in os.environ.get("UAM_ALLOWED_ORIGINS", "").split(",")
            if item.strip()
        }
        gateway = MiddlewareGateway(args.registry, args.state_dir)
        server = UAMHTTPServer(
            (args.host, args.port),
            Handler,
            gateway=gateway,
            bearer_token=token,
            allowed_origins=allowed_origins,
        )
        print(f"Universal Agent Middleware listening on http://{args.host}:{args.port}")
        server.serve_forever()
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
