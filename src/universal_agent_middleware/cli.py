from __future__ import annotations

import argparse
import fcntl
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

from .mcp import serve_stdio
from .openapi import schema as openapi_schema
from .policy import is_loopback_host
from .release_seal import SealError, create_seal, write_seal
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

    index = sub.add_parser("index", help="build or refresh the cross-process reality index")
    index.add_argument("--registry", required=True)
    index.add_argument("--state-dir", default=".state")
    index.add_argument("--scope", dest="scope_id", help="scope to index (omit for all discover scopes)")
    index.add_argument("--background", action="store_true", help="spawn detached index worker that survives caller exit")
    index.add_argument("--enrich-git", action="store_true", help="include git metadata enrichment")
    index.add_argument("--json", action="store_true", dest="json_output")

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

    release = sub.add_parser("release", help="build immutable release from current HEAD and activate")
    release.add_argument("--runtime-manifest", required=True)
    release.add_argument("--dry-run", action="store_true", help="build but do not activate or restart tunnel")
    release.add_argument("--json", action="store_true", dest="json_output")
    release.add_argument(
        "--acceptance", metavar="FILE",
        help="reviewed declaration of the exact workspace gaps this release may ship with "
             "(default: any unavailable workspace fails the release)")
    release.add_argument(
        "--expect-seal", metavar="FILE",
        help="sealed activation: never build, and refuse unless the release on disk is exactly the one "
             "sealed in FILE (see release-seal); checked before the service is stopped")

    seal = sub.add_parser(
        "release-seal",
        help="write a seal of an existing release (read-only: nothing is built, executed or activated)")
    seal.add_argument("--release-dir", required=True, help="the staged release directory to seal")
    seal.add_argument("--source-root", default=".", help="the Git checkout the release was built from")
    seal.add_argument("--commit", help="commit the release must have been built from (default: HEAD)")
    seal.add_argument("--out", required=True, help="seal file to create (never overwritten)")
    seal.add_argument("--json", action="store_true", dest="json_output")

    return p


def _spawn_detached_index_worker(
    *,
    registry: str,
    state_dir: str,
    scope_id: str | None,
    enrich_git: bool,
) -> int:
    """Launch a detached foreground index worker that survives CLI exit."""
    cmd = [
        sys.executable,
        "-m",
        "universal_agent_middleware.cli",
        "index",
        "--registry",
        registry,
        "--state-dir",
        state_dir,
        "--json",
    ]
    if scope_id:
        cmd.extend(["--scope", scope_id])
    if enrich_git:
        cmd.append("--enrich-git")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return proc.pid


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command in {"audit-migrate", "audit-init"}:
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
    if args.command == "index":
        from .gateway import MiddlewareGateway

        if args.background:
            scopes_path = Path(args.registry).parent / "root_scopes.json"
            scope_ids: list[str | None]
            if args.scope_id:
                scope_ids = [args.scope_id]
            else:
                if scopes_path.exists():
                    raw = json.loads(scopes_path.read_text(encoding="utf-8"))
                    scope_ids = [
                        s["scope_id"]
                        for s in raw.get("scopes", [])
                        if s.get("authority", {}).get("discover")
                        and s.get("authority", {}).get("index")
                    ]
                else:
                    scope_ids = [None]
            results = []
            for scope_id in scope_ids:
                pid = _spawn_detached_index_worker(
                    registry=args.registry,
                    state_dir=args.state_dir,
                    scope_id=scope_id,
                    enrich_git=args.enrich_git,
                )
                results.append({
                    "scope_id": scope_id or "*",
                    "status": "spawned",
                    "pid": pid,
                })
            payload = {"scopes": results, "count": len(results), "mode": "detached_process"}
            if args.json_output:
                print(json.dumps(payload, indent=2, ensure_ascii=False))
            else:
                for item in results:
                    print(f"  {item.get('scope_id')}: spawned (pid={item.get('pid')})")
            return 0

        gw = MiddlewareGateway(args.registry, args.state_dir)
        scopes = gw.scopes.list_scopes()
        target_ids = [args.scope_id] if args.scope_id else [
            s["scope_id"] for s in scopes if s["authority"].get("discover")
        ]
        if args.scope_id and args.scope_id not in target_ids:
            target_ids = [args.scope_id]
        results = []
        state_dir = Path(args.state_dir).expanduser().resolve(strict=False)
        for scope_id in target_ids:
            lock_path = state_dir / f"refresh-{scope_id}.lock"
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            fd = lock_path.open("a+b")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                results.append({"scope_id": scope_id, "status": "skipped",
                                "reason": "another index worker is running"})
                fd.close()
                continue
            try:
                results.append(gw.index_scope(
                    scope_id,
                    enrich_git=args.enrich_git,
                    background=args.background,
                ))
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                fd.close()
        payload = {"scopes": results, "count": len(results)}
        if args.json_output:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            for item in results:
                status = item.get("status", item.get("total_projects", "ok"))
                print(f"  {item.get('scope_id')}: {status}")
        return 0
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
    if args.command == "release-seal":
        try:
            seal = create_seal(Path(args.source_root).resolve(), Path(args.release_dir), commit=args.commit)
            digest = write_seal(Path(args.out), seal)
        except SealError as exc:
            print(f"release-seal refused: {exc}", file=sys.stderr)
            return 1
        summary = {"seal": str(Path(args.out).resolve()), "sha256": digest, "release_id": seal["release_id"],
                   "commit": seal["source"]["commit"], "package_files": len(seal["package_files"]),
                   "dependencies": len(seal["dependencies"])}
        print(json.dumps(summary, indent=2) if args.json_output else
              "\n".join(f"{key}: {value}" for key, value in summary.items()))
        return 0
    if args.command == "release":
        from .release import build_and_activate
        # Only a sealed run changes the call shape; the legacy invocation is passed through unchanged.
        sealed = {"seal_path": args.expect_seal} if args.expect_seal else {}
        result = build_and_activate(
            manifest_path=args.runtime_manifest,
            dry_run=args.dry_run,
            acceptance_path=args.acceptance,
            **sealed,
        )
        if args.json_output:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"release: {result['overall']} (accepted={result['accepted']}, exit={result['exit_code']})")
            if result.get("release_id"):
                print(f"  id: {result['release_id']}")
            if result.get("doctor_overall"):
                print(f"  doctor: {result['doctor_overall']}")
            for step in result.get("steps", []):
                print(f"  {step['name']}: {step['status']}")
        return result["exit_code"]
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
