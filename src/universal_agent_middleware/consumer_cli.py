"""Command line of the resident Consumer (candidate, not adopted): launch configuration only.

``python -m universal_agent_middleware.consumer_cli run --registry R --state-dir S --work-dir W --principal P
--endpoint-ref E --policy POLICY.json [--workers W.json] [--codex-spec C.json]
[--authority-factory /abs/file.py:callable --authority-factory-sha256 SHA]``

Everything that grants something is an input the operator owns: the policy file (own-user, not group/world writable),
the worker and Codex descriptors, and the authority factory, which is loaded only when its sha256 is pinned on the
command line. Without a factory the control object has no verifier and denies every effect. Exit codes: 0 stopped,
2 a launch input was refused, 75 another Consumer already holds the work directory.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import signal
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .consumer import Consumer, PolicySource, Refusal, SingleInstance, own_private_file
from .errors import UAMError
from .gateway import MiddlewareGateway
from .harness_adapter import (
    CodexAppServerAdapter,
    CodexServerSpec,
    CommandSpec,
    HarnessAdapter,
    LocalCommandAdapter,
    cursor_cli_adapter,
    cursor_sdk_adapter,
)
from .task_continuity_control import ContinuityControl
from .task_control import AuthorityVerifier


def load_authority(factory: str | None, expected_sha256: str | None, argument: str) -> AuthorityVerifier | None:
    """The replaceable authority port: ``/abs/file.py:callable`` pinned by sha256. Absent means deny-all."""
    if factory is None:
        return None
    path_text, _, callable_name = factory.rpartition(":")
    path = Path(path_text)
    if not path.is_absolute() or not callable_name or expected_sha256 is None:
        raise Refusal("AUTHORITY_FACTORY_INCOMPLETE")
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha256:
        raise Refusal("AUTHORITY_FACTORY_SHA_MISMATCH")
    spec = importlib.util.spec_from_file_location("uam_consumer_authority_factory", path)
    if spec is None or spec.loader is None:
        raise Refusal("AUTHORITY_FACTORY_UNLOADABLE")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # a pinned file that does not load is a refusal of the launch, not a crash
        raise Refusal("AUTHORITY_FACTORY_UNLOADABLE") from exc
    build = getattr(module, callable_name, None)
    if not callable(build):
        raise Refusal("AUTHORITY_FACTORY_CALLABLE_MISSING")
    verifier = build(**json.loads(argument))
    if not callable(getattr(verifier, "verify", None)):
        raise Refusal("AUTHORITY_FACTORY_NOT_A_VERIFIER")
    return verifier


def _load_json(path: str) -> Any:
    file = Path(path)
    own_private_file(file)
    return json.loads(file.read_text(encoding="utf-8"))


def build_adapters(workers_file: str | None, codex_file: str | None) -> dict[str, HarnessAdapter]:
    """Always registers the two Cursor interfaces as what they currently are; the others only when described."""
    adapters: dict[str, HarnessAdapter] = {"cursor-cli": cursor_cli_adapter(), "cursor-sdk": cursor_sdk_adapter()}
    if workers_file is not None:
        adapters["local-command"] = LocalCommandAdapter({
            name: CommandSpec(
                argv=tuple(raw["argv"]), max_seconds=float(raw.get("max_seconds", 60)), env=dict(raw.get("env", {})),
            )
            for name, raw in _load_json(workers_file)["workers"].items()
        })
    if codex_file is not None:
        raw = _load_json(codex_file)
        adapters["codex-app-server"] = CodexAppServerAdapter(
            CodexServerSpec(argv=tuple(raw["argv"]), codex_home=raw["codex_home"], home=raw["home"]),
            io_log=Path(raw["io_log"]) if raw.get("io_log") else None,
        )
    return adapters


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="uam-consumer", description=(__doc__ or "").split("\n", 1)[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="poll one principal's inbox (resident, or --once until idle)")
    for name in ("registry", "state-dir", "work-dir", "principal", "endpoint-ref"):
        run.add_argument(f"--{name}", required=True)
    run.add_argument("--policy", required=True, help="uam-consumer-policy-v1 JSON; without a matching rule nothing runs")
    run.add_argument("--workers", help="JSON registering the local commands a rule may name")
    run.add_argument("--codex-spec", help="JSON naming the Codex App Server command, CODEX_HOME and HOME")
    run.add_argument("--authority-factory", help="/abs/file.py:callable returning the AuthorityVerifier (default: deny all)")
    run.add_argument("--authority-factory-sha256")
    run.add_argument("--authority-factory-arg", default="{}")
    run.add_argument("--once", action="store_true", help="stop when a pass starts nothing and nothing is running")
    run.add_argument("--max-seconds", type=float, default=None)
    run.add_argument("--poll-seconds", type=float, default=1.0)
    run.add_argument("--max-concurrency", type=int, default=4)
    run.add_argument("--drain-seconds", type=float, default=30.0)
    run.add_argument("--backoff-seconds", type=float, default=30.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    work_dir = Path(args.work_dir).resolve()
    try:
        instance = SingleInstance(work_dir / "consumer.lock")
    except Refusal as refusal:
        print(f"consumer: refused ({refusal.code})", file=sys.stderr)
        return 75
    try:
        authority = load_authority(args.authority_factory, args.authority_factory_sha256, args.authority_factory_arg)
        gateway = MiddlewareGateway(args.registry, args.state_dir)
        consumer = Consumer(
            control=ContinuityControl(
                gateway.state_dir, contracts=gateway.contracts, results=gateway.results_v2, authority=authority,
                audit=gateway.audit, endpoint_ref=args.endpoint_ref,
            ),
            gateway=gateway, principal=args.principal, policy=PolicySource(Path(args.policy)),
            adapters=build_adapters(args.workers, args.codex_spec), work_dir=work_dir,
            max_concurrency=args.max_concurrency, backoff_seconds=args.backoff_seconds,
        )
    except (Refusal, OSError, ValueError, KeyError, TypeError, UAMError) as exc:
        print(f"consumer: refused ({exc.code if isinstance(exc, Refusal) else type(exc).__name__})", file=sys.stderr)
        instance.close()
        return 2
    stop = threading.Event()
    previous = {number: signal.signal(number, lambda *_: stop.set()) for number in (signal.SIGTERM, signal.SIGINT)}
    try:
        print(f"consumer: started pid={os.getpid()} consumer_id={consumer.consumer_id} principal={args.principal}", flush=True)
        if args.once:
            consumer.run_until_idle(poll_seconds=args.poll_seconds, max_seconds=args.max_seconds or 600.0)
        else:
            consumer.run(
                stop=stop, poll_seconds=args.poll_seconds, max_seconds=args.max_seconds, drain_seconds=args.drain_seconds,
            )
        print(f"consumer: stopped pid={os.getpid()} consumer_id={consumer.consumer_id}", flush=True)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        instance.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
