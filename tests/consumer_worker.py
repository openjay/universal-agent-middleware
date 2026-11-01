"""TEST WORKER for the Consumer's local-command adapter. Not an Agent, not product, no model.

It stands in for "an executor that does the delivery's work" so that the Consumer's mechanics (pickup, concurrency,
locks, crash recovery) can be run with real operating-system processes. Its behaviour is fixed by the environment of
the registered worker, never read out of the delivery's text:

``UAM_TEST_EVIDENCE_DIR``   where it records ``executions.log`` (one line per run) and ``<task>.start/.end.json``
``UAM_TEST_MODE``           ``write`` (default) | ``concat`` (writes, and appends every authoritative input it was
                            given, so a result shows the data flow) | ``fail`` (reports FAILED) |
                            ``crash`` (exit 7, no outcome) | ``noop`` (reports DONE without writing anything)
``UAM_TEST_BARRIER_DIR`` / ``UAM_TEST_BARRIER_N``   rendezvous: it finishes only once N workers are alive at the same time
``UAM_TEST_HOLD_FILE``      it waits until that file exists (a test holds the executor open while it kills things)
``UAM_TEST_MAX_SECONDS``    every wait is bounded (default 30); an executor left behind ends by itself
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from universal_agent_middleware.harness_adapter import DONE, FAILED, write_outcome

PATIENCE = float(os.environ.get("UAM_TEST_MAX_SECONDS", "30"))


def _append(path: Path, line: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, line.encode("utf-8"))
    finally:
        os.close(descriptor)


def _wait(condition, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return condition()


def main(argv: list[str]) -> int:
    job = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    task, started_ns = job["business_task_ref"], time.time_ns()
    evidence = Path(os.environ["UAM_TEST_EVIDENCE_DIR"])
    evidence.mkdir(parents=True, exist_ok=True)
    _append(evidence / "executions.log", f"{task} {job['attempt_ref']} pid={os.getpid()}\n")
    (evidence / f"{task}.start.json").write_text(json.dumps({
        "task": task, "pid": os.getpid(), "pgid": os.getpgrp(), "started_ns": started_ns, "cwd": os.getcwd(),
    }), encoding="utf-8")
    outcome = {"delivery_id": job["delivery_id"], "attempt_ref": job["attempt_ref"], "executor": f"test-worker:{task}"}

    barrier_dir, barrier_n = os.environ.get("UAM_TEST_BARRIER_DIR"), int(os.environ.get("UAM_TEST_BARRIER_N", "0"))
    if barrier_dir and barrier_n:
        directory = Path(barrier_dir)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{task}.arrived").write_text("here\n", encoding="utf-8")
        if not _wait(lambda: len(list(directory.glob("*.arrived"))) >= barrier_n, PATIENCE):
            write_outcome(job["outcome_file"], status=FAILED, note="BARRIER_NOT_REACHED", **outcome)
            return 0
    hold = os.environ.get("UAM_TEST_HOLD_FILE")
    if hold and not _wait(lambda: Path(hold).exists(), PATIENCE):
        write_outcome(job["outcome_file"], status=FAILED, note="HOLD_TIMEOUT", **outcome)
        return 0

    mode = os.environ.get("UAM_TEST_MODE", "write")
    if mode == "crash":
        return 7
    if mode == "fail":
        write_outcome(job["outcome_file"], status=FAILED, note="TEST_FAILURE_REQUESTED", **outcome)
        return 0
    if mode in ("write", "concat"):
        for relative in job["allowed_change_paths"]:
            body = f"result of {task}\n"
            if mode == "concat":  # data flow made visible: the output carries every authoritative input it was given
                for source in job["authoritative_paths"]:
                    body += f"--- {source} ---\n{(Path(job['cwd']) / source).read_text(encoding='utf-8')}"
            target = Path(job["cwd"]) / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
    ended_ns = time.time_ns()
    (evidence / f"{task}.end.json").write_text(json.dumps({"task": task, "ended_ns": ended_ns}), encoding="utf-8")
    write_outcome(job["outcome_file"], status=DONE, note="nothing written" if mode == "noop" else "written", **outcome)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
