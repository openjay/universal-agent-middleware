"""Replaceable Harness adapter seam for the resident Consumer (candidate, not adopted, not a Dispatcher).

The Consumer (``consumer.py``) decides *whether* a delivery may run (policy, authority, UAM's own gates). An adapter
decides only *how one job is executed* and reports one exact status. It never talks to UAM Task Control, never
starts or ends an attempt and never writes a result: those stay with the Consumer, so Task authority stays single.

An adapter is a port of three members, ``preflight()``, ``run(job, on_started=, keep_fds=)`` and the attributes
``name`` / ``is_agent`` / ``needs_session``. Nothing in the core imports a vendor SDK.

Adapters in this module, and what each one honestly is:

* ``LocalCommandAdapter``      a registered local command in its own process group. It is NOT an Agent: it exists so
                               the Consumer's mechanics (pickup, concurrency, crash recovery) can be run for real
                               without a model. Its label says ``local-command``.
* ``CodexAppServerAdapter``    the Codex App Server (JSON-RPC over stdio, the modern CLI's ``app-server``; not an MCP
                               server and not the legacy ``mcp-server`` that the compatibility shim still serves).
                               It needs an explicit CLI command prefix, an explicit confined ``CODEX_HOME`` and an
                               explicit session. Without a logged-in account it reports ``AUTH_REQUIRED`` and starts
                               no turn; it never reads, writes or asks for a credential.
* ``UnsupportedAdapter``       an exact, honest ``UNSUPPORTED`` / ``AUTH_REQUIRED`` for an interface that is not
                               available (Cursor CLI, Cursor SDK). It never fakes an agent task.

Limits, stated once: a process group is not a sandbox; an executor that outlives its Consumer keeps running and
keeps the target locks it inherited (``keep_fds`` reaches every process an adapter starts, the Codex App Server
included), and is picked up again by its outcome file, never executed twice; the status vocabulary below is the only
thing that crosses the seam.

What an agent adapter *observed* of the executor's actual session (the thread and cwd the App Server answered with,
the turn id, the spawn PID, whether the stop was confirmed by a PID read-back) travels as ``HarnessOutcome.binding``,
separate from what was only declared (the session and cwd of the rule). The Consumer keeps it in its journal, in the
attempt's outcome file and in the record of the submitted result; UAM's own result record has no field for it, and it
is a local observation, not an authenticated identity.

'Stopped' is a claim that only an observation can make. For the Codex App Server ``HarnessOutcome.stopped`` is True only
when the process table was read before and after the close, the first read is shown to have been made while the server
itself still ran, no recorded process is still there and the server's own group is gone. A table that cannot be read is
not an empty table; a table whose read is not shown to have been made while the server ran (the server is found exited
right after it) is not an inventory of what it started: a child in a group of its own is reparented out of the tree once
the server is gone, and what is left is empty or only the dead root. A recorded PID that now runs another command line is
not shown gone either (an ``exec`` keeps the PID). The outcome is then ``UNKNOWN`` with ``stopped=False``, the server has
been closed all the same, and the identities that were recorded travel in ``binding``. The Consumer reads them back and
settles once every one is gone, except after a table that could not be read or one whose read is not shown to have covered
a live server: the identities are then not known to be all of them, and no later read-back lifts that.
"""
from __future__ import annotations

import copy
import json
import os
import queue
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

DONE = "DONE"
FAILED = "FAILED"
REFUSED = "REFUSED"          # the adapter would not start the job (a precondition is missing); nothing ran
UNSUPPORTED = "UNSUPPORTED"  # the interface does not exist here; nothing ran
AUTH_REQUIRED = "AUTH_REQUIRED"  # the interface exists and needs a credential nobody here may create or read
UNKNOWN = "UNKNOWN"          # something ran and the adapter cannot say how it ended or that it stopped
STATUSES = frozenset({DONE, FAILED, REFUSED, UNSUPPORTED, AUTH_REQUIRED, UNKNOWN})

OUTCOME_SCHEMA = "uam-consumer-outcome-v1"
CLIENT_NAME = "uam-consumer"
CLIENT_VERSION = "0.1-candidate"
_SAFE_PATH = "/usr/bin:/bin"
_CODEX_PATH = "/opt/homebrew/bin:/usr/bin:/bin"
_DENY_SERVER_REQUEST = {"code": -32000, "message": "the UAM consumer declines every request a server makes of it"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


# --- the port ---------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class HarnessJob:
    """Everything an adapter may know about one job. ``cwd`` and ``session`` are stated, never guessed."""

    delivery_id: str
    attempt_ref: str
    fence: int
    contract_id: str
    workspace_id: str
    business_task_ref: str
    owner_ref: str
    cwd: str
    session: str | None
    worker: str | None
    objective: str
    authoritative_paths: tuple[str, ...]
    allowed_change_paths: tuple[str, ...]
    verification_commands: tuple[str, ...]
    job_dir: str
    deadline_seconds: float

    @property
    def outcome_path(self) -> Path:
        return Path(self.job_dir) / "outcome.json"

    def public(self) -> dict[str, Any]:
        """What a worker is told (a file, never an argument list): references, paths and the objective."""
        return {
            "delivery_id": self.delivery_id, "attempt_ref": self.attempt_ref, "fence": self.fence,
            "contract_id": self.contract_id, "workspace_id": self.workspace_id,
            "business_task_ref": self.business_task_ref, "owner_ref": self.owner_ref, "cwd": self.cwd,
            "objective": self.objective, "authoritative_paths": list(self.authoritative_paths),
            "allowed_change_paths": list(self.allowed_change_paths),
            "verification_commands": list(self.verification_commands),
            "outcome_file": str(self.outcome_path), "deadline_seconds": self.deadline_seconds,
        }


@dataclass(frozen=True)
class ExecutorHandle:
    """Where the executor lives, so a restarted Consumer can tell whether it is still there (never to signal it blindly).

    ``binding`` is empty at first. An agent adapter announces the same handle again, with ``binding`` filled, once the
    executor's *actual* session is known (see ``HarnessOutcome.binding``); the latest announcement wins.
    """

    kind: str
    pid: int
    pgid: int
    started_at: str
    binding: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class HarnessOutcome:
    """One exact status. ``binding`` holds only what the adapter itself *observed* of the executor's actual session
    (for the Codex App Server: the thread id and cwd the server answered with, the turn id, the spawn PID); never what
    was declared. It is persisted with the outcome, the journal and the submitted record; it is not an authenticated
    identity, and UAM's own result record has no field for it."""

    status: str
    code: str
    detail: str
    stopped: bool       # the adapter KNOWS no member of the executor is left
    executor: str       # declared label, not an authenticated identity
    risks: tuple[str, ...] = ()
    started_at: str | None = None
    ended_at: str | None = None
    binding: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"unknown status {self.status!r}")

    @property
    def nothing_ran(self) -> bool:
        """The adapter knows no executor did any work: a refusal, an unavailable interface, a missing credential."""
        return self.status in (REFUSED, UNSUPPORTED, AUTH_REQUIRED) or self.code == "SPAWN_FAILED"


class HarnessAdapter(Protocol):
    name: str
    is_agent: bool
    needs_session: bool

    def preflight(self) -> tuple[str, str] | None:
        """``None`` when a job could run, else ``(status, code)``; asked before an attempt is started."""

    def run(
        self, job: HarnessJob, *, on_started: Callable[[ExecutorHandle], None], keep_fds: Sequence[int],
    ) -> HarnessOutcome:
        """Execute one job. ``on_started`` is called once the executor exists (and again, same identity, when its actual
        session is known); ``keep_fds`` stay open in every process the adapter starts for the job."""


# --- helpers shared by adapters and workers -----------------------------------------------------------------------------


def atomic_write_json(path: Path, payload: Mapping[str, Any], *, mode: int = 0o600) -> None:
    """Write-then-rename with fsync of the file and its directory: a reader sees the old file or the whole new one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    data = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def write_outcome(
    path: str | Path, *, delivery_id: str, attempt_ref: str, status: str, executor: str, note: str = "",
    risks: Iterable[str] = (), started_at: str | None = None, ended_at: str | None = None, before_effect: bool = False,
    binding: Mapping[str, Any] | None = None,
) -> None:
    """What a worker calls last: its own, durable statement about the job. Survives the death of its Consumer.

    ``before_effect`` is written only by the Consumer, for a job it knows never ran (a refusal, a missing credential).
    ``binding`` is what the adapter observed of the executor's actual session (see ``HarnessOutcome``).
    """
    if status not in (DONE, FAILED):
        raise ValueError("a worker outcome is DONE or FAILED")
    atomic_write_json(Path(path), {
        "schema": OUTCOME_SCHEMA, "delivery_id": delivery_id, "attempt_ref": attempt_ref, "status": status,
        "executor": executor, "note": note[:500], "unresolved_risks": [str(item)[:300] for item in risks],
        "started_at": started_at, "ended_at": ended_at or utc_now(), "before_effect": bool(before_effect),
        "binding": dict(binding) if binding else None,
    })


def read_outcome(path: str | Path, *, delivery_id: str, attempt_ref: str) -> dict[str, Any] | None:
    """The outcome file if it exists, parses and names exactly this delivery and attempt; ``None`` otherwise."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("schema") != OUTCOME_SCHEMA:
        return None
    if data.get("delivery_id") != delivery_id or data.get("attempt_ref") != attempt_ref:
        return None
    if data.get("status") not in (DONE, FAILED) or not isinstance(data.get("executor"), str):
        return None
    return data


def group_alive(pgid: int) -> bool:
    """Whether any process of the group exists. A group this user may not signal still counts as alive."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def terminate_group(pgid: int, *, grace: float = 5.0, reaper: subprocess.Popen[Any] | None = None) -> bool:
    """SIGTERM, wait, SIGKILL, wait. ``True`` only when no member of the group is left (a zombie leader is reaped)."""
    for signal_number, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, 5.0)):
        try:
            os.killpg(pgid, signal_number)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if reaper is not None:
                reaper.poll()
            if not group_alive(pgid):
                return True
            time.sleep(0.05)
    if reaper is not None:
        reaper.poll()
    return not group_alive(pgid)


def process_table(*, strict: bool = False) -> dict[int, dict[str, Any]]:
    """``pid -> {ppid, pgid, command}`` of every process, from one ``ps`` read (no assumption about names or arguments).

    The default reads whatever ``ps`` printed, so a failed ``ps`` gives an empty table: fine for finding a process to
    record, wrong for deciding that nothing runs. ``strict=True`` is for that second use (a decision that *lifts* a
    hold): ``ps`` failing, timing out or printing no process at all raises ``OSError`` instead of reading as 'gone'.
    """
    try:
        done = subprocess.run(
            ["/bin/ps", "-axo", "pid=,ppid=,pgid=,command="], capture_output=True, text=True, check=False, timeout=15,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.SubprocessError as exc:
        if strict:
            raise OSError(f"the process table could not be read: {type(exc).__name__}") from exc
        raise
    table: dict[int, dict[str, Any]] = {}
    for line in done.stdout.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) >= 3 and all(part.isdigit() for part in parts[:3]):
            table[int(parts[0])] = {"ppid": int(parts[1]), "pgid": int(parts[2]), "command": (parts[3] if len(parts) > 3 else "")[:300]}
    if strict and (done.returncode != 0 or not table):
        raise OSError(f"the process table could not be read: ps exit {done.returncode}, {len(table)} process(es) listed")
    return table


def process_tree(root_pid: int, *, strict: bool = False) -> list[dict[str, Any]]:
    """``root_pid`` and every descendant that exists now, each with the command line it was running.

    ``strict`` is ``process_table(strict=True)``: a table that cannot be read raises ``OSError`` instead of reading as 'the
    root is gone and has no children'."""
    table = process_table(strict=strict)
    found = [root_pid] if root_pid in table else []
    for pid in found:
        found += [child for child, info in table.items() if info["ppid"] == pid and child not in found]
    return [{"pid": pid, **table[pid]} for pid in found]


def still_running(seen: Sequence[Mapping[str, Any]], *, strict: bool = False) -> list[dict[str, Any]]:
    """Those of ``seen`` that are still there.

    By default a process is there if its PID exists now *with the same command line*: a reused PID is not the process that
    was seen. That is right for evidence and bookkeeping, where a wrong 'running' costs nothing.

    ``strict=True`` is for a decision that lifts a hold, and asks the other question: which of ``seen`` is *not shown gone*.
    A process table that cannot be read raises ``OSError`` (never an empty answer), and a recorded PID that exists with
    another command line stays in the answer, flagged ``command_changed``: a legitimate ``exec`` keeps the PID and the
    process, and without a birth identity sampled when it was recorded that cannot be told from a PID the system reused after
    the process left. What the PID runs now is not copied into the answer (it may be an unrelated process)."""
    table = process_table(strict=strict)
    found: list[dict[str, Any]] = []
    for item in seen:
        now = table.get(item["pid"])
        if now is None:
            continue
        if now["command"] == item["command"]:
            found.append(dict(item))
        elif strict:
            found.append({**item, "command_changed": True})
    return found


# --- adapter 1: a registered local command (NOT an agent) ----------------------------------------------------------------


@dataclass(frozen=True)
class CommandSpec:
    argv: tuple[str, ...]
    max_seconds: float = 600.0
    env: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.argv or not all(isinstance(item, str) and item for item in self.argv):
            raise ValueError("argv must be a non-empty list of strings")
        if not os.path.isabs(self.argv[0]):
            raise ValueError("argv[0] must be an absolute path: no PATH lookup decides what runs")
        if not (isinstance(self.max_seconds, (int, float)) and 0 < self.max_seconds <= 3_600):
            raise ValueError("max_seconds must be in (0, 3600]")
        if not all(isinstance(key, str) and isinstance(value, str) for key, value in self.env.items()):
            raise ValueError("env must map strings to strings")


class LocalCommandAdapter:
    """Run one registered command per job in its own process group. Not an Agent; labelled that way."""

    is_agent = False
    needs_session = False

    def __init__(self, workers: Mapping[str, CommandSpec], *, name: str = "local-command") -> None:
        self.name = name
        self._workers = dict(workers)

    def preflight(self) -> tuple[str, str] | None:
        return None if self._workers else (REFUSED, "NO_WORKER_REGISTERED")

    def known_worker(self, worker: str | None) -> bool:
        return worker in self._workers

    def run(
        self, job: HarnessJob, *, on_started: Callable[[ExecutorHandle], None], keep_fds: Sequence[int] = (),
    ) -> HarnessOutcome:
        label = f"local-command:{job.worker}"
        spec = self._workers.get(job.worker or "")
        if spec is None:
            return HarnessOutcome(REFUSED, "WORKER_NOT_REGISTERED", "no registered command has that name", True, label)
        job_dir = Path(job.job_dir)
        job_dir.mkdir(parents=True, exist_ok=True)
        job_file = job_dir / "job.json"
        atomic_write_json(job_file, job.public())
        env = {
            "PATH": _SAFE_PATH, "LANG": "en_US.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
            "UAM_JOB_FILE": str(job_file), "UAM_OUTCOME_FILE": str(job.outcome_path), **spec.env,
        }
        started_at = utc_now()
        with (job_dir / "stdout.txt").open("ab") as out, (job_dir / "stderr.txt").open("ab") as err:
            try:
                process = subprocess.Popen(
                    [*spec.argv, str(job_file)], cwd=job.cwd, env=env, stdin=subprocess.DEVNULL, stdout=out,
                    stderr=err, start_new_session=True, close_fds=True, pass_fds=tuple(keep_fds),
                )
            except OSError as exc:
                return HarnessOutcome(FAILED, "SPAWN_FAILED", type(exc).__name__, True, label, started_at=started_at)
        on_started(ExecutorHandle("process-group", process.pid, process.pid, started_at))
        limit = min(spec.max_seconds, job.deadline_seconds)
        try:
            exit_code = process.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            stopped = terminate_group(process.pid, reaper=process)
            return HarnessOutcome(
                FAILED if stopped else UNKNOWN, "EXECUTOR_TIMEOUT", f"no outcome within {limit:.0f}s", stopped, label,
                started_at=started_at, ended_at=utc_now(),
            )
        stopped = terminate_group(process.pid, grace=2.0, reaper=process)  # a leader that left children behind
        ended_at = utc_now()
        reported = read_outcome(job.outcome_path, delivery_id=job.delivery_id, attempt_ref=job.attempt_ref)
        common = {"stopped": stopped, "executor": label, "started_at": started_at, "ended_at": ended_at}
        if exit_code != 0:
            return HarnessOutcome(FAILED, f"EXECUTOR_EXIT_{exit_code}", "the command exited non-zero", **common)
        if reported is None:
            return HarnessOutcome(FAILED, "NO_VALID_OUTCOME", "exit 0 without a valid outcome file", **common)
        risks = tuple(str(item) for item in reported.get("unresolved_risks", ()))
        if reported["status"] != DONE:
            return HarnessOutcome(FAILED, "WORKER_REPORTED_FAILURE", str(reported.get("note", ""))[:200], risks=risks, **common)
        return HarnessOutcome(DONE, "WORKER_REPORTED_DONE", str(reported.get("note", ""))[:200], risks=risks, **common)


# --- adapter 2: the Codex App Server (JSON-RPC over stdio) ---------------------------------------------------------------


class JsonRpcError(Exception):
    def __init__(self, error: Mapping[str, Any]):
        super().__init__(f"{error.get('code')}: {error.get('message')}")
        self.code = error.get("code")
        self.message = str(error.get("message"))


@dataclass(frozen=True)
class CodexServerSpec:
    """How to reach the *modern* CLI's ``app-server``.

    ``argv`` is the explicit command prefix (for example the node binary plus the package's ``codex.js``). The
    ``/opt/homebrew/bin/codex`` compatibility shim is not assumed: it forwards only ``mcp-server`` to an old
    package and is not a path this seam depends on. ``codex_home`` and ``home`` confine what the child may
    read and write; the credential stores are forced to files inside ``codex_home`` so that no OS keychain
    is consulted.
    """

    argv: tuple[str, ...]
    codex_home: str
    home: str
    config_overrides: tuple[str, ...] = (
        'cli_auth_credentials_store="file"', 'mcp_oauth_credentials_store="file"', "analytics.enabled=false",
    )

    def __post_init__(self) -> None:
        if not self.argv or not os.path.isabs(self.argv[0]):
            raise ValueError("argv[0] must be an absolute path")
        if not (os.path.isabs(self.codex_home) and os.path.isabs(self.home)):
            raise ValueError("codex_home and home must be absolute")


def codex_version(spec: CodexServerSpec, *, timeout: float = 30.0) -> str | None:
    """Ask the CLI itself which version it is (discovery; nothing is installed, upgraded or configured)."""
    env = {"PATH": _CODEX_PATH, "HOME": spec.home, "CODEX_HOME": spec.codex_home, "LANG": "en_US.UTF-8"}
    try:
        done = subprocess.run(
            [*spec.argv, "--version"], env=env, capture_output=True, text=True, timeout=timeout, check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (done.stdout.strip() or None) if done.returncode == 0 else None


@dataclass(frozen=True)
class StopReport:
    """How one app-server ended, from two independent sources: what ``close()`` answered, and a read-back by PID.

    A recorded process is *not shown gone* while its PID exists now, whether it still runs the recorded command line or
    another one (``command_changed``: an ``exec`` keeps the PID; nothing recorded tells it from a reused PID). No
    command-line filter decides anything: the PIDs are the ones recorded while the server ran.

    The process table is read twice, before the server is closed (``observation``: which processes exist) and after it
    (``readback``: which of them are still there). A read that could not be made is recorded in ``observation_failure`` /
    ``readback_failure`` and is never read as 'nothing runs': the report is then not a confirmation. After an unavailable
    observation ``processes_seen`` is not known to hold every process; after an unavailable read-back it does.

    The first read is an inventory of what the server started only if it was made while the server itself still ran
    (``coverage``): its processes are found by their parent PID, and once the server has exited (a zombie, or reaped) a
    child that escaped into a group of its own is reparented out of the tree, so a read made then finds nothing or only
    the dead root and a read-back of that proves nothing. The server is asked right after the read; one found exited may
    have died before the read or while it was made, and which of the two cannot be told, so the read is not shown to have
    covered a live server. ``coverage_failure`` names that case; the report is then not a confirmation,
    ``processes_seen`` is not known to hold every process, and no later read-back lifts it.
    """

    spawn_pid: int
    close_returned_stopped: bool
    processes_seen: tuple[Mapping[str, Any], ...]
    still_running: tuple[int, ...]
    group_alive: bool
    observation_failure: str | None = None
    readback_failure: str | None = None
    command_changed: tuple[int, ...] = ()  # the part of ``still_running`` whose PID now runs another command line
    coverage_failure: str | None = None  # why the first read is not shown to have been made while the server ran

    @property
    def confirmed(self) -> bool:
        return (
            self.close_returned_stopped and self.observation_failure is None and self.readback_failure is None
            and self.coverage_failure is None and not self.still_running and not self.group_alive
        )

    def public(self) -> dict[str, Any]:
        report: dict[str, Any] = {
            "spawn_pid": self.spawn_pid, "close_returned_stopped": self.close_returned_stopped,
            "processes_seen": [dict(item) for item in self.processes_seen], "still_running": list(self.still_running),
            "group_alive": self.group_alive, "confirmed": self.confirmed,
            "observation": "UNAVAILABLE" if self.observation_failure is not None else "COMPLETE",
            "readback": "UNAVAILABLE" if self.readback_failure is not None else "COMPLETE",
            "coverage": "COVERED" if self.observation_failure is None and self.coverage_failure is None else "UNCOVERED",
            "command_changed": list(self.command_changed),
        }
        if self.observation_failure is not None:
            report["observation_failure"] = self.observation_failure
        if self.readback_failure is not None:
            report["readback_failure"] = self.readback_failure
        if self.coverage_failure is not None:
            report["coverage_failure"] = self.coverage_failure
        return report


def _failure_text(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {str(exc)[:100]}"


class CodexAppServerClient:
    """A JSON-RPC client over the app-server's stdio (one JSON object per line; no ``jsonrpc`` member)."""

    def __init__(
        self, spec: CodexServerSpec, *, cwd: str, io_log: Path | None = None, keep_fds: Sequence[int] = (),
    ) -> None:
        self._spec = spec
        self._cwd = cwd
        self._io_log = io_log
        self._keep_fds = tuple(keep_fds)  # inherited by the app-server: a lock held through them outlives the Consumer
        self._process: subprocess.Popen[str] | None = None
        self._pending: dict[int, queue.Queue[dict[str, Any]]] = {}
        self._next_id = 1
        self._send_lock = threading.Lock()
        self._log_lock = threading.Lock()
        self._condition = threading.Condition()
        self.notifications: list[dict[str, Any]] = []
        self.declined_server_requests: list[dict[str, Any]] = []
        self.stderr_lines: list[str] = []
        self.methods_sent: list[str] = []  # every JSON-RPC method that was actually written, in order
        self.tree_seen: list[dict[str, Any]] = []

    def __enter__(self) -> CodexAppServerClient:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @property
    def pid(self) -> int:
        assert self._process is not None
        return self._process.pid

    def start(self) -> None:
        argv = [*self._spec.argv, "app-server"]
        for override in self._spec.config_overrides:
            argv += ["-c", override]
        argv += ["--listen", "stdio://"]
        env = {
            "PATH": _CODEX_PATH, "HOME": self._spec.home, "CODEX_HOME": self._spec.codex_home, "LANG": "en_US.UTF-8",
        }
        self._process = subprocess.Popen(
            argv, cwd=self._cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, start_new_session=True, close_fds=True, pass_fds=self._keep_fds,
        )
        # The server exists from here on, and ``run`` reads an ``OSError`` out of ``start`` as 'nothing was started'
        # (SPAWN_FAILED): so nothing below may raise one.
        if self._io_log is not None:
            self._record_spawn(self._process.pid)
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _record_spawn(self, pid: int) -> None:
        """The spawn PID and the command it runs, so a later read-back needs no name filter.

        Evidence only: a record that cannot be made is a missing record, never a failed spawn and never a skipped close.
        A process table that cannot be read says so in the record (``command_unavailable``) instead of saying 'no command'."""
        entry: dict[str, Any] = {"pid": pid, "command": None}
        try:
            entry["command"] = process_table(strict=True).get(pid, {}).get("command")
        except (OSError, subprocess.SubprocessError) as exc:
            entry["command_unavailable"] = type(exc).__name__
        try:
            self._log("spawn", json.dumps(entry))
        except OSError:
            pass

    def initialize(self) -> dict[str, Any]:
        result = self.request("initialize", {
            "clientInfo": {"name": CLIENT_NAME, "title": None, "version": CLIENT_VERSION}, "capabilities": None,
        })
        self.notify("initialized")
        return result

    def request(self, method: str, params: Mapping[str, Any] | None = None, *, timeout: float = 30.0) -> Any:
        with self._send_lock:
            request_id = self._next_id
            self._next_id += 1
        box: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
        self._pending[request_id] = box
        message: dict[str, Any] = {"id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)
        try:
            reply = box.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError(f"{method}: no reply within {timeout:.0f}s") from None
        finally:
            self._pending.pop(request_id, None)
        if "error" in reply:
            raise JsonRpcError(reply["error"])
        return reply["result"]

    def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

    def wait_notification(
        self, predicate: Callable[[dict[str, Any]], bool], timeout: float,
    ) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        seen = 0
        with self._condition:
            while True:
                for message in self.notifications[seen:]:
                    if predicate(message):
                        return message
                seen = len(self.notifications)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._condition.wait(timeout=min(remaining, 0.5))

    def close(self) -> bool:
        """Stop the app-server (stdin closed, then the group signalled). ``True`` only when none of it is left."""
        process = self._process
        if process is None:
            return True
        try:
            if process.stdin is not None:
                process.stdin.close()
        except OSError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        return terminate_group(process.pid, grace=3.0, reaper=process)

    def observe_tree(self, *, strict: bool = False) -> list[dict[str, Any]]:
        """Record the app-server and every descendant that exists now (the MCP servers it starts live in their own groups).

        ``strict``: a process table that cannot be read raises ``OSError`` instead of recording nothing."""
        known = {item["pid"] for item in self.tree_seen}
        self.tree_seen += [item for item in process_tree(self.pid, strict=strict) if item["pid"] not in known]
        return self.tree_seen

    def has_exited(self) -> bool:
        """Whether the server has exited, asked of the child itself. ``Popen.poll()`` reaps a zombie, so a server that died
        and was never waited for reads as exited; while it answers ``None`` the PID is still this child's, never a reused
        one. Death is permanent: a server that has not exited now had not exited at any earlier moment either."""
        assert self._process is not None
        return self._process.poll() is not None

    def close_and_report(self) -> StopReport:
        """``close()`` plus the PID read-back; ``report.confirmed`` is the only honest 'it is stopped'.

        The server is closed whatever the process table says. A table that cannot be read is recorded as such
        (``observation_failure`` before the close, ``readback_failure`` after it) and is never an empty table that reads as
        'nothing runs': the report is then not a confirmation and the caller reports the executor as not confirmed stopped.

        The tree is read once, here, and it lists what the server started only if the server still ran while it was read.
        So the child is asked right after the read (``has_exited``). One that answers 'not exited' ran at the read, and
        the read stands. One found exited (a zombie that is still listed, or one that is gone and leaves an empty tree) is
        ``coverage_failure`` whatever the table holds, because it may have died before the read or while it was made and
        the two cannot be told apart; a table that merely contains the root proves nothing, since a dead root is listed
        until it is reaped."""
        observation_failure: str | None = None
        readback_failure: str | None = None
        coverage_failure: str | None = None
        try:
            self.observe_tree(strict=True)
            if self.has_exited():
                coverage_failure = (
                    "the server was found exited after its process tree was read; live coverage of that read cannot be established"
                )
        except OSError as exc:
            observation_failure = _failure_text(exc)
        finally:
            returned = self.close()
        alive: list[dict[str, Any]] = []
        try:
            alive = still_running(self.tree_seen, strict=True)
            deadline = time.monotonic() + 3.0
            while alive and time.monotonic() < deadline:
                time.sleep(0.1)
                alive = still_running(self.tree_seen, strict=True)
        except OSError as exc:
            readback_failure = _failure_text(exc)
        return StopReport(
            self.pid, returned, tuple(dict(item) for item in self.tree_seen), tuple(item["pid"] for item in alive),
            group_alive(self.pid), observation_failure, readback_failure,
            tuple(item["pid"] for item in alive if item.get("command_changed")), coverage_failure,
        )

    def _send(self, message: Mapping[str, Any]) -> None:
        assert self._process is not None and self._process.stdin is not None
        line = json.dumps(message, ensure_ascii=False)
        with self._send_lock:
            self._process.stdin.write(line + "\n")
            self._process.stdin.flush()
            if "method" in message:
                self.methods_sent.append(str(message["method"]))
        self._log("client->server", line)

    def _log(self, direction: str, line: str) -> None:
        if self._io_log is None:
            return
        entry = json.dumps({"at": utc_now(), "dir": direction, "line": line}, ensure_ascii=False)
        with self._log_lock, self._io_log.open("a", encoding="utf-8") as handle:
            handle.write(entry + "\n")

    def _read_stdout(self) -> None:
        assert self._process is not None and self._process.stdout is not None
        for raw in self._process.stdout:
            line = raw.rstrip("\n")
            self._log("server->client", line)
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if not isinstance(message, dict):
                continue
            if "id" in message and ("result" in message or "error" in message):
                box = self._pending.get(message["id"])
                if box is not None:
                    box.put(message)
            elif "id" in message and "method" in message:
                self.declined_server_requests.append({"method": message["method"], "id": message["id"]})
                self._send({"id": message["id"], "error": _DENY_SERVER_REQUEST})
            elif "method" in message:
                with self._condition:
                    self.notifications.append(message)
                    self._condition.notify_all()

    def _read_stderr(self) -> None:
        assert self._process is not None and self._process.stderr is not None
        for raw in self._process.stderr:
            self.stderr_lines.append(raw.rstrip("\n"))
            self._log("server-stderr", raw.rstrip("\n"))


class CodexAppServerAdapter:
    """One Codex thread and one turn per job, through the App Server; or a credential-free native MCP tool call."""

    is_agent = True
    needs_session = True

    def __init__(self, spec: CodexServerSpec, *, name: str = "codex-app-server", io_log: Path | None = None) -> None:
        self.name = name
        self._spec = spec
        self._io_log = io_log

    # discovery and the native MCP entry (no model, no credential) ---------------------------------------------------

    def probe(self, *, cwd: str) -> dict[str, Any]:
        """Discovery only: the version the CLI reports and whether the confined home holds a logged-in account.

        ``stop`` is the PID read-back of this one App Server (see ``StopReport``); ``methods_sent`` what was written to it."""
        client = CodexAppServerClient(self._spec, cwd=cwd, io_log=self._io_log)
        client.start()
        try:
            init = client.initialize()
            account = client.request("account/read", {"refreshToken": False})
            client.observe_tree()
        except BaseException:
            client.close()
            raise
        stop = client.close_and_report()
        return {
            "version": codex_version(self._spec), "initialize": init, "account": account,
            "methods_sent": list(client.methods_sent), "stop": stop.public(),
        }

    def call_native_mcp_tool(
        self, *, cwd: str, mcp_servers: Mapping[str, Mapping[str, Any]], calls: Sequence[tuple[str, str, Mapping[str, Any]]],
    ) -> dict[str, Any]:
        """Through the App Server's own MCP client: start an ephemeral thread whose config names ``mcp_servers``,
        list their status, and call each ``(server, tool, arguments)``. No turn is started, so no model and no
        account are involved; the thread is read-only with approvals set to ``never``.

        The answer carries the evidence a caller needs instead of a claim: the thread the server *answered* with (id and
        cwd as returned, compared with the cwd asked for), the methods actually sent (``NO_TURN_MCP_ONLY`` is derived from
        them) and ``stop``: the spawn PID, every process seen under it, what ``close()`` returned and a PID read-back."""
        client = CodexAppServerClient(self._spec, cwd=cwd, io_log=self._io_log)
        client.start()
        try:
            init = client.initialize()
            started = client.request("thread/start", {
                "cwd": cwd, "ephemeral": True, "sandbox": "read-only", "approvalPolicy": "never",
                "config": {"mcp_servers": {name: dict(spec) for name, spec in mcp_servers.items()}},
            }, timeout=60.0)
            facts = thread_facts(started, cwd)
            thread_id = started["thread"]["id"]
            statuses = {
                name: client.request("mcpServerStatus/list", {"threadId": thread_id, "serverName": name}, timeout=60.0)
                for name in mcp_servers
            }
            client.observe_tree()
            outcomes = [
                {"server": server, "tool": tool, "result": client.request("mcpServer/tool/call", {
                    "threadId": thread_id, "server": server, "tool": tool, "arguments": dict(arguments),
                }, timeout=60.0)}
                for server, tool, arguments in calls
            ]
        except BaseException:
            client.close()
            raise
        stop = client.close_and_report()
        methods = list(client.methods_sent)
        return {
            "version": codex_version(self._spec), "initialize": init, "thread_id": thread_id, "thread": facts,
            "mcp_server_status": statuses, "tool_calls": outcomes,
            "declined_server_requests": client.declined_server_requests,
            "methods_sent": methods, "NO_TURN_MCP_ONLY": not any(method.startswith(("turn/", "account/")) for method in methods),
            "stop": stop.public(),
        }

    # the adapter port -----------------------------------------------------------------------------------------------

    def preflight(self) -> tuple[str, str] | None:
        try:
            with CodexAppServerClient(self._spec, cwd=self._spec.home, io_log=self._io_log) as client:
                client.initialize()
                account = client.request("account/read", {"refreshToken": False})
        except (OSError, TimeoutError, JsonRpcError):
            return (UNSUPPORTED, "APP_SERVER_UNAVAILABLE")
        if account.get("account") is None and account.get("requiresOpenaiAuth"):
            return (AUTH_REQUIRED, "CODEX_LOGIN_REQUIRED")
        return None

    def run(
        self, job: HarnessJob, *, on_started: Callable[[ExecutorHandle], None], keep_fds: Sequence[int] = (),
    ) -> HarnessOutcome:
        label = self.name
        if not job.cwd:
            return HarnessOutcome(REFUSED, "CWD_REQUIRED", "no working directory was stated", True, label)
        if job.session is None:
            return HarnessOutcome(REFUSED, "SESSION_REQUIRED", "no session was stated; none is guessed", True, label)
        resume_id = job.session[len("resume:"):] if job.session.startswith("resume:") else None
        if job.session != "new" and not resume_id:
            return HarnessOutcome(REFUSED, "SESSION_INVALID", "a session is `new` or `resume:<thread id>`", True, label)
        started_at = utc_now()
        client = CodexAppServerClient(self._spec, cwd=job.cwd, io_log=self._io_log, keep_fds=keep_fds)
        try:
            client.start()
        except OSError as exc:
            return HarnessOutcome(FAILED, "SPAWN_FAILED", type(exc).__name__, True, label, started_at=started_at)
        # What was asked for and which task this is are declarations; ``observed`` receives only what the server answered.
        binding: dict[str, Any] = {
            "adapter": label,
            "declared": {"session": job.session, "cwd": job.cwd},
            "task": {
                "delivery_id": job.delivery_id, "attempt_ref": job.attempt_ref, "business_task_ref": job.business_task_ref,
                "contract_id": job.contract_id, "workspace_id": job.workspace_id,
            },
            "observed": {"spawn_pid": client.pid},
        }

        def announce() -> None:
            on_started(ExecutorHandle("codex-app-server", client.pid, client.pid, started_at, binding=copy.deepcopy(binding)))

        # The server exists from here on, so it is closed on every way out: the conversation's own answer, an exception no
        # one planned for, a failing ``on_started`` callback, an interrupt. Only the known protocol errors are a FAILED job;
        # any other exception leaves it unknown what the executor did, and the exception's type is all that is kept of it.
        try:
            announce()
            try:
                status, code, detail = self._converse(client, job, resume_id, binding["observed"], announce)
            except (OSError, TimeoutError, JsonRpcError, KeyError) as exc:
                status, code, detail = FAILED, "APP_SERVER_PROTOCOL_ERROR", type(exc).__name__
            except Exception as exc:
                status, code, detail = UNKNOWN, "APP_SERVER_UNEXPECTED_ERROR", type(exc).__name__
        finally:
            stop = client.close_and_report()
        # ``stop_report`` keeps the identity of every process seen (pid, ppid, pgid, command), not only how many: a later
        # life of the Consumer needs them to tell whether a child that outlived the server is still there.
        binding["observed"].update({
            "methods_sent": list(client.methods_sent), "stop_confirmed": stop.confirmed, "processes_seen": len(stop.processes_seen),
            "stop_report": stop.public(),
        })
        if not stop.confirmed:
            if stop.observation_failure or stop.readback_failure:
                why = ": the process table could not be read"
            elif stop.coverage_failure:
                why = ": it was found exited after its process tree was read"
            else:
                why = ""
            status, detail = UNKNOWN, f"{detail} (the app-server was not confirmed stopped{why})".strip()
        return HarnessOutcome(status, code, detail, stop.confirmed, label, started_at=started_at, ended_at=utc_now(), binding=binding)

    @staticmethod
    def _converse(
        client: CodexAppServerClient, job: HarnessJob, resume_id: str | None, observed: dict[str, Any],
        announce: Callable[[], None],
    ) -> tuple[str, str, str]:
        """One thread, one turn. Returns ``(status, code, detail)``; the caller stops the server and owns the lifecycle.

        ``observed`` is filled with what the server answered (thread id and cwd, turn id and status) and ``announce`` is
        called when the thread and the turn become known. No turn is sent unless the answered thread is the one stated
        (``resume:<id>``) and is bound to the task's directory: a declared session is never taken for the actual one."""
        client.initialize()
        account = client.request("account/read", {"refreshToken": False})
        if account.get("account") is None and account.get("requiresOpenaiAuth"):
            return AUTH_REQUIRED, "CODEX_LOGIN_REQUIRED", "no logged-in account; no credential is created or read"
        if resume_id is None:
            started = client.request("thread/start", {
                "cwd": job.cwd, "ephemeral": True, "sandbox": "workspace-write", "approvalPolicy": "never",
            }, timeout=60.0)
        else:
            started = client.request("thread/resume", {
                "threadId": resume_id, "cwd": job.cwd, "sandbox": "workspace-write", "approvalPolicy": "never",
            }, timeout=60.0)
        facts = thread_facts(started, job.cwd)
        observed.update({
            "thread_id": facts["thread_id"], "session_id": facts["session_id"],
            "thread_cwd": facts["response_cwd"] or facts["thread_cwd"], "cwd_matches": facts["cwd_matches"],
        })
        announce()
        thread_id = facts["thread_id"]
        if thread_id is None:
            return REFUSED, "THREAD_ID_MISSING", "the server did not name the thread it opened; no turn was sent"
        if resume_id is not None and thread_id != resume_id:
            return REFUSED, "SESSION_MISMATCH", "the server answered with another thread than the one stated; no turn was sent"
        if facts["response_cwd"] is None and facts["thread_cwd"] is None:
            return REFUSED, "THREAD_CWD_UNVERIFIED", "the server did not say where the thread is bound; no turn was sent"
        if not facts["cwd_matches"]:
            return REFUSED, "THREAD_CWD_MISMATCH", "the thread is bound to another directory than the task's; no turn was sent"
        turn_id = client.request("turn/start", {
            "threadId": thread_id, "cwd": job.cwd, "approvalPolicy": "never",
            "input": [{"type": "text", "text": _prompt(job), "text_elements": []}],
        }, timeout=60.0)["turn"]["id"]
        observed["turn_id"] = turn_id
        announce()
        done = client.wait_notification(
            lambda message: message.get("method") == "turn/completed"
            and message.get("params", {}).get("threadId") == thread_id
            and message.get("params", {}).get("turn", {}).get("id") == turn_id,
            timeout=job.deadline_seconds,
        )
        if done is None:
            observed["turn_status"] = "no-completion-seen"
            try:
                client.request("turn/interrupt", {"threadId": thread_id, "turnId": turn_id}, timeout=15.0)
            except (TimeoutError, JsonRpcError):
                pass
            return FAILED, "TURN_TIMEOUT", "the turn did not complete in time"
        status = done["params"]["turn"].get("status")
        observed["turn_status"] = status
        if status == "completed":
            return DONE, "TURN_COMPLETED", ""
        return FAILED, f"TURN_{str(status).upper()}", "the turn did not complete"


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def thread_facts(started: Mapping[str, Any], requested_cwd: str) -> dict[str, Any]:
    """What the App Server *answered* to ``thread/start`` or ``thread/resume``: the thread it opened and the directory
    it says the thread is bound to, compared (by real path) with the directory that was asked for. Anything the answer
    leaves out is ``None`` and is never replaced by what was requested."""
    thread = started.get("thread")
    thread = thread if isinstance(thread, Mapping) else {}
    response_cwd, thread_cwd = _text(started.get("cwd")), _text(thread.get("cwd"))
    reported = [value for value in (response_cwd, thread_cwd) if value is not None]
    return {
        "thread_id": _text(thread.get("id")), "session_id": _text(thread.get("sessionId")),
        "requested_cwd": requested_cwd, "response_cwd": response_cwd, "thread_cwd": thread_cwd,
        "cwd_matches": bool(reported) and all(os.path.realpath(value) == os.path.realpath(requested_cwd) for value in reported),
        "sandbox": started.get("sandbox"), "approval_policy": started.get("approvalPolicy"),
    }


def _prompt(job: HarnessJob) -> str:
    """References and instructions only: the job's own words, never a credential or another task's content."""
    allowed = ", ".join(job.allowed_change_paths) or "(none)"
    sources = ", ".join(job.authoritative_paths) or "(none)"
    return (
        f"Task {job.business_task_ref} (delivery {job.delivery_id}).\n"
        f"Objective: {job.objective}\n"
        f"You may create or change only these files, relative to the working directory: {allowed}.\n"
        f"Source files you may read: {sources}.\n"
        "Do not touch any other file, do not run git commit or push, do not use the network. "
        "When the files hold the result, reply DONE."
    )


# --- adapter 3: an interface that is not available -----------------------------------------------------------------------


class UnsupportedAdapter:
    """An exact, honest refusal: the interface is unavailable (``UNSUPPORTED``) or needs a credential (``AUTH_REQUIRED``)."""

    is_agent = True
    needs_session = False

    def __init__(self, name: str, status: str, code: str, detail: str) -> None:
        if status not in (UNSUPPORTED, AUTH_REQUIRED):
            raise ValueError("an unavailable interface is UNSUPPORTED or AUTH_REQUIRED")
        self.name = name
        self._status = status
        self._code = code
        self._detail = detail

    def preflight(self) -> tuple[str, str] | None:
        return (self._status, self._code)

    def run(
        self, job: HarnessJob, *, on_started: Callable[[ExecutorHandle], None], keep_fds: Sequence[int] = (),
    ) -> HarnessOutcome:
        return HarnessOutcome(self._status, self._code, self._detail, True, self.name)


def cursor_cli_adapter() -> UnsupportedAdapter:
    return UnsupportedAdapter(
        "cursor-cli", UNSUPPORTED, "CURSOR_CLI_UNAVAILABLE", "the owner stated that the Cursor CLI is unavailable; not retried",
    )


def cursor_sdk_adapter() -> UnsupportedAdapter:
    return UnsupportedAdapter(
        "cursor-sdk", AUTH_REQUIRED, "CURSOR_SDK_NEEDS_NEW_AUTH",
        "the SDK needs a credential that this slice neither creates, reads nor requests",
    )
