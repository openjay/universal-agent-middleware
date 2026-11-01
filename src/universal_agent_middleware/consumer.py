"""Resident Consumer for UAM Task Control v2 deliveries (candidate, not adopted, not a Dispatcher).

A Consumer is the *recipient's* long-running client of the existing Task / Inbox / Attempt / Result surface
(``ContinuityControl``): it reads the inbox of one principal, asks an operator-owned policy whether a delivery may
run, starts the attempt, hands the job to a replaceable adapter (``harness_adapter.py``), reads the outcome back and
submits a ``uam-result-v2``. It adds no second task database, no scheduler and no queue: the delivery records stay in
UAM, and the only state of its own is an append-only journal and per-job files that let a restarted Consumer finish
or leave alone what an earlier one began.

Rules it keeps, each of them a refusal rather than a guess:

* default deny: a delivery with no matching rule is only journalled (``DENIED``), never started;
* ``cwd`` and ``session`` come from the rule and are never inferred; ``cwd`` must also be the workspace root UAM
  resolves for the contract, and an adapter that needs a session without one is refused (``SESSION_REQUIRED``);
* an adapter that is unsupported or needs a credential (``HOLD``) starts no attempt at all;
* only the contract's ``verification_commands`` that the rule allow-lists, verbatim, are run, by the Consumer, without a shell;
* a delivery that already has an attempt is never started again automatically (``PRIOR_ATTEMPT_NO_AUTOMATIC_REDO``):
  after a failure, after a crash, and while an old executor may still be running, that is a decision for the owner
  or for a new delivery, and UAM's own gates (``ATTEMPT_ACTIVE``, ``STOP_NOT_CONFIRMED``, ``BASELINE_CHANGED``, the
  same-task guard) stay in force underneath;
* an old executor is never signalled by a later Consumer life (a recorded process group id may have been reused);
* an executor that nothing has shown stopped is never reported to UAM as stopped because its root process group is gone.
  That covers an adapter that could not call it stopped (``stopped=False``) and an Agent whose ``EXECUTOR_ENDED`` was
  never journalled (the Consumer died first). The identities the adapter recorded are read back strictly, and until a
  complete read-back finds them all gone the attempt stays open (``WAITING_OLD_EXECUTOR`` / ``ATTEMPT_LEFT_OPEN``, one
  code per fact), so UAM's lease and ``STOP_NOT_CONFIRMED`` gates keep blocking every successor. A recorded PID that runs
  another command line is not shown gone (an ``exec`` keeps it), and what cannot be proven stays unknown. A process group
  that its handle declares to be the whole executor (``process-group``, the local command) keeps that meaning;
* a contract that declares ``expected_changes: ["none"]`` is a read-only task: files that stayed as the baseline are
  delivered as the existing ``no-change-v1`` result and a changed file is a ``FAILED``; every other contract keeps the
  artifact rules, so a job that changed nothing is still ``NO_ALLOWED_PATH_CHANGED``;
* a target path that another job holds is a ``BLOCKED(TARGET_BUSY)`` for that job only; other jobs run.

What it is not: not authority (the verifier port of ``ContinuityControl`` decides every effect; without one the
control object denies all), not an authenticated identity (the principal is launch configuration), not a sandbox
(an executor can write anywhere its user can; UAM only observes the paths of the contract), not a supervisor of
the host (it does not restart itself), and not a wake-up for a Harness whose GUI is closed.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shlex
import subprocess
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from .errors import UAMError, WorkspaceError
from .gateway import MiddlewareGateway
from .harness_adapter import (
    DONE,
    FAILED,
    ExecutorHandle,
    HarnessAdapter,
    HarnessJob,
    HarnessOutcome,
    atomic_write_json,
    group_alive,
    read_outcome,
    still_running,
    utc_now,
    write_outcome,
)
from .task_continuity import DELIVERY_SCHEMA_V2
from .task_continuity_control import ContinuityControl
from .task_control import ATTEMPT_ACTIVE, MAX_INBOX, STATE_ATTEMPT_ACTIVE, TaskControlError

POLICY_SCHEMA = "uam-consumer-policy-v1"
PATH_ABSENT = "path does not exist"
VERIFY_SECONDS = 60.0
_SAFE_PATH = "/usr/bin:/bin"

# journal phases ------------------------------------------------------------------------------------------------------
P_CONSUMER_STARTED = "CONSUMER_STARTED"
P_CONSUMER_STOPPING = "CONSUMER_STOPPING"
P_ERROR = "CONSUMER_ERROR"
P_POLICY_INVALID = "POLICY_INVALID"
P_INBOX_TRUNCATED = "INBOX_TRUNCATED"
P_DENIED = "DENIED"
P_HOLD = "HOLD"
P_BLOCKED = "BLOCKED"
P_WAITING = "WAITING_OLD_EXECUTOR"
P_LEFT_OPEN = "ATTEMPT_LEFT_OPEN"
P_INTENT = "ATTEMPT_INTENT"
P_INTENT_CLEARED = "INTENT_CLEARED"
P_STARTED = "ATTEMPT_STARTED"
P_EXECUTOR_STARTED = "EXECUTOR_STARTED"
P_EXECUTOR_ENDED = "EXECUTOR_ENDED"
P_RECONCILED = "STOP_RECONCILED"
P_PREPARED = "RESULT_PREPARED"
P_SUBMITTED = "RESULT_SUBMITTED"
P_ENDED = "ATTEMPT_ENDED"
_ADVISORY = frozenset({P_DENIED, P_HOLD, P_BLOCKED, P_WAITING, P_LEFT_OPEN})
# What is journalled while an executor that nothing has shown stopped is not proven gone (see ``_stop_state``). One code per
# fact: a recorded process that is there, a recorded PID that runs another command, a table that cannot be read now, an
# adapter that could not read it when it closed the executor, an adapter whose read is not shown to have covered a live
# server (the server was found exited right after it), an end record that was never written, and nothing recorded.
_NOT_PROVEN_STOPPED = {
    "ALIVE": (P_WAITING, "EXECUTOR_NOT_CONFIRMED_STOPPED"),
    "IDENTITY_CHANGED": (P_WAITING, "EXECUTOR_PID_IDENTITY_CHANGED"),
    "READBACK_UNAVAILABLE": (P_LEFT_OPEN, "EXECUTOR_STOP_READBACK_UNAVAILABLE"),
    "OBSERVATION_FAILED": (P_LEFT_OPEN, "EXECUTOR_STOP_OBSERVATION_FAILED"),
    "EXITED_BEFORE_OBSERVATION": (P_LEFT_OPEN, "EXECUTOR_EXITED_BEFORE_OBSERVATION"),
    "END_NOT_RECORDED": (P_LEFT_OPEN, "EXECUTOR_END_NOT_RECORDED"),
    "UNPROVABLE": (P_LEFT_OPEN, "EXECUTOR_STOP_UNPROVABLE"),
}


class Refusal(Exception):
    """Why a delivery is not started (or an input is not trusted): one exact code, journalled once, never guessed around."""

    def __init__(self, code: str, *, phase: str = P_DENIED, retry: float | None = None, **details: Any):
        super().__init__(code)
        self.code = code
        self.phase = phase
        self.retry = retry
        self.details = details


# --- policy: default deny ---------------------------------------------------------------------------------------------


def own_private_file(path: Path) -> None:
    """Operator-owned inputs (policy, workers, specs) must be the current user's and not writable by others."""
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise Refusal("INPUT_FILE_NOT_PRIVATE")


@dataclass(frozen=True)
class Rule:
    """What may run, and exactly where and how. Every selector that is set has to match."""

    adapter: str
    cwd: str | None = None
    worker: str | None = None
    session: str | None = None
    lease_seconds: int = 120
    max_seconds: float = 60.0
    verification_allowlist: tuple[str, ...] = ()
    owner_ref: str | None = None
    business_task_ref: str | None = None
    business_task_ref_prefix: str | None = None
    contract_id: str | None = None

    def __post_init__(self) -> None:
        if not (self.owner_ref or self.business_task_ref or self.business_task_ref_prefix or self.contract_id):
            raise Refusal("RULE_WITHOUT_SELECTOR")
        if not isinstance(self.lease_seconds, int) or isinstance(self.lease_seconds, bool) or not 10 <= self.lease_seconds <= 3600:
            raise Refusal("RULE_LEASE_OUT_OF_RANGE")
        if isinstance(self.max_seconds, bool) or not isinstance(self.max_seconds, (int, float)):
            raise Refusal("RULE_MAX_SECONDS_SHAPE")
        if not 0 < self.max_seconds <= self.lease_seconds - 5:
            raise Refusal("RULE_MAX_SECONDS_EXCEEDS_LEASE")

    def matches(self, item: Mapping[str, Any]) -> bool:
        exact = (
            (self.owner_ref, item.get("owner_ref")),
            (self.business_task_ref, item.get("business_task_ref")),
            (self.contract_id, item.get("contract_id")),
        )
        if any(wanted is not None and wanted != actual for wanted, actual in exact):
            return False
        prefix = self.business_task_ref_prefix
        return prefix is None or str(item.get("business_task_ref", "")).startswith(prefix)


_RULE_KEYS = frozenset(Rule.__dataclass_fields__)
_RULE_TEXT_KEYS = ("adapter", "cwd", "worker", "session", "owner_ref", "business_task_ref", "business_task_ref_prefix", "contract_id")


@dataclass(frozen=True)
class Policy:
    rules: tuple[Rule, ...] = ()

    def match(self, item: Mapping[str, Any]) -> tuple[int, Rule] | None:
        for index, rule in enumerate(self.rules):
            if rule.matches(item):
                return index, rule
        return None

    @staticmethod
    def parse(document: Any) -> Policy:
        if not isinstance(document, dict) or document.get("schema") != POLICY_SCHEMA or set(document) != {"schema", "rules"}:
            raise Refusal("POLICY_SHAPE")
        if not isinstance(document["rules"], list):
            raise Refusal("POLICY_SHAPE")
        rules = []
        for raw in document["rules"]:
            if not isinstance(raw, dict) or not set(raw) <= _RULE_KEYS or not isinstance(raw.get("adapter"), str):
                raise Refusal("POLICY_RULE_SHAPE")
            allowlist = raw.get("verification_allowlist", [])
            if (
                any(raw.get(key) is not None and not isinstance(raw[key], str) for key in _RULE_TEXT_KEYS)
                or not isinstance(allowlist, list) or not all(isinstance(command, str) for command in allowlist)
            ):
                raise Refusal("POLICY_RULE_SHAPE")
            rules.append(Rule(**{**raw, "verification_allowlist": tuple(allowlist)}))
        return Policy(tuple(rules))


class PolicySource:
    """The policy file, re-read when it changes. A file that cannot be trusted or parsed denies everything."""

    def __init__(self, path: Path | None):
        self._path = path
        self._stamp: tuple[int, int] | None = None
        self._policy = Policy()
        self.last_error: str | None = None

    def get(self) -> Policy:
        if self._path is None:
            return self._policy
        try:
            info = self._path.stat()
            stamp = (info.st_mtime_ns, info.st_size)
            if stamp != self._stamp:
                own_private_file(self._path)
                self._policy = Policy.parse(json.loads(self._path.read_text(encoding="utf-8")))
                self._stamp, self.last_error = stamp, None
        except (OSError, ValueError, TypeError, Refusal) as exc:
            self._policy, self._stamp = Policy(), None
            self.last_error = exc.code if isinstance(exc, Refusal) else type(exc).__name__
        return self._policy


# --- the journal and the target locks (not a task database) -----------------------------------------------------------


@dataclass
class Ledger:
    """What this Consumer's journal says about one delivery."""

    intent: dict[str, Any] | None = None
    live: dict[str, Any] | None = None
    handle: dict[str, Any] | None = None
    advisory: tuple[str, str] | None = None
    ended: dict[str, Any] | None = None  # the EXECUTOR_ENDED record of the live attempt: what its adapter said when it returned
    reconciled: bool = False  # a complete read-back already proved the unconfirmed executor gone (STOP_RECONCILED)


class Journal:
    """Append-only JSON lines, one fsync per record. It records what this Consumer did, never what UAM decided."""

    def __init__(self, path: Path, consumer_id: str):
        self._path = path
        self._consumer_id = consumer_id
        self._lock = threading.Lock()
        self._offset = 0
        self._count = 0
        self._ledgers: dict[str, Ledger] = {}
        path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, delivery_id: str | None, phase: str, **details: Any) -> dict[str, Any]:
        record = {
            "at": utc_now(), "consumer_id": self._consumer_id, "pid": os.getpid(), "delivery_id": delivery_id,
            "phase": phase, **details,
        }
        line = (json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
        with self._lock:
            descriptor = os.open(self._path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                size = os.fstat(descriptor).st_size
                if size and os.pread(descriptor, 1, size - 1) != b"\n":
                    line = b"\n" + line  # a torn last line from a crash must not swallow this record
                os.write(descriptor, line)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return record

    @staticmethod
    def _parse(chunk: bytes) -> list[dict[str, Any]]:
        """The complete, parsable records of a chunk of the file; a torn or foreign line is skipped, not interpreted."""
        found = []
        for line in chunk[: chunk.rfind(b"\n") + 1].splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict) and isinstance(record.get("phase"), str):
                found.append(record)
        return found

    def records(self) -> list[dict[str, Any]]:
        """The whole file, parsed afresh (for tests and tools; the Consumer itself reads incrementally)."""
        try:
            return self._parse(self._path.read_bytes())
        except FileNotFoundError:
            return []

    def count(self) -> int:
        with self._lock:
            self._refresh()
            return self._count

    def ledger(self, delivery_id: str) -> Ledger:
        """What this journal says about one delivery, folded incrementally: each record is read and applied once."""
        with self._lock:
            self._refresh()
            return replace(self._ledgers.get(delivery_id) or Ledger())

    def _refresh(self) -> None:  # the caller holds the thread lock
        try:
            with self._path.open("rb") as handle:
                handle.seek(self._offset)
                chunk = handle.read()
        except FileNotFoundError:
            return
        for record in self._parse(chunk):
            self._count += 1
            self._apply(record)
        self._offset += chunk.rfind(b"\n") + 1

    def _apply(self, record: dict[str, Any]) -> None:
        delivery_id = record.get("delivery_id")
        if not isinstance(delivery_id, str):
            return
        ledger = self._ledgers.setdefault(delivery_id, Ledger())
        phase = record["phase"]
        if phase == P_INTENT:
            ledger.intent = record
        elif phase == P_INTENT_CLEARED:
            ledger.intent = None
        elif phase == P_STARTED:
            ledger.live, ledger.intent, ledger.handle, ledger.ended, ledger.reconciled = record, None, None, None, False
        elif phase == P_EXECUTOR_STARTED and ledger.live and record.get("attempt_ref") == ledger.live["attempt_ref"]:
            ledger.handle = record["handle"]
        elif phase == P_EXECUTOR_ENDED and ledger.live and record.get("attempt_ref") == ledger.live["attempt_ref"]:
            ledger.ended = record
        elif phase == P_RECONCILED and ledger.live and record.get("attempt_ref") == ledger.live["attempt_ref"]:
            ledger.reconciled = True
        elif phase in (P_SUBMITTED, P_ENDED):
            ledger.live, ledger.handle, ledger.intent, ledger.ended, ledger.reconciled = None, None, None, None, False
        elif phase in _ADVISORY:
            ledger.advisory = (phase, str(record.get("code")))


class TargetLocks:
    """One ``flock`` per (workspace, path) a job may change.

    The lock is held through an inherited file descriptor: an executor that outlives its Consumer keeps it, and the
    parent releases its own copy by closing the descriptor only (an explicit unlock would release the child's too).
    """

    def __init__(self, directory: Path):
        self._directory = directory
        directory.mkdir(parents=True, exist_ok=True)

    def _path(self, workspace_id: str, path: str) -> Path:
        return self._directory / (hashlib.sha256(f"{workspace_id}\0{path}".encode()).hexdigest()[:40] + ".lock")

    def try_acquire(self, workspace_id: str, paths: Sequence[str]) -> list[int] | None:
        held: list[int] = []
        for path in sorted(set(paths)):
            descriptor = os.open(self._path(workspace_id, path), os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(descriptor)
                self.release(held)
                return None
            held.append(descriptor)
        return held

    @staticmethod
    def release(descriptors: Sequence[int]) -> None:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


class SingleInstance:
    """One Consumer per work directory: a second one refuses to start. Not inherited by any executor."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self._descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self._descriptor)
            raise Refusal("ALREADY_RUNNING") from None

    def close(self) -> None:
        os.close(self._descriptor)


def declares_no_change(contract: Mapping[str, Any]) -> bool:
    """A read-only task, in the contract's own words: ``expected_changes`` is exactly one item, ``none``.

    Neither an empty list nor any other wording is a declaration. Such a contract keeps the document-artifact rules (a job
    that changed nothing is ``NO_ALLOWED_PATH_CHANGED``), so ``no-change-v1`` cannot become a way around them."""
    expected = contract.get("expected_changes")
    return (
        isinstance(expected, list) and len(expected) == 1 and isinstance(expected[0], str)
        and expected[0].strip().lower() == "none"
    )


@dataclass(frozen=True)
class Admission:
    """A delivery that policy, adapter and contract all allow: what the attempt will run with."""

    index: int
    rule: Rule
    adapter: HarnessAdapter
    cwd: str
    contract: Mapping[str, Any]


# --- the Consumer --------------------------------------------------------------------------------------------------------


class Consumer:
    def __init__(
        self,
        *,
        control: ContinuityControl,
        gateway: MiddlewareGateway,
        principal: str,
        policy: PolicySource,
        adapters: Mapping[str, HarnessAdapter],
        work_dir: Path,
        max_concurrency: int = 4,
        backoff_seconds: float = 30.0,
        preflight_seconds: float = 60.0,
    ) -> None:
        self.control = control
        self.gateway = gateway
        self.principal = principal
        self.policy = policy
        self.adapters = dict(adapters)
        self.work_dir = work_dir
        self.consumer_id = uuid.uuid4().hex[:12]
        self.journal = Journal(work_dir / "journal.jsonl", self.consumer_id)
        self.locks = TargetLocks(work_dir / "target-locks")
        self.max_concurrency = max_concurrency
        self._backoff = backoff_seconds
        self._preflight_seconds = preflight_seconds
        self._inflight: set[str] = set()
        self._guard = threading.Lock()
        self._not_before: dict[str, float] = {}
        self._strikes: dict[str, int] = {}
        self._errors: dict[str, tuple[str, str]] = {}
        self._preflight: dict[str, tuple[float, tuple[str, str] | None]] = {}
        self._threads: list[threading.Thread] = []
        self._policy_error: str | None = None
        self._poll_error: tuple[str, str] | None = None
        self._truncated = False

    # -- life cycle -----------------------------------------------------------------------------------------------

    def run(
        self, *, stop: threading.Event, poll_seconds: float, max_seconds: float | None = None, drain_seconds: float = 0.0,
    ) -> None:
        """Resident mode: poll until ``stop`` is set (or ``max_seconds`` passed), then wait ``drain_seconds`` for running jobs."""
        self.journal.append(
            None, P_CONSUMER_STARTED, principal=self.principal, ppid=os.getppid(), max_concurrency=self.max_concurrency,
        )
        began = time.monotonic()
        while not stop.is_set():
            self._poll_safely()
            if max_seconds is not None and time.monotonic() - began >= max_seconds:
                break
            stop.wait(poll_seconds)
        self.stopping(drain_seconds=drain_seconds)

    def run_until_idle(self, *, poll_seconds: float, max_seconds: float) -> None:
        """Finite mode: poll until a whole pass wrote nothing to the journal and nothing runs (or ``max_seconds`` passed)."""
        self.journal.append(None, P_CONSUMER_STARTED, principal=self.principal, ppid=os.getppid(), mode="once")
        began = time.monotonic()
        while time.monotonic() - began < max_seconds:
            recorded = self.journal.count()
            self._poll_safely()
            self.wait_for_jobs(timeout=max(0.0, max_seconds - (time.monotonic() - began)))
            if self.journal.count() == recorded and not self._inflight:
                break
            time.sleep(poll_seconds)
        self.stopping(drain_seconds=0.0)

    def stopping(self, *, drain_seconds: float) -> None:
        self.wait_for_jobs(timeout=drain_seconds)
        with self._guard:
            running = sorted(self._inflight)
        self.journal.append(None, P_CONSUMER_STOPPING, still_running=running)

    def wait_for_jobs(self, *, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        for thread in list(self._threads):
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        self._threads = [thread for thread in self._threads if thread.is_alive()]
        return not self._threads

    # -- one pass over the inbox -----------------------------------------------------------------------------------

    def _poll_safely(self) -> None:
        """A resident Consumer outlives a failed pass (state busy, a transient I/O error); it says so once and tries again.

        A journal that cannot be written is different: ``append`` raises out of here and the process ends, because a
        Consumer that cannot record what it does must not go on doing it.
        """
        try:
            self.poll_once()
        except Exception as exc:
            error = (type(exc).__name__, str(exc)[:200])
            if error != self._poll_error:
                self._poll_error = error
                self.journal.append(None, P_ERROR, code=error[0], message=error[1], where="poll")
        else:
            self._poll_error = None

    def poll_once(self) -> list[str]:
        self.policy.get()  # reload the file; the rule itself is looked up per delivery
        if self.policy.last_error != self._policy_error:
            self._policy_error = self.policy.last_error
            if self._policy_error is not None:
                self.journal.append(None, P_POLICY_INVALID, code=self._policy_error)
        started = []
        self._threads = [thread for thread in self._threads if thread.is_alive()]
        inbox = self.control.inbox(self.principal, limit=MAX_INBOX)
        if bool(inbox.get("truncated")) != self._truncated:  # deliveries beyond the limit are not seen until others leave
            self._truncated = bool(inbox.get("truncated"))
            self.journal.append(None, P_INBOX_TRUNCATED, truncated=self._truncated, limit=MAX_INBOX)
        for item in inbox["items"]:
            delivery_id = item["delivery_id"]
            if time.monotonic() < self._not_before.get(delivery_id, 0.0):
                continue  # backing off after a refusal or an error
            with self._guard:
                if delivery_id in self._inflight or len(self._inflight) >= self.max_concurrency:
                    continue
                self._inflight.add(delivery_id)
            thread = threading.Thread(target=self._guarded, args=(item,), name=f"job-{delivery_id[-8:]}", daemon=True)
            self._threads.append(thread)
            thread.start()
            started.append(delivery_id)
        return started

    def _guarded(self, item: dict[str, Any]) -> None:
        delivery_id = item["delivery_id"]
        try:
            self._handle(item)
        except Exception as exc:  # one delivery's failure never stops the others
            error = (type(exc).__name__, str(exc)[:200])
            if self._errors.get(delivery_id) != error:  # the same error is journalled once, not once per poll
                self._errors[delivery_id] = error
                self.journal.append(delivery_id, P_ERROR, code=error[0], message=error[1])
            self._back_off(delivery_id)
        finally:
            with self._guard:
                self._inflight.discard(delivery_id)

    # -- per delivery ---------------------------------------------------------------------------------------------------

    def _handle(self, item: dict[str, Any]) -> None:
        delivery_id = item["delivery_id"]
        ledger = self.journal.ledger(delivery_id)
        if ledger.live is not None:
            self._finalize(delivery_id, ledger)
        elif ledger.intent is not None:
            self._adopt_or_clear(delivery_id, ledger)
        elif item.get("schema") != DELIVERY_SCHEMA_V2:
            self._record_refusal(delivery_id, ledger, Refusal("NOT_CONTINUITY_V2"))
        elif item["state"] != STATE_ATTEMPT_ACTIVE:  # an ATTEMPT_ACTIVE delivery with nothing of ours journalled is another executor's
            self._start(item, ledger)

    def _start(self, item: dict[str, Any], ledger: Ledger) -> None:
        delivery_id = item["delivery_id"]
        descriptors: list[int] | None = None
        try:
            view = self.control.get(self.principal, delivery_id=delivery_id)
            admission = self._admit(item, view)
            contract = admission.contract
            descriptors = self.locks.try_acquire(contract["workspace_id"], contract["allowed_change_paths"])
            if descriptors is None:
                raise Refusal("TARGET_BUSY", phase=P_BLOCKED, retry=0.0)
            self.journal.append(delivery_id, P_INTENT, lease_seconds=admission.rule.lease_seconds, rule_index=admission.index)
            try:
                started = self.control.start_attempt(
                    self.principal, delivery_id=delivery_id, lease_seconds=admission.rule.lease_seconds,
                )
            except TaskControlError as exc:
                self.journal.append(delivery_id, P_INTENT_CLEARED, code=exc.code)
                raise Refusal(exc.code, phase=P_BLOCKED, retry=5.0 if exc.code == "ATTEMPT_ACTIVE" else None) from exc
            self._run_attempt(item, view, admission, started["attempts"][-1], descriptors)
        except Refusal as refusal:
            self._record_refusal(delivery_id, ledger, refusal)
        finally:
            if descriptors is not None:
                self.locks.release(descriptors)  # an executor that outlives us still holds its inherited copies

    def _admit(self, item: dict[str, Any], view: Mapping[str, Any]) -> Admission:
        """Every reason not to start is raised here, before any attempt exists. Nothing is guessed to get past one."""
        if "content_withheld" in view:
            raise Refusal("CONTENT_WITHHELD", reason=view["content_withheld"].get("reason"))
        contract = view.get("contract")
        if not isinstance(contract, dict):
            raise Refusal("CONTRACT_UNREADABLE")
        if view.get("attempts"):
            raise Refusal("PRIOR_ATTEMPT_NO_AUTOMATIC_REDO", phase=P_BLOCKED)
        matched = self.policy.get().match(item)
        if matched is None:
            raise Refusal("NO_RULE")
        index, rule = matched
        adapter = self.adapters.get(rule.adapter)
        if adapter is None:
            raise Refusal("ADAPTER_NOT_REGISTERED", adapter=rule.adapter)
        try:
            cwd = self._checked_cwd(rule, contract)
            self._check_rule_against(rule, adapter, contract)
        except Refusal as refusal:
            refusal.details.setdefault("rule_index", index)
            raise
        held = self._preflight_of(rule.adapter, adapter)
        if held is not None:
            raise Refusal(f"{held[0]}:{held[1]}", phase=P_HOLD, adapter=rule.adapter, rule_index=index)
        return Admission(index, rule, adapter, cwd, contract)

    def _run_attempt(
        self, item: dict[str, Any], view: Mapping[str, Any], admission: Admission, attempt: Mapping[str, Any],
        descriptors: Sequence[int],
    ) -> None:
        delivery_id, contract, rule, adapter = item["delivery_id"], admission.contract, admission.rule, admission.adapter
        job_dir = self.work_dir / "jobs" / delivery_id / attempt["attempt_ref"]
        live = self.journal.append(
            delivery_id, P_STARTED, attempt_ref=attempt["attempt_ref"], fence=attempt["fence"],
            lease_expires_at=attempt["lease_expires_at"], adapter=rule.adapter, worker=rule.worker, cwd=admission.cwd,
            job_dir=str(job_dir), rule_index=admission.index,
            executor_kind="agent" if adapter.is_agent else "local-command-not-an-agent",
        )
        job = HarnessJob(
            delivery_id=delivery_id, attempt_ref=live["attempt_ref"], fence=live["fence"],
            contract_id=contract["contract_id"], workspace_id=contract["workspace_id"],
            business_task_ref=view["business_task_ref"], owner_ref=item["owner_ref"], cwd=admission.cwd,
            session=rule.session, worker=rule.worker, objective=str(contract.get("objective", "")),
            authoritative_paths=tuple(contract["authoritative_paths"]),
            allowed_change_paths=tuple(contract["allowed_change_paths"]),
            verification_commands=tuple(contract["verification_commands"]), job_dir=str(job_dir),
            deadline_seconds=float(rule.max_seconds),
        )

        def started(handle: ExecutorHandle) -> None:
            self.journal.append(delivery_id, P_EXECUTOR_STARTED, attempt_ref=job.attempt_ref, handle=asdict(handle))

        try:
            outcome = adapter.run(job, on_started=started, keep_fds=tuple(descriptors))
        except Exception as exc:  # the adapter broke; what it started is unknown, so it is not called stopped
            outcome = HarnessOutcome("UNKNOWN", "ADAPTER_RAISED", type(exc).__name__, False, adapter.name)
        self.journal.append(
            delivery_id, P_EXECUTOR_ENDED, attempt_ref=job.attempt_ref, status=outcome.status, code=outcome.code,
            stopped=outcome.stopped, executor=outcome.executor, binding=outcome.binding,
        )
        self._persist_outcome(job, outcome)
        self._finalize(delivery_id, self.journal.ledger(delivery_id))

    @staticmethod
    def _persist_outcome(job: HarnessJob, outcome: HarnessOutcome) -> None:
        """Make the adapter's observation durable: for an executor that cannot write one itself (in-process adapters,
        refusals) and where the worker's own file disagrees with what the adapter saw (a crash after writing DONE)."""
        if not outcome.stopped:
            return
        reported = read_outcome(job.outcome_path, delivery_id=job.delivery_id, attempt_ref=job.attempt_ref)
        if reported is not None and (reported["status"] == DONE) == (outcome.status == DONE):
            return
        write_outcome(
            job.outcome_path, delivery_id=job.delivery_id, attempt_ref=job.attempt_ref,
            status=DONE if outcome.status == DONE else FAILED, executor=outcome.executor, note=outcome.code,
            risks=outcome.risks, started_at=outcome.started_at, ended_at=outcome.ended_at, before_effect=outcome.nothing_ran,
            binding=outcome.binding,
        )

    # -- recovery and settlement (one path, from durable facts) ---------------------------------------------------------

    def _finalize(self, delivery_id: str, ledger: Ledger) -> None:
        """Settle an attempt of this journal from files and process state only: the same code after a crash as after a run."""
        live, handle = ledger.live, ledger.handle
        assert live is not None
        job_dir = Path(live["job_dir"])
        outcome = read_outcome(job_dir / "outcome.json", delivery_id=delivery_id, attempt_ref=live["attempt_ref"])
        if handle is not None and group_alive(int(handle["pgid"])):
            self._note(delivery_id, P_WAITING, "EXECUTOR_STILL_RUNNING", ledger, pgid=handle["pgid"])
            return
        if not self._stop_reconciled(delivery_id, live, ledger):
            return  # its adapter could not call the executor stopped and nothing proves it gone: the attempt stays open
        if outcome is None and handle is None and (job_dir / "job.json").exists():
            self._note(delivery_id, P_LEFT_OPEN, "EXECUTOR_UNKNOWN", ledger, detail="a job was written but no executor was recorded")
        elif outcome is None and handle is None:
            self._end(delivery_id, live, "FAILED_BEFORE_EFFECT", "NO_EXECUTOR_WAS_STARTED")
        elif outcome is None:
            self._end(delivery_id, live, "STOPPED", "EXECUTOR_GONE_NO_OUTCOME")
        elif outcome["status"] != DONE:
            kind = "FAILED_BEFORE_EFFECT" if outcome.get("before_effect") else "FAILED"
            self._end(delivery_id, live, kind, str(outcome.get("note") or "WORKER_REPORTED_FAILURE"))
        else:
            self._submit(delivery_id, live, outcome)

    @staticmethod
    def _stop_state(ledger: Ledger) -> tuple[str, dict[str, Any]] | None:
        """What the journal knows about an executor that nothing has shown stopped, read back now.

        ``None``: nothing says it was not stopped, so the ordinary rules apply. That is an adapter that confirmed the stop
        (``stopped=True``), and an executor that was never announced, and a handle that declares its process group to be the
        whole executor (``process-group``, the local command) with no end record. Otherwise ``(state, facts)``:

        * ``END_NOT_RECORDED``: an Agent was announced and ``EXECUTOR_ENDED`` was never journalled (the Consumer died
          first): no stop report exists, and what the Agent started besides its root process was never recorded;
        * ``OBSERVATION_FAILED``: its adapter could not read the process table when it closed the executor, so the
          identities it recorded are not known to be all of them and no later read-back can lift this;
        * ``EXITED_BEFORE_OBSERVATION``: its adapter found the server exited right after it read the process table, so the
          read is not shown to have been made while the server ran (the server may have exited before the read or while
          it was made): what the server started (a child in a group of its own is reparented out of its tree once the
          server is gone) may be missing from the identities, which may be empty or only the dead root. Those are not a
          basis for 'gone': no later read-back, however complete, can lift this;
        * ``READBACK_UNAVAILABLE``: the process table cannot be read now, so absence is not shown;
        * ``ALIVE``: a process recorded under the executor (same command line), or its recorded group, exists now;
        * ``IDENTITY_CHANGED``: a recorded PID exists with another command line. An ``exec`` keeps the PID and the process
          and nothing recorded tells that from a PID the system reused, so it is not shown gone;
        * ``UNPROVABLE``: nothing recorded could show it gone (the adapter raised, the journal is from a version that kept
          only a count, the kind is unknown);
        * ``GONE``: every recorded identity and the recorded group are absent in a complete read-back.

        The root group alone never decides for an Agent: what it starts can live in a group of its own.
        """
        ended, handle = ledger.ended, ledger.handle or {}
        pgid = handle.get("pgid")
        if ended is None:
            if handle and handle.get("kind") != "process-group":
                return "END_NOT_RECORDED", {"recorded_processes": 0, "pgid": pgid, "kind": handle.get("kind")}
            return None
        if ended.get("stopped") is not False:
            return None
        report = ((ended.get("binding") or {}).get("observed") or {}).get("stop_report")
        seen = report.get("processes_seen") if isinstance(report, dict) else None
        identities = [
            {"pid": item["pid"], "command": item["command"]}
            for item in (seen if isinstance(seen, list) else ())
            if isinstance(item, dict) and isinstance(item.get("pid"), int) and isinstance(item.get("command"), str)
        ]
        facts: dict[str, Any] = {"recorded_processes": len(identities), "pgid": pgid}
        if isinstance(report, dict) and report.get("observation") == "UNAVAILABLE":
            return "OBSERVATION_FAILED", {**facts, "detail": str(report.get("observation_failure"))[:120]}
        if isinstance(report, dict) and report.get("coverage") == "UNCOVERED":  # a report without ``coverage`` is read as before
            return "EXITED_BEFORE_OBSERVATION", {**facts, "detail": str(report.get("coverage_failure"))[:120]}
        try:
            running = still_running(identities, strict=True) if identities else []
        except OSError as exc:
            return "READBACK_UNAVAILABLE", {**facts, "detail": str(exc)[:120]}
        same = [item["pid"] for item in running if not item.get("command_changed")]
        changed = [item["pid"] for item in running if item.get("command_changed")]
        if same or (isinstance(pgid, int) and group_alive(pgid)):
            return "ALIVE", {**facts, "running_pids": same, "command_changed_pids": changed}
        if changed:
            return "IDENTITY_CHANGED", {**facts, "command_changed_pids": changed}
        whole_executor = bool(identities) or handle.get("kind") == "process-group"
        return ("GONE" if whole_executor else "UNPROVABLE"), facts

    def _stop_reconciled(self, delivery_id: str, live: Mapping[str, Any], ledger: Ledger) -> bool:
        """``False`` while an executor that nothing has shown stopped is not proven gone; an advisory says why.

        ``True`` when nothing says it was not stopped, or when a complete read-back proved it gone (journalled once as
        ``STOP_RECONCILED``): only then may the attempt be settled. Until then UAM is told nothing, so its lease and its
        ``STOP_NOT_CONFIRMED`` / same-task gates keep blocking every successor. The delivery is backed off like any other
        refusal, so a stuck one reads the process table at the doubling backoff and not at every poll."""
        known = self._stop_state(ledger)
        if known is None:
            return True
        state, facts = known
        if state == "GONE":
            if not ledger.reconciled:
                self.journal.append(delivery_id, P_RECONCILED, attempt_ref=live["attempt_ref"], **facts)
            return True
        phase, code = _NOT_PROVEN_STOPPED[state]
        self._note(delivery_id, phase, code, ledger, **facts)
        self._back_off(delivery_id)
        return False

    def _adopt_or_clear(self, delivery_id: str, ledger: Ledger) -> None:
        """A start was intended and the journal never saw it begin: look at UAM, and adopt only what is plainly ours."""
        attempts = self.control.get(self.principal, delivery_id=delivery_id).get("attempts", [])
        last = attempts[-1] if attempts else None
        if last is None:
            self.journal.append(delivery_id, P_INTENT_CLEARED, code="NO_ATTEMPT_WAS_STARTED")
        elif last.get("executor") == self.principal and last["state"] == ATTEMPT_ACTIVE:
            self.journal.append(
                delivery_id, P_STARTED, attempt_ref=last["attempt_ref"], fence=last["fence"],
                lease_expires_at=last["lease_expires_at"], adopted=True,
                job_dir=str(self.work_dir / "jobs" / delivery_id / last["attempt_ref"]),
            )
            self._finalize(delivery_id, self.journal.ledger(delivery_id))
        else:
            self._note(delivery_id, P_LEFT_OPEN, "INTENT_UNRESOLVED", ledger, detail="an attempt exists that this journal cannot place")

    def _end(self, delivery_id: str, live: Mapping[str, Any], reported: str, note: str, **details: Any) -> None:
        try:
            view = self.control.end_attempt(
                self.principal, delivery_id=delivery_id, attempt_ref=live["attempt_ref"], fence=live["fence"],
                outcome=reported, note=note,
            )
        except TaskControlError as exc:
            self._note(
                delivery_id, P_BLOCKED, f"END_REFUSED_{exc.code}", self.journal.ledger(delivery_id), attempt_ref=live["attempt_ref"],
            )
            self._back_off(delivery_id)
            return
        self.journal.append(
            delivery_id, P_ENDED, attempt_ref=live["attempt_ref"], reported_outcome=reported, note=note,
            effect=view.get("effect"), state=view.get("state"), **details,
        )

    def _submit(self, delivery_id: str, live: Mapping[str, Any], outcome: Mapping[str, Any]) -> None:
        view = self.control.get(self.principal, delivery_id=delivery_id)
        contract = view.get("contract")
        if not isinstance(contract, dict):
            self._note(delivery_id, P_BLOCKED, "CONTRACT_UNREADABLE", self.journal.ledger(delivery_id))
            return
        workspace_id = contract["workspace_id"]
        baseline = contract["baseline"].get("files", {})
        prepared = Path(live["job_dir"]) / "result.json"
        payload = self._prepared(prepared)
        if payload is None:
            read_only = declares_no_change(contract)
            try:
                artifacts = [] if read_only else self._changed_artifacts(workspace_id, contract["allowed_change_paths"], baseline)
                differing = self._baseline_differences(workspace_id, contract["allowed_change_paths"], baseline) if read_only else []
            except (Refusal, WorkspaceError) as exc:
                self._note(delivery_id, P_BLOCKED, "READBACK_FAILED", self.journal.ledger(delivery_id), detail=str(exc)[:120])
                return
            if read_only and differing:  # the contract says nothing may change: a no-change claim would be false
                self._end(delivery_id, live, "FAILED", "READ_ONLY_TASK_CHANGED_FILES", differing=differing[:20])
                return
            if not read_only and not artifacts:
                self._end(delivery_id, live, "FAILED", "NO_ALLOWED_PATH_CHANGED")
                return
            matched = self.policy.get().match(view)
            receipts = self._verify(
                matched[1] if matched else None, str(self._root_of(workspace_id)), contract["verification_commands"],
            )
            payload = {
                "result_version": "uam-result-v2",
                "result_id": f"res-{delivery_id[4:]}-{live['fence']}", "business_task_ref": view["business_task_ref"],
                "task_revision": view["task_revision"], "attempt_ref": live["attempt_ref"],
                "contract_id": contract["contract_id"], "contract_digest": contract["contract_digest"],
                "workspace_instance": workspace_id, "executor": self.principal, "verification_receipts": receipts,
                "unresolved_risks": [str(risk) for risk in outcome.get("unresolved_risks", ())],
            }
            if read_only:
                payload.update({
                    "result_kind": "no-change-v1", "rationale": self._no_change_rationale(contract, outcome),
                    "baseline": contract["baseline"],
                })
            else:
                payload.update({
                    "result_kind": "document-artifact-v1",
                    "source_digests": {path: baseline[path] for path in contract["authoritative_paths"] if path in baseline},
                    "artifacts": artifacts,
                })
            atomic_write_json(prepared, payload)  # a replay after a crash sends exactly these bytes
            self.journal.append(delivery_id, P_PREPARED, attempt_ref=live["attempt_ref"], result_id=payload["result_id"])
        try:
            answer = self.control.submit_result(
                self.principal, delivery_id=delivery_id, attempt_ref=live["attempt_ref"], fence=live["fence"], result=payload,
            )
        except TaskControlError as exc:
            self._note(
                delivery_id, P_BLOCKED, f"SUBMIT_REFUSED_{exc.code}", self.journal.ledger(delivery_id), attempt_ref=live["attempt_ref"],
            )
            self._back_off(delivery_id)
            return
        recorded = answer["delivery"]["result"]
        self.journal.append(
            delivery_id, P_SUBMITTED, attempt_ref=live["attempt_ref"], result_id=payload["result_id"],
            review_state=recorded["review_state"], review_blockers=recorded["review_blockers"],
            executor_binding=outcome.get("binding"),  # UAM's result record has no field for the executor's actual session
        )

    # -- small pieces -----------------------------------------------------------------------------------------------------

    @staticmethod
    def _prepared(path: Path) -> dict[str, Any] | None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _changed_artifacts(
        self, workspace_id: str, allowed: Sequence[str], baseline: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        artifacts = []
        for path in allowed:
            state = self._live_state(workspace_id, path)
            if state != baseline.get(path) and "absent" not in state:
                artifacts.append({"path": path, **state})
        return artifacts

    def _baseline_differences(self, workspace_id: str, allowed: Sequence[str], baseline: Mapping[str, Any]) -> list[str]:
        """The paths of the contract baseline (and the allowed paths) whose live state is not the baseline's, deletions included."""
        return [
            path for path in sorted(set(baseline) | set(allowed))
            if self._live_state(workspace_id, path) != baseline.get(path)
        ]

    @staticmethod
    def _no_change_rationale(contract: Mapping[str, Any], outcome: Mapping[str, Any]) -> str:
        """What the Consumer itself observed, in words that claim nothing about what the executor concluded."""
        compared = ", ".join(sorted(set(contract["baseline"].get("files", {})) | set(contract["allowed_change_paths"])))[:1500]
        note = str(outcome.get("note") or "")[:300]
        detail = f" ({note})" if note else ""
        return (
            f"Read-only task (the contract expects no change). Executor {str(outcome.get('executor') or 'unnamed')[:100]} "
            f"ended with status {outcome['status']}{detail}. After it ended the Consumer compared {compared} with the "
            "contract baseline and found no difference. This records what the Consumer observed; it is not the executor's own conclusion."
        )

    def _root_of(self, workspace_id: str) -> Path:
        return Path(self.gateway.resolve_workspace(workspace_id).spec.root).resolve()

    def _checked_cwd(self, rule: Rule, contract: Mapping[str, Any]) -> str:
        if not rule.cwd or not os.path.isabs(rule.cwd):
            raise Refusal("CWD_REQUIRED")
        try:
            root = self._root_of(contract["workspace_id"])
        except (WorkspaceError, UAMError):
            raise Refusal("WORKSPACE_UNRESOLVED") from None
        if Path(rule.cwd).resolve() != root:
            raise Refusal("CWD_MISMATCH")
        return str(root)

    @staticmethod
    def _check_rule_against(rule: Rule, adapter: HarnessAdapter, contract: Mapping[str, Any]) -> None:
        if adapter.needs_session and not rule.session:
            raise Refusal("SESSION_REQUIRED")
        known = getattr(adapter, "known_worker", None)
        if known is not None and not rule.worker:
            raise Refusal("WORKER_REQUIRED")
        if known is not None and not known(rule.worker):
            raise Refusal("WORKER_NOT_REGISTERED")
        if not contract.get("allowed_change_paths"):
            raise Refusal("NO_ALLOWED_PATHS")
        if contract.get("baseline", {}).get("kind") != "file-digests":
            raise Refusal("BASELINE_KIND_UNSUPPORTED")
        if any(command not in rule.verification_allowlist for command in contract["verification_commands"]):
            raise Refusal("VERIFICATION_NOT_ALLOWLISTED")

    def _preflight_of(self, name: str, adapter: HarnessAdapter) -> tuple[str, str] | None:
        cached = self._preflight.get(name)
        if cached is not None and time.monotonic() < cached[0]:
            return cached[1]
        answer = adapter.preflight()
        self._preflight[name] = (time.monotonic() + self._preflight_seconds, answer)
        return answer

    def _live_state(self, workspace_id: str, path: str) -> dict[str, Any]:
        try:
            result = self.gateway.file_digest(workspace_id, path)
        except WorkspaceError as exc:
            if str(exc) == PATH_ABSENT:
                return {"absent": True}
            raise
        if not result["complete"]:
            raise Refusal("DIGEST_INCOMPLETE")
        return {"sha256": result["sha256"], "size_bytes": result["size_bytes"]}

    @staticmethod
    def _verify(rule: Rule | None, cwd: str, commands: Sequence[str]) -> list[dict[str, Any]]:
        """Run each allow-listed command verbatim, without a shell. A command that cannot run is a failed receipt."""
        receipts = []
        allowed = rule.verification_allowlist if rule is not None else ()
        for command in commands:
            if command not in allowed:
                receipts.append({"command": command, "exit_code": 126, "evidence": "not allow-listed; not run"})
                continue
            try:
                done = subprocess.run(
                    shlex.split(command), cwd=cwd, env={"PATH": _SAFE_PATH, "LANG": "en_US.UTF-8"}, stdin=subprocess.DEVNULL,
                    capture_output=True, timeout=VERIFY_SECONDS, check=False,
                )
                code = done.returncode
                evidence = f"exit {code}; stdout {len(done.stdout)} bytes sha256 {hashlib.sha256(done.stdout).hexdigest()[:16]}"
            except subprocess.TimeoutExpired:
                code, evidence = 124, f"timed out after {VERIFY_SECONDS:.0f}s"
            except (OSError, ValueError, IndexError) as exc:  # IndexError: a command that splits into nothing
                code, evidence = 127, f"could not run: {type(exc).__name__}"
            receipts.append({"command": command, "exit_code": code, "evidence": evidence})
        return receipts

    def _defer(self, delivery_id: str, seconds: float) -> None:
        self._not_before[delivery_id] = time.monotonic() + seconds

    def _back_off(self, delivery_id: str) -> None:
        """Defer by the base backoff, doubled for every earlier refusal of this delivery in this life (at most 64 times)."""
        strikes = self._strikes.get(delivery_id, 0)
        self._strikes[delivery_id] = strikes + 1
        self._defer(delivery_id, self._backoff * 2 ** min(strikes, 6))

    def _note(self, delivery_id: str, phase: str, code: str, ledger: Ledger, **details: Any) -> None:
        """An advisory record, written only when it differs from the last one for this delivery."""
        if ledger.advisory != (phase, code):
            self.journal.append(delivery_id, phase, code=code, **details)

    def _record_refusal(self, delivery_id: str, ledger: Ledger, refusal: Refusal) -> None:
        self._note(delivery_id, refusal.phase, refusal.code, ledger, **refusal.details)
        if refusal.retry is None:
            self._back_off(delivery_id)
        else:
            self._defer(delivery_id, refusal.retry)
