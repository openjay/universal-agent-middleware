"""Bounded child processes for the release pipeline.

Every outcome of a child process is returned as data. Timeouts, launch failures and
non-zero exits never escape as exceptions, because the release receipt must stay complete
after the host has already been changed.

``subprocess.TimeoutExpired.stdout`` and ``.stderr`` are ``bytes`` (or ``None``) even for a
text-mode run, so output is always captured as bytes and decoded in one place.
"""
from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DIAGNOSTIC_LIMIT = 600
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def as_bytes(value: object) -> bytes:
    """Normalise whatever a child-process API handed back to bytes."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8", "replace")
    return b""


def diagnostic_text(value: object, *, limit: int = DIAGNOSTIC_LIMIT) -> str:
    """Printable tail of child output: undecodable bytes replaced, control characters removed."""
    text = as_bytes(value).decode("utf-8", "replace").replace("\r\n", "\n")
    text = _CONTROL_CHARACTERS.sub("?", text).strip()
    if len(text) > limit:
        return "..." + text[-limit:]
    return text


@dataclass(frozen=True)
class ProcessOutcome:
    stage: str
    returncode: int | None
    timed_out: bool
    timeout_seconds: float
    elapsed_seconds: float
    stdout: bytes
    stderr: bytes
    launch_error: str | None = None

    @property
    def completed(self) -> bool:
        return self.launch_error is None and not self.timed_out and self.returncode is not None

    @property
    def succeeded(self) -> bool:
        return self.completed and self.returncode == 0

    def describe_failure(self) -> str:
        if self.launch_error:
            return f"could not start: {diagnostic_text(self.launch_error, limit=200)}"
        if self.timed_out:
            return f"timed out after {self.timeout_seconds:g}s; process state is uncertain"
        tail = diagnostic_text(self.stderr, limit=300) or diagnostic_text(self.stdout, limit=300)
        return f"exited with rc={self.returncode}" + (f": {tail}" if tail else "")

    def receipt(self, *, include_stdout: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "stage": self.stage,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "timeout_seconds": self.timeout_seconds,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "launch_error": self.launch_error,
            "stderr_tail": diagnostic_text(self.stderr),
        }
        if include_stdout:
            data["stdout_tail"] = diagnostic_text(self.stdout)
        return data


def run_bounded(argv: Sequence[str], *, stage: str, timeout: float,
                cwd: str | Path | None = None,
                env: Mapping[str, str] | None = None) -> ProcessOutcome:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            list(argv), capture_output=True, timeout=timeout, cwd=cwd, env=env, check=False)
    except subprocess.TimeoutExpired as exc:
        return ProcessOutcome(stage, None, True, timeout, time.monotonic() - started,
                              as_bytes(exc.stdout), as_bytes(exc.stderr))
    except OSError as exc:
        return ProcessOutcome(stage, None, False, timeout, time.monotonic() - started, b"", b"",
                              launch_error=f"{type(exc).__name__}: {exc}")
    return ProcessOutcome(stage, completed.returncode, False, timeout, time.monotonic() - started,
                          as_bytes(completed.stdout), as_bytes(completed.stderr))
