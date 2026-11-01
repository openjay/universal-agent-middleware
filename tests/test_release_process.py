"""The bounded child-process runner: every outcome is data, and output is bytes until one decode.

CPython hands `TimeoutExpired.stdout/stderr` back as bytes (or None) even for a text-mode run, so
the runner never uses text mode, and the diagnostic tail it exposes is sanitised in one place.
"""
from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

import pytest
from release_fixtures import executable

from universal_agent_middleware import release_process as proc


@pytest.mark.parametrize("value,expected", [
    (b"abc", b"abc"), (bytearray(b"abc"), b"abc"), ("é", "é".encode()), (None, b""), (7, b""), ([], b"")])
def test_as_bytes_normalises_whatever_a_child_api_returns(value, expected):
    assert proc.as_bytes(value) == expected


def test_diagnostic_text_is_printable_bounded_and_keeps_the_tail():
    assert proc.diagnostic_text(b"ok \xff bytes") == "ok \ufffd bytes"
    assert proc.diagnostic_text(b"a\x00b\x1b[31mred\x7f") == "a?b?[31mred?"
    assert proc.diagnostic_text(b"  padded\r\n") == "padded"
    tail = proc.diagnostic_text("x" * 50 + "THE END", limit=10)
    assert tail == "..." + "x" * 3 + "THE END" and len(tail) == 13
    assert proc.diagnostic_text(None) == ""


def test_a_successful_run_keeps_both_streams_as_bytes(tmp_path):
    script = executable(tmp_path / "child", "echo out; echo err >&2\n")
    outcome = proc.run_bounded([str(script)], stage="demo", timeout=10)
    assert outcome.succeeded and outcome.completed and not outcome.timed_out
    assert (outcome.stdout, outcome.stderr) == (b"out\n", b"err\n")
    assert outcome.receipt(include_stdout=True)["stdout_tail"] == "out"
    json.dumps(outcome.receipt())


def test_a_nonzero_exit_is_data_with_a_describing_tail(tmp_path):
    script = executable(tmp_path / "child", "echo 'what went wrong' >&2\nexit 7\n")
    outcome = proc.run_bounded([str(script)], stage="demo", timeout=10)
    assert outcome.completed and not outcome.succeeded and outcome.returncode == 7
    assert outcome.describe_failure() == "exited with rc=7: what went wrong"


def test_a_timeout_keeps_partial_bytes_and_marks_the_state_uncertain(tmp_path):
    script = executable(tmp_path / "child", "printf 'half \\377 done'\nprintf 'warn' >&2\nexec sleep 5\n")
    outcome = proc.run_bounded([str(script)], stage="demo", timeout=1.0)
    assert outcome.timed_out and not outcome.completed and outcome.returncode is None
    assert outcome.stdout == b"half \xff done" and outcome.stderr == b"warn"
    assert "timed out after 1s" in outcome.describe_failure()
    assert "uncertain" in outcome.describe_failure()
    assert 0.9 <= outcome.elapsed_seconds < 4


def test_a_timeout_whose_partial_output_is_text_or_none_is_still_data():
    for partial in ("text output", None, b"bytes"):
        expired = subprocess.TimeoutExpired(["x"], 1, output=partial, stderr=partial)
        with patch.object(proc.subprocess, "run", side_effect=expired):
            outcome = proc.run_bounded(["x"], stage="demo", timeout=1)
        assert outcome.timed_out and isinstance(outcome.stdout, bytes) and isinstance(outcome.stderr, bytes)


def _not_executable(base):
    path = base / "plain"
    path.write_text("not executable")
    return path


@pytest.mark.parametrize("prepare,error", [
    (lambda base: base / "missing", "FileNotFoundError"),
    (_not_executable, "PermissionError"),
])
def test_a_program_that_cannot_start_is_data(tmp_path, prepare, error):
    outcome = proc.run_bounded([str(prepare(tmp_path))], stage="demo", timeout=5)
    assert not outcome.completed and not outcome.succeeded and outcome.returncode is None
    assert outcome.launch_error.startswith(error)
    assert outcome.describe_failure().startswith("could not start")
    assert outcome.receipt()["launch_error"] == outcome.launch_error
