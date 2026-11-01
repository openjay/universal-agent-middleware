"""Instruments shared by the S1 (sensitive-content) tests.

They observe what the code under test really did, instead of asserting on what a mock was told:
``OpenOracle`` watches every ``os.open`` and identifies a protected file by inode, whatever name, link or path
reached it; ``alarm`` turns a hang (an opened FIFO) into a failure.
"""
from __future__ import annotations

import os
import signal
from contextlib import contextmanager
from pathlib import Path
from unittest import mock


@contextmanager
def alarm(seconds: int = 5):
    """A FIFO opened without O_NONBLOCK would block forever: fail the test instead of hanging the run."""

    def expired(_signum, _frame):
        raise AssertionError(f"blocked for {seconds}s: something opened a FIFO that must never be opened")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


class OpenOracle:
    """Records every ``os.open`` that lands on a protected file, identified by inode and not by name."""

    def __init__(self, protected: list[Path]):
        self.identities = {(info.st_dev, info.st_ino) for info in (os.stat(path) for path in protected)}
        self.violations: list[str] = []

    @contextmanager
    def watching(self):
        real_open = os.open

        def recording(path, flags, mode=0o777, *, dir_fd=None):
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) in self.identities:
                self.violations.append(str(path))
            return descriptor

        with mock.patch("os.open", recording):
            yield self
