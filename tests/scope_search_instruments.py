"""Black-box sentinels for the scope search tests.

The scope search is a read-only observer, so "it did not read X" is a claim about the process, not
about the response: a hit that is dropped from the answer may still have been opened. Three
independent sentinels watch for that, so the tests do not rely on the response lacking a hit:

* ``AtimeSentinel`` arms files so that a read moves their access time. A file whose atime did not
  move was not read by any process (ripgrep, ``cat`` or Python); an open without a read does not
  move it. Atime is a filesystem property, so the sentinel proves it is alive: an allowed control
  file that *was* searched must be seen as read, otherwise the test is skipped rather than passed.
* ``RunRecorder`` wraps ``subprocess.run`` and records every ripgrep invocation: the operands it
  was given and, for each descriptor handed over, the identity of the object behind it. The
  scope search must hand ripgrep nothing but descriptors of authorised regular files.
* ``OpenSpy`` wraps ``os.open`` and ``os.scandir`` and records the identity of every object this
  process opened or listed, so a denied directory can be shown never to have been listed and a
  denied file never to have been opened.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import unittest
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest import mock

Identity = tuple[int, int]
DESCRIPTOR_OPERAND = re.compile(r"/dev/fd/\d+")


def identity_of(path: Path) -> Identity:
    info = os.stat(path)
    return (info.st_dev, info.st_ino)


class AtimeSentinel:
    """Arm files so a read moves their atime, then report which were read."""

    def __init__(self) -> None:
        self._armed: dict[Path, int] = {}

    def arm(self, *paths: Path) -> None:
        for path in paths:
            info = os.stat(path)
            os.utime(path, ns=(info.st_mtime_ns - 10_000_000_000, info.st_mtime_ns))
            self._armed[path] = os.stat(path).st_atime_ns

    def was_read(self, path: Path) -> bool:
        return os.stat(path).st_atime_ns != self._armed[path]

    def require_alive(self, test: unittest.TestCase, control: Path) -> None:
        """Skip, rather than pass, when reads do not move atime on this filesystem."""
        if not self.was_read(control):
            test.skipTest("this filesystem does not record access time on reads: sentinel is not alive")


@dataclass
class RunRecord:
    argv: list[str]
    pass_fds: tuple[int, ...]
    descriptor_identities: list[tuple[int, Identity, int]] = field(default_factory=list)
    kwargs: dict[str, Any] = field(default_factory=dict)

    @property
    def operands(self) -> list[str]:
        """What ripgrep was told to search: everything after the query that follows ``--``."""
        return self.argv[self.argv.index("--") + 2:] if "--" in self.argv else []

    @property
    def query(self) -> str | None:
        return self.argv[self.argv.index("--") + 1] if "--" in self.argv else None

    def operand_for(self, path: Path) -> str:
        """The ``/dev/fd/N`` operand that stands for ``path`` in this run; the path must be handed over."""
        wanted = identity_of(path)
        for descriptor, identity, _mode in self.descriptor_identities:
            if identity == wanted:
                return f"/dev/fd/{descriptor}"
        raise AssertionError(f"{path} was not handed to ripgrep as a descriptor")


class RunRecorder:
    """``subprocess.run`` stand-in that records ripgrep invocations and delegates to the real run."""

    def __init__(self, delegate: Callable[..., Any] | None = None, *, before_run: Callable[[RunRecord], None] | None = None) -> None:
        self._delegate = delegate or subprocess.run
        self._before_run = before_run
        self.ripgrep_calls: list[RunRecord] = []

    def __call__(self, command: Any, *args: Any, **kwargs: Any) -> Any:
        argv = [os.fspath(part) for part in command]
        if Path(argv[0]).name == "rg":
            record = RunRecord(argv=argv, pass_fds=tuple(kwargs.get("pass_fds") or ()), kwargs=dict(kwargs))
            for descriptor in record.pass_fds:
                info = os.fstat(descriptor)
                record.descriptor_identities.append((descriptor, (info.st_dev, info.st_ino), info.st_mode))
            self.ripgrep_calls.append(record)
            if self._before_run is not None:
                self._before_run(record)
        return self._delegate(command, *args, **kwargs)

    def patch(self) -> Any:
        return mock.patch.object(subprocess, "run", self)

    @property
    def handed_identities(self) -> set[Identity]:
        return {identity for call in self.ripgrep_calls for _fd, identity, _mode in call.descriptor_identities}

    @property
    def operands(self) -> list[str]:
        return [operand for call in self.ripgrep_calls for operand in call.operands]


class ScriptedRipgrep(RunRecorder):
    """Play ripgrep for the scope search: ``reply`` decides what each invocation answers or raises.

    The search hands ripgrep open descriptors, so a stand-in answers in descriptor terms: it names a
    file by the ``/dev/fd/N`` it was handed (``RunRecord.operand_for``). ``reply`` receives the
    ``RunRecord`` of the invocation and returns a ``CompletedProcess``, or raises what a real run
    would (``TimeoutExpired``, ``OSError``). Invocations are recorded as ``RunRecorder`` does.
    """

    def __init__(self, reply: Callable[[RunRecord], subprocess.CompletedProcess[Any]]) -> None:
        self._real_run = subprocess.run  # captured before this instance is patched in
        super().__init__(delegate=self._respond)
        self._reply = reply

    def _respond(self, command: Any, *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        if Path(os.fspath(command[0])).name != "rg":
            return self._real_run(command, *args, **kwargs)  # Git and the like are not scripted
        return self._reply(self.ripgrep_calls[-1])


def completed(stdout: bytes | None, returncode: int = 0) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=["rg"], returncode=returncode, stdout=stdout, stderr=b"")


class OpenSpy:
    """Record the identity of every object opened (``os.open``) or listed (``os.scandir``)."""

    def __init__(self) -> None:
        self.opened: set[Identity] = set()
        self.listed: set[Identity] = set()
        self._real_open = os.open
        self._real_scandir = os.scandir

    def _open(self, path: Any, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        descriptor = self._real_open(path, flags, mode, dir_fd=dir_fd)
        info = os.fstat(descriptor)
        self.opened.add((info.st_dev, info.st_ino))
        return descriptor

    def _scandir(self, path: Any = None) -> Any:
        target = "." if path is None else path
        info = os.fstat(target) if isinstance(target, int) else os.stat(target)
        self.listed.add((info.st_dev, info.st_ino))
        return self._real_scandir(target)

    def patch(self) -> Any:
        return mock.patch.multiple(os, open=self._open, scandir=self._scandir)


def regular_file_identities(*paths: Path) -> set[Identity]:
    return {identity_of(path) for path in paths if stat.S_ISREG(os.stat(path).st_mode)}


def handed_relative_paths(recorder: RunRecorder, root: Path) -> set[str]:
    """POSIX paths, below ``root``, of the regular files whose objects were handed to ripgrep.

    A file counts by the object behind its name, not by the name, so a name that was never listed
    cannot be mistaken for one that was; symlinks are not followed, since the link itself is never
    handed over. Names that share an object (hard links) are indistinguishable here.
    """
    handed = recorder.handed_identities
    found: set[str] = set()
    for directory, _dirs, names in os.walk(root, followlinks=False):
        for name in names:
            path = Path(directory) / name
            info = os.lstat(path)
            if stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) in handed:
                found.add(path.relative_to(root).as_posix())
    return found
