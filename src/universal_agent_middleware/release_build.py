"""Build a release from the bytes of one Git commit, and from nothing else.

``pip wheel <worktree>`` builds whatever lies on disk. Ignored files (a stale ``build/lib``, a
local override module), files left behind by another checkout and files that changed after the
clean check all enter the wheel while ``git status`` stays clean, and every comparison that reads
the same worktree agrees with the contaminated artifact. This module closes that path:

* ``export_commit`` writes the commit's tree into a private directory with ``git archive`` and
  proves, entry by entry, that the directory holds exactly the objects of the tree. The proof is
  needed because ``.gitattributes`` can make an archive differ from its commit (``export-ignore``
  drops a tracked file, ``export-subst`` rewrites one, ``eol`` converts line endings);
* ``build_wheel`` builds from that directory only;
* ``build_violations`` proves that the wheel and the installed package are the commit's blobs and
  nothing else (the wheel's whole inventory, not only the package directory).

Nothing here activates, stops or starts a service; a failure leaves only the caller's scratch.
Limits, stated so they are not mistaken for guarantees: the build backend and the interpreter that
runs it are not pinned here (the release manifest pins what was installed); bytecode is ignored
when the installed package is compared, as it is everywhere in the release pipeline.
"""
from __future__ import annotations

import hashlib
import io
import os
import tarfile
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .release_process import run_bounded
from .release_seal import SealError, diff_files, installed_package_files, wheel_inventory_violations

GIT_TIMEOUT = 60.0
WHEEL_TIMEOUT = 120.0
_LISTED_LIMIT = 20
_EXPORT_MODES = frozenset({"100644", "100755", "120000"})
_SHA1_LENGTH = 40


class BuildError(Exception):
    """The release cannot be built from the commit; ``stage`` names the receipt step that failed."""

    def __init__(self, stage: str, reason: str) -> None:
        super().__init__(reason)
        self.stage = stage
        self.reason = reason


@dataclass(frozen=True)
class TreeEntry:
    mode: str
    kind: str
    oid: str
    path: str


def git_blob_id(data: bytes) -> str:
    """The object id Git gives a file with these bytes (SHA-1 repositories only)."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def _git(source_root: Path, *args: str) -> bytes:
    outcome = run_bounded(["git", *args], stage=f"git {args[0]}", timeout=GIT_TIMEOUT, cwd=source_root)
    if not outcome.succeeded:
        raise BuildError("export_commit", f"git {args[0]} {outcome.describe_failure()}")
    return outcome.stdout


def tree_entries(source_root: Path, commit: str) -> list[TreeEntry]:
    """Every object of the commit's tree, listed from the repository root (a subdirectory hides the rest)."""
    if _git(source_root, "rev-parse", "--show-prefix").strip():
        raise BuildError("export_commit", f"{source_root} is not the root of its Git repository")
    entries: list[TreeEntry] = []
    for record in _git(source_root, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
        if not record:
            continue
        meta, _, raw_path = record.partition(b"\t")
        try:
            mode, kind, oid = meta.decode("ascii").split()
        except (UnicodeDecodeError, ValueError) as exc:
            raise BuildError("export_commit", "git ls-tree returned an entry this build cannot read") from exc
        entries.append(TreeEntry(mode, kind, oid, os.fsdecode(raw_path)))
    if not entries:
        raise BuildError("export_commit", f"commit {commit[:12]} has an empty tree")
    return entries


def export_differences(entries: Sequence[TreeEntry], root: Path) -> dict[str, list[str]]:
    """How ``root`` differs from the tree, object by object: presence, content, executable bit and type."""
    expected = {entry.path: entry for entry in entries}
    present: set[str] = set()
    for directory, subdirectories, files in os.walk(root):
        base = Path(directory)
        links_to_directories = [name for name in subdirectories if (base / name).is_symlink()]
        for name in [*files, *links_to_directories]:
            present.add((base / name).relative_to(root).as_posix())
    changed: list[str] = []
    for path, entry in expected.items():
        target = root / path
        if not os.path.lexists(target):
            continue
        if entry.mode == "120000":
            same = target.is_symlink() and git_blob_id(os.fsencode(os.readlink(target))) == entry.oid
        elif target.is_symlink() or not target.is_file():
            same = False
        else:
            same = git_blob_id(target.read_bytes()) == entry.oid and (
                bool(target.stat().st_mode & 0o100) == (entry.mode == "100755"))
        if not same:
            changed.append(path)
    return {
        "missing": sorted(set(expected) - present)[:_LISTED_LIMIT],
        "unexpected": sorted(present - set(expected))[:_LISTED_LIMIT],
        "changed": sorted(changed)[:_LISTED_LIMIT],
    }


def export_commit(source_root: Path, commit: str, destination: Path) -> dict[str, Any]:
    """Write the tree of ``commit`` into the new directory ``destination`` and prove it is that tree."""
    entries = tree_entries(source_root, commit)
    refused = [f"{entry.kind} {entry.mode} {entry.path}" for entry in entries
               if entry.kind != "blob" or entry.mode not in _EXPORT_MODES or len(entry.oid) != _SHA1_LENGTH]
    if refused:
        raise BuildError("export_commit", "the tree holds entries a clean export cannot reproduce "
                                          f"(submodules, or a repository that is not SHA-1): {refused[:_LISTED_LIMIT]}")
    archive = _git(source_root, "archive", "--format=tar", commit)
    destination.mkdir(parents=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(destination, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise BuildError("export_commit", f"the archive of {commit[:12]} could not be extracted: "
                                          f"{type(exc).__name__}: {exc}") from exc
    differences = export_differences(entries, destination)
    if any(differences.values()):
        raise BuildError("export_commit", f"the export is not the tree of {commit[:12]} (attributes can change "
                                          f"what git archive writes): {differences}")
    return {"commit": commit, "files": len(entries)}


def build_wheel(export_root: Path, wheel_dir: Path, *, python: str) -> Path:
    """Build the one wheel of the exported tree into ``wheel_dir``; nothing outside the export is an input."""
    outcome = run_bounded([python, "-m", "pip", "wheel", "--no-deps", "-w", str(wheel_dir), str(export_root)],
                          stage="build_wheel", timeout=WHEEL_TIMEOUT, cwd=export_root)
    if not outcome.succeeded:
        raise BuildError("build_wheel", f"pip wheel {outcome.describe_failure()}")
    wheels = sorted(wheel_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise BuildError("build_wheel", f"the build must produce exactly one wheel, found {len(wheels)}")
    return wheels[0]


def build_violations(expected: Mapping[str, str], release_dir: Path, wheel_file: str,
                     *, version: str) -> list[dict[str, str]]:
    """The wheel and the installed package of ``release_dir`` are the blobs in ``expected`` and nothing else."""
    problems: list[dict[str, str]] = []

    def violation(code: str, detail: str) -> None:
        problems.append({"code": code, "detail": detail[:300]})

    named = PurePosixPath(wheel_file)
    if named.is_absolute() or ".." in named.parts:
        violation("wheel_path_unsafe", f"the manifest names a wheel outside the release: {wheel_file!r}")
    else:
        try:
            problems.extend(wheel_inventory_violations(release_dir / wheel_file, expected, version=version))
        except (OSError, zipfile.BadZipFile) as exc:
            violation("wheel_unreadable", f"{type(exc).__name__}: {exc}")
    try:
        installed = installed_package_files(release_dir)
    except (SealError, OSError) as exc:
        violation("package_unreadable", f"{type(exc).__name__}: {exc}")
    else:
        differences = diff_files(expected, installed)
        if any(differences.values()):
            violation("installed_package_differs", f"installed package differs from the commit's blobs: {differences}")
    return problems
