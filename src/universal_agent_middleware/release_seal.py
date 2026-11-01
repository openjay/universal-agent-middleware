"""A seal of a built release, and the check that refuses to activate anything else.

``uam release`` builds from a clean export of the commit (``release_build``) and checks the
artifact against the commit's Git blobs, never against the working tree: "the artifact equals the
tree" says nothing about "the artifact equals the commit", because the tree can change between the
clean check and the build and ignored files never show up in it. A seal states what a release must
be from that same independent source (the Git blobs of the exact commit) plus what was observed on
disk when it was sealed (manifest, wheel, installed package files, dependencies, inherited service
files, the interpreter executable). ``uam release --expect-seal`` re-derives all of it, under the
Supervisor lock and before the service is stopped, and rejects any difference.

Everything here is read-only and static: no code of the release is executed. The seal is an
operator-supplied expectation, not a trust root of its own; its package hashes are cross-checked
against the Git object database every time it is used.

Limits, stated so they are not mistaken for guarantees: the interpreter is pinned by the SHA-256
of its executable, not of the libraries it loads; the inherited ``service/`` files are pinned as
observed at seal time (they come from the previous release, not from Git); and a check followed by
an activation is not atomic, so the window is shortened, not closed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import zipfile
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .release_process import run_bounded

SEAL_SCHEMA = "uam-release-seal-v1"
PACKAGE = "universal_agent_middleware"
PACKAGE_SOURCE = f"src/{PACKAGE}"
GIT_TIMEOUT = 30.0
RUNTIME_MANIFEST = "runtime/uam-runtime.json"
_LISTED_LIMIT = 20
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_ID = re.compile(r"[0-9a-f]{40}")
_FILE_MODES = {"100644", "100755"}
_SEAL_KEYS = frozenset({
    "schema_version", "release_id", "release_dir", "source", "manifest_sha256", "runtime_manifest_sha256",
    "wheel", "package_files", "dependencies", "service_files", "interpreter",
})


class SealError(Exception):
    """A seal cannot be created, loaded or trusted."""


@dataclass(frozen=True)
class SealVerdict:
    ok: bool
    violations: list[dict[str, str]] = field(default_factory=list)
    checked: dict[str, Any] = field(default_factory=dict)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_bytecode(parts: tuple[str, ...]) -> bool:
    return "__pycache__" in parts or parts[-1].endswith(".pyc")


def _git(root: Path, *args: str) -> bytes:
    outcome = run_bounded(["git", *args], stage=f"git {args[0]}", timeout=GIT_TIMEOUT, cwd=root)
    if not outcome.succeeded:
        raise SealError(f"git {args[0]} {outcome.describe_failure()}")
    return outcome.stdout


def git_identity(source_root: Path, rev: str = "HEAD") -> tuple[str, str]:
    """(commit, tree) object ids of ``rev``. A failure is an error, never an empty answer."""
    commit = _git(source_root, "rev-parse", "--verify", f"{rev}^{{commit}}").decode().strip()
    tree = _git(source_root, "rev-parse", "--verify", f"{commit}^{{tree}}").decode().strip()
    if not (_GIT_ID.fullmatch(commit) and _GIT_ID.fullmatch(tree)):
        raise SealError("git returned an unexpected object id")
    return commit, tree


def git_is_clean(source_root: Path) -> bool:
    return not _git(source_root, "status", "--porcelain").strip()


def git_package_files(source_root: Path, commit: str) -> dict[str, str]:
    """SHA-256 of every package file as stored in ``commit``: Git blobs, never the working tree."""
    listing = _git(source_root, "ls-tree", "-r", "-z", "--full-name", commit, "--", PACKAGE_SOURCE)
    files: dict[str, str] = {}
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        meta, _, raw_name = entry.partition(b"\t")
        mode, kind, oid = meta.decode().split()
        name = raw_name.decode("utf-8")
        if kind != "blob" or mode not in _FILE_MODES or not name.startswith(PACKAGE_SOURCE + "/"):
            raise SealError(f"unexpected {kind} ({mode}) {name!r} in the package tree of {commit[:12]}")
        rel = name[len(PACKAGE_SOURCE) + 1:]
        if _is_bytecode(tuple(rel.split("/"))):
            continue
        files[rel] = _sha256_bytes(_git(source_root, "cat-file", "blob", oid))
    if not files:
        raise SealError(f"commit {commit[:12]} has no files under {PACKAGE_SOURCE}")
    return files


def _site_packages(release_dir: Path) -> Path:
    found = sorted((release_dir / "venv" / "lib").glob("python3*/site-packages"))
    if len(found) != 1:
        raise SealError(f"expected exactly one site-packages in the release venv, found {len(found)}")
    return found[0]


def installed_package_files(release_dir: Path) -> dict[str, str]:
    """SHA-256 of every file of the package installed in the release venv (read, never imported)."""
    root = _site_packages(release_dir) / PACKAGE
    if not root.is_dir():
        raise SealError("the release venv has no installed package")
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if _is_bytecode(rel.parts) or not (path.is_file() or path.is_symlink()):
            continue
        files[rel.as_posix()] = "symlink" if path.is_symlink() else _sha256_file(path)
    return files


def wheel_package_files(wheel: Path) -> dict[str, str]:
    """SHA-256 of every package file inside the wheel."""
    files: dict[str, str] = {}
    with zipfile.ZipFile(wheel) as archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.startswith(f"{PACKAGE}/"):
                continue
            rel = info.filename[len(PACKAGE) + 1:]
            if _is_bytecode(tuple(rel.split("/"))):
                continue
            files[rel] = _sha256_bytes(archive.read(info))
    return files


def _metadata_version(metadata: bytes) -> str | None:
    for line in metadata.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            break
        key, _, value = line.partition(":")
        if key == "Version":
            return value.strip()
    return None


def wheel_inventory_violations(wheel: Path, expected: Mapping[str, str], *, version: str) -> list[dict[str, str]]:
    """Every member of the wheel must be accounted for, not only the files of the package directory.

    ``wheel_package_files`` reads the package directory and skips the rest, so a module that sits
    next to the package (a stale ``build/lib`` leftover, an ignored local file) or a bytecode-only
    module would pass it. The wheel of this distribution holds exactly the package files of the
    commit (same bytes), the ``<name>-<version>.dist-info`` directory the build backend writes for
    that version, and nothing else. Static: the wheel is only read.
    """
    dist_info = f"{PACKAGE}-{version}.dist-info/"
    package: dict[str, str] = {}
    counts: Counter[str] = Counter()
    unsafe: list[str] = []
    bytecode: list[str] = []
    stray: list[str] = []
    metadata: bytes | None = None
    with zipfile.ZipFile(wheel) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename
            counts[name] += 1
            parts = tuple(name.split("/"))
            if name.startswith("/") or "\\" in name or ".." in parts or "" in parts:
                unsafe.append(name)
            elif _is_bytecode(parts):
                bytecode.append(name)
            elif name.startswith(f"{PACKAGE}/"):
                package[name[len(PACKAGE) + 1:]] = _sha256_bytes(archive.read(info))
            elif name.startswith(dist_info):
                if name == f"{dist_info}METADATA":
                    metadata = archive.read(info)
            else:
                stray.append(name)

    problems: list[dict[str, str]] = []

    def violation(code: str, detail: str) -> None:
        problems.append({"code": code, "detail": detail[:300]})

    def listed(names: list[str]) -> list[str]:
        return sorted(names)[:_LISTED_LIMIT]

    if unsafe:
        violation("wheel_unsafe_member", f"member names that leave the wheel root: {listed(unsafe)}")
    duplicated = [name for name, count in counts.items() if count > 1]
    if duplicated:
        violation("wheel_duplicate_member", f"members stored more than once: {listed(duplicated)}")
    if bytecode:
        violation("wheel_bytecode_member", f"a wheel built from source holds no bytecode: {listed(bytecode)}")
    if stray:
        violation("wheel_stray_member", f"members outside the package and {dist_info.rstrip('/')}: {listed(stray)}")
    differences = diff_files(expected, package)
    if any(differences.values()):
        violation("wheel_package_differs", f"package files differ from the commit's blobs: {differences}")
    if metadata is None:
        violation("wheel_metadata_missing", f"{dist_info}METADATA is not in the wheel")
    elif _metadata_version(metadata) != version:
        violation("wheel_version_differs",
                  f"the wheel declares version {_metadata_version(metadata)!r}, the release is {version!r}")
    return problems


def _normalised(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def installed_dependencies(release_dir: Path) -> dict[str, dict[str, str]]:
    """Every installed distribution: its version and the SHA-256 of its RECORD."""
    dependencies: dict[str, dict[str, str]] = {}
    for dist in sorted(_site_packages(release_dir).glob("*.dist-info")):
        fields: dict[str, str] = {}
        for line in (dist / "METADATA").read_text(encoding="utf-8", errors="replace").splitlines():
            key, _, value = line.partition(":")
            if key in ("Name", "Version") and key not in fields:
                fields[key] = value.strip()
            if not line.strip():
                break
        if "Name" not in fields or "Version" not in fields:
            raise SealError(f"{dist.name} has no Name/Version in METADATA")
        name = _normalised(fields["Name"])
        if name in dependencies:
            raise SealError(f"distribution {name} is installed twice")
        dependencies[name] = {"version": fields["Version"], "record_sha256": _sha256_file(dist / "RECORD")}
    return dependencies


def service_files(release_dir: Path) -> dict[str, str]:
    """SHA-256 of the inherited service files, as observed (they do not come from Git)."""
    root = release_dir / "service"
    files: dict[str, str] = {}
    if root.is_dir():
        for path in sorted(root.rglob("*")):
            rel = path.relative_to(root)
            if path.is_file() and not _is_bytecode(rel.parts):
                files[rel.as_posix()] = _sha256_file(path)
    return files


def interpreter_identity(release_dir: Path) -> dict[str, str]:
    """The release interpreter's real executable and its SHA-256 (not the libraries it loads)."""
    real = Path(os.path.realpath(release_dir / "venv" / "bin" / "python"))
    if not real.is_file():
        raise SealError("the release venv interpreter does not resolve to a file")
    identity = {"realpath": str(real), "sha256": _sha256_file(real)}
    try:
        for line in (release_dir / "venv" / "pyvenv.cfg").read_text().splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "version":
                identity["version"] = value.strip()
    except OSError:
        pass
    return identity


def diff_files(expected: Mapping[str, str], observed: Mapping[str, str]) -> dict[str, list[str]]:
    return {
        "missing": sorted(set(expected) - set(observed))[:_LISTED_LIMIT],
        "unexpected": sorted(set(observed) - set(expected))[:_LISTED_LIMIT],
        "changed": sorted(n for n in set(expected) & set(observed) if expected[n] != observed[n])[:_LISTED_LIMIT],
    }


def _differs(expected: Mapping[str, Any], observed: Mapping[str, Any]) -> bool:
    return dict(expected) != dict(observed)


def create_seal(source_root: Path, release_dir: Path, *, commit: str | None = None) -> dict[str, Any]:
    """Seal an existing release, refusing unless its bytes are exactly the commit's.

    The package files are taken from the Git blobs of ``commit`` and must equal both the files
    installed in the release venv and the files inside its wheel.
    """
    try:
        release_dir = release_dir.resolve(strict=True)
        manifest = json.loads((release_dir / "RELEASE_MANIFEST.json").read_text())
    except (OSError, ValueError) as exc:
        raise SealError(f"release manifest unreadable: {type(exc).__name__}: {exc}") from exc
    sealed_commit, tree = git_identity(source_root, commit or "HEAD")
    if (manifest.get("source_commit"), manifest.get("source_tree")) != (sealed_commit, tree):
        raise SealError("the release was not built from this commit")
    if not isinstance(manifest.get("tool_contract"), dict) or not manifest["tool_contract"]:
        raise SealError("the release has not passed the pre-activation gates (its manifest records no tool contract)")
    expected = git_package_files(source_root, sealed_commit)
    wheel_rel = manifest.get("wheel_file")
    if not isinstance(wheel_rel, str) or not wheel_rel:
        raise SealError("the release manifest names no wheel")
    try:
        observed = {"installed package": installed_package_files(release_dir),
                    "wheel": wheel_package_files(release_dir / wheel_rel)}
    except (OSError, zipfile.BadZipFile) as exc:
        raise SealError(f"release artifacts unreadable: {type(exc).__name__}: {exc}") from exc
    for label, files in observed.items():
        differences = diff_files(expected, files)
        if any(differences.values()):
            raise SealError(f"the {label} differs from the Git blobs of {sealed_commit[:12]}: {differences}")
    version = manifest.get("package_version")
    if not isinstance(version, str) or not version:
        raise SealError("the release manifest names no package version")
    try:
        inventory = wheel_inventory_violations(release_dir / wheel_rel, expected, version=version)
    except (OSError, zipfile.BadZipFile) as exc:
        raise SealError(f"release artifacts unreadable: {type(exc).__name__}: {exc}") from exc
    if inventory:
        raise SealError(f"the wheel holds more than the commit's package: {inventory}")
    return {
        "schema_version": SEAL_SCHEMA,
        "release_id": release_dir.name,
        "release_dir": str(release_dir),
        "source": {"commit": sealed_commit, "tree": tree},
        "manifest_sha256": _sha256_file(release_dir / "RELEASE_MANIFEST.json"),
        "runtime_manifest_sha256": _sha256_file(release_dir / RUNTIME_MANIFEST),
        "wheel": {"file": wheel_rel, "sha256": _sha256_file(release_dir / wheel_rel)},
        "package_files": expected,
        "dependencies": installed_dependencies(release_dir),
        "service_files": service_files(release_dir),
        "interpreter": interpreter_identity(release_dir),
    }


def write_seal(path: Path, seal: Mapping[str, Any]) -> str:
    """Create ``path`` exclusively (a seal is never overwritten); returns the SHA-256 of the file."""
    data = (json.dumps(seal, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        with path.open("xb") as handle:
            handle.write(data)
    except FileExistsError as exc:
        raise SealError(f"{path} already exists; a seal is never overwritten") from exc
    except OSError as exc:
        path.unlink(missing_ok=True)
        raise SealError(f"seal could not be written: {type(exc).__name__}: {exc}") from exc
    return _sha256_bytes(data)


def _require(condition: bool, what: str) -> None:
    if not condition:
        raise SealError(f"seal is invalid: {what}")


def _is_hash_map(value: object) -> bool:
    return isinstance(value, dict) and all(
        isinstance(k, str) and isinstance(v, str) and _SHA256.fullmatch(v) for k, v in value.items())


def load_seal(path: str | Path) -> dict[str, Any]:
    """Read and strictly validate a seal; the result carries ``path`` and the file's ``sha256``."""
    target = Path(path)
    try:
        data = target.read_bytes()
        seal = json.loads(data)
    except (OSError, ValueError) as exc:
        raise SealError(f"seal unreadable: {type(exc).__name__}: {exc}") from exc
    _require(isinstance(seal, dict), "not an object")
    _require(seal.get("schema_version") == SEAL_SCHEMA, f"schema_version must be {SEAL_SCHEMA}")
    _require(set(seal) == _SEAL_KEYS, f"keys must be exactly {sorted(_SEAL_KEYS)}")
    _require(isinstance(seal["release_id"], str) and bool(seal["release_id"]), "release_id")
    _require(isinstance(seal["release_dir"], str) and os.path.isabs(seal["release_dir"]),
             "release_dir must be an absolute path")
    source = seal["source"]
    _require(isinstance(source, dict) and set(source) == {"commit", "tree"}
             and all(isinstance(source[k], str) and _GIT_ID.fullmatch(source[k]) for k in source),
             "source must hold a 40-hex commit and tree")
    for key in ("manifest_sha256", "runtime_manifest_sha256"):
        _require(isinstance(seal[key], str) and bool(_SHA256.fullmatch(seal[key])), key)
    wheel = seal["wheel"]
    _require(isinstance(wheel, dict) and set(wheel) == {"file", "sha256"} and isinstance(wheel["file"], str)
             and isinstance(wheel["sha256"], str) and bool(_SHA256.fullmatch(wheel["sha256"])), "wheel")
    _require(_is_hash_map(seal["package_files"]) and bool(seal["package_files"]), "package_files")
    _require(_is_hash_map(seal["service_files"]), "service_files")
    dependencies = seal["dependencies"]
    _require(isinstance(dependencies, dict) and all(
        isinstance(k, str) and isinstance(v, dict) and set(v) == {"version", "record_sha256"}
        and isinstance(v["version"], str) and isinstance(v["record_sha256"], str)
        and _SHA256.fullmatch(v["record_sha256"]) for k, v in dependencies.items()), "dependencies")
    interpreter = seal["interpreter"]
    _require(isinstance(interpreter, dict) and {"realpath", "sha256"} <= set(interpreter)
             and bool(_SHA256.fullmatch(str(interpreter.get("sha256")))), "interpreter")
    return {**seal, "path": str(target.resolve()), "sha256": _sha256_bytes(data)}


def identity_violations(seal: Mapping[str, Any], *, commit: str, tree: str,
                        release_dir: Path) -> list[dict[str, str]]:
    """The cheap checks that need no file hashing: which commit, tree and directory is being released."""
    problems: list[dict[str, str]] = []
    if commit != seal["source"]["commit"]:
        problems.append({"code": "commit_differs",
                         "detail": f"source HEAD {commit[:12]} is not the sealed commit {seal['source']['commit'][:12]}"})
    if tree != seal["source"]["tree"]:
        problems.append({"code": "tree_differs", "detail": "source tree is not the sealed tree"})
    if os.path.realpath(release_dir) != seal["release_dir"] or release_dir.name != seal["release_id"]:
        problems.append({"code": "release_path_differs",
                         "detail": f"release directory {release_dir} is not the sealed {seal['release_dir']}"})
    return problems


def verify_seal(seal: Mapping[str, Any], *, source_root: Path, release_dir: Path) -> SealVerdict:
    """Re-derive everything the seal states and report EVERY difference (static, read-only)."""
    problems: list[dict[str, str]] = []
    checked: dict[str, Any] = {}

    def violation(code: str, detail: str) -> None:
        problems.append({"code": code, "detail": detail})

    def observe(code: str, produce: Callable[[], Any]) -> Any:
        try:
            return produce()
        except (SealError, OSError, ValueError, zipfile.BadZipFile) as exc:
            violation(code, f"{type(exc).__name__}: {exc}"[:300])
            return None

    try:
        commit, tree = git_identity(source_root)
        problems.extend(identity_violations(seal, commit=commit, tree=tree, release_dir=release_dir))
        if not git_is_clean(source_root):
            violation("source_dirty", "the source worktree has uncommitted changes")
    except SealError as exc:
        violation("source_unreadable", str(exc)[:300])

    if not release_dir.is_dir():
        violation("release_missing", f"{release_dir} does not exist")
        return SealVerdict(False, problems, checked)

    manifest_sha = observe("manifest_unreadable", lambda: _sha256_file(release_dir / "RELEASE_MANIFEST.json"))
    if manifest_sha is not None and manifest_sha != seal["manifest_sha256"]:
        violation("manifest_differs", "RELEASE_MANIFEST.json is not the sealed manifest")
    runtime_sha = observe("runtime_manifest_unreadable", lambda: _sha256_file(release_dir / RUNTIME_MANIFEST))
    if runtime_sha is not None and runtime_sha != seal["runtime_manifest_sha256"]:
        violation("runtime_manifest_differs", f"{RUNTIME_MANIFEST} is not the sealed runtime manifest")
    wheel_sha = observe("wheel_unreadable", lambda: _sha256_file(release_dir / seal["wheel"]["file"]))
    if wheel_sha is not None and wheel_sha != seal["wheel"]["sha256"]:
        violation("wheel_differs", "the wheel is not the sealed wheel")

    installed = observe("package_unreadable", lambda: installed_package_files(release_dir))
    if installed is not None:
        checked["package_files"] = len(installed)
        if _differs(seal["package_files"], installed):
            violation("package_files_differ",
                      f"installed package differs from the seal: {diff_files(seal['package_files'], installed)}")
    blobs = observe("git_blobs_unreadable", lambda: git_package_files(source_root, seal["source"]["commit"]))
    if blobs is not None and _differs(seal["package_files"], blobs):
        violation("seal_contradicts_git",
                  f"the seal's package hashes are not the Git blobs of its commit: {diff_files(blobs, seal['package_files'])}")

    dependencies = observe("dependencies_unreadable", lambda: installed_dependencies(release_dir))
    if dependencies is not None:
        checked["dependencies"] = len(dependencies)
        if _differs(seal["dependencies"], dependencies):
            changed = sorted(n for n in set(seal["dependencies"]) | set(dependencies)
                             if seal["dependencies"].get(n) != dependencies.get(n))
            violation("dependencies_differ", f"installed distributions differ from the seal: {changed[:_LISTED_LIMIT]}")
    service = observe("service_unreadable", lambda: service_files(release_dir))
    if service is not None and _differs(seal["service_files"], service):
        violation("service_files_differ",
                  f"service files differ from the seal: {diff_files(seal['service_files'], service)}")
    interpreter = observe("interpreter_unreadable", lambda: interpreter_identity(release_dir))
    if interpreter is not None and (interpreter["realpath"], interpreter["sha256"]) != (
            seal["interpreter"]["realpath"], seal["interpreter"]["sha256"]):
        violation("interpreter_differs", "the release interpreter executable is not the sealed one")
    return SealVerdict(not problems, problems, checked)
