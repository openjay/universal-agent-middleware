from __future__ import annotations

"""Workspace registry and descriptor-anchored reader with root identity binding (R3.1-01).

Root identity binding & residual same-UID threat boundary:
* At authorization/registration time, UAM establishes a ``RootIdentity(dev, ino, root, policy_version,
  policy_generation)`` from an ``O_DIRECTORY | O_NOFOLLOW`` descriptor of the canonical root directory.
* Every subsequent read session opens the pinned root path without re-resolving new symlink targets
  (never calling ``Path.resolve(strict=True)`` to accept a replaced root or swapped parent symlink),
  and verifies ``(st_dev, st_ino)``, ``realpath``, directory permissions (``R_OK | X_OK``), and live
  authority at both the read (entry) stage and the return (exit) stage.
* Residual same-UID threat: when a concurrent malicious process runs under the same OS UID and can
  modify ancestor directories or process state while UAM executes, neither a single ``stat`` nor
  user-space FD pinning can provide kernel-grade isolation against arbitrary same-UID concurrent
  parent-tree splicing or same-UID process interference between syscalls. Eliminating same-UID
  adversary capabilities requires OS principal separation (distinct UID / MAC / container boundary).
"""

import fcntl
import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .descriptor_io import (
    NotADirectoryTarget,
    Opened,
    OpenDenied,
    list_directory,
    open_beneath,
    open_child,
    open_root,
    read_bounded,
    require_descriptor_walk,
    stat_beneath,
)
from .errors import PathPolicyError, WorkspaceError, WorkspaceUnavailableError
from .file_digest import digest_denied, digest_opened_file
from .models import (
    KIND_CAPABILITIES,
    KIND_FILESYSTEM_DIRECTORY,
    ROOT_POLICY_VERSION,
    RootIdentity,
    WorkspaceSpec,
)
from .path_authority import PathOperation, PathPolicy
from .policy import ensure_relative_path, is_denied_component

_ALLOWED_CAPABILITIES = frozenset().union(*KIND_CAPABILITIES.values())
# Registry fields that describe a Git repository; a directory has no identity to declare.
_GIT_ONLY_FIELDS = frozenset({"repository_identity", "discovery"})
_REGISTRY_VERSION = "uam-workspace-registry-v1"
_WORKSPACE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

ROOT_MISSING = "root_missing"
ROOT_NOT_DIRECTORY = "root_not_directory"
ROOT_UNRESOLVABLE = "root_unresolvable"
ROOT_IDENTITY_CHANGED = "root_identity_changed"


# Registry fields that group a workspace into a project. The registry validates their names only; ``declarations()``
# hands them to ``ProjectRegistry`` from the same read that produced the served entries.
_PROJECT_FIELDS = ("project_id", "role", "lifecycle", "repository_identity", "discovery")


@dataclass(frozen=True)
class _RegistryEntry:
    """A validated registry declaration and why its root could not be served at load."""

    spec: WorkspaceSpec
    load_reason: str | None
    root_identity: RootIdentity | None = None
    declared_root: str = ""
    declared: dict[str, Any] = field(default_factory=dict)


def _best_effort_path(path: Path) -> str:
    try:
        return str(path.resolve(strict=False))
    except (OSError, RuntimeError):
        return os.path.abspath(path)


def _is_root_readable(path: Path, info: os.stat_result) -> bool:
    if hasattr(os, "geteuid") and os.geteuid() != 0 and (info.st_mode & 0o500) != 0o500:
        return False
    return os.access(path, os.R_OK | os.X_OK)


def _fd_canonical_path(fd: int) -> Path | None:
    """Return the kernel-resolved path for ``fd`` when ``fcntl.F_GETPATH`` is supported."""
    if not hasattr(fcntl, "F_GETPATH"):
        return None
    raw = fcntl.fcntl(fd, fcntl.F_GETPATH, bytes(1024))
    nul = raw.find(0)
    if nul >= 0:
        raw = raw[:nul]
    return Path(os.fsdecode(raw))


def _probe_git_marker(root_fd: int) -> tuple[int | None, int | None, int | None]:
    """Capture ``(st_dev, st_ino, S_IFMT(st_mode))`` of ``.git`` inside ``root_fd`` when present."""
    try:
        info = os.stat(".git", dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None, None, None
    except OSError as exc:
        raise WorkspaceError("workspace root .git entry cannot be inspected") from exc
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def bind_root_identity(
    raw_root: str | Path,
    *,
    policy_version: str = ROOT_POLICY_VERSION,
    policy_generation: str = "",
) -> RootIdentity:
    """Establish a trusted ``RootIdentity`` for ``raw_root`` at authorization time."""
    declared = Path(raw_root).expanduser()
    try:
        resolved = declared.resolve(strict=True)
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise WorkspaceError("workspace root does not exist") from exc
    except (OSError, RuntimeError) as exc:
        raise WorkspaceError("workspace root cannot be resolved") from exc
    try:
        lstat_info = os.stat(resolved, follow_symlinks=False)
    except OSError as exc:
        raise WorkspaceError("workspace root cannot be inspected") from exc
    if not stat.S_ISDIR(lstat_info.st_mode):
        raise WorkspaceError("workspace root is not a directory")
    root_fd = open_root(resolved)
    try:
        held = os.fstat(root_fd)
        if not stat.S_ISDIR(held.st_mode):
            raise WorkspaceError("workspace root is not a directory")
        if (held.st_dev, held.st_ino) != (lstat_info.st_dev, lstat_info.st_ino):
            raise WorkspaceError("workspace root identity changed during binding")
        if Path(os.path.realpath(resolved)) != resolved:
            raise WorkspaceError("workspace root identity changed during binding")
        fd_path = _fd_canonical_path(root_fd)
        if fd_path is not None and fd_path != resolved:
            raise WorkspaceError("workspace root identity changed during binding")
        if not _is_root_readable(resolved, held):
            raise WorkspaceError("workspace root is not readable")
        git_dev, git_ino, git_mode = _probe_git_marker(root_fd)
    finally:
        os.close(root_fd)
    return RootIdentity(
        dev=held.st_dev,
        ino=held.st_ino,
        root=str(resolved),
        policy_version=policy_version,
        policy_generation=policy_generation,
        git_dev=git_dev,
        git_ino=git_ino,
        git_mode=git_mode,
    )


def verify_bound_root_fd(root_fd: int, identity: RootIdentity) -> None:
    """Verify that ``root_fd`` and ``identity.root`` still name the bound root object and remain readable."""
    if identity.policy_version != ROOT_POLICY_VERSION:
        raise WorkspaceError("workspace root policy version mismatch")
    root_path = Path(identity.root)
    try:
        held = os.fstat(root_fd)
        lstat_info = os.stat(root_path, follow_symlinks=False)
        real_now = Path(os.path.realpath(root_path))
        fd_path = _fd_canonical_path(root_fd)
    except OSError as exc:
        raise WorkspaceError("workspace root identity changed or became inaccessible") from exc
    if stat.S_ISLNK(lstat_info.st_mode) or not stat.S_ISDIR(lstat_info.st_mode) or not stat.S_ISDIR(held.st_mode):
        raise WorkspaceError("workspace root identity changed: not a directory")
    if (held.st_dev, held.st_ino) != (identity.dev, identity.ino):
        raise WorkspaceError("workspace root identity changed")
    if (lstat_info.st_dev, lstat_info.st_ino) != (identity.dev, identity.ino):
        raise WorkspaceError("workspace root identity changed")
    if real_now != root_path:
        raise WorkspaceError("workspace root identity changed")
    if fd_path is not None and fd_path != root_path:
        raise WorkspaceError("workspace root identity changed")
    if not _is_root_readable(root_path, held):
        raise WorkspaceError("workspace root permissions revoked")
    if identity.git_dev is not None:
        now_git = _probe_git_marker(root_fd)
        if now_git != (identity.git_dev, identity.git_ino, identity.git_mode):
            raise WorkspaceError("workspace root identity changed: .git entry replaced")


def open_verified_root(identity: RootIdentity) -> tuple[int, Path]:
    """Open the workspace root anchored to ``identity`` without re-resolving new symlink targets."""
    if identity.policy_version != ROOT_POLICY_VERSION:
        raise WorkspaceError("workspace root policy version mismatch")
    root_real = Path(identity.root)
    try:
        lstat_info = os.stat(root_real, follow_symlinks=False)
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise WorkspaceError("workspace root does not exist") from exc
    except OSError as exc:
        raise WorkspaceError("workspace root is not accessible") from exc
    if stat.S_ISLNK(lstat_info.st_mode):
        raise WorkspaceError("workspace root identity changed: symlink at root")
    if not stat.S_ISDIR(lstat_info.st_mode):
        raise WorkspaceError("workspace root is not a directory")
    if (lstat_info.st_dev, lstat_info.st_ino) != (identity.dev, identity.ino):
        raise WorkspaceError("workspace root identity changed")
    if Path(os.path.realpath(root_real)) != root_real:
        raise WorkspaceError("workspace root identity changed")
    root_fd = open_root(root_real)
    try:
        verify_bound_root_fd(root_fd, identity)
    except BaseException:
        os.close(root_fd)
        raise
    return root_fd, root_real


def _probe_root(raw_root: str, *, policy_generation: str = "") -> tuple[str, str | None, RootIdentity | None]:
    """Resolve a declared root once; return (root, None, identity) or (declared root, reason, None)."""
    declared = Path(raw_root).expanduser()
    try:
        resolved = declared.resolve(strict=True)
    except (FileNotFoundError, NotADirectoryError):
        return _best_effort_path(declared), ROOT_MISSING, None
    except (OSError, RuntimeError):
        return _best_effort_path(declared), ROOT_UNRESOLVABLE, None
    try:
        lstat_info = os.stat(resolved, follow_symlinks=False)
    except OSError:
        return str(resolved), ROOT_UNRESOLVABLE, None
    if not stat.S_ISDIR(lstat_info.st_mode):
        return str(resolved), ROOT_NOT_DIRECTORY, None
    try:
        root_fd = open_root(resolved)
    except OSError:
        return str(resolved), ROOT_UNRESOLVABLE, None
    try:
        held = os.fstat(root_fd)
        if not stat.S_ISDIR(held.st_mode):
            return str(resolved), ROOT_NOT_DIRECTORY, None
        if (held.st_dev, held.st_ino) != (lstat_info.st_dev, lstat_info.st_ino):
            return str(resolved), ROOT_IDENTITY_CHANGED, None
        if not _is_root_readable(resolved, held):
            return str(resolved), ROOT_UNRESOLVABLE, None
        git_dev, git_ino, git_mode = _probe_git_marker(root_fd)
        identity = RootIdentity(
            dev=held.st_dev,
            ino=held.st_ino,
            root=str(resolved),
            policy_version=ROOT_POLICY_VERSION,
            policy_generation=policy_generation,
            git_dev=git_dev,
            git_ino=git_ino,
            git_mode=git_mode,
        )
    except (OSError, WorkspaceError):
        return str(resolved), ROOT_UNRESOLVABLE, None
    finally:
        os.close(root_fd)
    return str(resolved), None, identity


class WorkspaceRegistry:
    """Validated workspace declarations plus which of them can be served right now.

    Schema, identifier, kind and capability errors still reject the whole
    registry (fail closed). A root that is missing, not a directory or cannot be
    resolved only makes that one workspace unavailable: it is never served, it
    is reported through ``unavailable()``/``coverage()``, and its identity stays
    reserved so no other workspace can answer to it. Availability fixed at load
    time is re-evaluated on the next registry reload; a root that was served at
    load keeps its pinned path and is re-checked on every access.
    """

    def __init__(self, registry_path: str | Path):
        self.registry_path = Path(registry_path)
        self._source_mtime_ns: int | None = None
        self._source_size: int | None = None
        self._source_hash: str = ""
        self._loaded_at: str | None = None
        self._entries = self._load()

    def _clear_registry(self) -> None:
        self._entries = {}
        self._source_mtime_ns = None
        self._source_size = None
        self._source_hash = ""
        self._loaded_at = None

    def _load(self) -> dict[str, _RegistryEntry]:
        try:
            stat = self.registry_path.stat()
            raw_text = self.registry_path.read_text(encoding="utf-8")
            payload = json.loads(raw_text)
        except FileNotFoundError as exc:
            raise WorkspaceError(
                f"workspace registry not found: {self.registry_path}"
            ) from exc
        except (json.JSONDecodeError, OSError) as exc:
            raise WorkspaceError(
                f"workspace registry unreadable: {self.registry_path}"
            ) from exc
        if not isinstance(payload, dict):
            raise WorkspaceError("workspace registry must be an object")
        unknown_root = sorted(set(payload) - {"registry_version", "workspaces"})
        if unknown_root:
            raise WorkspaceError(f"unknown workspace registry fields: {', '.join(unknown_root)}")
        if payload.get("registry_version") != _REGISTRY_VERSION:
            raise WorkspaceError(f"unsupported workspace registry version: {payload.get('registry_version')}")
        if not isinstance(payload.get("workspaces"), list):
            raise WorkspaceError("workspace registry must contain a workspaces list")
        source_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        entries: dict[str, _RegistryEntry] = {}
        for raw in payload.get("workspaces", []):
            if not isinstance(raw, dict):
                raise WorkspaceError("workspace entry must be an object")
            allowed_fields = {
                "workspace_id", "root", "label", "kind", "capabilities",
                "max_file_bytes", "max_search_files",
                "project_id", "role", "lifecycle", "repository_identity", "discovery",
            }
            required_fields = {"workspace_id", "root", "kind", "capabilities"}
            missing = sorted(required_fields - set(raw))
            if missing:
                raise WorkspaceError(
                    f"missing required workspace fields: {', '.join(missing)}"
                )
            unknown = sorted(set(raw) - allowed_fields)
            if unknown:
                raise WorkspaceError(f"unknown workspace fields: {', '.join(unknown)}")
            spec = WorkspaceSpec(
                workspace_id=raw["workspace_id"],
                root=raw["root"],
                label=raw.get("label", ""),
                kind=raw["kind"],
                capabilities=raw["capabilities"],
                max_file_bytes=raw.get("max_file_bytes", 524_288),
                max_search_files=raw.get("max_search_files", 5_000),
            )
            if not _WORKSPACE_ID.fullmatch(spec.workspace_id) or spec.workspace_id in entries:
                raise WorkspaceError("workspace_id must be unique and match the V1 identifier grammar")
            if not isinstance(spec.kind, str) or spec.kind not in KIND_CAPABILITIES:
                raise WorkspaceError(f"unsupported workspace kind: {spec.kind}")
            if not spec.capabilities or any(
                capability not in _ALLOWED_CAPABILITIES for capability in spec.capabilities
            ):
                raise WorkspaceError("workspace declares an unsupported capability")
            beyond_kind = [c for c in spec.capabilities if c not in KIND_CAPABILITIES[spec.kind]]
            if beyond_kind:
                raise WorkspaceError(
                    f"workspace kind {spec.kind} cannot grant capability {beyond_kind[0]}"
                )
            if spec.kind == KIND_FILESYSTEM_DIRECTORY:
                git_only = sorted(set(raw) & _GIT_ONLY_FIELDS)
                if git_only:
                    raise WorkspaceError(
                        f"fields not applicable to workspace kind {spec.kind}: {', '.join(git_only)}"
                    )
            root, load_reason, root_identity = _probe_root(spec.root, policy_generation=source_hash)
            entries[spec.workspace_id] = _RegistryEntry(
                spec=WorkspaceSpec(
                    workspace_id=spec.workspace_id,
                    root=root,
                    label=spec.label,
                    kind=spec.kind,
                    capabilities=list(dict.fromkeys(spec.capabilities)),
                    max_file_bytes=spec.max_file_bytes,
                    max_search_files=spec.max_search_files,
                    root_identity=root_identity,
                ),
                load_reason=load_reason,
                root_identity=root_identity,
                declared_root=spec.root,
                declared={key: raw[key] for key in _PROJECT_FIELDS if key in raw},
            )
        self._source_mtime_ns = stat.st_mtime_ns
        self._source_size = stat.st_size
        self._source_hash = source_hash
        self._loaded_at = datetime.now(timezone.utc).isoformat()
        return entries

    def _maybe_reload(self) -> None:
        """Reload registry from disk when workspaces.json has changed or revoked."""
        if not self.registry_path.exists():
            if self._entries or self._source_hash:
                self._clear_registry()
            return
        try:
            stat = self.registry_path.stat()
            raw_text = self.registry_path.read_text(encoding="utf-8")
            content_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        except OSError:
            if self._entries or self._source_hash:
                self._clear_registry()
            return
        if (
            self._source_mtime_ns is not None
            and stat.st_mtime_ns == self._source_mtime_ns
            and self._source_size == stat.st_size
            and self._source_hash == content_hash
        ):
            return
        self._entries = self._load()

    @staticmethod
    def _current_reason(entry: _RegistryEntry) -> str | None:
        """Why this workspace cannot be served now, or None when it can."""
        if entry.load_reason is not None:
            return entry.load_reason
        identity = entry.root_identity
        if identity is None:
            return ROOT_UNRESOLVABLE
        root_path = Path(identity.root)
        if entry.declared_root:
            declared = Path(entry.declared_root).expanduser()
            try:
                declared_resolved = declared.resolve(strict=True)
            except (FileNotFoundError, NotADirectoryError):
                return ROOT_MISSING if not root_path.exists() else ROOT_IDENTITY_CHANGED
            except (OSError, RuntimeError):
                return ROOT_UNRESOLVABLE
            if declared_resolved != root_path:
                return ROOT_IDENTITY_CHANGED
        try:
            lstat_info = os.stat(root_path, follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError):
            return ROOT_MISSING
        except OSError:
            return ROOT_UNRESOLVABLE
        if stat.S_ISLNK(lstat_info.st_mode):
            return ROOT_IDENTITY_CHANGED
        if not stat.S_ISDIR(lstat_info.st_mode):
            return ROOT_NOT_DIRECTORY
        if (lstat_info.st_dev, lstat_info.st_ino) != (identity.dev, identity.ino):
            return ROOT_IDENTITY_CHANGED
        try:
            real_now = Path(os.path.realpath(root_path))
        except OSError:
            return ROOT_UNRESOLVABLE
        if real_now != root_path:
            return ROOT_IDENTITY_CHANGED
        try:
            root_fd = open_root(root_path)
        except (FileNotFoundError, NotADirectoryError):
            return ROOT_MISSING
        except OSError:
            return ROOT_UNRESOLVABLE
        try:
            held = os.fstat(root_fd)
            if not stat.S_ISDIR(held.st_mode):
                return ROOT_NOT_DIRECTORY
            if (held.st_dev, held.st_ino) != (identity.dev, identity.ino):
                return ROOT_IDENTITY_CHANGED
            fd_path = _fd_canonical_path(root_fd)
            if fd_path is not None and fd_path != root_path:
                return ROOT_IDENTITY_CHANGED
            if identity.git_dev is not None:
                if _probe_git_marker(root_fd) != (identity.git_dev, identity.git_ino, identity.git_mode):
                    return ROOT_IDENTITY_CHANGED
            if not _is_root_readable(root_path, held):
                return ROOT_UNRESOLVABLE
        except (OSError, WorkspaceError):
            return ROOT_UNRESOLVABLE
        finally:
            os.close(root_fd)
        return None

    def list(self) -> list[dict[str, Any]]:
        """Workspaces that can be served right now; see ``unavailable()`` for the rest."""
        self._maybe_reload()
        return [
            entry.spec.to_dict() for entry in self._entries.values()
            if self._current_reason(entry) is None
        ]

    def unavailable(self) -> list[dict[str, Any]]:
        """Registered workspaces that cannot be served, with the local root for operators."""
        self._maybe_reload()
        result: list[dict[str, Any]] = []
        for entry in self._entries.values():
            reason = self._current_reason(entry)
            if reason is not None:
                result.append({
                    "workspace_id": entry.spec.workspace_id,
                    "label": entry.spec.label,
                    "reason": reason,
                    "root": entry.spec.root,
                })
        return result

    def coverage(self) -> dict[str, Any]:
        """Root-free summary of which registered workspaces are served right now.

        ``complete`` is about the registered workspaces only (``basis``). It says nothing about
        directories inside authorized RootScopes that are not registered: those may still be
        admitted on demand, or be unreadable, and this summary does not assess them.
        """
        self._maybe_reload()
        unavailable = [
            {"workspace_id": item["workspace_id"], "label": item["label"], "reason": item["reason"]}
            for item in self.unavailable()
        ]
        return {
            "schema_version": "workspace-coverage-v1",
            "basis": "registered_workspaces",
            "unregistered_root_scope_paths": "not_assessed",
            "registered": len(self._entries),
            "available": len(self._entries) - len(unavailable),
            "unavailable": unavailable,
            "complete": not unavailable,
        }

    def snapshot(self) -> dict[str, Any]:
        """Identity of the registry file contents this instance is currently serving."""
        self._maybe_reload()
        return {"registry_sha256": self._source_hash, "loaded_at": self._loaded_at}

    def declarations(self) -> tuple[str, list[dict[str, Any]]]:
        """The registry generation being served and every declaration in it, usable or not.

        The generation is the SHA-256 of the registry text these entries were loaded from (empty
        when the file is absent, which serves nothing). ``ProjectRegistry`` builds its view from
        this single read instead of reading the file a second time, so a project is listed only
        while the registry that registers it is the one being served. A registry that cannot be
        served raises ``WorkspaceError`` (fail closed). ``root`` is the root as declared and
        ``resolved_root`` the one pinned at load: both are host paths and are for the northbound
        output boundary to recognise, never to print.
        """
        self._maybe_reload()
        return self._source_hash, [
            {
                **entry.declared,
                "workspace_id": entry.spec.workspace_id,
                "root": entry.declared_root,
                "resolved_root": entry.spec.root,
                "label": entry.spec.label,
                "kind": entry.spec.kind,
            }
            for entry in self._entries.values()
        ]

    def is_registered(self, workspace_id: str) -> bool:
        """True when the registry declares this identity, usable or not."""
        self._maybe_reload()
        return workspace_id in self._entries

    def get(self, workspace_id: str) -> WorkspaceSpec:
        self._maybe_reload()
        entry = self._entries.get(workspace_id)
        if entry is None:
            raise WorkspaceError(f"unknown workspace: {workspace_id}")
        reason = self._current_reason(entry)
        if reason is not None:
            raise WorkspaceUnavailableError(workspace_id, reason)
        return entry.spec

    def has(self, workspace_id: str) -> bool:
        self._maybe_reload()
        entry = self._entries.get(workspace_id)
        return entry is not None and self._current_reason(entry) is None

    def require_capability(self, workspace_id: str, capability: str) -> WorkspaceSpec:
        spec = self.get(workspace_id)
        if capability not in spec.capabilities:
            raise WorkspaceError(
                f"workspace {workspace_id} does not grant capability {capability}"
            )
        return spec


@dataclass
class _TreeState:
    """What one ``tree`` call accumulates while it walks descriptors."""

    root_real: Path
    base_depth: int
    depth: int
    max_entries: int
    entries: list[dict[str, Any]] = field(default_factory=list)
    truncated: bool = False
    withheld: bool = False  # part of the tree was left out because its scope does not allow enumeration


@dataclass
class _SearchState:
    """What one ``search_text`` call accumulates while it walks descriptors."""

    query: str
    needle: str
    max_results: int
    root_real: Path
    results: list[dict[str, Any]] = field(default_factory=list)
    scanned: int = 0
    oversized: int = 0
    binary: int = 0
    errors: int = 0
    withheld: bool = False  # part of the tree was left out because its scope does not allow search


class WorkspaceReader:
    """Confined, read-only access to one workspace.

    ``path_policy`` carries the authority of RootScopes nested under the workspace root; the
    default is unrestricted, which is what a static registration gets (see ``path_authority``).
    The policy is a snapshot: build one reader per operation.
    """

    def __init__(
        self,
        spec: WorkspaceSpec,
        *,
        path_policy: PathPolicy | None = None,
        authority_check: Callable[[], None] | None = None,
    ):
        if "filesystem.read" not in spec.capabilities:
            raise WorkspaceError("workspace does not grant filesystem.read")
        self.spec = spec
        self.root = Path(spec.root)
        self._policy = path_policy or PathPolicy.unrestricted()
        self._authority_check = authority_check
        if spec.root_identity is not None:
            self.root_identity: RootIdentity | None = spec.root_identity
        else:
            try:
                self.root_identity = bind_root_identity(self.root)
            except WorkspaceError:
                self.root_identity = None

    # Every listing or content operation takes the same three steps, and the second and third are ONE act:
    #   1. authority from the path as written (traversal, denied names, nested scopes), before the filesystem is
    #      consulted, so a denied subtree cannot be probed for which files exist;
    #   2. the descriptor walk (``descriptor_io.open_beneath``): names are validated and opened component by component
    #      and the kernel is never asked to follow a link, so nothing can change between "checked" and "opened";
    #   3. authority again on the path that was REALLY opened (an alias of a denied file is denied by where it lives)
    #      and the hard-link check on the object that is held, before the first byte is read.
    # There is no fallback to opening by path: a platform without the primitives refuses (see ``descriptor_io``).
    def _authorize(self, raw: str, operation: PathOperation, root_real: Path) -> tuple[str, ...]:
        rel = ensure_relative_path(raw)
        self._policy.require(operation, root_real / rel)
        return rel.parts

    def _verify_return_stage(self, root_fd: int, root_real: Path) -> None:
        """Re-verify root identity, permissions, and live authority before returning data."""
        if self.root_identity is None:
            raise WorkspaceError("workspace root identity is not bound")
        verify_bound_root_fd(root_fd, self.root_identity)
        if self._authority_check is not None:
            self._authority_check()

    @contextmanager
    def _session(self) -> Iterator[tuple[int, Path]]:
        """The workspace root, opened once for one operation: ``(descriptor, real path)``."""
        require_descriptor_walk()
        if self._authority_check is not None:
            self._authority_check()
        if self.root_identity is None:
            raise WorkspaceError("workspace root identity is not bound")
        root_fd, root_real = open_verified_root(self.root_identity)
        try:
            yield root_fd, root_real
            self._verify_return_stage(root_fd, root_real)
        finally:
            os.close(root_fd)

    def _open(
        self, root_fd: int, root_real: Path, parts: tuple[str, ...], operation: PathOperation, kind: str
    ) -> Opened:
        try:
            opened = open_beneath(root_fd, root_real, parts, kind=kind)
        except (FileNotFoundError, NotADirectoryError) as exc:
            # Authority was decided first (``_authorize``), so this is no existence oracle for a protected name. The
            # operating system's text names the entry and an ``OSError`` is not caught by a tool body: answer, typed.
            raise WorkspaceError("path does not exist") from exc
        try:
            self._policy.require(operation, root_real.joinpath(*opened.parts))
        except BaseException:
            opened.close()
            raise
        return opened

    def tree(
        self, path: str = ".", *, depth: int = 3, max_entries: int = 500
    ) -> dict[str, Any]:
        if depth < 0 or depth > 8:
            raise PathPolicyError("depth must be between 0 and 8")
        with self._session() as (root_fd, root_real):
            parts = self._authorize(path, "enumerate", root_real)
            try:
                base = self._open(root_fd, root_real, parts, "enumerate", "dir")
            except NotADirectoryTarget as exc:
                raise WorkspaceError("tree path must be a directory") from exc
            with base:
                state = _TreeState(root_real=root_real, base_depth=len(base.parts), depth=depth, max_entries=max_entries)
                self._tree_directory(state, base.fd, base.parts)
        result: dict[str, Any] = {"path": path, "entries": state.entries, "truncated": state.truncated}
        if state.withheld:
            result["excluded_by_scope_authority"] = True
        return result

    def _tree_directory(self, state: _TreeState, dir_fd: int, parts_here: tuple[str, ...]) -> None:
        """List one directory through its descriptor, then descend into the allowed subdirectories."""
        current_path = state.root_real.joinpath(*parts_here)
        current_depth = len(parts_here) - state.base_depth
        try:
            found = {entry.name: entry for entry in list_directory(dir_fd)}
        except OSError:
            return  # an unreadable directory is skipped, as os.walk skips it
        descend: list[str] = []
        files: list[str] = []
        for name, entry in found.items():
            if entry.is_symlink() or is_denied_component(name):
                continue
            if entry.is_dir(follow_symlinks=False):
                if current_depth >= state.depth:
                    continue
                if not self._policy.descends("enumerate", current_path / name):
                    state.withheld = True
                    continue
                descend.append(name)
            else:
                files.append(name)
        for name in sorted(descend + files):
            if not self._policy.allows("enumerate", current_path / name):
                state.withheld = True
                continue
            entry = found[name]
            item: dict[str, Any] = {
                "path": "/".join((*parts_here, name)),
                "type": "dir" if entry.is_dir(follow_symlinks=False) else "file",
            }
            if entry.is_file(follow_symlinks=False):
                try:
                    item["size"] = entry.stat(follow_symlinks=False).st_size
                except OSError:
                    item["size"] = None
            state.entries.append(item)
            if len(state.entries) >= state.max_entries:
                state.truncated = True
                return
        for name in sorted(descend):
            try:
                child_fd = open_child(name, dir_fd, directory=True)
            except OSError:
                continue
            try:
                self._tree_directory(state, child_fd, (*parts_here, name))
            finally:
                os.close(child_fd)
            if state.truncated:
                return

    def read_file(
        self, path: str, *, start_line: int = 1, end_line: int | None = None
    ) -> dict[str, Any]:
        with self._session() as (root_fd, root_real):
            parts = self._authorize(path, "read", root_real)
            with self._open(root_fd, root_real, parts, "read", "file") as opened:
                self._policy.require_single_object_name("read", opened.info)
                # The budget is counted on the bytes read from this descriptor, not on an earlier stat.
                raw = read_bounded(opened.fd, self.spec.max_file_bytes)
        if raw is None:
            raise WorkspaceError(
                f"file exceeds max_file_bytes ({self.spec.max_file_bytes})"
            )
        if b"\x00" in raw[:8192]:
            raise WorkspaceError("binary files are not readable")
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        if start_line < 1:
            raise WorkspaceError("start_line must be >= 1")
        if end_line is None:
            end_line = min(len(lines), start_line + 399)
        if end_line < start_line or end_line - start_line > 999:
            raise WorkspaceError("invalid line range")
        selected = lines[start_line - 1 : end_line]
        return {
            "path": path,
            "start_line": start_line,
            "end_line": start_line + len(selected) - 1 if selected else start_line - 1,
            "total_lines": len(lines),
            "content": "\n".join(selected),
            "truncated": end_line < len(lines),
        }

    def file_digest(self, path: str) -> dict[str, Any]:
        """SHA-256 of a file's raw bytes, authorised exactly like a read, without any content.

        A digest is a fact about the content, so it needs the same ``read`` authority as the
        content itself: the same path rules, secret names, nested-scope authority and revocation.
        What it does not need is a text file under ``max_file_bytes``: the point is evidence that
        cannot be read as text. The file is opened by the descriptor walk and every byte hashed comes from that one
        descriptor. See ``digest_opened_file`` for the bounds and the change detection.
        """
        try:
            with self._session() as (root_fd, root_real):
                parts = self._authorize(path, "read", root_real)
                try:
                    opened = self._open(root_fd, root_real, parts, "read", "file")
                except OpenDenied as exc:  # the operating system refused UAM's own account: a result, not an error
                    result = digest_denied(exc.info)
                else:
                    try:
                        self._policy.require_single_object_name("read", opened.info)  # the same bytes under another name
                    except BaseException:
                        opened.close()
                        raise
                    result = digest_opened_file(
                        opened.fd,  # closed by the call
                        restat=lambda: stat_beneath(root_fd, root_real, opened.parts, kind="file"),
                    )
        except FileNotFoundError as exc:  # authority was decided first: this is no existence oracle
            raise WorkspaceError("path does not exist") from exc
        result["path"] = path
        result["permission_check"] = {"authority": "allowed", **result["permission_check"]}
        return result

    def search_text(
        self, query: str, *, path: str = ".", max_results: int = 100
    ) -> dict[str, Any]:
        if not query or len(query) > 256:
            raise WorkspaceError("query must contain 1..256 characters")
        if not (1 <= max_results <= 500):
            raise WorkspaceError("max_results must be 1..500")
        with self._session() as (root_fd, root_real):
            parts = self._authorize(path, "search", root_real)
            try:
                base = self._open(root_fd, root_real, parts, "search", "dir")
            except NotADirectoryTarget as exc:
                raise WorkspaceError("search path must be a directory") from exc
            with base:
                state = _SearchState(query=query, needle=query.lower(), max_results=max_results, root_real=root_real)
                finished = self._search_directory(state, base.fd, base.parts)
        return finished if finished is not None else self._finish_search(state, truncated=False, reason=None)

    def _finish_search(
        self, state: _SearchState, *, truncated: bool, reason: str | None, scanned: int | None = None
    ) -> dict[str, Any]:
        return self._search_result(
            state.query, state.results, state.scanned if scanned is None else scanned,
            truncated=truncated, truncation_reason=reason,
            files_skipped_oversized=state.oversized,
            files_skipped_binary=state.binary,
            files_skipped_error=state.errors,
            excluded_by_scope_authority=state.withheld,
        )

    def _search_directory(self, state: _SearchState, dir_fd: int, parts_here: tuple[str, ...]) -> dict[str, Any] | None:
        """Search one directory through its descriptor; a finished result when a limit ended the search."""
        current_path = state.root_real.joinpath(*parts_here)
        try:
            found = {entry.name: entry for entry in list_directory(dir_fd)}
        except OSError:
            return None  # an unreadable directory is skipped, as os.walk skips it
        descend: list[str] = []
        files: list[str] = []
        for name, entry in found.items():
            if entry.is_symlink() or is_denied_component(name):
                continue
            if entry.is_dir(follow_symlinks=False):
                if not self._policy.descends("search", current_path / name):
                    state.withheld = True  # part of the tree was left out because its scope does not allow search
                    continue
                descend.append(name)
            else:
                files.append(name)
        for name in sorted(files):
            finished = self._search_file(state, dir_fd, found[name], parts_here)
            if finished is not None:
                return finished
        for name in sorted(descend):
            try:
                child_fd = open_child(name, dir_fd, directory=True)
            except OSError:
                continue
            try:
                finished = self._search_directory(state, child_fd, (*parts_here, name))
            finally:
                os.close(child_fd)
            if finished is not None:
                return finished
        return None

    def _search_file(
        self, state: _SearchState, dir_fd: int, entry: os.DirEntry[str], parts_here: tuple[str, ...]
    ) -> dict[str, Any] | None:
        name = entry.name
        if not self._policy.allows("search", state.root_real.joinpath(*parts_here, name)):
            state.withheld = True  # not scanned and not counted: a count would reveal what is there
            return None
        if not entry.is_file(follow_symlinks=False):
            # FIFOs, sockets and devices are not text, and opening a FIFO blocks until a writer appears: one stray
            # pipe would hang the whole search. They are never opened.
            return None
        try:
            descriptor = open_child(name, dir_fd, directory=False)
        except FileNotFoundError:
            return None
        except OSError:  # permission denied, or a link/type swapped in after the listing (never followed)
            state.errors += 1
            return None
        try:
            held = os.fstat(descriptor)
            if self._policy.refuses_other_names("search", held):
                state.withheld = True
                return None
            if not stat.S_ISREG(held.st_mode):
                return None
            state.scanned += 1
            if state.scanned > self.spec.max_search_files:
                return self._finish_search(
                    state, truncated=True, reason="file_limit", scanned=state.scanned - 1,
                )
            if held.st_size > self.spec.max_file_bytes:
                state.oversized += 1
                return None
            raw = read_bounded(descriptor, self.spec.max_file_bytes)
        except OSError:
            state.errors += 1
            return None
        finally:
            os.close(descriptor)
        if raw is None:  # grew past the budget after the listing
            state.oversized += 1
            return None
        if b"\x00" in raw[:8192]:
            state.binary += 1
            return None
        for number, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), start=1):
            if state.needle in line.lower():
                state.results.append(
                    {"path": "/".join((*parts_here, name)), "line": number, "text": line[:500]}
                )
                if len(state.results) >= state.max_results:
                    return self._finish_search(state, truncated=True, reason="result_limit")
        return None

    @staticmethod
    def _search_result(
        query: str,
        results: list[dict[str, Any]],
        files_scanned: int,
        *,
        truncated: bool,
        truncation_reason: str | None,
        files_skipped_oversized: int,
        files_skipped_binary: int,
        files_skipped_error: int,
        excluded_by_scope_authority: bool = False,
    ) -> dict[str, Any]:
        skipped_total = files_skipped_oversized + files_skipped_binary + files_skipped_error
        skipped_searchable = files_skipped_oversized + files_skipped_error
        # Part of the tree that its scope keeps out of search was not examined: absence over the
        # workspace cannot be concluded from what was.
        safe = not truncated and skipped_searchable == 0 and not excluded_by_scope_authority
        if truncated:
            completeness = "PARTIAL"
        elif skipped_searchable > 0 or excluded_by_scope_authority:
            completeness = "PARTIAL"
        else:
            completeness = "COMPLETE"
        result: dict[str, Any] = {
            "query": query,
            "results": results,
            "files_scanned": files_scanned,
            "truncated": truncated,
            "search_completeness": completeness,
            "safe_to_conclude_absent": safe and len(results) == 0,
        }
        if truncated:
            result["truncation_reason"] = truncation_reason
        if excluded_by_scope_authority:
            result["excluded_by_scope_authority"] = True
        if skipped_total > 0:
            result["files_skipped"] = {
                "oversized": files_skipped_oversized,
                "binary": files_skipped_binary,
                "read_error": files_skipped_error,
            }
        return result
