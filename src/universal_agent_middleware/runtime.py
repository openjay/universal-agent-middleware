"""Explicit runtime identity shared by service entrypoints; no inferred state root."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

SCHEMA = "uam-runtime-v1"
# Under recovery_root. Whoever holds it is the only party allowed to make recovery or install decisions.
SUPERVISOR_LOCK_NAME = "supervisor.lock"
PATH_KEYS = {"uam_home", "release_root", "current_release", "config_root", "state_root",
             "audit_file", "recovery_root", "credential_root", "log_root", "registry_file",
             "root_scopes_file", "tunnel_client", "tunnel_config", "policy_file"}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(value, fh, sort_keys=True, indent=2, allow_nan=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def load_runtime(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA:
        raise ValueError("unsupported runtime manifest schema")
    for key in PATH_KEYS:
        value = data.get(key)
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise ValueError(f"runtime path must be absolute: {key}")
    def same(key: str, expected: Path) -> None:
        if Path(data[key]).resolve() != expected.resolve():
            raise ValueError(f"runtime path mismatch: {key}")
    same("release_root", Path(data["uam_home"]) / "releases")
    same("audit_file", Path(data["state_root"]) / "audit.jsonl")
    same("registry_file", Path(data["config_root"]) / "workspaces.json")
    same("root_scopes_file", Path(data["config_root"]) / "root_scopes.json")
    same("policy_file", Path(data["current_release"]) / "service/recovery_policies.yaml")
    release = Path(data["current_release"])
    if release.parent.resolve() != Path(data["release_root"]).resolve():
        raise ValueError("current_release outside release_root")
    if not isinstance(data.get("release_manifest_sha256"), str) or len(data["release_manifest_sha256"]) != 64:
        raise ValueError("missing release manifest hash")
    if not isinstance(data.get("tunnel_profile"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", data["tunnel_profile"]):
        raise ValueError("unsupported tunnel profile")
    if Path(data["tunnel_config"]).name != data["tunnel_profile"] + ".yaml":
        raise ValueError("tunnel profile/config mismatch")
    if not isinstance(data.get("canaries"), list):
        raise ValueError("canaries must be explicit")
    return data


def control_plane_paths(runtime: dict[str, Any]) -> list[Path]:
    """UAM's own home, releases, config, state, credentials, logs and recovery paths.

    No directory workspace may equal, contain or sit inside any of them: a directory that
    overlaps UAM's control plane would let a reading client see UAM's own ledger and secrets.
    """
    return [Path(runtime[key]) for key in sorted(PATH_KEYS)]


def validate_paths(runtime: dict[str, Any], registry: str, state: str) -> None:
    for actual, key in [(registry, "registry_file"), (state, "state_root")]:
        if Path(actual).resolve() != Path(runtime[key]).resolve():
            raise ValueError(f"effective path differs from runtime manifest: {key}")


class AdmissionError(ValueError):
    """A launch the sealed runtime does not admit. ``code`` is all a caller reports: no path and no value."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def release_id(runtime: dict[str, Any]) -> str:
    """The name of the release directory the runtime selects; audit records written under it are stamped with it."""
    return Path(runtime["current_release"]).name


def validate_dedicated_state(runtime: dict[str, Any], registry: str, state: str) -> None:
    """The path rule of a profile that reads the runtime's registry and keeps a state directory of its own.

    ``validate_paths`` is the rule for the process that serves THE state of the runtime. This is its counterpart: the registry
    must still be the manifest's, so the profile sees exactly the workspaces the runtime admits, but the state directory must
    neither equal, contain nor sit inside any control-plane path. It can then never be the read-only service's audit chain, a
    recovery latch, a credential or log directory, the config or a release.
    """
    if Path(registry).resolve() != Path(runtime["registry_file"]).resolve():
        raise AdmissionError("REGISTRY_NOT_RUNTIMES")
    target = Path(state).expanduser().resolve(strict=False)
    for path in control_plane_paths(runtime):
        other = path.resolve(strict=False)
        if target == other or target.is_relative_to(other) or other.is_relative_to(target):
            raise AdmissionError("STATE_NOT_DEDICATED")


def admit_dedicated_runtime(manifest: str | Path, registry: str, state: str) -> dict[str, Any]:
    """The runtime a dedicated-state launch runs under, or ``AdmissionError`` carrying exactly one code.

    The release checks are those ``uam mcp-sdk-stdio`` makes before it serves: the manifest loads, and the package that is
    executing is the whole, current release the manifest names (``validate_release``). The state rule is turned around
    (``validate_dedicated_state``), so the launch never shares the read-only service's state. A FROZEN latch of the runtime stops
    the launch here; once the gateway is built with the returned runtime it stops every later audit write as well. The latch is
    any entry named ``FROZEN.json`` in the recovery root (``os.path.lexists``, the reading of ``release._freeze_evidence`` and of the
    audit writer): a symlink that points nowhere, at itself or into a directory that cannot be searched is a latch, not its absence.
    """
    try:
        runtime = load_runtime(manifest)
    except (OSError, ValueError, KeyError, TypeError):
        raise AdmissionError("RUNTIME_UNREADABLE") from None
    try:
        validate_release(runtime)
    except (OSError, ValueError, KeyError, TypeError):
        raise AdmissionError("RELEASE_NOT_SEALED") from None
    validate_dedicated_state(runtime, registry, state)
    if os.path.lexists(Path(runtime["recovery_root"]) / "FROZEN.json"):
        raise AdmissionError("RUNTIME_FROZEN")
    return runtime


def validate_configs(runtime: dict[str, Any], *, require_complete_registry: bool = False) -> None:
    """Validate runtime configuration.

    A registered workspace whose root is gone does not fail runtime start or Doctor: it is
    served as unavailable and reported as a coverage gap. Release staging and activation pass
    ``require_complete_registry=True`` so the gap is caught before ``current`` is switched
    instead of after activation, when only a FROZEN latch can follow.
    """
    from .workspace import WorkspaceRegistry
    from .root_scope import RootScopeAuthority
    registry = WorkspaceRegistry(runtime["registry_file"])
    if require_complete_registry:
        gaps = registry.coverage()["unavailable"]
        if gaps:
            names = ", ".join(f"{item['workspace_id']} ({item['reason']})" for item in gaps)
            raise ValueError(
                f"workspace registry has unavailable workspaces; retire or restore them first: {names}")
    canaries = runtime.get("canaries")
    if not isinstance(canaries, list) or any(
            not isinstance(c, dict) or set(c) != {"workspace_id", "path"}
            or not isinstance(c["workspace_id"], str) or not c["workspace_id"]
            or not isinstance(c["path"], str) or not c["path"] for c in canaries):
        raise ValueError("invalid explicit canary configuration")
    from .policy import ensure_relative_path
    for canary in canaries:
        ensure_relative_path(canary["path"])
    raw = json.loads(Path(runtime["root_scopes_file"]).read_text())
    if not isinstance(raw, dict) or raw.get("schema_version") != "root-scope-registry-v1":
        raise ValueError("unsupported root scope schema; explicit migration required")
    if set(raw) - {"schema_version", "scopes", "overrides"} or not isinstance(raw.get("scopes"), list):
        raise ValueError("invalid root scope registry")
    seen = set()
    for scope in raw["scopes"]:
        if not isinstance(scope, dict) or set(scope) - {"scope_id", "root", "authority", "description"}:
            raise ValueError("invalid root scope fields")
        if not scope.get("scope_id") or scope["scope_id"] in seen:
            raise ValueError("invalid or duplicate scope id")
        seen.add(scope["scope_id"])
        if not isinstance(scope.get("root"), str) or not Path(scope["root"]).is_absolute():
            raise ValueError("scope root must be absolute")
        auth = scope.get("authority", {})
        if not isinstance(auth, dict) or any(type(v) is not bool for v in auth.values()):
            raise ValueError("scope authority values must be booleans")
        RootScopeAuthority(**auth)
    # Overrides are not enforced by this version; accepting one would imply authority falsely.
    if raw.get("overrides"):
        raise ValueError("scope overrides not supported by this release")


def validate_release(runtime: dict[str, Any], *, executing: bool = True,
                     require_current: bool = True) -> dict[str, Any]:
    release = Path(runtime["current_release"])
    current = Path(runtime["uam_home"]) / "current"
    if require_current and (not current.is_symlink() or current.resolve(strict=True) != release.resolve(strict=True)):
        raise ValueError("current symlink does not match runtime manifest")
    path = release / "RELEASE_MANIFEST.json"
    if sha256(path) != runtime["release_manifest_sha256"]:
        raise ValueError("release manifest hash mismatch")
    manifest = json.loads(path.read_text())
    if (manifest.get("schema_version") != "uam-release-v1" or manifest.get("source_dirty") is not False
            or manifest.get("source_kind") != "git_commit"
            or manifest.get("release_id") != release.name):
        raise ValueError("invalid release provenance")
    for key in ("source_commit", "source_tree"):
        value = manifest.get(key)
        if not isinstance(value, str) or len(value) not in (40, 64):
            raise ValueError(f"missing release identity: {key}")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files or not manifest.get("tool_contract"):
        raise ValueError("release has no file/tool contract")
    for rel, digest in files.items():
        p = release / rel
        if Path(rel).is_absolute() or ".." in Path(rel).parts or sha256(p) != digest:
            raise ValueError(f"release file hash mismatch: {rel}")
    # Refuse injected Python modules, not just changes to listed files.
    actual = release_files(release)
    if actual != files:
        raise ValueError("release file inventory mismatch")
    wheel = release / manifest["wheel_file"]
    if sha256(wheel) != manifest["wheel_sha256"]:
        raise ValueError("wheel hash mismatch")
    if executing:
        import universal_agent_middleware as package
        if not Path(package.__file__).resolve().is_relative_to(release.resolve()):
            raise ValueError("executing package outside selected release")
        if package.__version__ != manifest.get("package_version"):
            raise ValueError("executing package version mismatch")
    return manifest


def release_files(release: Path) -> dict[str, str]:
    """Bind installed code, dependencies, services and wheel; exclude generated bytecode."""
    result = {}
    for root in (release / "venv", release / "service", release / "artifacts"):
        for path in sorted(root.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                if path.is_symlink():
                    # venv Python links are represented by their target binary digest.
                    if path.parent != release / "venv/bin":
                        raise ValueError("unexpected release symlink")
                result[str(path.relative_to(release))] = sha256(path)
    return result


def check_credential(runtime: dict[str, Any]) -> dict[str, Any]:
    path = Path(runtime["credential_root"]) / "control_plane_api_key"
    try:
        parent = path.parent.lstat()
        info = path.lstat()
        ok = (stat.S_ISREG(info.st_mode) and not path.is_symlink() and
              stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid() and info.st_size > 0
              and stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700
              and parent.st_uid == os.getuid())
        if ok:
            ok = bool(path.read_bytes().strip())
        return {"status": "PASS" if ok else "FAIL", "severity": "INFO" if ok else "P0"}
    except OSError:
        return {"status": "FAIL", "severity": "P0", "reason": "credential missing or inaccessible"}
