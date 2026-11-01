"""Workspace Context Profile: which files open a session on a workspace, and how much of them to read.

A profile is operator configuration in ``<config>/workspace-contexts/<workspace_id>.json``. It is trusted to say WHICH
workspace-relative files are entrypoints and how large a bootstrap may be; it is not trusted for anything else:

* **Selected by identity, never by the raw selector.** Only a workspace the REGISTRY declares (resolution kind
  ``static``) has a profile, and it is found by the registry's own identifier. A derived workspace, an absolute path, a
  project-name alias or a literal handle string has no profile: such a name is chosen by the client, and the string a
  client sends must never become part of a path.
* **Found by exact entry name.** The store directory is listed and the entry named exactly ``<id>.json`` is opened. A
  case-insensitive volume would otherwise open ``alpha.json`` for the identifier ``Alpha``: another identity's file.
* **Opened without following a link**, relative to the descriptor of the store directory (the same primitive the
  workspace reader uses), size-bounded by the bytes actually read, strictly decoded and parsed.
* **Validated**: schema version, the owner it declares (must be this identity: a copy or hard link under another name is
  not a profile for that name), entrypoint paths (relative, inside the workspace, not a sensitive name), and limits.
* **Never echoed raw.** What a client sees is the validated entrypoint list or a fixed problem code, never file content.

The outcome is one of three states, and they are different facts: ``NOT_CONFIGURED`` (nothing is configured for this
identity), ``CONFIGURED`` (a valid profile is in effect) and ``INVALID`` (something is configured and cannot be trusted:
it contributes nothing, and the problem code says why). Damage must never read as "not configured".
"""
from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .descriptor_io import open_child, open_root, read_bounded
from .errors import PathPolicyError, WorkspaceError
from .policy import ensure_relative_path

PROFILE_SCHEMA_VERSION = "workspace-context-profile-v1"
PROFILE_STORE_DIRECTORY = "workspace-contexts"

NOT_CONFIGURED = "NOT_CONFIGURED"
CONFIGURED = "CONFIGURED"
INVALID = "INVALID"

# The resolver's kind for an identity the registry itself declares (``ResolutionResult.resolution_kind``). A test pins
# this to the resolver so that the two cannot drift apart.
REGISTERED_RESOLUTION_KIND = "static"

MAX_PROFILE_BYTES = 64 * 1024
MAX_STORE_ENTRIES_SCANNED = 10_000
MAX_ENTRYPOINTS = 32
MAX_ENTRYPOINT_CHARS = 512
DEFAULT_MAX_FILES = 8
DEFAULT_MAX_TOTAL_BYTES = 131_072
MAX_FILES_LIMIT = 32
MAX_TOTAL_BYTES_LIMIT = 1_048_576

# The registry's own identifier grammar (``workspace._WORKSPACE_ID``): the only strings that can be a profile key.
_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


@dataclass(frozen=True)
class ContextProfile:
    state: str
    entrypoints: tuple[str, ...] = ()
    max_files: int = DEFAULT_MAX_FILES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    problem: str | None = None  # a fixed code, present only for INVALID; never file content

    @property
    def configured(self) -> bool:
        return self.state == CONFIGURED

    def report(
        self,
        entrypoints: list[Any] | None = None,
        *,
        truncated: bool | None = None,
    ) -> dict[str, Any]:
        """The client-visible form. ``entrypoints`` may carry read results; it defaults to the validated names."""
        body: dict[str, Any] = {
            "configured": self.configured,
            "state": self.state,
            "entrypoints": list(self.entrypoints) if entrypoints is None else entrypoints,
        }
        if truncated is not None:
            body["truncated"] = truncated
            body["complete"] = not truncated
        if self.problem is not None:
            body["problem"] = self.problem
        return body


_NOT_CONFIGURED = ContextProfile(NOT_CONFIGURED)


def _invalid(problem: str) -> ContextProfile:
    return ContextProfile(INVALID, problem=problem)


def profile_key(workspace_id: str, resolution_kind: str) -> str | None:
    """The key of the profile an identity may have, or ``None`` when it cannot have one."""
    if resolution_kind != REGISTERED_RESOLUTION_KIND or _KEY.fullmatch(workspace_id) is None:
        return None
    return workspace_id


def load_context_profile(config_dir: Path, *, workspace_id: str, resolution_kind: str) -> ContextProfile:
    """The profile of the resolved identity ``workspace_id`` (see the module docstring), as one of three states."""
    key = profile_key(workspace_id, resolution_kind)
    if key is None:
        return _NOT_CONFIGURED
    entry_name = f"{key}.json"
    try:
        config_fd = open_root(config_dir.resolve(strict=True))
    except FileNotFoundError:
        return _NOT_CONFIGURED
    except (OSError, WorkspaceError):
        return _invalid("store_unreadable")
    try:
        return _load_from_store(config_fd, key, entry_name)
    finally:
        os.close(config_fd)


def _load_from_store(config_fd: int, key: str, entry_name: str) -> ContextProfile:
    try:
        store_fd = open_child(PROFILE_STORE_DIRECTORY, config_fd, directory=True)
    except FileNotFoundError:
        return _NOT_CONFIGURED
    except WorkspaceError:  # a link, or something that is not a directory, stands where the store should be
        return _invalid("store_not_a_directory")
    except OSError:
        return _invalid("store_unreadable")
    try:
        try:
            listed = _lists_exact_entry(store_fd, entry_name)
        except OSError:
            return _invalid("store_unreadable")
        if listed is None:
            return _invalid("store_too_large")
        return _load_entry(store_fd, key, entry_name) if listed else _NOT_CONFIGURED
    finally:
        os.close(store_fd)


def _lists_exact_entry(store_fd: int, entry_name: str) -> bool | None:
    """Whether the store lists an entry spelled exactly ``entry_name``; ``None`` if it lists too many to scan.

    Listing, not ``stat`` by name: on a case-insensitive volume ``stat("Alpha.json")`` succeeds for ``alpha.json``.
    """
    scanned = 0
    with os.scandir(store_fd) as entries:
        for entry in entries:
            scanned += 1
            if scanned > MAX_STORE_ENTRIES_SCANNED:
                return None
            if entry.name == entry_name:
                return True
    return False


def _load_entry(store_fd: int, key: str, entry_name: str) -> ContextProfile:
    try:
        descriptor = open_child(entry_name, store_fd, directory=False)
    except WorkspaceError:
        return _invalid("profile_not_a_regular_file")  # a link (or another type) stands where the profile should be
    except OSError:
        return _invalid("profile_unreadable")
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return _invalid("profile_not_a_regular_file")
        raw = read_bounded(descriptor, MAX_PROFILE_BYTES)
    except OSError:
        return _invalid("profile_unreadable")
    finally:
        os.close(descriptor)
    if raw is None:
        return _invalid("profile_too_large")
    return _validate(raw, key)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number: {name}")


def _validate(raw: bytes, key: str) -> ContextProfile:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _invalid("profile_encoding")
    try:
        document = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError):  # JSONDecodeError is a ValueError
        return _invalid("profile_syntax")
    if not isinstance(document, dict):
        return _invalid("profile_not_an_object")
    if document.get("schema_version") != PROFILE_SCHEMA_VERSION:
        return _invalid("profile_schema")
    if document.get("workspace_id") != key:
        return _invalid("profile_owner")
    entrypoints = _entrypoints(document.get("entrypoints", []))
    if entrypoints is None:
        return _invalid("profile_entrypoints")
    limits = _limits(document.get("bootstrap_limits", {}))
    if limits is None:
        return _invalid("profile_limits")
    return ContextProfile(CONFIGURED, entrypoints, max_files=limits[0], max_total_bytes=limits[1])


def _entrypoints(value: Any) -> tuple[str, ...] | None:
    if not isinstance(value, list) or len(value) > MAX_ENTRYPOINTS:
        return None
    accepted: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > MAX_ENTRYPOINT_CHARS:
            return None
        try:
            path = ensure_relative_path(item)
        except PathPolicyError:
            return None
        if not path.parts:
            return None
        accepted.append(path.as_posix())
    return tuple(accepted)


def _limits(value: Any) -> tuple[int, int] | None:
    if not isinstance(value, dict):
        return None
    max_files = value.get("max_files", DEFAULT_MAX_FILES)
    max_total_bytes = value.get("max_total_bytes", DEFAULT_MAX_TOTAL_BYTES)
    for number, ceiling in ((max_files, MAX_FILES_LIMIT), (max_total_bytes, MAX_TOTAL_BYTES_LIMIT)):
        if isinstance(number, bool) or not isinstance(number, int) or not 1 <= number <= ceiling:
            return None
    return max_files, max_total_bytes
