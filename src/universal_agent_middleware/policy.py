from __future__ import annotations

import os
import re
from pathlib import Path

from .errors import PathPolicyError

# Deny exact or structurally sensitive names. Avoid broad substring blocking so
# documentation such as docs/credential-model.md can still be researched.
_DENIED_EXACT = {
    ".git",
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "credentials.json",
    "secrets.json",
}
_DENIED_PATTERNS = [
    re.compile(r"^\.env(?:\..*)?$", re.IGNORECASE),
    re.compile(r".*\.(?:pem|p12|pfx|key|keystore)$", re.IGNORECASE),
]


def _is_denied_component(component: str) -> bool:
    if component in _DENIED_EXACT:
        return True
    return any(pattern.fullmatch(component) for pattern in _DENIED_PATTERNS)


def ensure_relative_path(raw: str) -> Path:
    if "\x00" in raw:
        raise PathPolicyError("NUL byte is forbidden")
    path = Path(raw or ".")
    if path.is_absolute():
        raise PathPolicyError("absolute paths are forbidden")
    if any(part in {"..", "~"} for part in path.parts):
        raise PathPolicyError("path traversal is forbidden")
    for part in path.parts:
        if _is_denied_component(part):
            raise PathPolicyError(f"denied path component: {part}")
    return path


def resolve_safe_path(root: str | Path, raw: str, *, must_exist: bool = True) -> Path:
    root_path = Path(root).expanduser().resolve(strict=True)
    rel = ensure_relative_path(raw)
    candidate = (root_path / rel).resolve(strict=must_exist)
    try:
        candidate.relative_to(root_path)
    except ValueError as exc:
        raise PathPolicyError("resolved path escapes workspace") from exc

    # Re-check the resolved relative path so a symlink cannot land inside a
    # denied subtree while using an innocent-looking alias.
    resolved_rel = candidate.relative_to(root_path)
    for part in resolved_rel.parts:
        if _is_denied_component(part):
            raise PathPolicyError(f"denied resolved path component: {part}")
    return candidate


def should_hide_path(root: str | Path, path: Path) -> bool:
    try:
        rel = path.relative_to(Path(root).resolve(strict=True))
    except ValueError:
        return True
    return any(_is_denied_component(part) for part in rel.parts)


def is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}


def redact_environment_value(name: str) -> str:
    value = os.environ.get(name, "")
    return "<set>" if value else "<unset>"
