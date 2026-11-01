"""The configuration a release is activated with is one verifiable combination.

A release directory pins code. The Registry, the RootScopes and the canaries it is activated
against live outside it and are replaced independently, so a release could be staged against one
triplet and find another on disk at activation (``installer stage`` used to keep an existing file
and silently ignore the one it was given), or be restored by a rollback against whatever the last
release left behind. Doctor judges the canaries only after the switch, when a mixed pair can
only end in FROZEN.

``config_bundle`` is recorded in the release's runtime manifest when the release is built or
staged: the SHA-256 of the Registry file, of the RootScopes file and of the canary list that were
validated together. The runtime manifest names the release (``release_manifest_sha256``), is itself
pinned (a sealed release pins its SHA-256 and the running service watches it) and carries the
canaries, so it is the one record of the combination: Release, Runtime Manifest, Registry,
RootScopes and Canaries. ``config_violations`` re-derives it from disk at every admission point
(staging, ``uam release`` before the switch and again under the Supervisor lock, installer
activation) and refuses a combination that differs or is incoherent.

Registry and RootScopes are hot-reloaded on purpose (a revocation must take effect without a
restart). The bundle is therefore an admission contract, never a runtime freeze trigger: editing
them after activation is legitimate and does not touch a running service; it only stops a release
that was prepared against the old combination from being activated against the new one.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .errors import UAMError
from .runtime import sha256, validate_configs
from .workspace import WorkspaceRegistry

BUNDLE_SCHEMA = "uam-config-bundle-v1"
_DIGESTS = ("registry_sha256", "root_scopes_sha256", "canaries_sha256")
_DIFFERS = {"registry_sha256": "registry_differs", "root_scopes_sha256": "root_scopes_differ",
            "canaries_sha256": "canaries_differ"}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_LISTED_LIMIT = 20


def canaries_sha256(canaries: object) -> str:
    return hashlib.sha256(json.dumps(canaries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def compute_bundle(runtime: Mapping[str, Any]) -> dict[str, str]:
    """The digests of the configuration ``runtime`` names, read now. Raises OSError when a file is missing."""
    return {
        "schema_version": BUNDLE_SCHEMA,
        "registry_sha256": sha256(Path(runtime["registry_file"])),
        "root_scopes_sha256": sha256(Path(runtime["root_scopes_file"])),
        "canaries_sha256": canaries_sha256(runtime["canaries"]),
    }


def _well_formed(bundle: object) -> bool:
    return (isinstance(bundle, dict) and set(bundle) == {"schema_version", *_DIGESTS}
            and bundle["schema_version"] == BUNDLE_SCHEMA
            and all(isinstance(bundle[key], str) and _SHA256.fullmatch(bundle[key]) for key in _DIGESTS))


def adopt_config_file(supplied: Path, destination: Path) -> str:
    """Create ``destination`` from ``supplied`` when absent; an existing file must already be those bytes.

    Staging is not a configuration-adoption mechanism: keeping a different file under the supplied
    one's name would stage a release against a combination nobody validated.
    """
    data = supplied.read_bytes()
    if not (destination.exists() or destination.is_symlink()):
        with destination.open("xb") as handle:
            handle.write(data)
        return "created"
    if destination.read_bytes() != data:
        raise ValueError(f"{destination.name} already exists and differs from the supplied file; staging never "
                         "adopts or replaces configuration (replace it through the controlled configuration "
                         "procedure, or supply the existing file)")
    return "identical"


def config_violations(runtime: Mapping[str, Any], *, require_bundle: bool) -> list[dict[str, str]]:
    """Why the configuration on disk is not the combination ``runtime`` records; empty when it is.

    Coherence is checked even when no bundle is recorded: the files must load, and every canary must
    name a workspace the registry declares (a canary for an unregistered workspace can only fail
    after the switch). ``require_bundle`` refuses a release that records no combination at all.
    """
    problems: list[dict[str, str]] = []

    def violation(code: str, detail: str) -> None:
        problems.append({"code": code, "detail": detail[:300]})

    try:
        validate_configs(dict(runtime))
        registry = WorkspaceRegistry(runtime["registry_file"])
    except (OSError, ValueError, KeyError, TypeError, UAMError) as exc:
        violation("config_invalid", f"{type(exc).__name__}: {exc}")
        return problems
    unregistered = sorted({canary["workspace_id"] for canary in runtime["canaries"]
                           if not registry.is_registered(canary["workspace_id"])})
    if unregistered:
        violation("canary_workspace_unregistered",
                  f"canaries name workspaces the registry does not declare: {unregistered[:_LISTED_LIMIT]}")
    recorded = runtime.get("config_bundle")
    if recorded is None:
        if require_bundle:
            violation("config_bundle_missing", "the runtime manifest records no configuration bundle")
        return problems
    if not _well_formed(recorded):
        violation("config_bundle_malformed", "config_bundle is not a uam-config-bundle-v1 record of three SHA-256 digests")
        return problems
    try:
        current = compute_bundle(runtime)
    except OSError as exc:
        violation("config_unreadable", f"{type(exc).__name__}: {exc}")
        return problems
    for key in _DIGESTS:
        if current[key] != recorded[key]:
            violation(_DIFFERS[key], f"{key.removesuffix('_sha256')} is not the one this release was built and "
                                     f"validated with (recorded {recorded[key][:12]}, now {current[key][:12]})")
    return problems


def describe(problems: list[dict[str, str]]) -> str:
    return "; ".join(f"{problem['code']} ({problem['detail']})" for problem in problems)


def require_config_combination(runtime: Mapping[str, Any], *, require_bundle: bool) -> None:
    """Raise ``ValueError`` unless the configuration on disk is one verified combination."""
    problems = config_violations(runtime, require_bundle=require_bundle)
    if problems:
        raise ValueError(f"the configuration is not one verified combination: {describe(problems)}")
