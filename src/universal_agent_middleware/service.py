"""Tunnel bootstrap consuming exactly the same runtime manifest as Doctor."""
from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import time
from pathlib import Path

from .runtime import (load_runtime, validate_release, validate_configs, check_credential,
                      atomic_json, sha256)


def setup_credential(manifest: str) -> None:
    """Interactive first-time setup only; rotation never happens implicitly."""
    import getpass
    import stat
    import sys
    runtime = load_runtime(manifest)
    root = Path(runtime["credential_root"])
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
        raise ValueError("credential directory must be owned by this user with mode 700")
    path = root / "control_plane_api_key"
    if path.exists() or path.is_symlink():
        raise ValueError("credential already exists; explicit rotation procedure required")
    if not sys.stdin.isatty():
        raise ValueError("credential setup requires an interactive terminal")
    key = getpass.getpass("Control plane API key (hidden): ").strip()
    if not key:
        raise ValueError("empty credential")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(key)
        fh.flush()
        os.fsync(fh.fileno())


def mcp_command(runtime: dict, manifest: str) -> list[str]:
    return [str(Path(runtime["uam_home"]) / "current/venv/bin/python"),
            "-I", "-m", "universal_agent_middleware.cli", "mcp-sdk-stdio",
            "--runtime-manifest", str(Path(manifest).absolute()), "--profile", "session-read"]


def validate_tunnel_config(runtime: dict, manifest: str) -> None:
    import yaml
    config = yaml.safe_load(Path(runtime["tunnel_config"]).read_text())
    commands = config["mcp"]["commands"]
    if not isinstance(commands, list) or len(commands) != 1:
        raise ValueError("tunnel config must have exactly one explicit MCP command")
    if shlex.split(commands[0]["command"]) != mcp_command(runtime, manifest):
        raise ValueError("tunnel MCP command differs from runtime manifest")
    if commands[0].get("env"):
        raise ValueError("MCP command environment overrides require explicit review")


def run_tunnel(manifest: str) -> int:
    runtime = load_runtime(manifest)
    expected_config = Path.home() / ".config/tunnel-client" / (runtime["tunnel_profile"] + ".yaml")
    if Path(runtime["tunnel_config"]).resolve() != expected_config.resolve():
        raise ValueError("runtime tunnel profile is not the effective user's config")
    validate_release(runtime)
    manifest_digest = sha256(Path(manifest))
    validate_configs(runtime)
    validate_tunnel_config(runtime, manifest)
    root = Path(runtime["recovery_root"])
    root.mkdir(parents=True, exist_ok=True)
    latch = root / "FROZEN.json"
    if latch.exists():
        return 78
    if check_credential(runtime)["status"] != "PASS":
        atomic_json(latch, {"overall": "FROZEN", "failure_class": "credential_security_failure"})
        return 78
    from .doctor import _check_audit
    if _check_audit(runtime["state_root"], require_existing=True)["status"] != "PASS":
        atomic_json(latch, {"overall": "FROZEN", "failure_class": "audit_integrity_failure"})
        return 78
    client = Path(runtime["tunnel_client"])
    if not client.is_file() or not os.access(client, os.X_OK):
        raise ValueError("configured tunnel executable unavailable")
    # Never print the credential, its hash or the child's environment/output.
    key = (Path(runtime["credential_root"]) / "control_plane_api_key").read_text().strip()
    if not key:
        raise ValueError("empty credential")
    env = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "PYTHONHOME"}}
    env.update(CONTROL_PLANE_API_KEY=key, UAM_RUNTIME_MANIFEST=manifest)
    child = subprocess.Popen([str(client), "run", "--config", runtime["tunnel_config"]],
                             env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def stop(*_args):
        if child.poll() is None:
            child.terminate()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        # comm after exec, not the supervisor/wrapper's pre-exec process identity.
        identity = ""
        for _ in range(20):
            if child.poll() is not None:
                return child.returncode or 1
            info = subprocess.run(["ps", "-p", str(child.pid), "-o", "lstart=", "-o", "comm="],
                                  capture_output=True, text=True, timeout=5).stdout.strip()
            if str(client) in info:
                identity = info
                break
            time.sleep(0.05)
        if not identity:
            raise ValueError("could not verify tunnel child executable")
        atomic_json(root / "tunnel-identity.json", {
            "pid": child.pid, "process_identity": identity, "started_at": time.time(),
            "release": runtime["current_release"], "config_sha256": sha256(Path(runtime["tunnel_config"])),
            "executable_sha256": sha256(client)})
        while child.poll() is None:
            try:
                aligned = (sha256(Path(manifest)) == manifest_digest and
                           (Path(runtime["uam_home"]) / "current").resolve(strict=True) ==
                           Path(runtime["current_release"]).resolve(strict=True))
            except OSError:
                aligned = False
            if not aligned:
                atomic_json(latch, {"overall": "FROZEN", "failure_class": "runtime_path_failure"})
            if latch.exists():
                stop()
                break
            time.sleep(0.5)
        try:
            return child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            return child.wait(timeout=5)
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-manifest", required=True)
    parser.add_argument("--setup-credential", action="store_true")
    args = parser.parse_args()
    try:
        if args.setup_credential:
            setup_credential(args.runtime_manifest)
            print("Credential stored; services have not been activated.")
            return 0
        return run_tunnel(args.runtime_manifest)
    except Exception as exc:
        print(json.dumps({"overall": "FAILED", "reason": type(exc).__name__}))
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
