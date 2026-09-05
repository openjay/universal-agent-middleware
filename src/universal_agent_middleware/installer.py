"""macOS service staging and explicit activation from a clean, archived source tree."""
from __future__ import annotations

import argparse
import fcntl
import io
import json
import os
import plistlib
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import uuid
from pathlib import Path

from .runtime import (SCHEMA, atomic_json, sha256, release_files, load_runtime,
                      validate_configs, validate_release, check_credential)
from .service import mcp_command, validate_tunnel_config


def clean_source(source: Path) -> dict:
    def git(*args):
        return subprocess.run(["git", "-C", str(source), *args], capture_output=True,
                              text=True, check=True, timeout=30).stdout.strip()
    if git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("production build rejected: source tree is dirty")
    if any(line.startswith("160000 ") for line in git("ls-files", "--stage").splitlines()):
        raise ValueError("submodules require a separately bound source archive")
    commit = git("rev-parse", "HEAD")
    return {"source_commit": commit, "source_tree": git("rev-parse", f"{commit}^{{tree}}"),
            "source_dirty": False, "source_kind": "git_commit"}


def switch_current(home: Path, release: Path) -> None:
    current = home / "current"
    if current.exists() and not current.is_symlink():
        raise ValueError("current exists and is not a symlink")
    tmp = home / f".current-{uuid.uuid4()}"
    try:
        tmp.symlink_to(release)
        os.replace(tmp, current)
        fd = os.open(home, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if tmp.is_symlink():
            tmp.unlink()


def render_plists(source: Path, destination: Path, home: Path, uam_home: Path,
                  log_root: Path, manifest: Path) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    replacements = {"__HOME__": str(home), "__UAM_HOME__": str(uam_home),
                    "__LOG_DIR__": str(log_root), "__RUNTIME_MANIFEST__": str(manifest)}
    def replace(value):
        if isinstance(value, str):
            for old, new in replacements.items():
                value = value.replace(old, new)
            return value
        if isinstance(value, list): return [replace(v) for v in value]
        if isinstance(value, dict): return {k: replace(v) for k, v in value.items()}
        return value
    paths = []
    for path in sorted(source.glob("*.plist")):
        data = replace(plistlib.loads(path.read_bytes()))
        dest = destination / path.name
        dest.write_bytes(plistlib.dumps(data))
        paths.append(dest)
    if len(paths) != 2:
        raise ValueError("expected two service definitions")
    return paths


def bootstrap_agents(plists: list[Path]) -> None:
    for path in plists:
        # No fallback swallowing failure. The caller cannot claim successful install.
        subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)],
                       capture_output=True, check=True, timeout=15)


def wait_for_readiness(manifest: str, runtime: dict, *, seconds: float = 60) -> dict:
    from .supervisor import doctor_process
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        report = doctor_process(manifest, runtime, max(1, min(30, int(deadline - time.monotonic()))))
        if report["overall"] == "READY":
            return report
        if report["overall"] == "FROZEN" or report.get("failure_class") == "doctor_output_invalid":
            raise ValueError("activation failed integrity or Doctor contract checks")
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    raise ValueError("activated but readiness not proven within deadline")


def stage(source: Path, *, home: Path, state_root: Path, registry: Path, scopes: Path,
          canaries: Path, tunnel_config: Path, tunnel_client: Path, version: str | None = None) -> Path:
    identity = clean_source(source)
    import yaml
    if tunnel_config != home / ".config/tunnel-client" / tunnel_config.name or tunnel_config.suffix != ".yaml":
        raise ValueError("tunnel config must be the selected user's explicit profile file")
    # Validate supported tunnel shape without ever logging config contents.
    tunnel = yaml.safe_load(tunnel_config.read_text())
    if not isinstance(tunnel, dict) or not isinstance(tunnel.get("mcp"), dict):
        raise ValueError("invalid tunnel config")
    commands = tunnel["mcp"].get("commands")
    if not isinstance(commands, list) or len(commands) != 1 or not isinstance(commands[0], dict):
        raise ValueError("tunnel config requires exactly one MCP command")
    if commands[0].get("env"):
        raise ValueError("MCP environment overrides require explicit review")
    if not tunnel_client.is_file() or not os.access(tunnel_client, os.X_OK):
        raise ValueError("tunnel client prerequisite missing")
    uam_home = home / "Library/Application Support/OpenJay/UAM"
    config_root = uam_home / "config"
    config_root.mkdir(parents=True, exist_ok=True)
    for src, name in [(registry, "workspaces.json"), (scopes, "root_scopes.json")]:
        dest = config_root / name
        if not dest.exists():
            with dest.open("xb") as fh:
                fh.write(src.read_bytes())
    with tempfile.TemporaryDirectory(prefix="uam-clean-build-") as td:
        build_root = Path(td)
        archive = subprocess.run(["git", "-C", str(source), "archive", identity["source_commit"]],
                                 capture_output=True, check=True, timeout=30).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(build_root, filter="data")
        package_version = tomllib.loads((build_root / "pyproject.toml").read_text())["project"]["version"]
        if version and version != package_version:
            raise ValueError("requested version differs from archived source")
        release_id = f"v{package_version}+{identity['source_commit']}"
        release = uam_home / "releases" / release_id
        release.parent.mkdir(parents=True, exist_ok=True)
        release.mkdir()  # Exclusive identity: never back up, reuse or overwrite an existing release.
        runtime = {"schema_version": SCHEMA, "uam_home": str(uam_home),
            "release_root": str(release.parent), "current_release": str(release),
            "config_root": str(config_root), "state_root": str(state_root),
            "audit_file": str(state_root / "audit.jsonl"),
            "recovery_root": str(state_root.parent / "recovery"),
            "credential_root": str(state_root.parent / "credentials"),
            "log_root": str(home / "Library/Logs/UAM"),
            "registry_file": str(config_root / "workspaces.json"),
            "root_scopes_file": str(config_root / "root_scopes.json"),
            "tunnel_client": str(tunnel_client), "tunnel_config": str(tunnel_config),
            "tunnel_profile": tunnel_config.stem,
            "policy_file": str(release / "service/recovery_policies.yaml"),
            "canaries": json.loads(canaries.read_text())}
        validate_configs(runtime)
        if not runtime["canaries"]:
            raise ValueError("at least one explicit semantic canary is required")
        # Build only the Git archive; ignored local files cannot enter this artifact.
        artifacts = release / "artifacts"
        artifacts.mkdir()
        subprocess.run([sys.executable, "-m", "build", "--wheel", "--outdir", str(artifacts)],
                       cwd=build_root, check=True, timeout=180)
        wheels = list(artifacts.glob("*.whl"))
        if len(wheels) != 1:
            raise ValueError("build must produce exactly one wheel")
        wheel = wheels[0]
        subprocess.run([sys.executable, "-m", "venv", str(release / "venv")], check=True, timeout=60)
        python = release / "venv/bin/python"
        subprocess.run([str(python), "-m", "pip", "install", f"{wheel}[service]"], check=True, timeout=180)
        service = release / "service"
        service.mkdir()
        for path in (build_root / "tools/system-service/scripts").glob("*.sh"):
            shutil.copy2(path, service / path.name)
        shutil.copy2(build_root / "tools/system-service/config/recovery_policies.yaml", service)
        manifest_path = uam_home / "runtime/uam-runtime.json"
        planned = release / "runtime"
        planned.mkdir()
        commands[0]["command"] = shlex.join(mcp_command(runtime, str(manifest_path)))
        planned_tunnel = planned / "tunnel-config.yaml"
        planned_tunnel.write_text(yaml.safe_dump(tunnel, sort_keys=False))
        planned_tunnel.chmod(0o600)
        render_plists(build_root / "tools/system-service/plists", planned / "plists",
                      home, uam_home, Path(runtime["log_root"]), manifest_path)
        contract = json.loads((build_root / "src/universal_agent_middleware/tool_contract.json").read_text())
        # Independently inspect installed SDK contract without contacting a tunnel or real workspaces.
        probe = """import asyncio,json,tempfile
from pathlib import Path
import universal_agent_middleware as u
from universal_agent_middleware.doctor import tool_contract
from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'workspaces.json'; p.write_text(json.dumps({'registry_version':'uam-workspace-registry-v1','workspaces':[]}))
 c=tool_contract(asyncio.run(create_session_read_server(str(p),str(Path(d)/'state')).list_tools()))
 print(json.dumps({'version':u.__version__,'contract':c}))
"""
        probe_result = subprocess.run([str(python), "-I", "-c", probe], capture_output=True,
                                      text=True, check=True, timeout=30)
        installed = json.loads(probe_result.stdout)
        if installed != {"version": package_version, "contract": contract}:
            raise ValueError("installed package/tool contract mismatch")
        release_manifest = {"schema_version": "uam-release-v1", **identity, "release_id": release_id,
            "package_version": package_version, "wheel_file": str(wheel.relative_to(release)),
            "wheel_sha256": sha256(wheel), "build_timestamp": time.time(),
            "tool_contract": contract, "files": release_files(release)}
        atomic_json(release / "RELEASE_MANIFEST.json", release_manifest)
        digest = sha256(release / "RELEASE_MANIFEST.json")
        (release / "RELEASE_MANIFEST.sha256").write_text(digest + "\n")
        runtime["release_manifest_sha256"] = digest
        atomic_json(planned / "uam-runtime.json", runtime)
        atomic_json(release / "STAGING_RECEIPT.json", {"state": "STAGED_NOT_ACTIVE", "release_id": release_id,
                                                      "runtime_ready": False, "release_manifest_sha256": digest})
        return planned / "uam-runtime.json"


def activate(plan: Path, home: Path) -> None:
    runtime = load_runtime(plan)
    release, uam_home = Path(runtime["current_release"]), Path(runtime["uam_home"])
    validate_configs(runtime)
    # Refuse legacy, corrupt or missing state instead of silently resetting GENESIS.
    from .doctor import _check_audit
    if _check_audit(runtime["state_root"], require_existing=True)["status"] != "PASS":
        raise ValueError("audit requires explicit offline initialization/migration before activation")
    if check_credential(runtime)["status"] != "PASS":
        raise ValueError("credential prerequisite failed")
    if (Path(runtime["recovery_root"]) / "FROZEN.json").exists():
        raise ValueError("operator must resolve existing freeze before activation")
    # Activation must follow a separately controlled writer-stop, including old MCP children.
    for label in ("com.openjay.uam.tunnel", "com.openjay.uam.supervisor"):
        probe = subprocess.run(["launchctl", "print", f"gui/{os.getuid()}/{label}"],
                               capture_output=True, timeout=10)
        if probe.returncode == 0:
            raise ValueError("loaded service exists; controlled writer-stop required before activation")
    validate_release(runtime, executing=False, require_current=False)
    canonical = uam_home / "runtime/uam-runtime.json"
    canonical.parent.mkdir(parents=True, exist_ok=True)
    target = uam_home / "current/runtime/uam-runtime.json"
    if canonical.is_symlink():
        if os.readlink(canonical) != str(target):
            raise ValueError("unexpected canonical manifest link")
    elif canonical.exists():
        raise ValueError("existing runtime manifest requires explicit migration to atomic layout")
    else:
        canonical.symlink_to(target)
    planned = plan.parent
    tunnel_path = Path(runtime["tunnel_config"])
    if tunnel_path.exists():
        backup = tunnel_path.with_name(f"{tunnel_path.name}.preserved-{uuid.uuid4()}")
        with backup.open("xb") as fh:
            os.chmod(backup, 0o600)
            fh.write(tunnel_path.read_bytes())
    # JSON is valid YAML; atomic replacement avoids torn tunnel configuration.
    import yaml
    atomic_json(tunnel_path, yaml.safe_load((planned / "tunnel-config.yaml").read_text()))
    validate_tunnel_config(runtime, str(canonical))
    plists = []
    destination = home / "Library/LaunchAgents"
    destination.mkdir(parents=True, exist_ok=True)
    Path(runtime["log_root"]).mkdir(parents=True, exist_ok=True)
    for path in (planned / "plists").glob("*.plist"):
        dest = destination / path.name
        shutil.copy2(path, dest)
        plists.append(dest)
    switch_current(uam_home, release)
    validate_release(runtime, executing=False)
    try:
        bootstrap_agents(plists)
        wait_for_readiness(str(canonical), runtime)
    except Exception:
        atomic_json(Path(runtime["recovery_root"]) / "FROZEN.json",
                    {"overall": "FROZEN", "failure_class": "activation_failed", "release": str(release)})
        raise
    atomic_json(Path(runtime["recovery_root"]) / "INSTALL_RECEIPT.json", {"overall": "READY", "release": str(release)})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--root-scopes", type=Path)
    parser.add_argument("--canaries", type=Path)
    parser.add_argument("--tunnel-config", type=Path)
    parser.add_argument("--tunnel-client", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--activate", type=Path, metavar="STAGED_RUNTIME_MANIFEST")
    args = parser.parse_args()
    try:
        # Serialize installers before any staging or activation mutation.
        home = args.home.expanduser().resolve()
        lock_root = home / "Library/Application Support/OpenJay/UAM"
        lock_root.mkdir(parents=True, exist_ok=True)
        with (lock_root / "installer.lock").open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if args.activate:
                activate(args.activate.resolve(), home)
                print("Installation READY (Doctor verified)")
            else:
                fields = [args.source, args.state_root, args.registry, args.root_scopes,
                          args.canaries, args.tunnel_config, args.tunnel_client]
                if any(v is None for v in fields):
                    raise ValueError("staging requires --source, --state-root, --registry, --root-scopes, --canaries, --tunnel-config, --tunnel-client")
                plan = stage(args.source.resolve(), home=home, state_root=args.state_root.resolve(),
                             registry=args.registry.resolve(), scopes=args.root_scopes.resolve(),
                             canaries=args.canaries.resolve(), tunnel_config=args.tunnel_config.resolve(),
                             tunnel_client=args.tunnel_client.resolve(), version=args.version)
                print(json.dumps({"state": "STAGED_NOT_ACTIVE", "runtime_manifest": str(plan)}))
        return 0
    except Exception as exc:
        # YAML parser exceptions can embed source lines containing credentials.
        # Keep our controlled validation reasons, suppress external exception payloads.
        reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print(f"Installation failed: {reason}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
