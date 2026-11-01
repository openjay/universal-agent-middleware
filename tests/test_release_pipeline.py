"""Release pipeline tests — validate build_and_activate correctness invariants.

Covers:
    - Incomplete release directory must be refused (not reused)
    - Cryptographic validation required for existing release reuse
    - Failed tool_contract generation must produce FAIL receipt
    - Failed index refresh must produce FAIL receipt
    - _refresh_index must use the new release's Python, not old runtime
    - Dirty worktree must be rejected

Freeze handling, exact acceptance, bounded child processes and the pre-activation contract
checks live in test_release_guardrails.py, test_release_acceptance.py and
test_release_contract.py.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from universal_agent_middleware.release import (
    _validate_existing_release,
    _release_files,
    _sha256,
    _step,
    _update_tool_contract,
    _refresh_index,
    _start_tunnel,
)


class TestValidateExistingRelease(unittest.TestCase):
    """P1: release_exists must cryptographically validate, not blindly reuse."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="uam-rel-test-")
        self.release_dir = Path(self._tmp.name) / "v0.1.0+abc123"
        self.release_dir.mkdir(parents=True)

        venv = self.release_dir / "venv" / "bin"
        venv.mkdir(parents=True)
        (venv / "python").write_text("#!/usr/bin/env python3\n")
        artifacts = self.release_dir / "artifacts"
        artifacts.mkdir()
        (artifacts / "test-0.1.0-py3-none-any.whl").write_bytes(b"fake wheel")
        service = self.release_dir / "service"
        service.mkdir()
        (service / "wrapper.sh").write_text("#!/bin/bash\n")

    def tearDown(self):
        self._tmp.cleanup()

    def _write_valid_manifest(self):
        files = _release_files(self.release_dir)
        wheel_name = "test-0.1.0-py3-none-any.whl"
        manifest = {
            "build_timestamp": 1000000,
            "files": files,
            "package_version": "0.1.0",
            "release_id": self.release_dir.name,
            "schema_version": "uam-release-v1",
            "source_commit": "abc123" + "0" * 34,
            "source_dirty": False,
            "source_kind": "git_commit",
            "source_tree": "def456" + "0" * 34,
            "tool_contract": {"uam_test": "hash123"},
            "wheel_file": f"artifacts/{wheel_name}",
            "wheel_sha256": _sha256(self.release_dir / "artifacts" / wheel_name),
        }
        (self.release_dir / "RELEASE_MANIFEST.json").write_text(
            json.dumps(manifest, indent=2)
        )
        return manifest

    def test_missing_manifest_is_invalid(self):
        result = _validate_existing_release(
            self.release_dir, "abc", "def", "0.1.0"
        )
        self.assertFalse(result["valid"])
        self.assertIn("RELEASE_MANIFEST.json missing", result["reason"])

    def test_corrupt_manifest_is_invalid(self):
        (self.release_dir / "RELEASE_MANIFEST.json").write_text("not json{{{")
        result = _validate_existing_release(
            self.release_dir, "abc", "def", "0.1.0"
        )
        self.assertFalse(result["valid"])
        self.assertIn("unreadable", result["reason"])

    def test_commit_mismatch_is_invalid(self):
        self._write_valid_manifest()
        result = _validate_existing_release(
            self.release_dir, "wrong_commit" + "0" * 30, "def456" + "0" * 34, "0.1.0"
        )
        self.assertFalse(result["valid"])
        self.assertIn("source_commit mismatch", result["reason"])

    def test_empty_tool_contract_is_invalid(self):
        manifest = self._write_valid_manifest()
        manifest["tool_contract"] = {}
        (self.release_dir / "RELEASE_MANIFEST.json").write_text(
            json.dumps(manifest, indent=2)
        )
        result = _validate_existing_release(
            self.release_dir, "abc123" + "0" * 34, "def456" + "0" * 34, "0.1.0"
        )
        self.assertFalse(result["valid"])
        self.assertIn("tool_contract", result["reason"])

    def test_tampered_file_is_invalid(self):
        self._write_valid_manifest()
        (self.release_dir / "service" / "wrapper.sh").write_text("#!/bin/bash\nPWNED\n")
        result = _validate_existing_release(
            self.release_dir, "abc123" + "0" * 34, "def456" + "0" * 34, "0.1.0"
        )
        self.assertFalse(result["valid"])
        self.assertIn("hash mismatch", result["reason"])

    def test_extra_file_is_invalid(self):
        self._write_valid_manifest()
        (self.release_dir / "venv" / "bin" / "rogue").write_text("hack")
        result = _validate_existing_release(
            self.release_dir, "abc123" + "0" * 34, "def456" + "0" * 34, "0.1.0"
        )
        self.assertFalse(result["valid"])
        self.assertIn("file inventory mismatch", result["reason"])

    def test_valid_release_is_accepted(self):
        self._write_valid_manifest()
        result = _validate_existing_release(
            self.release_dir, "abc123" + "0" * 34, "def456" + "0" * 34, "0.1.0"
        )
        self.assertTrue(result["valid"])
        self.assertGreater(result["file_count"], 0)


class TestFailClosedReceipts(unittest.TestCase):
    """P1: phase receipts must reflect actual execution outcome."""

    def test_tool_contract_returns_failure_on_missing_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            release = Path(tmp) / "release"
            release.mkdir()
            (release / "venv" / "bin").mkdir(parents=True)
            runtime = {"registry_file": "/dev/null", "state_root": "/tmp"}
            result = _update_tool_contract(release, runtime)
            self.assertFalse(result.ok)
            self.assertIn("not found", result.reason)

    def test_tool_contract_returns_failure_on_missing_mcp_sdk(self):
        with tempfile.TemporaryDirectory() as tmp:
            release = Path(tmp) / "release"
            venv_bin = release / "venv" / "bin"
            venv_bin.mkdir(parents=True)
            python = venv_bin / "python"
            python.write_text("#!/usr/bin/env python3\n")
            python.chmod(0o755)
            (release / "venv" / "lib").mkdir(parents=True)
            runtime = {"registry_file": "/dev/null", "state_root": "/tmp"}
            result = _update_tool_contract(release, runtime)
            self.assertFalse(result.ok)
            self.assertIn("mcp_sdk.py not found", result.reason)

    def test_start_tunnel_reports_bootstrap_failure(self):
        # Host-independent: the plist, label and launchctl are injected, so no LaunchAgent is addressed.
        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "tunnel.plist"
            plist.write_text("<plist/>")
            bootstrap = MagicMock(returncode=78, stdout=b"", stderr=b"service not found")
            with patch("universal_agent_middleware.release.subprocess.run", side_effect=[bootstrap]):
                result = _start_tunnel(
                    {"recovery_root": tmp}, plist=plist, label="test.uam.tunnel",
                    launchctl="/nonexistent/launchctl")
            self.assertFalse(result.ok)
            self.assertIn("bootstrap failed", result.reason)

    def test_refresh_index_reports_subprocess_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_python = Path(tmp) / "python"
            fake_python.write_text("#!/bin/sh\nexit 1\n")
            fake_python.chmod(0o755)
            runtime = {"registry_file": "/dev/null", "state_root": "/tmp"}
            result = _refresh_index(fake_python, runtime)
            self.assertFalse(result.ok)
            self.assertIn("index refresh failed", result.reason)


class TestIndexUsesNewReleasePython(unittest.TestCase):
    """P1: _refresh_index must use the explicitly passed Python, not old runtime."""

    def test_refresh_index_passes_explicit_python_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            explicit_python = Path(tmp) / "new_python"
            explicit_python.write_text("#!/bin/sh\nexit 0\n")
            explicit_python.chmod(0o755)
            runtime = {"registry_file": "/dev/null", "state_root": "/tmp"}
            with patch("universal_agent_middleware.release.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="{}", stderr="")
                _refresh_index(explicit_python, runtime)
                args = mock_run.call_args[0][0]
                self.assertEqual(args[0], str(explicit_python))

    def test_refresh_index_includes_enrich_git_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            py = Path(tmp) / "python"
            py.write_text("#!/bin/sh\nexit 0\n")
            py.chmod(0o755)
            runtime = {"registry_file": "/dev/null", "state_root": "/tmp"}
            with patch("universal_agent_middleware.release.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="{}", stderr="")
                _refresh_index(py, runtime)
                args = mock_run.call_args[0][0]
                self.assertIn("--enrich-git", args)


class TestStepReceipts(unittest.TestCase):
    """Verify _step produces structured, timestamped receipts."""

    def test_step_includes_timestamp(self):
        steps: list[dict] = []
        _step(steps, "test", "OK", extra_key="val")
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["name"], "test")
        self.assertEqual(steps[0]["status"], "OK")
        self.assertIn("t", steps[0])
        self.assertEqual(steps[0]["extra_key"], "val")


if __name__ == "__main__":
    unittest.main()
