"""The core names no execution vendor; the two harness adapters do, on purpose, and the read-only service never loads them.

The invariant used to read "no top-level module except ``cli.py`` names Codex, Cursor, Claude Code or ChatGPT". The Consumer then
added two modules whose job is to drive those harnesses as subprocesses (``harness_adapter.py``, ``consumer_cli.py``), and that scan
failed on them. The boundary is stated in two parts, so that it is neither dropped nor widened by accident:

* the modules that name a vendor are exactly ``HARNESS_ADAPTERS`` (and ``cli.py``, as before): a new module that names one fails,
  and so does an adapter that no longer does (a stale exemption);
* the read-only service's own entry path (``uam mcp-sdk-stdio``: ``cli`` and the SDK adapter, with the server built) loads none of
  the modules that drive a harness, in a fresh interpreter. The opt-in Consumer and task profile are separate entries and do load them.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from universal_agent_middleware.adapters.openai_actions import with_actions_extensions
from universal_agent_middleware.openapi import schema

try:
    from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
except ImportError:
    create_session_read_server = None

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "universal_agent_middleware"
VENDOR_TERMS = ("codex", "claude code", "cursor", "chatgpt")
# Modules that name an execution vendor on purpose: they adapt the harnesses the Consumer drives. A closed list.
HARNESS_ADAPTERS = frozenset({"consumer_cli.py", "harness_adapter.py"})
# What loads them: the adapters, the Consumer (imports harness_adapter) and the task profile (imports consumer_cli).
HARNESS_DRIVERS = frozenset({"harness_adapter", "consumer_cli", "consumer", "task_profile"})
# Runs in a fresh interpreter with this checkout first on the path (``-I`` ignores PYTHONPATH, so a stale install cannot answer).
READ_ONLY_ENTRY = """
import json, sys
sys.path.insert(0, sys.argv[1])
import universal_agent_middleware as package
from universal_agent_middleware import cli
from universal_agent_middleware.adapters.mcp_sdk import create_session_read_server
create_session_read_server(registry_path=sys.argv[2], state_dir=sys.argv[3])
print(json.dumps({"package": package.__file__,
                  "modules": sorted(name for name in sys.modules if name.startswith("universal_agent_middleware."))}))
"""


class VendorNeutralityTests(unittest.TestCase):
    def test_generic_openapi_has_no_vendor_extension(self):
        doc = schema()
        rendered = str(doc).lower()
        self.assertNotIn("x-openai", rendered)
        self.assertNotIn("chatgpt", rendered)
        self.assertNotIn("codex", rendered)

    def test_vendor_adapter_is_overlay_only(self):
        base = schema()
        overlay = with_actions_extensions(base)
        self.assertNotEqual(base, overlay)
        for path_item in overlay["paths"].values():
            for method, operation in path_item.items():
                if method in {"get", "post", "put", "patch", "delete"}:
                    self.assertIn("x-openai-isConsequential", operation)
        self.assertNotIn("x-openai-isConsequential", str(base))

    def test_only_the_harness_adapters_name_execution_vendors(self):
        named = {
            path.name
            for path in PACKAGE.glob("*.py")
            if path.name != "cli.py" and any(term in path.read_text(encoding="utf-8").lower() for term in VENDOR_TERMS)
        }
        self.assertEqual(
            named, HARNESS_ADAPTERS,
            "the modules that name an execution vendor must be exactly the harness adapters: "
            f"unexpected {sorted(named - HARNESS_ADAPTERS)}, no longer naming one {sorted(HARNESS_ADAPTERS - named)}",
        )

    def test_every_module_the_boundary_names_exists(self):
        for module in sorted(HARNESS_DRIVERS):
            with self.subTest(module=module):
                self.assertTrue((PACKAGE / f"{module}.py").is_file())

    @unittest.skipIf(create_session_read_server is None, "MCP SDK unavailable")
    def test_the_read_only_service_never_loads_a_harness_adapter(self):
        with tempfile.TemporaryDirectory(prefix="uam-vendor-boundary-") as tmp:
            registry, state = Path(tmp) / "workspaces.json", Path(tmp) / "state"
            registry.write_text(json.dumps({"registry_version": "uam-workspace-registry-v1", "workspaces": []}), encoding="utf-8")
            state.mkdir()
            done = subprocess.run(
                [sys.executable, "-I", "-B", "-c", READ_ONLY_ENTRY, str(PACKAGE.parent), str(registry), str(state)],
                capture_output=True, text=True, timeout=120, check=False,
            )
        self.assertEqual(done.returncode, 0, done.stderr)
        report = json.loads(done.stdout.strip().splitlines()[-1])
        self.assertEqual(Path(report["package"]).resolve(), (PACKAGE / "__init__.py").resolve(), "the checkout under test must answer")
        loaded = {name.split(".")[1] for name in report["modules"]}
        self.assertEqual(loaded & HARNESS_DRIVERS, set(), "the read-only service loaded a harness adapter")


if __name__ == "__main__":
    unittest.main()
