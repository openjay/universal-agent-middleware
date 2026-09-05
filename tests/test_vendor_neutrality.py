from pathlib import Path
import unittest

from universal_agent_middleware.openapi import schema
from universal_agent_middleware.adapters.openai_actions import with_actions_extensions


ROOT = Path(__file__).resolve().parents[1]


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

    def test_core_source_does_not_name_execution_vendors(self):
        core_files = [
            p
            for p in (ROOT / "src" / "universal_agent_middleware").glob("*.py")
            if p.name != "cli.py"
        ]
        corpus = "\n".join(p.read_text(encoding="utf-8") for p in core_files).lower()
        for term in ("codex", "claude code", "cursor", "chatgpt"):
            self.assertNotIn(term, corpus)


if __name__ == "__main__":
    unittest.main()
