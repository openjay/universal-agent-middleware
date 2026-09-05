import json
import tempfile
import unittest
from pathlib import Path

from universal_agent_middleware.audit import HashChainedAuditLog


class AuditTests(unittest.TestCase):
    def test_detects_tampering(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td, "audit.jsonl")
            log = HashChainedAuditLog(path)
            log.append(action="a", workspace_id="w", outcome="PASS")
            log.append(action="b", workspace_id="w", outcome="PASS")
            self.assertTrue(log.verify()["valid"])
            lines = path.read_text().splitlines()
            row = json.loads(lines[0])
            row["outcome"] = "FAIL"
            lines[0] = json.dumps(row)
            path.write_text("\n".join(lines) + "\n")
            self.assertFalse(log.verify()["valid"])


if __name__ == "__main__":
    unittest.main()
