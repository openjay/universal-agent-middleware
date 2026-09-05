import tempfile
import unittest

from universal_agent_middleware.contracts import ContractStore
from universal_agent_middleware.errors import ContractError


class ContractTests(unittest.TestCase):
    def payload(self):
        return {
            "profile": "repository-change-v1",
            "contract_id": "task-001",
            "workspace_id": "w",
            "base_revision": "abc123",
            "objective": "Make one bounded change",
            "non_goals": ["No deploy"],
            "authoritative_paths": ["src/a.py"],
            "allowed_change_paths": ["src/a.py"],
            "constraints": ["small patch"],
            "implementation_decision": "Change only src/a.py",
            "expected_changes": ["behavior fixed"],
            "acceptance_criteria": ["test passes"],
            "verification_commands": ["python -m unittest"],
            "risk_notes": [],
            "rollback": ["revert patch"],
            "open_questions": [],
        }

    def test_ready_and_immutable(self):
        with tempfile.TemporaryDirectory() as td:
            store = ContractStore(td)
            result = store.put(self.payload())
            self.assertEqual(result["readiness"]["state"], "READY")
            with self.assertRaises(ContractError):
                store.put(self.payload())

    def test_open_questions_hold(self):
        with tempfile.TemporaryDirectory() as td:
            p = self.payload()
            p["open_questions"] = ["Which API?"]
            result = ContractStore(td).put(p)
            self.assertEqual(result["readiness"]["state"], "HOLD")

    def test_unknown_field_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = self.payload()
            p["vendor_magic"] = True
            with self.assertRaises(ContractError):
                ContractStore(td).put(p)


if __name__ == "__main__":
    unittest.main()
