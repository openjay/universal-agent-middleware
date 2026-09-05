import tempfile
import unittest

from universal_agent_middleware.contracts import ContractStore
from universal_agent_middleware.results import ExecutorResultStore


class ResultReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.contracts = ContractStore(self.tmp.name)
        self.contracts.put({
            "profile": "repository-change-v1",
            "contract_id": "task-100",
            "workspace_id": "w",
            "base_revision": "base123",
            "objective": "bounded patch",
            "non_goals": [],
            "authoritative_paths": ["src/a.py"],
            "allowed_change_paths": ["src/a.py", "tests/test_a.py"],
            "constraints": ["no scope expansion"],
            "implementation_decision": "patch a",
            "expected_changes": ["fixed"],
            "acceptance_criteria": ["test green"],
            "verification_commands": ["python -m unittest tests.test_a"],
            "risk_notes": [],
            "rollback": ["revert"],
            "open_questions": [],
        })
        self.results = ExecutorResultStore(self.tmp.name, self.contracts)

    def tearDown(self):
        self.tmp.cleanup()

    def result(self):
        return {
            "result_id": "result-100",
            "contract_id": "task-100",
            "workspace_id": "w",
            "base_revision": "base123",
            "final_revision": "final456",
            "changed_paths": ["src/a.py", "tests/test_a.py"],
            "verification": [{"command": "python -m unittest tests.test_a", "exit_code": 0, "evidence": "1 passed"}],
            "unresolved_risks": [],
            "executor": "simulated-executor"
        }

    def test_pass(self):
        out = self.results.put(self.result())
        self.assertEqual(out["review"]["state"], "PASS")

    def test_scope_expansion_holds(self):
        result = self.result()
        result["result_id"] = "result-101"
        result["changed_paths"].append("secrets.txt")
        out = self.results.put(result)
        self.assertEqual(out["review"]["state"], "HOLD")
        self.assertIn("CHANGED_PATH_OUTSIDE_CONTRACT", out["review"]["blockers"])

    def test_failed_verification_holds(self):
        result = self.result()
        result["result_id"] = "result-102"
        result["verification"][0]["exit_code"] = 1
        out = self.results.put(result)
        self.assertIn("VERIFICATION_FAILED", out["review"]["blockers"])

    def test_unchanged_final_revision_holds(self):
        result = self.result()
        result["result_id"] = "result-103"
        result["final_revision"] = result["base_revision"]
        out = self.results.put(result)
        self.assertIn("FINAL_REVISION_UNCHANGED", out["review"]["blockers"])


if __name__ == "__main__":
    unittest.main()
