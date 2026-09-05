import json
import os
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from universal_agent_middleware.gateway import MiddlewareGateway
from universal_agent_middleware.server import Handler, UAMHTTPServer


class APITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.repo = Path(cls.tmp.name, "repo")
        cls.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(cls.repo)], check=True)
        subprocess.run(["git", "-C", str(cls.repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(cls.repo), "config", "user.name", "UAM Test"], check=True)
        Path(cls.repo, "README.md").write_text("hello research plane\nneedle here\n", encoding="utf-8")
        Path(cls.repo, ".gitignore").write_text(".env\nescape-link\n", encoding="utf-8")
        Path(cls.repo, ".env").write_text("TOP_SECRET=yes\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(cls.repo), "add", "README.md", ".gitignore"], check=True)
        subprocess.run(["git", "-C", str(cls.repo), "commit", "-qm", "fixture"], check=True)
        cls.head = subprocess.check_output(["git", "-C", str(cls.repo), "rev-parse", "HEAD"], text=True).strip()

        outside = Path(cls.tmp.name, "outside.txt")
        outside.write_text("must not escape")
        try:
            Path(cls.repo, "escape-link").symlink_to(outside)
        except (OSError, NotImplementedError):
            pass

        registry = Path(cls.tmp.name, "workspaces.json")
        registry.write_text(json.dumps({"registry_version": "uam-workspace-registry-v1", "workspaces": [{"workspace_id": "fixture", "root": str(cls.repo), "kind": "git-repository", "capabilities": ["filesystem.read", "git.observe"]}]}))
        state = Path(cls.tmp.name, "state")
        gateway = MiddlewareGateway(str(registry), str(state))
        cls.token = "x" * 48
        cls.server = UAMHTTPServer(("127.0.0.1", 0), Handler, gateway=gateway, bearer_token=cls.token)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.tmp.cleanup()

    def request(self, method, path, body=None, auth=True):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if auth:
            req.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status, json.loads(resp.read())

    def test_01_health_and_auth(self):
        status, body = self.request("GET", "/health", auth=False)
        self.assertEqual(status, 200)
        self.assertEqual(body["mode"], "target-workspace-read-only")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.request("GET", "/v1/workspaces", auth=False)
        self.assertEqual(ctx.exception.code, 401)

    def test_health_poll_does_not_append_and_corruption_is_unready(self):
        audit = self.server.gateway.audit
        before = audit.verify()["records"]
        _, body = self.request("GET", "/status", auth=False)
        self.assertEqual(body["workspace_count"], 1)
        self.request("GET", "/readyz", auth=False)
        self.assertEqual(audit.verify()["records"], before)
        with patch.object(audit, "verify", return_value={"valid": False, "records": before}):
            for endpoint in ("/status", "/readyz"):
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    self.request("GET", endpoint, auth=False)
                self.assertEqual(ctx.exception.code, 503)

    def test_02_research_flow(self):
        _, workspaces = self.request("GET", "/v1/workspaces")
        self.assertEqual(workspaces["workspaces"][0]["workspace_id"], "fixture")
        _, tree = self.request("GET", "/v1/tree?workspace_id=fixture&depth=2")
        paths = {x["path"] for x in tree["entries"]}
        self.assertIn("README.md", paths)
        self.assertNotIn(".env", paths)
        _, read = self.request("POST", "/v1/read", {"workspace_id": "fixture", "path": "README.md", "start_line": 2, "end_line": 2})
        self.assertEqual(read["content"], "needle here")
        _, search = self.request("POST", "/v1/search", {"workspace_id": "fixture", "query": "needle"})
        self.assertEqual(search["results"][0]["line"], 2)
        _, git = self.request("GET", "/v1/git/status?workspace_id=fixture")
        self.assertEqual(git["head"], self.head)

    def test_03_secret_and_symlink_escape(self):
        for path in [".env", "../outside.txt", "escape-link"]:
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self.request("POST", "/v1/read", {"workspace_id": "fixture", "path": path})
            self.assertEqual(ctx.exception.code, 400)

    def test_04_contract_and_audit(self):
        payload = {
            "profile": "repository-change-v1",
            "contract_id": "fixture-task-001",
            "workspace_id": "fixture",
            "base_revision": self.head,
            "objective": "Change README wording",
            "non_goals": ["No release"],
            "authoritative_paths": ["README.md"],
            "allowed_change_paths": ["README.md"],
            "constraints": ["one file only"],
            "implementation_decision": "Edit the wording only.",
            "expected_changes": ["README changed"],
            "acceptance_criteria": ["README contains desired wording"],
            "verification_commands": ["git diff --check"],
            "risk_notes": [],
            "rollback": ["revert the patch"],
            "open_questions": []
        }
        _, contract = self.request("POST", "/v1/contracts", payload)
        self.assertEqual(contract["readiness"]["state"], "READY")
        # Contract state must not appear in the target repository.
        self.assertFalse((self.repo / ".state").exists())
        _, fetched = self.request("GET", "/v1/contracts/fixture-task-001")
        self.assertEqual(fetched["base_revision"], self.head)
        result_payload = {
            "result_id": "fixture-result-001",
            "contract_id": "fixture-task-001",
            "workspace_id": "fixture",
            "base_revision": self.head,
            "final_revision": "simulated-final",
            "changed_paths": ["README.md"],
            "verification": [{"command": "git diff --check", "exit_code": 0, "evidence": "simulated PASS"}],
            "unresolved_risks": [],
            "executor": "simulated-executor"
        }
        _, result = self.request("POST", "/v1/results", result_payload)
        self.assertEqual(result["review"]["state"], "PASS")
        _, fetched_result = self.request("GET", "/v1/results/fixture-result-001")
        self.assertEqual(fetched_result["review"]["state"], "PASS")
        _, audit = self.request("GET", "/v1/audit/verify")
        self.assertTrue(audit["valid"])
        self.assertGreaterEqual(audit["records"], 1)

    def test_05_openapi(self):
        _, schema = self.request("GET", "/openapi.json", auth=False)
        self.assertEqual(schema["openapi"], "3.1.0")
        self.assertIn("/v1/contracts", schema["paths"])


if __name__ == "__main__":
    unittest.main()
