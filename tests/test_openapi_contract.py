import unittest

from universal_agent_middleware.openapi import schema


class OpenAPIContractTests(unittest.TestCase):
    def test_operation_ids_unique_and_v1_secured(self):
        doc = schema()
        operation_ids = []
        for path, path_item in doc["paths"].items():
            for method, op in path_item.items():
                if method not in {"get", "post", "put", "patch", "delete"}:
                    continue
                operation_ids.append(op["operationId"])
                self.assertTrue(op.get("security"), f"{method} {path} missing security")
        self.assertEqual(len(operation_ids), len(set(operation_ids)))

    def test_contract_schema_exposes_ready_fields(self):
        doc = schema()
        contract = doc["paths"]["/v1/contracts"]["post"]["requestBody"]["content"]["application/json"]["schema"]
        required = set(contract["required"])
        for field in {
            "profile",
            "authoritative_paths",
            "allowed_change_paths",
            "acceptance_criteria",
            "verification_commands",
            "rollback",
            "open_questions",
        }:
            self.assertIn(field, required)
        self.assertFalse(contract["additionalProperties"])

    def test_executor_result_schema_requires_evidence_surface(self):
        doc = schema()
        result = doc["paths"]["/v1/results"]["post"]["requestBody"]["content"]["application/json"]["schema"]
        required = set(result["required"])
        self.assertTrue({"changed_paths", "verification", "unresolved_risks"}.issubset(required))
        self.assertFalse(result["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
