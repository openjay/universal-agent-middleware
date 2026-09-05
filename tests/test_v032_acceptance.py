"""UAM v0.3.2 acceptance tests — semantic correctness hardening.

T1: landed candidate lifecycle != active
T2: candidate absent → active_candidate = NOT_APPLICABLE, not a coverage warning
T3: forge_ci = EXTERNALLY_VERIFIED → observation requirement may be satisfied
T4: all observation surfaces satisfied → authority remains NOT_EVALUATED_BY_UAM
T5: sample observation profile → runtime_identity included, candidate conditional
T6: v0.3.1 regression (MCP/read-only/security) → all PASS
"""
import tempfile
import unittest

from universal_agent_middleware.project import (
    ProjectRegistry,
    WorkspaceInstance,
    _compute_coverage,
    _observation_surface_requirements,
    _INSTANCE_ROLES,
    _LIFECYCLE_STATES,
    _COVERAGE_STATES,
)
from universal_agent_middleware.workspace import WorkspaceRegistry
from universal_agent_middleware.gateway import MiddlewareGateway

from synthetic_fixtures import SyntheticRegistryBundle


class AcceptanceFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = SyntheticRegistryBundle()
        cls.registry_path = cls.bundle.registry_path

    @classmethod
    def tearDownClass(cls):
        cls.bundle.cleanup()


class T1_CandidateLifecycleLanded(AcceptanceFixture):
    """Landed candidate → lifecycle != active."""

    def test_candidate_has_landed_lifecycle(self):
        ws_reg = WorkspaceRegistry(str(self.registry_path))
        proj_reg = ProjectRegistry(ws_reg, str(self.registry_path))
        inst = proj_reg.get_instance("sampleproj-candidate")
        self.assertIsNotNone(inst)
        self.assertEqual(inst.role, "candidate")
        self.assertEqual(inst.lifecycle, "landed")
        self.assertNotEqual(inst.lifecycle, "active")

    def test_role_and_lifecycle_are_orthogonal(self):
        self.assertIn("candidate", _INSTANCE_ROLES)
        self.assertIn("landed", _LIFECYCLE_STATES)
        self.assertNotIn("active-candidate", _INSTANCE_ROLES)

    def test_instance_to_dict_includes_lifecycle(self):
        inst = WorkspaceInstance(
            workspace_id="test", project_id="p", role="candidate",
            root="/tmp", lifecycle="landed",
        )
        payload = inst.to_dict()
        self.assertEqual(payload["lifecycle"], "landed")
        self.assertEqual(payload["role"], "candidate")


class T2_CandidateAbsentNotApplicable(AcceptanceFixture):
    """No active candidate → active_candidate = not_applicable, not a warning."""

    def test_no_candidate_yields_not_applicable(self):
        coverage = _compute_coverage(
            roles_observed={"canonical-main"},
            unregistered_worktrees=[],
            has_active_candidate=False,
            observation_profile=None,
        )
        self.assertEqual(coverage["surfaces"]["active_candidate"], "not_applicable")

    def test_not_applicable_does_not_reduce_status(self):
        coverage = _compute_coverage(
            roles_observed={"canonical-main"},
            unregistered_worktrees=[],
            has_active_candidate=False,
            observation_profile=None,
        )
        self.assertNotEqual(coverage["status"], "UNKNOWN")

    def test_not_applicable_in_coverage_states(self):
        self.assertIn("not_applicable", _COVERAGE_STATES)


class T3_ExternallyVerifiedSatisfiesRequirement(AcceptanceFixture):
    """externally_verified is an acceptable coverage state."""

    def test_externally_verified_in_states(self):
        self.assertIn("externally_verified", _COVERAGE_STATES)

    def test_observation_requirements_note_no_authority(self):
        reqs = _observation_surface_requirements(None)
        merge_req = reqs.get("merge_consideration", {})
        self.assertIn("note", merge_req)
        self.assertIn("authority", merge_req["note"].lower())


class T4_AuthorityNeverEvaluatedByUAM(AcceptanceFixture):
    """Coverage COMPLETE → authority_evaluation still says NOT evaluated by UAM."""

    def test_authority_evaluation_field_present(self):
        coverage = _compute_coverage(
            roles_observed={"canonical-main", "candidate", "runtime"},
            unregistered_worktrees=[],
            has_active_candidate=True,
            observation_profile=None,
        )
        ae = coverage["authority_evaluation"]
        self.assertEqual(ae["mode"], "PROJECT_DEFINED")
        self.assertFalse(ae["evaluated_by_uam"])

    def test_complete_coverage_does_not_imply_authorized(self):
        coverage = _compute_coverage(
            roles_observed={"canonical-main", "candidate", "runtime"},
            unregistered_worktrees=[],
            has_active_candidate=True,
            observation_profile=None,
        )
        ae = coverage["authority_evaluation"]
        self.assertFalse(ae["evaluated_by_uam"])
        self.assertNotIn("granted", ae.get("note", "").lower())


class T5_SampleObservationProfile(AcceptanceFixture):
    """Sample profile: runtime_identity included, candidate conditional."""

    def test_profile_exists_and_loads(self):
        ws_reg = WorkspaceRegistry(str(self.registry_path))
        proj_reg = ProjectRegistry(ws_reg, str(self.registry_path))
        profile = proj_reg.get_observation_profile("sampleproj")
        self.assertIsNotNone(profile)
        self.assertEqual(profile["project_id"], "sampleproj")

    def test_profile_has_phase_a_exit(self):
        ws_reg = WorkspaceRegistry(str(self.registry_path))
        proj_reg = ProjectRegistry(ws_reg, str(self.registry_path))
        profile = proj_reg.get_observation_profile("sampleproj")
        reqs = profile["requirements"]
        self.assertIn("phase_a_exit_observation", reqs)
        surfaces = reqs["phase_a_exit_observation"]["surfaces"]
        self.assertIn("runtime", surfaces)

    def test_profile_candidate_conditional(self):
        ws_reg = WorkspaceRegistry(str(self.registry_path))
        proj_reg = ProjectRegistry(ws_reg, str(self.registry_path))
        profile = proj_reg.get_observation_profile("sampleproj")
        merge_req = profile["requirements"]["merge_consideration"]
        self.assertIn("conditional", merge_req)
        cond = merge_req["conditional"]["active_candidate"]
        self.assertEqual(cond["otherwise"], "not_applicable")

    def test_profile_authority_policy(self):
        ws_reg = WorkspaceRegistry(str(self.registry_path))
        proj_reg = ProjectRegistry(ws_reg, str(self.registry_path))
        profile = proj_reg.get_observation_profile("sampleproj")
        self.assertEqual(profile["authority_policy"]["mode"], "PROJECT_DEFINED")

    def test_project_reality_uses_profile(self):
        ws_reg = WorkspaceRegistry(str(self.registry_path))
        proj_reg = ProjectRegistry(ws_reg, str(self.registry_path))
        snapshot = proj_reg.project_reality_snapshot("sampleproj")
        reqs = snapshot["coverage"]["observation_requirements"]
        self.assertIn("phase_a_exit_observation", reqs)


class T6_RegressionCheck(AcceptanceFixture):
    """v0.3.1 regression: MCP/read-only/security basics still work."""

    def setUp(self):
        self.state = tempfile.TemporaryDirectory(prefix="uam-acceptance-test-")
        self.addCleanup(self.state.cleanup)
        self.state_dir = self.state.name

    def test_version_is_032(self):
        import universal_agent_middleware
        self.assertTrue(universal_agent_middleware.__version__ >= "0.3.2")

    def test_gateway_initializes(self):
        gw = MiddlewareGateway(registry_path=str(self.registry_path), state_dir=self.state_dir)
        self.assertIsNotNone(gw)

    def test_list_workspaces_returns_workspaces(self):
        gw = MiddlewareGateway(registry_path=str(self.registry_path), state_dir=self.state_dir)
        result = gw.list_workspaces()
        self.assertIn("workspaces", result)
        self.assertGreaterEqual(len(result["workspaces"]), 2)

    def test_schema_version_v2(self):
        ws_reg = WorkspaceRegistry(str(self.registry_path))
        proj_reg = ProjectRegistry(ws_reg, str(self.registry_path))
        snapshot = proj_reg.project_reality_snapshot("sampleproj")
        self.assertEqual(snapshot["schema_version"], "project-reality-snapshot-v2")

    def test_no_decision_requirements_key(self):
        ws_reg = WorkspaceRegistry(str(self.registry_path))
        proj_reg = ProjectRegistry(ws_reg, str(self.registry_path))
        snapshot = proj_reg.project_reality_snapshot("sampleproj")
        self.assertNotIn("decision_requirements", snapshot["coverage"])
        self.assertIn("observation_requirements", snapshot["coverage"])


if __name__ == "__main__":
    unittest.main()
