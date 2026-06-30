import unittest

from pmpfuzz.emitter import AssemblyEmitter
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.schema import scenario_to_case_dict


OOO_PROFILES = (
    "ooo-fetch-replay-pmp",
    "ooo-itlb-stale-after-pmp-update",
    "ooo-dtlb-stale-after-pmp-update",
    "ooo-ptw-replay-pmp-deny",
    "ooo-exception-priority",
    "ooo-misaligned-page-cross-pmp",
    "ooo-ad-bit-side-effect",
    "ooo-fence-race-matrix",
)


class OoOMicroarchitectureProfileTest(unittest.TestCase):
    def test_ooo_profiles_emit_schema_and_coverage_metadata(self):
        for profile in OOO_PROFILES:
            with self.subTest(profile=profile):
                scenario = ScenarioGenerator(seed=20260630, include_smepmp=False, profile=profile).generate_batch(1)[0]
                case = scenario_to_case_dict(scenario, seed=20260630, index=0)

                self.assertEqual(case["profile"], profile)
                self.assertIn("ooo-target", case["coverage_tags"])
                self.assertTrue(str(case["security_focus"]).startswith("ooo-"))
                self.assertTrue(case["semantic_bins"])
                self.assertTrue(case["combo_bins"])

    def test_ooo_fetch_replay_focuses_on_fetch_pmp_boundary(self):
        cases = [
            scenario_to_case_dict(scenario, seed=20260630, index=index)
            for index, scenario in enumerate(
                ScenarioGenerator(seed=20260630, include_smepmp=False, profile="ooo-fetch-replay-pmp").generate_batch(96)
            )
        ]

        self.assertEqual({case["access"] for case in cases}, {"fetch"})
        self.assertGreaterEqual({case["privilege"] for case in cases}, {"S", "U"})
        self.assertGreaterEqual({case["pmp_match_mode"] for case in cases}, {"tor", "na4", "napot", "first-match-overlap"})
        self.assertEqual({case["expected_allowed"] for case in cases}, {False, True})

    def test_ooo_itlb_stale_uses_fetch_stateful_with_fence_i(self):
        scenarios = ScenarioGenerator(
            seed=20260630,
            include_smepmp=False,
            profile="ooo-itlb-stale-after-pmp-update",
        ).generate_batch(4)
        cases = [scenario_to_case_dict(scenario, seed=20260630, index=index) for index, scenario in enumerate(scenarios)]
        asm = AssemblyEmitter().emit(scenarios[0])

        self.assertEqual({case["access"] for case in cases}, {"fetch"})
        self.assertEqual({case["stateful_sequence"]["mutation"] for case in cases}, {"pmpcfg-deny-target"})
        self.assertIn("with-sfence-fence-i", {case["stateful_sequence"]["fence"] for case in cases})
        self.assertIn("fence.i", asm)

    def test_ooo_dtlb_and_fence_profiles_cover_load_store_and_fence_modes(self):
        dtlb_cases = [
            scenario_to_case_dict(scenario, seed=20260630, index=index)
            for index, scenario in enumerate(
                ScenarioGenerator(seed=20260630, include_smepmp=False, profile="ooo-dtlb-stale-after-pmp-update").generate_batch(8)
            )
        ]
        fence_cases = [
            scenario_to_case_dict(scenario, seed=20260630, index=index)
            for index, scenario in enumerate(
                ScenarioGenerator(seed=20260630, include_smepmp=False, profile="ooo-fence-race-matrix").generate_batch(12)
            )
        ]

        self.assertEqual({case["access"] for case in dtlb_cases}, {"load", "store"})
        self.assertEqual({case["stateful_sequence"]["mutation"] for case in dtlb_cases}, {"pmpcfg-deny-target"})
        self.assertGreaterEqual(
            {case["stateful_sequence"]["fence"] for case in fence_cases},
            {"with-sfence", "with-sfence-fence-i", "no-fence-experimental"},
        )
        self.assertIn("fetch", {case["access"] for case in fence_cases})

    def test_ooo_ptw_exception_misaligned_and_ad_profiles_expose_risk_dimensions(self):
        ptw_cases = [
            scenario_to_case_dict(scenario, seed=20260630, index=index)
            for index, scenario in enumerate(
                ScenarioGenerator(seed=20260630, include_smepmp=False, profile="ooo-ptw-replay-pmp-deny").generate_batch(96)
            )
        ]
        priority_cases = [
            scenario_to_case_dict(scenario, seed=20260630, index=index)
            for index, scenario in enumerate(
                ScenarioGenerator(seed=20260630, include_smepmp=False, profile="ooo-exception-priority").generate_batch(12)
            )
        ]
        cross_cases = [
            scenario_to_case_dict(scenario, seed=20260630, index=index)
            for index, scenario in enumerate(
                ScenarioGenerator(seed=20260630, include_smepmp=False, profile="ooo-misaligned-page-cross-pmp").generate_batch(6)
            )
        ]
        ad_cases = [
            scenario_to_case_dict(scenario, seed=20260630, index=index)
            for index, scenario in enumerate(
                ScenarioGenerator(seed=20260630, include_smepmp=False, profile="ooo-ad-bit-side-effect").generate_batch(8)
            )
        ]

        self.assertEqual({case["ptw_fault_level"] for case in ptw_cases}, {"L0", "L1", "L2"})
        self.assertGreaterEqual({case["preload_mode"] for case in ptw_cases}, {"cold", "root-target", "denied-l1", "all"})
        self.assertTrue(any(not case["pte_permissions"]["valid"] for case in priority_cases))
        self.assertIn("page_cross", {case["probe_offset"] for case in cross_cases})
        self.assertEqual({case["pte_permissions"]["accessed"] for case in ad_cases}, {False, True})
        self.assertIn(False, {case["pte_permissions"]["dirty"] for case in ad_cases})


if __name__ == "__main__":
    unittest.main()
