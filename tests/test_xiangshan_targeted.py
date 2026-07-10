import unittest
from pathlib import Path

from pmpfuzz.emitter import AssemblyEmitter
from pmpfuzz.mmu import TranslationMode
from pmpfuzz.pmp import Access, Privilege
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.schema import scenario_to_case_dict


XIANGSHAN_TARGETED_PROFILES = (
    "xiangshan-fetch-pmp-boundary",
    "xiangshan-itlb-stale-pmp",
    "xiangshan-ptw-pmp-depth",
    "xiangshan-side-effect",
)


class XiangShanTargetedProfileTest(unittest.TestCase):
    def test_xiangshan_targeted_profiles_emit_schema_metadata(self):
        for profile in XIANGSHAN_TARGETED_PROFILES:
            with self.subTest(profile=profile):
                scenario = ScenarioGenerator(seed=20260630, include_smepmp=False, profile=profile).generate_batch(1)[0]
                case = scenario_to_case_dict(scenario, seed=20260630, index=0)

                self.assertEqual(case["profile"], profile)
                self.assertIn("xiangshan-target", case["coverage_tags"])
                self.assertTrue(str(case["security_focus"]).startswith("xiangshan"))
                self.assertTrue(case["semantic_bins"])
                self.assertTrue(case["combo_bins"])

    def test_fetch_pmp_boundary_profile_is_fetch_focused_and_crosses_privileges(self):
        cases = [
            scenario_to_case_dict(scenario, seed=20260630, index=index)
            for index, scenario in enumerate(
                ScenarioGenerator(seed=20260630, include_smepmp=False, profile="xiangshan-fetch-pmp-boundary").generate_batch(96)
            )
        ]

        self.assertEqual({case["access"] for case in cases}, {"fetch"})
        self.assertGreaterEqual({case["privilege"] for case in cases}, {"S", "U"})
        self.assertGreaterEqual(
            {case["pmp_match_mode"] for case in cases},
            {"tor", "na4", "napot", "first-match-overlap"},
        )
        self.assertEqual({case["expected_allowed"] for case in cases}, {False, True})
        self.assertIn("inside", {case["probe_offset"] for case in cases})
        self.assertIn("upper_bound", {case["probe_offset"] for case in cases})

    def test_itlb_stale_pmp_profile_uses_fetch_warmup_mutation_and_fence_i(self):
        scenarios = ScenarioGenerator(seed=20260630, include_smepmp=False, profile="xiangshan-itlb-stale-pmp").generate_batch(8)
        cases = [scenario_to_case_dict(scenario, seed=20260630, index=index) for index, scenario in enumerate(scenarios)]

        self.assertEqual({case["access"] for case in cases}, {"fetch"})
        self.assertEqual({case["translation"] for case in cases}, {"sv39"})
        self.assertEqual({case["stateful_sequence"]["kind"] for case in cases}, {"xiangshan-itlb-stale-pmp"})
        self.assertEqual({case["stateful_sequence"]["mutation"] for case in cases}, {"pmpcfg-deny-target"})
        self.assertIn("with-sfence-fence-i", {case["stateful_sequence"]["fence"] for case in cases})
        self.assertTrue(all(case["pte_permissions"]["rwx"].endswith("x") for case in cases))

        asm = AssemblyEmitter().emit(scenarios[0])
        self.assertIn("fence.i", asm)
        self.assertIn("target_region:\n    ecall", asm)

    def test_ptw_depth_profile_covers_levels_preload_and_fetch(self):
        cases = [
            scenario_to_case_dict(scenario, seed=20260630, index=index)
            for index, scenario in enumerate(
                ScenarioGenerator(seed=20260630, include_smepmp=False, profile="xiangshan-ptw-pmp-depth").generate_batch(96)
            )
        ]

        self.assertEqual({case["translation"] for case in cases}, {"sv39"})
        self.assertEqual({case["ptw_fault_level"] for case in cases}, {"L0", "L1", "L2"})
        self.assertGreaterEqual({case["preload_mode"] for case in cases}, {"cold", "root-target", "denied-l1", "all"})
        self.assertIn("fetch", {case["access"] for case in cases})
        self.assertEqual({case["mxr"] for case in cases}, {False, True})

    def test_side_effect_profile_keeps_stateful_sentinel_checks(self):
        scenario = ScenarioGenerator(seed=20260630, include_smepmp=False, profile="xiangshan-side-effect").generate_batch(1)[0]
        case = scenario_to_case_dict(scenario, seed=20260630, index=0)
        asm = AssemblyEmitter().emit(scenario)

        self.assertEqual(case["stateful_sequence"]["kind"], "xiangshan-side-effect")
        self.assertEqual(case["access"], "store")
        self.assertIn(case["privilege"], {"S", "U"})
        self.assertIn("sentinel_word:", asm)
        self.assertIn("stateful_sentinel_initial:", asm)
        self.assertIn("stateful_sentinel_modified:", asm)
        self.assertIn("stateful_report_trap:", asm)

    def test_xiangshan_targeted_script_runs_only_targeted_duts_by_default(self):
        script = Path("scripts/run_xiangshan_targeted_campaign.sh")

        self.assertTrue(script.exists())
        text = script.read_text(encoding="ascii")
        self.assertIn("xiangshan-fetch-pmp-boundary", text)
        self.assertIn("xiangshan-itlb-stale-pmp", text)
        self.assertIn("xiangshan-clean", text)
        self.assertIn("rocket-clean", text)
        self.assertIn("spike", text)
        self.assertNotIn("cva6-clean", text)


if __name__ == "__main__":
    unittest.main()
