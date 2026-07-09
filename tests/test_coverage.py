import tempfile
import unittest
from pathlib import Path

from pmpfuzz.coverage import coverage_from_run, write_coverage
from pmpfuzz.schema import result_to_dict, scenario_to_case_dict, write_json
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.semantic_coverage import XIANGSHAN_TARGETED_TARGET, target_profiles


class CoverageTest(unittest.TestCase):
    def test_coverage_from_run_counts_schema_tags_profiles_and_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=1, include_smepmp=False, profile="pmp-boundary").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=1, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)
            write_json(
                run_dir / "results" / case["name"] / "result.json",
                result_to_dict(
                    case=case,
                    dut="spike",
                    status="pass",
                    elapsed_seconds=0.1,
                    returncode=0,
                    log=run_dir / "results" / case["name"] / "case.log",
                    reason=None,
                ),
            )

            coverage = coverage_from_run(run_dir)
            out = write_coverage(run_dir)
            out_exists = out.exists()

        self.assertEqual(coverage["total_cases"], 1)
        self.assertEqual(coverage["schema_version"], 4)
        self.assertEqual(coverage["profiles"]["pmp-boundary"], 1)
        self.assertEqual(coverage["dut_whitebox"]["provider"], "dut-whitebox")
        self.assertIn("pmp", coverage["coverage_tags"])
        self.assertIn("combo2:profile=pmp-boundary|priv=U|access=load", coverage["combo_bins"])
        self.assertGreater(coverage["target_combo_bins"], coverage["covered_target_combo_bins"])
        self.assertEqual(coverage["statuses"]["pass"], 1)
        self.assertTrue(out_exists)

    def test_coverage_counts_stateful_sequence_dimensions(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=5, include_smepmp=False, profile="tlb-stale-pmp").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=5, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            coverage = coverage_from_run(run_dir)

        self.assertEqual(coverage["stateful_sequences"]["tlb-stale-pmp"], 1)
        self.assertEqual(coverage["stateful_mutations"]["pmpcfg-deny-target"], 1)
        self.assertIn("with-sfence", coverage["stateful_fences"])

    def test_coverage_counts_smepmp_dimensions(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=6, include_smepmp=True, profile="smepmp-mml-shared-code").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=6, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            coverage = coverage_from_run(run_dir)

        self.assertEqual(coverage["smepmp_mml"]["1"], 1)
        self.assertIn(case["smepmp_rule"], coverage["smepmp_rules"])
        self.assertIn(case["effective_privilege"], coverage["effective_privileges"])
        self.assertIn(case["pmp_match_result"], coverage["pmp_match_results"])

    def test_xiangshan_targeted_runs_use_xiangshan_target_coverage_space(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            profile = "xiangshan-fetch-pmp-boundary"
            scenario = ScenarioGenerator(seed=20260630, include_smepmp=False, profile=profile).generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=20260630, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            coverage = coverage_from_run(run_dir)

        self.assertEqual(coverage["target"], XIANGSHAN_TARGETED_TARGET)
        self.assertIn(profile, target_profiles(XIANGSHAN_TARGETED_TARGET))
        self.assertGreater(coverage["covered_target_bins"], 0)
        self.assertLess(coverage["missing_target_bins"], coverage["target_bins"])


if __name__ == "__main__":
    unittest.main()
