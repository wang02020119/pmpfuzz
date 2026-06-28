import tempfile
import unittest
from pathlib import Path

from pmpfuzz.coverage import coverage_from_run, write_coverage
from pmpfuzz.schema import result_to_dict, scenario_to_case_dict, write_json
from pmpfuzz.scenario import ScenarioGenerator


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
        self.assertEqual(coverage["profiles"]["pmp-boundary"], 1)
        self.assertIn("pmp", coverage["coverage_tags"])
        self.assertEqual(coverage["statuses"]["pass"], 1)
        self.assertTrue(out_exists)


if __name__ == "__main__":
    unittest.main()
