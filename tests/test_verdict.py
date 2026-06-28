import tempfile
import unittest
from pathlib import Path

from pmpfuzz.schema import result_to_dict, scenario_to_case_dict, write_json
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.verdict import verdict_for_run


class VerdictTest(unittest.TestCase):
    def test_boom_ptw_pmp_hang_is_confirmed_new_failure_mode_with_spike_rocket_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=1, include_smepmp=False, profile="boom-ptw-pmp-regression").generate_batch(1)[
                0
            ]
            case = scenario_to_case_dict(scenario, seed=1, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            for dut, status, failure_class in [
                ("spike", "pass", None),
                ("rocket-clean", "pass", None),
                ("boom-clean", "infra_failure", "pipeline_hung"),
            ]:
                write_json(
                    run_dir / "results" / f"{case['name']}_{dut}" / "result.json",
                    result_to_dict(
                        case=case,
                        dut=dut,
                        status=status,
                        elapsed_seconds=0.1,
                        returncode=0 if status == "pass" else 1,
                        log=run_dir / "results" / f"{case['name']}_{dut}" / "case.log",
                        reason=None if status == "pass" else "Pipeline has hung",
                        failure_class=failure_class,
                    ),
                )

            verdict = verdict_for_run(run_dir)

        self.assertTrue(verdict["has_vulnerability"])
        self.assertEqual(verdict["verdict"], "confirmed_new_failure_mode")
        self.assertEqual(verdict["impact"], "denial_of_service / missing_precise_trap")
        self.assertIn(case["name"], verdict["evidence"][0]["case"])


if __name__ == "__main__":
    unittest.main()
