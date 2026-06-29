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

    def test_boom_pmp_na4_fetch_failure_is_confirmed_with_spike_rocket_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=20260629, include_smepmp=False, profile="pmp-boundary").generate_batch(19)[18]
            case = scenario_to_case_dict(scenario, seed=20260629, index=18)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            for dut, status, failure_class, observed_tohost in [
                ("spike", "pass", None, None),
                ("rocket-clean", "pass", None, None),
                ("boom-clean", "fail", "sim_assert", 32768),
            ]:
                write_json(
                    run_dir / "results" / f"{case['name']}_{dut}" / "result.json",
                    result_to_dict(
                        case=case,
                        dut=dut,
                        status=status,
                        elapsed_seconds=0.1,
                        returncode=0 if status == "pass" else 2,
                        log=run_dir / "results" / f"{case['name']}_{dut}" / "case.log",
                        reason=None if status == "pass" else "chipyard simulator reported failure",
                        failure_class=failure_class,
                        observed_tohost=observed_tohost,
                    ),
                )

            verdict = verdict_for_run(run_dir)

        self.assertTrue(verdict["has_vulnerability"])
        self.assertEqual(verdict["verdict"], "confirmed_pmp_fetch_boundary_failure")
        self.assertEqual(verdict["impact"], "denial_of_service / incorrect_execute_permission_handling")
        self.assertIn(case["name"], verdict["evidence"][0]["case"])

    def test_stateful_side_effect_failure_is_confirmed_vulnerability(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=7, include_smepmp=False, profile="pmp-side-effect").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=7, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            for dut, status, failure_class in [
                ("spike", "pass", None),
                ("rocket-clean", "fail", "forbidden_side_effect"),
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
                        reason=failure_class,
                        failure_class=failure_class,
                    ),
                )

            verdict = verdict_for_run(run_dir)

        self.assertTrue(verdict["has_vulnerability"])
        self.assertEqual(verdict["verdict"], "confirmed_side_effect_failure")

    def test_no_fence_stale_permission_is_experimental_not_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=11, include_smepmp=False, profile="tlb-stale-pte").generate_batch(2)[1]
            case = scenario_to_case_dict(scenario, seed=11, index=1)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)
            write_json(
                run_dir / "results" / f"{case['name']}_rocket-clean" / "result.json",
                result_to_dict(
                    case=case,
                    dut="rocket-clean",
                    status="fail",
                    elapsed_seconds=0.1,
                    returncode=1,
                    log=run_dir / "results" / f"{case['name']}_rocket-clean" / "case.log",
                    reason="stale no-fence observation",
                    failure_class="stale_tlb_permission",
                ),
            )

            verdict = verdict_for_run(run_dir)

        self.assertFalse(verdict["has_vulnerability"])
        self.assertEqual(verdict["verdict"], "experimental_no_fence_observation")


if __name__ == "__main__":
    unittest.main()
