import tempfile
import unittest
from pathlib import Path

from pmpfuzz.__main__ import _write_observed_whitebox_outputs
from pmpfuzz.__main__ import main
from pmpfuzz.coverage import coverage_from_run
from pmpfuzz.dut_coverage import (
    dut_coverage_from_run,
    dut_coverage_matrix_from_runs,
    write_dut_coverage,
    write_dut_coverage_matrix,
)
from pmpfuzz.schema import result_to_dict, scenario_to_case_dict, write_json
from pmpfuzz.scenario import ScenarioGenerator


class DutWhiteboxCoverageTest(unittest.TestCase):
    def test_dut_coverage_normalizes_real_whitebox_signals_into_bins(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _write_case_result(run_dir, dut="boom-clean")
            log = run_dir / "results" / case["name"] / "scenario.log"
            log.write_text(
                "PMFUZZ_PROBE dut=boom-clean probe=ptw_pmp_check chain=sv39-ptw-pmp "
                "stage=ptw level=L1 paddr=0x80014000 allow=0 match=3 cause=5\n"
                "[PERF ][time=10] SimTop.cpu.l2tlb: PTW_refill,                    3\n",
                encoding="ascii",
            )

            coverage = dut_coverage_from_run(run_dir)

        keys = {item["key"] for item in coverage["top_bins"]}
        self.assertEqual(coverage["schema_version"], 1)
        self.assertEqual(coverage["provider"], "dut-whitebox")
        self.assertEqual(coverage["coverage_model"], "observed-dut-whitebox-v1")
        self.assertTrue(coverage["targetless"])
        self.assertGreaterEqual(coverage["input_signal_count"], 2)
        self.assertGreater(coverage["covered_bins"], 0)
        self.assertIn("boom-clean", coverage["by_dut"])
        self.assertIn("dut=boom-clean|chain=sv39-ptw-pmp|kind=source_probe", keys)
        self.assertIn("chain=sv39-ptw-pmp|stage=ptw|allow=denied", keys)
        self.assertIn("dut=boom-clean|perf_counter=PTW_refill", keys)

    def test_write_dut_coverage_and_embed_in_campaign_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _write_case_result(run_dir)
            (run_dir / "results" / case["name"] / "scenario.log").write_text(
                "COVERAGE: PMP_PTW_DENY, 8, 1, 1\n",
                encoding="ascii",
            )

            out = write_dut_coverage(run_dir)
            campaign_coverage = coverage_from_run(run_dir)
            out_exists = out.exists()

        self.assertTrue(out_exists)
        self.assertEqual(campaign_coverage["schema_version"], 4)
        self.assertGreater(campaign_coverage["dut_whitebox"]["covered_bins"], 0)
        self.assertIn("security_coverage_point", campaign_coverage["dut_whitebox"]["by_kind"])

    def test_dut_coverage_cli_writes_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            out_dir = Path(tmp) / "out"
            case = _write_case_result(run_dir)
            (run_dir / "results" / case["name"] / "scenario.log").write_text(
                "[PERF ][time=10] SimTop.cpu.l2tlb: PTW_refill, 1\n",
                encoding="ascii",
            )

            rc = main(["dut-coverage", "--run-dir", str(run_dir), "--out", str(out_dir)])
            out_exists = (out_dir / "dut_coverage.json").exists()

        self.assertEqual(rc, 0)
        self.assertTrue(out_exists)

    def test_observed_whitebox_outputs_write_signals_and_dut_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _write_case_result(run_dir)
            (run_dir / "results" / case["name"] / "scenario.log").write_text(
                "[PERF ][time=10] SimTop.cpu.l2tlb: PTW_refill, 1\n",
                encoding="ascii",
            )

            signal_path, coverage_path = _write_observed_whitebox_outputs(run_dir)
            signal_exists = signal_path.exists()
            coverage_exists = coverage_path.exists()

        self.assertTrue(signal_exists)
        self.assertTrue(coverage_exists)

    def test_dut_coverage_matrix_reports_cross_dut_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            boom_run = root / "boom"
            rocket_run = root / "rocket"
            cva6_run = root / "cva6"
            boom_case = _write_case_result(boom_run, dut="boom-clean")
            rocket_case = _write_case_result(rocket_run, dut="rocket-clean")
            _write_case_result(cva6_run, dut="cva6-clean")
            (boom_run / "results" / boom_case["name"] / "scenario.log").write_text(
                "PMFUZZ_PROBE dut=boom-clean probe=ptw_pmp_check chain=sv39-ptw-pmp "
                "stage=ptw level=L1 paddr=0x80014000 allow=0 match=3 cause=5\n"
                "[PERF ][time=10] SimTop.cpu.l2tlb: PTW_refill, 1\n",
                encoding="ascii",
            )
            (rocket_run / "results" / rocket_case["name"] / "scenario.log").write_text(
                "PMFUZZ_PROBE dut=rocket-clean probe=ptw_pmp_check chain=sv39-ptw-pmp "
                "stage=ptw level=L1 paddr=0x80014000 allow=0 match=3 cause=5\n",
                encoding="ascii",
            )

            matrix = dut_coverage_matrix_from_runs([boom_run, rocket_run, cva6_run])
            out = write_dut_coverage_matrix([boom_run, rocket_run, cva6_run], out_dir=root / "matrix")
            cli_rc = main(
                [
                    "dut-coverage-matrix",
                    "--from-runs",
                    f"{boom_run},{rocket_run},{cva6_run}",
                    "--out",
                    str(root / "matrix_cli"),
                ]
            )
            matrix_written = out.exists()
            cli_written = (root / "matrix_cli" / "dut_coverage_matrix.json").exists()

        rows = {row["key"]: row for row in matrix["matrix"]}
        self.assertEqual(matrix["schema_version"], 1)
        self.assertEqual(matrix["coverage_model"], "observed-dut-whitebox-matrix-v1")
        self.assertEqual(matrix["duts"], ["boom-clean", "cva6-clean", "rocket-clean"])
        self.assertEqual(rows["chain=sv39-ptw-pmp|stage=ptw|allow=denied"]["coverage_rate"], 0.6667)
        self.assertEqual(rows["chain=sv39-ptw-pmp|stage=ptw|allow=denied"]["missing_duts"], ["cva6-clean"])
        self.assertEqual(rows["perf_counter=PTW_refill"]["covered_duts"], ["boom-clean"])
        self.assertEqual(rows["perf_counter=PTW_refill"]["missing_duts"], ["cva6-clean", "rocket-clean"])
        self.assertEqual(matrix["per_dut"]["cva6-clean"]["covered_bins"], 0)
        self.assertLess(matrix["per_dut"]["rocket-clean"]["coverage_rate"], matrix["per_dut"]["boom-clean"]["coverage_rate"])
        self.assertTrue(matrix_written)
        self.assertEqual(cli_rc, 0)
        self.assertTrue(cli_written)


def _write_case_result(run_dir: Path, *, dut: str = "xiangshan-clean") -> dict:
    scenario = ScenarioGenerator(seed=20260709, include_smepmp=False, profile="boom-ptw-pmp-regression").generate_batch(1)[0]
    case = scenario_to_case_dict(scenario, seed=20260709, index=0)
    write_json(run_dir / "cases" / case["name"] / "case.json", case)
    result = result_to_dict(
        case=case,
        dut=dut,
        status="pass",
        elapsed_seconds=0.1,
        returncode=0,
        log=run_dir / "results" / case["name"] / "scenario.log",
        reason=None,
        failure_class=None,
        oracle_applicability="valid",
    )
    write_json(run_dir / "results" / case["name"] / "result.json", result)
    return case


if __name__ == "__main__":
    unittest.main()
