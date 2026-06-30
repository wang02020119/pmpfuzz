import tempfile
import unittest
from pathlib import Path

from pmpfuzz.__main__ import main
from pmpfuzz.feedback import build_feedback_schedule
from pmpfuzz.schema import result_to_dict, scenario_to_case_dict, write_json
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.whitebox import extract_security_whitebox_signals, write_whitebox_signals


class SecurityWhiteboxSignalsTest(unittest.TestCase):
    def test_extracts_ptw_pmp_footprint_signal(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _write_case_result(run_dir, profile="boom-ptw-pmp-regression")
            denied_ptw = _first_denied_ptw_address(case)
            footprint = run_dir / "results" / case["name"] / "xiangshan.footprints"
            footprint.write_text(f"load {denied_ptw}\n", encoding="ascii")

            payload = extract_security_whitebox_signals(run_dir)

        signals = payload["signals"]
        self.assertTrue(signals)
        signal = signals[0]
        self.assertEqual(signal["provider"], "whitebox")
        self.assertEqual(signal["kind"], "ptw_pmp_footprint")
        self.assertEqual(signal["case"], case["name"])
        self.assertEqual(signal["features"]["security_chain"], "sv39-ptw-pmp")
        self.assertEqual(signal["features"]["pmp_stage"], "ptw")
        self.assertEqual(signal["features"]["ptw_level"], "L1")
        self.assertFalse(signal["features"]["pmp_allowed"])

    def test_extracts_forbidden_side_effect_footprint_signal(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _write_case_result(run_dir, profile="pmp-side-effect")
            footprint = run_dir / "results" / case["name"] / "mem.footprints"
            footprint.write_text(f"store {case['physical_address']}\n", encoding="ascii")

            payload = extract_security_whitebox_signals(run_dir)

        signal = payload["signals"][0]
        self.assertEqual(signal["kind"], "forbidden_side_effect_footprint")
        self.assertEqual(signal["features"]["security_chain"], "pmp-side-effect")
        self.assertEqual(signal["features"]["access"], "store")
        self.assertEqual(signal["features"]["address"], case["physical_address"])
        self.assertGreaterEqual(signal["weight"], 80)

    def test_whitebox_cli_writes_feedback_compatible_signal_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            out_dir = Path(tmp) / "whitebox_out"
            case = _write_case_result(run_dir, profile="boom-ptw-pmp-regression")
            denied_ptw = _first_denied_ptw_address(case)
            (run_dir / "results" / case["name"] / "trace.footprints").write_text(
                f"ptw-read {denied_ptw}\n",
                encoding="ascii",
            )

            rc = main(["whitebox", "--run-dir", str(run_dir), "--out", str(out_dir)])

            self.assertEqual(rc, 0)
            signal_file = out_dir / "whitebox_signals.json"
            self.assertTrue(signal_file.exists())
            schedule = build_feedback_schedule(
                [run_dir],
                max_cases=4,
                seed=20260629,
                signal_files=[signal_file],
            )

        self.assertTrue(schedule["entries"])
        self.assertEqual(schedule["entries"][0]["source_signal"]["provider"], "whitebox")
        self.assertEqual(schedule["entries"][0]["mutation_strategy"], "ptw-pmp-neighborhood")

    def test_extracts_security_perf_counter_from_xiangshan_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _write_case_result(run_dir, profile="boom-ptw-pmp-regression")
            log = run_dir / "results" / case["name"] / "scenario.log"
            log.write_text(
                "[PERF ][time=10] SimTop.cpu.l2tlb: PTW_refill,                    3\n",
                encoding="ascii",
            )

            payload = extract_security_whitebox_signals(run_dir)

        signal = payload["signals"][0]
        self.assertEqual(signal["kind"], "security_perf_counter")
        self.assertEqual(signal["features"]["security_chain"], "rtl-security-perf")
        self.assertEqual(signal["features"]["perf_counter"], "PTW_refill")
        self.assertEqual(signal["features"]["perf_value"], 3)

    def test_write_whitebox_signals_uses_default_run_subdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _write_case_result(run_dir, profile="pmp-side-effect")
            (run_dir / "results" / case["name"] / "mem.footprints").write_text(
                f"store {case['physical_address']}\n",
                encoding="ascii",
            )

            path = write_whitebox_signals(run_dir)

        self.assertEqual(path.name, "whitebox_signals.json")
        self.assertEqual(path.parent.name, "whitebox")


def _write_case_result(run_dir: Path, *, profile: str) -> dict:
    scenario = ScenarioGenerator(seed=20260630, include_smepmp=False, profile=profile).generate_batch(1)[0]
    case = scenario_to_case_dict(scenario, seed=20260630, index=0)
    write_json(run_dir / "cases" / case["name"] / "case.json", case)
    result = result_to_dict(
        case=case,
        dut="xiangshan-clean",
        status="pass",
        elapsed_seconds=0.1,
        returncode=0,
        log=run_dir / "results" / case["name"] / "case.log",
        reason=None,
        failure_class=None,
        oracle_applicability="valid",
    )
    write_json(run_dir / "results" / case["name"] / "result.json", result)
    return case


def _first_denied_ptw_address(case: dict) -> str:
    for check in case["contract_trace"]["pmp_checks"]:
        if check["stage"] == "ptw" and not check["allowed"]:
            return check["physical_address"]
    raise AssertionError("case does not contain a denied PTW PMP check")


if __name__ == "__main__":
    unittest.main()
