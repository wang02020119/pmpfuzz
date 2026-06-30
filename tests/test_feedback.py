import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from pmpfuzz.__main__ import main
from pmpfuzz.feedback import build_feedback_schedule, extract_behavior_signals, load_external_signals, write_feedback
from pmpfuzz.schema import result_to_dict, scenario_to_case_dict, write_json
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.triage import write_report


class BehaviorFeedbackTest(unittest.TestCase):
    def test_extracts_differential_boom_pipeline_hung_signal(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            case = _write_boom_ptw_diff_run(run_dir)

            signals = extract_behavior_signals([run_dir])

        self.assertTrue(signals)
        signal = signals[0]
        self.assertEqual(signal["provider"], "behavior")
        self.assertEqual(signal["kind"], "differential_failure")
        self.assertEqual(signal["case"], case["name"])
        self.assertEqual(signal["dut"], "boom-clean")
        self.assertEqual(signal["features"]["failure_class"], "pipeline_hung")
        self.assertEqual(signal["features"]["profile"], "boom-ptw-pmp-regression")
        self.assertGreaterEqual(signal["weight"], 100)

    def test_feedback_schedule_prioritizes_ptw_pmp_neighborhood(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            _write_boom_ptw_diff_run(run_dir)

            first = build_feedback_schedule([run_dir], max_cases=8, seed=20260629)
            second = build_feedback_schedule([run_dir], max_cases=8, seed=20260629)

        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], 3)
        self.assertEqual(first["guidance_mode"], "behavior")
        self.assertTrue(first["entries"])
        entry = first["entries"][0]
        self.assertEqual(entry["guidance_mode"], "behavior")
        self.assertEqual(entry["source_signal"]["kind"], "differential_failure")
        self.assertEqual(entry["mutation_strategy"], "ptw-pmp-neighborhood")
        self.assertTrue(entry["mutation_ops"])
        self.assertGreater(entry["score"], 0)
        self.assertTrue(
            any(
                item["profile"] == "boom-ptw-pmp-regression" and item["index"] in {1, 2, 3, 4, 5}
                for item in first["entries"]
            )
        )

    def test_whitebox_signal_placeholder_is_loaded_but_not_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            signal_file = Path(tmp) / "whitebox_signals.json"
            write_json(
                signal_file,
                {
                    "schema_version": 1,
                    "signals": [
                        {
                            "provider": "whitebox",
                            "kind": "rtl_branch_edge",
                            "case": "scenario_0000",
                            "dut": "boom-clean",
                            "weight": 10,
                            "features": {"edge": "tlb.refill"},
                            "evidence": {"source": "future-trace"},
                        }
                    ],
                },
            )

            signals = load_external_signals([signal_file])

        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["provider"], "whitebox")
        self.assertEqual(signals[0]["kind"], "rtl_branch_edge")

    def test_gen_accepts_behavior_schedule_v3_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "run"
            _write_boom_ptw_diff_run(run_dir)
            schedule_path = write_feedback([run_dir], max_cases=4, seed=20260629, out_dir=root / "feedback")

            rc = main(["gen", "--schedule", str(schedule_path), "--out", str(root / "generated")])
            generated_cases = sorted((root / "generated" / "cases").glob("*/case.json"))

        self.assertEqual(rc, 0)
        self.assertEqual(len(generated_cases), 4)

    def test_report_includes_behavior_feedback_guidance(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            _write_boom_ptw_diff_run(run_dir)

            report_path = write_report(run_dir)
            report_text = report_path.read_text(encoding="ascii")

        self.assertIn("Behavior Feedback Guidance", report_text)
        self.assertIn("Suggested feedback scheduler", report_text)
        self.assertIn("differential_failure", report_text)

    def test_feedback_schedule_generates_smepmp_neighborhood(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=17, include_smepmp=True, profile="smepmp-mmwp-mmode-default-deny").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=17, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)
            for dut, status, failure_class in [
                ("spike", "pass", None),
                ("boom-clean", "fail", "unexpected_no_trap"),
            ]:
                _write_result(
                    run_dir,
                    case,
                    dut=dut,
                    status=status,
                    failure_class=failure_class,
                    reason=failure_class,
                )

            schedule = build_feedback_schedule([run_dir], max_cases=6, seed=20260630, include_experimental=True)

        self.assertTrue(schedule["entries"])
        self.assertTrue(all("smepmp" in entry["profile"] for entry in schedule["entries"]))
        self.assertEqual(schedule["entries"][0]["mutation_strategy"], "smepmp-permission-neighborhood")
        self.assertTrue(any(op.startswith("set-mseccfg-") for op in schedule["entries"][0]["mutation_ops"]))

    def test_whitebox_itlb_signal_generates_xiangshan_ptw_neighborhood(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "run"
            scenario = ScenarioGenerator(seed=19, include_smepmp=False, profile="xiangshan-itlb-stale-pmp").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=19, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)
            _write_result(run_dir, case, dut="xiangshan-clean", status="pass", failure_class=None)
            signal_file = root / "whitebox_signals.json"
            write_json(
                signal_file,
                {
                    "schema_version": 1,
                    "signals": [
                        {
                            "provider": "whitebox",
                            "kind": "security_perf_counter",
                            "case": case["name"],
                            "dut": "xiangshan-clean",
                            "weight": 120,
                            "features": {
                                "profile": case["profile"],
                                "privilege": case["privilege"],
                                "access": case["access"],
                                "translation": case["translation"],
                                "perf_counter": "stallCycles_fetch_icachePrefetch_itlbMiss",
                                "security_chain": "rtl-security-perf",
                                "failure_class": "pass",
                            },
                            "evidence": {"source": "unit"},
                        }
                    ],
                },
            )

            schedule = build_feedback_schedule(
                [run_dir],
                target="xiangshan-targeted",
                max_cases=4,
                seed=20260630,
                signal_files=[signal_file],
            )

        self.assertTrue(schedule["entries"])
        self.assertEqual(schedule["entries"][0]["mutation_strategy"], "ptw-pmp-neighborhood")
        self.assertIn(schedule["entries"][0]["profile"], {"xiangshan-itlb-stale-pmp", "xiangshan-ptw-pmp-depth"})

    def test_boom_ooo_ptw_hang_generates_ooo_ptw_feedback(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=23, include_smepmp=False, profile="ooo-ptw-replay-pmp-deny").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=23, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)
            _write_result(run_dir, case, dut="spike", status="pass", failure_class=None)
            _write_result(run_dir, case, dut="rocket-clean", status="pass", failure_class=None)
            _write_result(run_dir, case, dut="boom-clean", status="infra_failure", failure_class="pipeline_hung")

            schedule = build_feedback_schedule(
                [run_dir],
                target="ooo-microarchitecture",
                max_cases=4,
                seed=20260630,
            )

        self.assertTrue(schedule["entries"])
        self.assertEqual(schedule["entries"][0]["mutation_strategy"], "ptw-pmp-neighborhood")
        self.assertIn(schedule["entries"][0]["profile"], {"ooo-ptw-replay-pmp-deny", "ooo-itlb-stale-after-pmp-update", "ooo-dtlb-stale-after-pmp-update"})


def _write_boom_ptw_diff_run(run_dir: Path) -> dict:
    scenario = ScenarioGenerator(seed=20260629, include_smepmp=False, profile="boom-ptw-pmp-regression").generate_batch(1)[0]
    scenario = replace(scenario, name="boom-ptw-pmp-regression__scenario_0000")
    case = scenario_to_case_dict(scenario, seed=20260629, index=0)
    write_json(run_dir / "cases" / case["name"] / "case.json", case)
    _write_result(run_dir, case, dut="spike", status="pass", failure_class=None)
    _write_result(run_dir, case, dut="rocket-clean", status="pass", failure_class=None)
    _write_result(run_dir, case, dut="boom-clean", status="fail", failure_class="pipeline_hung", reason="Pipeline has hung")
    return case


def _write_result(
    run_dir: Path,
    case: dict,
    *,
    dut: str,
    status: str,
    failure_class: str | None,
    reason: str | None = None,
) -> None:
    result = result_to_dict(
        case=case,
        dut=dut,
        status=status,
        elapsed_seconds=0.1,
        returncode=0 if status == "pass" else -1,
        log=run_dir / "results" / f"{case['name']}_{dut}" / "case.log",
        reason=reason,
        observed_tohost=1 if status == "pass" else None,
        observed_mcause=None,
        observed_mtval=None,
        failure_class=failure_class,
        oracle_applicability="valid",
    )
    write_json(run_dir / "results" / f"{case['name']}_{dut}" / "result.json", result)


if __name__ == "__main__":
    unittest.main()
