import json
import tempfile
import unittest
from pathlib import Path

from pmpfuzz.__main__ import build_parser, main
from pmpfuzz.schema import aggregate_results, result_to_dict, scenario_to_case_dict, write_json
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.triage import triage_run, write_report


class EngineeringCliTest(unittest.TestCase):
    def test_main_parser_accepts_required_subcommands(self):
        parser = build_parser()

        self.assertEqual(parser.parse_args(["env-check"]).command, "env-check")
        self.assertEqual(parser.parse_args(["gen", "--out", "out"]).command, "gen")
        self.assertEqual(parser.parse_args(["run", "--out", "out"]).command, "run")
        self.assertEqual(parser.parse_args(["triage", "--run-dir", "out"]).command, "triage")
        self.assertEqual(parser.parse_args(["report", "--run-dir", "out"]).command, "report")
        self.assertEqual(parser.parse_args(["coverage", "--run-dir", "out"]).command, "coverage")
        self.assertEqual(
            parser.parse_args(["schedule", "--from-runs", "seed", "--out", "next"]).command,
            "schedule",
        )
        self.assertEqual(
            parser.parse_args(
                ["schedule", "--from-runs", "seed", "--out", "next", "--coverage-mode", "pairwise"]
            ).coverage_mode,
            "pairwise",
        )
        self.assertEqual(
            parser.parse_args(["gen", "--out", "out", "--profiles", "legacy-data,pmp-boundary"]).profiles,
            "legacy-data,pmp-boundary",
        )
        self.assertEqual(
            parser.parse_args(["gen", "--schedule", "schedule.json", "--out", "out"]).schedule,
            Path("schedule.json"),
        )
        self.assertEqual(
            parser.parse_args(["run", "--schedule", "schedule.json", "--out", "out"]).schedule,
            Path("schedule.json"),
        )
        self.assertEqual(
            parser.parse_args(["run", "--dut", "cva6-clean", "--out", "out"]).dut,
            "cva6-clean",
        )

    def test_gen_command_writes_case_json_and_assembly(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = main(["gen", "--profile", "legacy-data", "--count", "2", "--out", tmp, "--no-smepmp"])

            case_dir = Path(tmp) / "cases" / "scenario_0000"
            case = json.loads((case_dir / "case.json").read_text(encoding="ascii"))

        self.assertEqual(rc, 0)
        self.assertEqual(case["profile"], "legacy-data")
        self.assertTrue((case_dir / "scenario_0000.S").name.endswith(".S"))

    def test_gen_profiles_writes_unique_cases_with_coverage_tags(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = main(
                [
                    "gen",
                    "--profiles",
                    "pmp-boundary,sv39-perm-matrix,sv39-ptw-pmp-matrix",
                    "--count",
                    "2",
                    "--out",
                    tmp,
                    "--no-smepmp",
                ]
            )

            case_dirs = sorted((Path(tmp) / "cases").iterdir())
            cases = [json.loads((case_dir / "case.json").read_text(encoding="ascii")) for case_dir in case_dirs]

        self.assertEqual(rc, 0)
        self.assertEqual(len(cases), 6)
        self.assertEqual(len({case["name"] for case in cases}), 6)
        self.assertEqual({case["schema_version"] for case in cases}, {2})
        self.assertTrue(all(case["coverage_tags"] for case in cases))
        self.assertEqual(
            {case["profile"] for case in cases},
            {"pmp-boundary", "sv39-perm-matrix", "sv39-ptw-pmp-matrix"},
        )

    def test_schema_and_triage_group_nonpass_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=1, include_smepmp=False, profile="legacy-data").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=1, index=0)
            result = result_to_dict(
                case=case,
                dut="boom-clean",
                status="fail",
                elapsed_seconds=0.1,
                returncode=2,
                log=run_dir / "results" / "scenario_0000" / "case.log",
                reason="test",
                observed_tohost=123,
                observed_mcause=5,
                observed_mtval=0x8000,
                failure_class="wrong_mcause",
            )
            write_json(run_dir / "results" / "scenario_0000" / "result.json", result)

            aggregate = aggregate_results(run_dir)
            triage = triage_run(run_dir)
            report_path = write_report(run_dir)
            report_text = report_path.read_text(encoding="ascii")

        self.assertEqual(aggregate["nonpass"], 1)
        self.assertEqual(triage["group_count"], 1)
        self.assertIn("PMP Fuzz Report", report_text)
        self.assertIn("Security Verdict", report_text)

    def test_gen_command_accepts_schedule_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            schedule = {
                "schema_version": 1,
                "target": "core-stateful",
                "seed": 20260628,
                "include_smepmp": False,
                "entries": [
                    {
                        "profile": "pmp-boundary",
                        "index": 0,
                        "name": "pmp-boundary__scenario_0000",
                        "seed": 20260628,
                        "include_smepmp": False,
                        "semantic_bins": ["profile=pmp-boundary"],
                        "covers_missing_bins": ["profile=pmp-boundary"],
                        "reason": "test",
                    }
                ],
            }
            write_json(root / "schedule.json", schedule)

            rc = main(["gen", "--schedule", str(root / "schedule.json"), "--out", str(root / "generated")])
            case = json.loads(
                (root / "generated" / "cases" / "pmp-boundary__scenario_0000" / "case.json").read_text(
                    encoding="ascii"
                )
            )

        self.assertEqual(rc, 0)
        self.assertEqual(case["name"], "pmp-boundary__scenario_0000")
        self.assertIn("profile=pmp-boundary", case["semantic_bins"])
        self.assertTrue(case["combo_bins"])

    def test_report_includes_combination_coverage_guidance(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=71, include_smepmp=False, profile="pmp-boundary").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=71, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            report_path = write_report(run_dir)
            report_text = report_path.read_text(encoding="ascii")

        self.assertIn("Combination Coverage Guidance", report_text)
        self.assertIn("Pairwise combo coverage", report_text)


if __name__ == "__main__":
    unittest.main()
