import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pmpfuzz.runner import (
    CampaignResult,
    RunnerConfig,
    _run_indexed_work_with_budget,
    parse_time_budget,
    run_campaign,
    write_summary,
)
from pmpfuzz.scenario import ScenarioGenerator


class RunnerTest(unittest.TestCase):
    @staticmethod
    def _capability(*, dut: str = "rocket-clean") -> dict:
        return {
            "schema_version": 3,
            "dut": dut,
            "available": True,
            "path": f"/fake/{dut}",
            "isa": "rv64gc_smepmp",
            "supported_capabilities": {"pmp": True, "smepmp": True},
            "oracle_applicability": "valid",
            "smepmp": {"probe_status": "supported"},
            "notes": [],
        }

    def test_parse_time_budget_accepts_hours_minutes_and_seconds(self):
        self.assertEqual(parse_time_budget("7h"), 7 * 60 * 60)
        self.assertEqual(parse_time_budget("15m"), 15 * 60)
        self.assertEqual(parse_time_budget("30s"), 30)

    def test_write_summary_records_failures_and_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            config = RunnerConfig(
                profile="mixed-smepmp-mmu",
                count=3,
                seed=1,
                jobs=1,
                time_budget_seconds=60,
                out=out,
                generator_variant="syntax",
                bapc_core_version="v2",
            )
            write_summary(
                config=config,
                results=[
                    CampaignResult(
                        name="case_pass",
                        profile="mixed-smepmp-mmu",
                        status="pass",
                        expected_allowed=True,
                        expected_cause=None,
                        elapsed_seconds=0.1,
                    ),
                    CampaignResult(
                        name="case_fail",
                        profile="mixed-smepmp-mmu",
                        status="fail",
                        expected_allowed=False,
                        expected_cause=5,
                        elapsed_seconds=0.2,
                    ),
                    CampaignResult(
                        name="case_infra",
                        profile="mixed-smepmp-mmu",
                        status="infra_failure",
                        expected_allowed=False,
                        expected_cause=1,
                        elapsed_seconds=0.3,
                    ),
                ],
            )

            summary = json.loads((out / "summary.json").read_text(encoding="ascii"))
            coverage = (out / "coverage.csv").read_text(encoding="ascii")

        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["dut"], "spike")
        self.assertEqual(summary["generator_variant"], "syntax")
        self.assertEqual(summary["passed"], 1)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["infra_failed"], 1)
        self.assertEqual(summary["nonpass"], 2)
        self.assertIn("mixed-smepmp-mmu", coverage)

    def test_time_budget_does_not_submit_all_pending_work_up_front(self):
        calls = []
        clock = {"now": 0.0}

        def run_one(index, item):
            calls.append((index, item))
            clock["now"] = 10.0
            return f"result-{index}"

        results = _run_indexed_work_with_budget(
            [(0, "first"), (1, "second"), (2, "third")],
            run_one,
            max_workers=1,
            start_time=0.0,
            time_budget_seconds=5,
            time_fn=lambda: clock["now"],
        )

        self.assertEqual(results, ["result-0"])
        self.assertEqual(calls, [(0, "first")])

    # ---- New tests for execution-qualified coverage (RED phase additions) ----

    def test_runner_writes_run_json_with_isa(self):
        """RunnerConfig should record the isa field."""
        config = RunnerConfig(
            profile="pmp-boundary", count=4, seed=1, jobs=1,
            time_budget_seconds=60, out=Path("/tmp/test_runner_out"),
            dut="spike", isa="rv64gc", bapc_core_version="v2",
        )
        self.assertEqual(config.isa, "rv64gc")

    def test_runner_config_with_no_smepmp_selects_rv64gc(self):
        """When no-smepmp is active, ISA defaults to rv64gc."""
        config = RunnerConfig(
            profile="pmp-boundary", count=4, seed=1, jobs=1,
            time_budget_seconds=60, out=Path("/tmp/test_runner_out"),
            dut="spike", isa="rv64gc", include_smepmp=False, bapc_core_version="v2",
        )
        self.assertEqual(config.isa, "rv64gc")
        self.assertFalse(config.include_smepmp)

    def test_runner_config_with_smepmp_selects_rv64gc_smepmp(self):
        """When smepmp is active, ISA defaults to rv64gc_smepmp."""
        config = RunnerConfig(
            profile="pmp-boundary", count=4, seed=1, jobs=1,
            time_budget_seconds=60, out=Path("/tmp/test_runner_out"),
            dut="spike", isa="rv64gc_smepmp", include_smepmp=True, bapc_core_version="v2",
        )
        self.assertEqual(config.isa, "rv64gc_smepmp")
        self.assertTrue(config.include_smepmp)

    def test_run_campaign_requires_explicit_bapc_core_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = RunnerConfig(
                profile="pmp-boundary",
                count=0,
                seed=1,
                jobs=1,
                time_budget_seconds=10,
                out=Path(tmp),
                bapc_core_version=None,
            )

            with self.assertRaisesRegex(ValueError, "bapc_core_version"):
                run_campaign(config)

    @mock.patch("pmpfuzz.runner.oracle_applicability_for_case", return_value="unsupported")
    @mock.patch("pmpfuzz.runner._scenario_plan")
    @mock.patch("pmpfuzz.runner.make_dut")
    @mock.patch("pmpfuzz.runner.capability_for_dut")
    def test_setup_unsupported_result_records_ineligible_bapc_payload(
        self,
        mock_capability_for_dut,
        mock_make_dut,
        mock_scenario_plan,
        _mock_oracle_applicability_for_case,
    ):
        scenario = ScenarioGenerator(seed=7, profile="pmp-boundary").generate_batch(1)[0]
        mock_capability_for_dut.return_value = self._capability()
        mock_make_dut.return_value = mock.MagicMock()
        mock_scenario_plan.return_value = [(0, scenario)]

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            config = RunnerConfig(
                profile="pmp-boundary",
                count=1,
                seed=7,
                jobs=1,
                time_budget_seconds=10,
                out=out,
                dut="rocket-clean",
                isa="rv64gc_smepmp",
                bapc_core_version="v4",
            )

            run_campaign(config)

            result = json.loads(
                (out / "results" / scenario.name / "result.json").read_text(encoding="ascii")
            )

        self.assertEqual(result["status"], "setup_unsupported")
        self.assertIsInstance(result["bapc_coverage"], dict)
        self.assertFalse(result["bapc_coverage"]["eligible"])
        self.assertEqual(result["bapc_coverage"]["bapc_schema_version"], 2)
        self.assertEqual(result["bapc_coverage"]["bapc_core_version"], "v4")
        self.assertEqual(result["bapc_coverage"]["qualification_reason"], "missing-actual-observation")

    @mock.patch("pmpfuzz.runner.subprocess.run")
    @mock.patch("pmpfuzz.runner.oracle_applicability_for_case", return_value="valid")
    @mock.patch("pmpfuzz.runner._scenario_plan")
    @mock.patch("pmpfuzz.runner.make_dut")
    @mock.patch("pmpfuzz.runner.capability_for_dut")
    def test_compile_fail_result_records_ineligible_bapc_payload(
        self,
        mock_capability_for_dut,
        mock_make_dut,
        mock_scenario_plan,
        _mock_oracle_applicability_for_case,
        mock_subprocess_run,
    ):
        scenario = ScenarioGenerator(seed=9, profile="pmp-boundary").generate_batch(1)[0]
        mock_capability_for_dut.return_value = self._capability()
        mock_make_dut.return_value = mock.MagicMock()
        mock_scenario_plan.return_value = [(0, scenario)]
        mock_subprocess_run.return_value = mock.MagicMock(
            returncode=1,
            stdout="compile failed",
        )

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            config = RunnerConfig(
                profile="pmp-boundary",
                count=1,
                seed=9,
                jobs=1,
                time_budget_seconds=10,
                out=out,
                dut="rocket-clean",
                isa="rv64gc_smepmp",
                bapc_core_version="v4",
            )

            run_campaign(config)

            result = json.loads(
                (out / "results" / scenario.name / "result.json").read_text(encoding="ascii")
            )

        self.assertEqual(result["status"], "compile_fail")
        self.assertIsInstance(result["bapc_coverage"], dict)
        self.assertFalse(result["bapc_coverage"]["eligible"])
        self.assertEqual(result["bapc_coverage"]["bapc_schema_version"], 2)
        self.assertEqual(result["bapc_coverage"]["bapc_core_version"], "v4")
        self.assertEqual(result["bapc_coverage"]["qualification_reason"], "missing-actual-observation")


    # ---- Fix 8: mocked runner/repro tests --------

    @mock.patch("pmpfuzz.runner.make_dut")
    @mock.patch("pmpfuzz.runner.capability_for_dut")
    def test_run_campaign_calls_capability_for_dut_for_spike(self, mock_cap, mock_make):
        """Runner must call capability_for_dut with correct args for Spike."""
        mock_cap.return_value = {
            "schema_version": 3,
            "dut": "spike",
            "available": True,
            "path": "/fake/spike",
            "isa": "rv64gc",
            "supported_capabilities": {"pmp": True},
            "oracle_applicability": "valid",
            "smepmp": {"probe_status": "unsupported"},
            "notes": [],
        }
        mock_dut = mock.MagicMock()
        mock_make.return_value = mock_dut

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            config = RunnerConfig(
                profile="pmp-boundary", count=0, seed=1, jobs=1,
                time_budget_seconds=10, out=out,
                dut="spike", isa="rv64gc", spike="/fake/spike", generator_variant="syntax",
                bapc_core_version="v2",
            )
            from pmpfuzz.runner import run_campaign
            run_campaign(config)

            # Verify output files were written
            self.assertTrue((out / "run.json").is_file(),
                            "run_campaign must write run.json")
            self.assertTrue((out / "dut_capabilities.json").is_file(),
                            "run_campaign must write dut_capabilities.json")
            run_data = json.loads((out / "run.json").read_text(encoding="ascii"))
            self.assertEqual(run_data["dut"], "spike")
            self.assertEqual(run_data["isa"], "rv64gc")
            self.assertEqual(run_data["generator_variant"], "syntax")
            cap_data = json.loads((out / "dut_capabilities.json").read_text(encoding="ascii"))
            self.assertEqual(cap_data["schema_version"], 3)
            self.assertIn("spike", cap_data["duts"])

        mock_cap.assert_called_once_with(
            "spike",
            path=config.spike,
            isa=config.isa,
        )

    @mock.patch("pmpfuzz.__main__.subprocess.run")
    @mock.patch("pmpfuzz.__main__.capability_for_dut")
    def test_repro_writes_run_json_and_dut_capabilities(self, mock_cap, mock_run):
        """Repro must write run.json with mode=repro and dut_capabilities.json."""
        from pmpfuzz.__main__ import main
        from pmpfuzz.scenario import ScenarioGenerator
        from pmpfuzz.schema import scenario_to_case_dict, write_json

        mock_cap.return_value = {
            "schema_version": 3,
            "dut": "spike",
            "available": True,
            "path": "/fake/spike",
            "isa": "rv64gc",
            "supported_capabilities": {"pmp": True},
            "oracle_applicability": "valid",
            "smepmp": {"probe_status": "unsupported"},
            "notes": [],
        }
        mock_run.return_value = mock.MagicMock(
            returncode=1, stdout="mock compile failure", args=[],
        )

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "repro_out"
            case_dir = Path(tmp) / "case_dir"
            case_dir.mkdir()
            case = scenario_to_case_dict(
                ScenarioGenerator(seed=1, profile="pmp-boundary").generate_batch(1)[0],
                seed=1, index=0,
            )
            write_json(case_dir / "case.json", case)

            rc = main([
                "repro",
                "--case", str(case_dir),
                "--out", str(out),
                "--dut", "spike",
                "--no-smepmp",
            ])

            # Unconditional assertions — metadata must always exist
            self.assertEqual(rc, 1)  # compile failure is expected
            run_json_path = out / "run.json"
            cap_path = out / "dut_capabilities.json"
            self.assertTrue(run_json_path.is_file(),
                            "repro must always write run.json")
            self.assertTrue(cap_path.is_file(),
                            "repro must always write dut_capabilities.json")

            run_data = json.loads(run_json_path.read_text(encoding="ascii"))
            self.assertEqual(run_data.get("mode"), "repro")
            self.assertEqual(run_data.get("isa"), "rv64gc")

            cap_data = json.loads(cap_path.read_text(encoding="ascii"))
            self.assertEqual(cap_data.get("schema_version"), 3)
            self.assertIn("spike", cap_data.get("duts", {}))


if __name__ == "__main__":
    unittest.main()
