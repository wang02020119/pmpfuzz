import json
import tempfile
import unittest
from pathlib import Path

from pmpfuzz.capabilities import DEFAULT_CAPABILITY_SCHEMA_VERSION, capability_for_dut
from pmpfuzz.coverage import coverage_from_run, write_coverage
from pmpfuzz.schema import result_to_dict, scenario_to_case_dict, write_json
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.semantic_coverage import (
    CORE_STATEFUL_TARGET,
    XIANGSHAN_TARGETED_TARGET,
    target_profiles,
)


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

            write_json(
                run_dir / "dut_capabilities.json",
                {
                    "schema_version": 3,
                    "duts": {
                        "spike": capability_for_dut("spike", available=True),
                    },
                },
            )
            write_json(run_dir / "run.json", {"mode": "test", "dut": "spike", "isa": "rv64gc"})

            coverage = coverage_from_run(run_dir)
            out = write_coverage(run_dir)
            out_exists = out.exists()

        self.assertEqual(coverage["total_cases"], 1)
        self.assertEqual(coverage["schema_version"], 5)
        self.assertEqual(coverage["legacy_top_level_basis"], "generated_manifest")
        self.assertEqual(coverage["profiles"]["pmp-boundary"], 1)
        self.assertEqual(coverage["dut_whitebox"]["provider"], "dut-whitebox")
        self.assertIn("pmp", coverage["coverage_tags"])
        self.assertIn("combo2:profile=pmp-boundary|priv=U|access=load", coverage["combo_bins"])
        self.assertGreater(coverage["target_combo_bins"], coverage["covered_target_combo_bins"])
        self.assertEqual(coverage["statuses"]["pass"], 1)
        self.assertTrue(out_exists)

        self.assertIn("execution_coverage", coverage)
        exec_cov = coverage["execution_coverage"]
        self.assertEqual(exec_cov["coverage_model"], "execution-qualified-capability-scoped-v1")
        self.assertIn("spike", exec_cov["by_dut"])

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
        self.assertEqual(coverage["schema_version"], 5)

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


    def test_execution_fixture_with_case_result_and_capability_produces_eligible_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=100, include_smepmp=False, profile="pmp-boundary").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=100, index=0)

            expected_allowed = case["expected"]["allowed"]
            phase = "completed" if expected_allowed else "probe"
            result = result_to_dict(
                case=case,
                dut="spike",
                status="pass" if expected_allowed else "fail",
                elapsed_seconds=0.1,
                returncode=0 if expected_allowed else 1,
                log=run_dir / "results" / case["name"] / "case.log",
                reason=None,
                observed_phase=phase,
                observed_event="completion" if expected_allowed else "trap",
                observed_tohost=0 if expected_allowed else None,
                observed_mcause=None if expected_allowed else 5,
                observation_valid=True,
                stage_verified=True,
                oracle_applicability="valid",
            )
            write_json(run_dir / "cases" / case["name"] / "case.json", case)
            write_json(run_dir / "results" / case["name"] / "result.json", result)
            write_json(
                run_dir / "dut_capabilities.json",
                {
                    "schema_version": 3,
                    "duts": {"spike": capability_for_dut("spike", available=True)},
                },
            )
            write_json(run_dir / "run.json", {"mode": "test", "dut": "spike", "isa": "rv64gc"})

            coverage = coverage_from_run(run_dir)

        self.assertEqual(coverage["schema_version"], 5)
        exec_cov = coverage["execution_coverage"]
        spike = exec_cov["by_dut"]["spike"]
        self.assertTrue(spike["available"])
        self.assertGreaterEqual(spike["qualification"]["eligible_results"], 1)

    def test_repro_metadata_includes_run_json_and_dut_capabilities(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=200, include_smepmp=False, profile="pmp-boundary").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=200, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)
            result = result_to_dict(
                case=case,
                dut="spike",
                status="pass",
                elapsed_seconds=0.1,
                returncode=0,
                log=run_dir / "results" / case["name"] / "case.log",
                reason=None,
                observed_phase="probe",
                observation_valid=True,
                stage_verified=True,
                oracle_applicability="valid",
            )
            write_json(run_dir / "results" / case["name"] / "result.json", result)


            write_json(
                run_dir / "run.json",
                {
                    "mode": "repro",
                    "source_case": str(run_dir / "cases" / case["name"]),
                    "duts": ["spike"],
                    "isa": "rv64gc",
                    "no_smepmp": True,
                },
            )
            write_json(
                run_dir / "dut_capabilities.json",
                {
                    "schema_version": 3,
                    "duts": {"spike": capability_for_dut("spike", available=True)},
                },
            )

            run_json = json.loads((run_dir / "run.json").read_text(encoding="ascii"))
            caps = json.loads((run_dir / "dut_capabilities.json").read_text(encoding="ascii"))

        self.assertEqual(run_json["mode"], "repro")
        self.assertIn("spike", caps["duts"])
        self.assertEqual(caps["schema_version"], 3)

    def test_schedule_defaults_to_execution_with_explicit_manifest_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "seed"
            out_exec = Path(tmp) / "schedule_exec"
            out_manifest = Path(tmp) / "schedule_manifest"
            scenario = ScenarioGenerator(seed=11, include_smepmp=False, profile="pmp-boundary").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=11, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)
            write_json(run_dir / "dut_capabilities.json",
                       {"schema_version": 3, "duts": {"spike": capability_for_dut("spike", available=True)}})
            write_json(run_dir / "run.json", {"mode": "test", "dut": "spike", "isa": "rv64gc"})


            from pmpfuzz.semantic_coverage import build_schedule
            schedule_exec = build_schedule(
                [run_dir], target=CORE_STATEFUL_TARGET, max_cases=4, seed=20260628,
                coverage_basis="execution",
            )

            schedule_manifest = build_schedule(
                [run_dir], target=CORE_STATEFUL_TARGET, max_cases=4, seed=20260628,
                coverage_basis="manifest",
            )

        self.assertEqual(schedule_exec["coverage_basis"], "execution")
        self.assertEqual(schedule_manifest["coverage_basis"], "manifest")

    def test_spike_with_actual_isa_rv64gc_has_smepmp_unsupported(self):
        from pmpfuzz.capabilities import capability_for_dut
        cap = capability_for_dut("spike", isa="rv64gc", available=True)
        self.assertEqual(cap["isa"], "rv64gc")
        self.assertFalse(cap["supported_capabilities"]["smepmp"],
                         "rv64gc Spike must not claim Smepmp support")

    def test_spike_with_actual_isa_rv64gc_smepmp_has_smepmp_supported(self):
        from pmpfuzz.capabilities import capability_for_dut
        cap = capability_for_dut("spike", isa="rv64gc_smepmp", available=True)
        self.assertEqual(cap["isa"], "rv64gc_smepmp")
        self.assertTrue(cap["supported_capabilities"]["smepmp"],
                        "rv64gc_smepmp Spike must claim Smepmp support")


if __name__ == "__main__":
    unittest.main()
