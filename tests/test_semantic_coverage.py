import tempfile
import unittest
from pathlib import Path

from pmpfuzz.schema import scenario_to_case_dict, write_json
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.semantic_coverage import (
    CORE_STATEFUL_TARGET,
    build_schedule,
    combo_bins_for_case,
    combination_gap_from_runs,
    coverage_gap_from_runs,
    semantic_bins_for_case,
    write_schedule,
)


class SemanticCoverageTest(unittest.TestCase):
    def test_semantic_bins_are_stable_for_pmp_sv39_and_stateful_cases(self):
        pmp_case = scenario_to_case_dict(
            ScenarioGenerator(seed=1, include_smepmp=False, profile="pmp-boundary").generate_batch(1)[0],
            seed=1,
            index=0,
        )
        sv39_case = scenario_to_case_dict(
            ScenarioGenerator(seed=2, include_smepmp=False, profile="sv39-ptw-pmp-matrix").generate_batch(1)[0],
            seed=2,
            index=0,
        )
        stateful_case = scenario_to_case_dict(
            ScenarioGenerator(seed=3, include_smepmp=False, profile="tlb-stale-pmp").generate_batch(1)[0],
            seed=3,
            index=0,
        )

        self.assertIn("profile=pmp-boundary|priv=U|access=load", semantic_bins_for_case(pmp_case))
        self.assertIn("profile=pmp-boundary|pmp=tor", semantic_bins_for_case(pmp_case))
        self.assertIn("profile=sv39-ptw-pmp-matrix|ptw=L2", semantic_bins_for_case(sv39_case))
        self.assertIn("profile=sv39-ptw-pmp-matrix|preload=cold", semantic_bins_for_case(sv39_case))
        self.assertIn("profile=tlb-stale-pmp|mutation=pmpcfg-deny-target", semantic_bins_for_case(stateful_case))
        self.assertIn("profile=tlb-stale-pmp|fence=with-sfence", semantic_bins_for_case(stateful_case))

    def test_combo_bins_are_stable_for_pmp_sv39_ptw_and_stateful_cases(self):
        pmp_case = scenario_to_case_dict(
            ScenarioGenerator(seed=1, include_smepmp=False, profile="pmp-boundary").generate_batch(1)[0],
            seed=1,
            index=0,
        )
        ptw_case = scenario_to_case_dict(
            ScenarioGenerator(seed=2, include_smepmp=False, profile="sv39-ptw-pmp-matrix").generate_batch(1)[0],
            seed=2,
            index=0,
        )
        stateful_case = scenario_to_case_dict(
            ScenarioGenerator(seed=3, include_smepmp=False, profile="tlb-stale-pmp").generate_batch(1)[0],
            seed=3,
            index=0,
        )

        self.assertIn("combo2:profile=pmp-boundary|priv=U|access=load", combo_bins_for_case(pmp_case))
        self.assertIn("combo3:profile=pmp-boundary|priv=U|access=load|pmp=tor", combo_bins_for_case(pmp_case))
        self.assertIn(
            "combo3:profile=sv39-ptw-pmp-matrix|mxr=1|preload=cold|ptw=L2",
            combo_bins_for_case(ptw_case),
        )
        self.assertIn(
            "combo3:profile=tlb-stale-pmp|mutation=pmpcfg-deny-target|fence=with-sfence|priv=U",
            combo_bins_for_case(stateful_case),
        )

    def test_coverage_gap_reads_old_cases_and_reports_missing_bins(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=7, include_smepmp=False, profile="pmp-boundary").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=7, index=0)
            case.pop("semantic_bins", None)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            gap = coverage_gap_from_runs([run_dir], target=CORE_STATEFUL_TARGET)

        self.assertEqual(gap["schema_version"], 1)
        self.assertIn("profile=pmp-boundary|priv=U|access=load", gap["covered_bins"])
        self.assertIn("profile=ptw-stale-pmp", gap["missing_bins"])
        self.assertGreater(gap["total_target_bins"], gap["covered_target_bins"])

    def test_combination_gap_reads_old_cases_and_reports_combo_missing_bins(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=7, include_smepmp=False, profile="pmp-boundary").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=7, index=0)
            case.pop("combo_bins", None)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            gap = combination_gap_from_runs(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                coverage_mode="pairwise",
            )

        self.assertEqual(gap["schema_version"], 3)
        self.assertIn("combo2:profile=pmp-boundary|priv=U|access=load", gap["covered_combo_bins"])
        self.assertGreater(gap["total_target_combo_bins"], gap["covered_target_combo_bins"])
        self.assertTrue(gap["top_combo_gaps"])

    def test_scheduler_is_deterministic_and_prioritizes_missing_bins(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "seed"
            out_dir = Path(tmp) / "schedule"
            scenario = ScenarioGenerator(seed=11, include_smepmp=False, profile="pmp-boundary").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=11, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            first = build_schedule([run_dir], target=CORE_STATEFUL_TARGET, max_cases=8, seed=20260628)
            second = build_schedule([run_dir], target=CORE_STATEFUL_TARGET, max_cases=8, seed=20260628)
            schedule_path = write_schedule(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                max_cases=8,
                seed=20260628,
                out_dir=out_dir,
            )

            written = schedule_path.read_text(encoding="ascii")
            gap_exists = (out_dir / "coverage_gap.json").exists()

        self.assertEqual(first, second)
        self.assertEqual(len(first["entries"]), 8)
        self.assertTrue(all(entry["semantic_bins"] for entry in first["entries"]))
        self.assertTrue(all(entry["name"].startswith(entry["profile"] + "__") for entry in first["entries"]))
        self.assertTrue(gap_exists)
        self.assertIn("covers_missing_bins", written)

    def test_pairwise_scheduler_is_deterministic_and_prioritizes_combo_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "seed"
            out_dir = Path(tmp) / "schedule"
            scenario = ScenarioGenerator(seed=11, include_smepmp=False, profile="pmp-boundary").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=11, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            first = build_schedule(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                coverage_mode="pairwise",
                max_cases=8,
                seed=20260628,
            )
            second = build_schedule(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                coverage_mode="pairwise",
                max_cases=8,
                seed=20260628,
            )
            schedule_path = write_schedule(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                coverage_mode="pairwise",
                max_cases=8,
                seed=20260628,
                out_dir=out_dir,
            )
            written = schedule_path.read_text(encoding="ascii")

        self.assertEqual(first, second)
        self.assertEqual(first["coverage_mode"], "pairwise")
        self.assertEqual(len(first["entries"]), 8)
        self.assertTrue(all(entry["combo_bins"] for entry in first["entries"]))
        self.assertTrue(all(entry["covers_missing_combo_bins"] for entry in first["entries"]))
        self.assertIn("coverage_mode", written)

    def test_security_triples_scheduler_uses_high_risk_triple_bins(self):
        with tempfile.TemporaryDirectory() as tmp:
            schedule = build_schedule(
                [Path(tmp) / "empty"],
                target=CORE_STATEFUL_TARGET,
                coverage_mode="security-triples",
                max_cases=4,
                seed=20260628,
            )

        self.assertEqual(schedule["coverage_mode"], "security-triples")
        self.assertEqual(len(schedule["entries"]), 4)
        self.assertTrue(
            all(
                bin_name.startswith("combo3:")
                for entry in schedule["entries"]
                for bin_name in entry["covers_missing_combo_bins"]
            )
        )


if __name__ == "__main__":
    unittest.main()
