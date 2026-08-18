import csv
import json
import tempfile
import unittest
from pathlib import Path

from pmpfuzz.bapc import build_bapc_coverage_universe
from scripts.evaluation.analysis.aggregate_results import aggregate
from tests.test_bapc_analysis import _make_bapc_campaign, _write_json, _write_jsonl


def _read_jsonl(path: Path) -> list[dict]:
    raw = path.read_text(encoding="ascii").strip()
    if not raw:
        return []
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def _pick_family_bin(universe: dict, family: str) -> str:
    for bin_id in universe["bin_ids"]:
        if str(bin_id).startswith(f"family={family}|"):
            return str(bin_id)
    raise AssertionError(f"missing family {family} in universe")


class BapcAggregateGateTest(unittest.TestCase):
    def test_coverage_final_exports_generator_variant_and_explicit_bapc_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = build_bapc_coverage_universe(
                dut="rocket-clean",
                generator_seed=1,
                supports_fault_stage=True,
                supports_smepmp=False,
                bapc_core_version="v4",
            )
            covered_bin = _pick_family_bin(universe, "config")
            campaign = _make_bapc_campaign(
                root,
                seed=1,
                universe=universe,
                covered_bins=[covered_bin],
                universe_filename="bapc_v4.json",
            )

            metadata_path = campaign / "metrics" / "campaign_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
            metadata["generator_variant"] = "syntax"
            _write_json(metadata_path, metadata)

            aggregate(root, "exp")

            with (root / "aggregate" / "coverage_final.csv").open(encoding="ascii", newline="") as handle:
                rows = list(csv.DictReader(handle))
            with (root / "aggregate" / "campaign_index.csv").open(encoding="ascii", newline="") as handle:
                campaign_rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["generator_variant"], "syntax")
        self.assertEqual(rows[0]["covered_bin_count"], "1")
        self.assertEqual(rows[0]["coverage_denominator"], str(universe["bin_count"]))
        self.assertEqual(campaign_rows[0]["generator_variant"], "syntax")
        self.assertEqual(campaign_rows[0]["bapc_target"], str(universe["bin_count"]))

    def test_coverage_final_filters_bapc_on_eligible_bapc_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = build_bapc_coverage_universe(
                dut="rocket-clean",
                generator_seed=1,
                supports_fault_stage=True,
                supports_smepmp=False,
            )
            eligible_bin = _pick_family_bin(universe, "config")
            _make_bapc_campaign(root, seed=1, universe=universe, covered_bins=[eligible_bin], universe_filename="bapc_v4.json")
            ineligible_campaign = _make_bapc_campaign(root, seed=2, universe=universe, covered_bins=[], universe_filename="bapc_v4.json")
            timeline_path = ineligible_campaign / "metrics" / "coverage_timeline.jsonl"
            timeline = _read_jsonl(timeline_path)
            timeline[1].update({
                "coverage_eligible": False,
                "bapc_eligible": False,
                "eligible_cases": 1,
                "eligible_bapc_cases": 0,
                "qualification_reason": "oracle_capability_dependent",
                "bapc_covered": 0,
                "bapc_rate": 0.0,
                "new_bapc_bins": 0,
            })
            _write_jsonl(timeline_path, timeline)

            aggregate(root, "exp")

            with (root / "aggregate" / "coverage_final.csv").open(encoding="ascii", newline="") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["campaign_id"], "camp-1")
        self.assertEqual(rows[0]["eligible_cases"], "1")
        self.assertEqual(rows[0]["eligible_bapc_cases"], "1")
        self.assertEqual(rows[0]["effective_eligible_cases"], "1")

    def test_coverage_timeseries_exports_dual_eligible_counters_for_bapc(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = build_bapc_coverage_universe(
                dut="rocket-clean",
                generator_seed=1,
                supports_fault_stage=True,
                supports_smepmp=False,
            )
            covered_bin = _pick_family_bin(universe, "config")
            _make_bapc_campaign(root, seed=1, universe=universe, covered_bins=[covered_bin], universe_filename="bapc_v4.json")

            aggregate(root, "exp")

            with (root / "aggregate" / "coverage_timeseries.csv").open(encoding="ascii", newline="") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 1)
        self.assertIn("eligible_bapc_cases", rows[0])
        self.assertIn("eligible_hpm_cases", rows[0])
        self.assertEqual(rows[0]["eligible_cases"], "1")
        self.assertEqual(rows[0]["eligible_bapc_cases"], "1")
        self.assertEqual(rows[0]["coverage_mode"], "bapc")

    def test_aggregate_exports_bapc_family_and_qualification_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = build_bapc_coverage_universe(
                dut="rocket-clean",
                generator_seed=1,
                supports_fault_stage=True,
                supports_smepmp=False,
            )
            covered_bins = [
                _pick_family_bin(universe, "config"),
                _pick_family_bin(universe, "stimulus"),
                _pick_family_bin(universe, "decision"),
            ]
            campaign = _make_bapc_campaign(root, seed=1, universe=universe, covered_bins=covered_bins, universe_filename="bapc_v4.json")

            coverage_path = campaign / "coverage" / "coverage.json"
            coverage = json.loads(coverage_path.read_text(encoding="ascii"))
            coverage["bapc_bins"] = list(covered_bins)
            coverage["covered_target_bapc_bins"] = len(covered_bins)
            coverage["target_bapc_bins"] = universe["bin_count"]
            _write_json(coverage_path, coverage)

            timeline_path = campaign / "metrics" / "coverage_timeline.jsonl"
            timeline = _read_jsonl(timeline_path)
            timeline[1].update({
                "case_id": "case-1-ineligible",
                "coverage_eligible": False,
                "bapc_eligible": False,
                "eligible_cases": 1,
                "eligible_bapc_cases": 0,
                "qualification_reason": "oracle_capability_dependent",
                "bapc_covered": 0,
                "bapc_rate": 0.0,
                "new_bapc_bins": 0,
            })
            timeline.append({
                **timeline[1],
                "completion_seq": 2,
                "case_id": "case-1-eligible",
                "elapsed_wall_seconds": 2.0,
                "completed_cases": 2,
                "eligible_cases": 2,
                "eligible_bapc_cases": 1,
                "coverage_eligible": True,
                "bapc_eligible": True,
                "qualification_reason": "eligible",
                "bapc_covered": len(covered_bins),
                "bapc_rate": len(covered_bins) / universe["bin_count"],
                "new_bapc_bins": len(covered_bins),
                "last_bapc_novelty_time": 2.0,
            })
            _write_jsonl(timeline_path, timeline)

            aggregate(root, "exp")

            with (root / "aggregate" / "bapc_family_coverage.csv").open(encoding="ascii", newline="") as handle:
                family_rows = list(csv.DictReader(handle))
            with (root / "aggregate" / "bapc_qualification_reason_distribution.csv").open(encoding="ascii", newline="") as handle:
                reason_rows = list(csv.DictReader(handle))

        self.assertEqual(len(family_rows), 1)
        family = family_rows[0]
        self.assertEqual(family["config_covered"], "1")
        self.assertEqual(family["stimulus_covered"], "1")
        self.assertEqual(family["decision_covered"], "1")
        self.assertEqual(family["eligible_cases"], "2")
        self.assertEqual(family["eligible_bapc_cases"], "1")

        reason_counts = {row["qualification_reason"]: int(row["count"]) for row in reason_rows}
        self.assertEqual(reason_counts["oracle_capability_dependent"], 1)
        self.assertEqual(reason_counts["eligible"], 1)


if __name__ == "__main__":
    unittest.main()
