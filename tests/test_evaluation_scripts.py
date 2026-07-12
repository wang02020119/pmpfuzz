"""Smoke tests for evaluation scripts (import and basic function)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.evaluation.validate_timeline import validate_timeline
from scripts.evaluation.aggregate_results import aggregate
from scripts.evaluation.plot_coverage_time import plot_from_csv


class TestValidateTimeline(unittest.TestCase):
    """Basic tests for timeline validation."""

    def test_missing_campaign(self):
        report = validate_timeline(Path("/nonexistent/campaign"))
        self.assertFalse(report["valid"])
        self.assertGreater(report["error_count"], 0)

    def test_empty_timeline(self):
        with TemporaryDirectory() as tmp:
            campaign = Path(tmp) / "camp"
            (campaign / "metrics").mkdir(parents=True)
            (campaign / "metrics" / "coverage_timeline.jsonl").write_text("", encoding="ascii")
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"])
            self.assertGreater(report["error_count"], 0)

    def test_valid_timeline_passes(self):
        with TemporaryDirectory() as tmp:
            campaign = Path(tmp) / "camp"
            (campaign / "metrics").mkdir(parents=True)
            timeline = [
                {
                    "schema_version": 1,
                    "campaign_id": "test-campaign",
                    "variant": "guided-semantic",
                    "dut": "spike",
                    "seed": 1,
                    "completion_seq": 0,
                    "case_id": None,
                    "profile": None,
                    "elapsed_wall_seconds": 0.0,
                    "case_elapsed_seconds": 0.0,
                    "completed_cases": 0,
                    "eligible_cases": 0,
                    "status": None,
                    "failure_class": None,
                    "coverage_eligible": False,
                    "qualification_reason": None,
                    "semantic_covered": 0,
                    "semantic_target": 100,
                    "semantic_rate": 0.0,
                    "pairwise_covered": 0,
                    "pairwise_target": 400,
                    "pairwise_rate": 0.0,
                    "security_triples_covered": 0,
                    "security_triples_target": 900,
                    "security_triples_rate": 0.0,
                    "predicates_covered": 0,
                    "predicates_target": 21,
                    "predicates_rate": 0.0,
                    "new_semantic_bins": 0,
                    "new_pairwise_bins": 0,
                    "new_security_triple_bins": 0,
                    "new_predicate_bins": 0,
                    "whitebox_distinct_events": 0,
                    "new_whitebox_events": 0,
                },
                {
                    "schema_version": 1,
                    "campaign_id": "test-campaign",
                    "variant": "guided-semantic",
                    "dut": "spike",
                    "seed": 1,
                    "completion_seq": 1,
                    "case_id": "case_0",
                    "profile": "pmp-boundary",
                    "elapsed_wall_seconds": 10.0,
                    "case_elapsed_seconds": 2.0,
                    "completed_cases": 1,
                    "eligible_cases": 1,
                    "status": "pass",
                    "failure_class": None,
                    "coverage_eligible": True,
                    "qualification_reason": "eligible",
                    "semantic_covered": 5,
                    "semantic_target": 100,
                    "semantic_rate": 0.05,
                    "pairwise_covered": 10,
                    "pairwise_target": 400,
                    "pairwise_rate": 0.025,
                    "security_triples_covered": 3,
                    "security_triples_target": 900,
                    "security_triples_rate": 3/900,
                    "predicates_covered": 2,
                    "predicates_target": 21,
                    "predicates_rate": 2/21,
                    "new_semantic_bins": 5,
                    "new_pairwise_bins": 10,
                    "new_security_triple_bins": 3,
                    "new_predicate_bins": 2,
                    "whitebox_distinct_events": 0,
                    "new_whitebox_events": 0,
                },
            ]
            (campaign / "metrics" / "coverage_timeline.jsonl").write_text(
                "\n".join(json.dumps(line, ensure_ascii=True, sort_keys=True) for line in timeline),
                encoding="ascii",
            )
            report = validate_timeline(campaign)
            self.assertTrue(report["valid"], f"Checks: {report['checks']}")
            self.assertEqual(report["error_count"], 0)


class TestAggregateResults(unittest.TestCase):
    """Basic tests for result aggregation."""

    def test_empty_aggregate(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "artifacts"
            root.mkdir()
            (root / "aggregate").mkdir()
            outputs = aggregate(root, "test-experiment")
            # Should produce at least statistics.json even with no data
            stats_path = root / "aggregate" / "statistics.json"
            self.assertTrue(stats_path.exists(), f"Not found: {stats_path}")
            stats = json.loads(stats_path.read_text(encoding="ascii"))
            self.assertEqual(stats["total_campaigns"], 0)


class TestPlotCoverageTime(unittest.TestCase):
    """Basic tests for plot generation."""

    def test_plot_empty_csv_returns_gracefully(self):
        """Empty CSV should return empty outputs without crashing."""
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "plots"
            csv_path = Path(tmp) / "empty.csv"
            csv_path.write_text("schema_version,experiment_id,campaign_id,method,variant,dut,seed,coverage_mode,completion_seq,elapsed_wall_seconds,completed_cases,eligible_cases,covered_bins,target_bins,coverage_rate,new_bins,status,failure_class,case_id\n", encoding="ascii")
            outputs = plot_from_csv(csv_path, out_dir)
            # No data rows → no plots, but no crash either
            self.assertIsInstance(outputs, dict)
            # Should not have crashed


if __name__ == "__main__":
    unittest.main()
