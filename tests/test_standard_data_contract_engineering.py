"""Engineering-only tests for the normalized evaluation data contract."""

from __future__ import annotations

import csv
import json
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.evaluation.analysis.aggregate_results import aggregate


REQUIRED_OUTPUTS = [
    "normalized/campaigns.csv",
    "normalized/coverage_timeseries.csv",
    "normalized/security_event_timeseries.csv",
    "aggregate/coverage_threshold_times.csv",
    "aggregate/coverage_auc.csv",
    "aggregate/overhead.csv",
    "aggregate/exclusions.csv",
    "aggregate/validation_report.json",
    "schemas/data_dictionary.md",
    "manifests/artifact-sha256.txt",
]


def _write_campaign(root: Path) -> Path:
    campaign = (
        root
        / "campaigns"
        / "E1-COVERAGE-FEEDBACK"
        / "rocket-clean"
        / "random"
        / "semantic"
        / "seed-0101"
    )
    metrics = campaign / "metrics"
    metrics.mkdir(parents=True)
    metadata = {
        "schema_version": "1.0",
        "experiment_id": "E1-COVERAGE-FEEDBACK",
        "campaign_id": "e1-rocket-random-0101",
        "method": "pmpfuzz",
        "variant": "random",
        "coverage_mode": "semantic",
        "dut": "rocket-clean",
        "seed": 101,
        "source_sha": "a" * 40,
        "dut_sha": "b" * 40,
        "dut_binary_sha256": "c" * 64,
        "capability_fingerprint": "d" * 64,
        "start_utc": "2026-07-13T00:00:00+00:00",
        "end_utc": "2026-07-13T00:00:10+00:00",
        "time_budget_seconds": 30,
        "round_size": 2,
        "jobs": 1,
        "per_case_timeout_seconds": 10,
    }
    (metrics / "campaign_metadata.json").write_text(
        json.dumps(metadata), encoding="ascii"
    )
    baseline = {
        "schema_version": 1,
        "campaign_id": metadata["campaign_id"],
        "variant": "random",
        "dut": "rocket-clean",
        "seed": 101,
        "completion_seq": 0,
        "case_id": None,
        "elapsed_wall_seconds": 0.0,
        "completed_cases": 0,
        "eligible_cases": 0,
        "semantic_covered": 0,
        "semantic_target": 10,
        "semantic_rate": 0.0,
        "pairwise_covered": 0,
        "pairwise_target": 5,
        "pairwise_rate": 0.0,
        "security_triples_covered": 0,
        "security_triples_target": 3,
        "security_triples_rate": 0.0,
        "predicates_covered": 0,
        "predicates_target": 2,
        "predicates_rate": 0.0,
    }
    rows = [baseline]
    for seq, covered, elapsed in [(1, 2, 2.0), (2, 5, 7.0)]:
        rows.append(
            {
                **baseline,
                "completion_seq": seq,
                "case_id": f"case-{seq}",
                "elapsed_wall_seconds": elapsed,
                "completed_cases": seq,
                "eligible_cases": seq,
                "semantic_covered": covered,
                "semantic_rate": covered / 10,
                "new_semantic_bins": covered - rows[-1]["semantic_covered"],
                "status": "pass",
                "failure_class": None,
            }
        )
    (metrics / "coverage_timeline.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="ascii"
    )
    events = [
        {
            "schema_version": "1.0",
            "experiment_id": metadata["experiment_id"],
            "campaign_id": metadata["campaign_id"],
            "method": "pmpfuzz",
            "variant": "random",
            "dut": "rocket-clean",
            "seed": 101,
            "completion_seq": 2,
            "event_index": 1,
            "elapsed_wall_seconds": 7.0,
            "event_namespace": "dut-probe",
            "event_category": "pmp-check",
            "event_id": "event-1",
            "is_new_event": True,
            "total_distinct_events": 1,
            "case_id": "case-2",
        }
    ]
    (metrics / "security_event_timeseries.jsonl").write_text(
        "\n".join(json.dumps(row) for row in events) + "\n", encoding="ascii"
    )
    return campaign


class TestStandardDataContract(unittest.TestCase):
    def test_aggregate_generates_complete_contract(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_campaign(root)
            aggregate(root, "compact-evaluation")

            for relative in REQUIRED_OUTPUTS:
                self.assertTrue((root / relative).exists(), relative)

            with (root / "normalized/coverage_timeseries.csv").open(
                "r", encoding="ascii", newline=""
            ) as handle:
                coverage_rows = list(csv.DictReader(handle))
            self.assertEqual([row["completion_seq"] for row in coverage_rows], ["1", "2"])

            with (root / "normalized/security_event_timeseries.csv").open(
                "r", encoding="ascii", newline=""
            ) as handle:
                event_rows = list(csv.DictReader(handle))
            self.assertEqual(len(event_rows), 1)
            self.assertEqual(event_rows[0]["event_id"], "event-1")

            report = json.loads(
                (root / "aggregate/validation_report.json").read_text(encoding="ascii")
            )
            self.assertEqual(report["error_count"], 0, report)

            hashes = (root / "manifests/artifact-sha256.txt").read_text(
                encoding="ascii"
            )
            self.assertIn("normalized/coverage_timeseries.csv", hashes)
            self.assertIn("aggregate/coverage_auc.csv", hashes)

    def test_aggregate_ignores_superseded_campaign_copies(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _write_campaign(root)
            replaced = campaign.with_name(campaign.name + ".replaced-20260729T164200Z")
            rerun_aborted = campaign.with_name(
                campaign.name + ".rerun-aborted-20260729T162514Z"
            )
            interrupted = campaign.with_name(
                campaign.name + ".interrupted-20260729T164230Z"
            )
            campaign_root = root / "campaigns" / "E1-COVERAGE-FEEDBACK" / "rocket-clean"
            orphaned_root = root / "campaigns" / "E1-COVERAGE-FEEDBACK" / "rocket-clean.orphaned-20260729T161656Z"
            orphaned = orphaned_root / campaign.relative_to(campaign_root)
            shutil.copytree(campaign, replaced)
            shutil.copytree(campaign, rerun_aborted)
            shutil.copytree(campaign, interrupted)
            shutil.copytree(campaign, orphaned)

            aggregate(root, "compact-evaluation")

            with (root / "normalized/campaigns.csv").open(
                "r", encoding="ascii", newline=""
            ) as handle:
                campaign_rows = list(csv.DictReader(handle))
            self.assertEqual(len(campaign_rows), 1)
            self.assertEqual(campaign_rows[0]["campaign_id"], "e1-rocket-random-0101")


if __name__ == "__main__":
    unittest.main()
