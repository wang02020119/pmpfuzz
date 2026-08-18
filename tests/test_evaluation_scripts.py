
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from scripts.evaluation.validation.validate_timeline import validate_timeline
from scripts.evaluation.analysis.aggregate_results import aggregate


class TestValidateTimeline(unittest.TestCase):

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

            (campaign / "metrics" / "campaign_metadata.json").write_text(json.dumps({
                "campaign_id": "test-campaign",
                "variant": "guided-semantic",
                "dut": "spike",
                "seed": 1,
                "run_class": "development-smoke",
                "source_sha": "0" * 40,
                "dut_sha": "0" * 40,
                "dut_binary_sha256": "0" * 64,
                "capability_fingerprint": "0" * 64,
                "coverage_mode": "semantic",
                "method": "pmpfuzz",
            }), encoding="ascii")
            report = validate_timeline(campaign)
            self.assertTrue(report["valid"], f"Checks: {report['checks']}")
            self.assertEqual(report["error_count"], 0)


class TestAggregateResults(unittest.TestCase):

    def test_empty_aggregate(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "artifacts"
            root.mkdir()
            (root / "aggregate").mkdir()
            outputs = aggregate(root, "test-experiment")

            stats_path = root / "aggregate" / "statistics.json"
            self.assertTrue(stats_path.exists(), f"Not found: {stats_path}")
            stats = json.loads(stats_path.read_text(encoding="ascii"))
            self.assertEqual(stats["total_campaigns"], 0)
class TestFormalMatrixProgress(unittest.TestCase):
    def test_cascade_progress_marker_counts_pre_metadata_artifacts(self):
        from scripts.evaluation.campaigns.run_formal_matrix import cascade_progress_marker

        with TemporaryDirectory() as tmp:
            campaign = Path(tmp) / "campaign"
            (campaign / "elfs").mkdir(parents=True)
            (campaign / "logs").mkdir(parents=True)
            (campaign / "elfs" / "case_0000.elf").write_bytes(b"ELF")
            (campaign / "elfs" / "case_0000.json").write_text("{}", encoding="ascii")
            (campaign / "logs" / "case_0000.stdout.log").write_text("ok", encoding="ascii")
            (campaign / "logs" / "case_0000.stderr.log").write_text("ok", encoding="ascii")

            self.assertEqual(
                cascade_progress_marker(campaign),
                {
                    "elf_count": 1,
                    "sidecar_count": 1,
                    "stdout_log_count": 1,
                    "stderr_log_count": 1,
                },
            )

    def test_refresh_entry_progress_uses_cascade_artifact_growth_without_metadata(self):
        from scripts.evaluation.campaigns.run_formal_matrix import refresh_entry_progress

        with TemporaryDirectory() as tmp:
            campaign = Path(tmp) / "campaign"
            (campaign / "elfs").mkdir(parents=True)
            (campaign / "logs").mkdir(parents=True)
            entry = {
                "spec": {"dut": "rocket-clean", "kind": "cascade", "variant": "cascade", "wave_name": "wave03"},
                "campaign_dir": campaign,
                "last_completed": 0,
                "last_progress_marker": None,
                "last_progress_time": 10.0,
            }

            progressed, snapshot = refresh_entry_progress(entry, now=20.0)
            self.assertFalse(progressed)
            self.assertFalse(snapshot["metadata_present"])
            self.assertEqual(entry["last_progress_time"], 10.0)

            (campaign / "elfs" / "case_0000.elf").write_bytes(b"ELF")
            (campaign / "elfs" / "case_0000.json").write_text("{}", encoding="ascii")
            (campaign / "logs" / "case_0000.stdout.log").write_text("ok", encoding="ascii")
            (campaign / "logs" / "case_0000.stderr.log").write_text("ok", encoding="ascii")

            progressed, snapshot = refresh_entry_progress(entry, now=35.0)
            self.assertTrue(progressed)
            self.assertEqual(entry["last_progress_time"], 35.0)
            self.assertEqual(snapshot["artifact_progress"]["elf_count"], 1)
            self.assertIsNone(snapshot["completed_cases"])

    def test_monitor_wave_does_not_false_stall_during_long_cascade_generation_gap(self):
        import scripts.evaluation.campaigns.run_formal_matrix as formal

        proc = MagicMock()
        proc.poll.side_effect = [None, 0]
        entry = {
            "spec": {"dut": "cva6-clean", "kind": "cascade", "variant": "cascade", "wave_name": "wave03"},
            "campaign_dir": Path("/tmp/cascade-seed-0006"),
            "last_completed": 0,
            "last_progress_marker": (192, 192, 191, 191),
            "last_progress_time": 0.0,
            "proc": proc,
        }
        snapshot = {
            "dut": "cva6-clean",
            "metadata_present": False,
            "completed_cases": None,
            "eligible_cases": None,
            "eligible_bapc_cases": None,
            "artifact_progress": {
                "elf_count": 192,
                "sidecar_count": 192,
                "stdout_log_count": 191,
                "stderr_log_count": 191,
            },
        }

        with patch.object(formal, "assert_frozen_inputs"),\
             patch.object(formal, "refresh_entry_progress", side_effect=[(False, snapshot), (False, snapshot)]),\
             patch.object(formal, "atomic_write_json") as atomic_write,\
             patch.object(formal, "log"),\
             patch.object(formal.time, "sleep"),\
             patch.object(formal.time, "monotonic", side_effect=[1000.0, 1001.0]):
            formal.monitor_wave("8.3-8.4-wave03", [entry])

        atomic_write.assert_called()


if __name__ == "__main__":
    unittest.main()
