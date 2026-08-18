import csv
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts.evaluation.analysis.aggregate_results import aggregate
from scripts.evaluation.campaigns import run_formal_matrix


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(row, ensure_ascii=True, sort_keys=True) for row in rows) + "\n",
        encoding="ascii",
    )


def _build_minimal_cascade_campaign(root: Path) -> tuple[Path, Path]:
    campaign = (
        root
        / "campaigns"
        / "compact-evaluation"
        / "cva6-clean"
        / "cascade"
        / "bapc"
        / "seed-0004"
    )
    metrics = campaign / "metrics"
    _write_json(
        metrics / "campaign_metadata.json",
        {
            "schema_version": "1.0",
            "experiment_id": "compact-evaluation",
            "campaign_id": "cascade-cva6-seed-0004",
            "method": "cascade",
            "variant": "cascade",
            "coverage_mode": "bapc",
            "dut": "cva6-clean",
            "seed": 4,
            "bapc_core_version": "v4",
            "bapc_target": 144,
            "source_sha": "a" * 40,
            "dut_sha": "b" * 40,
            "dut_binary_sha256": "c" * 64,
            "capability_fingerprint": "d" * 64,
            "wall_clock_horizon_seconds": 7200,
            "jobs": 1,
        },
    )
    _write_jsonl(
        metrics / "coverage_timeline.jsonl",
        [
            {
                "schema_version": 1,
                "campaign_id": "cascade-cva6-seed-0004",
                "completion_seq": 0,
                "elapsed_wall_seconds": 0.0,
                "completed_cases": 0,
                "eligible_cases": 0,
                "eligible_bapc_cases": 0,
                "bapc_covered": 0,
                "bapc_target": 144,
                "bapc_rate": 0.0,
                "new_bapc_bins": 0,
                "status": "initialized",
                "case_id": None,
            },
            {
                "schema_version": 1,
                "campaign_id": "cascade-cva6-seed-0004",
                "completion_seq": 1,
                "elapsed_wall_seconds": 12.5,
                "completed_cases": 1,
                "eligible_cases": 1,
                "eligible_bapc_cases": 1,
                "bapc_covered": 9,
                "bapc_target": 144,
                "bapc_rate": 9 / 144,
                "new_bapc_bins": 9,
                "status": "pass",
                "case_id": "cascade-cva6-case-0001",
            },
        ],
    )
    events_path = metrics / "security_event_timeseries.jsonl"
    _write_jsonl(
        events_path,
        [
            {
                "schema_version": "1.0",
                "experiment_id": "compact-evaluation",
                "campaign_id": "cascade-cva6-seed-0004",
                "method": "cascade",
                "variant": "cascade",
                "dut": "cva6-clean",
                "seed": 4,
                "completion_seq": 1,
                "event_index": 1,
                "elapsed_wall_seconds": 12.5,
                "event_namespace": "dut-probe",
                "event_category": "runtime-target",
                "event_id": "evt-1",
                "is_new_event": True,
                "total_distinct_events": 1,
                "case_id": "cascade-cva6-case-0001",
            }
        ],
    )
    return campaign, events_path


class CascadeFormalAggregationTest(unittest.TestCase):
    def test_aggregate_skip_mode_does_not_slurp_security_event_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _campaign, events_path = _build_minimal_cascade_campaign(root)

            original_read_text = Path.read_text

            def guarded_read_text(path_self: Path, *args, **kwargs):
                if path_self == events_path:
                    raise AssertionError("security event stream must not be read in skip mode")
                return original_read_text(path_self, *args, **kwargs)

            with mock.patch.object(Path, "read_text", guarded_read_text):
                outputs = aggregate(root, "compact-evaluation", security_events_mode="skip")

            self.assertTrue((root / "aggregate" / "coverage_final.csv").exists())
            self.assertEqual(outputs["normalized_security_event_timeseries"], root / "normalized" / "security_event_timeseries.csv")
            with (root / "normalized" / "security_event_timeseries.csv").open(
                "r", encoding="ascii", newline=""
            ) as handle:
                self.assertEqual(list(csv.DictReader(handle)), [])
            stats = json.loads((root / "aggregate" / "statistics.json").read_text(encoding="ascii"))
            self.assertEqual(stats["security_event_export_mode"], "skip")
            self.assertEqual(stats["security_event_source_count"], 1)
            self.assertEqual(stats["normalized_security_event_row_count"], 0)
            validation = json.loads((root / "aggregate" / "validation_report.json").read_text(encoding="ascii"))
            self.assertTrue(validation["valid"], validation)

    def test_cascade_wave_uses_skip_security_event_aggregation(self):
        self.assertEqual(
            run_formal_matrix.aggregate_security_events_mode(
                {"kind": "cascade", "variant": "cascade"},
                section="8.3-8.4",
            ),
            "skip",
        )
        self.assertEqual(
            run_formal_matrix.aggregate_security_events_mode(
                {"kind": "pmpfuzz", "variant": "bb-guided"},
                section="8.3-8.4",
            ),
            "full",
        )
        self.assertEqual(
            run_formal_matrix.aggregate_security_events_mode(
                {"generator_variant": "syntax"},
                section="8.5",
            ),
            "full",
        )

    def test_aggregate_experiment_passes_security_event_mode_to_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "logs"
            logs.mkdir(parents=True)
            original_artifact_root = run_formal_matrix.ARTIFACT_ROOT
            original_worktree = run_formal_matrix.WORKTREE
            try:
                run_formal_matrix.ARTIFACT_ROOT = root
                run_formal_matrix.WORKTREE = root
                proc = SimpleNamespace(returncode=0, stdout="ok\n")
                with mock.patch.object(run_formal_matrix.subprocess, "run", return_value=proc) as run_mock:
                    with mock.patch.object(run_formal_matrix, "dut_root", return_value=root / "dut-root"):
                        run_formal_matrix.aggregate_experiment(
                            "cva6-clean",
                            "section-8.3-8.4-formal-v4",
                            security_events_mode="skip",
                        )
                cmd = run_mock.call_args.args[0]
                self.assertIn("--security-events-mode", cmd)
                self.assertEqual(cmd[cmd.index("--security-events-mode") + 1], "skip")
                self.assertEqual(
                    (logs / "aggregate-cva6-clean-section-8.3-8.4-formal-v4.log").read_text(encoding="utf-8"),
                    "ok\n",
                )
            finally:
                run_formal_matrix.ARTIFACT_ROOT = original_artifact_root
                run_formal_matrix.WORKTREE = original_worktree


if __name__ == "__main__":
    unittest.main()
