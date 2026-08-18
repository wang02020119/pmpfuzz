import csv
import json
import tempfile
import unittest
from pathlib import Path

from pmpfuzz.hpm import build_hpm_coverage_universe
from pmpfuzz.scenario_codec import scenario_hash
from scripts.evaluation.analysis.aggregate_results import aggregate
from scripts.evaluation.validation.validate_timeline import validate_timeline


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n", encoding="ascii")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row, ensure_ascii=True, sort_keys=True) for row in rows) + "\n", encoding="ascii")


def _campaign_root(root: Path, seed: int) -> Path:
    return root / "campaigns" / "exp" / "rocket-clean" / "bb-guided" / "hpm" / f"seed-{seed:04d}"


def _make_hpm_campaign(root: Path, *, seed: int, universe: dict, covered_bins: list[str]) -> Path:
    campaign_dir = _campaign_root(root, seed)
    metrics_dir = campaign_dir / "metrics"
    coverage_dir = campaign_dir / "coverage"
    universe_dir = metrics_dir / "coverage_universe"
    universe_path = universe_dir / "hpm_v1.json"
    spec = {"name": f"case-{seed}", "profile": "pmp-boundary"}
    spec_hash = scenario_hash(spec)
    _write_jsonl(
        metrics_dir / "schedule_v4.jsonl",
        [
            {
                "schema_version": 4,
                "event_seq": 1,
                "event": "candidate_admitted",
                "scenario_hash": spec_hash,
                "scenario_spec": spec,
                "profile": "pmp-boundary",
                "name": f"case-{seed}",
                "parent_hash": None,
                "mutation_operator": "root",
                "mutation_seed": 0,
                "generation_seq": 1,
                "mutation_depth": 0,
                "root_sequence": 0,
                "rejection_reason": None,
            },
            {
                "schema_version": 4,
                "event_seq": 2,
                "event": "execution_committed",
                "scenario_hash": spec_hash,
                "candidate_id": f"cand-{seed}",
                "case_id": f"case-{seed}",
                "profile": "pmp-boundary",
                "status": "pass",
                "failure_class": None,
                "eligible": True,
                "qualification_reason": "eligible",
                "elapsed_wall_seconds": 1.0,
                "case_elapsed_seconds": 0.2,
                "execution_cost": 0.2,
                "new_bins": {"semantic": [], "pairwise": [], "security_triples": [], "predicates": [], "hpm": covered_bins},
                "promoted": True,
                "evicted_hashes": [],
                "retained_without_novelty": False,
                "security_events": [],
                "new_whitebox_events": 0,
            },
        ],
    )
    _write_json(universe_path, universe)
    _write_json(
        universe_dir / "coverage_contract_v1.json",
        {"schema_version": 1, "modes": {"hpm": "hpm_v1.json"}, "hashes": {"hpm": universe["sha256"]}},
    )
    timeline = [
        {
            "schema_version": 1,
            "campaign_id": f"camp-{seed}",
            "variant": "bb-guided",
            "dut": "rocket-clean",
            "seed": seed,
            "completion_seq": 0,
            "case_id": None,
            "profile": None,
            "elapsed_wall_seconds": 0.0,
            "case_elapsed_seconds": 0.0,
            "completed_cases": 0,
            "eligible_cases": 0,
            "eligible_hpm_cases": 0,
            "status": None,
            "failure_class": None,
            "coverage_eligible": False,
            "qualification_reason": None,
            "semantic_covered": 0,
            "semantic_target": 1,
            "semantic_rate": 0.0,
            "pairwise_covered": 0,
            "pairwise_target": 1,
            "pairwise_rate": 0.0,
            "security_triples_covered": 0,
            "security_triples_target": 1,
            "security_triples_rate": 0.0,
            "predicates_covered": 0,
            "predicates_target": 1,
            "predicates_rate": 0.0,
            "hpm_covered": 0,
            "hpm_target": universe["bin_count"],
            "hpm_rate": 0.0,
            "new_semantic_bins": 0,
            "new_pairwise_bins": 0,
            "new_security_triple_bins": 0,
            "new_predicate_bins": 0,
            "new_hpm_bins": 0,
            "hpm_eligible": False,
            "last_hpm_novelty_time": 0.0,
            "whitebox_distinct_events": 0,
            "new_whitebox_events": 0,
        },
        {
            "schema_version": 1,
            "campaign_id": f"camp-{seed}",
            "variant": "bb-guided",
            "dut": "rocket-clean",
            "seed": seed,
            "completion_seq": 1,
            "case_id": f"case-{seed}",
            "profile": "pmp-boundary",
            "elapsed_wall_seconds": 1.0,
            "case_elapsed_seconds": 0.2,
            "completed_cases": 1,
            "eligible_cases": 1,
            "eligible_hpm_cases": 1,
            "status": "pass",
            "failure_class": None,
            "coverage_eligible": True,
            "qualification_reason": "eligible",
            "semantic_covered": 0,
            "semantic_target": 1,
            "semantic_rate": 0.0,
            "pairwise_covered": 0,
            "pairwise_target": 1,
            "pairwise_rate": 0.0,
            "security_triples_covered": 0,
            "security_triples_target": 1,
            "security_triples_rate": 0.0,
            "predicates_covered": 0,
            "predicates_target": 1,
            "predicates_rate": 0.0,
            "hpm_covered": len(covered_bins),
            "hpm_target": universe["bin_count"],
            "hpm_rate": len(covered_bins) / universe["bin_count"],
            "new_semantic_bins": 0,
            "new_pairwise_bins": 0,
            "new_security_triple_bins": 0,
            "new_predicate_bins": 0,
            "new_hpm_bins": len(covered_bins),
            "hpm_eligible": True,
            "last_hpm_novelty_time": 1.0,
            "whitebox_distinct_events": 0,
            "new_whitebox_events": 0,
        },
    ]
    _write_jsonl(metrics_dir / "coverage_timeline.jsonl", timeline)
    _write_json(
        metrics_dir / "campaign_metadata.json",
        {
            "schema_version": "1.0",
            "experiment_id": "exp",
            "campaign_id": f"camp-{seed}",
            "method": "pmpfuzz",
            "variant": "bb-guided",
            "coverage_mode": "hpm",
            "driver_mode": "continuous",
            "dut": "rocket-clean",
            "seed": seed,
            "jobs": 8,
            "time_budget_seconds": 180,
            "wall_clock_horizon_seconds": 180,
            "per_case_timeout_seconds": 10,
            "round_size": 8,
            "run_class": "development-smoke",
            "budget_class": "primary-wall-clock",
            "schedule_v4": "metrics/schedule_v4.jsonl",
            "source_sha": "a" * 40,
            "source_tree_sha256": "b" * 64,
            "source_dirty": False,
            "dut_sha": "c" * 40,
            "dut_sha_status": "available",
            "dut_binary_sha256": "d" * 64,
            "dut_binary_path": "/dut",
            "capability_fingerprint": "cap",
            "coverage_universe_hashes": {"hpm": universe["sha256"]},
            "coverage_universe_files": {"hpm": str(universe_path.relative_to(campaign_dir))},
        },
    )
    _write_json(
        coverage_dir / "coverage.json",
        {
            "schema_version": 6,
            "driver_mode": "campaign",
            "coverage_universe_hashes": {"hpm": universe["sha256"]},
            "execution_coverage": {
                "by_dut": {
                    "rocket-clean": {
                        "hpm": {
                            "covered_target_bins": len(covered_bins),
                            "total_target_bins": universe["bin_count"],
                            "covered_bins": covered_bins,
                            "target": "pmp-relevant-hpm",
                            "universe_sha256": universe["sha256"],
                        }
                    }
                }
            },
        },
    )
    _write_json(
        campaign_dir / "validation.json",
        {"campaign_id": f"camp-{seed}", "valid": True, "inputs": {}, "checked_utc": "2026-07-15T00:00:00Z"},
    )
    return campaign_dir


class HpmAnalysisContractTest(unittest.TestCase):
    def test_validate_timeline_accepts_single_mode_hpm_campaign(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = build_hpm_coverage_universe(dut="rocket-clean", generator_seed=1)
            campaign_dir = _make_hpm_campaign(root, seed=1, universe=universe, covered_bins=["event=exception|bucket=0-0.1"])

            report = validate_timeline(campaign_dir)

        self.assertTrue(report["valid"], report)

    def test_aggregate_exports_hpm_mode_and_uses_bin_set_comparability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = build_hpm_coverage_universe(dut="rocket-clean", generator_seed=1)
            second = build_hpm_coverage_universe(dut="rocket-clean", generator_seed=2)
            self.assertNotEqual(first["sha256"], second["sha256"])
            self.assertEqual(first["bin_set_sha256"], second["bin_set_sha256"])
            _make_hpm_campaign(root, seed=1, universe=first, covered_bins=["event=exception|bucket=0-0.1"])
            _make_hpm_campaign(root, seed=2, universe=second, covered_bins=["event=exception|bucket=0-0.1"])

            aggregate(root, "exp")

            with (root / "aggregate" / "validation_report.json").open(encoding="ascii") as handle:
                report = json.load(handle)
            with (root / "aggregate" / "coverage_timeseries.csv").open(encoding="ascii", newline="") as handle:
                rows = list(csv.DictReader(handle))

        self.assertTrue(report["valid"], report)
        self.assertEqual({row["coverage_mode"] for row in rows}, {"hpm"})


if __name__ == "__main__":
    unittest.main()
