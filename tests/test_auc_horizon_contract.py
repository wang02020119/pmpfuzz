"""Phase C RED: frozen-horizon step coverage metrics contract.

Tests A-N verify the AUC, threshold, and horizon contract before GREEN
implementation.  Each test calls real ``aggregate()`` or its helpers through
the public API, using temporary directory trees that mimic real campaign output.

Expected outcome at RED:  all tests FAIL because the current code uses
trapezoidal AUC, infers horizon from last data point, and lacks explicit
wall_clock_horizon_seconds / budget_class / censored-threshold semantics.
"""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.evaluation.analysis.aggregate_results import aggregate


# ==============================================================================
# Helpers
# ==============================================================================

def _write_campaign_metadata(metrics_dir: Path, **overrides) -> dict:
    """Write campaign_metadata.json and return the dict written."""
    meta = {
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
        "end_utc": "2026-07-13T00:00:30+00:00",
        "time_budget_seconds": 30,
        "round_size": 2,
        "jobs": 1,
        "per_case_timeout_seconds": 10,
        "run_class": "pilot",
        "wall_clock_horizon_seconds": 10,
        "budget_class": "primary-wall-clock",
    }
    meta.update(overrides)
    metrics_dir.mkdir(parents=True, exist_ok=True)
    (metrics_dir / "campaign_metadata.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=True), encoding="ascii")
    return meta


def _write_validation(metrics_dir: Path, *, valid: bool = True) -> None:
    campaign_dir = metrics_dir.parent
    bindings = {}
    for label, rel_path in (
        ("metadata", Path("metrics/campaign_metadata.json")),
        ("timeline", Path("metrics/coverage_timeline.jsonl")),
    ):
        path = campaign_dir / rel_path
        if path.exists():
            bindings[label] = {
                "path": str(rel_path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
    campaign_id = json.loads((metrics_dir / "campaign_metadata.json").read_text(encoding="ascii")).get("campaign_id")
    (campaign_dir / "validation.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "campaign_id": campaign_id,
                "valid": valid,
                "error_count": 0 if valid else 1,
                "warning_count": 0,
                "inputs": bindings,
            },
            indent=2,
            ensure_ascii=True,
        ),
        encoding="ascii",
    )


def _write_timeline(metrics_dir: Path, campaign_id: str,
                    rows_spec: list,
                    target_bins: int = 10,
                    dut: str = "rocket-clean",
                    seed: int = 101,
                    variant: str = "random") -> Path:
    """Write coverage_timeline.jsonl.

    *rows_spec*: list of (completion_seq, elapsed_wall_seconds, coverage_rate).
    A synthetic baseline row (seq=0, rate=0.0) is prepended automatically.
    coverage_rate may be None for denominator=0 scenarios.
    """
    metrics_dir.mkdir(parents=True, exist_ok=True)
    lines = []
    baseline = {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "variant": variant,
        "dut": dut,
        "seed": seed,
        "completion_seq": 0,
        "case_id": None,
        "elapsed_wall_seconds": 0.0,
        "case_elapsed_seconds": 0.0,
        "completed_cases": 0,
        "eligible_cases": 0,
        "status": None,
        "failure_class": None,
        "coverage_eligible": False,
        "qualification_reason": None,
        "semantic_covered": 0,
        "semantic_target": target_bins,
        "semantic_rate": 0.0,
        "pairwise_covered": 0,
        "pairwise_target": 20,
        "pairwise_rate": 0.0,
        "security_triples_covered": 0,
        "security_triples_target": 30,
        "security_triples_rate": 0.0,
        "predicates_covered": 0,
        "predicates_target": 5,
        "predicates_rate": 0.0,
        "new_semantic_bins": 0,
        "new_pairwise_bins": 0,
        "new_security_triple_bins": 0,
        "new_predicate_bins": 0,
        "whitebox_distinct_events": 0,
        "new_whitebox_events": 0,
    }
    lines.append(baseline)
    prev_covered = 0
    for seq, elapsed, rate in rows_spec:
        covered = int(round((rate or 0.0) * target_bins))
        new_bins = max(0, covered - prev_covered)
        prev_covered = covered
        row = {
            **baseline,
            "completion_seq": seq,
            "case_id": f"case-{seq:04d}",
            "elapsed_wall_seconds": elapsed,
            "case_elapsed_seconds": 2.0,
            "completed_cases": seq,
            "eligible_cases": seq,
            "status": "pass",
            "coverage_eligible": True,
            "qualification_reason": "eligible",
            "semantic_covered": covered,
            "semantic_rate": rate,
            "new_semantic_bins": new_bins,
        }
        lines.append(row)
    path = metrics_dir / "coverage_timeline.jsonl"
    path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=True, sort_keys=True)
                  for r in lines) + "\n",
        encoding="ascii")
    _write_validation(metrics_dir)
    return path


def _make_campaign_dir(root: Path, experiment_id: str, dut: str,
                        variant: str, mode: str, seed: int) -> Path:
    """Create the standard campaign directory tree and return the campaign dir."""
    campaign = (root / "campaigns" / experiment_id / dut / variant
                / mode / f"seed-{seed:04d}")
    campaign.mkdir(parents=True)
    return campaign


def _read_csv(path: Path) -> list:
    with path.open("r", encoding="ascii", newline="") as f:
        return list(csv.DictReader(f))


# ==============================================================================
# Test A: Right-continuous step AUC hand-computed
# ==============================================================================

class TestA_RightContinuousStepAuc(unittest.TestCase):
    """A: AUC computed as right-continuous step function.

    Points: (2, 0.2), (5, 0.5), T=10
    Step AUC = 0*2 + 0.2*3 + 0.5*5 = 3.1
    Normalized = 3.1 / 10 = 0.31
    """

    def test_hand_computed_auc_step_integral(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _make_campaign_dir(
                root, "E1-COVERAGE-FEEDBACK", "rocket-clean",
                "random", "semantic", 101)
            metrics = campaign / "metrics"
            _write_campaign_metadata(
                metrics,
                campaign_id="auc-test-a",
                wall_clock_horizon_seconds=10,
            )
            _write_timeline(metrics, "auc-test-a", [
                (1, 2.0, 0.2),
                (2, 5.0, 0.5),
            ])

            outputs = aggregate(root, "E1-COVERAGE-FEEDBACK")
            auc_rows = _read_csv(root / "aggregate" / "coverage_auc.csv")
            self.assertEqual(len(auc_rows), 1)
            row = auc_rows[0]
            self.assertAlmostEqual(float(row["auc"]), 3.1, places=4,
                                   msg="Step AUC must be 3.1")
            self.assertAlmostEqual(float(row["normalized_auc"]), 0.31, places=4,
                                   msg="Normalized AUC must be 0.31")


# ==============================================================================
# Test B: Explicitly not trapezoidal
# ==============================================================================

class TestB_NotTrapezoidal(unittest.TestCase):
    """B: Step AUC output is NOT trapezoidal.

    With points (2, 0.2), (5, 0.5), T=10:
      Trapezoidal = (0+0.2)*2/2 + (0.2+0.5)*3/2 + 0.5*5 = 0.2+1.05+2.5 = 3.75
      Step        = 0*2 + 0.2*3 + 0.5*5 = 3.1

    These must differ, proving the implementation uses step (right-continuous),
    not trapezoidal integration.
    """

    def test_auc_explicitly_not_trapezoidal(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _make_campaign_dir(
                root, "E1-COVERAGE-FEEDBACK", "rocket-clean",
                "random", "semantic", 101)
            metrics = campaign / "metrics"
            _write_campaign_metadata(
                metrics,
                campaign_id="auc-test-b",
                wall_clock_horizon_seconds=10,
            )
            _write_timeline(metrics, "auc-test-b", [
                (1, 2.0, 0.2),
                (2, 5.0, 0.5),
            ])

            outputs = aggregate(root, "E1-COVERAGE-FEEDBACK")
            auc_rows = _read_csv(root / "aggregate" / "coverage_auc.csv")
            auc_val = float(auc_rows[0]["auc"])
            trapezoidal_would_be = 3.75
            self.assertNotAlmostEqual(
                auc_val, trapezoidal_would_be, places=4,
                msg="AUC must NOT match trapezoidal (3.75)")
            self.assertAlmostEqual(auc_val, 3.1, places=4,
                                   msg="AUC must be step integral 3.1")


# ==============================================================================
# Test C: Premature pool exhaustion - final coverage extends to T
# ==============================================================================

class TestC_PrematurePoolExhaustion(unittest.TestCase):
    """C: When the pool is exhausted before T, the last coverage rate extends.

    Last data point at t=5 (rate=0.5), T=10.
    Step AUC must include 0.5 * (10-5) = 2.5 extension.
    """

    def test_coverage_extends_to_horizon_after_last_point(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _make_campaign_dir(
                root, "E1-COVERAGE-FEEDBACK", "rocket-clean",
                "random", "semantic", 101)
            metrics = campaign / "metrics"
            _write_campaign_metadata(
                metrics,
                campaign_id="auc-test-c",
                wall_clock_horizon_seconds=10,
            )
            _write_timeline(metrics, "auc-test-c", [
                (1, 2.0, 0.2),
                (2, 5.0, 0.5),  # last point at t=5, but T=10
            ])

            outputs = aggregate(root, "E1-COVERAGE-FEEDBACK")
            auc_rows = _read_csv(root / "aggregate" / "coverage_auc.csv")
            auc_val = float(auc_rows[0]["auc"])
            # Must include extension: 0.5 * (10 - 5) = 2.5
            expected = 0.0 * 2 + 0.2 * 3 + 0.5 * 5  # = 3.1
            self.assertAlmostEqual(auc_val, expected, places=4)

            # Verify final_extension_seconds field
            self.assertIn("final_extension_seconds", auc_rows[0])
            self.assertAlmostEqual(
                float(auc_rows[0]["final_extension_seconds"]), 5.0, places=2,
                msg="Extension from last point (5s) to horizon (10s) must be 5s")


# ==============================================================================
# Test D: Different last time, same T -> comparable
# ==============================================================================

class TestD_DifferentLastTimeSameT(unittest.TestCase):
    """D: Campaigns with different last-data times but same horizon T comparable.

    Two campaigns share T=10 but one ends at t=5, the other at t=8.
    Both must produce AUC rows with the same horizon_seconds=10.
    """

    def test_same_horizon_different_last_time(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for seed, last_t in [(101, 5.0), (102, 8.0)]:
                campaign = _make_campaign_dir(
                    root, "E1-COVERAGE-FEEDBACK", "rocket-clean",
                    "random", "semantic", seed)
                metrics = campaign / "metrics"
                _write_campaign_metadata(
                    metrics,
                    campaign_id=f"auc-test-d-{seed:04d}",
                    seed=seed,
                    wall_clock_horizon_seconds=10,
                )
                _write_timeline(metrics, f"auc-test-d-{seed:04d}", [
                    (1, 2.0, 0.2),
                    (2, last_t, 0.4),
                ], seed=seed)

            outputs = aggregate(root, "E1-COVERAGE-FEEDBACK")
            auc_rows = _read_csv(root / "aggregate" / "coverage_auc.csv")
            self.assertEqual(len(auc_rows), 2)
            horizons = {float(r["horizon_seconds"]) for r in auc_rows}
            self.assertEqual(horizons, {10.0},
                             "Both campaigns must report horizon_seconds=10")


# ==============================================================================
# Test E: strict/pilot without explicit wall_clock_horizon_seconds -> invalid
# ==============================================================================

class TestE_MissingHorizonInvalid(unittest.TestCase):
    """E: strict/pilot campaigns missing wall_clock_horizon_seconds are invalid.

    The horizon MUST come from metadata; it must NOT be inferred from last point.
    """

    def test_pilot_without_explicit_horizon_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _make_campaign_dir(
                root, "E1-COVERAGE-FEEDBACK", "rocket-clean",
                "random", "semantic", 101)
            metrics = campaign / "metrics"
            _write_campaign_metadata(
                metrics,
                campaign_id="auc-test-e",
                run_class="pilot",
            )
            # Remove wall_clock_horizon_seconds if helper added it
            meta_path = metrics / "campaign_metadata.json"
            meta = json.loads(meta_path.read_text(encoding="ascii"))
            meta.pop("wall_clock_horizon_seconds", None)
            meta.pop("budget_class", None)
            meta_path.write_text(
                json.dumps(meta, ensure_ascii=True), encoding="ascii")

            _write_timeline(metrics, "auc-test-e", [
                (1, 2.0, 0.2),
                (2, 5.0, 0.5),
            ])

            outputs = aggregate(root, "E1-COVERAGE-FEEDBACK")
            report = json.loads(
                (root / "aggregate" / "validation_report.json")
                .read_text(encoding="ascii"))
            self.assertFalse(
                report["valid"],
                "Missing wall_clock_horizon_seconds must invalidate "
                "strict campaign")
            horizon_errors = [e for e in report.get("errors", [])
                              if "horizon" in e.lower()]
            self.assertTrue(len(horizon_errors) > 0,
                            "Must report horizon-related error")

    def test_strict_without_explicit_horizon_is_invalid(self):
        """Same check for run_class='formal'."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _make_campaign_dir(
                root, "E1-COVERAGE-FEEDBACK", "rocket-clean",
                "random", "semantic", 101)
            metrics = campaign / "metrics"
            meta = {
                "schema_version": "1.0",
                "experiment_id": "E1-COVERAGE-FEEDBACK",
                "campaign_id": "auc-test-e2",
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
                "end_utc": "2026-07-13T00:00:30+00:00",
                "time_budget_seconds": 30,
                "round_size": 2,
                "jobs": 1,
                "per_case_timeout_seconds": 10,
                "run_class": "formal",
            }
            metrics.mkdir(parents=True, exist_ok=True)
            (metrics / "campaign_metadata.json").write_text(
                json.dumps(meta, ensure_ascii=True), encoding="ascii")
            _write_timeline(metrics, "auc-test-e2", [
                (1, 2.0, 0.2),
            ])

            outputs = aggregate(root, "E1-COVERAGE-FEEDBACK")
            report = json.loads(
                (root / "aggregate" / "validation_report.json")
                .read_text(encoding="ascii"))
            self.assertFalse(report["valid"],
                             "Missing horizon must invalidate formal campaigns")


# ==============================================================================
# Test F: Same (experiment_id, dut, budget_class) horizon inconsistent -> invalid
# ==============================================================================

class TestF_HorizonInconsistencyInvalid(unittest.TestCase):
    """F: Campaigns in the same comparison group must share the same T."""

    def test_same_group_different_horizon_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for seed, horizon in [(101, 10), (102, 20)]:
                campaign = _make_campaign_dir(
                    root, "E1-COVERAGE-FEEDBACK", "rocket-clean",
                    "random", "semantic", seed)
                metrics = campaign / "metrics"
                _write_campaign_metadata(
                    metrics,
                    campaign_id=f"auc-test-f-{seed:04d}",
                    seed=seed,
                    wall_clock_horizon_seconds=horizon,
                    budget_class="primary-wall-clock",
                )
                _write_timeline(metrics, f"auc-test-f-{seed:04d}", [
                    (1, 2.0, 0.2),
                    (2, 5.0, 0.5),
                ], seed=seed)

            outputs = aggregate(root, "E1-COVERAGE-FEEDBACK")
            report = json.loads(
                (root / "aggregate" / "validation_report.json")
                .read_text(encoding="ascii"))
            self.assertFalse(
                report["valid"],
                "Inconsistent horizon within comparison group must be invalid")
            group_errors = [
                e for e in report.get("errors", [])
                if "horizon" in e.lower()
                and ("inconsistent" in e.lower() or "group" in e.lower()
                     or "budget_class" in e.lower())
            ]
            self.assertTrue(len(group_errors) > 0,
                            "Must report horizon inconsistency error")


# ==============================================================================
# Test G: raw tail > T is allowed, but analysis must truncate
# ==============================================================================

class TestG_LastTimeExceedsHorizonTruncated(unittest.TestCase):
    """G: Raw timeline may extend past T if aggregate analysis truncates to T."""

    def test_last_time_exceeds_horizon_is_truncated_from_analysis(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _make_campaign_dir(
                root, "E1-COVERAGE-FEEDBACK", "rocket-clean",
                "random", "semantic", 101)
            metrics = campaign / "metrics"
            _write_campaign_metadata(
                metrics,
                campaign_id="auc-test-g",
                wall_clock_horizon_seconds=10,
            )
            _write_timeline(metrics, "auc-test-g", [
                (1, 5.0, 0.2),
                (2, 12.0, 0.5),  # exceeds T
            ])

            aggregate(root, "E1-COVERAGE-FEEDBACK")
            report = json.loads(
                (root / "aggregate" / "validation_report.json")
                .read_text(encoding="ascii"))
            self.assertTrue(
                report["valid"],
                f"raw tail beyond T must be allowed when analysis rows are truncated, got {report.get('errors', [])}",
            )
            self.assertFalse(
                any("horizon_exceeded" in err for err in report.get("errors", [])),
                report.get("errors", []),
            )

            ts_rows = _read_csv(root / "aggregate" / "coverage_timeseries.csv")
            self.assertEqual(len(ts_rows), 1)
            self.assertAlmostEqual(float(ts_rows[0]["elapsed_wall_seconds"]), 5.0, places=3)
            self.assertEqual(ts_rows[0]["covered_bins"], "2")

            final_rows = _read_csv(root / "aggregate" / "coverage_final.csv")
            self.assertEqual(len(final_rows), 1)
            self.assertAlmostEqual(float(final_rows[0]["semantic_rate"]), 0.2, places=4)


# ==============================================================================
# Test H: denominator 0 or missing -> rate/AUC/threshold null + not_applicable
# ==============================================================================

class TestH_DenominatorZero(unittest.TestCase):
    """H: target_bins=0 -> coverage_rate=null, AUC=null, threshold=not_applicable."""

    def test_zero_denominator_yields_null_auc_and_not_applicable(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _make_campaign_dir(
                root, "E1-COVERAGE-FEEDBACK", "rocket-clean",
                "random", "semantic", 101)
            metrics = campaign / "metrics"
            _write_campaign_metadata(
                metrics,
                campaign_id="auc-test-h",
                wall_clock_horizon_seconds=10,
            )
            _write_timeline(metrics, "auc-test-h", [
                (1, 2.0, None),
            ], target_bins=0)
            # Fix timeline: null rate for denominator=0
            tl_path = metrics / "coverage_timeline.jsonl"
            lines = [json.loads(l)
                     for l in tl_path.read_text(encoding="ascii").strip()
                                        .split("\n")
                     if l.strip()]
            for line in lines:
                if line.get("completion_seq", 0) > 0:
                    line["semantic_rate"] = None
                    line["semantic_covered"] = 0
            tl_path.write_text(
                "\n".join(json.dumps(l, ensure_ascii=True, sort_keys=True)
                          for l in lines) + "\n",
                encoding="ascii")

            outputs = aggregate(root, "E1-COVERAGE-FEEDBACK")
            auc_rows = _read_csv(root / "aggregate" / "coverage_auc.csv")
            self.assertEqual(len(auc_rows), 1)
            row = auc_rows[0]
            auc_val = row.get("auc", "")
            self.assertTrue(
                auc_val == "" or auc_val is None,
                f"AUC must be null/empty for zero denominator, got {auc_val!r}")
            self.assertIn("not_applicable", row,
                          "AUC row must have not_applicable field")
            self.assertEqual(row.get("not_applicable", ""), "True")

            threshold_rows = _read_csv(
                root / "aggregate" / "coverage_threshold_times.csv")
            self.assertTrue(len(threshold_rows) > 0)
            for tr in threshold_rows:
                self.assertEqual(tr.get("not_applicable", ""), "True")

    def test_missing_denominator_yields_null_auc(self):
        """Missing target_bins also yields null AUC."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _make_campaign_dir(
                root, "E1-COVERAGE-FEEDBACK", "rocket-clean",
                "random", "semantic", 101)
            metrics = campaign / "metrics"
            _write_campaign_metadata(
                metrics,
                campaign_id="auc-test-h2",
                wall_clock_horizon_seconds=10,
            )
            _write_timeline(metrics, "auc-test-h2", [
                (1, 2.0, None),
            ], target_bins=0)

            tl_path = metrics / "coverage_timeline.jsonl"
            lines = [json.loads(l)
                     for l in tl_path.read_text(encoding="ascii").strip()
                                        .split("\n")
                     if l.strip()]
            for line in lines:
                if line.get("completion_seq", 0) > 0:
                    line["semantic_rate"] = None
                    line["semantic_covered"] = 0
                    line["semantic_target"] = 0
            tl_path.write_text(
                "\n".join(json.dumps(l, ensure_ascii=True, sort_keys=True)
                          for l in lines) + "\n",
                encoding="ascii")

            outputs = aggregate(root, "E1-COVERAGE-FEEDBACK")
            auc_rows = _read_csv(root / "aggregate" / "coverage_auc.csv")
            self.assertEqual(len(auc_rows), 1)
            row = auc_rows[0]
            self.assertEqual(row.get("not_applicable", ""), "True")


# ==============================================================================
# Test I: Threshold not reached -> censored
# ==============================================================================

class TestI_ThresholdNotReached(unittest.TestCase):
    """I: Unreached threshold -> reached=false, censored=true, elapsed=null,
    censor_time=T."""

    def test_unreached_threshold_is_censored_with_censor_time(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _make_campaign_dir(
                root, "E1-COVERAGE-FEEDBACK", "rocket-clean",
                "random", "semantic", 101)
            metrics = campaign / "metrics"
            _write_campaign_metadata(
                metrics,
                campaign_id="auc-test-i",
                wall_clock_horizon_seconds=10,
            )
            _write_timeline(metrics, "auc-test-i", [
                (1, 2.0, 0.2),  # only 20%, never reaches 90%
            ])

            outputs = aggregate(root, "E1-COVERAGE-FEEDBACK")
            threshold_rows = _read_csv(
                root / "aggregate" / "coverage_threshold_times.csv")
            high = [r for r in threshold_rows
                    if float(r["threshold"]) >= 0.5]
            for row in high:
                self.assertEqual(row.get("threshold_reached", ""), "False")
                self.assertEqual(row.get("censored", ""), "True")
                self.assertEqual(row.get("elapsed_wall_seconds", ""), "",
                                 "elapsed must be empty for unreached threshold")
                self.assertIn("censor_time_seconds", row)
                self.assertAlmostEqual(
                    float(row.get("censor_time_seconds", 0)), 10.0, places=2,
                    msg="censor_time must equal T=10")


# ==============================================================================
# Test J: Threshold reached -> first crossing
# ==============================================================================

class TestJ_ThresholdFirstCrossing(unittest.TestCase):
    """J: When threshold is reached, use the first point where rate >= threshold."""

    def test_threshold_first_crossing_time(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _make_campaign_dir(
                root, "E1-COVERAGE-FEEDBACK", "rocket-clean",
                "random", "semantic", 101)
            metrics = campaign / "metrics"
            _write_campaign_metadata(
                metrics,
                campaign_id="auc-test-j",
                wall_clock_horizon_seconds=10,
            )
            _write_timeline(metrics, "auc-test-j", [
                (1, 2.0, 0.3),
                (2, 5.0, 0.6),
            ])

            outputs = aggregate(root, "E1-COVERAGE-FEEDBACK")
            threshold_rows = _read_csv(
                root / "aggregate" / "coverage_threshold_times.csv")
            # Threshold 0.25: first crossing at t=2
            t25 = [r for r in threshold_rows
                   if abs(float(r["threshold"]) - 0.25) < 0.001]
            self.assertEqual(len(t25), 1)
            self.assertEqual(t25[0]["threshold_reached"], "True")
            self.assertAlmostEqual(
                float(t25[0]["elapsed_wall_seconds"]), 2.0, places=2)

            # Threshold 0.5: first crossing at t=5
            t50 = [r for r in threshold_rows
                   if abs(float(r["threshold"]) - 0.5) < 0.001]
            self.assertEqual(len(t50), 1)
            self.assertEqual(t50[0]["threshold_reached"], "True")
            self.assertAlmostEqual(
                float(t50[0]["elapsed_wall_seconds"]), 5.0, places=2)


# ==============================================================================
# Test K: seq=0 synthetic excluded
# ==============================================================================

class TestK_Seq0Excluded(unittest.TestCase):
    """K: Synthetic baseline row (completion_seq=0) excluded from normalized data."""

    def test_seq0_excluded_from_normalized_outputs(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _make_campaign_dir(
                root, "E1-COVERAGE-FEEDBACK", "rocket-clean",
                "random", "semantic", 101)
            metrics = campaign / "metrics"
            _write_campaign_metadata(
                metrics,
                campaign_id="auc-test-k",
                wall_clock_horizon_seconds=10,
            )
            _write_timeline(metrics, "auc-test-k", [
                (1, 2.0, 0.2),
                (2, 5.0, 0.5),
            ])

            outputs = aggregate(root, "E1-COVERAGE-FEEDBACK")
            ts_rows = _read_csv(root / "aggregate" / "coverage_timeseries.csv")
            for row in ts_rows:
                self.assertNotEqual(row.get("completion_seq"), "0",
                                    "seq=0 must not appear in timeseries")
            norm_ts = _read_csv(
                root / "normalized" / "coverage_timeseries.csv")
            for row in norm_ts:
                self.assertNotEqual(row.get("completion_seq"), "0",
                                    "seq=0 must not appear in normalized data")


# ==============================================================================
# Test K2: raw tail beyond horizon is kept raw but excluded from analysis
# ==============================================================================

class TestK2_ContinuousTailExcludedFromAnalysis(unittest.TestCase):
    """K2: aggregate metrics must truncate to elapsed_wall_seconds <= T."""

    def test_tail_past_horizon_does_not_enter_analysis_metrics(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _make_campaign_dir(
                root, "E1-COVERAGE-FEEDBACK", "rocket-clean",
                "random", "semantic", 101)
            metrics = campaign / "metrics"
            _write_campaign_metadata(
                metrics,
                campaign_id="auc-test-k2",
                wall_clock_horizon_seconds=900,
            )
            _write_timeline(metrics, "auc-test-k2", [
                (1, 899.0, 0.4),
                (2, 900.2, 0.9),
            ])

            aggregate(root, "E1-COVERAGE-FEEDBACK")

            report = json.loads(
                (root / "aggregate" / "validation_report.json")
                .read_text(encoding="ascii"))
            self.assertTrue(
                report["valid"],
                f"raw tail past T must be allowed when analysis rows are truncated, got {report.get('errors', [])}",
            )
            self.assertFalse(
                any("horizon_exceeded" in err for err in report.get("errors", [])),
                report.get("errors", []),
            )

            ts_rows = _read_csv(root / "aggregate" / "coverage_timeseries.csv")
            self.assertEqual(len(ts_rows), 1)
            self.assertAlmostEqual(float(ts_rows[0]["elapsed_wall_seconds"]), 899.0, places=3)
            self.assertEqual(ts_rows[0]["completed_cases"], "1")
            self.assertEqual(ts_rows[0]["eligible_cases"], "1")

            auc_rows = _read_csv(root / "aggregate" / "coverage_auc.csv")
            self.assertEqual(len(auc_rows), 1)
            self.assertAlmostEqual(float(auc_rows[0]["auc"]), 0.4, places=4)
            self.assertAlmostEqual(float(auc_rows[0]["normalized_auc"]), 0.4 / 900.0, places=8)

            final_rows = _read_csv(root / "aggregate" / "coverage_final.csv")
            self.assertEqual(len(final_rows), 1)
            self.assertAlmostEqual(float(final_rows[0]["semantic_rate"]), 0.4, places=4)
            self.assertEqual(final_rows[0]["completed_cases"], "1")
            self.assertEqual(final_rows[0]["eligible_cases"], "1")

            threshold_rows = _read_csv(root / "aggregate" / "coverage_threshold_times.csv")
            t50 = [
                row for row in threshold_rows
                if abs(float(row["threshold"]) - 0.5) < 0.001
            ]
            self.assertEqual(len(t50), 1)
            self.assertEqual(t50[0]["threshold_reached"], "False")
            self.assertEqual(t50[0]["elapsed_wall_seconds"], "")

            overhead_rows = _read_csv(root / "aggregate" / "overhead.csv")
            self.assertEqual(len(overhead_rows), 1)
            self.assertEqual(overhead_rows[0]["completed_cases"], "1")
            self.assertEqual(overhead_rows[0]["eligible_cases"], "1")


# ==============================================================================
# Test L: Same timestamp stable by seq
# ==============================================================================

class TestL_SameTimestampStableBySeq(unittest.TestCase):
    """L: Rows with same elapsed_wall_seconds ordered by completion_seq.

    AUC computation must sort by (elapsed_wall_seconds, completion_seq) for
    deterministic results when multiple cases complete at same wall time.
    """

    def test_same_timestamp_ordered_by_seq(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _make_campaign_dir(
                root, "E1-COVERAGE-FEEDBACK", "rocket-clean",
                "random", "semantic", 101)
            metrics = campaign / "metrics"
            _write_campaign_metadata(
                metrics,
                campaign_id="auc-test-l",
                wall_clock_horizon_seconds=10,
            )
            _write_timeline(metrics, "auc-test-l", [
                (1, 3.0, 0.1),
                (2, 3.0, 0.3),  # same time, later seq, higher rate
            ])

            outputs = aggregate(root, "E1-COVERAGE-FEEDBACK")
            auc_rows = _read_csv(root / "aggregate" / "coverage_auc.csv")
            self.assertEqual(len(auc_rows), 1)
            auc1 = float(auc_rows[0]["auc"])

            # Re-run with clean output dirs
            for p in ["aggregate", "normalized", "schemas", "manifests"]:
                shutil.rmtree(root / p, ignore_errors=True)
            (root / "aggregate").mkdir()
            outputs2 = aggregate(root, "E1-COVERAGE-FEEDBACK")
            auc_rows2 = _read_csv(root / "aggregate" / "coverage_auc.csv")
            auc2 = float(auc_rows2[0]["auc"])
            self.assertEqual(auc1, auc2,
                             "AUC must be deterministic for same-timestamp rows")


# ==============================================================================
# Test M: Different DUT can have different T
# ==============================================================================

class TestM_DifferentDutDifferentT(unittest.TestCase):
    """M: Different DUTs may have different wall_clock_horizon_seconds.

    This must NOT trigger a validation error."""

    def test_different_dut_different_horizon_is_valid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for dut, horizon in [("rocket-clean", 10), ("boom-clean", 20)]:
                campaign = _make_campaign_dir(
                    root, "E1-COVERAGE-FEEDBACK", dut,
                    "random", "semantic", 101)
                metrics = campaign / "metrics"
                _write_campaign_metadata(
                    metrics,
                    campaign_id=f"auc-test-m-{dut}",
                    dut=dut,
                    wall_clock_horizon_seconds=horizon,
                )
                _write_timeline(metrics, f"auc-test-m-{dut}", [
                    (1, 2.0, 0.2),
                    (2, 5.0, 0.5),
                ], dut=dut)

            outputs = aggregate(root, "E1-COVERAGE-FEEDBACK")
            report = json.loads(
                (root / "aggregate" / "validation_report.json")
                .read_text(encoding="ascii"))
            self.assertTrue(
                report["valid"],
                f"Different DUTs with different T must be valid, "
                f"got: {report.get('errors', [])}")


# ==============================================================================
# Test N: Same DUT, different method must have same T
# ==============================================================================

class TestN_SameDutDifferentMethodSameT(unittest.TestCase):
    """N: Same DUT, different methods must share the same T.

    Cross-method consistency rule within a DUT."""

    def test_same_dut_different_method_different_horizon_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            # pmpfuzz with T=10
            campaign1 = _make_campaign_dir(
                root, "E2-BASELINE", "rocket-clean",
                "bb-wb", "semantic", 101)
            metrics1 = campaign1 / "metrics"
            _write_campaign_metadata(
                metrics1,
                experiment_id="E2-BASELINE",
                campaign_id="auc-test-n-pmpfuzz",
                method="pmpfuzz",
                variant="bb-wb",
                wall_clock_horizon_seconds=10,
                budget_class="primary-wall-clock",
            )
            _write_timeline(metrics1, "auc-test-n-pmpfuzz", [
                (1, 2.0, 0.2),
                (2, 5.0, 0.5),
            ])

            # cascade with T=20 - same DUT, different T
            campaign2 = _make_campaign_dir(
                root, "E2-BASELINE", "rocket-clean",
                "cascade", "semantic", 101)
            metrics2 = campaign2 / "metrics"
            _write_campaign_metadata(
                metrics2,
                experiment_id="E2-BASELINE",
                campaign_id="auc-test-n-cascade",
                method="cascade",
                variant="cascade",
                wall_clock_horizon_seconds=20,
                budget_class="primary-wall-clock",
            )
            _write_timeline(metrics2, "auc-test-n-cascade", [
                (1, 2.0, 0.2),
                (2, 8.0, 0.5),
            ], variant="cascade")

            outputs = aggregate(root, "E2-BASELINE")
            report = json.loads(
                (root / "aggregate" / "validation_report.json")
                .read_text(encoding="ascii"))
            self.assertFalse(
                report["valid"],
                "Same DUT with different T across methods must be invalid")
            dut_errors = [e for e in report.get("errors", [])
                          if "dut" in e.lower() and "horizon" in e.lower()]
            self.assertTrue(len(dut_errors) > 0,
                            "Must report DUT-level horizon inconsistency error")

    def test_same_dut_different_method_same_horizon_is_valid(self):
        """Same DUT, different methods, same T -> valid (no false positive)."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for method, variant in [("pmpfuzz", "bb-wb"),
                                     ("cascade", "cascade")]:
                campaign = _make_campaign_dir(
                    root, "E2-BASELINE", "rocket-clean",
                    variant, "semantic", 101)
                metrics = campaign / "metrics"
                _write_campaign_metadata(
                    metrics,
                    experiment_id="E2-BASELINE",
                    campaign_id=f"auc-test-n-valid-{method}",
                    method=method,
                    variant=variant,
                    wall_clock_horizon_seconds=10,
                    budget_class="primary-wall-clock",
                )
                _write_timeline(metrics, f"auc-test-n-valid-{method}", [
                    (1, 2.0, 0.2),
                    (2, 5.0, 0.5),
                ], variant=variant)

            outputs = aggregate(root, "E2-BASELINE")
            report = json.loads(
                (root / "aggregate" / "validation_report.json")
                .read_text(encoding="ascii"))
            dut_violations = [e for e in report.get("errors", [])
                              if "dut" in e.lower() and "horizon" in e.lower()]
            self.assertEqual(
                len(dut_violations), 0,
                f"Same T within DUT must not flag errors, "
                f"got: {dut_violations}")


# ==============================================================================
# Test O: Cross-method horizon consistency must be budget-class scoped
# ==============================================================================

class TestO_BudgetClassScoping(unittest.TestCase):
    """O: Cross-method horizon check is scoped to (experiment_id, dut, budget_class).

    Different budget classes may legitimately have different horizons for the
    same DUT.  The cross-method consistency rule only applies within a single
    budget class, not across distinct budget classes.
    """

    def test_different_budget_class_different_horizon_valid(self):
        """Same DUT, different budget classes, different positive horizons: valid.

        Current code groups cross-method horizon checks by (experiment_id, dut)
        only, which incorrectly rejects legitimate different budget classes.
        This test MUST fail on a40aca0.
        """
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            # pmpfuzz: primary budget, T=10
            c1 = _make_campaign_dir(
                root, "E-PHASE-C", "rocket-clean", "random", "semantic", 101)
            m1 = c1 / "metrics"
            _write_campaign_metadata(
                m1,
                experiment_id="E-PHASE-C",
                campaign_id="o1-pmpfuzz-primary",
                method="pmpfuzz",
                wall_clock_horizon_seconds=10,
                budget_class="primary-wall-clock",
            )
            _write_timeline(m1, "o1-pmpfuzz-primary",
                            [(1, 2.0, 0.2), (2, 5.0, 0.5)])

            # cascade: secondary budget, T=20 — different method, different budget
            c2 = _make_campaign_dir(
                root, "E-PHASE-C", "rocket-clean", "cascade-wide", "semantic", 101)
            m2 = c2 / "metrics"
            _write_campaign_metadata(
                m2,
                experiment_id="E-PHASE-C",
                campaign_id="o2-cascade-secondary",
                method="cascade",
                variant="cascade-wide",
                wall_clock_horizon_seconds=20,
                budget_class="secondary-threshold",
            )
            _write_timeline(m2, "o2-cascade-secondary",
                            [(1, 2.0, 0.2), (2, 8.0, 0.5)],
                            variant="cascade-wide")

            outputs = aggregate(root, "E-PHASE-C")
            report = json.loads(
                (root / "aggregate" / "validation_report.json")
                .read_text(encoding="ascii"))
            self.assertTrue(
                report["valid"],
                f"Different budget classes with different T must be valid; "
                f"got errors: {report.get('errors', [])}")

    def test_same_budget_class_different_methods_different_horizon_invalid(self):
        """Same budget_class, different methods, different T: invalid.

        Cross-method consistency IS required within the same budget class.
        This test documents the correct contract boundary."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            # pmpfuzz: T=10, primary budget
            c1 = _make_campaign_dir(
                root, "E-PHASE-C", "rocket-clean", "random", "semantic", 101)
            m1 = c1 / "metrics"
            _write_campaign_metadata(
                m1,
                experiment_id="E-PHASE-C",
                campaign_id="o3-pmpfuzz",
                method="pmpfuzz",
                wall_clock_horizon_seconds=10,
                budget_class="primary-wall-clock",
            )
            _write_timeline(m1, "o3-pmpfuzz",
                            [(1, 2.0, 0.2), (2, 5.0, 0.5)])

            # cascade: T=20, same primary budget
            c2 = _make_campaign_dir(
                root, "E-PHASE-C", "rocket-clean", "cascade-wide", "semantic", 101)
            m2 = c2 / "metrics"
            _write_campaign_metadata(
                m2,
                experiment_id="E-PHASE-C",
                campaign_id="o4-cascade",
                method="cascade",
                variant="cascade-wide",
                wall_clock_horizon_seconds=20,
                budget_class="primary-wall-clock",
            )
            _write_timeline(m2, "o4-cascade",
                            [(1, 2.0, 0.2), (2, 8.0, 0.5)],
                            variant="cascade-wide")

            outputs = aggregate(root, "E-PHASE-C")
            report = json.loads(
                (root / "aggregate" / "validation_report.json")
                .read_text(encoding="ascii"))
            self.assertFalse(
                report["valid"],
                "Same budget_class across different methods with "
                "different T must be invalid")
            horizon_errors = [
                e for e in report.get("errors", [])
                if "horizon" in e.lower()
                and ("inconsistent" in e.lower() or "budget_class" in e.lower())
            ]
            self.assertTrue(
                len(horizon_errors) > 0,
                "Must report horizon inconsistency error within budget class")


# ==============================================================================
# Test P: Invalid horizon values rejected fail-closed
# ==============================================================================

class TestP_InvalidHorizonValues(unittest.TestCase):
    """P: Non-numeric, zero, negative, NaN, infinity, and boolean horizons
    are rejected fail-closed without an uncaught exception.

    Uses subtests so the parameter sweep is explicit and each failure
    is reported independently.
    """

    def _make_strict_campaign(self, root, experiment_id, dut, variant, mode,
                               seed, campaign_id, horizon_value, run_class="pilot"):
        """Create a single strict campaign with a specific horizon value."""
        campaign = _make_campaign_dir(root, experiment_id, dut, variant, mode, seed)
        metrics = campaign / "metrics"
        _write_campaign_metadata(
            metrics,
            experiment_id=experiment_id,
            campaign_id=campaign_id,
            run_class=run_class,
            wall_clock_horizon_seconds=horizon_value,
        )
        _write_timeline(metrics, campaign_id,
                        [(1, 2.0, 0.2), (2, 5.0, 0.5)])
        return campaign

    def test_non_numeric_horizon_no_crash(self):
        """String 'nonsense' horizon on strict/pilot -> no crash, valid=false."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_strict_campaign(
                root, "E-PHASE-C", "rocket-clean", "random", "semantic",
                101, "p1-nonnumeric", "nonsense", run_class="pilot")

            # Must not raise — validation_report.json must be produced
            outputs = aggregate(root, "E-PHASE-C")
            report_path = root / "aggregate" / "validation_report.json"
            self.assertTrue(report_path.exists(),
                            "validation_report.json must exist after non-numeric horizon")
            report = json.loads(report_path.read_text(encoding="ascii"))
            self.assertFalse(report["valid"],
                             "Non-numeric horizon on strict campaign must be invalid")
            horizon_errors = [
                e for e in report.get("errors", [])
                if "horizon" in e.lower()
            ]
            self.assertTrue(
                len(horizon_errors) > 0,
                "Must report a precise horizon-invalid diagnostic for "
                "non-numeric value")

    def test_boolean_horizon_rejected(self):
        """Boolean True horizon on strict/formal -> invalid (not silently accepted as 1.0).

        Uses sub-horizon elapsed times so the test is NOT satisfied by a
        coincidental horizon-exceeded error.  The boolean type itself must
        be rejected.
        """
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _make_campaign_dir(
                root, "E-PHASE-C", "rocket-clean", "random", "semantic", 101)
            metrics = campaign / "metrics"
            _write_campaign_metadata(
                metrics,
                experiment_id="E-PHASE-C",
                campaign_id="p2-bool",
                run_class="formal",
                wall_clock_horizon_seconds=True,
            )
            # Timeline fits within T=1.0 (bool→1.0), so horizon_exceeded
            # will NOT fire.  The boolean must be rejected by type validation.
            _write_timeline(metrics, "p2-bool",
                            [(1, 0.3, 0.2), (2, 0.6, 0.5)])

            outputs = aggregate(root, "E-PHASE-C")
            report = json.loads(
                (root / "aggregate" / "validation_report.json")
                .read_text(encoding="ascii"))
            self.assertFalse(report["valid"],
                             "Boolean horizon on strict campaign must be invalid")
            # Check that the error specifically calls out the horizon issue
            horizon_errors = [
                e for e in report.get("errors", [])
                if "horizon" in e.lower()
            ]
            self.assertTrue(len(horizon_errors) > 0,
                            "Must have at least one horizon-specific error")

    def test_zero_negative_nan_inf_rejected(self):
        """0, negative, NaN, Infinity string: all rejected fail-closed with subtests."""
        test_cases = [
            ("zero", 0),
            ("negative", -5),
            ("nan_string", "NaN"),
            ("inf_string", "Infinity"),
            ("neg_inf_string", "-Infinity"),
        ]
        for label, value in test_cases:
            with self.subTest(label=label):
                with TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    self._make_strict_campaign(
                        root, "E-PHASE-C", "rocket-clean", "random",
                        "semantic", 101, f"p3-{label}", value,
                        run_class="pilot")

                    outputs = aggregate(root, "E-PHASE-C")
                    report = json.loads(
                        (root / "aggregate" / "validation_report.json")
                        .read_text(encoding="ascii"))
                    self.assertFalse(
                        report["valid"],
                        f"Horizon {label}={value!r} must invalidate "
                        f"strict campaign")

    def test_invalid_horizon_no_last_point_fallback(self):
        """When strict horizon is invalid, AUC must not silently fall back to last_point.

        coverage_auc.csv must not advertise horizon_source=last_point as a
        usable result.  Either horizon_source indicates invalid/missing, or
        validation makes the aggregate unusable."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_strict_campaign(
                root, "E-PHASE-C", "rocket-clean", "random", "semantic",
                101, "p4-zero", 0, run_class="pilot")

            outputs = aggregate(root, "E-PHASE-C")
            auc_rows = _read_csv(root / "aggregate" / "coverage_auc.csv")
            self.assertGreaterEqual(len(auc_rows), 1,
                                    "Must produce at least one AUC row")
            for row in auc_rows:
                source = row.get("horizon_source", "")
                self.assertNotEqual(
                    source, "last_point",
                    f"Invalid strict horizon must not fall back to "
                    f"last_point, got horizon_source={source!r}")
                # AUC fields must be null (not a misleading small number)
                auc_val = row.get("auc", "")
                self.assertTrue(
                    auc_val == "" or auc_val is None,
                    f"AUC must be null for invalid horizon, got {auc_val!r}")
                norm_auc = row.get("normalized_auc", "")
                self.assertTrue(
                    norm_auc == "" or norm_auc is None,
                    f"normalized_auc must be null for invalid horizon, "
                    f"got {norm_auc!r}")


if __name__ == "__main__":
    unittest.main()
