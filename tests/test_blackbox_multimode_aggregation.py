
import csv
import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import sys

_script_dir = Path(__file__).resolve().parents[1]
if str(_script_dir) not in sys.path:
    sys.path.insert(0, str(_script_dir))

from pmpfuzz.coverage_universe import make_coverage_universe

NL = chr(10)
ALL_FOUR = ["semantic", "pairwise", "security-triples", "predicates"]



def _tl_row(**kw):
    return {
        "schema_version": 1, "campaign_id": kw.get("cid", "test"),
        "variant": kw.get("variant", "random"), "dut": "rocket-clean",
        "seed": kw.get("seed", 101), "completion_seq": kw.get("seq", 0),
        "case_id": kw.get("case_id"),
        "elapsed_wall_seconds": 0, "case_elapsed_seconds": 0,
        "completed_cases": 0, "eligible_cases": 0,
        "status": None, "failure_class": None,
        "coverage_eligible": False, "qualification_reason": None,
        "semantic_covered": 0, "semantic_target": 313, "semantic_rate": 0.0,
        "pairwise_covered": 0, "pairwise_target": 3691, "pairwise_rate": 0.0,
        "security_triples_covered": 0, "security_triples_target": 225,
        "security_triples_rate": 0.0,
        "predicates_covered": 0, "predicates_target": 41, "predicates_rate": 0.0,
        "new_semantic_bins": 0, "new_pairwise_bins": 0,
        "new_security_triple_bins": 0, "new_predicate_bins": 0,
        "whitebox_distinct_events": 0, "new_whitebox_events": 0,
    }


def _write_timeline(metrics_dir, cid="test", variant="random", seed=101,
                    partial_drop=None, rows_count=3):
    rows = [_tl_row(cid=cid, variant=variant, seed=seed, seq=0)]
    DENOMS = {"semantic": 313, "pairwise": 3691, "security-triples": 225, "predicates": 41}
    for i in range(1, rows_count + 1):

        s_cov = int(0.1 * i * 313)
        p_cov = int(0.1 * i * 3691)
        t_cov = int(0.1 * i * 225)
        pr_cov = int(0.1 * i * 41)
        rows.append({**_tl_row(cid=cid, variant=variant, seed=seed),
                     "completion_seq": i, "case_id": f"c-{i}",
                     "elapsed_wall_seconds": i * 5.0,
                     "completed_cases": i, "eligible_cases": i,
                     "status": "pass", "coverage_eligible": True,
                     "qualification_reason": "eligible",
                     "semantic_covered": s_cov,
                     "semantic_rate": s_cov / 313,
                     "pairwise_covered": p_cov,
                     "pairwise_rate": p_cov / 3691,
                     "security_triples_covered": t_cov,
                     "security_triples_rate": t_cov / 225,
                     "predicates_covered": pr_cov,
                     "predicates_rate": pr_cov / 41,
                     "new_semantic_bins": 10, "new_pairwise_bins": 5,
                     "new_security_triple_bins": 3, "new_predicate_bins": 2,
                     })
    if partial_drop:
        drop_keys = {
            "semantic": ["semantic_covered", "semantic_target", "semantic_rate", "new_semantic_bins"],
            "pairwise": ["pairwise_covered", "pairwise_target", "pairwise_rate", "new_pairwise_bins"],
            "security-triples": ["security_triples_covered", "security_triples_target",
                                 "security_triples_rate", "new_security_triple_bins"],
            "predicates": ["predicates_covered", "predicates_target", "predicates_rate", "new_predicate_bins"],
        }
        for row in rows:
            for k in drop_keys.get(partial_drop, []):
                row.pop(k, None)
    (metrics_dir / "coverage_timeline.jsonl").write_text(
        NL.join(json.dumps(r, ensure_ascii=True, sort_keys=True) for r in rows) + NL,
        encoding="ascii")


def _write_validation(camp):
    bindings = {}
    for label, rel_path in (
        ("metadata", Path("metrics/campaign_metadata.json")),
        ("timeline", Path("metrics/coverage_timeline.jsonl")),
    ):
        path = camp / rel_path
        if path.exists():
            bindings[label] = {
                "path": str(rel_path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
    campaign_id = json.loads((camp / "metrics/campaign_metadata.json").read_text(encoding="ascii")).get("campaign_id")
    (camp / "validation.json").write_text(json.dumps({
        "schema_version": "1.0",
        "campaign_id": campaign_id,
        "valid": True,
        "error_count": 0,
        "warning_count": 0,
        "inputs": bindings,
    }, ensure_ascii=True), encoding="ascii")


def _make_campaign(root, cid, variant="random", seed=101, partial_drop=None,
                   write_val=True, rows_count=3):
    camp = (root / "campaigns" / "test-exp" / "rocket-clean"
            / variant / "semantic" / f"seed-{seed:04d}")
    camp.mkdir(parents=True)
    (camp / "metrics").mkdir()
    _write_timeline(camp / "metrics", cid, variant, seed, partial_drop, rows_count)
    (camp / "metrics/campaign_metadata.json").write_text(json.dumps({
        "campaign_id": cid, "variant": variant, "dut": "rocket-clean",
        "seed": seed, "coverage_mode": "semantic", "run_class": "pilot",
        "budget_class": "primary-wall-clock",
        "wall_clock_horizon_seconds": 1800,
        "source_sha": "a" * 40, "method": "pmpfuzz",
        "driver_mode": "continuous",
        "coverage_schema": "pmpfuzz-v1-four-mode",
    }, ensure_ascii=True), encoding="ascii")
    if write_val:
        _write_validation(camp)
    return camp


def _write_scope(root, overrides=None):
    (root / "manifests").mkdir(parents=True, exist_ok=True)
    data = {
        "schema_version": 1, "analysis_id": "TEST",
        "run_class": "pilot",
        "guidance_mode": "semantic",
        "primary_metric": "semantic",
        "primary_variants": ["random", "bb"],
        "primary_seeds": [101],
        "coverage_modes": ALL_FOUR,
        "whitebox_event_coverage": {"status": "not_applicable",
                                    "reason": "Black-box pilot."},
        "expected_rows_per_campaign_mode": 3,
    }
    if overrides:
        data.update(overrides)
    (root / "manifests/analysis-scope.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=True), encoding="ascii")


def _run_aggregate(root):
    from scripts.evaluation.analysis.aggregate_results import aggregate
    aggregate(root, "test-exp")
    vr = root / "aggregate/validation_report.json"
    return json.loads(vr.read_text(encoding="ascii"))


def _write_coverage_universes(
    campaign: Path,
    *,
    generator_seed: int,
    semantic_bin_ids=None,
    pairwise_bin_ids=None,
    security_triples_bin_ids=None,
    predicates_bin_ids=None,
):
    universe_dir = campaign / "metrics" / "coverage_universe"
    universe_dir.mkdir(parents=True, exist_ok=True)
    mode_specs = {
        "semantic": ("semantic", semantic_bin_ids or ["sem:0", "sem:1"]),
        "pairwise": ("pairwise", pairwise_bin_ids or ["pair:0"]),
        "security_triples": ("security_triples", security_triples_bin_ids or ["triple:0"]),
        "predicates": ("predicates", predicates_bin_ids or ["pred:0"]),
    }
    files = {}
    hashes = {}
    for mode, (coverage_mode, bin_ids) in mode_specs.items():
        universe = make_coverage_universe(
            coverage_mode=coverage_mode,
            bin_ids=bin_ids,
            capability_fingerprint="cap-1",
            target="core-stateful",
            include_experimental=False,
            generator_seed=generator_seed,
            generation_rule_version="v1",
        )
        path = universe_dir / f"{mode}_v1.json"
        path.write_text(json.dumps(universe, indent=2, ensure_ascii=True), encoding="ascii")
        files[mode] = str(path.relative_to(campaign))
        hashes[mode] = universe["sha256"]
    meta_path = campaign / "metrics" / "campaign_metadata.json"
    meta = json.loads(meta_path.read_text(encoding="ascii"))
    meta["coverage_universe_files"] = files
    meta["coverage_universe_hashes"] = hashes
    meta_path.write_text(json.dumps(meta, ensure_ascii=True), encoding="ascii")
    _write_validation(campaign)






class TestNoScopeEmptyEvents(unittest.TestCase):

    def test_no_scope_empty_events_must_be_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_campaign(root, "no-scope", rows_count=3)
            report = _run_aggregate(root)
            self.assertFalse(report["valid"],
                             "No analysis-scope with empty events must be invalid")
            errors = [e for e in report.get("errors", [])
                      if "analysis_scope" in e.lower() or "scope" in e.lower()]
            self.assertTrue(len(errors) > 0,
                            f"Must have scope-related error, got: {report.get('errors')}")






class TestBBWBEmptyEventsAlwaysFail(unittest.TestCase):

    def test_bbwb_empty_events_without_scope(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_campaign(root, "bbwb-no-scope", variant="bb-wb", rows_count=3)
            report = _run_aggregate(root)
            self.assertFalse(report["valid"],
                             "bb-wb + empty events must be invalid (no scope)")
            errors = [e for e in report.get("errors", [])
                      if "bbwb" in e.lower() or "bb-wb" in e.lower() or "event" in e.lower()]
            self.assertTrue(len(errors) > 0,
                            f"Must have bbwb/event error, got: {report.get('errors')}")

    def test_bbwb_empty_events_with_scope(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_campaign(root, "bbwb-scoped", variant="bb-wb", rows_count=3)
            _write_scope(root, {"primary_variants": ["random", "bb", "bb-wb"]})
            report = _run_aggregate(root)
            self.assertFalse(report["valid"],
                             "bb-wb + empty events must be invalid even with scope")
            errors = [e for e in report.get("errors", [])
                      if "bbwb" in e.lower() or "bb-wb" in e.lower() or "event" in e.lower()]
            self.assertTrue(len(errors) > 0,
                            f"Must have bbwb/event error, got: {report.get('errors')}")






class TestPartialModesFailClosed(unittest.TestCase):

    def test_missing_predicates_must_be_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_campaign(root, "partial", partial_drop="predicates", rows_count=3)
            _write_scope(root)
            report = _run_aggregate(root)
            self.assertFalse(report["valid"],
                             "Missing predicates fields must cause valid=False")
            errors = [e for e in report.get("errors", [])
                      if "predicates" in e.lower() or "coverage_mode" in e.lower()
                      or "incomplete" in e.lower() or "missing" in e.lower()]
            self.assertTrue(len(errors) > 0,
                            f"Must have mode-related error, got: {report.get('errors')}")

    def test_partial_no_scope_must_be_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_campaign(root, "partial-ns", partial_drop="predicates", rows_count=3)
            report = _run_aggregate(root)
            self.assertFalse(report["valid"],
                             "Incomplete PMPFuzz fields must be invalid without scope")

    def test_declared_multimode_zero_coverage_still_requires_all_modes(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            camp = _make_campaign(root, "zero-still-multimode", rows_count=3)
            tl_path = camp / "metrics" / "coverage_timeline.jsonl"
            rows = [json.loads(line) for line in tl_path.read_text(encoding="ascii").splitlines() if line.strip()]
            for row in rows:
                if int(row.get("completion_seq", 0)) <= 0:
                    continue
                row["pairwise_covered"] = 0
                row["pairwise_rate"] = 0.0
                row["new_pairwise_bins"] = 0
                row["security_triples_covered"] = 0
                row["security_triples_rate"] = 0.0
                row["new_security_triple_bins"] = 0
                row.pop("predicates_covered", None)
                row.pop("predicates_target", None)
                row.pop("predicates_rate", None)
                row.pop("new_predicate_bins", None)
            tl_path.write_text(
                NL.join(json.dumps(r, ensure_ascii=True, sort_keys=True) for r in rows) + NL,
                encoding="ascii",
            )
            meta_path = camp / "metrics" / "campaign_metadata.json"
            meta = json.loads(meta_path.read_text(encoding="ascii"))
            meta["driver_mode"] = "continuous"
            meta["coverage_schema"] = "pmpfuzz-v1-four-mode"
            meta_path.write_text(json.dumps(meta, ensure_ascii=True), encoding="ascii")
            _write_validation(camp)
            _write_scope(root)

            report = _run_aggregate(root)

            self.assertFalse(report["valid"])
            self.assertTrue(any("predicates" in err.lower() for err in report.get("errors", [])))






class TestCartesianBypass(unittest.TestCase):

    def test_bb_missing_three_modes_must_fail(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_campaign(root, "r-full", variant="random", rows_count=3)
            _make_campaign(root, "bb-partial", variant="bb", partial_drop="predicates",
                           rows_count=3)
            _write_scope(root)
            report = _run_aggregate(root)
            self.assertFalse(report["valid"],
                             "BB missing modes must produce valid=False")
            errors = report.get("errors", [])

            pred_errs = [e for e in errors if "predicates" in e.lower()]
            self.assertTrue(len(pred_errs) > 0,
                            f"Must report missing predicates, got: {errors}")






class TestScopedHappyPath(unittest.TestCase):

    def test_random_and_bb_full_four_modes_must_pass(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_campaign(root, "r-happy", variant="random", rows_count=3)
            _make_campaign(root, "bb-happy", variant="bb", rows_count=3)
            _write_scope(root)
            report = _run_aggregate(root)
            self.assertTrue(report["valid"],
                            f"Happy path must be valid, got errors: {report.get('errors')}")






class TestCoverageUniverseComparability(unittest.TestCase):

    def test_same_bin_ids_with_different_generator_seed_remain_comparable(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            random_campaign = _make_campaign(root, "r-compare", variant="random", seed=101, rows_count=3)
            bb_campaign = _make_campaign(root, "bb-compare", variant="bb", seed=101, rows_count=3)
            _write_coverage_universes(random_campaign, generator_seed=1)
            _write_coverage_universes(bb_campaign, generator_seed=2)
            _write_scope(root)

            report = _run_aggregate(root)

            self.assertTrue(
                report["valid"],
                f"Same bin_ids with different generator_seed should stay comparable, got {report.get('errors')}",
            )

    def test_different_bin_ids_fail_closed_even_when_generator_seed_differs(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            random_campaign = _make_campaign(root, "r-universe", variant="random", seed=101, rows_count=3)
            bb_campaign = _make_campaign(root, "bb-universe", variant="bb", seed=101, rows_count=3)
            _write_coverage_universes(random_campaign, generator_seed=1)
            _write_coverage_universes(
                bb_campaign,
                generator_seed=2,
                semantic_bin_ids=["sem:0", "sem:2"],
            )
            _write_scope(root)

            report = _run_aggregate(root)

            self.assertFalse(
                report["valid"],
                "Different bin_ids must fail closed even when complete provenance hashes are allowed to differ",
            )
            self.assertTrue(
                any("universe" in err.lower() or "bin_set_sha256" in err.lower() for err in report.get("errors", [])),
                report.get("errors", []),
            )


class TestLegacyBaseline(unittest.TestCase):

    def test_legacy_single_mode(self):
        from scripts.evaluation.analysis.aggregate_results import aggregate
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            camp = (root / "campaigns" / "legacy" / "spike" / "guided"
                    / "semantic" / "seed-0001")
            camp.mkdir(parents=True)
            (camp / "metrics").mkdir()
            tl = [
                {"schema_version": 1, "campaign_id": "leg", "variant": "guided",
                 "dut": "spike", "seed": 1, "completion_seq": 0, "case_id": None,
                 "elapsed_wall_seconds": 0, "completed_cases": 0, "eligible_cases": 0,
                 "semantic_covered": 0, "semantic_target": 10, "semantic_rate": 0.0},
                {"schema_version": 1, "campaign_id": "leg", "variant": "guided",
                 "dut": "spike", "seed": 1, "completion_seq": 1, "case_id": "c1",
                 "elapsed_wall_seconds": 5.0, "completed_cases": 1, "eligible_cases": 1,
                 "status": "pass", "coverage_eligible": True,
                 "semantic_covered": 3, "semantic_target": 10, "semantic_rate": 0.3},
            ]
            (camp / "metrics/coverage_timeline.jsonl").write_text(
                NL.join(json.dumps(r, ensure_ascii=True, sort_keys=True) for r in tl) + NL,
                encoding="ascii")
            (camp / "metrics/campaign_metadata.json").write_text(json.dumps({
                "campaign_id": "leg", "variant": "guided", "dut": "spike", "seed": 1,
                "coverage_mode": "semantic", "run_class": "pilot",
                "wall_clock_horizon_seconds": 300, "source_sha": "x" * 40,
                "budget_class": "primary-wall-clock", "method": "cascade",
            }, ensure_ascii=True), encoding="ascii")
            (camp / "validation.json").write_text(json.dumps({
                "valid": True, "error_count": 0, "warning_count": 0,
            }, ensure_ascii=True), encoding="ascii")
            _write_validation(camp)
            aggregate(root, "test-exp")
            with (root / "normalized/coverage_timeseries.csv").open(newline="") as f:
                rows = list(csv.DictReader(f))
            modes = {r["coverage_mode"] for r in rows}
            self.assertEqual({"semantic"}, modes)

    def test_legacy_with_extra_fields_stays_single(self):
        from scripts.evaluation.analysis.aggregate_results import aggregate
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            camp = (root / "campaigns" / "cascade" / "spike" / "cascade-default"
                    / "semantic" / "seed-0001")
            camp.mkdir(parents=True)
            (camp / "metrics").mkdir()
            tl = [
                {"schema_version": 1, "campaign_id": "cas", "variant": "cascade-default",
                 "dut": "spike", "seed": 1, "completion_seq": 0, "case_id": None,
                 "elapsed_wall_seconds": 0, "completed_cases": 0, "eligible_cases": 0,
                 "semantic_covered": 0, "semantic_target": 10, "semantic_rate": 0.0,
                 "pairwise_covered": 0, "pairwise_target": 20, "pairwise_rate": 0.0,
                 "predicates_covered": 0, "predicates_target": 5, "predicates_rate": 0.0,
                 },
                {"schema_version": 1, "campaign_id": "cas", "variant": "cascade-default",
                 "dut": "spike", "seed": 1, "completion_seq": 1, "case_id": "c1",
                 "elapsed_wall_seconds": 5.0, "completed_cases": 1, "eligible_cases": 1,
                 "status": "pass", "coverage_eligible": True,
                 "semantic_covered": 3, "semantic_target": 10, "semantic_rate": 0.3,
                 "pairwise_covered": 5, "pairwise_target": 20, "pairwise_rate": 0.25,
                 "predicates_covered": 1, "predicates_target": 5, "predicates_rate": 0.2,
                 },
            ]
            (camp / "metrics/coverage_timeline.jsonl").write_text(
                NL.join(json.dumps(r, ensure_ascii=True, sort_keys=True) for r in tl) + NL,
                encoding="ascii")
            (camp / "metrics/campaign_metadata.json").write_text(json.dumps({
                "campaign_id": "cas", "variant": "cascade-default",
                "dut": "spike", "seed": 1, "coverage_mode": "semantic",
                "method": "cascade", "run_class": "pilot",
                "wall_clock_horizon_seconds": 300, "source_sha": "x" * 40,
                "budget_class": "primary-wall-clock",
            }, ensure_ascii=True), encoding="ascii")
            (camp / "validation.json").write_text(json.dumps({
                "valid": True, "error_count": 0, "warning_count": 0,
            }, ensure_ascii=True), encoding="ascii")
            _write_validation(camp)
            aggregate(root, "test-exp")
            with (root / "normalized/coverage_timeseries.csv").open(newline="") as f:
                rows = list(csv.DictReader(f))
            modes = {r["coverage_mode"] for r in rows}
            self.assertEqual({"semantic"}, modes,
                             f"Cascade must stay single-mode, got {modes}")






class TestFourModeFields(unittest.TestCase):

    def test_all_four_present_and_correct(self):
        from scripts.evaluation.analysis.aggregate_results import aggregate
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            camp = _make_campaign(root, "fields", rows_count=3)
            (camp / "metrics/campaign_metadata.json").write_text(json.dumps({
                "campaign_id": "fields", "variant": "random", "dut": "rocket-clean",
                "seed": 101, "coverage_mode": "semantic", "run_class": "pilot",
                "budget_class": "primary-wall-clock",
                "wall_clock_horizon_seconds": 1800,
                "source_sha": "a" * 40, "method": "pmpfuzz",
                "driver_mode": "continuous",
                "coverage_schema": "pmpfuzz-v1-four-mode",
            }, ensure_ascii=True), encoding="ascii")
            aggregate(root, "test-exp")
            with (root / "normalized/coverage_timeseries.csv").open(newline="") as f:
                rows = list(csv.DictReader(f))
            modes = {r["coverage_mode"] for r in rows}
            self.assertEqual(set(ALL_FOUR), modes)
            by_mode = {}
            for r in rows:
                by_mode.setdefault(r["coverage_mode"], []).append(r)

            for mode, denom in [("semantic", "313"), ("pairwise", "3691"),
                                ("security-triples", "225"), ("predicates", "41")]:
                mr = by_mode[mode]
                self.assertGreater(len(mr), 0)
                self.assertEqual(mr[-1]["target_bins"], denom)


class TestAdditionalMultimodeGuards(unittest.TestCase):

    def test_same_variant_seed_different_dut_cannot_fill_missing_modes(self):
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_campaign(root, "rocket-full", variant="random", seed=101, rows_count=3)
            camp = (root / "campaigns" / "test-exp" / "boom-clean"
                    / "random" / "semantic" / "seed-0101")
            camp.mkdir(parents=True)
            (camp / "metrics").mkdir()
            _write_timeline(camp / "metrics", cid="boom-partial", variant="random", seed=101,
                            partial_drop="predicates", rows_count=3)
            (camp / "metrics/campaign_metadata.json").write_text(json.dumps({
                "campaign_id": "boom-partial", "variant": "random", "dut": "boom-clean",
                "seed": 101, "coverage_mode": "semantic", "run_class": "pilot",
                "budget_class": "primary-wall-clock",
                "wall_clock_horizon_seconds": 1800,
                "source_sha": "a" * 40, "method": "pmpfuzz",
                "driver_mode": "continuous",
                "coverage_schema": "pmpfuzz-v1-four-mode",
            }, ensure_ascii=True), encoding="ascii")
            _write_validation(camp)
            _write_scope(root)

            aggregate(root, "test-exp")
            report = json.loads((root / "aggregate/validation_report.json").read_text(encoding="ascii"))

            self.assertFalse(report["valid"])
            self.assertTrue(any("boom-partial" in err for err in report.get("errors", [])))


if __name__ == "__main__":
    raise SystemExit(
        0 if unittest.main(verbosity=2, exit=False).result.wasSuccessful() else 1)
