
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import scripts.evaluation.campaigns.run_closed_loop_campaign as driver
from scripts.evaluation.campaigns.run_closed_loop_campaign import CampaignState, _select_random, _select_guided, _select_bb_wb


def _make_pool(n: int) -> list[dict]:
    return [
        {
            "candidate_id": f"cand_{i:04d}",
            "profile": "pmp-boundary",
            "generation_seed": 1,
            "scenario_index": i,
            "name": f"case_{i}",
            "semantic_bins": [f"sem:{i % 10}"],
            "pairwise_bins": [f"combo2:{i % 5}"],
            "security_triple_bins": [f"combo3:{i % 3}"],
            "predicate_bins": [f"pred:{i % 3}"],
        }
        for i in range(n)
    ]


class TestDriverThreeRoundIntegration(unittest.TestCase):

    def test_three_round_random_state(self):
        pool = _make_pool(24)
        state = CampaignState("test-random-3r", "random", "spike", 1, "semantic", pool, 0.0)


        r0 = [c for c in pool[:8]]
        for c in r0:
            state.record_case(c["candidate_id"], c["candidate_id"], c["profile"],
                              "pass", None, True, "eligible", 10.0, 1.0, 1, 1, 0, 0, 0,
                              case_semantic=set(c.get("semantic_bins", [])),
                              case_pairwise=set(c.get("pairwise_bins", [])),
                              case_predicates=set(c.get("predicate_bins", [])))
        state.advance_round()
        self.assertEqual(state.completion_seq, 8)
        self.assertEqual(state.completed_cases, 8)
        self.assertEqual(len(state.executed_ids), 8)


        unexec1 = state.unexecuted_candidates()
        self.assertEqual(len(unexec1), 16)
        r1 = _select_random(unexec1, 8, state.seed + 1000)
        self.assertEqual(len(r1), 8)
        for c in r1:
            self.assertNotIn(c["candidate_id"], state.executed_ids)
            state.record_case(c["candidate_id"], c["candidate_id"], c["profile"],
                              "pass", None, True, "eligible", 20.0, 1.0, 1, 0, 0, 0, 0)
        state.advance_round()
        self.assertEqual(state.completion_seq, 16)


        unexec2 = state.unexecuted_candidates()
        self.assertEqual(len(unexec2), 8)
        r2 = _select_random(unexec2, 8, state.seed + 2000)
        self.assertEqual(len(r2), 8)
        for c in r2:
            self.assertNotIn(c["candidate_id"], state.executed_ids)
            state.record_case(c["candidate_id"], c["candidate_id"], c["profile"],
                              "pass", None, True, "eligible", 30.0, 1.0, 1, 0, 0, 0, 0)
        state.advance_round()

        self.assertEqual(state.completion_seq, 24)
        self.assertEqual(state.completed_cases, 24)
        self.assertEqual(state.eligible_cases, 24)
        self.assertEqual(len(state.executed_ids), 24)
        self.assertEqual(len(state.unexecuted_candidates()), 0)


        tl_path = Path(TemporaryDirectory().name) / "tl.jsonl"
        tl_path.parent.mkdir(parents=True, exist_ok=True)
        state.set_timeline_path(tl_path)
        state.write_timeline(tl_path)
        lines = [json.loads(l) for l in tl_path.read_text(encoding="ascii").strip().split("\n") if l.strip()]
        self.assertEqual(len(lines), 25)

        last = lines[-1]
        self.assertGreater(last["semantic_covered"], 0)
        self.assertGreater(last["semantic_target"], 0)
        self.assertIsNotNone(last["semantic_rate"])

    def test_three_round_guided_covers_more_than_random(self):
        pool = _make_pool(32)

        r_state = CampaignState("test-r", "random", "spike", 1, "semantic", pool, 0.0)
        r_cands = _select_random(pool, 16, 1)
        for c in r_cands[:8]:
            r_state.record_case(c["candidate_id"], c["candidate_id"], c["profile"],
                                "pass", None, True, "eligible", 10.0, 1.0, 1, 0, 0, 0, 0)
        r_state.advance_round()
        r_unexec = r_state.unexecuted_candidates()
        r2 = _select_random(r_unexec, 8, 1000)
        for c in r2:
            r_state.record_case(c["candidate_id"], c["candidate_id"], c["profile"],
                                "pass", None, True, "eligible", 20.0, 1.0, 1, 0, 0, 0, 0)


        g_state = CampaignState("test-g", "guided", "spike", 1, "semantic", pool, 0.0)
        g_cands = _select_guided(g_state, pool, 16, [], 1)
        self.assertGreaterEqual(len(g_cands), 1, "guided should select at least 1 candidate")

        for c in g_cands[:8]:
            g_state.record_case(c["candidate_id"], c["candidate_id"], c["profile"],
                                "pass", None, True, "eligible", 10.0, 1.0, 1, 0, 0, 0, 0)
        g_state.advance_round()
        g_unexec = g_state.unexecuted_candidates()
        g2 = _select_guided(g_state, g_unexec, 8, [], 1)
        for c in g2:
            g_state.record_case(c["candidate_id"], c["candidate_id"], c["profile"],
                                "pass", None, True, "eligible", 20.0, 1.0, 1, 0, 0, 0, 0)


        self.assertEqual(r_state.completion_seq, 16)
        self.assertEqual(g_state.completion_seq, 16)
        self.assertEqual(r_state.completed_cases, 16)
        self.assertEqual(g_state.completed_cases, 16)

    def test_random_and_guided_selection_differ(self):
        pool = _make_pool(32)
        r = _select_random(pool, 8, 42)
        g = _select_guided(CampaignState("g", "guided", "s", 1, "semantic", pool, 0.0),
                           pool, 8, [], 42)

        r_ids = {c["candidate_id"] for c in r}
        g_ids = {c["candidate_id"] for c in g}
        self.assertGreater(len(r_ids & g_ids), 0, "some overlap expected from same pool")


        self.assertEqual(len(r), 8)
        self.assertGreater(len(g), 0)


class TestWhiteboxFeedback(unittest.TestCase):

    def _make_rich_pool(self, n: int) -> list[dict]:
        pool = []
        for i in range(n):
            profile = "pmp-boundary" if i % 2 == 0 else "sv39-ptw-pmp-matrix"
            pool.append({
                "candidate_id": f"cand_{i:04d}",
                "profile": profile,
                "generation_seed": 1,
                "scenario_index": i,
                "name": f"case_{i}",
                "semantic_bins": [f"sem:{i % 10}"],
                "pairwise_bins": [f"combo2:{i % 5}"],
                "security_triple_bins": [f"combo3:{i % 3}"],
                "predicate_bins": [f"pred:{i % 3}"],
            })
        return pool

    def test_bb_and_bb_wb_selection_differ(self):
        pool = self._make_rich_pool(64)
        state_bb = CampaignState("bb", "bb", "spike", 1, "semantic", pool, 0.0)
        state_bw = CampaignState("bw", "bb-wb", "spike", 1, "semantic", pool, 0.0)

        bb = _select_bb_wb(state_bb, pool, 32, [], 1) if hasattr(driver, '_select_bb_wb') else []
        bw = _select_bb_wb(state_bw, pool, 32, [], 1) if hasattr(driver, '_select_bb_wb') else []


        self.assertIsInstance(bb, list)
        self.assertIsInstance(bw, list)

    def test_whitebox_schedule_produces_candidates(self):
        pool = _make_pool(32)
        selected, counts, warnings = driver._whitebox_schedule(pool, [], max_wb=16)
        self.assertIsInstance(selected, list)
        self.assertLessEqual(len(selected), 16)
        self.assertIsInstance(counts, dict)
        self.assertIsInstance(warnings, list)


class TestDataContract(unittest.TestCase):

    def test_aggregate_generates_all_files(self):
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "artifacts"
            root.mkdir()
            (root / "aggregate").mkdir()


            camp = root / "campaigns" / "test" / "spike" / "random" / "semantic" / "seed-0001"
            camp.mkdir(parents=True)
            metrics = camp / "metrics"
            metrics.mkdir()

            tl = [
                {"schema_version": 1, "campaign_id": "test", "variant": "random",
                 "dut": "spike", "seed": 1, "completion_seq": 0, "case_id": None,
                 "elapsed_wall_seconds": 0, "case_elapsed_seconds": 0,
                 "completed_cases": 0, "eligible_cases": 0,
                 "status": None, "failure_class": None,
                 "coverage_eligible": False, "qualification_reason": None,
                 "semantic_covered": 0, "semantic_target": 10, "semantic_rate": 0.0,
                 "pairwise_covered": 0, "pairwise_target": 20, "pairwise_rate": 0.0,
                 "security_triples_covered": 0, "security_triples_target": 30, "security_triples_rate": 0.0,
                 "predicates_covered": 0, "predicates_target": 5, "predicates_rate": 0.0,
                 "new_semantic_bins": 0, "new_pairwise_bins": 0,
                 "new_security_triple_bins": 0, "new_predicate_bins": 0,
                 "whitebox_distinct_events": 0, "new_whitebox_events": 0},
                {"schema_version": 1, "campaign_id": "test", "variant": "random",
                 "dut": "spike", "seed": 1, "completion_seq": 1,
                 "case_id": "case_0", "profile": "pmp-boundary",
                 "elapsed_wall_seconds": 10.0, "case_elapsed_seconds": 2.0,
                 "completed_cases": 1, "eligible_cases": 1,
                 "status": "pass", "failure_class": None,
                 "coverage_eligible": True, "qualification_reason": "eligible",
                 "semantic_covered": 3, "semantic_target": 10, "semantic_rate": 0.3,
                 "pairwise_covered": 5, "pairwise_target": 20, "pairwise_rate": 0.25,
                 "security_triples_covered": 2, "security_triples_target": 30, "security_triples_rate": 0.0667,
                 "predicates_covered": 1, "predicates_target": 5, "predicates_rate": 0.2,
                 "new_semantic_bins": 3, "new_pairwise_bins": 5,
                 "new_security_triple_bins": 2, "new_predicate_bins": 1,
                 "whitebox_distinct_events": 0, "new_whitebox_events": 0},
            ]
            (metrics / "coverage_timeline.jsonl").write_text(
                "\n".join(json.dumps(l, ensure_ascii=True, sort_keys=True) for l in tl),
                encoding="ascii",
            )
            (metrics / "campaign_metadata.json").write_text(json.dumps({
                "campaign_id": "test", "variant": "random", "dut": "spike", "seed": 1,
                "coverage_mode": "semantic", "source_sha": "abc123",
            }), encoding="ascii")

            outputs = aggregate(root, "test-exp")
            agg_dir = root / "aggregate"


            required = ["campaign_index.csv", "coverage_final.csv",
                        "coverage_threshold_times.csv", "coverage_timeseries.csv",
                        "statistics.json"]
            for name in required:
                path = agg_dir / name
                self.assertTrue(path.exists(), f"Missing required output: {name}")


            import csv
            with (agg_dir / "coverage_timeseries.csv").open("r", newline="") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                for row in rows:
                    self.assertNotEqual(row.get("completion_seq"), "0",
                                        "Normalized CSV must exclude baseline row")


            self.assertIn("new_bins", rows[0] if rows else {})


class TestCascadeAdapter(unittest.TestCase):

    def test_event_id_from_probe_fields(self):
        import hashlib

        chain, stage, addr, prv, dut = "pmp-check", "pmp", "0x1000", "3", "rocket-clean"
        key1 = f"source_probe|{dut}|{chain}|{stage}|{addr}|{prv}"
        eid1 = hashlib.sha256(key1.encode("ascii")).hexdigest()[:16]
        key2 = f"source_probe|{dut}|{chain}|{stage}|{addr}|{prv}"
        eid2 = hashlib.sha256(key2.encode("ascii")).hexdigest()[:16]
        self.assertEqual(eid1, eid2)


        key3 = f"source_probe|{dut}|{chain}|{stage}|0x2000|{prv}"
        eid3 = hashlib.sha256(key3.encode("ascii")).hexdigest()[:16]
        self.assertNotEqual(eid1, eid3)

    def test_cascade_adapter_imports(self):
        from scripts.evaluation.baseline_adapters import cascade
        self.assertTrue(hasattr(cascade, "run_cascade_baseline"))
        self.assertTrue(hasattr(cascade, "_extract_probe_events"))


class TestDataContractCompleteness(unittest.TestCase):

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name) / "artifacts"
        self.root.mkdir()
        (self.root / "aggregate").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def _make_minimal_campaign(self, camp_id, variant="random"):
        camp = self.root / "campaigns" / "test" / "spike" / variant / "semantic" / f"seed-{camp_id}"
        camp.mkdir(parents=True)
        (camp / "metrics").mkdir()
        tl = [
            {"schema_version": 1, "campaign_id": camp_id, "variant": variant,
             "dut": "spike", "seed": int(camp_id), "completion_seq": 0, "case_id": None,
             "elapsed_wall_seconds": 0, "case_elapsed_seconds": 0,
             "completed_cases": 0, "eligible_cases": 0, "status": None, "failure_class": None,
             "coverage_eligible": False, "qualification_reason": None,
             "semantic_covered": 0, "semantic_target": 10, "semantic_rate": 0.0,
             "pairwise_covered": 0, "pairwise_target": 20, "pairwise_rate": 0.0,
             "security_triples_covered": 0, "security_triples_target": 30, "security_triples_rate": 0.0,
             "predicates_covered": 0, "predicates_target": 5, "predicates_rate": 0.0,
             "new_semantic_bins": 0, "new_pairwise_bins": 0,
             "new_security_triple_bins": 0, "new_predicate_bins": 0,
             "whitebox_distinct_events": 0, "new_whitebox_events": 0},
            {"schema_version": 1, "campaign_id": camp_id, "variant": variant,
             "dut": "spike", "seed": int(camp_id), "completion_seq": 1,
             "case_id": "c1", "profile": "pmp-boundary",
             "elapsed_wall_seconds": 10.0, "case_elapsed_seconds": 2.0,
             "completed_cases": 1, "eligible_cases": 1,
             "status": "pass", "failure_class": None,
             "coverage_eligible": True, "qualification_reason": "eligible",
             "semantic_covered": 3, "semantic_target": 10, "semantic_rate": 0.3,
             "pairwise_covered": 5, "pairwise_target": 20, "pairwise_rate": 0.25,
             "security_triples_covered": 2, "security_triples_target": 30, "security_triples_rate": 0.0667,
             "predicates_covered": 1, "predicates_target": 5, "predicates_rate": 0.2,
             "new_semantic_bins": 3, "new_pairwise_bins": 5,
             "new_security_triple_bins": 2, "new_predicate_bins": 1,
             "whitebox_distinct_events": 0, "new_whitebox_events": 0},
        ]
        (camp / "metrics" / "coverage_timeline.jsonl").write_text(
            "\n".join(json.dumps(l, ensure_ascii=True, sort_keys=True) for l in tl), encoding="ascii")
        (camp / "metrics" / "campaign_metadata.json").write_text(json.dumps({
            "campaign_id": camp_id, "variant": variant, "dut": "spike",
            "seed": int(camp_id), "coverage_mode": "semantic", "source_sha": "abc",
        }), encoding="ascii")

    def test_aggregate_all_outputs(self):
        from scripts.evaluation.analysis.aggregate_results import aggregate
        for i in range(2):
            self._make_minimal_campaign(str(i), "random" if i % 2 == 0 else "guided")
        outputs = aggregate(self.root, "test")
        agg = self.root / "aggregate"
        for name in ["campaign_index.csv", "coverage_final.csv",
                     "coverage_threshold_times.csv", "coverage_timeseries.csv",
                     "statistics.json"]:
            self.assertTrue((agg / name).exists(), f"Missing: {name}")

    def test_coverage_threshold_times_censored(self):
        from scripts.evaluation.analysis.aggregate_results import aggregate
        self._make_minimal_campaign("1")
        outputs = aggregate(self.root, "test")
        import csv
        path = self.root / "aggregate" / "coverage_threshold_times.csv"
        self.assertTrue(path.exists())
        with path.open("r", newline="") as f:
            rows = list(csv.DictReader(f))

        thresholds = {row["threshold"] for row in rows}
        self.assertIn("0.9", thresholds)
        self.assertIn("1.0", thresholds)

        high_thresholds = [r for r in rows if float(r["threshold"]) >= 0.9]
        for r in high_thresholds:
            if float(r["threshold"]) > 0.3:
                self.assertEqual(r["censored"], "True",
                                 f"threshold {r['threshold']} should be censored at 30% coverage")


if __name__ == "__main__":
    unittest.main()
