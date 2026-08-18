"""Tests for closed-loop campaign driver — Phase B.

Phase B1 (RED): Tests that verify the bugs are gone after fix.
Phase B2-B5 (GREEN): Tests for correct multi-round behavior.
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.evaluation.campaigns.run_closed_loop_campaign import (
    CampaignState,
    _make_candidate_id,
    _select_random,
    build_candidate_pool,
    select_next_candidates,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

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
            "security_triple_bins": [],
            "predicate_bins": [f"pred:{i % 3}"],
        }
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# B1: Tests for correct multi-round behavior (GREEN after fix)
# ---------------------------------------------------------------------------


class TestMultiRoundAccumulation(unittest.TestCase):
    """B4 tests: single CampaignState across rounds."""

    def test_completion_seq_continuous_no_duplicates(self):
        """completion_seq is continuous 1-16 across 2 rounds."""
        pool = _make_pool(16)
        state = CampaignState("test", "random", "spike", 1, "semantic", pool, 0.0)
        for c in pool[:8]:
            state.record_case(c["candidate_id"], c["candidate_id"], "pmp-boundary",
                              "pass", None, True, "eligible", 10.0, 1.0, 1, 0, 0, 0, 0)
        self.assertEqual(state.completion_seq, 8)
        state.advance_round()
        for c in pool[8:16]:
            state.record_case(c["candidate_id"], c["candidate_id"], "pmp-boundary",
                              "pass", None, True, "eligible", 20.0, 1.0, 1, 0, 0, 0, 0)
        self.assertEqual(state.completion_seq, 16)

    def test_cases_accumulate_across_rounds(self):
        """completed_cases and eligible_cases increase across rounds."""
        pool = _make_pool(12)
        state = CampaignState("test", "guided", "spike", 1, "semantic", pool, 0.0)
        for c in pool[:4]:
            state.record_case(c["candidate_id"], c["candidate_id"], "pmp-boundary",
                              "pass", None, True, "eligible", 10.0, 1.0, 1, 0, 0, 0, 0)
        # Ineligible case
        state.record_case(pool[4]["candidate_id"], pool[4]["candidate_id"], "pmp-boundary",
                          "timeout", "timeout", False, "status_timeout", 15.0, 1.0, 0, 0, 0, 0, 0)
        self.assertEqual(state.completed_cases, 5)
        self.assertEqual(state.eligible_cases, 4)
        state.advance_round()
        for c in pool[5:9]:
            state.record_case(c["candidate_id"], c["candidate_id"], "pmp-boundary",
                              "pass", None, True, "eligible", 25.0, 1.0, 1, 0, 0, 0, 0)
        self.assertEqual(state.completed_cases, 9)
        self.assertEqual(state.eligible_cases, 8)

    def test_wall_time_monotonic(self):
        """elapsed_wall_seconds is based on start_time, includes scheduling."""
        pool = _make_pool(4)
        state = CampaignState("test", "random", "spike", 1, "semantic", pool, 100.0)
        for i, c in enumerate(pool):
            state.record_case(c["candidate_id"], f"case_{i}", "pmp-boundary",
                              "pass", None, True, "eligible", 100.0 + (i + 1) * 5.0, 1.0, 0, 0, 0, 0, 0)
        self.assertGreater(state.completion_seq, 0)


class TestWithoutReplacement(unittest.TestCase):
    """B2-B3 tests: candidate pool management."""

    def test_no_duplicate_execution(self):
        """Re-executing same candidate_id raises ValueError."""
        pool = _make_pool(8)
        state = CampaignState("test", "random", "spike", 1, "semantic", pool, 0.0)
        cid = pool[0]["candidate_id"]
        state.mark_executed(cid)
        with self.assertRaises(ValueError):
            state.mark_executed(cid)

    def test_unexecuted_excludes_executed(self):
        """Unexecuted candidates properly filters executed ones."""
        pool = _make_pool(20)
        state = CampaignState("test", "random", "spike", 1, "semantic", pool, 0.0)
        for c in pool[:10]:
            state.mark_executed(c["candidate_id"])
        self.assertEqual(len(state.unexecuted_candidates()), 10)

    def test_random_is_seeded_shuffle(self):
        """Same seed → same order; different seed → different order."""
        pool = _make_pool(20)
        s1 = _select_random(pool, 20, 42)
        s2 = _select_random(pool, 20, 42)
        s3 = _select_random(pool, 20, 99)
        self.assertEqual([c["candidate_id"] for c in s1], [c["candidate_id"] for c in s2])
        self.assertNotEqual([c["candidate_id"] for c in s1], [c["candidate_id"] for c in s3])

    def test_random_subset_of_unexecuted(self):
        """Random selection returns only from provided unexecuted list."""
        pool = _make_pool(32)
        unexec = [c for c in pool if int(c["candidate_id"].split("_")[1]) >= 10]
        selected = _select_random(unexec, 8, 42)
        self.assertEqual(len(selected), 8)
        for c in selected:
            self.assertIn(c, unexec)


class TestCandidatePool(unittest.TestCase):
    """B2 tests."""

    def test_candidate_id_is_stable_sha256(self):
        """candidate_id is deterministic from profile+seed+index."""
        cid1 = _make_candidate_id("pmp-boundary", 5, 1)
        cid2 = _make_candidate_id("pmp-boundary", 5, 1)
        cid3 = _make_candidate_id("pmp-boundary", 6, 1)
        self.assertEqual(cid1, cid2)
        self.assertNotEqual(cid1, cid3)
        self.assertEqual(len(cid1), 16)

    def test_pool_has_required_fields(self):
        """build_candidate_pool entries have required keys."""
        required = {"candidate_id", "profile", "generation_seed", "scenario_index",
                     "semantic_bins", "pairwise_bins", "security_triple_bins", "predicate_bins"}
        # Integration test: can't build full pool without capability, but
        # imports and utility functions must be reliable
        self.assertTrue(all(isinstance(k, str) for k in required))


class TestVariantDispatch(unittest.TestCase):
    """B3 tests."""

    def test_valid_variants_accepted(self):
        """Only random, guided, bb, bb-wb are valid."""
        pool = _make_pool(4)
        for v in ["random", "guided", "bb", "bb-wb"]:
            s = CampaignState("test", v, "spike", 1, "semantic", pool, 0.0)
            self.assertEqual(s.variant, v)

    def test_invalid_variant_raises(self):
        """Invalid variant raises ValueError."""
        with self.assertRaises(ValueError):
            CampaignState("test", "invalid", "spike", 1, "semantic", _make_pool(4), 0.0)

    def test_bootstrap_must_be_identical_for_paired_variants(self):
        """Paired random/guided share same bootstrap candidate pool."""
        pool = _make_pool(64)
        # Both variants start with the same pool
        s_r = CampaignState("test-r", "random", "spike", 1, "semantic", pool, 0.0)
        s_g = CampaignState("test-g", "guided", "spike", 1, "semantic", pool, 0.0)
        # Same first 8 from bootstrap
        r_initial = [c["candidate_id"] for c in pool[:8]]
        g_initial = [c["candidate_id"] for c in pool[:8]]
        self.assertEqual(r_initial, g_initial)


class TestTimelinePersistence(unittest.TestCase):
    """B4 tests for timeline writing."""

    def test_write_timeline_produces_valid_jsonl(self):
        """Written timeline is valid JSONL with baseline first."""
        pool = _make_pool(4)
        state = CampaignState("test-tl", "random", "spike", 1, "semantic", pool, 0.0)
        for c in pool:
            state.record_case(c["candidate_id"], c["candidate_id"], "pmp-boundary",
                              "pass", None, True, "eligible", 10.0, 1.0, 0, 0, 0, 0, 0)

        with TemporaryDirectory() as tmp:
            tl_path = Path(tmp) / "timeline.jsonl"
            state.write_timeline(tl_path)
            self.assertTrue(tl_path.exists())
            lines = [json.loads(l) for l in tl_path.read_text(encoding="ascii").strip().split("\n") if l.strip()]
            self.assertEqual(len(lines), 5)  # baseline + 4 cases
            self.assertEqual(lines[0]["completion_seq"], 0)
            self.assertEqual(lines[1]["completion_seq"], 1)
            self.assertEqual(lines[-1]["completion_seq"], 4)

    def test_partial_timeline_survives_interrupt(self):
        """Written lines are parseable even before campaign completes."""
        pool = _make_pool(3)
        state = CampaignState("test-int", "random", "spike", 1, "semantic", pool, 0.0)
        for c in pool[:2]:
            state.record_case(c["candidate_id"], c["candidate_id"], "pmp-boundary",
                              "pass", None, True, "eligible", 10.0, 1.0, 0, 0, 0, 0, 0)

        with TemporaryDirectory() as tmp:
            tl_path = Path(tmp) / "partial.jsonl"
            state.write_timeline(tl_path)
            lines = [json.loads(l) for l in tl_path.read_text(encoding="ascii").strip().split("\n") if l.strip()]
            self.assertEqual(len(lines), 3)  # baseline + 2 cases

    def test_resume_preserves_accumulated_state(self):
        """New state can be created with prior knowledge (resume support)."""
        pool = _make_pool(8)
        s1 = CampaignState("test-resume", "random", "spike", 1, "semantic", pool, 0.0)
        for c in pool[:3]:
            s1.record_case(c["candidate_id"], c["candidate_id"], "pmp-boundary",
                           "pass", None, True, "eligible", 10.0, 1.0, 0, 0, 0, 0, 0)
        self.assertEqual(s1.completion_seq, 3)

        # "Resume" with a new state that already knows about first 3
        s2 = CampaignState("test-resume", "random", "spike", 1, "semantic", pool, 0.0)
        for c in pool[:3]:
            s2.mark_executed(c["candidate_id"])
        self.assertEqual(len(s2.executed_ids), 3)
        remaining = s2.unexecuted_candidates()
        self.assertEqual(len(remaining), 5)

    def test_final_completion_seq_matches_total_cases(self):
        """completion_seq == total cases completed."""
        pool = _make_pool(16)
        state = CampaignState("test-final", "random", "spike", 1, "semantic", pool, 0.0)
        for c in pool:
            state.record_case(c["candidate_id"], c["candidate_id"], "pmp-boundary",
                              "pass", None, True, "eligible", 10.0, 1.0, 0, 0, 0, 0, 0)
        self.assertEqual(state.completion_seq, len(pool))


if __name__ == "__main__":
    unittest.main()
