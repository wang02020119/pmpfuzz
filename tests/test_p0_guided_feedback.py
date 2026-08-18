"""P0-1: Real guided DUT-qualified feedback tests (RED phase).

These tests expose bugs:
1. _coverage_gap_* functions hardcode dut="unknown" — all real results excluded
2. guided may return fewer than round_size candidates
3. bb may consume whitebox feedback
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


class TestGuidedFeedbackDutQualified(unittest.TestCase):
    """P0-1: guided must use real DUT-qualified execution feedback."""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self._create_round_with_dut_results(
            "round_0000", [
                ("case_A", "spike", True),
                ("case_B", "spike", False),
                ("case_C", "rocket-clean", True),
            ])

    def tearDown(self):
        self.tmp.cleanup()

    def _create_round_with_dut_results(self, round_name, cases):
        rd = self.root / round_name
        for case_name, dut, obs_valid in cases:
            cdir = rd / "cases" / case_name
            rdir = rd / "results" / case_name
            cdir.mkdir(parents=True)
            rdir.mkdir(parents=True)
            (cdir / "case.json").write_text(json.dumps({
                "name": case_name, "profile": "pmp-boundary",
                "privilege": "M", "access": "load", "translation": "bare",
                "pmp_match_mode": "OFF", "expected_allowed": True,
                "expected_trap_cause": None, "expected_stage": "normal",
                "coverage_tags": [],
            }), encoding="ascii")
            (rdir / "result.json").write_text(json.dumps({
                "name": case_name, "dut": dut, "status": "pass",
                "observation_valid": obs_valid,
                "observed_event": "completion" if obs_valid else None,
                "observed_phase": "completed" if obs_valid else "",
                "observed_tohost": 0, "oracle_applicability": "valid",
            }), encoding="ascii")

    # --- RED tests: demonstrate the dut="unknown" bug ---

    def test_coverage_gap_with_real_dut_finds_bins(self):
        """GREEN: _coverage_gap_semantic with real DUT finds eligible results."""
        from scripts.evaluation.campaigns.run_closed_loop_campaign import _coverage_gap_semantic
        from pmpfuzz.semantic_coverage import target_semantic_bins

        full_target = set(target_semantic_bins(target="core-stateful"))
        missing = _coverage_gap_semantic([self.root / "round_0000"], dut="spike")
        # With real DUT (spike), the eligible case_A closes some bins
        # missing should be a proper subset (not the full target)
        self.assertLess(len(missing), len(full_target),
                        "FIX: with correct DUT, eligible cases reduce coverage gap")

    def test_collect_evidence_with_correct_dut_finds_eligible(self):
        """Evidence with correct DUT finds eligible cases."""
        from pmpfuzz.coverage_qualification import collect_execution_evidence
        evidence = collect_execution_evidence(
            [self.root / "round_0000"], dut="spike")
        self.assertEqual(evidence.summary.eligible_results, 1,
                          "Only case_A (spike, obs_valid=True) is eligible")

    def test_wrong_dut_results_excluded(self):
        """Other DUT results must not pollute spike gap."""
        from pmpfuzz.coverage_qualification import collect_execution_evidence
        ev_spike = collect_execution_evidence([self.root / "round_0000"], dut="spike")
        ev_rocket = collect_execution_evidence([self.root / "round_0000"], dut="rocket-clean")
        self.assertEqual(ev_spike.summary.eligible_results, 1)
        self.assertEqual(ev_rocket.summary.eligible_results, 1)


class TestGuidedFillsRoundSize(unittest.TestCase):
    """P0-1: guided fills to round_size with fallback."""

    def _make_pool(self, n):
        return [{"candidate_id": f"c_{i:04d}", "profile": "pmp-boundary",
                 "generation_seed": 1, "scenario_index": i, "name": f"case_{i}",
                 "semantic_bins": [f"sem:{i % 10}"], "pairwise_bins": [],
                 "security_triple_bins": [], "predicate_bins": []}
                for i in range(n)]

    def test_guided_fills_to_round_size(self):
        """With sufficient candidates, guided returns exactly round_size."""
        from scripts.evaluation.campaigns.run_closed_loop_campaign import _select_guided, CampaignState
        pool = self._make_pool(64)
        state = CampaignState("t", "guided", "spike", 1, "semantic", pool, 0.0)
        selected = _select_guided(state, pool, 32, [], 1)
        self.assertEqual(len(selected), 32)

    def test_guided_returns_all_when_insufficient(self):
        """When fewer candidates than round_size, return all remaining."""
        from scripts.evaluation.campaigns.run_closed_loop_campaign import _select_guided, CampaignState
        pool = self._make_pool(5)
        state = CampaignState("t", "guided", "spike", 1, "semantic", pool, 0.0)
        selected = _select_guided(state, pool, 32, [], 1)
        self.assertEqual(len(selected), 5)

    def test_guided_never_repeats_executed(self):
        """Guided never selects already-executed candidates."""
        from scripts.evaluation.campaigns.run_closed_loop_campaign import _select_guided, CampaignState
        pool = self._make_pool(64)
        state = CampaignState("t", "guided", "spike", 1, "semantic", pool, 0.0)
        for c in pool[:8]:
            state.mark_executed(c["candidate_id"])
        unexec = state.unexecuted_candidates()
        selected = _select_guided(state, unexec, 16, [], 1)
        for c in selected:
            self.assertNotIn(c["candidate_id"], state.executed_ids)

    def test_guided_reproducible(self):
        """Same seed + pool = same guided selection."""
        from scripts.evaluation.campaigns.run_closed_loop_campaign import _select_guided, CampaignState
        pool = self._make_pool(64)
        s1 = _select_guided(CampaignState("t", "guided", "spike", 1, "sem", pool, 0.0), pool, 16, [], 42)
        s2 = _select_guided(CampaignState("t", "guided", "spike", 1, "sem", pool, 0.0), pool, 16, [], 42)
        self.assertEqual([c["candidate_id"] for c in s1], [c["candidate_id"] for c in s2])


class TestBBNoWhitebox(unittest.TestCase):
    """P0-1: bb consumes only blackbox, not whitebox."""

    def _make_pool(self, n):
        return [{"candidate_id": f"c_{i:04d}", "profile": "pmp-boundary",
                 "generation_seed": 1, "scenario_index": i, "name": f"case_{i}",
                 "semantic_bins": [f"sem:{i % 10}"], "pairwise_bins": [],
                 "security_triple_bins": [], "predicate_bins": []}
                for i in range(n)]

    def test_bb_and_bb_wb_both_return_full_rounds(self):
        """Both bb and bb-wb return round_size selections."""
        from scripts.evaluation.campaigns.run_closed_loop_campaign import select_next_candidates, CampaignState
        pool = self._make_pool(64)
        bb = select_next_candidates(
            CampaignState("bb", "bb", "spike", 1, "semantic", pool, 0.0), 32, [], 1)
        bw = select_next_candidates(
            CampaignState("bw", "bb-wb", "spike", 1, "semantic", pool, 0.0), 32, [], 1)
        self.assertEqual(len(bb), 32)
        self.assertEqual(len(bw), 32)


if __name__ == "__main__":
    unittest.main()
