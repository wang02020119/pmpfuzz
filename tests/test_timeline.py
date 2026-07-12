"""Tests for timeline recording — execution-qualified coverage over time.

Validates:
1. elapsed_wall_seconds is monotonically non-decreasing
2. completion_seq grows continuously from 0
3. Four coverage rates are monotonically non-decreasing
4. valid mismatch increases coverage
5. invalid observation does NOT increase coverage
6. wrong_phase does NOT increase coverage
7. timeout/inconclusive/unsupported do NOT increase coverage
8. denominator stays constant within a campaign
9. denominator=0 yields rate=null
10. Timeline final row matches execution coverage
11. Concurrent fake tasks record in real completion order (not sorted)
12. Process interrupt — completed lines are still parseable
13. Existing non-empty output dir rejects silent overwrite
"""

from __future__ import annotations

import json
import time
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from pmpfuzz.coverage_qualification import CoverageQualification
from pmpfuzz.runner import CampaignResult
from pmpfuzz.timeline import TimelineRecorder, timeline_on_complete_factory


class TestTimelineRecorder(unittest.TestCase):
    """Unit tests for TimelineRecorder."""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "out"
        self.run_dir.mkdir(parents=True)
        # Create minimal cases and results directories
        (self.run_dir / "cases").mkdir(exist_ok=True)
        (self.run_dir / "results").mkdir(exist_ok=True)

        self.target_semantic = {"bin:s1", "bin:s2", "bin:s3"}
        self.target_pairwise = {"combo2:p1", "combo2:p2", "combo2:p3"}
        self.target_security_triples = {"combo3:t1", "combo3:t2"}
        self.target_predicates = {"pred:a", "pred:b"}

    def tearDown(self):
        self.tmp.cleanup()

    def _make_recorder(self):
        r = TimelineRecorder(
            run_dir=self.run_dir,
            campaign_id="test-campaign",
            variant="guided-semantic",
            dut="spike",
            seed=1,
        )
        r.target_semantic = self.target_semantic
        r.target_pairwise = self.target_pairwise
        r.target_security_triples = self.target_security_triples
        r.target_predicates = self.target_predicates
        return r

    def _make_case(self, name="test_case_0"):
        """Make a minimal eligible case dict (with bins matching target)."""
        return {
            "name": name,
            "profile": "pmp-boundary",
            "privilege": "M",
            "access": "load",
            "translation": "bare",
            "pmp_match_mode": "TOR",
            "expected_allowed": True,
            "expected_trap_cause": None,
            "expected_stage": "normal",
            "coverage_tags": [],
        }

    def _make_result_pass(self, name="test_case_0", oracle_applicability="valid"):
        """Make a minimal pass result that should qualify."""
        return {
            "name": name,
            "status": "pass",
            "failure_class": None,
            "observation_valid": True,
            "stage_verified": True,
            "observed_event": "completion",
            "observed_phase": "completed",
            "observed_tohost": 0,
            "oracle_applicability": oracle_applicability,
            "dut": "spike",
        }

    def _make_result_mismatch(self, name="test_case_0"):
        """Make a valid mismatch result."""
        return {
            "name": name,
            "status": "fail",
            "failure_class": "unexpected_trap",
            "observation_valid": True,
            "stage_verified": True,
            "observed_event": "trap",
            "observed_phase": "probe",
            "observed_tohost": 0,
            "observed_mcause": 13,
            "oracle_applicability": "valid",
            "dut": "spike",
        }

    def _write_case_and_result(self, name, case, result):
        case_dir = self.run_dir / "cases" / name
        result_dir = self.run_dir / "results" / name
        case_dir.mkdir(parents=True, exist_ok=True)
        result_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "case.json").write_text(json.dumps(case), encoding="ascii")
        (result_dir / "result.json").write_text(json.dumps(result), encoding="ascii")

    # --- Test 1: elapsed_wall_seconds monotonically non-decreasing ---
    def test_wall_seconds_monotonic(self):
        recorder = self._make_recorder()
        case = self._make_case("c0")
        result_pass = self._make_result_pass("c0")
        self._write_case_and_result("c0", case, result_pass)

        recorder.record(case, result_pass, elapsed_wall_seconds=10.0, case_elapsed_seconds=2.0)
        recorder.record(case, result_pass, elapsed_wall_seconds=15.0, case_elapsed_seconds=3.0)
        recorder.record(case, result_pass, elapsed_wall_seconds=15.0, case_elapsed_seconds=1.0)  # same is OK
        recorder.record(case, result_pass, elapsed_wall_seconds=20.0, case_elapsed_seconds=2.5)

        lines = self._read_timeline_lines()
        times = [line["elapsed_wall_seconds"] for line in lines[1:]]  # skip baseline
        self.assertEqual(times, [10.0, 15.0, 15.0, 20.0])
        for i in range(1, len(times)):
            self.assertGreaterEqual(times[i], times[i - 1])

    # --- Test 2: completion_seq grows continuously from 0 ---
    def test_completion_seq_continuous(self):
        recorder = self._make_recorder()
        case = self._make_case("c0")
        result_pass = self._make_result_pass("c0")
        self._write_case_and_result("c0", case, result_pass)

        for i in range(5):
            recorder.record(case, result_pass, elapsed_wall_seconds=i * 10.0, case_elapsed_seconds=1.0)

        lines = self._read_timeline_lines()
        seqs = [line["completion_seq"] for line in lines]
        self.assertEqual(seqs, [0, 1, 2, 3, 4, 5])

    # --- Test 3: Four coverage rates monotonically non-decreasing ---
    def test_coverage_rates_monotonic(self):
        recorder = self._make_recorder()
        # Case that covers one semantic bin
        case = self._make_case("c0")
        result_pass = self._make_result_pass("c0")
        self._write_case_and_result("c0", case, result_pass)

        for i in range(3):
            recorder.record(case, result_pass, elapsed_wall_seconds=(i + 1) * 5.0, case_elapsed_seconds=1.0)

        lines = self._read_timeline_lines()
        for i in range(2, len(lines)):
            self.assertGreaterEqual(lines[i]["semantic_rate"] or 0, lines[i - 1]["semantic_rate"] or 0)
            self.assertGreaterEqual(lines[i]["pairwise_rate"] or 0, lines[i - 1]["pairwise_rate"] or 0)
            self.assertGreaterEqual(lines[i]["security_triples_rate"] or 0, lines[i - 1]["security_triples_rate"] or 0)
            self.assertGreaterEqual(lines[i]["predicates_rate"] or 0, lines[i - 1]["predicates_rate"] or 0)

    # --- Test 4: valid mismatch increases coverage ---
    def test_valid_mismatch_counts_for_coverage(self):
        recorder = self._make_recorder()
        case = self._make_case("c_mismatch")
        result_mismatch = self._make_result_mismatch("c_mismatch")
        self._write_case_and_result("c_mismatch", case, result_mismatch)

        recorder.record(case, result_mismatch, elapsed_wall_seconds=5.0, case_elapsed_seconds=1.0)

        lines = self._read_timeline_lines()
        last = lines[-1]
        self.assertTrue(last["coverage_eligible"], "valid mismatch should be coverage-eligible")
        self.assertEqual(last["eligible_cases"], 1)

    # --- Test 5: invalid observation does NOT increase coverage ---
    def test_invalid_observation_skipped(self):
        recorder = self._make_recorder()
        case = self._make_case("c_bad")
        result_bad = {
            "name": "c_bad",
            "status": "pass",
            "observation_valid": False,
            "observed_event": None,
            "observed_phase": "",
            "oracle_applicability": "valid",
            "dut": "spike",
        }
        self._write_case_and_result("c_bad", case, result_bad)

        recorder.record(case, result_bad, elapsed_wall_seconds=5.0, case_elapsed_seconds=1.0)

        lines = self._read_timeline_lines()
        last = lines[-1]
        self.assertFalse(last["coverage_eligible"])
        self.assertEqual(last["eligible_cases"], 0)
        self.assertEqual(last["semantic_covered"], 0)

    # --- Test 6: wrong_phase does NOT increase coverage ---
    def test_wrong_phase_skipped(self):
        recorder = self._make_recorder()
        case = self._make_case("c_wrong_phase")
        result_wrong = {
            "name": "c_wrong_phase",
            "status": "pass",
            "observation_valid": True,
            "observed_event": "trap",
            "observed_phase": "setup",
            "observed_tohost": 0,
            "oracle_applicability": "valid",
            "dut": "spike",
        }
        self._write_case_and_result("c_wrong_phase", case, result_wrong)

        recorder.record(case, result_wrong, elapsed_wall_seconds=5.0, case_elapsed_seconds=1.0)

        lines = self._read_timeline_lines()
        last = lines[-1]
        self.assertFalse(last["coverage_eligible"])
        self.assertEqual(last["eligible_cases"], 0)

    # --- Test 7: timeout/inconclusive/unsupported do NOT increase coverage ---
    def test_non_pass_fail_statuses_skipped(self):
        for bad_status in ("timeout", "inconclusive", "compile_fail"):
            recorder = self._make_recorder()
            case = self._make_case(f"c_{bad_status}")
            result_bad = {
                "name": f"c_{bad_status}",
                "status": bad_status,
                "failure_class": bad_status,
                "observation_valid": False,
                "observed_event": None,
                "observed_phase": "",
                "oracle_applicability": "valid",
                "dut": "spike",
            }
            self._write_case_and_result(f"c_{bad_status}", case, result_bad)
            recorder.record(case, result_bad, elapsed_wall_seconds=1.0, case_elapsed_seconds=1.0)
            lines = self._read_timeline_lines()
            last = lines[-1]
            self.assertFalse(last["coverage_eligible"], f"status={bad_status} should not be eligible")
            self.assertEqual(last["eligible_cases"], 0)

    # --- Test 8: denominator stays constant within a campaign ---
    def test_denominator_constant(self):
        recorder = self._make_recorder()
        case = self._make_case("c0")
        result_pass = self._make_result_pass("c0")
        self._write_case_and_result("c0", case, result_pass)

        for i in range(5):
            recorder.record(case, result_pass, elapsed_wall_seconds=(i + 1) * 2.0, case_elapsed_seconds=0.5)

        lines = self._read_timeline_lines()
        baseline = lines[0]
        for line in lines[1:]:
            self.assertEqual(line["semantic_target"], baseline["semantic_target"])
            self.assertEqual(line["pairwise_target"], baseline["pairwise_target"])
            self.assertEqual(line["security_triples_target"], baseline["security_triples_target"])
            self.assertEqual(line["predicates_target"], baseline["predicates_target"])

    # --- Test 9: denominator=0 yields rate=null ---
    def test_zero_denominator_yields_null_rate(self):
        recorder = TimelineRecorder(
            run_dir=self.run_dir,
            campaign_id="zero-denom",
            variant="test",
            dut="spike",
            seed=1,
        )
        recorder.target_semantic = set()
        recorder.target_pairwise = set()
        recorder.target_security_triples = set()
        recorder.target_predicates = set()

        case = self._make_case("c0")
        result_pass = self._make_result_pass("c0")
        self._write_case_and_result("c0", case, result_pass)
        recorder.record(case, result_pass, elapsed_wall_seconds=1.0, case_elapsed_seconds=1.0)

        lines = self._read_timeline_lines()
        last = lines[-1]
        self.assertIsNone(last["semantic_rate"])
        self.assertIsNone(last["pairwise_rate"])
        self.assertIsNone(last["security_triples_rate"])
        self.assertIsNone(last["predicates_rate"])

    # --- Test 10: final timeline row matches coverage state ---
    def test_final_timeline_matches_coverage_state(self):
        recorder = self._make_recorder()
        case = self._make_case("c0")
        result_pass = self._make_result_pass("c0")
        self._write_case_and_result("c0", case, result_pass)

        recorder.record(case, result_pass, elapsed_wall_seconds=10.0, case_elapsed_seconds=2.0)

        lines = self._read_timeline_lines()
        last = lines[-1]
        state = recorder.coverage_state()
        self.assertEqual(last["semantic_covered"], state["semantic"]["covered_target_bins"])
        self.assertEqual(last["pairwise_covered"], state["pairwise"]["covered_target_bins"])
        self.assertEqual(last["security_triples_covered"], state["security_triples"]["covered_target_bins"])
        self.assertEqual(last["predicates_covered"], state["predicates"]["covered_target_bins"])

    # --- Test 11: concurrent fake tasks record in completion order (not name order) ---
    def test_completion_order_preserved(self):
        """Verify that the callback approach preserves true completion order."""
        from pmpfuzz.runner import _run_indexed_work_with_budget

        # Fake clock that advances by 1 second per call
        clock_state = [0.0]

        def fake_clock():
            val = clock_state[0]
            clock_state[0] += 1.0
            return val

        recording = []

        def on_complete(index, scenario, result, completion_seq, campaign_elapsed):
            recording.append((completion_seq, result.name))

        # Create work items where item 2 finishes before item 1
        # Item 0: fast, item 1: slow (but in real system they complete as submitted)
        work = [
            (0, {"name": "task-fast"}),
            (1, {"name": "task-slow"}),
        ]

        def run_one(index, item):
            name = item["name"]
            if name == "task-slow":
                time.sleep(0.05)  # actually slower
            return CampaignResult(
                name=name, profile="pmp-boundary", status="pass",
                expected_allowed=True, expected_cause=None,
                elapsed_seconds=0.1,
            )

        results = _run_indexed_work_with_budget(
            work, run_one,
            max_workers=2, start_time=0.0,
            time_budget_seconds=30, time_fn=fake_clock,
            on_complete=on_complete,
        )

        # task-fast should complete before task-slow (it has no sleep)
        names_in_order = [r.name for r in results]
        self.assertEqual(names_in_order[0], "task-fast")
        self.assertEqual(names_in_order[1], "task-slow")

        # Recording should also show completion order
        self.assertEqual(recording[0][1], "task-fast")
        self.assertEqual(recording[1][1], "task-slow")

    # --- Test 12: process interrupt — completed lines still parseable ---
    def test_interrupt_lines_parseable(self):
        recorder = self._make_recorder()
        case = self._make_case("c0")
        result_pass = self._make_result_pass("c0")
        self._write_case_and_result("c0", case, result_pass)

        for i in range(5):
            recorder.record(case, result_pass, elapsed_wall_seconds=(i + 1) * 2.0, case_elapsed_seconds=0.5)

        # Read back — all lines should be valid JSON
        path = recorder.output_path
        raw = path.read_text(encoding="ascii")
        lines = raw.strip().split("\n")
        self.assertEqual(len(lines), 6)  # baseline + 5 records
        for i, line in enumerate(lines):
            try:
                obj = json.loads(line)
                self.assertIsInstance(obj, dict)
            except json.JSONDecodeError as exc:
                self.fail(f"Line {i} is not valid JSON: {exc}")

    # --- Test 13: existing non-empty output dir — append, don't overwrite ---
    def test_resume_from_existing_timeline(self):
        # First session — write 2 records
        r1 = self._make_recorder()
        case = self._make_case("c0")
        result_pass = self._make_result_pass("c0")
        self._write_case_and_result("c0", case, result_pass)

        for i in range(2):
            r1.record(case, result_pass, elapsed_wall_seconds=(i + 1) * 3.0, case_elapsed_seconds=0.5)

        self.assertTrue(r1.output_path.exists())
        size_before = r1.output_path.stat().st_size

        # Second session — same campaign_id, same output path
        r2 = TimelineRecorder(
            run_dir=self.run_dir,
            campaign_id="test-campaign",
            variant="guided-semantic",
            dut="spike",
            seed=1,
        )
        r2.target_semantic = self.target_semantic
        r2.target_pairwise = self.target_pairwise
        r2.target_security_triples = self.target_security_triples
        r2.target_predicates = self.target_predicates

        for i in range(2):
            r2.record(case, result_pass, elapsed_wall_seconds=(i + 3) * 3.0, case_elapsed_seconds=0.5)

        # Should have appended, so size increased
        size_after = r2.output_path.stat().st_size
        self.assertGreater(size_after, size_before, "Timeline should append, not overwrite")

        # Total lines: original baseline + 2 first-session + 2 second-session = 5
        lines = self._read_timeline_lines()
        self.assertEqual(len(lines), 5)

    # --- Additional: baseline row has correct shape ---
    def test_baseline_row_shape(self):
        recorder = self._make_recorder()
        case = self._make_case("c0")
        result_pass = self._make_result_pass("c0")
        self._write_case_and_result("c0", case, result_pass)
        # Trigger lazy baseline write via one record
        recorder.record(case, result_pass, elapsed_wall_seconds=1.0, case_elapsed_seconds=0.5)

        lines = self._read_timeline_lines()
        self.assertGreaterEqual(len(lines), 2)  # baseline + at least one record
        baseline = lines[0]
        self.assertEqual(baseline["completion_seq"], 0)
        self.assertEqual(baseline["elapsed_wall_seconds"], 0.0)
        self.assertEqual(baseline["completed_cases"], 0)
        self.assertEqual(baseline["eligible_cases"], 0)
        self.assertIsNone(baseline["case_id"])

    # --- Additional: write_metadata creates valid JSON ---
    def test_write_metadata(self):
        recorder = self._make_recorder()
        recorder.write_metadata(
            source_sha="abc123",
            time_budget_seconds=3600,
            jobs=4,
            per_case_timeout_seconds=10,
            hostname="testhost",
            coverage_mode="semantic",
        )
        meta_path = self.run_dir / "metrics" / "campaign_metadata.json"
        self.assertTrue(meta_path.exists())
        meta = json.loads(meta_path.read_text(encoding="ascii"))
        self.assertEqual(meta["campaign_id"], "test-campaign")
        self.assertEqual(meta["source_sha"], "abc123")

    # --- Helpers ---
    def _read_timeline_lines(self):
        path = Path(self.tmp.name) / "out" / "metrics" / "coverage_timeline.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="ascii").strip().split("\n") if line.strip()]


class TestTimelineCallbackFactory(unittest.TestCase):
    """Tests for timeline_on_complete_factory."""

    def test_factory_reads_case_and_result_from_disk(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_dir = Path(tmp.name) / "out"
        run_dir.mkdir(parents=True)
        (run_dir / "metrics").mkdir(exist_ok=True)

        recorder = TimelineRecorder(
            run_dir=run_dir,
            campaign_id="callback-test",
            variant="test",
            dut="spike",
            seed=1,
        )
        recorder.target_semantic = set()
        recorder.target_pairwise = set()
        recorder.target_security_triples = set()
        recorder.target_predicates = set()

        callback = timeline_on_complete_factory(recorder)

        # Write case and result to disk first
        case_dir = run_dir / "cases" / "test_case_0"
        result_dir = run_dir / "results" / "test_case_0"
        case_dir.mkdir(parents=True)
        result_dir.mkdir(parents=True)
        (case_dir / "case.json").write_text(json.dumps({
            "name": "test_case_0",
            "profile": "pmp-boundary",
            "privilege": "M",
            "access": "load",
            "translation": "bare",
            "pmp_match_mode": "OFF",
            "expected_allowed": True,
            "expected_trap_cause": None,
            "expected_stage": "normal",
            "coverage_tags": [],
        }), encoding="ascii")
        (result_dir / "result.json").write_text(json.dumps({
            "name": "test_case_0",
            "status": "pass",
            "observation_valid": True,
            "observed_event": "completion",
            "observed_phase": "completed",
            "observed_tohost": 0,
            "oracle_applicability": "valid",
            "dut": "spike",
        }), encoding="ascii")

        result = CampaignResult(
            name="test_case_0", profile="pmp-boundary", status="pass",
            expected_allowed=True, expected_cause=None,
            elapsed_seconds=3.5,
        )

        callback(0, {}, result, 1, 42.5)

        # Timeline should have been written
        tl_path = run_dir / "metrics" / "coverage_timeline.jsonl"
        self.assertTrue(tl_path.exists())
        lines = [json.loads(line) for line in tl_path.read_text(encoding="ascii").strip().split("\n") if line.strip()]
        self.assertGreaterEqual(len(lines), 2)  # baseline + at least one record


if __name__ == "__main__":
    unittest.main()
