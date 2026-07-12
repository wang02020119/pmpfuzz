"""Engineering-only end-to-end guards for the closed-loop driver.

These tests intentionally avoid interpreting any nonpass result.  They verify
process orchestration, result accounting, timing inputs, feedback eligibility,
and schedule traceability.
"""

from __future__ import annotations

import json
import unittest
from argparse import Namespace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import scripts.evaluation.run_closed_loop_campaign as driver


def _candidate(index: int, name: str | None = None) -> dict:
    return {
        "candidate_id": f"candidate-{index:04d}",
        "profile": "pmp-boundary",
        "generation_seed": 1,
        "scenario_index": index,
        "name": name or f"case-{index:04d}",
        "semantic_bins": [f"semantic:{index % 4}"],
        "pairwise_bins": [f"combo2:{index % 3}"],
        "security_triple_bins": [f"combo3:{index % 2}"],
        "predicate_bins": [f"predicate:{index % 3}"],
    }


def _write_case_result(round_dir: Path, candidate: dict, *, eligible: bool = True) -> None:
    name = candidate["name"]
    case_dir = round_dir / "cases" / name
    result_dir = round_dir / "results" / name
    case_dir.mkdir(parents=True, exist_ok=True)
    result_dir.mkdir(parents=True, exist_ok=True)
    case = {
        "name": name,
        "profile": candidate["profile"],
        "privilege": "M",
        "access": "load",
        "translation": "bare",
        "pmp_match_mode": "OFF",
        "expected_allowed": True,
        "expected_trap_cause": None,
        "expected_stage": "normal",
        "coverage_tags": [],
    }
    result = {
        "name": name,
        "dut": "spike",
        "status": "pass",
        "elapsed_seconds": 0.25,
        "observation_valid": eligible,
        "observed_event": "completion" if eligible else None,
        "observed_phase": "completed" if eligible else "",
        "observed_tohost": 0,
        "oracle_applicability": "valid",
    }
    (case_dir / "case.json").write_text(json.dumps(case), encoding="ascii")
    (result_dir / "result.json").write_text(json.dumps(result), encoding="ascii")


def _write_round_timeline(round_dir: Path, candidates: list[dict]) -> None:
    metrics = round_dir / "metrics"
    metrics.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "schema_version": 1,
            "campaign_id": "round",
            "completion_seq": 0,
            "case_id": None,
            "elapsed_wall_seconds": 0.0,
        }
    ]
    for sequence, candidate in enumerate(candidates, 1):
        rows.append(
            {
                "schema_version": 1,
                "campaign_id": "round",
                "completion_seq": sequence,
                "case_id": candidate["name"],
                "elapsed_wall_seconds": float(sequence),
                "completion_monotonic_seconds": 1000.0 + float(sequence),
            }
        )
    (metrics / "coverage_timeline.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="ascii"
    )


class TestRoundExecution(unittest.TestCase):
    def test_run_round_invokes_subprocess_and_records_one_final_status(self):
        pool = [_candidate(0)]
        state = driver.CampaignState("campaign", "random", "spike", 1, "semantic", pool, 999.0)
        args = Namespace(seed=1)

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            round_dir = root / "round_0000"
            schedule_path = root / "schedule.json"
            schedule_path.write_text('{"entries": []}', encoding="ascii")
            completed = SimpleNamespace(returncode=0)
            with patch.object(driver.subprocess, "run", return_value=completed) as run_mock:
                with patch.object(driver, "_ingest_round_results", return_value=True):
                    success = driver._run_round(
                        ["python", "-m", "pmpfuzz", "run"],
                        round_dir,
                        args,
                        state,
                        schedule_path=schedule_path,
                        expected_candidates=pool,
                        env={"PYTHONPATH": "test"},
                        round_start_offset=1.0,
                    )

        self.assertTrue(success)
        run_mock.assert_called_once()
        self.assertEqual(len(state._round_results), 1)
        self.assertTrue(state._round_results[0]["process_success"])
        self.assertTrue(state._round_results[0]["ingest_success"])


class TestRoundIngestionIntegrity(unittest.TestCase):
    def test_missing_round_timeline_is_an_ingest_failure(self):
        pool = [_candidate(0)]
        state = driver.CampaignState("campaign", "random", "spike", 1, "semantic", pool, 999.0)
        with TemporaryDirectory() as tmp:
            round_dir = Path(tmp)
            _write_case_result(round_dir, pool[0])
            success = driver._ingest_round_results(state, round_dir, pool)

        self.assertFalse(success)
        self.assertEqual(state.completed_cases, 0)

    def test_every_expected_candidate_must_have_timeline_case_and_result(self):
        pool = [_candidate(0), _candidate(1)]
        state = driver.CampaignState("campaign", "random", "spike", 1, "semantic", pool, 999.0)
        with TemporaryDirectory() as tmp:
            round_dir = Path(tmp)
            for candidate in pool:
                _write_case_result(round_dir, candidate)
            _write_round_timeline(round_dir, [pool[0]])
            success = driver._ingest_round_results(state, round_dir, pool)

        self.assertFalse(success)
        self.assertEqual(state.completed_cases, 1)

    def test_ineligible_result_does_not_update_whitebox_feedback(self):
        pool = [_candidate(0)]
        state = driver.CampaignState("campaign", "bb-wb", "spike", 1, "semantic", pool, 999.0)
        with TemporaryDirectory() as tmp:
            round_dir = Path(tmp)
            _write_case_result(round_dir, pool[0], eligible=False)
            _write_round_timeline(round_dir, pool)
            with patch(
                "pmpfuzz.whitebox.whitebox_event_ids_for_result",
                return_value={"event-that-must-not-be-feedback"},
            ) as extract_mock:
                success = driver._ingest_round_results(
                    state, round_dir, pool, enable_whitebox=True
                )

        self.assertTrue(success)
        extract_mock.assert_not_called()
        self.assertEqual(state.whitebox_distinct_events, 0)


class TestRoundNumberingAndOwnership(unittest.TestCase):
    def test_bootstrap_advances_once_and_each_round_has_one_status(self):
        pool = [_candidate(i) for i in range(8)]
        captured: dict[str, driver.CampaignState] = {}

        def fake_run_round(base_cmd, round_dir, args, state, **kwargs):
            candidates = kwargs.get("bootstrap_candidates") or kwargs.get("expected_candidates") or []
            for candidate in candidates:
                if candidate["candidate_id"] not in state.executed_ids:
                    state.mark_executed(candidate["candidate_id"])
            state.record_round_result(True, {"process_success": True, "ingest_success": True})
            captured["state"] = state
            return True

        with TemporaryDirectory() as tmp:
            args = Namespace(
                artifact_root=Path(tmp),
                experiment_id="driver-e2e",
                campaign_id=None,
                variant="random",
                coverage_mode="semantic",
                dut="spike",
                seed=1,
                round_size=2,
                bootstrap_size=2,
                time_budget=60,
                per_case_timeout=1,
                jobs=1,
                whitebox=False,
                max_rounds=2,
                spike=None,
                isa=None,
                chipyard_dir=None,
                dut_bin=None,
                no_smepmp=False,
            )
            with patch.object(driver, "build_candidate_pool", return_value=pool):
                with patch("pmpfuzz.capabilities.capability_for_dut", return_value={}):
                    with patch.object(driver, "_build_base_cmd", return_value=(["fake"], {})):
                        with patch.object(driver, "_run_round", side_effect=fake_run_round) as run_mock:
                            with patch.object(driver, "_finalize"):
                                rc = driver.run_closed_loop(args)

        self.assertEqual(rc, 0)
        self.assertEqual(run_mock.call_count, 2)
        self.assertEqual(captured["state"].round_idx, 2)
        self.assertEqual(len(captured["state"]._round_results), 2)


class TestScheduleTraceability(unittest.TestCase):
    def test_random_selection_records_source(self):
        pool = [_candidate(i) for i in range(8)]
        state = driver.CampaignState("campaign", "random", "spike", 1, "semantic", pool, 0.0)
        selected = driver.select_next_candidates(state, 4, [], 1)
        self.assertEqual({item["selection_source"] for item in selected}, {"random"})

    def test_bb_wb_marks_whitebox_and_blackbox_sources(self):
        pool = [_candidate(i) for i in range(8)]
        state = driver.CampaignState("campaign", "bb-wb", "spike", 1, "semantic", pool, 0.0)
        whitebox_candidate = dict(pool[0])
        with patch.object(
            driver,
            "_whitebox_schedule",
            return_value=([whitebox_candidate], {"pmp-boundary": 1}, []),
        ):
            selected = driver._select_bb_wb(state, pool, 4, [], 1)

        by_id = {item["candidate_id"]: item for item in selected}
        self.assertEqual(by_id[whitebox_candidate["candidate_id"]]["selection_source"], "whitebox")
        self.assertEqual(len(selected), 4)
        self.assertTrue(
            all("selection_source" in item and "estimated_new_bins" in item for item in selected)
        )


if __name__ == "__main__":
    unittest.main()
