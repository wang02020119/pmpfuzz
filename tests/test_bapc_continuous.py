import unittest
from argparse import Namespace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from pmpfuzz.bapc import build_bapc_coverage_universe
from pmpfuzz.continuous import ScenarioStream
from pmpfuzz.continuous_campaign import ContinuousQueueManager
from pmpfuzz.coverage_universe import make_coverage_universe
from pmpfuzz.scenario_codec import scenario_hash
from pmpfuzz.schedule_v4 import ScheduleV4Writer, recover_schedule_v4
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.schema import scenario_to_case_dict
from scripts.evaluation.campaigns.run_closed_loop_campaign import (
    CampaignState,
    ContinuousConvergenceTracker,
    _build_base_cmd,
    _ingest_round_results,
    _rebuild_convergence_state_from_recovery,
    build_parser,
    run_continuous_closed_loop,
)


def _universes():
    return {
        "semantic": make_coverage_universe(
            coverage_mode="semantic",
            bin_ids=["sem:0"],
            capability_fingerprint="cap-x",
            target="core-stateful",
            include_experimental=False,
            generator_seed=1,
        ),
        "pairwise": make_coverage_universe(
            coverage_mode="pairwise",
            bin_ids=["combo2:0"],
            capability_fingerprint="cap-x",
            target="core-stateful",
            include_experimental=False,
            generator_seed=1,
        ),
        "security_triples": make_coverage_universe(
            coverage_mode="security_triples",
            bin_ids=["combo3:0"],
            capability_fingerprint="cap-x",
            target="core-stateful",
            include_experimental=False,
            generator_seed=1,
        ),
        "predicates": make_coverage_universe(
            coverage_mode="predicates",
            bin_ids=["pred:0"],
            capability_fingerprint="cap-x",
            target="core-stateful",
            include_experimental=False,
            generator_seed=1,
        ),
        "bapc": build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
        ),
    }


def _first_bapc_bin() -> str:
    return _universes()["bapc"]["bin_ids"][0]


class BapcContinuousQueueTest(unittest.TestCase):
    def test_queue_accepts_bapc_as_active_coverage_mode(self):
        manager = ContinuousQueueManager(
            variant="bb-guided",
            stream=ScenarioStream(root_seed=7, profiles=("pmp-boundary",)),
            coverage_universes=_universes(),
            scheduler_seed=7,
            pending_limit=8,
            corpus_limit=4,
            coverage_mode="bapc",
        )

        manager.fill_pending(1)
        candidate = manager.pop_batch(1)[0]
        summary = manager.prepare_execution(
            candidate,
            eligible=True,
            observed_bins={
                "semantic": [],
                "pairwise": [],
                "security_triples": [],
                "predicates": [],
                "bapc": [_first_bapc_bin()],
            },
            execution_cost=1.0,
        )

        self.assertEqual(summary["discovered_bins"]["bapc"], [_first_bapc_bin()])

    def test_bb_guided_energy_comes_from_new_bapc_bins(self):
        universe = _universes()["bapc"]["bin_ids"]
        manager = ContinuousQueueManager(
            variant="bb-guided",
            stream=ScenarioStream(root_seed=9, profiles=("pmp-boundary",)),
            coverage_universes=_universes(),
            scheduler_seed=9,
            pending_limit=8,
            corpus_limit=8,
            coverage_mode="bapc",
        )

        manager.fill_pending(2)
        first, second = manager.pop_batch(2)
        first_summary = manager.prepare_execution(
            first,
            eligible=True,
            observed_bins={"semantic": [], "pairwise": [], "security_triples": [], "predicates": [], "bapc": []},
            execution_cost=1.0,
        )
        second_summary = manager.prepare_execution(
            second,
            eligible=True,
            observed_bins={
                "semantic": [],
                "pairwise": [],
                "security_triples": [],
                "predicates": [],
                "bapc": [universe[0], universe[1]],
            },
            execution_cost=1.0,
        )

        self.assertLess(first_summary["corpus_entry"].energy, second_summary["corpus_entry"].energy)


class BapcConvergenceTrackerTest(unittest.TestCase):
    def test_bapc_tracker_requires_both_time_and_eligible_windows(self):
        tracker = ContinuousConvergenceTracker(
            enabled=True,
            min_runtime_seconds=0.0,
            confirmation_seconds=600.0,
            confirmation_eligible_cases=300,
            tracked_modes=("bapc",),
        )

        tracker.note_execution(
            elapsed_wall_seconds=10.0,
            completed_cases=1,
            eligible_cases=1,
            completion_seq=1,
            unique_scenario_count=1,
            eligible=True,
            new_bins={"bapc": [_first_bapc_bin()]},
        )

        not_enough_eligible = tracker.evaluate(
            elapsed_wall_seconds=610.0,
            completed_cases=300,
            eligible_cases=300,
            unique_scenario_count=300,
            pending_count=1,
            any_round_failed=False,
        )
        not_enough_time = tracker.evaluate(
            elapsed_wall_seconds=609.0,
            completed_cases=301,
            eligible_cases=301,
            unique_scenario_count=301,
            pending_count=1,
            any_round_failed=False,
        )
        converged = tracker.evaluate(
            elapsed_wall_seconds=610.0,
            completed_cases=301,
            eligible_cases=301,
            unique_scenario_count=301,
            pending_count=1,
            any_round_failed=False,
        )

        self.assertIsNone(not_enough_eligible["suggested_stop_reason"])
        self.assertIsNone(not_enough_time["suggested_stop_reason"])
        self.assertEqual(converged["suggested_stop_reason"], "coverage_converged")

    def test_other_mode_novelty_does_not_reset_bapc_tracker(self):
        tracker = ContinuousConvergenceTracker(
            enabled=True,
            min_runtime_seconds=10.0,
            confirmation_seconds=5.0,
            confirmation_eligible_cases=3,
            tracked_modes=("bapc",),
        )

        tracker.note_execution(
            elapsed_wall_seconds=4.0,
            completed_cases=4,
            eligible_cases=4,
            completion_seq=4,
            unique_scenario_count=4,
            eligible=True,
            new_bins={"semantic": ["sem:0"], "bapc": []},
        )
        tracker.note_execution(
            elapsed_wall_seconds=6.0,
            completed_cases=6,
            eligible_cases=6,
            completion_seq=6,
            unique_scenario_count=6,
            eligible=True,
            new_bins={"bapc": [_first_bapc_bin()]},
        )
        tracker.note_execution(
            elapsed_wall_seconds=9.0,
            completed_cases=9,
            eligible_cases=9,
            completion_seq=9,
            unique_scenario_count=9,
            eligible=True,
            new_bins={"semantic": ["sem:1"], "bapc": []},
        )

        self.assertEqual(tracker.last_novelty_time, 6.0)
        self.assertEqual(tracker.last_novelty_eligible_seq, 6)

    def test_bapc_mode_snapshot_is_side_effect_free(self):
        state = CampaignState(
            "campaign",
            "random-mutation",
            "rocket-clean",
            1,
            "bapc",
            [],
            0.0,
            coverage_universes=_universes(),
        )
        state.configure_convergence(
            enabled=True,
            min_runtime_seconds=10.0,
            confirmation_seconds=10.0,
            confirmation_eligible_cases=1,
            tracked_modes=("bapc",),
        )
        state.note_convergence_execution(
            elapsed_wall_seconds=1.0,
            eligible=True,
            new_bins={"bapc": [_first_bapc_bin()]},
            unique_scenario_count=1,
            completed_cases=1,
            eligible_cases=1,
        )

        snapshot = state.convergence_mode_snapshot()

        self.assertIn("bapc", snapshot)
        self.assertFalse(state.convergence_confirmed)
        self.assertIsNone(state.stop_reason)

    def test_bapc_novelty_anchor_uses_bapc_eligible_counter(self):
        state = CampaignState(
            "campaign",
            "random-mutation",
            "rocket-clean",
            1,
            "bapc",
            [],
            0.0,
            coverage_universes=_universes(),
        )
        state.configure_convergence(
            enabled=True,
            min_runtime_seconds=0.0,
            confirmation_seconds=10.0,
            confirmation_eligible_cases=1,
            tracked_modes=("bapc",),
        )
        state.set_unique_scenario_count(10)
        state._completed_cases = 10
        state._eligible_cases = 4
        state._eligible_bapc_cases = 1

        state.note_convergence_execution(
            elapsed_wall_seconds=50.0,
            eligible=True,
            new_bins={"bapc": [_first_bapc_bin()]},
            unique_scenario_count=10,
            completed_cases=10,
            eligible_cases=4,
        )

        snapshot = state.convergence_snapshot(
            elapsed_wall_seconds=50.0,
            unique_scenario_count=10,
            pending_count=1,
        )

        self.assertEqual(snapshot["last_novelty_eligible_seq"], 1)

    def test_bapc_confirmation_window_uses_bapc_eligible_counter(self):
        state = CampaignState(
            "campaign",
            "random-mutation",
            "rocket-clean",
            1,
            "bapc",
            [],
            0.0,
            coverage_universes=_universes(),
        )
        state.configure_convergence(
            enabled=True,
            min_runtime_seconds=0.0,
            confirmation_seconds=10.0,
            confirmation_eligible_cases=1,
            tracked_modes=("bapc",),
        )
        state.set_unique_scenario_count(1)
        state._completed_cases = 1
        state._eligible_cases = 1
        state._eligible_bapc_cases = 1
        state.note_convergence_execution(
            elapsed_wall_seconds=10.0,
            eligible=True,
            new_bins={"bapc": [_first_bapc_bin()]},
            unique_scenario_count=1,
            completed_cases=1,
            eligible_cases=1,
        )

        state.set_unique_scenario_count(2)
        state._completed_cases = 2
        state._eligible_cases = 2
        state._eligible_bapc_cases = 1

        snapshot = state.convergence_snapshot(
            elapsed_wall_seconds=30.0,
            unique_scenario_count=2,
            pending_count=1,
        )

        self.assertEqual(snapshot["confirmation_window_eligible_cases"], 0)
        self.assertFalse(snapshot["convergence_confirmed"])

    def test_bapc_recovery_rebuild_uses_bapc_eligible_counter(self):
        state = CampaignState(
            "campaign",
            "random-mutation",
            "rocket-clean",
            1,
            "bapc",
            [],
            0.0,
            coverage_universes=_universes(),
        )
        state.configure_convergence(
            enabled=True,
            min_runtime_seconds=0.0,
            confirmation_seconds=10.0,
            confirmation_eligible_cases=1,
            tracked_modes=("bapc",),
        )

        recovered = SimpleNamespace(
            execution_commits=[
                {
                    "_recovered_completed_cases": 1,
                    "_recovered_eligible_cases": 1,
                    "_recovered_unique_scenario_count": 1,
                    "elapsed_wall_seconds": 10.0,
                    "eligible": True,
                    "bapc_eligible": True,
                    "new_bins": {"bapc": [_first_bapc_bin()]},
                },
                {
                    "_recovered_completed_cases": 2,
                    "_recovered_eligible_cases": 2,
                    "_recovered_unique_scenario_count": 2,
                    "elapsed_wall_seconds": 20.0,
                    "eligible": True,
                    "bapc_eligible": False,
                    "new_bins": {"bapc": []},
                },
            ]
        )

        with TemporaryDirectory() as tmp:
            _rebuild_convergence_state_from_recovery(
                state,
                Path(tmp) / "timeline.jsonl",
                recovered,
            )

        snapshot = state.convergence_snapshot(
            elapsed_wall_seconds=30.0,
            unique_scenario_count=2,
            pending_count=1,
        )

        self.assertEqual(snapshot["last_novelty_eligible_seq"], 1)
        self.assertEqual(snapshot["confirmation_window_eligible_cases"], 0)
        self.assertFalse(snapshot["convergence_confirmed"])


class BapcScheduleRecoveryTest(unittest.TestCase):
    def test_schedule_v4_normalizes_legacy_hard_cap_stop_reason(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedule_v4.jsonl"
            writer = ScheduleV4Writer(path)
            writer.append(
                "stop_latched",
                round_idx=0,
                pending_count=0,
                corpus_count=0,
                completed_cases=0,
                eligible_cases=0,
                stop_reason="right_censored_not_converged",
            )

            recovered = recover_schedule_v4(path)

        self.assertEqual(recovered.stop_reason, "hard_cap_censored")

    def test_schedule_v4_recovers_bapc_bins(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedule_v4.jsonl"
            writer = ScheduleV4Writer(path)
            spec = {"name": "x", "profile": "pmp-boundary"}
            spec_hash = scenario_hash(spec)
            writer.append(
                "candidate_admitted",
                scenario_hash=spec_hash,
                scenario_spec=spec,
                profile="pmp-boundary",
                name="x",
                parent_hash=None,
                mutation_operator="root",
                mutation_seed=0,
                generation_seq=1,
                mutation_depth=0,
                root_sequence=0,
                rejection_reason=None,
            )
            writer.append(
                "execution_committed",
                scenario_hash=spec_hash,
                candidate_id="cand-1",
                case_id="x",
                profile="pmp-boundary",
                status="pass",
                failure_class=None,
                eligible=True,
                qualification_reason="eligible",
                elapsed_wall_seconds=1.0,
                case_elapsed_seconds=0.2,
                execution_cost=0.2,
                new_bins={
                    "semantic": [],
                    "pairwise": [],
                    "security_triples": [],
                    "predicates": [],
                    "bapc": [_first_bapc_bin()],
                },
                promoted=True,
                evicted_hashes=[],
                retained_without_novelty=False,
                security_events=[],
                new_whitebox_events=0,
            )

            recovered = recover_schedule_v4(path)

        self.assertEqual(
            recovered.candidate_discovered_bins[spec_hash]["bapc"],
            [_first_bapc_bin()],
        )
        self.assertEqual(recovered.coverage_state["bapc"], {_first_bapc_bin()})

    def test_schedule_v4_recovers_stop_latched_and_discarded_pending(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "schedule_v4.jsonl"
            writer = ScheduleV4Writer(path)
            spec_a = {"name": "a", "profile": "pmp-boundary"}
            spec_b = {"name": "b", "profile": "pmp-boundary"}
            hash_a = scenario_hash(spec_a)
            hash_b = scenario_hash(spec_b)
            for generation_seq, spec_hash, spec, root_sequence in (
                (1, hash_a, spec_a, 0),
                (2, hash_b, spec_b, 1),
            ):
                writer.append(
                    "candidate_admitted",
                    scenario_hash=spec_hash,
                    scenario_spec=spec,
                    profile="pmp-boundary",
                    name=spec["name"],
                    parent_hash=None,
                    mutation_operator="root",
                    mutation_seed=0,
                    generation_seq=generation_seq,
                    mutation_depth=0,
                    root_sequence=root_sequence,
                    rejection_reason=None,
                )
            writer.append(
                "candidate_discarded",
                scenario_hash=hash_b,
                discard_reason="discarded_due_to_convergence",
                round_idx=0,
            )
            writer.append(
                "stop_latched",
                round_idx=0,
                pending_count=1,
                corpus_count=0,
                completed_cases=0,
                eligible_cases=0,
                discarded_pending_count=1,
                stop_reason="coverage_converged",
                convergence_enabled=True,
                convergence_confirmed=True,
                convergence_confirmation_seconds=10.0,
                convergence_confirmation_eligible_cases=1,
                convergence_last_mode_novelty={
                    "bapc": {
                        "elapsed_wall_seconds": 1.0,
                        "completed_cases": 1,
                        "eligible_cases": 1,
                        "completion_seq": 1,
                    }
                },
            )

            recovered = recover_schedule_v4(path)

        self.assertTrue(recovered.stop_latched)
        self.assertEqual(recovered.stop_reason, "coverage_converged")
        self.assertNotIn(hash_b, recovered.pending_hashes)
        self.assertIn(hash_a, recovered.seen_hashes)


class BapcDriverContractTest(unittest.TestCase):
    def test_closed_loop_parser_accepts_bapc_coverage_mode(self):
        args = build_parser().parse_args(
            ["--artifact-root", "artifact-root", "--coverage-mode", "bapc"]
        )
        self.assertEqual(args.coverage_mode, "bapc")

    def test_base_command_does_not_require_hpm_manifest_for_bapc(self):
        args = Namespace(
            dut="rocket-clean",
            round_size=8,
            per_case_timeout=10,
            jobs=8,
            whitebox=False,
            spike=None,
            isa=None,
            chipyard_dir=None,
            dut_bin=None,
            no_smepmp=True,
            hpm_manifest=None,
        )

        cmd, _ = _build_base_cmd(args)

        self.assertNotIn("--hpm-manifest", cmd)

    def test_round_ingestion_projects_bapc_result_into_parent_timeline(self):
        import json
        import tempfile

        scenario = ScenarioGenerator(seed=17, include_smepmp=False, profile="pmp-boundary").generate_batch(1)[0]
        case = scenario_to_case_dict(scenario, seed=17, index=0)
        pool = [
            {
                "candidate_id": "cand-1",
                "profile": case["profile"],
                "generation_seed": 17,
                "scenario_index": 0,
                "name": case["name"],
                "scenario_hash": case["scenario_hash"],
            }
        ]
        state = CampaignState(
            "campaign",
            "random-mutation",
            "spike",
            17,
            "bapc",
            pool,
            1000.0,
            coverage_universes=_universes(),
        )

        with tempfile.TemporaryDirectory() as tmp:
            round_dir = Path(tmp)
            case_dir = round_dir / "cases" / case["name"]
            result_dir = round_dir / "results" / case["name"]
            metrics_dir = round_dir / "metrics"
            case_dir.mkdir(parents=True, exist_ok=True)
            result_dir.mkdir(parents=True, exist_ok=True)
            metrics_dir.mkdir(parents=True, exist_ok=True)
            (case_dir / "case.json").write_text(json.dumps(case), encoding="ascii")
            (result_dir / "result.json").write_text(
                json.dumps(
                    {
                        "name": case["name"],
                        "dut": "spike",
                        "status": "pass",
                        "elapsed_seconds": 0.2,
                        "observation_valid": True,
                        "observed_event": "completion",
                        "observed_phase": "completed",
                        "observed_tohost": 0,
                        "oracle_applicability": "valid",
                        "bapc_coverage": {
                            "bapc_schema_version": 2,
                            "bapc_core_version": "v2",
                            "eligible": True,
                            "qualification_reason": "eligible",
                            "observed_bins": [_first_bapc_bin()],
                        },
                    }
                ),
                encoding="ascii",
            )
            (metrics_dir / "coverage_timeline.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "schema_version": 1,
                                "campaign_id": "round",
                                "completion_seq": 0,
                                "case_id": None,
                                "elapsed_wall_seconds": 0.0,
                            }
                        ),
                        json.dumps(
                            {
                                "schema_version": 1,
                                "campaign_id": "round",
                                "completion_seq": 1,
                                "case_id": case["name"],
                                "elapsed_wall_seconds": 1.0,
                                "completion_monotonic_seconds": 1001.0,
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="ascii",
            )

            success = _ingest_round_results(state, round_dir, pool)

        self.assertTrue(success)
        self.assertEqual(state._covered_bapc, {_first_bapc_bin()})
        self.assertEqual(state._eligible_bapc_cases, 1)
        self.assertEqual(state._timeline_lines[-1]["new_bapc_bins"], 1)
        self.assertEqual(state._timeline_lines[-1]["bapc_covered"], 1)

    def test_continuous_driver_can_materialize_bapc_universe(self):
        with TemporaryDirectory() as tmp:
            spike_bin = Path(tmp) / "spike"
            spike_bin.write_bytes(b"spike-binary")
            args = build_parser().parse_args(
                [
                    "--artifact-root",
                    tmp,
                    "--coverage-mode",
                    "bapc",
                    "--bapc-core-version",
                    "v2",
                    "--variant",
                    "random-fresh",
                    "--dut",
                    "spike",
                    "--spike",
                    str(spike_bin),
                    "--time-budget",
                    "60",
                    "--max-rounds",
                    "0",
                    "--jobs",
                    "1",
                    "--round-size",
                    "1",
                    "--per-case-timeout",
                    "1",
                    "--no-smepmp",
                ]
            )

            rc = run_continuous_closed_loop(args)

        self.assertEqual(rc, 0)

if __name__ == "__main__":
    unittest.main()
