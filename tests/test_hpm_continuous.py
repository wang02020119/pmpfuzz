import unittest
from argparse import Namespace
from pathlib import Path

from pmpfuzz.continuous import ScenarioStream
from pmpfuzz.continuous_campaign import ContinuousQueueManager
from pmpfuzz.coverage_universe import make_coverage_universe
from pmpfuzz.hpm import build_hpm_coverage_universe
from pmpfuzz.scenario_codec import scenario_hash
from pmpfuzz.schema import scenario_to_case_dict
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.schedule_v4 import ScheduleV4Writer, recover_schedule_v4
from scripts.evaluation.campaigns.run_closed_loop_campaign import (
    CampaignState,
    ContinuousConvergenceTracker,
    _build_base_cmd,
    _ingest_round_results,
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
        "hpm": build_hpm_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
        ),
    }


class HpmContinuousQueueTest(unittest.TestCase):
    def test_stream_supports_single_profile_not_in_target_count_table(self):
        scenario = ScenarioStream(root_seed=5, profiles=("sv39-final-pmp",)).generate_root(0)

        self.assertEqual(scenario.profile, "sv39-final-pmp")

    def test_queue_accepts_hpm_as_active_coverage_mode(self):
        manager = ContinuousQueueManager(
            variant="bb-guided",
            stream=ScenarioStream(root_seed=7, profiles=("pmp-boundary",)),
            coverage_universes=_universes(),
            scheduler_seed=7,
            pending_limit=8,
            corpus_limit=4,
            coverage_mode="hpm",
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
                "hpm": ["event=exception|bucket=0-0.1"],
            },
            execution_cost=1.0,
        )

        self.assertEqual(summary["discovered_bins"]["hpm"], ["event=exception|bucket=0-0.1"])

    def test_bb_guided_energy_comes_from_new_hpm_bins(self):
        manager = ContinuousQueueManager(
            variant="bb-guided",
            stream=ScenarioStream(root_seed=9, profiles=("pmp-boundary",)),
            coverage_universes=_universes(),
            scheduler_seed=9,
            pending_limit=8,
            corpus_limit=8,
            coverage_mode="hpm",
        )

        manager.fill_pending(2)
        first, second = manager.pop_batch(2)
        first_summary = manager.prepare_execution(
            first,
            eligible=True,
            observed_bins={"semantic": [], "pairwise": [], "security_triples": [], "predicates": [], "hpm": []},
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
                "hpm": [
                    "event=exception|bucket=0-0.1",
                    "event=itlb_miss|bucket=0-0.1",
                ],
            },
            execution_cost=1.0,
        )

        self.assertLess(first_summary["corpus_entry"].energy, second_summary["corpus_entry"].energy)

    def test_random_parent_selection_does_not_depend_on_hpm_energy(self):
        stream = ScenarioStream(root_seed=11, profiles=("pmp-boundary",))
        manager_a = ContinuousQueueManager(
            variant="random-mutation",
            stream=stream,
            coverage_universes=_universes(),
            scheduler_seed=11,
            pending_limit=8,
            corpus_limit=8,
            coverage_mode="hpm",
        )
        manager_b = ContinuousQueueManager(
            variant="random-mutation",
            stream=ScenarioStream(root_seed=11, profiles=("pmp-boundary",)),
            coverage_universes=_universes(),
            scheduler_seed=11,
            pending_limit=8,
            corpus_limit=8,
            coverage_mode="hpm",
        )

        for manager, hpm_bins in (
            (manager_a, [["event=exception|bucket=0-0.1"], ["event=itlb_miss|bucket=10-100"]]),
            (manager_b, [["event=exception|bucket=0-0.1"], []]),
        ):
            manager.fill_pending(2)
            first, second = manager.pop_batch(2)
            for candidate, bins in zip((first, second), hpm_bins):
                summary = manager.prepare_execution(
                    candidate,
                    eligible=True,
                    observed_bins={
                        "semantic": [],
                        "pairwise": [],
                        "security_triples": [],
                        "predicates": [],
                        "hpm": bins,
                    },
                    execution_cost=1.0,
                )
                manager.commit_execution(candidate, summary)

        self.assertEqual(
            manager_a.choose_parent_for_mutation().scenario_hash,
            manager_b.choose_parent_for_mutation().scenario_hash,
        )


class HpmConvergenceTrackerTest(unittest.TestCase):
    def test_other_mode_novelty_does_not_reset_hpm_tracker(self):
        tracker = ContinuousConvergenceTracker(
            enabled=True,
            min_runtime_seconds=10.0,
            confirmation_seconds=5.0,
            confirmation_eligible_cases=3,
            tracked_modes=("hpm",),
        )

        tracker.note_execution(
            elapsed_wall_seconds=4.0,
            completed_cases=4,
            eligible_cases=4,
            completion_seq=4,
            unique_scenario_count=4,
            eligible=True,
            new_bins={"semantic": ["sem:0"], "hpm": []},
        )
        tracker.note_execution(
            elapsed_wall_seconds=6.0,
            completed_cases=6,
            eligible_cases=6,
            completion_seq=6,
            unique_scenario_count=6,
            eligible=True,
            new_bins={"hpm": ["event=exception|bucket=0-0.1"]},
        )
        tracker.note_execution(
            elapsed_wall_seconds=9.0,
            completed_cases=9,
            eligible_cases=9,
            completion_seq=9,
            unique_scenario_count=9,
            eligible=True,
            new_bins={"semantic": ["sem:1"], "hpm": []},
        )

        self.assertEqual(tracker.last_novelty_time, 6.0)
        self.assertEqual(tracker.last_novelty_eligible_seq, 6)


class HpmScheduleRecoveryTest(unittest.TestCase):
    def test_schedule_v4_recovers_hpm_bins(self):
        import tempfile
        from pathlib import Path

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
                    "hpm": ["event=exception|bucket=0-0.1"],
                },
                promoted=True,
                evicted_hashes=[],
                retained_without_novelty=False,
                security_events=[],
                new_whitebox_events=0,
            )

            recovered = recover_schedule_v4(path)

        self.assertEqual(
            recovered.candidate_discovered_bins[spec_hash]["hpm"],
            ["event=exception|bucket=0-0.1"],
        )
        self.assertEqual(
            recovered.coverage_state["hpm"],
            {"event=exception|bucket=0-0.1"},
        )


class HpmDriverContractTest(unittest.TestCase):
    def test_closed_loop_parser_accepts_hpm_coverage_mode(self):
        args = build_parser().parse_args(
            ["--artifact-root", "artifact-root", "--coverage-mode", "hpm"]
        )

        self.assertEqual(args.coverage_mode, "hpm")

    def test_base_command_passes_hpm_manifest_to_child_run(self):
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
            hpm_manifest="D:/artifacts/hpm_manifest_v1.json",
        )

        cmd, _ = _build_base_cmd(args)

        self.assertIn("--hpm-manifest", cmd)
        self.assertIn("D:/artifacts/hpm_manifest_v1.json", cmd)

    def test_round_ingestion_projects_hpm_result_into_parent_timeline(self):
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
            "hpm",
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
                        "hpm_snapshot_before": {
                            "minstret": 100,
                            "mcycle": 200,
                            "c3": 1,
                            "c4": 2,
                            "c5": 3,
                            "c6": 4,
                        },
                        "hpm_snapshot_after": {
                            "minstret": 200,
                            "mcycle": 320,
                            "c3": 2,
                            "c4": 2,
                            "c5": 3,
                            "c6": 4,
                        },
                        "hpm_coverage": {
                            "eligible": True,
                            "qualification_reason": "eligible",
                            "observed_bins": ["event=exception|bucket=0-0.1"],
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
        self.assertEqual(state._covered_hpm, {"event=exception|bucket=0-0.1"})
        self.assertEqual(state._eligible_hpm_cases, 1)
        self.assertEqual(state._timeline_lines[-1]["new_hpm_bins"], 1)
        self.assertEqual(state._timeline_lines[-1]["hpm_covered"], 1)

    def test_continuous_driver_constrains_stream_to_requested_profile(self):
        import tempfile
        from unittest.mock import patch

        captured: dict[str, object] = {}

        class FakeStream:
            def __init__(self, *, root_seed, profiles, **kwargs):
                captured["root_seed"] = root_seed
                captured["profiles"] = tuple(profiles)

        parser = build_parser()
        with tempfile.TemporaryDirectory() as tmp:
            args = parser.parse_args(
                [
                    "--variant",
                    "random-mutation",
                    "--coverage-mode",
                    "hpm",
                    "--dut",
                    "rocket-clean",
                    "--profile",
                    "sv39-final-pmp",
                    "--seed",
                    "1",
                    "--round-size",
                    "1",
                    "--time-budget",
                    "1",
                    "--per-case-timeout",
                    "1",
                    "--jobs",
                    "1",
                    "--run-class",
                    "development-smoke",
                    "--artifact-root",
                    tmp,
                    "--no-smepmp",
                    "--low-watermark",
                    "1",
                    "--pending-limit",
                    "1",
                    "--corpus-limit",
                    "1",
                ]
            )

            with patch("pmpfuzz.continuous.ScenarioStream", FakeStream):
                with patch(
                    "pmpfuzz.continuous_campaign.ContinuousQueueManager",
                    side_effect=RuntimeError("stop-after-stream-init"),
                ):
                    with self.assertRaisesRegex(RuntimeError, "stop-after-stream-init"):
                        run_continuous_closed_loop(args)

        self.assertEqual(captured["root_seed"], 1)
        self.assertEqual(captured["profiles"], ("sv39-final-pmp",))


class HpmCampaignStateTest(unittest.TestCase):
    def test_campaign_timeline_tracks_hpm_fields_monotonically(self):
        state = CampaignState(
            campaign_id="camp",
            variant="bb-guided",
            dut="rocket-clean",
            seed=1,
            coverage_mode="hpm",
            candidate_pool=[],
            start_time=0.0,
            coverage_universes=_universes(),
        )

        first = state.record_case(
            candidate_id="cand-1",
            case_id="case-1",
            profile="pmp-boundary",
            status="pass",
            failure_class=None,
            eligible=True,
            qualification_reason="eligible",
            elapsed_wall=1.0,
            case_elapsed=0.2,
            new_semantic=0,
            new_pairwise=0,
            new_triples=0,
            new_predicates=0,
            new_whitebox=0,
            new_hpm=1,
            hpm_eligible=True,
            case_hpm={"event=exception|bucket=0-0.1"},
            hpm_snapshot={"last_hpm_novelty_time": 1.0},
        )
        second = state.record_case(
            candidate_id="cand-2",
            case_id="case-2",
            profile="pmp-boundary",
            status="pass",
            failure_class=None,
            eligible=True,
            qualification_reason="eligible",
            elapsed_wall=2.0,
            case_elapsed=0.2,
            new_semantic=1,
            new_pairwise=0,
            new_triples=0,
            new_predicates=0,
            new_whitebox=0,
            new_hpm=0,
            hpm_eligible=False,
            case_hpm=set(),
            hpm_snapshot={"last_hpm_novelty_time": 1.0},
        )

        self.assertEqual(first["hpm_covered"], 1)
        self.assertEqual(second["hpm_covered"], 1)
        self.assertEqual(second["eligible_hpm_cases"], 1)
        self.assertEqual(second["last_hpm_novelty_time"], 1.0)


if __name__ == "__main__":
    unittest.main()
