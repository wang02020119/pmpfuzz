import json
import unittest
from argparse import Namespace
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import scripts.evaluation.campaigns.run_closed_loop_campaign as driver
from pmpfuzz.continuous import ScenarioStream as _RealScenarioStream
from pmpfuzz.coverage_universe import make_coverage_universe
from pmpfuzz.schedule_v4 import ScheduleV4Writer, recover_schedule_v4
from pmpfuzz.scenario_codec import scenario_from_spec, scenario_to_spec


def _universes():
    return {
        "semantic": make_coverage_universe(
            coverage_mode="semantic",
            bin_ids=["sem:0", "sem:1", "sem:2"],
            capability_fingerprint="cap-conv",
            target="core-stateful",
            include_experimental=False,
            generator_seed=4,
        ),
        "pairwise": make_coverage_universe(
            coverage_mode="pairwise",
            bin_ids=["combo2:0", "combo2:1"],
            capability_fingerprint="cap-conv",
            target="core-stateful",
            include_experimental=False,
            generator_seed=4,
        ),
        "security_triples": make_coverage_universe(
            coverage_mode="security_triples",
            bin_ids=["combo3:0", "combo3:1"],
            capability_fingerprint="cap-conv",
            target="core-stateful",
            include_experimental=False,
            generator_seed=4,
        ),
        "predicates": make_coverage_universe(
            coverage_mode="predicates",
            bin_ids=["pred:0", "pred:1"],
            capability_fingerprint="cap-conv",
            target="core-stateful",
            include_experimental=False,
            generator_seed=4,
        ),
    }


def _args(
    root: Path,
    *,
    variant: str = "random-fresh",
    resume: bool = False,
    max_rounds: int | None = 10,
    low_watermark: int = 1,
    time_budget: int = 20,
    convergence_stop: bool = True,
    convergence_min_runtime_seconds: int = 10,
    convergence_confirmation_seconds: int = 6,
    convergence_confirmation_eligible_cases: int = 3,
    max_wall_time_seconds: int = 20,
) -> Namespace:
    root.mkdir(parents=True, exist_ok=True)
    dut_bin = root / "fake-dut.bin"
    if not dut_bin.exists():
        dut_bin.write_bytes(b"fake-dut-binary\n")
    return Namespace(
        artifact_root=root,
        experiment_id="continuous-convergence",
        campaign_id=None,
        variant=variant,
        coverage_mode="semantic",
        dut="spike",
        profile="pmp-boundary",
        bootstrap_profile=None,
        seed=4,
        round_size=1,
        bootstrap_size=1,
        time_budget=time_budget,
        per_case_timeout=1,
        jobs=1,
        whitebox=False,
        max_rounds=max_rounds,
        spike=None,
        isa=None,
        chipyard_dir=None,
        dut_bin=str(dut_bin),
        no_smepmp=False,
        resume=resume,
        pending_limit=8,
        corpus_limit=8,
        low_watermark=low_watermark,
        run_class="pilot",
        budget_class="primary-wall-clock",
        source_sha=None,
        dut_sha=None,
        dut_binary_sha256=None,
        capability_fingerprint=None,
        convergence_stop=convergence_stop,
        convergence_min_runtime_seconds=convergence_min_runtime_seconds,
        convergence_confirmation_seconds=convergence_confirmation_seconds,
        convergence_confirmation_eligible_cases=convergence_confirmation_eligible_cases,
        max_wall_time_seconds=max_wall_time_seconds,
    )


@dataclass
class _RoundPlan:
    elapsed_wall: float
    eligible: bool = True
    success: bool = True
    semantic: list[str] = field(default_factory=list)
    pairwise: list[str] = field(default_factory=list)
    security_triples: list[str] = field(default_factory=list)
    predicates: list[str] = field(default_factory=list)
    timeline_new_semantic: int | None = None
    timeline_new_pairwise: int | None = None
    timeline_new_security_triples: int | None = None
    timeline_new_predicates: int | None = None


def _planned_run_round(plans: list[_RoundPlan]):
    def _fake_run_round(
        base_cmd,
        round_dir,
        args,
        state,
        *,
        expected_candidates=None,
        on_case_ingested=None,
        **_kwargs,
    ):
        candidates = expected_candidates or []
        plan = plans[state.round_idx]
        for candidate in candidates:
            observed = {
                "semantic": list(plan.semantic),
                "pairwise": list(plan.pairwise),
                "security_triples": list(plan.security_triples),
                "predicates": list(plan.predicates),
            }
            state.record_case(
                candidate_id=candidate["candidate_id"],
                case_id=candidate["name"],
                profile=candidate["profile"],
                status="pass",
                failure_class=None,
                eligible=plan.eligible,
                qualification_reason="eligible" if plan.eligible else "rejected",
                elapsed_wall=plan.elapsed_wall,
                case_elapsed=0.1,
                new_semantic=(
                    (plan.timeline_new_semantic if plan.timeline_new_semantic is not None else len(plan.semantic))
                    if plan.eligible
                    else 0
                ),
                new_pairwise=(
                    (plan.timeline_new_pairwise if plan.timeline_new_pairwise is not None else len(plan.pairwise))
                    if plan.eligible
                    else 0
                ),
                new_triples=(
                    (
                        plan.timeline_new_security_triples
                        if plan.timeline_new_security_triples is not None
                        else len(plan.security_triples)
                    )
                    if plan.eligible
                    else 0
                ),
                new_predicates=(
                    (
                        plan.timeline_new_predicates
                        if plan.timeline_new_predicates is not None
                        else len(plan.predicates)
                    )
                    if plan.eligible
                    else 0
                ),
                new_whitebox=0,
                case_semantic=set(plan.semantic),
                case_pairwise=set(plan.pairwise),
                case_triples=set(plan.security_triples),
                case_predicates=set(plan.predicates),
            )
            if on_case_ingested is not None:
                on_case_ingested(
                    candidate,
                    {
                        "name": candidate["name"],
                        "profile": candidate["profile"],
                        "semantic_bins": list(plan.semantic),
                        "pairwise_bins": list(plan.pairwise),
                        "security_triple_bins": list(plan.security_triples),
                        "predicate_bins": list(plan.predicates),
                    },
                    {"status": "pass", "failure_class": None},
                    plan.eligible,
                    "eligible" if plan.eligible else "rejected",
                    float(plan.elapsed_wall),
                    observed,
                    0.1,
                    [],
                    0,
                )
        state.record_round_result(plan.success, {"process_success": plan.success, "ingest_success": plan.success, "returncode": 0})
        return plan.success

    return _fake_run_round


class _StallingFreshStream:
    def __init__(self, *, root_seed: int, **_kwargs):
        self.root_seed = root_seed
        self._base = _RealScenarioStream(root_seed=root_seed, profiles=("pmp-boundary",))
        self._scenarios = [
            self._base.generate_root(0),
            self._base.generate_root(1),
        ]

    def generate_root(self, sequence: int):
        if sequence < len(self._scenarios):
            scenario = self._scenarios[sequence]
        else:
            scenario = self._scenarios[-1]
        return scenario_from_spec(scenario_to_spec(scenario))


class ContinuousConvergenceTest(unittest.TestCase):
    def _campaign_dir(self, root: Path, variant: str) -> Path:
        return (
            root
            / "campaigns"
            / "continuous-convergence"
            / "spike"
            / variant
            / "semantic"
            / "seed-0004"
        )

    def _metadata(self, root: Path, variant: str) -> dict:
        return json.loads((self._campaign_dir(root, variant) / "metrics" / "campaign_metadata.json").read_text(encoding="ascii"))

    def _metadata_path(self, root: Path, variant: str) -> Path:
        return self._campaign_dir(root, variant) / "metrics" / "campaign_metadata.json"

    def _schedule_path(self, root: Path, variant: str) -> Path:
        return self._campaign_dir(root, variant) / "metrics" / "schedule_v4.jsonl"

    def _events(self, root: Path, variant: str) -> list[dict]:
        return [
            json.loads(line)
            for line in self._schedule_path(root, variant).read_text(encoding="ascii").splitlines()
            if line.strip()
        ]

    def _rewrite_latest_checkpoint(self, root: Path, variant: str, mutator) -> None:
        path = self._campaign_dir(root, variant) / "metrics" / "schedule_v4.jsonl"
        events = [
            json.loads(line)
            for line in path.read_text(encoding="ascii").splitlines()
            if line.strip()
        ]
        for index in range(len(events) - 1, -1, -1):
            if events[index].get("event") == "checkpoint":
                mutator(events[index])
                break
        else:
            raise AssertionError("missing checkpoint event")
        path.write_text(
            "".join(json.dumps(event, ensure_ascii=True, sort_keys=True) + "\n" for event in events),
            encoding="ascii",
        )

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_single_mode_novelty_prevents_convergence(self, *_mocks):
        plans = [
            _RoundPlan(1.0, semantic=["sem:0"], pairwise=["combo2:0"], security_triples=["combo3:0"], predicates=["pred:0"]),
            _RoundPlan(4.0),
            _RoundPlan(9.0, pairwise=["combo2:1"]),
            _RoundPlan(16.0),
        ]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                rc = driver.run_closed_loop(
                    _args(
                        root,
                        convergence_confirmation_eligible_cases=2,
                        max_rounds=len(plans),
                    )
                )
            metadata = self._metadata(root, "random-fresh")

        self.assertEqual(rc, 0)
        self.assertFalse(metadata["convergence_confirmed"])
        self.assertNotEqual(metadata["stop_reason"], "coverage_converged")

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_quiet_time_without_enough_eligible_does_not_converge(self, *_mocks):
        plans = [
            _RoundPlan(1.0, semantic=["sem:0"], pairwise=["combo2:0"], security_triples=["combo3:0"], predicates=["pred:0"]),
            _RoundPlan(4.0),
            _RoundPlan(7.0),
            _RoundPlan(10.0),
        ]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                rc = driver.run_closed_loop(
                    _args(
                        root,
                        convergence_confirmation_eligible_cases=4,
                        max_rounds=len(plans),
                    )
                )
            metadata = self._metadata(root, "random-fresh")

        self.assertEqual(rc, 0)
        self.assertFalse(metadata["convergence_confirmed"])
        self.assertNotEqual(metadata["stop_reason"], "coverage_converged")

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_enough_eligible_without_enough_time_does_not_converge(self, *_mocks):
        plans = [
            _RoundPlan(1.0, semantic=["sem:0"], pairwise=["combo2:0"], security_triples=["combo3:0"], predicates=["pred:0"]),
            _RoundPlan(4.0),
            _RoundPlan(7.0),
            _RoundPlan(10.0),
        ]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                rc = driver.run_closed_loop(
                    _args(
                        root,
                        convergence_confirmation_seconds=12,
                        max_rounds=len(plans),
                    )
                )
            metadata = self._metadata(root, "random-fresh")

        self.assertEqual(rc, 0)
        self.assertFalse(metadata["convergence_confirmed"])
        self.assertNotEqual(metadata["stop_reason"], "coverage_converged")

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_four_mode_stability_stops_with_coverage_converged(self, *_mocks):
        plans = [
            _RoundPlan(1.0, semantic=["sem:0"], pairwise=["combo2:0"], security_triples=["combo3:0"], predicates=["pred:0"]),
            _RoundPlan(4.0),
            _RoundPlan(7.0),
            _RoundPlan(10.0),
        ]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                rc = driver.run_closed_loop(_args(root, max_rounds=len(plans), low_watermark=2))
            metadata = self._metadata(root, "random-fresh")

        self.assertEqual(rc, 0)
        self.assertTrue(metadata["convergence_confirmed"])
        self.assertEqual(metadata["stop_reason"], "coverage_converged")

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_repeated_hits_without_new_bins_do_not_reset_novelty_and_can_converge(self, *_mocks):
        plans = [
            _RoundPlan(1.0, semantic=["sem:0"], pairwise=["combo2:0"], security_triples=["combo3:0"], predicates=["pred:0"]),
            _RoundPlan(
                8.0,
                semantic=["sem:0"],
                pairwise=["combo2:0"],
                security_triples=["combo3:0"],
                predicates=["pred:0"],
                timeline_new_semantic=0,
                timeline_new_pairwise=0,
                timeline_new_security_triples=0,
                timeline_new_predicates=0,
            ),
            _RoundPlan(
                16.0,
                semantic=["sem:0"],
                pairwise=["combo2:0"],
                security_triples=["combo3:0"],
                predicates=["pred:0"],
                timeline_new_semantic=0,
                timeline_new_pairwise=0,
                timeline_new_security_triples=0,
                timeline_new_predicates=0,
            ),
            _RoundPlan(
                24.0,
                semantic=["sem:0"],
                pairwise=["combo2:0"],
                security_triples=["combo3:0"],
                predicates=["pred:0"],
                timeline_new_semantic=0,
                timeline_new_pairwise=0,
                timeline_new_security_triples=0,
                timeline_new_predicates=0,
            ),
        ]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                rc = driver.run_closed_loop(
                    _args(
                        root,
                        low_watermark=2,
                        max_rounds=len(plans),
                        convergence_min_runtime_seconds=20,
                        convergence_confirmation_seconds=20,
                        convergence_confirmation_eligible_cases=2,
                        max_wall_time_seconds=40,
                        time_budget=40,
                    )
                )
            metadata = self._metadata(root, "random-fresh")

        self.assertEqual(rc, 0)
        self.assertTrue(metadata["convergence_confirmed"])
        self.assertEqual(metadata["stop_reason"], "coverage_converged")
        self.assertEqual(metadata["last_novelty_time"], 1.0)
        self.assertEqual(metadata["last_novelty_eligible_seq"], 1)
        self.assertEqual(metadata["convergence_time_seconds"], 24.0)

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_true_new_bins_reset_novelty_after_repeated_hits(self, *_mocks):
        plans = [
            _RoundPlan(1.0, semantic=["sem:0"], pairwise=["combo2:0"], security_triples=["combo3:0"], predicates=["pred:0"]),
            _RoundPlan(
                8.0,
                semantic=["sem:0"],
                pairwise=["combo2:0"],
                security_triples=["combo3:0"],
                predicates=["pred:0"],
                timeline_new_semantic=0,
                timeline_new_pairwise=0,
                timeline_new_security_triples=0,
                timeline_new_predicates=0,
            ),
            _RoundPlan(
                16.0,
                semantic=["sem:0"],
                pairwise=["combo2:0"],
                security_triples=["combo3:0"],
                predicates=["pred:0"],
                timeline_new_semantic=0,
                timeline_new_pairwise=0,
                timeline_new_security_triples=0,
                timeline_new_predicates=0,
            ),
            _RoundPlan(
                30.0,
                semantic=["sem:0", "sem:1"],
                pairwise=["combo2:0", "combo2:1"],
                security_triples=["combo3:0", "combo3:1"],
                predicates=["pred:0", "pred:1"],
            ),
            _RoundPlan(
                38.0,
                semantic=["sem:0", "sem:1"],
                pairwise=["combo2:0", "combo2:1"],
                security_triples=["combo3:0", "combo3:1"],
                predicates=["pred:0", "pred:1"],
                timeline_new_semantic=0,
                timeline_new_pairwise=0,
                timeline_new_security_triples=0,
                timeline_new_predicates=0,
            ),
            _RoundPlan(
                46.0,
                semantic=["sem:0", "sem:1"],
                pairwise=["combo2:0", "combo2:1"],
                security_triples=["combo3:0", "combo3:1"],
                predicates=["pred:0", "pred:1"],
                timeline_new_semantic=0,
                timeline_new_pairwise=0,
                timeline_new_security_triples=0,
                timeline_new_predicates=0,
            ),
            _RoundPlan(
                54.0,
                semantic=["sem:0", "sem:1"],
                pairwise=["combo2:0", "combo2:1"],
                security_triples=["combo3:0", "combo3:1"],
                predicates=["pred:0", "pred:1"],
                timeline_new_semantic=0,
                timeline_new_pairwise=0,
                timeline_new_security_triples=0,
                timeline_new_predicates=0,
            ),
        ]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                rc = driver.run_closed_loop(
                    _args(
                        root,
                        low_watermark=2,
                        max_rounds=len(plans),
                        convergence_min_runtime_seconds=40,
                        convergence_confirmation_seconds=20,
                        convergence_confirmation_eligible_cases=2,
                        max_wall_time_seconds=70,
                        time_budget=70,
                    )
                )
            metadata = self._metadata(root, "random-fresh")

        self.assertEqual(rc, 0)
        self.assertTrue(metadata["convergence_confirmed"])
        self.assertEqual(metadata["stop_reason"], "coverage_converged")
        self.assertEqual(metadata["last_novelty_time"], 30.0)
        self.assertEqual(metadata["last_novelty_eligible_seq"], 4)
        self.assertEqual(metadata["convergence_time_seconds"], 54.0)

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_no_new_unique_scenarios_prevents_convergence(self, *_mocks):
        plans = [
            _RoundPlan(1.0, semantic=["sem:0"], pairwise=["combo2:0"], security_triples=["combo3:0"], predicates=["pred:0"]),
            _RoundPlan(6.0),
        ]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                with patch("pmpfuzz.continuous.ScenarioStream", _StallingFreshStream):
                    rc = driver.run_closed_loop(
                        _args(
                            root,
                            low_watermark=2,
                            convergence_min_runtime_seconds=5,
                            convergence_confirmation_seconds=3,
                            convergence_confirmation_eligible_cases=1,
                            max_rounds=len(plans) + 1,
                        )
                    )
            metadata = self._metadata(root, "random-fresh")

        self.assertEqual(rc, 0)
        self.assertFalse(metadata["convergence_confirmed"])
        self.assertNotEqual(metadata["stop_reason"], "coverage_converged")

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_max_wall_time_marks_hard_cap_censored(self, *_mocks):
        plans = [
            _RoundPlan(1.0, semantic=["sem:0"], pairwise=["combo2:0"], security_triples=["combo3:0"], predicates=["pred:0"]),
            _RoundPlan(6.0),
            _RoundPlan(12.0),
        ]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                rc = driver.run_closed_loop(
                    _args(
                        root,
                        convergence_confirmation_eligible_cases=20,
                        max_wall_time_seconds=12,
                        time_budget=12,
                        max_rounds=len(plans),
                    )
                )
            metadata = self._metadata(root, "random-fresh")

        self.assertEqual(rc, 0)
        self.assertFalse(metadata["convergence_confirmed"])
        self.assertEqual(metadata["stop_reason"], "hard_cap_censored")

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_hard_cap_and_convergence_same_round_prefers_coverage_converged(self, *_mocks):
        plans = [
            _RoundPlan(1.0, semantic=["sem:0"], pairwise=["combo2:0"], security_triples=["combo3:0"], predicates=["pred:0"]),
            _RoundPlan(6.0),
            _RoundPlan(12.0),
        ]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                rc = driver.run_closed_loop(
                    _args(
                        root,
                        convergence_min_runtime_seconds=0,
                        convergence_confirmation_seconds=10,
                        convergence_confirmation_eligible_cases=2,
                        max_wall_time_seconds=12,
                        time_budget=12,
                        max_rounds=len(plans),
                    )
                )
            metadata = self._metadata(root, "random-fresh")

        self.assertEqual(rc, 0)
        self.assertTrue(metadata["convergence_confirmed"])
        self.assertEqual(metadata["stop_reason"], "coverage_converged")

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_resume_matches_uninterrupted_convergence_state(self, *_mocks):
        plans = [
            _RoundPlan(1.0, semantic=["sem:0"], pairwise=["combo2:0"], security_triples=["combo3:0"], predicates=["pred:0"]),
            _RoundPlan(
                8.0,
                semantic=["sem:0"],
                pairwise=["combo2:0"],
                security_triples=["combo3:0"],
                predicates=["pred:0"],
                timeline_new_semantic=0,
                timeline_new_pairwise=0,
                timeline_new_security_triples=0,
                timeline_new_predicates=0,
            ),
            _RoundPlan(
                16.0,
                semantic=["sem:0"],
                pairwise=["combo2:0"],
                security_triples=["combo3:0"],
                predicates=["pred:0"],
                timeline_new_semantic=0,
                timeline_new_pairwise=0,
                timeline_new_security_triples=0,
                timeline_new_predicates=0,
            ),
            _RoundPlan(
                24.0,
                semantic=["sem:0"],
                pairwise=["combo2:0"],
                security_triples=["combo3:0"],
                predicates=["pred:0"],
                timeline_new_semantic=0,
                timeline_new_pairwise=0,
                timeline_new_security_triples=0,
                timeline_new_predicates=0,
            ),
        ]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            direct = root / "direct"
            resumed = root / "resumed"
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                rc_direct = driver.run_closed_loop(
                    _args(
                        direct,
                        max_rounds=len(plans),
                        low_watermark=2,
                        convergence_min_runtime_seconds=20,
                        convergence_confirmation_seconds=20,
                        convergence_confirmation_eligible_cases=2,
                        max_wall_time_seconds=40,
                        time_budget=40,
                    )
                )
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                rc_split_1 = driver.run_closed_loop(
                    _args(
                        resumed,
                        max_rounds=2,
                        low_watermark=2,
                        convergence_min_runtime_seconds=20,
                        convergence_confirmation_seconds=20,
                        convergence_confirmation_eligible_cases=2,
                        max_wall_time_seconds=40,
                        time_budget=40,
                    )
                )
            self._rewrite_latest_checkpoint(
                resumed,
                "random-fresh",
                lambda event: event.update(
                    {
                        "last_novelty_time": 8.0,
                        "last_novelty_eligible_seq": 2,
                        "last_novelty_completed_cases": 2,
                        "last_novelty_unique_scenario_count": 999,
                        "convergence_last_mode_novelty": {
                            mode: {
                                "elapsed_wall_seconds": 8.0,
                                "completed_cases": 2,
                                "eligible_cases": 2,
                                "completion_seq": 2,
                            }
                            for mode in ("semantic", "pairwise", "security_triples", "predicates")
                        },
                    }
                ),
            )
            resumed_events = self._events(resumed, "random-fresh")
            if resumed_events[-1]["event"] == "campaign_closed":
                resumed_events.pop()
            self._schedule_path(resumed, "random-fresh").write_text(
                "".join(json.dumps(event, ensure_ascii=True, sort_keys=True) + "\n" for event in resumed_events),
                encoding="ascii",
            )
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                rc_split_2 = driver.run_closed_loop(
                    _args(
                        resumed,
                        resume=True,
                        max_rounds=len(plans),
                        low_watermark=2,
                        convergence_min_runtime_seconds=20,
                        convergence_confirmation_seconds=20,
                        convergence_confirmation_eligible_cases=2,
                        max_wall_time_seconds=40,
                        time_budget=40,
                    )
                )
            direct_meta = self._metadata(direct, "random-fresh")
            resumed_meta = self._metadata(resumed, "random-fresh")

        self.assertEqual((rc_direct, rc_split_1, rc_split_2), (0, 0, 0))
        self.assertEqual(direct_meta["stop_reason"], resumed_meta["stop_reason"])
        self.assertEqual(direct_meta["convergence_confirmed"], resumed_meta["convergence_confirmed"])
        self.assertEqual(direct_meta["last_novelty_time"], resumed_meta["last_novelty_time"])
        self.assertEqual(direct_meta["last_novelty_eligible_seq"], resumed_meta["last_novelty_eligible_seq"])
        self.assertEqual(resumed_meta["last_novelty_time"], 1.0)
        self.assertEqual(resumed_meta["last_novelty_eligible_seq"], 1)

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_stop_reason_persisted_to_metadata_and_schedule(self, *_mocks):
        plans = [
            _RoundPlan(1.0, semantic=["sem:0"], pairwise=["combo2:0"], security_triples=["combo3:0"], predicates=["pred:0"]),
            _RoundPlan(4.0),
            _RoundPlan(7.0),
            _RoundPlan(10.0),
        ]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                rc = driver.run_closed_loop(_args(root, max_rounds=len(plans), low_watermark=2))
            metadata = self._metadata(root, "random-fresh")
            events = self._events(root, "random-fresh")
            stop_latched = [event for event in events if event["event"] == "stop_latched"][-1]
            checkpoint = [event for event in events if event["event"] == "checkpoint"][-1]
            closed = [event for event in events if event["event"] == "campaign_closed"][-1]

        self.assertEqual(rc, 0)
        self.assertEqual(metadata["stop_reason"], "coverage_converged")
        self.assertEqual(stop_latched["stop_reason"], "coverage_converged")
        self.assertEqual(checkpoint["stop_reason"], "coverage_converged")
        self.assertEqual(closed["stop_reason"], "coverage_converged")
        self.assertTrue(metadata["convergence_confirmed"])

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_confirmed_with_pending_nonempty_discards_pending_and_stops_without_refill(self, *_mocks):
        from pmpfuzz.continuous_campaign import ContinuousQueueManager

        plans = [
            _RoundPlan(1.0, semantic=["sem:0"], pairwise=["combo2:0"], security_triples=["combo3:0"], predicates=["pred:0"]),
            _RoundPlan(8.0),
            _RoundPlan(16.0),
            _RoundPlan(24.0),
        ]
        fill_calls: list[int] = []
        original_fill = ContinuousQueueManager.fill_pending

        def _tracked_fill(self, low_watermark):
            fill_calls.append(int(self._mutation_attempt if hasattr(self, "_mutation_attempt") else 0))
            return original_fill(self, low_watermark)

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                with patch("pmpfuzz.continuous_campaign.ContinuousQueueManager.fill_pending", new=_tracked_fill):
                    rc = driver.run_closed_loop(
                        _args(
                            root,
                            low_watermark=3,
                            max_rounds=len(plans) + 5,
                            convergence_min_runtime_seconds=20,
                            convergence_confirmation_seconds=20,
                            convergence_confirmation_eligible_cases=2,
                            max_wall_time_seconds=40,
                            time_budget=40,
                        )
                    )
            metadata = self._metadata(root, "random-fresh")
            events = self._events(root, "random-fresh")

        self.assertEqual(rc, 0)
        self.assertEqual(len(fill_calls), len(plans))
        self.assertEqual(metadata["stop_reason"], "coverage_converged")
        self.assertEqual(metadata["completed_cases"], len(plans))
        stop_events = [event for event in events if event["event"] == "stop_latched"]
        self.assertEqual(len(stop_events), 1)
        self.assertTrue(stop_events[0]["convergence_confirmed"])
        self.assertTrue(stop_events[0]["convergence_pending_queue_nonempty"])
        discarded = [event for event in events if event["event"] == "candidate_discarded"]
        self.assertGreater(len(discarded), 0)
        checkpoints = [event for event in events if event["event"] == "checkpoint"]
        self.assertEqual(checkpoints[-1]["pending_count"], 0)

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_resume_latches_confirmed_null_without_new_executions(self, *_mocks):
        plans = [
            _RoundPlan(1.0, semantic=["sem:0"], pairwise=["combo2:0"], security_triples=["combo3:0"], predicates=["pred:0"]),
            _RoundPlan(
                8.0,
                semantic=["sem:0"],
                pairwise=["combo2:0"],
                security_triples=["combo3:0"],
                predicates=["pred:0"],
                timeline_new_semantic=0,
                timeline_new_pairwise=0,
                timeline_new_security_triples=0,
                timeline_new_predicates=0,
            ),
        ]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                rc_first = driver.run_closed_loop(
                    _args(
                        root,
                        low_watermark=3,
                        max_rounds=2,
                        convergence_min_runtime_seconds=10,
                        convergence_confirmation_seconds=10,
                        convergence_confirmation_eligible_cases=1,
                        max_wall_time_seconds=40,
                        time_budget=40,
                    )
                )
            schedule_path = self._schedule_path(root, "random-fresh")
            events_before = self._events(root, "random-fresh")
            if events_before[-1]["event"] == "campaign_closed":
                events_before.pop()
            schedule_path.write_text(
                "".join(json.dumps(event, ensure_ascii=True, sort_keys=True) + "\n" for event in events_before),
                encoding="ascii",
            )
            exec_count_before = sum(1 for event in events_before if event["event"] == "execution_committed")
            metadata_path = self._metadata_path(root, "random-fresh")
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
            metadata["elapsed_wall_seconds"] = 30.0
            metadata["stop_reason"] = None
            metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
            with patch.object(driver, "_run_round", side_effect=AssertionError("resume must not execute DUT cases")):
                rc_resume = driver.run_closed_loop(
                    _args(
                        root,
                        resume=True,
                        low_watermark=3,
                        max_rounds=5,
                        convergence_min_runtime_seconds=10,
                        convergence_confirmation_seconds=10,
                        convergence_confirmation_eligible_cases=1,
                        max_wall_time_seconds=40,
                        time_budget=40,
                    )
                )
            events_after = self._events(root, "random-fresh")
            metadata_after = self._metadata(root, "random-fresh")

        self.assertEqual((rc_first, rc_resume), (0, 0))
        self.assertEqual(
            exec_count_before,
            sum(1 for event in events_after if event["event"] == "execution_committed"),
        )
        self.assertEqual(metadata_after["stop_reason"], "coverage_converged")
        self.assertEqual(
            len([event for event in events_after if event["event"] == "stop_latched"]),
            1,
        )

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_resume_after_stop_latched_crash_writes_no_duplicate_stop_event(self, *_mocks):
        plans = [
            _RoundPlan(1.0, semantic=["sem:0"], pairwise=["combo2:0"], security_triples=["combo3:0"], predicates=["pred:0"]),
            _RoundPlan(
                8.0,
                semantic=["sem:0"],
                pairwise=["combo2:0"],
                security_triples=["combo3:0"],
                predicates=["pred:0"],
                timeline_new_semantic=0,
                timeline_new_pairwise=0,
                timeline_new_security_triples=0,
                timeline_new_predicates=0,
            ),
        ]
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(driver, "_run_round", side_effect=_planned_run_round(plans)):
                rc_first = driver.run_closed_loop(
                    _args(
                        root,
                        low_watermark=3,
                        max_rounds=2,
                        convergence_min_runtime_seconds=10,
                        convergence_confirmation_seconds=10,
                        convergence_confirmation_eligible_cases=1,
                        max_wall_time_seconds=40,
                        time_budget=40,
                    )
                )
            events = self._events(root, "random-fresh")
            if events[-1]["event"] == "campaign_closed":
                events.pop()
            schedule_path = self._schedule_path(root, "random-fresh")
            schedule_path.write_text(
                "".join(json.dumps(event, ensure_ascii=True, sort_keys=True) + "\n" for event in events),
                encoding="ascii",
            )
            recovered = recover_schedule_v4(schedule_path)
            pending_hashes = list(recovered.pending_hashes)
            checkpoint = [event for event in events if event["event"] == "checkpoint"][-1]
            stop_fields = {
                key: checkpoint[key]
                for key in checkpoint
                if key.startswith("convergence_")
                or key in {
                    "last_novelty_time",
                    "last_novelty_eligible_seq",
                    "last_novelty_completed_cases",
                    "last_novelty_unique_scenario_count",
                    "confirmation_window_seconds",
                    "confirmation_window_eligible_cases",
                    "stop_reason",
                    "max_wall_time_seconds",
                    "tracked_modes",
                }
            }
            stop_fields["stop_reason"] = "coverage_converged"
            writer = ScheduleV4Writer(schedule_path)
            for scenario_hash_value in pending_hashes:
                writer.append(
                    "candidate_discarded",
                    scenario_hash=scenario_hash_value,
                    discard_reason="discarded_due_to_convergence",
                    round_idx=0,
                )
            writer.append(
                "stop_latched",
                round_idx=0,
                pending_count=len(pending_hashes),
                corpus_count=0,
                completed_cases=1,
                eligible_cases=1,
                discarded_pending_count=len(pending_hashes),
                **stop_fields,
            )
            # Simulate a crash before checkpoint/campaign_closed.
            truncated_events = [
                json.loads(line)
                for line in schedule_path.read_text(encoding="ascii").splitlines()
                if line.strip()
            ]
            while truncated_events and truncated_events[-1]["event"] in {"checkpoint", "campaign_closed"}:
                truncated_events.pop()
            schedule_path.write_text(
                "".join(json.dumps(event, ensure_ascii=True, sort_keys=True) + "\n" for event in truncated_events),
                encoding="ascii",
            )
            metadata_path = self._metadata_path(root, "random-fresh")
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
            metadata["elapsed_wall_seconds"] = 30.0
            metadata["stop_reason"] = None
            metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
            with patch.object(driver, "_run_round", side_effect=AssertionError("resume must not execute DUT cases")):
                rc_resume = driver.run_closed_loop(
                    _args(
                        root,
                        resume=True,
                        low_watermark=3,
                        max_rounds=5,
                        convergence_min_runtime_seconds=10,
                        convergence_confirmation_seconds=10,
                        convergence_confirmation_eligible_cases=1,
                        max_wall_time_seconds=40,
                        time_budget=40,
                    )
                )
            events_after = self._events(root, "random-fresh")

        self.assertEqual((rc_first, rc_resume), (0, 0))
        self.assertEqual(
            len([event for event in events_after if event["event"] == "stop_latched"]),
            1,
        )
        self.assertEqual(
            len([event for event in events_after if event["event"] == "campaign_closed"]),
            1,
        )

    def test_stop_reason_latch_cannot_be_cleared_or_replaced(self):
        state = driver.CampaignState(
            "campaign",
            "random-fresh",
            "spike",
            4,
            "semantic",
            [],
            0.0,
            coverage_universes=_universes(),
        )

        state.set_stop_reason("coverage_converged")
        with self.assertRaises(ValueError):
            state.clear_stop_reason()
        with self.assertRaises(ValueError):
            state.set_stop_reason("hard_cap_censored")

    def test_legacy_hard_cap_name_normalizes_when_latched(self):
        state = driver.CampaignState(
            "campaign",
            "random-fresh",
            "spike",
            4,
            "semantic",
            [],
            0.0,
            coverage_universes=_universes(),
        )

        state.set_stop_reason("right_censored_not_converged")

        self.assertEqual(state.stop_reason, "hard_cap_censored")


if __name__ == "__main__":
    unittest.main()
