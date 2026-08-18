import json
import unittest
from argparse import Namespace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import scripts.evaluation.campaigns.run_closed_loop_campaign as driver
from pmpfuzz.bapc import (
    BAPC_SCHEMA_VERSION,
    build_bapc_coverage_universe,
    load_bapc_coverage_universe,
)
from pmpfuzz.continuous import ScenarioStream as _RealScenarioStream
from pmpfuzz.coverage_universe import make_coverage_universe
from pmpfuzz.experiment_protocols import (
    BAPC_CONVERGENCE_PROTOCOL_ID,
    build_bapc_convergence_contract,
)
from pmpfuzz.schedule_v4 import ScheduleV4Writer, recover_schedule_v4
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.scenario_codec import scenario_from_spec, scenario_hash, scenario_to_spec
from pmpfuzz.schema import scenario_to_case_dict, write_json
from scripts.evaluation.validation.validate_timeline import validate_timeline


def _universes():
    return {
        "semantic": make_coverage_universe(
            coverage_mode="semantic",
            bin_ids=["sem:0", "sem:1", "sem:2"],
            capability_fingerprint="cap-z",
            target="core-stateful",
            include_experimental=False,
            generator_seed=1,
        ),
        "pairwise": make_coverage_universe(
            coverage_mode="pairwise",
            bin_ids=["combo2:0"],
            capability_fingerprint="cap-z",
            target="core-stateful",
            include_experimental=False,
            generator_seed=1,
        ),
        "security_triples": make_coverage_universe(
            coverage_mode="security_triples",
            bin_ids=["combo3:0"],
            capability_fingerprint="cap-z",
            target="core-stateful",
            include_experimental=False,
            generator_seed=1,
        ),
        "predicates": make_coverage_universe(
            coverage_mode="predicates",
            bin_ids=["pred:0"],
            capability_fingerprint="cap-z",
            target="core-stateful",
            include_experimental=False,
            generator_seed=1,
        ),
    }


def _args(
    root: Path,
    *,
    variant: str,
    generator_variant: str = "full",
    resume: bool = False,
    max_rounds: int = 1,
    low_watermark: int = 2,
    pending_limit: int = 8,
    corpus_limit: int = 8,
    run_class: str = "pilot",
) -> Namespace:
    root.mkdir(parents=True, exist_ok=True)
    dut_bin = root / "fake-dut.bin"
    if not dut_bin.exists():
        dut_bin.write_bytes(b"fake-dut-binary\n")
    return Namespace(
        artifact_root=root,
        experiment_id="continuous-e2e",
        campaign_id=None,
        variant=variant,
        generator_variant=generator_variant,
        coverage_mode="semantic",
        dut="spike",
        profile="pmp-boundary",
        bootstrap_profile=None,
        seed=1,
        round_size=1,
        bootstrap_size=1,
        time_budget=60,
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
        pending_limit=pending_limit,
        corpus_limit=corpus_limit,
        low_watermark=low_watermark,
        run_class=run_class,
        budget_class="primary-wall-clock",
        experiment_protocol_id="",
        convergence_stop=False,
        convergence_min_runtime_seconds=None,
        convergence_confirmation_seconds=None,
        convergence_confirmation_eligible_cases=None,
        max_wall_time_seconds=None,
        source_sha=None,
        dut_sha=None,
        dut_binary_sha256=None,
        capability_fingerprint=None,
        dut_source_dir=None,
        bapc_core_version=None,
    )


def _formal_bapc_args(
    root: Path,
    *,
    variant: str = "random-mutation",
    seed: int = 4,
) -> Namespace:
    args = _args(root, variant=variant, run_class="formal", max_rounds=None)
    args.experiment_id = "boom-formal"
    args.coverage_mode = "bapc"
    args.bapc_core_version = "v2"
    args.dut = "boom-clean"
    args.seed = seed
    args.time_budget = 7200
    args.experiment_protocol_id = BAPC_CONVERGENCE_PROTOCOL_ID
    return args


def _formal_bapc_universe() -> dict[str, dict]:
    return {
        "bapc": build_bapc_coverage_universe(
            dut="boom-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
        )
    }


def _fixed_pool():
    return [
        {
            "candidate_id": "cand-0000",
            "name": "case-0000",
            "profile": "pmp-boundary",
            "generation_seed": 1,
            "scenario_index": 0,
            "semantic_bins": ["sem:0"],
            "pairwise_bins": ["combo2:0"],
            "security_triple_bins": ["combo3:0"],
            "predicate_bins": ["pred:0"],
        }
    ]


def _fixed_pool_bapc():
    candidate = dict(_fixed_pool()[0])
    candidate["bapc_bins"] = [
        "family=config|pmp_mode=off|permission_rwx=000|locked=false"
    ]
    return [candidate]


def _bapc_universes(*, core_version: str = "v3") -> dict[str, dict]:
    universes = dict(_universes())
    universes["bapc"] = build_bapc_coverage_universe(
        dut="spike",
        generator_seed=1,
        supports_fault_stage=True,
        supports_smepmp=True,
        bapc_core_version=core_version,
    )
    return universes


def _write_round_case_and_result(
    round_dir: Path,
    *,
    bapc_payload: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    scenario = ScenarioGenerator(seed=97, include_smepmp=False, profile="pmp-boundary").generate_one(0)
    case = scenario_to_case_dict(scenario, seed=97, index=0)
    candidate = {
        "candidate_id": "cand-0000",
        "name": str(case["name"]),
        "profile": str(case["profile"]),
        "scenario_hash": str(case["scenario_hash"]),
    }
    write_json(round_dir / "cases" / case["name"] / "case.json", case)
    write_json(
        round_dir / "results" / case["name"] / "result.json",
        {
            "name": case["name"],
            "profile": case["profile"],
            "dut": "spike",
            "status": "pass",
            "failure_class": None,
            "oracle_applicability": "valid",
            "observation_valid": True,
            "observed_event": "completion",
            "observed_phase": "completed",
            "observed_tohost": 1,
            "elapsed_seconds": 0.1,
            "bapc_coverage": bapc_payload,
        },
    )
    timeline_path = round_dir / "metrics" / "coverage_timeline.jsonl"
    timeline_path.parent.mkdir(parents=True, exist_ok=True)
    timeline_path.write_text(
        json.dumps(
            {
                "completion_seq": 1,
                "case_id": case["name"],
                "elapsed_wall_seconds": 0.1,
            },
            ensure_ascii=True,
        )
        + "\n",
        encoding="ascii",
    )
    return case, candidate


def _fake_run_round(base_cmd, round_dir, args, state, *, expected_candidates=None, on_case_ingested=None, **kwargs):
    candidates = expected_candidates or []
    for candidate in candidates:
        compatible_semantic = [f"sem:{state.completed_cases % 3}"]
        compatible_pairwise = ["combo2:0"]
        compatible_triples = ["combo3:0"]
        compatible_predicates = ["pred:0"]
        compatible_bapc = []
        if state.coverage_mode == "bapc":
            compatible_bapc = list(state.target_bapc_bins)[:1]
        state.record_case(
            candidate_id=candidate["candidate_id"],
            case_id=candidate["name"],
            profile=candidate["profile"],
            status="pass",
            failure_class=None,
            eligible=True,
            qualification_reason="eligible",
            elapsed_wall=float(state.completed_cases + 1),
            case_elapsed=0.1,
            new_semantic=len(compatible_semantic),
            new_pairwise=len(compatible_pairwise),
            new_triples=len(compatible_triples),
            new_predicates=len(compatible_predicates),
            new_whitebox=0,
            new_bapc=len(compatible_bapc),
            bapc_eligible=bool(compatible_bapc),
            case_bapc=set(compatible_bapc),
            case_semantic=set(compatible_semantic),
            case_pairwise=set(compatible_pairwise),
            case_triples=set(compatible_triples),
            case_predicates=set(compatible_predicates),
        )
        if on_case_ingested is not None:
            on_case_ingested(
                candidate,
                {
                    "name": candidate["name"],
                    "profile": candidate["profile"],
                    "semantic_bins": list(compatible_semantic),
                    "pairwise_bins": list(compatible_pairwise),
                    "security_triple_bins": list(compatible_triples),
                    "predicate_bins": list(compatible_predicates),
                },
                {"status": "pass", "failure_class": None},
                True,
                "eligible",
                float(state.completed_cases),
                {
                    "semantic": list(compatible_semantic),
                    "pairwise": list(compatible_pairwise),
                    "security_triples": list(compatible_triples),
                    "predicates": list(compatible_predicates),
                },
                0.1,
                [],
                0,
            )
    state.record_round_result(True, {"process_success": True, "ingest_success": True, "returncode": 0})
    return True


class _NoOpThenChildStream:
    def __init__(self, *, root_seed: int, **_kwargs):
        self.root_seed = root_seed
        self._base = _RealScenarioStream(root_seed=root_seed, profiles=("pmp-boundary",))
        self._parent = self._base.generate_root(2)

    def generate_root(self, sequence: int):
        if sequence == 0:
            return self._parent
        return self._base.generate_root(sequence + 10)

    def applicable_operators(self, parent_spec):
        return ("synthetic-no-op",)

    def mutate(self, parent_spec, operator, attempt):
        if attempt == 0:
            return scenario_from_spec(parent_spec)
        return self._base.mutate(parent_spec, "toggle-access", attempt)


class ContinuousDriverTest(unittest.TestCase):
    def _generated_events(self, campaign: Path) -> list[dict]:
        return [
            json.loads(line)
            for line in (campaign / "metrics" / "schedule_v4.jsonl").read_text(encoding="ascii").splitlines()
            if line.strip()
        ]

    def test_parser_accepts_continuous_variants_and_resume(self):
        parser = driver.build_parser()
        args = parser.parse_args(
            [
                "--artifact-root",
                "out",
                "--variant",
                "random-mutation",
                "--resume",
            ]
        )
        self.assertEqual(args.variant, "random-mutation")
        self.assertTrue(args.resume)

    def test_parser_rejects_unknown_run_class(self):
        parser = driver.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "--artifact-root",
                    "out",
                    "--run-class",
                    "fomral",
                ]
            )

    def test_parser_accepts_generator_variant_and_max_completed_cases(self):
        parser = driver.build_parser()
        args = parser.parse_args(
            [
                "--artifact-root",
                "out",
                "--variant",
                "bb-guided",
                "--generator-variant",
                "syntax",
                "--max-completed-cases",
                "256",
            ]
        )
        self.assertEqual(args.generator_variant, "syntax")
        self.assertEqual(args.max_completed_cases, 256)

    def test_formal_bapc_requires_protocol_id_before_round_execution(self):
        with TemporaryDirectory() as tmp:
            args = _formal_bapc_args(Path(tmp))
            args.experiment_protocol_id = ""
            with patch.object(
                driver,
                "_run_round",
                side_effect=AssertionError("formal preflight must fail before DUT execution"),
            ):
                with self.assertRaisesRegex(ValueError, "protocol"):
                    driver.run_closed_loop(args)

    def test_formal_bapc_rejects_explicit_mismatched_protocol_parameters(self):
        scenarios = [
            ("time_budget", 28800),
            ("max_wall_time_seconds", 28800),
            ("convergence_min_runtime_seconds", 1),
            ("convergence_confirmation_seconds", 601),
            ("convergence_confirmation_eligible_cases", 301),
        ]
        for field, bad_value in scenarios:
            with self.subTest(field=field, bad_value=bad_value):
                with TemporaryDirectory() as tmp:
                    args = _formal_bapc_args(Path(tmp))
                    setattr(args, field, bad_value)
                    with patch.object(
                        driver,
                        "_run_round",
                        side_effect=AssertionError("formal preflight must fail before DUT execution"),
                    ):
                        with self.assertRaisesRegex(ValueError, field):
                            driver.run_closed_loop(args)

    def test_formal_bapc_contract_manifest_is_full_matrix_from_first_campaign(self):
        with TemporaryDirectory() as tmp:
            artifact_root = Path(tmp)
            args = _formal_bapc_args(artifact_root, variant="random-mutation", seed=4)
            driver._write_experiment_contract_manifest(args, artifact_root, _formal_bapc_universe())
            contract = json.loads(
                (artifact_root / "manifests" / "experiment-contract.json").read_text(
                    encoding="ascii"
                )
            )

        self.assertEqual(
            sorted(contract["variants"]),
            ["bb-guided", "cascade", "random-mutation"],
        )
        self.assertEqual(contract["seeds"], [4, 5, 6])

    def test_formal_bapc_existing_contract_mismatch_fails_closed(self):
        with TemporaryDirectory() as tmp:
            artifact_root = Path(tmp)
            manifests_dir = artifact_root / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            args = _formal_bapc_args(artifact_root, variant="random-mutation", seed=4)
            universe = _formal_bapc_universe()["bapc"]
            mismatched = build_bapc_convergence_contract(
                dut="boom-clean",
                bin_count=int(universe["bin_count"]),
                bin_set_sha256=str(universe["bin_set_sha256"]),
                variants=["random-mutation"],
                seeds=[4],
            )
            contract_path = manifests_dir / "experiment-contract.json"
            original = json.dumps(mismatched, indent=2, ensure_ascii=True) + "\n"
            contract_path.write_text(original, encoding="ascii")

            with self.assertRaisesRegex(ValueError, "experiment-contract"):
                driver._write_experiment_contract_manifest(args, artifact_root, {"bapc": universe})
            self.assertEqual(contract_path.read_text(encoding="ascii"), original)

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_random_mutation_driver_records_noop_rejection_and_reaches_next_round(self, *_mocks):
        with TemporaryDirectory() as tmp:
            args = _args(
                Path(tmp),
                variant="random-mutation",
                max_rounds=2,
                low_watermark=1,
                pending_limit=4,
                corpus_limit=4,
            )
            with patch("pmpfuzz.continuous.ScenarioStream", _NoOpThenChildStream):
                rc = driver.run_closed_loop(args)

            self.assertEqual(rc, 0)
            campaign = (
                Path(tmp)
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "random-mutation"
                / "semantic"
                / "seed-0001"
            )
            events = self._generated_events(campaign)
            event_names = [item["event"] for item in events]
            metadata = json.loads((campaign / "metrics" / "campaign_metadata.json").read_text(encoding="ascii"))

        self.assertIn("candidate_rejected", event_names)
        self.assertIn("candidate_admitted", event_names)
        self.assertEqual(metadata["completed_rounds"], 2)
        self.assertEqual(
            [
                item["rejection_reason"]
                for item in events
                if item["event"] == "candidate_rejected"
            ][0],
            "mutation-no-semantic-change",
        )

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_resume_matches_uninterrupted_stream_after_noop_rejection(self, *_mocks):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            direct_root = root / "direct"
            resumed_root = root / "resumed"
            with patch("pmpfuzz.continuous.ScenarioStream", _NoOpThenChildStream):
                rc_direct = driver.run_closed_loop(
                    _args(direct_root, variant="random-mutation", max_rounds=3, low_watermark=1)
                )
                rc_split_1 = driver.run_closed_loop(
                    _args(resumed_root, variant="random-mutation", max_rounds=1, low_watermark=1)
                )
                rc_split_2 = driver.run_closed_loop(
                    _args(
                        resumed_root,
                        variant="random-mutation",
                        resume=True,
                        max_rounds=3,
                        low_watermark=1,
                    )
                )

            self.assertEqual((rc_direct, rc_split_1, rc_split_2), (0, 0, 0))

            def project(root_path: Path):
                campaign = (
                    root_path
                    / "campaigns"
                    / "continuous-e2e"
                    / "spike"
                    / "random-mutation"
                    / "semantic"
                    / "seed-0001"
                )
                return [
                    {
                        "event": item["event"],
                        "scenario_hash": item.get("scenario_hash"),
                        "parent_hash": item.get("parent_hash"),
                        "mutation_seed": item.get("mutation_seed"),
                        "rejection_reason": item.get("rejection_reason"),
                    }
                    for item in self._generated_events(campaign)
                    if item["event"] in {"candidate_admitted", "candidate_rejected"}
                ]

            direct_events = project(direct_root)
            resumed_events = project(resumed_root)

        self.assertEqual(direct_events, resumed_events)
        self.assertTrue(any(item["event"] == "candidate_rejected" for item in direct_events))

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_development_smoke_precreates_local_manifests_scope(self, *_mocks):
        with TemporaryDirectory() as tmp:
            outer_root = Path(tmp) / "artifact-parent"
            outer_root.mkdir(parents=True)
            outer_manifests = outer_root / "manifests"
            outer_manifests.mkdir(parents=True)
            (outer_manifests / "environment.json").write_text('{"parent": true}\n', encoding="ascii")
            (outer_manifests / "git-shas.txt").write_text("a" * 40 + "  parent\n", encoding="ascii")
            (outer_manifests / "artifact-sha256.txt").write_text(
                f"{'0' * 64}  missing-file.txt\n",
                encoding="ascii",
            )
            artifact_root = outer_root / "child-run"
            args = _args(
                artifact_root,
                variant="random-mutation",
                max_rounds=1,
                low_watermark=1,
                run_class="development-smoke",
            )
            with patch("pmpfuzz.continuous.ScenarioStream", _NoOpThenChildStream):
                rc = driver.run_closed_loop(args)

            self.assertEqual(rc, 0)
            campaign = (
                artifact_root
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "random-mutation"
                / "semantic"
                / "seed-0001"
            )
            report = validate_timeline(campaign)
            manifests_exists = (artifact_root / "manifests").is_dir()
            report_valid = report["valid"]
            report_checks = report["checks"]
            references_parent_manifest = any(
                "missing-file.txt" in str(check.get("detail"))
                for check in report["checks"]
            )

        self.assertTrue(manifests_exists)
        self.assertTrue(report_valid, report_checks)
        self.assertFalse(references_parent_manifest)

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_strict_run_generates_global_manifests(self, *_mocks):
        with TemporaryDirectory() as tmp:
            args = _args(Path(tmp), variant="random-mutation", max_rounds=1, low_watermark=1, run_class="pilot")
            with patch("pmpfuzz.continuous.ScenarioStream", _NoOpThenChildStream):
                rc = driver.run_closed_loop(args)

            self.assertEqual(rc, 0)
            manifests_dir = Path(tmp) / "manifests"
            environment_exists = (manifests_dir / "environment.json").is_file()
            git_shas_exists = (manifests_dir / "git-shas.txt").is_file()
            scope_exists = (manifests_dir / "analysis-scope.json").is_file()
            artifact_sha_exists = (manifests_dir / "artifact-sha256.txt").is_file()

        self.assertTrue(environment_exists)
        self.assertTrue(git_shas_exists)
        self.assertTrue(scope_exists)
        self.assertTrue(artifact_sha_exists)

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_strict_skip_finalize_still_writes_artifact_sha_manifest(self, *_mocks):
        with TemporaryDirectory() as tmp:
            args = _args(Path(tmp), variant="random-mutation", max_rounds=1, low_watermark=1, run_class="pilot")
            args.skip_artifact_root_finalize = True
            with patch("pmpfuzz.continuous.ScenarioStream", _NoOpThenChildStream):
                rc = driver.run_closed_loop(args)

            self.assertEqual(rc, 0)
            manifests_dir = Path(tmp) / "manifests"
            campaign = (
                Path(tmp)
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "random-mutation"
                / "semantic"
                / "seed-0001"
            )
            report = validate_timeline(campaign)
            artifact_sha_exists = (manifests_dir / "artifact-sha256.txt").is_file()

        self.assertTrue(artifact_sha_exists)
        self.assertTrue(report["valid"], report["checks"])

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_strict_run_scope_records_guidance_metric_and_four_modes(self, *_mocks):
        with TemporaryDirectory() as tmp:
            args = _args(Path(tmp), variant="random-mutation", max_rounds=1, low_watermark=1, run_class="pilot")
            with patch("pmpfuzz.continuous.ScenarioStream", _NoOpThenChildStream):
                rc = driver.run_closed_loop(args)

            self.assertEqual(rc, 0)
            scope = json.loads((Path(tmp) / "manifests" / "analysis-scope.json").read_text(encoding="ascii"))

        self.assertEqual(scope["guidance_mode"], "semantic")
        self.assertEqual(scope["primary_metric"], "semantic")
        self.assertEqual(
            scope["coverage_modes"],
            ["pairwise", "predicates", "security-triples", "semantic"],
        )

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_random_fresh_writes_schedule_v4_and_metadata(self, *_mocks):
        with TemporaryDirectory() as tmp:
            args = _args(Path(tmp), variant="random-fresh", max_rounds=1)

            rc = driver.run_closed_loop(args)

            self.assertEqual(rc, 0)
            campaign = (
                Path(tmp)
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "random-fresh"
                / "semantic"
                / "seed-0001"
            )
            schedule_v4 = campaign / "metrics" / "schedule_v4.jsonl"
            metadata = json.loads((campaign / "metrics" / "campaign_metadata.json").read_text(encoding="ascii"))
            events = [json.loads(line) for line in schedule_v4.read_text(encoding="ascii").splitlines() if line.strip()]
            coverage = json.loads((campaign / "coverage" / "coverage.json").read_text(encoding="ascii"))

        self.assertTrue(events)
        self.assertEqual(metadata["driver_mode"], "continuous")
        self.assertIn("schedule_v4", metadata)
        self.assertIn("random-fresh", metadata["variant"])
        self.assertIn("candidate_admitted", [item["event"] for item in events])
        self.assertIn("execution_committed", [item["event"] for item in events])
        self.assertIn("campaign_closed", [item["event"] for item in events])
        self.assertNotIn("execution_completed", [item["event"] for item in events])
        self.assertNotIn("candidate_queued", [item["event"] for item in events])
        self.assertEqual(coverage["covered_target_bins"], 1)
        self.assertEqual(coverage["target_bins"], 3)

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_random_fresh_writes_strict_metadata_contract(self, *_mocks):
        with TemporaryDirectory() as tmp:
            args = _args(Path(tmp), variant="random-fresh", max_rounds=1)

            rc = driver.run_closed_loop(args)

            self.assertEqual(rc, 0)
            campaign = (
                Path(tmp)
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "random-fresh"
                / "semantic"
                / "seed-0001"
            )
            metadata = json.loads((campaign / "metrics" / "campaign_metadata.json").read_text(encoding="ascii"))
            self.assertTrue(Path(metadata["dut_binary_path"]).is_file())

        self.assertEqual(metadata["method"], "pmpfuzz")
        self.assertEqual(metadata["run_class"], "pilot")
        self.assertEqual(metadata["budget_class"], "primary-wall-clock")
        self.assertEqual(metadata["wall_clock_horizon_seconds"], 60)
        self.assertEqual(metadata["coverage_schema"], "pmpfuzz-v1-four-mode")
        self.assertTrue(metadata["source_sha"])
        self.assertEqual(metadata["dut_sha_status"], "not-applicable")
        self.assertTrue(metadata["dut_sha_reason"])
        self.assertTrue(metadata["dut_binary_sha256"])
        self.assertEqual(len(metadata["source_tree_sha256"]), 64)
        self.assertIs(type(metadata["source_dirty"]), bool)
        self.assertEqual(metadata["capability_fingerprint"], "cap-z")

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "build_candidate_pool", return_value=_fixed_pool())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_fixed_random_writes_strict_metadata_contract(self, *_mocks):
        with TemporaryDirectory() as tmp:
            args = _args(Path(tmp), variant="random", max_rounds=1)

            rc = driver.run_closed_loop(args)

            self.assertEqual(rc, 0)
            campaign = (
                Path(tmp)
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "random"
                / "semantic"
                / "seed-0001"
            )
            metadata = json.loads((campaign / "metrics" / "campaign_metadata.json").read_text(encoding="ascii"))
            self.assertTrue(Path(metadata["dut_binary_path"]).is_file())

        self.assertEqual(metadata["method"], "pmpfuzz")
        self.assertEqual(metadata["run_class"], "pilot")
        self.assertEqual(metadata["budget_class"], "primary-wall-clock")
        self.assertEqual(metadata["wall_clock_horizon_seconds"], 60)
        self.assertEqual(metadata["coverage_schema"], "pmpfuzz-v1-four-mode")
        self.assertTrue(metadata["source_sha"])
        self.assertEqual(metadata["dut_sha_status"], "not-applicable")
        self.assertTrue(metadata["dut_sha_reason"])
        self.assertTrue(metadata["dut_binary_sha256"])
        self.assertEqual(len(metadata["source_tree_sha256"]), 64)
        self.assertIs(type(metadata["source_dirty"]), bool)
        self.assertEqual(metadata["capability_fingerprint"], "cap-z")

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_bapc_metadata_records_target_operation_contract(self, *_mocks):
        with TemporaryDirectory() as tmp:
            args = _args(Path(tmp), variant="random-fresh", max_rounds=1)
            args.coverage_mode = "bapc"
            args.bapc_core_version = "v2"

            rc = driver.run_closed_loop(args)

            self.assertEqual(rc, 0)
            campaign = (
                Path(tmp)
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "random-fresh"
                / "bapc"
                / "seed-0001"
            )
            metadata = json.loads((campaign / "metrics" / "campaign_metadata.json").read_text(encoding="ascii"))
            universe = load_bapc_coverage_universe(
                campaign / "metrics" / "coverage_universe" / "bapc_v2.json"
            )

        self.assertEqual(metadata["coverage_mode"], "bapc")
        self.assertEqual(metadata["bapc_schema_version"], 2)
        self.assertEqual(metadata["bapc_measurement_mode"], "target-operation")
        self.assertFalse(metadata["probe_required"])
        self.assertFalse(metadata["instrumented_supplemental_enabled"])
        self.assertEqual(Path(metadata["coverage_universe_files"]["bapc"]).name, "bapc_v2.json")
        self.assertEqual(universe["bin_count"], 208)
        self.assertEqual(metadata["coverage_universe_hashes"]["bapc"], universe["sha256"])

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_bapc_v3_metadata_records_selected_universe_contract(self, *_mocks):
        with TemporaryDirectory() as tmp:
            args = _args(Path(tmp), variant="random-fresh", max_rounds=1)
            args.coverage_mode = "bapc"
            args.bapc_core_version = "v3"

            rc = driver.run_closed_loop(args)

            self.assertEqual(rc, 0)
            campaign = (
                Path(tmp)
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "random-fresh"
                / "bapc"
                / "seed-0001"
            )
            metadata = json.loads((campaign / "metrics" / "campaign_metadata.json").read_text(encoding="ascii"))
            universe = load_bapc_coverage_universe(
                campaign / "metrics" / "coverage_universe" / "bapc_v3.json"
            )

        self.assertEqual(metadata["coverage_mode"], "bapc")
        self.assertEqual(Path(metadata["coverage_universe_files"]["bapc"]).name, "bapc_v3.json")
        self.assertEqual(universe["bin_count"], 129)
        self.assertEqual(metadata["coverage_universe_hashes"]["bapc"], universe["sha256"])

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_bapc_requires_explicit_core_version_selection(self, *_mocks):
        parser = driver.build_parser()
        with TemporaryDirectory() as tmp:
            args = parser.parse_args(
                [
                    "--artifact-root",
                    tmp,
                    "--variant",
                    "random-fresh",
                    "--coverage-mode",
                    "bapc",
                    "--dut-bin",
                    str(Path(tmp) / "fake-dut.bin"),
                ]
            )
            with self.assertRaisesRegex(ValueError, "bapc-core-version"):
                driver.run_closed_loop(args)

    def test_build_base_cmd_threads_selected_bapc_core_version_to_child_runner(self):
        with TemporaryDirectory() as tmp:
            args = _args(Path(tmp), variant="bb-guided", generator_variant="syntax", max_rounds=1)
            args.coverage_mode = "bapc"
            args.bapc_core_version = "v4"

            cmd, _env = driver._build_base_cmd(args)

        self.assertIn("--generator-variant", cmd)
        self.assertEqual(cmd[cmd.index("--generator-variant") + 1], "syntax")
        self.assertIn("--bapc-core-version", cmd)
        self.assertEqual(cmd[cmd.index("--bapc-core-version") + 1], "v4")

    def test_fixed_pool_bapc_guided_variants_fail_closed(self):
        for variant in ("guided", "bb", "bb-wb"):
            with self.subTest(variant=variant):
                with TemporaryDirectory() as tmp:
                    args = _args(Path(tmp), variant=variant, max_rounds=1)
                    args.coverage_mode = "bapc"
                    args.bapc_core_version = "v3"

                    with self.assertRaisesRegex(ValueError, "does not support fixed-pool BAPC guidance"):
                        driver.run_closed_loop(args)

    def test_ingest_round_results_rejects_bapc_version_mismatch(self):
        with TemporaryDirectory() as tmp:
            round_dir = Path(tmp) / "round_0001"
            universes = _bapc_universes(core_version="v3")
            target_bin = universes["bapc"]["bin_ids"][0]
            _case, candidate = _write_round_case_and_result(
                round_dir,
                bapc_payload={
                    "eligible": True,
                    "qualification_reason": "eligible",
                    "bapc_core_version": "v2",
                    "observed_bins": [target_bin],
                },
            )
            state = driver.CampaignState(
                campaign_id="cid",
                variant="random",
                dut="spike",
                seed=1,
                coverage_mode="bapc",
                candidate_pool=[candidate],
                start_time=0.0,
                coverage_universes=universes,
            )

            ok = driver._ingest_round_results(state, round_dir, [candidate])

        self.assertFalse(ok)
        self.assertEqual(len(state._covered_bapc), 0)

    def test_ingest_round_results_rejects_out_of_contract_bapc_bins(self):
        with TemporaryDirectory() as tmp:
            round_dir = Path(tmp) / "round_0001"
            v3_universes = _bapc_universes(core_version="v3")
            v2_universes = _bapc_universes(core_version="v2")
            v3_bins = set(v3_universes["bapc"]["bin_ids"])
            v2_only_bin = next(item for item in v2_universes["bapc"]["bin_ids"] if item not in v3_bins)
            _case, candidate = _write_round_case_and_result(
                round_dir,
                bapc_payload={
                    "eligible": True,
                    "qualification_reason": "eligible",
                    "bapc_core_version": "v3",
                    "observed_bins": [v2_only_bin],
                },
            )
            state = driver.CampaignState(
                campaign_id="cid",
                variant="random",
                dut="spike",
                seed=1,
                coverage_mode="bapc",
                candidate_pool=[candidate],
                start_time=0.0,
                coverage_universes=v3_universes,
            )

            ok = driver._ingest_round_results(state, round_dir, [candidate])

        self.assertFalse(ok)
        self.assertEqual(len(state._covered_bapc), 0)

    def test_ingest_round_results_skips_bapc_contract_for_non_bapc_campaign(self):
        with TemporaryDirectory() as tmp:
            round_dir = Path(tmp) / "round_0001"
            _case, candidate = _write_round_case_and_result(
                round_dir,
                bapc_payload={
                    "eligible": True,
                    "qualification_reason": "eligible",
                    "bapc_schema_version": BAPC_SCHEMA_VERSION,
                    "bapc_core_version": "v3",
                    "observed_bins": [
                        "family=config|pmp_mode=off|permission_rwx=000|locked=false"
                    ],
                },
            )
            state = driver.CampaignState(
                campaign_id="cid",
                variant="random",
                dut="spike",
                seed=1,
                coverage_mode="semantic",
                candidate_pool=[candidate],
                start_time=0.0,
                coverage_universes=_universes(),
            )

            ok = driver._ingest_round_results(state, round_dir, [candidate])

        self.assertTrue(ok)
        self.assertEqual(state.completed_cases, 1)
        self.assertEqual(len(state._covered_bapc), 0)

    def test_validate_bapc_payload_contract_rejects_ineligible_missing_or_v2_payloads(self):
        state = driver.CampaignState(
            campaign_id="cid",
            variant="random",
            dut="spike",
            seed=1,
            coverage_mode="bapc",
            candidate_pool=[],
            start_time=0.0,
            coverage_universes=_bapc_universes(core_version="v3"),
        )
        cases = [
            ("missing", {}, "missing BAPC payload"),
            (
                "v2",
                {
                    "eligible": False,
                    "qualification_reason": "filtered",
                    "bapc_schema_version": BAPC_SCHEMA_VERSION,
                    "bapc_core_version": "v2",
                    "observed_bins": [],
                },
                "BAPC core version mismatch",
            ),
        ]

        for label, payload, expected in cases:
            with self.subTest(label=label):
                observed, errors = driver._validate_bapc_payload_contract(
                    state=state,
                    case_name=f"case-{label}",
                    payload=payload,
                    eligible=False,
                )

                self.assertEqual(observed, set())
                self.assertEqual(len(errors), 1)
                self.assertIn(expected, errors[0])

    def test_validate_bapc_payload_contract_accepts_legal_ineligible_v3_payload(self):
        state = driver.CampaignState(
            campaign_id="cid",
            variant="random",
            dut="spike",
            seed=1,
            coverage_mode="bapc",
            candidate_pool=[],
            start_time=0.0,
            coverage_universes=_bapc_universes(core_version="v3"),
        )

        observed, errors = driver._validate_bapc_payload_contract(
            state=state,
            case_name="case-v3-ineligible",
            payload={
                "eligible": False,
                "qualification_reason": "filtered",
                "bapc_schema_version": BAPC_SCHEMA_VERSION,
                "bapc_core_version": "v3",
                "observed_bins": [],
            },
            eligible=False,
        )

        self.assertEqual(observed, set())
        self.assertEqual(errors, [])

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "build_candidate_pool", return_value=_fixed_pool_bapc())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_fixed_pool_variants_write_selected_bapc_v3_universe_contract(self, *_mocks):
        for variant in ("random",):
            with self.subTest(variant=variant):
                with TemporaryDirectory() as tmp:
                    args = _args(Path(tmp), variant=variant, max_rounds=1)
                    args.coverage_mode = "bapc"
                    args.bapc_core_version = "v3"

                    rc = driver.run_closed_loop(args)

                    self.assertEqual(rc, 0)
                    campaign = (
                        Path(tmp)
                        / "campaigns"
                        / "continuous-e2e"
                        / "spike"
                        / variant
                        / "bapc"
                        / "seed-0001"
                    )
                    metadata = json.loads(
                        (campaign / "metrics" / "campaign_metadata.json").read_text(encoding="ascii")
                    )
                    timeline_last = json.loads(
                        (campaign / "metrics" / "coverage_timeline.jsonl").read_text(encoding="ascii").splitlines()[-1]
                    )
                    universe = load_bapc_coverage_universe(
                        campaign / "metrics" / "coverage_universe" / "bapc_v3.json",
                        expected_bapc_core_version="v3",
                    )

                self.assertEqual(metadata["coverage_mode"], "bapc")
                self.assertEqual(metadata["bapc_core_version"], "v3")
                self.assertEqual(metadata["bapc_target"], 129)
                self.assertEqual(Path(metadata["coverage_universe_files"]["bapc"]).name, "bapc_v3.json")
                self.assertEqual(metadata["coverage_universe_hashes"]["bapc"], universe["sha256"])
                self.assertEqual(universe["bin_count"], 129)
                self.assertEqual(timeline_last["bapc_target"], 129)

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "build_candidate_pool", return_value=_fixed_pool_bapc())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_fixed_pool_variants_write_selected_bapc_v4_universe_contract(self, *_mocks):
        with TemporaryDirectory() as tmp:
            args = _args(Path(tmp), variant="random", max_rounds=1)
            args.coverage_mode = "bapc"
            args.bapc_core_version = "v4"

            rc = driver.run_closed_loop(args)

            self.assertEqual(rc, 0)
            campaign = (
                Path(tmp)
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "random"
                / "bapc"
                / "seed-0001"
            )
            metadata = json.loads((campaign / "metrics" / "campaign_metadata.json").read_text(encoding="ascii"))
            timeline_last = json.loads(
                (campaign / "metrics" / "coverage_timeline.jsonl").read_text(encoding="ascii").splitlines()[-1]
            )
            universe = load_bapc_coverage_universe(
                campaign / "metrics" / "coverage_universe" / "bapc_v4.json",
                expected_bapc_core_version="v4",
            )

        self.assertEqual(metadata["bapc_core_version"], "v4")
        self.assertEqual(metadata["bapc_target"], 144)
        self.assertEqual(Path(metadata["coverage_universe_files"]["bapc"]).name, "bapc_v4.json")
        self.assertEqual(metadata["coverage_universe_hashes"]["bapc"], universe["sha256"])
        self.assertEqual(universe["bin_count"], 144)
        self.assertEqual(timeline_last["bapc_target"], 144)

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_resume_reuses_existing_campaign_directory(self, *_mocks):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = _args(root, variant="random-fresh", max_rounds=1)
            rc1 = driver.run_closed_loop(args)
            rc2 = driver.run_closed_loop(_args(root, variant="random-fresh", resume=True, max_rounds=2))

            self.assertEqual((rc1, rc2), (0, 0))
            campaign = (
                root / "campaigns" / "continuous-e2e" / "spike" / "random-fresh" / "semantic" / "seed-0001"
            )
            events = [
                json.loads(line)
                for line in (campaign / "metrics" / "schedule_v4.jsonl").read_text(encoding="ascii").splitlines()
                if line.strip()
            ]

        self.assertEqual([item["event_seq"] for item in events], list(range(1, len(events) + 1)))
        self.assertGreater(len(events), 5)

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_bb_guided_writes_continuous_campaign_artifacts(self, *_mocks):
        with TemporaryDirectory() as tmp:
            args = _args(Path(tmp), variant="bb-guided", max_rounds=1)

            rc = driver.run_closed_loop(args)

            self.assertEqual(rc, 0)
            campaign = (
                Path(tmp)
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "bb-guided"
                / "semantic"
                / "seed-0001"
            )
            schedule_v4 = campaign / "metrics" / "schedule_v4.jsonl"
            metadata = json.loads((campaign / "metrics" / "campaign_metadata.json").read_text(encoding="ascii"))
            events = [json.loads(line) for line in schedule_v4.read_text(encoding="ascii").splitlines() if line.strip()]

        self.assertTrue(events)
        self.assertEqual(metadata["driver_mode"], "continuous")
        self.assertEqual(metadata["variant"], "bb-guided")
        self.assertIn("candidate_admitted", [item["event"] for item in events])
        self.assertIn("campaign_closed", [item["event"] for item in events])

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_bb_guided_syntax_uses_distinct_campaign_dir_and_metadata(self, *_mocks):
        with TemporaryDirectory() as tmp:
            args = _args(Path(tmp), variant="bb-guided", generator_variant="syntax", max_rounds=1)

            rc = driver.run_closed_loop(args)

            self.assertEqual(rc, 0)
            campaign = (
                Path(tmp)
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "bb-guided__syntax"
                / "semantic"
                / "seed-0001"
            )
            metadata = json.loads((campaign / "metrics" / "campaign_metadata.json").read_text(encoding="ascii"))

        self.assertEqual(metadata["variant"], "bb-guided")
        self.assertEqual(metadata["scheduler_variant"], "bb-guided")
        self.assertEqual(metadata["generator_variant"], "syntax")

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_resume_random_mutation_uses_restored_parent(self, *_mocks):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            rc1 = driver.run_closed_loop(_args(root, variant="random-mutation", max_rounds=1))
            rc2 = driver.run_closed_loop(
                _args(root, variant="random-mutation", resume=True, max_rounds=2)
            )
            self.assertEqual((rc1, rc2), (0, 0))
            campaign = (
                root / "campaigns" / "continuous-e2e" / "spike" / "random-mutation" / "semantic" / "seed-0001"
            )
            generated = [
                json.loads(line)
                for line in (campaign / "metrics" / "schedule_v4.jsonl").read_text(encoding="ascii").splitlines()
                if line.strip()
            ]
            generated = [item for item in generated if item["event"] == "candidate_admitted"]

        self.assertGreaterEqual(len(generated), 3)
        self.assertTrue(any(item["parent_hash"] is not None for item in generated[2:]))

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_resume_matches_uninterrupted_candidate_stream(self, *_mocks):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            direct_root = root / "direct"
            resumed_root = root / "resumed"

            rc_direct = driver.run_closed_loop(_args(direct_root, variant="random-mutation", max_rounds=3))
            rc_split_1 = driver.run_closed_loop(_args(resumed_root, variant="random-mutation", max_rounds=1))
            rc_split_2 = driver.run_closed_loop(
                _args(resumed_root, variant="random-mutation", resume=True, max_rounds=3)
            )
            self.assertEqual((rc_direct, rc_split_1, rc_split_2), (0, 0, 0))

            direct_campaign = (
                direct_root
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "random-mutation"
                / "semantic"
                / "seed-0001"
            )
            resumed_campaign = (
                resumed_root
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "random-mutation"
                / "semantic"
                / "seed-0001"
            )
            direct_generated = [
                {
                    "scenario_hash": item["scenario_hash"],
                    "parent_hash": item["parent_hash"],
                    "mutation_operator": item["mutation_operator"],
                    "mutation_seed": item["mutation_seed"],
                }
                for item in self._generated_events(direct_campaign)
                if item["event"] == "candidate_admitted"
            ]
            resumed_generated = [
                {
                    "scenario_hash": item["scenario_hash"],
                    "parent_hash": item["parent_hash"],
                    "mutation_operator": item["mutation_operator"],
                    "mutation_seed": item["mutation_seed"],
                }
                for item in self._generated_events(resumed_campaign)
                if item["event"] == "candidate_admitted"
            ]

        self.assertEqual(direct_generated, resumed_generated)

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_random_mutation_generates_child_after_first_promotion(self, *_mocks):
        with TemporaryDirectory() as tmp:
            args = _args(Path(tmp), variant="random-mutation", max_rounds=2)
            rc = driver.run_closed_loop(args)
            self.assertEqual(rc, 0)
            campaign = (
                Path(tmp)
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "random-mutation"
                / "semantic"
                / "seed-0001"
            )
            generated = [
                json.loads(line)
                for line in (campaign / "metrics" / "schedule_v4.jsonl").read_text(encoding="ascii").splitlines()
                if line.strip()
            ]
            generated = [item for item in generated if item["event"] == "candidate_admitted"]

        self.assertGreaterEqual(len(generated), 3)
        self.assertIsNone(generated[0]["parent_hash"])
        self.assertIsNotNone(generated[-1]["parent_hash"])
        self.assertEqual(generated[-1]["mutation_depth"], 1)

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=RuntimeError("boom-before-finalize"))
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_random_fresh_persists_metadata_before_finalize(self, *_mocks):
        with TemporaryDirectory() as tmp:
            args = _args(Path(tmp), variant="random-fresh", max_rounds=1)
            with self.assertRaisesRegex(RuntimeError, "boom-before-finalize"):
                driver.run_closed_loop(args)

            campaign = (
                Path(tmp)
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "random-fresh"
                / "semantic"
                / "seed-0001"
            )
            metadata_path = campaign / "metrics" / "campaign_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
            metadata_exists = metadata_path.exists()

        self.assertTrue(metadata_exists)
        self.assertEqual(metadata["driver_mode"], "continuous")
        self.assertEqual(metadata["completed_rounds"], 0)
        self.assertEqual(metadata["completed_cases"], 0)
        self.assertIn("schedule_v4", metadata)

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_driver_persists_candidate_rejected_events(self, *_mocks):
        from pmpfuzz.continuous import ScenarioStream as RealScenarioStream

        class RejectingStatefulStoreStream:
            def __init__(self, *, root_seed: int, **_kwargs):
                self.root_seed = root_seed
                self._fallback = RealScenarioStream(root_seed=root_seed, profiles=("pmp-boundary",))

            def generate_root(self, sequence: int):
                if sequence == 0:
                    scenario = ScenarioGenerator(seed=self.root_seed, include_smepmp=False, profile="pmp-side-effect").generate_one(1)
                    spec = scenario_to_spec(scenario)
                    spec["probe"]["size"] = 8
                    spec["probe"]["physical_address"] += 4
                    spec["probe"]["virtual_address"] = spec["probe"]["physical_address"]
                    return scenario_from_spec(spec)
                return self._fallback.generate_root(sequence)

            def applicable_operators(self, parent_spec):
                return self._fallback.applicable_operators(parent_spec)

            def mutate(self, parent_spec, operator, attempt):
                return self._fallback.mutate(parent_spec, operator, attempt)

        with TemporaryDirectory() as tmp:
            args = _args(Path(tmp), variant="random-fresh", max_rounds=1)
            with patch("pmpfuzz.continuous.ScenarioStream", RejectingStatefulStoreStream):
                rc = driver.run_closed_loop(args)

            self.assertEqual(rc, 0)
            campaign = (
                Path(tmp)
                / "campaigns"
                / "continuous-e2e"
                / "spike"
                / "random-fresh"
                / "semantic"
                / "seed-0001"
            )
            events = [item["event"] for item in self._generated_events(campaign)]

        self.assertIn("candidate_rejected", events)
        self.assertIn("candidate_admitted", events)
        self.assertNotIn("candidate_queued", events)

    def test_metadata_checkpoint_replace_failure_preserves_old_file(self):
        with TemporaryDirectory() as tmp:
            metadata_path = Path(tmp) / "campaign_metadata.json"
            metadata_path.write_text(
                json.dumps({"version": "old", "completed_rounds": 1}, ensure_ascii=True),
                encoding="ascii",
            )
            state = driver.CampaignState(
                campaign_id="cid",
                variant="random-fresh",
                dut="spike",
                seed=1,
                coverage_mode="semantic",
                candidate_pool=[],
                start_time=0.0,
                coverage_universes=_universes(),
            )
            state.record_round_result(True, {"process_success": True, "ingest_success": True, "returncode": 0})
            meta = {
                "campaign_id": "cid",
                "driver_mode": "continuous",
                "run_class": "pilot",
            }
            original = metadata_path.read_text(encoding="ascii")

            with patch.object(driver.os, "replace", side_effect=RuntimeError("replace-failed")):
                with self.assertRaisesRegex(RuntimeError, "replace-failed"):
                    driver._write_continuous_metadata_checkpoint(metadata_path, meta, state, start_wall=0.0)

            self.assertEqual(metadata_path.read_text(encoding="ascii"), original)
            parsed = json.loads(metadata_path.read_text(encoding="ascii"))
            self.assertEqual(parsed["version"], "old")

    @patch("pmpfuzz.coverage_universe.freeze_coverage_universes", return_value=_universes())
    @patch.object(driver, "_build_base_cmd", return_value=(["fake-run"], {}))
    @patch.object(driver, "_run_round", side_effect=_fake_run_round)
    @patch("pmpfuzz.capabilities.capability_for_dut", return_value={"available": True})
    def test_resume_rejects_tampered_universe_identity_and_schedule_path(self, *_mocks):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            rc = driver.run_closed_loop(_args(root, variant="random-fresh", max_rounds=1))
            self.assertEqual(rc, 0)
            campaign = (
                root / "campaigns" / "continuous-e2e" / "spike" / "random-fresh" / "semantic" / "seed-0001"
            )
            metadata_path = campaign / "metrics" / "campaign_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
            metadata["coverage_universe_hashes"]["semantic"] = "0" * 64
            metadata["schedule_v4"] = "metrics/other-schedule.jsonl"
            metadata_path.write_text(json.dumps(metadata, ensure_ascii=True, indent=2), encoding="ascii")

            with self.assertRaisesRegex(ValueError, "coverage_universe_hashes|schedule_v4"):
                driver.run_closed_loop(_args(root, variant="random-fresh", resume=True, max_rounds=2))

    def test_restore_state_rewrites_timeline_from_execution_commits(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaigns" / "continuous-e2e" / "spike" / "random-fresh" / "semantic" / "seed-0001"
            metrics = campaign / "metrics"
            rounds = campaign / "rounds"
            metrics.mkdir(parents=True)
            rounds.mkdir(parents=True)
            scenario = ScenarioGenerator(seed=91, include_smepmp=False, profile="pmp-boundary").generate_one(0)
            spec = scenario_to_spec(scenario)
            spec_hash = scenario_hash(spec)

            state = driver.CampaignState(
                campaign_id="cid",
                variant="random-fresh",
                dut="spike",
                seed=1,
                coverage_mode="semantic",
                candidate_pool=[],
                start_time=0.0,
                coverage_universes=_universes(),
            )
            timeline_path = metrics / "coverage_timeline.jsonl"
            state.set_timeline_path(timeline_path)

            schedule_path = metrics / "schedule_v4.jsonl"
            writer = ScheduleV4Writer(schedule_path)
            writer.append(
                "candidate_admitted",
                scenario_hash=spec_hash,
                scenario_spec=spec,
                generation_seq=1,
                parent_hash=None,
                mutation_operator="root",
            )
            writer.append(
                "execution_committed",
                scenario_hash=spec_hash,
                candidate_id=spec_hash,
                case_id="case-1",
                profile="pmp-boundary",
                status="pass",
                failure_class=None,
                eligible=True,
                qualification_reason="eligible",
                elapsed_wall_seconds=5.0,
                case_elapsed_seconds=0.1,
                execution_cost=0.1,
                new_bins={"semantic": ["sem:0"], "pairwise": [], "security_triples": [], "predicates": []},
                promoted=False,
                evicted_hashes=[],
                retained_without_novelty=False,
                new_whitebox_events=0,
            )
            recovered = recover_schedule_v4(schedule_path)

            driver._restore_continuous_campaign_state(state, timeline_path, rounds, recovered)
            lines = [json.loads(line) for line in timeline_path.read_text(encoding="ascii").splitlines() if line.strip()]

        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[-1]["case_id"], "case-1")
        self.assertEqual(lines[-1]["semantic_covered"], 1)


if __name__ == "__main__":
    unittest.main()
