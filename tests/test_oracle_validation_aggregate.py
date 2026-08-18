from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from pmpfuzz.capabilities import capability_for_dut
from scripts.evaluation.oracle_validation.aggregate_oracle_validation import aggregate_oracle_validation
from scripts.evaluation.oracle_validation.freeze_formal_artifact import freeze_formal_artifact
from scripts.evaluation.oracle_validation.generate_reference_cases import write_reference_corpus
from scripts.evaluation.oracle_validation.mutate_observations import build_counterfactuals
from scripts.evaluation.oracle_validation.run_oracle_validation import (
    run_clean_suite,
    run_counterfactual_suite,
    run_directed_suite,
)


def _freeze_test_artifact(root: Path) -> tuple[Path, dict[str, Path]]:
    artifact_root = root / "artifact"
    binaries: dict[str, Path] = {}
    capabilities = {}
    for dut in ("rocket-clean", "boom-clean", "cva6-clean"):
        binary = root / f"{dut}.bin"
        binary.write_bytes(f"{dut}-binary".encode("ascii"))
        binaries[dut] = binary
        capabilities[dut] = capability_for_dut(dut, available=True, path=binary)

    freeze_formal_artifact(
        artifact_root=artifact_root,
        source_root=root,
        dut_binary_paths=binaries,
        capabilities_by_dut=capabilities,
        source_provenance={
            "source_sha": "a" * 40,
            "source_tree_sha256": "b" * 64,
            "source_dirty": False,
        },
    )

    mutants_path = artifact_root / "manifests" / "mutants.json"
    mutants = json.loads(mutants_path.read_text(encoding="utf-8"))
    mutants["entries"] = [
        entry
        for entry in mutants["entries"]
        if entry["dut"] == "rocket-clean" and entry["mutant_id"] == "M08"
    ]
    mutants["directed_order_seeds"] = [4]
    mutants["online_seeds"] = [4]
    mutants["replay_count"] = 10
    mutants_path.write_text(json.dumps(mutants, indent=2, ensure_ascii=True), encoding="utf-8")
    return artifact_root, binaries


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


class OracleValidationAggregateTest(unittest.TestCase):
    def test_aggregate_rejects_duplicate_reference_case_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )
            cases_path = root / "reference" / "cases.jsonl"
            lines = cases_path.read_text(encoding="utf-8").splitlines()
            cases_path.write_text(lines[0] + "\n" + lines[0] + "\n" + "\n".join(lines[1:]) + "\n", encoding="utf-8")
            (root / "manifests" / "cases.sha256").write_text("", encoding="utf-8")

            report = aggregate_oracle_validation(root)

        self.assertFalse(report["valid"])
        self.assertTrue(any("duplicate case ids" in item for item in report["errors"]))

    def test_aggregate_rejects_wrong_bapc_denominator(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )
            (root / "manifests" / "coverage-contract.json").write_text(
                json.dumps({"bapc_v2": {"bin_count": 207}}, indent=2),
                encoding="utf-8",
            )

            report = aggregate_oracle_validation(root)

        self.assertFalse(report["valid"])
        self.assertTrue(any("207" in item for item in report["errors"]))

    def test_aggregate_rejects_missing_mutants_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )

            report = aggregate_oracle_validation(root)

        self.assertFalse(report["valid"])
        self.assertTrue(any("mutants.json" in item for item in report["errors"]))

    def test_aggregate_writes_clean_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )
            run_clean_suite(
                cases_path=root / "reference" / "cases.jsonl",
                labels_path=root / "reference" / "labels.jsonl",
                out_dir=root,
                dut="spike",
                order_seed=4,
                limit=1,
                materialize_only=True,
            )
            seed_root = root / "clean" / "spike" / "seed-0004"
            case_dir = next(item for item in seed_root.iterdir() if item.is_dir())
            observation = {
                "schema_version": 1,
                "available": True,
                "kind": "completion",
                "mcause": 8,
                "mtval_fingerprint": 0,
                "mepc_tag": 4,
                "phase": "completed",
                "observed_stage": None,
                "observed_ptw_level": None,
                "observed_fault_address": None,
            }
            result = json.loads((case_dir / "result.json").read_text(encoding="utf-8"))
            result.update(
                {
                    "status": "pass",
                    "oracle_applicability": "valid",
                    "observation_valid": True,
                    "stage_verified": True,
                }
            )
            (case_dir / "observation.json").write_text(json.dumps(observation, indent=2), encoding="utf-8")
            (case_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

            report = aggregate_oracle_validation(root)
            clean_rows = _read_csv(root / "aggregate" / "clean_conformance.csv")
            core_summary = json.loads((root / "aggregate" / "core_summary.json").read_text(encoding="utf-8"))

            self.assertTrue((root / "aggregate" / "clean_conformance.csv").is_file())
            self.assertTrue((root / "aggregate" / "clean_confusion_matrix.csv").is_file())
            self.assertTrue((root / "aggregate" / "clean_by_dut.csv").is_file())
            self.assertTrue((root / "aggregate" / "clean_by_family.csv").is_file())
            self.assertTrue((root / "aggregate" / "clean_mismatches.csv").is_file())
            self.assertTrue((root / "aggregate" / "validation_report.json").is_file())
            self.assertGreaterEqual(report["clean_case_rows"], 1)
            self.assertEqual(clean_rows[0]["label_applicability"], "applicable")
            self.assertEqual(clean_rows[0]["oracle_applicability"], "valid")
            self.assertEqual(clean_rows[0]["a_priori_observable"], "True")
            self.assertEqual(clean_rows[0]["observed_complete"], "True")
            self.assertEqual(clean_rows[0]["fully_observable"], "True")
            self.assertEqual(core_summary["e1"]["a_priori_observable_cases"], 1)
            self.assertEqual(core_summary["e1"]["observed_complete_rate"], 1.0)
            self.assertEqual(core_summary["e1"]["fully_observable_cases"], 1)
            self.assertEqual(core_summary["e1"]["fully_observable_judgment_accuracy"], 1.0)

    def test_aggregate_writes_clean_tables_for_nested_holdout_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )
            (root / "manifests" / "mutants.json").write_text(
                json.dumps({"schema_version": 1, "entries": []}, indent=2),
                encoding="utf-8",
            )
            run_clean_suite(
                cases_path=root / "reference" / "cases.jsonl",
                labels_path=root / "reference" / "labels.jsonl",
                out_dir=root / "clean" / "spike",
                dut="spike",
                order_seed=7,
                limit=1,
                materialize_only=True,
            )
            seed_root = root / "clean" / "spike" / "clean" / "spike" / "seed-0007"
            case_dir = next(item for item in seed_root.iterdir() if item.is_dir())
            observation = {
                "schema_version": 1,
                "available": True,
                "kind": "completion",
                "mcause": 8,
                "mtval_fingerprint": 0,
                "mepc_tag": 4,
                "phase": "completed",
                "observed_stage": None,
                "observed_ptw_level": None,
                "observed_fault_address": None,
            }
            result = json.loads((case_dir / "result.json").read_text(encoding="utf-8"))
            result.update(
                {
                    "status": "pass",
                    "oracle_applicability": "valid",
                    "observation_valid": True,
                    "stage_verified": True,
                }
            )
            (case_dir / "observation.json").write_text(json.dumps(observation, indent=2), encoding="utf-8")
            (case_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

            report = aggregate_oracle_validation(root)
            clean_rows = _read_csv(root / "aggregate" / "clean_conformance.csv")

            self.assertTrue(report["valid"], report["errors"])
            self.assertEqual(report["clean_case_rows"], 1)
            self.assertEqual(clean_rows[0]["dut"], "spike")
            self.assertEqual(clean_rows[0]["order_seed"], "seed-0007")
            self.assertEqual(clean_rows[0]["a_priori_observable"], "True")
            self.assertEqual(clean_rows[0]["fully_observable"], "True")

    def test_aggregate_separates_capability_limited_rows_from_fully_observable_accuracy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )
            (root / "manifests" / "mutants.json").write_text(
                json.dumps({"schema_version": 1, "entries": []}, indent=2),
                encoding="utf-8",
            )
            run_clean_suite(
                cases_path=root / "reference" / "cases.jsonl",
                labels_path=root / "reference" / "labels.jsonl",
                out_dir=root,
                dut="spike",
                order_seed=4,
                limit=1,
                materialize_only=True,
            )
            seed_root = root / "clean" / "spike" / "seed-0004"
            case_dir = next(item for item in seed_root.iterdir() if item.is_dir())
            observation = {
                "schema_version": 1,
                "available": True,
                "kind": "trap",
                "mcause": 5,
                "mtval_fingerprint": 0,
                "mepc_tag": 4,
                "phase": "probe",
                "observed_stage": "ptw",
                "observed_ptw_level": None,
                "observed_fault_address": None,
            }
            result = json.loads((case_dir / "result.json").read_text(encoding="utf-8"))
            result.update(
                {
                    "status": "inconclusive",
                    "failure_class": "unverified_trap_stage",
                    "oracle_applicability": "capability_dependent",
                    "observation_valid": True,
                    "stage_verified": False,
                }
            )
            (case_dir / "observation.json").write_text(json.dumps(observation, indent=2), encoding="utf-8")
            (case_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

            report = aggregate_oracle_validation(root)
            clean_rows = _read_csv(root / "aggregate" / "clean_conformance.csv")
            core_summary = json.loads((root / "aggregate" / "core_summary.json").read_text(encoding="utf-8"))

            self.assertTrue(report["valid"], report["errors"])
            self.assertEqual(clean_rows[0]["oracle_applicability"], "capability_dependent")
            self.assertEqual(clean_rows[0]["a_priori_observable"], "True")
            self.assertEqual(clean_rows[0]["observed_complete"], "False")
            self.assertEqual(clean_rows[0]["fully_observable"], "False")
            self.assertEqual(core_summary["e1"]["total_cases"], 1)
            self.assertEqual(core_summary["e1"]["capability_limited_cases"], 1)
            self.assertEqual(core_summary["e1"]["a_priori_observable_cases"], 1)
            self.assertEqual(core_summary["e1"]["observed_complete_cases"], 0)
            self.assertEqual(core_summary["e1"]["fully_observable_cases"], 0)
            self.assertIsNone(core_summary["e1"]["fully_observable_judgment_accuracy"])

    def test_a_priori_observable_does_not_depend_on_execution_outcome(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )
            (root / "manifests" / "mutants.json").write_text(
                json.dumps({"schema_version": 1, "entries": []}, indent=2),
                encoding="utf-8",
            )
            run_clean_suite(
                cases_path=root / "reference" / "cases.jsonl",
                labels_path=root / "reference" / "labels.jsonl",
                out_dir=root,
                dut="spike",
                order_seed=4,
                limit=1,
                materialize_only=True,
            )
            seed_root = root / "clean" / "spike" / "seed-0004"
            case_dir = next(item for item in seed_root.iterdir() if item.is_dir())
            observation = {
                "schema_version": 1,
                "available": True,
                "kind": "completion",
                "mcause": 9,
                "mtval_fingerprint": 0,
                "mepc_tag": 4,
                "phase": "completed",
                "observed_stage": None,
                "observed_ptw_level": None,
                "observed_fault_address": None,
            }
            result = json.loads((case_dir / "result.json").read_text(encoding="utf-8"))
            result.update(
                {
                    "status": "fail",
                    "failure_class": "unexpected_trap",
                    "oracle_applicability": "valid",
                    "observation_valid": False,
                    "stage_verified": False,
                }
            )
            (case_dir / "observation.json").write_text(json.dumps(observation, indent=2), encoding="utf-8")
            (case_dir / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

            report = aggregate_oracle_validation(root)
            clean_rows = _read_csv(root / "aggregate" / "clean_conformance.csv")

            self.assertTrue(report["valid"], report["errors"])
            self.assertEqual(clean_rows[0]["a_priori_observable"], "True")
            self.assertEqual(clean_rows[0]["observed_complete"], "False")
            self.assertEqual(clean_rows[0]["fully_observable"], "False")

    def test_aggregate_writes_counterfactual_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )
            (root / "manifests" / "mutants.json").write_text(
                json.dumps({"schema_version": 1, "entries": []}, indent=2),
                encoding="utf-8",
            )
            run_clean_suite(
                cases_path=root / "reference" / "cases.jsonl",
                labels_path=root / "reference" / "labels.jsonl",
                out_dir=root / "phase0",
                dut="spike",
                order_seed=4,
                limit=1,
                materialize_only=True,
            )
            seed_root = root / "phase0" / "clean" / "spike" / "seed-0004"
            case_dir = next(item for item in seed_root.iterdir() if item.is_dir())
            case_payload = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
            label_payload = json.loads((case_dir / "reference-label.json").read_text(encoding="utf-8"))
            counterfactuals = build_counterfactuals(
                case_record=case_payload,
                reference_label=label_payload,
                result_record={
                    "observed_event": "completion",
                    "observed_mcause": 8,
                    "observed_mtval_fingerprint": 0,
                    "observed_mepc_tag": 4,
                    "observed_phase": "completed",
                    "observed_stage": None,
                    "observed_ptw_level": None,
                    "observed_fault_address": None,
                },
            )
            counterfactual_path = root / "phase0" / "counterfactuals.jsonl"
            with counterfactual_path.open("w", encoding="utf-8") as handle:
                for item in counterfactuals:
                    handle.write(json.dumps(item, ensure_ascii=True, sort_keys=True) + "\n")

            run_counterfactual_suite(
                cases_path=root / "reference" / "cases.jsonl",
                counterfactuals_path=counterfactual_path,
                out_dir=root,
            )
            report = aggregate_oracle_validation(root)

            self.assertTrue((root / "aggregate" / "judgment_counterfactuals.csv").is_file())
            self.assertTrue((root / "aggregate" / "counterfactual_by_failure_class.csv").is_file())
            self.assertTrue((root / "aggregate" / "counterfactual_mismatches.csv").is_file())
            self.assertGreater(report["counterfactual_rows"], 0)

    def test_aggregate_writes_e3_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root, binaries = _freeze_test_artifact(root)

            run_directed_suite(
                artifact_root=artifact_root,
                dut="rocket-clean",
                mutant_id="M08",
                order_seed=4,
                dut_bin=binaries["rocket-clean"],
                materialize_only=True,
            )

            plan = json.loads(
                (artifact_root / "mutants" / "rocket-clean" / "M08" / "activation-plan.json").read_text(
                    encoding="utf-8"
                )
            )
            seed_root = artifact_root / "mutants" / "rocket-clean" / "M08" / "directed" / "seed-0004"
            for case_id in plan["activation_case_ids"]:
                activation_result = seed_root / case_id / "result.json"
                activation_payload = json.loads(activation_result.read_text(encoding="utf-8"))
                activation_payload.update(
                    {
                        "status": "fail",
                        "failure_class": "wrong_trap_cause",
                        "oracle_applicability": "valid",
                        "observation_valid": True,
                        "stage_verified": True,
                    }
                )
                activation_result.write_text(json.dumps(activation_payload, indent=2), encoding="utf-8")
            for case_id in plan["control_case_ids"]:
                control_result = seed_root / case_id / "result.json"
                control_payload = json.loads(control_result.read_text(encoding="utf-8"))
                control_payload.update(
                    {
                        "status": "pass",
                        "failure_class": "",
                        "oracle_applicability": "valid",
                        "observation_valid": True,
                        "stage_verified": True,
                    }
                )
                control_result.write_text(json.dumps(control_payload, indent=2), encoding="utf-8")

            mutant_root = artifact_root / "mutants" / "rocket-clean" / "M08"
            (mutant_root / "binary.sha256").write_text(
                hashlib.sha256(binaries["rocket-clean"].read_bytes()).hexdigest() + "\n",
                encoding="ascii",
            )
            (mutant_root / "build-manifest.json").write_text(
                json.dumps({"schema_version": 1, "status": "built"}, indent=2, ensure_ascii=True),
                encoding="utf-8",
            )

            replay_root = mutant_root / "replay" / "seed-0004"
            replay_root.mkdir(parents=True, exist_ok=True)
            (replay_root / "summary.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "results": [
                            {
                                "status": "fail",
                                "failure_class": "wrong_trap_cause",
                                "oracle_applicability": "valid",
                                "observation_valid": True,
                                "stage_verified": True,
                            }
                            for _ in range(10)
                        ],
                    },
                    indent=2,
                    ensure_ascii=True,
                ),
                encoding="utf-8",
            )

            campaign_root = mutant_root / "campaigns" / "seed-0004"
            metrics_dir = campaign_root / "metrics"
            metrics_dir.mkdir(parents=True, exist_ok=True)
            (metrics_dir / "campaign_metadata.json").write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "experiment_id": "E3-ONLINE",
                        "campaign_id": "rocket-m08-seed-0004",
                        "method": "pmpfuzz",
                        "variant": "bb-guided",
                        "coverage_mode": "semantic",
                        "dut": "rocket-clean",
                        "seed": 4,
                        "run_class": "formal",
                        "wall_clock_horizon_seconds": 7200,
                        "fault_family": "ptw_bypass",
                        "critical_family": True,
                    },
                    indent=2,
                    ensure_ascii=True,
                ),
                encoding="ascii",
            )
            timeline_rows = [
                {
                    "schema_version": 1,
                    "campaign_id": "rocket-m08-seed-0004",
                    "variant": "bb-guided",
                    "dut": "rocket-clean",
                    "seed": 4,
                    "completion_seq": 0,
                    "case_id": None,
                    "elapsed_wall_seconds": 0.0,
                    "completed_cases": 0,
                    "eligible_cases": 0,
                    "status": None,
                    "failure_class": None,
                    "semantic_covered": 0,
                    "semantic_target": 10,
                    "semantic_rate": 0.0,
                    "pairwise_covered": 0,
                    "pairwise_target": 0,
                    "pairwise_rate": None,
                    "security_triples_covered": 0,
                    "security_triples_target": 0,
                    "security_triples_rate": None,
                    "predicates_covered": 0,
                    "predicates_target": 0,
                    "predicates_rate": None,
                    "bapc_covered": 0,
                    "bapc_target": 208,
                    "bapc_rate": 0.0,
                    "new_semantic_bins": 0,
                    "new_pairwise_bins": 0,
                    "new_security_triple_bins": 0,
                    "new_predicate_bins": 0,
                    "new_bapc_bins": 0,
                },
                {
                    "schema_version": 1,
                    "campaign_id": "rocket-m08-seed-0004",
                    "variant": "bb-guided",
                    "dut": "rocket-clean",
                    "seed": 4,
                    "completion_seq": 1,
                    "case_id": "case-0001",
                    "elapsed_wall_seconds": 2.0,
                    "completed_cases": 1,
                    "eligible_cases": 1,
                    "status": "pass",
                    "failure_class": "",
                    "semantic_covered": 1,
                    "semantic_target": 10,
                    "semantic_rate": 0.1,
                    "pairwise_covered": 0,
                    "pairwise_target": 0,
                    "pairwise_rate": None,
                    "security_triples_covered": 0,
                    "security_triples_target": 0,
                    "security_triples_rate": None,
                    "predicates_covered": 0,
                    "predicates_target": 0,
                    "predicates_rate": None,
                    "bapc_covered": 21,
                    "bapc_target": 208,
                    "bapc_rate": 21 / 208,
                    "new_semantic_bins": 1,
                    "new_pairwise_bins": 0,
                    "new_security_triple_bins": 0,
                    "new_predicate_bins": 0,
                    "new_bapc_bins": 21,
                    "oracle_applicability": "valid",
                    "observation_valid": True,
                    "stage_verified": True,
                },
                {
                    "schema_version": 1,
                    "campaign_id": "rocket-m08-seed-0004",
                    "variant": "bb-guided",
                    "dut": "rocket-clean",
                    "seed": 4,
                    "completion_seq": 2,
                    "case_id": "case-0002",
                    "elapsed_wall_seconds": 5.0,
                    "completed_cases": 2,
                    "eligible_cases": 2,
                    "status": "fail",
                    "failure_class": "wrong_trap_cause",
                    "semantic_covered": 3,
                    "semantic_target": 10,
                    "semantic_rate": 0.3,
                    "pairwise_covered": 0,
                    "pairwise_target": 0,
                    "pairwise_rate": None,
                    "security_triples_covered": 0,
                    "security_triples_target": 0,
                    "security_triples_rate": None,
                    "predicates_covered": 0,
                    "predicates_target": 0,
                    "predicates_rate": None,
                    "bapc_covered": 52,
                    "bapc_target": 208,
                    "bapc_rate": 52 / 208,
                    "new_semantic_bins": 2,
                    "new_pairwise_bins": 0,
                    "new_security_triple_bins": 0,
                    "new_predicate_bins": 0,
                    "new_bapc_bins": 31,
                    "oracle_applicability": "valid",
                    "observation_valid": True,
                    "stage_verified": True,
                },
            ]
            (metrics_dir / "coverage_timeline.jsonl").write_text(
                "\n".join(json.dumps(row, ensure_ascii=True, sort_keys=True) for row in timeline_rows) + "\n",
                encoding="ascii",
            )
            (campaign_root / "validation.json").write_text(
                json.dumps({"schema_version": "1.0", "campaign_id": "rocket-m08-seed-0004", "valid": True}, indent=2),
                encoding="ascii",
            )

            report = aggregate_oracle_validation(artifact_root)

            mutation_rows = _read_csv(artifact_root / "aggregate" / "mutation_score.csv")
            directed_rows = _read_csv(artifact_root / "aggregate" / "directed_evidence.csv")
            replay_rows = _read_csv(artifact_root / "aggregate" / "replay.csv")
            detection_rows = _read_csv(artifact_root / "aggregate" / "time_to_detection.csv")
            auc_rows = _read_csv(artifact_root / "aggregate" / "coverage_auc.csv")
            core_summary = json.loads((artifact_root / "aggregate" / "core_summary.json").read_text(encoding="utf-8"))

            self.assertTrue(report["valid"], report["errors"])
            self.assertTrue((artifact_root / "aggregate" / "mutation_by_family.csv").is_file())
            self.assertTrue((artifact_root / "aggregate" / "coverage_final.csv").is_file())
            self.assertTrue((artifact_root / "aggregate" / "coverage_timeseries.csv").is_file())
            self.assertTrue((artifact_root / "aggregate" / "exclusions.csv").is_file())
            self.assertTrue((artifact_root / "aggregate" / "core_summary.json").is_file())
            self.assertEqual(directed_rows[0]["evidence_scope"], "directed-only-confirmation")
            self.assertEqual(directed_rows[0]["activation_complete"], "True")
            self.assertEqual(directed_rows[0]["control_complete"], "True")
            self.assertEqual(directed_rows[0]["killed"], "True")
            self.assertEqual(float(mutation_rows[0]["mutation_score"]), 1.0)
            self.assertEqual(float(core_summary["e3_directed"]["overall"]["mutation_score"]), 1.0)
            self.assertEqual(replay_rows[0]["replay_success_fraction"], "10/10")
            self.assertEqual(detection_rows[0]["detected"], "True")
            self.assertEqual(float(detection_rows[0]["first_detection_elapsed_wall_seconds"]), 5.0)
            semantic_auc = next(row for row in auc_rows if row["coverage_mode"] == "semantic")
            self.assertEqual(float(semantic_auc["normalized_auc"]), 0.29983333333333334)

    def test_core_only_aggregate_skips_replay_and_online_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root, binaries = _freeze_test_artifact(root)

            run_directed_suite(
                artifact_root=artifact_root,
                dut="rocket-clean",
                mutant_id="M08",
                order_seed=4,
                dut_bin=binaries["rocket-clean"],
                materialize_only=True,
            )

            plan = json.loads(
                (artifact_root / "mutants" / "rocket-clean" / "M08" / "activation-plan.json").read_text(
                    encoding="utf-8"
                )
            )
            seed_root = artifact_root / "mutants" / "rocket-clean" / "M08" / "directed" / "seed-0004"
            for case_id in plan["activation_case_ids"]:
                activation_result = seed_root / case_id / "result.json"
                activation_payload = json.loads(activation_result.read_text(encoding="utf-8"))
                activation_payload.update(
                    {
                        "status": "fail",
                        "failure_class": "wrong_trap_cause",
                        "oracle_applicability": "valid",
                        "observation_valid": True,
                        "stage_verified": True,
                    }
                )
                activation_result.write_text(json.dumps(activation_payload, indent=2), encoding="utf-8")

            for case_id in plan["control_case_ids"]:
                control_result = seed_root / case_id / "result.json"
                control_payload = json.loads(control_result.read_text(encoding="utf-8"))
                control_payload.update(
                    {
                        "status": "pass",
                        "failure_class": "",
                        "oracle_applicability": "valid",
                        "observation_valid": True,
                        "stage_verified": True,
                    }
                )
                control_result.write_text(json.dumps(control_payload, indent=2), encoding="utf-8")

            mutant_root = artifact_root / "mutants" / "rocket-clean" / "M08"
            (mutant_root / "binary.sha256").write_text(
                hashlib.sha256(binaries["rocket-clean"].read_bytes()).hexdigest() + "\n",
                encoding="ascii",
            )
            (mutant_root / "build-manifest.json").write_text(
                json.dumps({"schema_version": 1, "status": "built"}, indent=2, ensure_ascii=True),
                encoding="utf-8",
            )

            report = aggregate_oracle_validation(artifact_root, core_only=True, output_dir_name="aggregate-core")

            self.assertTrue(report["valid"], report["errors"])
            self.assertTrue(report["core_only"])
            self.assertEqual(report["output_dir_name"], "aggregate-core")
            self.assertEqual(report["replay_rows"], 0)
            self.assertEqual(report["time_to_detection_rows"], 0)
            self.assertEqual(report["coverage_final_rows"], 0)
            self.assertEqual(report["coverage_timeseries_rows"], 0)
            self.assertEqual(report["coverage_auc_rows"], 0)
            self.assertEqual(report["exclusion_rows"], 0)
            self.assertTrue((artifact_root / "aggregate-core" / "core_summary.json").is_file())
            self.assertEqual((artifact_root / "aggregate-core" / "replay.csv").read_text(encoding="utf-8"), "")

    def test_core_only_aggregate_counts_directed_results_without_summary_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root, binaries = _freeze_test_artifact(root)

            run_directed_suite(
                artifact_root=artifact_root,
                dut="rocket-clean",
                mutant_id="M08",
                order_seed=4,
                dut_bin=binaries["rocket-clean"],
                materialize_only=True,
            )

            plan = json.loads(
                (artifact_root / "mutants" / "rocket-clean" / "M08" / "activation-plan.json").read_text(
                    encoding="utf-8"
                )
            )
            seed_root = artifact_root / "mutants" / "rocket-clean" / "M08" / "directed" / "seed-0004"
            summary_path = seed_root / "summary.json"
            if summary_path.exists():
                summary_path.unlink()
            for case_id in plan["activation_case_ids"]:
                result_path = seed_root / case_id / "result.json"
                payload = json.loads(result_path.read_text(encoding="utf-8"))
                payload.update(
                    {
                        "status": "fail",
                        "failure_class": "wrong_trap_cause",
                        "oracle_applicability": "valid",
                        "observation_valid": True,
                        "stage_verified": True,
                    }
                )
                result_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            for case_id in plan["control_case_ids"]:
                result_path = seed_root / case_id / "result.json"
                payload = json.loads(result_path.read_text(encoding="utf-8"))
                payload.update(
                    {
                        "status": "pass",
                        "failure_class": "",
                        "oracle_applicability": "valid",
                        "observation_valid": True,
                        "stage_verified": True,
                    }
                )
                result_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            mutant_root = artifact_root / "mutants" / "rocket-clean" / "M08"
            (mutant_root / "binary.sha256").write_text(
                hashlib.sha256(binaries["rocket-clean"].read_bytes()).hexdigest() + "\n",
                encoding="ascii",
            )
            (mutant_root / "build-manifest.json").write_text(
                json.dumps({"schema_version": 1, "status": "built"}, indent=2, ensure_ascii=True),
                encoding="utf-8",
            )

            report = aggregate_oracle_validation(artifact_root, core_only=True, output_dir_name="aggregate-core")
            directed_rows = _read_csv(artifact_root / "aggregate-core" / "directed_evidence.csv")

            self.assertTrue(report["valid"], report["errors"])
            self.assertEqual(len(directed_rows), 1)
            self.assertEqual(directed_rows[0]["expected_seed_count"], "1")
            self.assertEqual(directed_rows[0]["observed_seed_count"], "1")
            self.assertEqual(directed_rows[0]["activation_result_count"], directed_rows[0]["activation_case_count"])
            self.assertEqual(directed_rows[0]["control_result_count"], directed_rows[0]["control_case_count"])

    def test_directed_stage_unverified_fail_still_counts_as_differential_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root, binaries = _freeze_test_artifact(root)

            run_directed_suite(
                artifact_root=artifact_root,
                dut="rocket-clean",
                mutant_id="M08",
                order_seed=4,
                dut_bin=binaries["rocket-clean"],
                materialize_only=True,
            )

            plan = json.loads(
                (artifact_root / "mutants" / "rocket-clean" / "M08" / "activation-plan.json").read_text(
                    encoding="utf-8"
                )
            )
            seed_root = artifact_root / "mutants" / "rocket-clean" / "M08" / "directed" / "seed-0004"
            for case_id in plan["activation_case_ids"]:
                result_path = seed_root / case_id / "result.json"
                payload = json.loads(result_path.read_text(encoding="utf-8"))
                payload.update(
                    {
                        "status": "fail",
                        "failure_class": "wrong_trap_stage",
                        "oracle_applicability": "valid",
                        "observation_valid": True,
                        "stage_verified": False,
                    }
                )
                result_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            for case_id in plan["control_case_ids"]:
                result_path = seed_root / case_id / "result.json"
                payload = json.loads(result_path.read_text(encoding="utf-8"))
                payload.update(
                    {
                        "status": "pass",
                        "failure_class": "",
                        "oracle_applicability": "valid",
                        "observation_valid": True,
                        "stage_verified": True,
                    }
                )
                result_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            mutant_root = artifact_root / "mutants" / "rocket-clean" / "M08"
            (mutant_root / "binary.sha256").write_text(
                hashlib.sha256(binaries["rocket-clean"].read_bytes()).hexdigest() + "\n",
                encoding="ascii",
            )
            (mutant_root / "build-manifest.json").write_text(
                json.dumps({"schema_version": 1, "status": "built"}, indent=2, ensure_ascii=True),
                encoding="utf-8",
            )

            report = aggregate_oracle_validation(artifact_root, core_only=True, output_dir_name="aggregate-core")
            directed_rows = _read_csv(artifact_root / "aggregate-core" / "directed_evidence.csv")

            self.assertTrue(report["valid"], report["errors"])
            self.assertEqual(directed_rows[0]["activation_semantic_failure_count"], directed_rows[0]["activation_case_count"])
            self.assertEqual(directed_rows[0]["killed"], "True")
            self.assertEqual(directed_rows[0]["kill_reason"], "activation_semantic_failure")

    def test_directed_control_failure_invalidates_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root, binaries = _freeze_test_artifact(root)

            run_directed_suite(
                artifact_root=artifact_root,
                dut="rocket-clean",
                mutant_id="M08",
                order_seed=4,
                dut_bin=binaries["rocket-clean"],
                materialize_only=True,
            )

            plan = json.loads(
                (artifact_root / "mutants" / "rocket-clean" / "M08" / "activation-plan.json").read_text(
                    encoding="utf-8"
                )
            )
            seed_root = artifact_root / "mutants" / "rocket-clean" / "M08" / "directed" / "seed-0004"
            for case_id in plan["activation_case_ids"]:
                result_path = seed_root / case_id / "result.json"
                payload = json.loads(result_path.read_text(encoding="utf-8"))
                payload.update(
                    {
                        "status": "fail",
                        "failure_class": "wrong_trap_cause",
                        "oracle_applicability": "valid",
                        "observation_valid": True,
                        "stage_verified": True,
                    }
                )
                result_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            for index, case_id in enumerate(plan["control_case_ids"]):
                result_path = seed_root / case_id / "result.json"
                payload = json.loads(result_path.read_text(encoding="utf-8"))
                payload.update(
                    {
                        "status": "fail" if index == 0 else "pass",
                        "failure_class": "wrong_trap_cause" if index == 0 else "",
                        "oracle_applicability": "valid",
                        "observation_valid": True,
                        "stage_verified": True,
                    }
                )
                result_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            mutant_root = artifact_root / "mutants" / "rocket-clean" / "M08"
            (mutant_root / "binary.sha256").write_text(
                hashlib.sha256(binaries["rocket-clean"].read_bytes()).hexdigest() + "\n",
                encoding="ascii",
            )

            report = aggregate_oracle_validation(artifact_root, core_only=True)
            directed_rows = _read_csv(artifact_root / "aggregate" / "directed_evidence.csv")

            self.assertFalse(report["valid"])
            self.assertEqual(directed_rows[0]["control_semantic_failure_count"], "1")
            self.assertEqual(directed_rows[0]["valid_for_score"], "False")
            self.assertTrue(any("control semantic failures present" in item for item in report["errors"]))

    def test_directed_incomplete_activation_invalidates_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root, binaries = _freeze_test_artifact(root)

            run_directed_suite(
                artifact_root=artifact_root,
                dut="rocket-clean",
                mutant_id="M08",
                order_seed=4,
                dut_bin=binaries["rocket-clean"],
                materialize_only=True,
            )

            plan = json.loads(
                (artifact_root / "mutants" / "rocket-clean" / "M08" / "activation-plan.json").read_text(
                    encoding="utf-8"
                )
            )
            seed_root = artifact_root / "mutants" / "rocket-clean" / "M08" / "directed" / "seed-0004"
            first_activation = True
            for case_id in plan["activation_case_ids"]:
                result_path = seed_root / case_id / "result.json"
                if first_activation:
                    result_path.unlink()
                    first_activation = False
                    continue
                payload = json.loads(result_path.read_text(encoding="utf-8"))
                payload.update(
                    {
                        "status": "fail",
                        "failure_class": "wrong_trap_cause",
                        "oracle_applicability": "valid",
                        "observation_valid": True,
                        "stage_verified": True,
                    }
                )
                result_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            for case_id in plan["control_case_ids"]:
                result_path = seed_root / case_id / "result.json"
                payload = json.loads(result_path.read_text(encoding="utf-8"))
                payload.update(
                    {
                        "status": "pass",
                        "failure_class": "",
                        "oracle_applicability": "valid",
                        "observation_valid": True,
                        "stage_verified": True,
                    }
                )
                result_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            mutant_root = artifact_root / "mutants" / "rocket-clean" / "M08"
            (mutant_root / "binary.sha256").write_text(
                hashlib.sha256(binaries["rocket-clean"].read_bytes()).hexdigest() + "\n",
                encoding="ascii",
            )

            report = aggregate_oracle_validation(artifact_root, core_only=True)
            directed_rows = _read_csv(artifact_root / "aggregate" / "directed_evidence.csv")

            self.assertFalse(report["valid"])
            self.assertEqual(directed_rows[0]["activation_complete"], "False")
            self.assertEqual(directed_rows[0]["valid_for_score"], "False")
            self.assertTrue(any("incomplete activation/control rows" in item for item in report["errors"]))


if __name__ == "__main__":
    unittest.main()
