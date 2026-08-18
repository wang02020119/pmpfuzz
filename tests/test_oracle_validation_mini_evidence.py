from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.evaluation.oracle_validation.build_mini_evidence import (
    E1_FAMILIES,
    E1_SELECTION_NAMESPACE,
    ExecutionBudget,
    _prepare_e3_artifact_layout,
    build_e1_selection,
    build_validation_report,
    summarize_counterfactual_rows,
)


class OracleValidationMiniEvidenceTest(unittest.TestCase):
    def test_execution_budget_enforces_hard_cap(self) -> None:
        budget = ExecutionBudget(planned_limit=116, hard_limit=144)
        budget.reserve(72, label="e1")
        budget.reserve(44, label="e3")
        self.assertEqual(budget.attempts, 116)
        with self.assertRaisesRegex(ValueError, "hard cap exceeded"):
            budget.reserve(29, label="overflow")

    def test_counterfactual_partition_counts_remain_consistent(self) -> None:
        regression_rows = [
            {
                "case_id": "C6-0001",
                "expected_status": "fail",
                "expected_failure_class": "stale_permission",
                "actual_status": "fail",
                "actual_failure_class": "stale_permission",
                "exact_match": "True",
            },
            {
                "case_id": "C1-0001",
                "expected_status": "fail",
                "expected_failure_class": "wrong_path",
                "actual_status": "fail",
                "actual_failure_class": "wrong_path",
                "exact_match": "True",
            },
        ]
        holdout_rows = [
            {
                "case_id": "C6-3001",
                "expected_status": "fail",
                "expected_failure_class": "stale_permission",
                "actual_status": "fail",
                "actual_failure_class": "stale_permission",
                "exact_match": "True",
            }
        ]
        cases = {
            "C6-0001": {"scenario_spec": {"stateful_sequence": {"stale_failure_class": "STALE_TLB_PERMISSION"}}},
            "C1-0001": {"scenario_spec": {}},
            "C6-3001": {"scenario_spec": {"stateful_sequence": {"stale_failure_class": "STALE_PMP_PERMISSION"}}},
        }
        regression = summarize_counterfactual_rows("regression", regression_rows, cases)
        holdout = summarize_counterfactual_rows("holdout", holdout_rows, cases)
        combined = summarize_counterfactual_rows("combined", regression_rows + holdout_rows, cases)

        self.assertEqual(regression["summary"]["total_counterfactuals"], 2)
        self.assertEqual(holdout["summary"]["total_counterfactuals"], 1)
        self.assertEqual(combined["summary"]["total_counterfactuals"], 3)
        self.assertEqual(combined["summary"]["exact_match_count"], 3)
        stale_rows = [row for row in combined["stale_source_rows"] if row["row_kind"] == "stale_source"]
        self.assertEqual({row["stale_source"] for row in stale_rows}, {"stale_pmp_permission", "stale_tlb_permission"})

    def test_e1_selection_prefers_shared_observable_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reference_dir = root / "reference"
            manifests_dir = root / "manifests"
            reference_dir.mkdir(parents=True, exist_ok=True)
            manifests_dir.mkdir(parents=True, exist_ok=True)

            cases = []
            labels = []
            capabilities = {
                "schema_version": 1,
                "reference_case_count": 0,
                "duts": {},
            }
            case_counter = 0
            for family in E1_FAMILIES:
                for index in range(8):
                    case_counter += 1
                    case_id = f"{family.split('.', 1)[0]}-{case_counter:04d}"
                    cases.append(
                        {
                            "schema_version": 1,
                            "case_id": case_id,
                            "family": family,
                            "scenario_hash": f"shared-{family}-{index}",
                            "scenario_spec": {},
                        }
                    )
                    labels.append(
                        {
                            "schema_version": 1,
                            "case_id": case_id,
                            "family": family,
                            "applicability": "applicable",
                            "scenario_hash": f"shared-{family}-{index}",
                        }
                    )
                for index in range(4):
                    case_counter += 1
                    case_id = f"{family.split('.', 1)[0]}-{case_counter:04d}"
                    cases.append(
                        {
                            "schema_version": 1,
                            "case_id": case_id,
                            "family": family,
                            "scenario_hash": f"local-{family}-{index}",
                            "scenario_spec": {},
                        }
                    )
                    labels.append(
                        {
                            "schema_version": 1,
                            "case_id": case_id,
                            "family": family,
                            "applicability": "applicable",
                            "scenario_hash": f"local-{family}-{index}",
                        }
                    )

            (reference_dir / "cases.jsonl").write_text(
                "".join(f"{__import__('json').dumps(row, ensure_ascii=True)}\n" for row in cases),
                encoding="utf-8",
            )
            (reference_dir / "labels.jsonl").write_text(
                "".join(f"{__import__('json').dumps(row, ensure_ascii=True)}\n" for row in labels),
                encoding="utf-8",
            )

            applicability = {row["case_id"]: "valid" for row in cases}
            capabilities["reference_case_count"] = len(cases)
            for dut in ("rocket-clean", "boom-clean", "cva6-clean"):
                capabilities["duts"][dut] = {
                    "capability": {
                        "available": True,
                        "finish_protocol": "tohost",
                        "diagnostic_depth": "full",
                        "observation_capabilities": {
                            "sv39_final_fault_address": True,
                            "sv39_ptw_target_attribution": True,
                            "sv39_stateful_reprobe_phase": True,
                        },
                    },
                    "applicability_by_case": applicability,
                }
            (manifests_dir / "capabilities.json").write_text(
                __import__("json").dumps(capabilities, indent=2, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )

            selection = build_e1_selection(
                holdout_semantic_root=root,
                duts=("rocket-clean", "boom-clean", "cva6-clean"),
                families=E1_FAMILIES,
                per_dut_family=8,
                order_seed=8,
            )
            self.assertEqual(selection["manifest"]["namespace"], E1_SELECTION_NAMESPACE)
            self.assertEqual(len(selection["selected_rows"]), 72)
            self.assertTrue(all(row["shared_observable"] for row in selection["selected_rows"]))
            by_scope = {}
            for row in selection["selected_rows"]:
                by_scope.setdefault((row["dut"], row["family"]), 0)
                by_scope[(row["dut"], row["family"])] += 1
            self.assertTrue(all(count == 8 for count in by_scope.values()))

    def test_prepare_e3_artifact_layout_preserves_results_and_copies_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            regression_root = root / "regression"
            e3_artifact_root = root / "e3-artifact"
            (regression_root / "reference").mkdir(parents=True, exist_ok=True)
            (regression_root / "manifests").mkdir(parents=True, exist_ok=True)
            source_mutant_root = regression_root / "mutants" / "rocket-clean" / "M05"
            source_mutant_root.mkdir(parents=True, exist_ok=True)
            (regression_root / "manifests" / "mutants.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "directed_order_seeds": [7],
                        "online_seeds": [7, 8, 9],
                        "replay_count": 3,
                        "entries": [
                            {
                                "dut": "rocket-clean",
                                "mutant_id": "M05",
                                "fault_family": "permission-bypass",
                            }
                        ],
                    },
                    indent=2,
                    ensure_ascii=True,
                )
                + "\n",
                encoding="utf-8",
            )
            (source_mutant_root / "build-manifest.json").write_text(
                json.dumps(
                    {
                        "dut": "rocket-clean",
                        "mutant_id": "M05",
                        "binary_path": "/tmp/rocket-M05.bin",
                        "binary_sha256": "deadbeef",
                    },
                    indent=2,
                    ensure_ascii=True,
                )
                + "\n",
                encoding="utf-8",
            )
            (source_mutant_root / "binary.sha256").write_text("deadbeef  rocket-M05.bin\n", encoding="utf-8")
            (e3_artifact_root / "manifests").mkdir(parents=True, exist_ok=True)
            existing_result = e3_artifact_root / "results" / "rocket-clean" / "M05" / "activation" / "C1-0001" / "result.json"
            existing_result.parent.mkdir(parents=True, exist_ok=True)
            existing_result.write_text("{}\n", encoding="utf-8")

            _prepare_e3_artifact_layout(
                regression_root=regression_root,
                e3_artifact_root=e3_artifact_root,
                e3_selection={
                    "selected_mutants": [
                        {
                            "dut": "rocket-clean",
                            "mutant_id": "M05",
                            "activation_case_ids": ["C1-0001", "C1-0002"],
                            "control_case_ids": ["C1-0003", "C1-0004"],
                            "order_seed": 8,
                            "activation_selection_policy": "clean_pass_only",
                            "clean_activation_precondition_met": True,
                            "protocol_exception": "",
                        }
                    ]
                },
                preserve_results=True,
            )

            self.assertTrue(existing_result.exists())
            self.assertTrue((e3_artifact_root / "mutants" / "rocket-clean" / "M05" / "build-manifest.json").exists())
            self.assertTrue((e3_artifact_root / "mutants" / "rocket-clean" / "M05" / "binary.sha256").exists())
            activation_plan = json.loads(
                (e3_artifact_root / "mutants" / "rocket-clean" / "M05" / "activation-plan.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(activation_plan["activation_case_count"], 2)
            subset_manifest = json.loads((e3_artifact_root / "manifests" / "mutants.json").read_text(encoding="utf-8"))
            self.assertEqual(len(subset_manifest["entries"]), 1)
            self.assertEqual(subset_manifest["entries"][0]["mutant_id"], "M05")
            self.assertEqual(subset_manifest["directed_order_seeds"], [8])
            self.assertEqual(subset_manifest["replay_count"], 3)

    def test_validation_report_keeps_warning_only_output_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            e1_manifest = root / "e1_frozen_manifest.json"
            e3_manifest = root / "e3_frozen_manifest.json"
            for path in (e1_manifest, e3_manifest):
                path.write_text('{"schema_version":1}\n', encoding="utf-8")
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                path.with_suffix(".json.sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8")

            report = build_validation_report(
                e1_outputs={"case_rows": [{} for _ in range(72)]},
                e2_outputs={
                    "summary": {
                        "regression": {"total_counterfactuals": 5875},
                        "holdout": {"total_counterfactuals": 450},
                        "combined": {"total_counterfactuals": 6325, "unexpected_pass_count": 0},
                    }
                },
                e3_outputs={
                    "case_rows": [{} for _ in range(44)],
                    "seed8_rows": [
                        {
                            "evidence_scope": "directed-only-confirmation",
                            "control_semantic_failure_count": 0,
                        }
                        for _ in range(11)
                    ],
                    "selected_mutants": [
                        {
                            "dut": "cva6-clean",
                            "mutant_id": "M08",
                            "clean_activation_precondition_met": False,
                        }
                    ],
                },
                budget_payload={
                    "actual_execution_attempts": 116,
                    "hard_execution_limit": 144,
                    "wall_clock_limit_exceeded": False,
                    "wall_clock_limit_seconds": 2700,
                },
                e1_manifest_path=e1_manifest,
                e3_manifest_path=e3_manifest,
            )

            self.assertEqual(report["error_count"], 0)
            self.assertEqual(report["warning_count"], 1)
            self.assertTrue(report["valid"])


if __name__ == "__main__":
    unittest.main()
