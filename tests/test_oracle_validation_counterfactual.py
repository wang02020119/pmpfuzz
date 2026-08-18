from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pmpfuzz.diagnostics import mepc_tag, mtval_fingerprint
from scripts.evaluation.oracle_validation.freeze_counterfactual_holdout import freeze_counterfactual_holdout
from scripts.evaluation.oracle_validation.mutate_observations import (
    build_canonical_result_record,
    build_counterfactuals,
    build_counterfactuals_from_reference_cases,
    extract_observation_record,
    run_counterfactual_judgment,
    select_counterfactual_rows,
)


class OracleValidationCounterfactualTest(unittest.TestCase):
    def test_counterfactuals_never_expect_pass(self):
        case = {
            "name": "allow_case",
            "access": "load",
            "privilege": "U",
            "translation": "bare",
            "address": "0x80008000",
            "expected": {"allowed": True, "trap_cause": None, "stage": "none"},
        }
        label = {
            "case_id": "C1-0001",
            "expected_allowed": True,
            "expected_stage": "none",
            "expected_side_effect": "not_applicable",
        }
        result = {
            "observed_event": "completion",
            "observed_mcause": 8,
            "observed_mtval_fingerprint": mtval_fingerprint(0),
            "observed_mepc_tag": mepc_tag(0x80004010),
            "observed_phase": "completed",
            "observed_stage": None,
            "observed_ptw_level": None,
            "observed_fault_address": None,
        }

        counterfactuals = build_counterfactuals(
            case_record=case,
            reference_label=label,
            result_record=result,
        )

        self.assertGreaterEqual(len(counterfactuals), 5)
        self.assertFalse(any(item["mutation_id"] == "O3" for item in counterfactuals))
        for item in counterfactuals:
            self.assertNotEqual(item["expected_judgment"]["status"], "pass")

    def test_malformed_payload_is_invalid_observation(self):
        case = {
            "name": "allow_case",
            "access": "load",
            "privilege": "U",
            "translation": "bare",
            "address": "0x80008000",
            "expected": {"allowed": True, "trap_cause": None, "stage": "none"},
        }
        counterfactual = {
            "observation": {
                "valid": False,
            }
        }

        actual = run_counterfactual_judgment(case_record=case, counterfactual=counterfactual)
        self.assertEqual(actual["status"], "fail")
        self.assertEqual(actual["failure_class"], "invalid_observation")

    def test_missing_ptw_stage_evidence_is_inconclusive(self):
        case = {
            "name": "ptw_case",
            "access": "load",
            "privilege": "U",
            "translation": "sv39",
            "address": "0x80008000",
            "expected": {"allowed": False, "trap_cause": 5, "stage": "page_table_walk"},
            "contract_trace": {
                "pmp_checks": [
                    {
                        "stage": "ptw",
                        "ptw_level": "L1",
                        "physical_address": "0x80013000",
                        "allowed": False,
                    }
                ]
            },
        }
        label = {
            "case_id": "C4-0001",
            "expected_allowed": False,
            "expected_stage": "page_table_walk",
            "expected_side_effect": "not_applicable",
        }
        result = {
            "observed_event": "trap",
            "observed_mcause": 5,
            "observed_mtval_fingerprint": mtval_fingerprint(0x80008000),
            "observed_mepc_tag": mepc_tag(0x40000000),
            "observed_phase": "probe",
            "observed_stage": "ptw",
            "observed_ptw_level": "L1",
            "observed_fault_address": 0x80013000,
        }

        counterfactuals = build_counterfactuals(
            case_record=case,
            reference_label=label,
            result_record=result,
        )
        missing = next(item for item in counterfactuals if item["mutation_id"] == "O6")
        actual = run_counterfactual_judgment(case_record=case, counterfactual=missing)

        self.assertEqual(missing["expected_judgment"]["status"], "inconclusive")
        self.assertEqual(missing["expected_judgment"]["failure_class"], "unverified_trap_stage")
        self.assertEqual(actual["status"], "inconclusive")
        self.assertEqual(actual["failure_class"], "unverified_trap_stage")

    def test_stateful_stale_permission_counterfactual_is_generated(self):
        case = {
            "case_id": "C6-0055",
            "name": "stateful_stale_case",
            "access": "load",
            "privilege": "S",
            "translation": "sv39",
            "address": "0x80008000",
            "profile": "unit-stateful",
            "expected": {"allowed": False, "trap_cause": 13, "stage": "stateful_final"},
            "stateful_sequence": {
                "kind": "unit-stateful",
                "warmup": True,
                "mutation": "pte-deny-leaf",
                "fence": "none",
                "final_probe": "repeat",
                "expected_final": "trap_after_mutation",
                "stale_failure_class": "STALE_TLB_PERMISSION",
            },
        }
        label = {
            "case_id": "C6-0055",
            "expected_allowed": False,
            "expected_stage": "stateful_final",
            "expected_side_effect": "not_applicable",
        }
        result = {
            "observed_event": "trap",
            "observed_mcause": 13,
            "observed_mtval_fingerprint": mtval_fingerprint(0x80008000),
            "observed_mepc_tag": 0,
            "observed_phase": "final",
            "observed_stage": "final_access",
            "observed_ptw_level": None,
            "observed_fault_address": 0x80008000,
        }

        counterfactuals = build_counterfactuals(
            case_record=case,
            reference_label=label,
            result_record=result,
        )
        stale = next(item for item in counterfactuals if item["mutation_id"] == "O11")

        self.assertEqual(stale["mutation_class"], "stale_permission_signature")
        self.assertEqual(stale["expected_judgment"]["status"], "fail")
        self.assertEqual(stale["expected_judgment"]["failure_class"], "stale_permission")
        self.assertEqual(stale["observation"]["kind"], "completion")
        self.assertEqual(stale["observation"]["phase"], "final")

    def test_stale_permission_judgment_does_not_consult_mutation_id(self):
        case = {
            "case_id": "C6-0055",
            "name": "stateful_stale_case",
            "access": "load",
            "privilege": "S",
            "translation": "sv39",
            "address": "0x80008000",
            "profile": "unit-stateful",
            "expected": {"allowed": False, "trap_cause": 13, "stage": "stateful_final"},
            "stateful_sequence": {
                "kind": "unit-stateful",
                "warmup": True,
                "mutation": "pte-deny-leaf",
                "fence": "none",
                "final_probe": "repeat",
                "expected_final": "trap_after_mutation",
                "stale_failure_class": "STALE_PMP_PERMISSION",
            },
        }
        label = {
            "case_id": "C6-0055",
            "expected_allowed": False,
            "expected_stage": "stateful_final",
            "expected_side_effect": "not_applicable",
        }
        result = {
            "observed_event": "trap",
            "observed_mcause": 13,
            "observed_mtval_fingerprint": mtval_fingerprint(0x80008000),
            "observed_mepc_tag": 0,
            "observed_phase": "final",
            "observed_stage": "final_access",
            "observed_ptw_level": None,
            "observed_fault_address": 0x80008000,
        }

        counterfactuals = build_counterfactuals(
            case_record=case,
            reference_label=label,
            result_record=result,
        )
        stale = next(item for item in counterfactuals if item["mutation_id"] == "O11")
        renamed = {
            **stale,
            "mutation_id": "O99",
            "mutation_class": "renamed_for_negative_test",
        }

        actual = run_counterfactual_judgment(case_record=case, counterfactual=stale)
        renamed_actual = run_counterfactual_judgment(case_record=case, counterfactual=renamed)

        self.assertEqual(actual["status"], "fail")
        self.assertEqual(actual["failure_class"], "stale_permission")
        self.assertEqual(renamed_actual, actual)

    def test_canonical_result_record_for_allowed_case_is_clean_pass(self):
        case = {
            "case_id": "C1-0001",
            "name": "allow_case",
            "access": "load",
            "privilege": "U",
            "translation": "bare",
            "address": "0x80008000",
            "expected": {"allowed": True, "trap_cause": None, "stage": "none"},
        }
        label = {
            "case_id": "C1-0001",
            "expected_allowed": True,
            "expected_stage": "none",
            "expected_side_effect": "not_applicable",
        }

        result = build_canonical_result_record(case_record=case, reference_label=label)
        actual = run_counterfactual_judgment(
            case_record=case,
            counterfactual={"observation": extract_observation_record(result)},
        )

        self.assertEqual(result["observed_phase"], "completed")
        self.assertEqual(actual["status"], "pass")
        self.assertIsNone(actual["failure_class"])

    def test_canonical_result_record_for_ptw_case_is_clean_pass(self):
        case = {
            "case_id": "C4-0001",
            "name": "ptw_case",
            "access": "load",
            "privilege": "U",
            "translation": "sv39",
            "address": "0x80008000",
            "expected": {"allowed": False, "trap_cause": 5, "stage": "page_table_walk"},
            "contract_trace": {
                "pmp_checks": [
                    {
                        "stage": "ptw",
                        "ptw_level": "L1",
                        "physical_address": "0x80013000",
                        "allowed": False,
                    }
                ]
            },
        }
        label = {
            "case_id": "C4-0001",
            "expected_allowed": False,
            "expected_trap_cause": 5,
            "expected_stage": "page_table_walk",
            "expected_ptw_level": "L1",
            "expected_fault_address": "0x80013000",
            "expected_side_effect": "not_applicable",
        }

        result = build_canonical_result_record(case_record=case, reference_label=label)
        actual = run_counterfactual_judgment(
            case_record=case,
            counterfactual={"observation": extract_observation_record(result)},
        )

        self.assertEqual(result["observed_stage"], "ptw")
        self.assertEqual(result["observed_fault_address"], 0x80013000)
        self.assertEqual(actual["status"], "pass")
        self.assertIsNone(actual["failure_class"])

    def test_select_counterfactual_rows_enforces_class_budgets(self):
        rows = [
            {
                "case_id": "C1-0001",
                "mutation_id": "O1",
                "expected_judgment": {"failure_class": "unexpected_trap"},
            },
            {
                "case_id": "C1-0002",
                "mutation_id": "O1",
                "expected_judgment": {"failure_class": "unexpected_trap"},
            },
            {
                "case_id": "C1-0003",
                "mutation_id": "O12",
                "expected_judgment": {"failure_class": "invalid_observation"},
            },
        ]

        selected = select_counterfactual_rows(
            rows,
            target_counts={"unexpected_trap": 2, "invalid_observation": 1},
        )

        self.assertEqual(len(selected), 3)
        self.assertEqual([item["case_id"] for item in selected], ["C1-0001", "C1-0002", "C1-0003"])

    def test_select_counterfactual_rows_rejects_insufficient_pool(self):
        rows = [
            {
                "case_id": "C1-0001",
                "mutation_id": "O1",
                "expected_judgment": {"failure_class": "unexpected_trap"},
            }
        ]

        with self.assertRaisesRegex(ValueError, "insufficient counterfactuals"):
            select_counterfactual_rows(rows, target_counts={"unexpected_trap": 2})

    def test_freeze_counterfactual_holdout_writes_manifest(self):
        cases = [
            {
                "case_id": "C1-0001",
                "name": "allow_case",
                "access": "load",
                "privilege": "U",
                "translation": "bare",
                "address": "0x80008000",
                "expected": {"allowed": True, "trap_cause": None, "stage": "none"},
            },
            {
                "case_id": "C1-0002",
                "name": "deny_case",
                "access": "load",
                "privilege": "U",
                "translation": "bare",
                "address": "0x80009000",
                "expected": {"allowed": False, "trap_cause": 5, "stage": "pmp"},
            },
        ]
        labels = [
            {
                "case_id": "C1-0001",
                "applicability": "applicable",
                "expected_allowed": True,
                "expected_stage": "none",
                "expected_side_effect": "not_applicable",
            },
            {
                "case_id": "C1-0002",
                "applicability": "applicable",
                "expected_allowed": False,
                "expected_trap_cause": 5,
                "expected_stage": "pmp",
                "expected_side_effect": "not_applicable",
            },
        ]

        all_rows = build_counterfactuals_from_reference_cases(cases=cases, labels=labels)
        self.assertGreaterEqual(len(all_rows), 10)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases_path = root / "cases.jsonl"
            labels_path = root / "labels.jsonl"
            out_path = root / "counterfactuals.jsonl"
            manifest_path = root / "manifest.json"
            cases_path.write_text("".join(f"{json.dumps(item, sort_keys=True)}\n" for item in cases), encoding="utf-8")
            labels_path.write_text("".join(f"{json.dumps(item, sort_keys=True)}\n" for item in labels), encoding="utf-8")

            summary = freeze_counterfactual_holdout(
                cases_jsonl=cases_path,
                labels_jsonl=labels_path,
                class_targets={"unexpected_trap": 1, "wrong_mcause": 1, "invalid_observation": 1},
                out_jsonl=out_path,
                manifest_json=manifest_path,
            )

            self.assertEqual(summary["selected_total"], 3)
            self.assertEqual(summary["selected_counts"]["invalid_observation"], 1)
            self.assertTrue(manifest_path.is_file())


if __name__ == "__main__":
    unittest.main()
