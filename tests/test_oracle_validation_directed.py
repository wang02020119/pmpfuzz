from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.evaluation.oracle_validation.directed_suite import build_directed_suite_plans
from scripts.evaluation.oracle_validation.generate_reference_cases import write_reference_corpus


class OracleValidationDirectedSuiteTest(unittest.TestCase):
    def test_m04_excludes_mmode_overlap_cases_without_priority_flip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )

            manifests_dir = root / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            (manifests_dir / "mutants.json").write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "dut": "rocket-clean",
                                "mutant_id": "M04",
                                "fault_family": "priority_error",
                            }
                        ]
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            summary = build_directed_suite_plans(
                artifact_root=root,
                max_controls_per_mutant=8,
            )

            self.assertEqual(summary["plan_count"], 1)
            plan = json.loads(
                (root / "mutants" / "rocket-clean" / "M04" / "activation-plan.json").read_text(encoding="utf-8")
            )
            self.assertEqual(plan["selection_rule"], "first_match_overlap_vs_nonoverlap_controls")
            self.assertEqual(plan["control_case_count"], 8)

            activation_case_ids = set(str(item) for item in plan["activation_case_ids"])
            self.assertGreaterEqual(plan["activation_case_count"], 20)
            self.assertTrue({"C1-0007", "C1-0008", "C1-0015", "C1-0016"} <= activation_case_ids)
            self.assertFalse(
                {"C1-0056", "C1-0064", "C1-0071", "C1-0072", "C2-0056", "C2-0064", "C2-0072"}
                & activation_case_ids
            )

            labels = {
                str(item["case_id"]): item
                for item in map(
                    json.loads,
                    (root / "reference" / "labels.jsonl").read_text(encoding="utf-8").splitlines(),
                )
            }
            cases = {
                str(item["case_id"]): item
                for item in map(
                    json.loads,
                    (root / "reference" / "cases.jsonl").read_text(encoding="utf-8").splitlines(),
                )
            }

            for case_id in activation_case_ids:
                case = cases[case_id]
                label = labels[case_id]
                self.assertEqual(case["pmp_match_mode"], "first-match-overlap")
                self.assertFalse(
                    case["privilege"] == "M" and str(label.get("expected_stage") or "") == "none"
                )

    def test_cva6_m04_excludes_effective_m_overlap_cases_without_second_locked_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )

            manifests_dir = root / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            (manifests_dir / "mutants.json").write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "dut": "cva6-clean",
                                "mutant_id": "M04",
                                "fault_family": "priority_error",
                            }
                        ]
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            summary = build_directed_suite_plans(
                artifact_root=root,
                max_controls_per_mutant=8,
            )

            self.assertEqual(summary["plan_count"], 1)
            plan = json.loads(
                (root / "mutants" / "cva6-clean" / "M04" / "activation-plan.json").read_text(encoding="utf-8")
            )
            activation_case_ids = set(str(item) for item in plan["activation_case_ids"])

            self.assertNotIn("C2-0071", activation_case_ids)
            self.assertIn("C2-0055", activation_case_ids)
            self.assertIn("C1-0055", activation_case_ids)

    def test_m05_targets_pow2_last_byte_allow_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )

            manifests_dir = root / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            (manifests_dir / "mutants.json").write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "dut": "rocket-clean",
                                "mutant_id": "M05",
                                "fault_family": "range_boundary",
                            }
                        ]
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            summary = build_directed_suite_plans(
                artifact_root=root,
                max_controls_per_mutant=8,
            )

            self.assertEqual(summary["plan_count"], 1)
            plan = json.loads(
                (root / "mutants" / "rocket-clean" / "M05" / "activation-plan.json").read_text(encoding="utf-8")
            )
            self.assertEqual(plan["selection_rule"], "pow2_last_byte_boundary_vs_inside_controls")
            self.assertEqual(plan["activation_case_count"], 12)
            self.assertEqual(plan["control_case_count"], 8)

            activation_case_ids = set(str(item) for item in plan["activation_case_ids"])
            control_case_ids = [str(item) for item in plan["control_case_ids"]]
            self.assertTrue({"C1-0005", "C1-0013", "C1-0021", "C1-0029"} <= activation_case_ids)
            self.assertFalse(
                {
                    "C1-0002",
                    "C1-0004",
                    "C1-0006",
                    "C1-0053",
                    "C1-0061",
                    "C1-0069",
                    "C2-0002",
                    "C2-0004",
                    "C2-0006",
                    "C2-0053",
                    "C2-0061",
                    "C2-0069",
                }
                & activation_case_ids
            )
            self.assertEqual(
                control_case_ids,
                [
                    "C1-0001",
                    "C1-0007",
                    "C1-0008",
                    "C1-0009",
                    "C1-0015",
                    "C1-0016",
                    "C1-0017",
                    "C1-0023",
                ],
            )

            labels = {
                str(item["case_id"]): item
                for item in map(
                    json.loads,
                    (root / "reference" / "labels.jsonl").read_text(encoding="utf-8").splitlines(),
                )
            }
            cases = {
                str(item["case_id"]): item
                for item in map(
                    json.loads,
                    (root / "reference" / "cases.jsonl").read_text(encoding="utf-8").splitlines(),
                )
            }

            for case_id in activation_case_ids:
                case = cases[case_id]
                label = labels[case_id]
                self.assertIn(case["pmp_match_mode"], {"napot", "na4"})
                self.assertEqual(case["probe_offset"], "last_byte")
                self.assertIn(case["privilege"], {"S", "U"})
                self.assertTrue(label["expected_allowed"])
                self.assertEqual(label["expected_stage"], "none")

            for case_id in control_case_ids:
                case = cases[case_id]
                self.assertEqual(case["probe_offset"], "inside")
                self.assertNotEqual(case["pmp_match_mode"], "na4")

    def test_m06_controls_are_allowed_inside_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )

            manifests_dir = root / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            (manifests_dir / "mutants.json").write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "dut": "rocket-clean",
                                "mutant_id": "M06",
                                "fault_family": "default_permission",
                            }
                        ]
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            summary = build_directed_suite_plans(
                artifact_root=root,
                max_controls_per_mutant=8,
            )

            self.assertEqual(summary["plan_count"], 1)
            plan = json.loads(
                (root / "mutants" / "rocket-clean" / "M06" / "activation-plan.json").read_text(encoding="utf-8")
            )
            self.assertEqual(plan["selection_rule"], "unmatched_su_default_deny_vs_inside_controls")
            self.assertEqual(plan["activation_case_count"], 36)
            self.assertEqual(plan["control_case_count"], 8)

            control_case_ids = set(str(item) for item in plan["control_case_ids"])
            self.assertTrue({"C1-0001", "C1-0003", "C1-0008", "C1-0009", "C1-0011", "C1-0016"} <= control_case_ids)
            self.assertFalse({"C1-0007", "C1-0015", "C2-0007", "C2-0015"} & control_case_ids)

            labels = {
                str(item["case_id"]): item
                for item in map(
                    json.loads,
                    (root / "reference" / "labels.jsonl").read_text(encoding="utf-8").splitlines(),
                )
            }
            cases = {
                str(item["case_id"]): item
                for item in map(
                    json.loads,
                    (root / "reference" / "cases.jsonl").read_text(encoding="utf-8").splitlines(),
                )
            }

            for case_id in control_case_ids:
                case = cases[case_id]
                label = labels[case_id]
                self.assertEqual(case["profile"], "pmp-boundary")
                self.assertEqual(case["probe_offset"], "inside")
                self.assertIn(case["privilege"], {"S", "U"})
                self.assertTrue(label["expected_allowed"])
                self.assertEqual(label["expected_stage"], "none")

    def test_m07_excludes_locked_mprv_cases_without_privilege_flip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )

            manifests_dir = root / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            (manifests_dir / "mutants.json").write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "dut": "rocket-clean",
                                "mutant_id": "M07",
                                "fault_family": "effective_privilege",
                            }
                        ]
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            synthetic_cases = [
                {
                    "case_id": "C1-0055",
                    "profile": "pmp-boundary",
                    "translation_mode": "bare",
                    "privilege": "M",
                    "access_type": "load",
                    "mprv": True,
                    "coverage_tags": ["unlocked"],
                },
                {
                    "case_id": "C1-0063",
                    "profile": "pmp-boundary",
                    "translation_mode": "bare",
                    "privilege": "M",
                    "access_type": "store",
                    "mprv": True,
                    "coverage_tags": ["unlocked"],
                },
                {
                    "case_id": "C2-0055",
                    "profile": "pmp-boundary",
                    "translation_mode": "bare",
                    "privilege": "M",
                    "access_type": "load",
                    "mprv": True,
                    "coverage_tags": ["locked"],
                },
                {
                    "case_id": "C2-0063",
                    "profile": "pmp-boundary",
                    "translation_mode": "bare",
                    "privilege": "M",
                    "access_type": "store",
                    "mprv": True,
                    "coverage_tags": ["locked"],
                },
                *[
                    {
                        "case_id": case_id,
                        "profile": "pmp-boundary",
                        "translation_mode": "bare",
                        "privilege": "M",
                        "access_type": access_type,
                        "mprv": False,
                        "coverage_tags": ["unlocked"],
                    }
                    for case_id, access_type in (
                        ("C1-0050", "load"),
                        ("C1-0052", "load"),
                        ("C1-0054", "load"),
                        ("C1-0056", "load"),
                        ("C1-0058", "store"),
                        ("C1-0060", "store"),
                        ("C1-0062", "store"),
                        ("C1-0064", "store"),
                    )
                ],
            ]
            synthetic_labels = [
                {
                    "case_id": "C1-0055",
                    "expected_allowed": False,
                    "expected_stage": "pmp",
                },
                {
                    "case_id": "C1-0063",
                    "expected_allowed": False,
                    "expected_stage": "pmp",
                },
                {
                    "case_id": "C2-0055",
                    "expected_allowed": False,
                    "expected_stage": "pmp",
                },
                {
                    "case_id": "C2-0063",
                    "expected_allowed": False,
                    "expected_stage": "pmp",
                },
                *[
                    {
                        "case_id": case_id,
                        "expected_allowed": True,
                        "expected_stage": "none",
                    }
                    for case_id in ("C1-0050", "C1-0052", "C1-0054", "C1-0056", "C1-0058", "C1-0060", "C1-0062", "C1-0064")
                ],
            ]
            (root / "reference" / "cases.jsonl").write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in synthetic_cases),
                encoding="utf-8",
            )
            (root / "reference" / "labels.jsonl").write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in synthetic_labels),
                encoding="utf-8",
            )

            summary = build_directed_suite_plans(
                artifact_root=root,
                max_controls_per_mutant=8,
            )

            self.assertEqual(summary["plan_count"], 1)
            plan = json.loads(
                (root / "mutants" / "rocket-clean" / "M07" / "activation-plan.json").read_text(encoding="utf-8")
            )
            self.assertEqual(plan["selection_rule"], "mprv_effective_privilege_denies_vs_nomprv_controls")
            self.assertEqual(plan["activation_case_count"], 2)
            self.assertEqual(plan["control_case_count"], 8)

            activation_case_ids = set(str(item) for item in plan["activation_case_ids"])
            self.assertTrue({"C1-0055", "C1-0063"} <= activation_case_ids)
            self.assertFalse({"C2-0055", "C2-0063"} & activation_case_ids)
            control_case_ids = set(str(item) for item in plan["control_case_ids"])
            self.assertEqual(
                control_case_ids,
                {"C1-0050", "C1-0052", "C1-0054", "C1-0056", "C1-0058", "C1-0060", "C1-0062", "C1-0064"},
            )

    def test_m08_controls_avoid_sv39_cases_shifted_by_ptw_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )

            manifests_dir = root / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            (manifests_dir / "mutants.json").write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "dut": "boom-clean",
                                "mutant_id": "M08",
                                "fault_family": "ptw_bypass",
                            }
                        ]
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            summary = build_directed_suite_plans(
                artifact_root=root,
                max_controls_per_mutant=8,
            )

            self.assertEqual(summary["plan_count"], 1)
            plan = json.loads(
                (root / "mutants" / "boom-clean" / "M08" / "activation-plan.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                plan["selection_rule"],
                "ptw_fault_cases_vs_pte_permission_sv39_controls",
            )
            self.assertEqual(plan["activation_case_count"], 72)
            self.assertEqual(plan["control_case_count"], 8)

            control_case_ids = set(str(item) for item in plan["control_case_ids"])
            self.assertEqual(
                control_case_ids,
                {"C3-0003", "C3-0004", "C3-0005", "C3-0007", "C3-0008", "C3-0010", "C3-0011", "C3-0012"},
            )
            self.assertFalse({"C3-0001", "C3-0002", "C3-0006"} & control_case_ids)

            labels = {
                str(item["case_id"]): item
                for item in map(
                    json.loads,
                    (root / "reference" / "labels.jsonl").read_text(encoding="utf-8").splitlines(),
                )
            }
            cases = {
                str(item["case_id"]): item
                for item in map(
                    json.loads,
                    (root / "reference" / "cases.jsonl").read_text(encoding="utf-8").splitlines(),
                )
            }

            for case_id in control_case_ids:
                case = cases[case_id]
                label = labels[case_id]
                self.assertEqual(case["translation_mode"], "sv39")
                self.assertEqual(label["expected_stage"], "pte_permission")

    def test_m09_controls_avoid_success_sv39_cases_shifted_by_final_access_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )

            manifests_dir = root / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            (manifests_dir / "mutants.json").write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "dut": "rocket-clean",
                                "mutant_id": "M09",
                                "fault_family": "final_access_bypass",
                            }
                        ]
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            summary = build_directed_suite_plans(
                artifact_root=root,
                max_controls_per_mutant=8,
            )

            self.assertEqual(summary["plan_count"], 1)
            plan = json.loads(
                (root / "mutants" / "rocket-clean" / "M09" / "activation-plan.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                plan["selection_rule"],
                "final_access_fault_cases_vs_other_sv39_controls",
            )
            self.assertGreaterEqual(plan["activation_case_count"], 14)
            self.assertEqual(plan["control_case_count"], 8)

            activation_case_ids = set(str(item) for item in plan["activation_case_ids"])
            control_case_ids = set(str(item) for item in plan["control_case_ids"])
            self.assertEqual(
                control_case_ids,
                {"C3-0003", "C3-0004", "C3-0005", "C3-0007", "C3-0008", "C3-0010", "C3-0011", "C3-0012"},
            )
            self.assertTrue({"C3-0001", "C3-0009", "C3-0017"} <= activation_case_ids)
            self.assertFalse({"C3-0002", "C3-0006"} & control_case_ids)
            self.assertFalse(activation_case_ids & control_case_ids)

            labels = {
                str(item["case_id"]): item
                for item in map(
                    json.loads,
                    (root / "reference" / "labels.jsonl").read_text(encoding="utf-8").splitlines(),
                )
            }
            cases = {
                str(item["case_id"]): item
                for item in map(
                    json.loads,
                    (root / "reference" / "cases.jsonl").read_text(encoding="utf-8").splitlines(),
                )
            }

            for case_id in activation_case_ids:
                case = cases[case_id]
                label = labels[case_id]
                self.assertEqual(case["translation_mode"], "sv39")
                self.assertEqual(label["expected_stage"], "final_access")

            for case_id in control_case_ids:
                case = cases[case_id]
                label = labels[case_id]
                self.assertEqual(case["translation_mode"], "sv39")
                self.assertEqual(label["expected_stage"], "pte_permission")
                self.assertFalse(label["expected_allowed"])

    def test_m10_targets_sum_sensitive_supervisor_data_cases_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )

            manifests_dir = root / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            (manifests_dir / "mutants.json").write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "dut": "rocket-clean",
                                "mutant_id": "M10",
                                "fault_family": "pte_permission",
                            }
                        ]
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            summary = build_directed_suite_plans(
                artifact_root=root,
                max_controls_per_mutant=8,
            )

            self.assertEqual(summary["plan_count"], 1)
            plan = json.loads(
                (root / "mutants" / "rocket-clean" / "M10" / "activation-plan.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                plan["selection_rule"],
                "sum_disabled_supervisor_user_page_data_cases_vs_other_sv39_controls",
            )
            self.assertEqual(plan["activation_case_count"], 4)
            self.assertEqual(plan["control_case_count"], 8)

            activation_case_ids = set(str(item) for item in plan["activation_case_ids"])
            control_case_ids = set(str(item) for item in plan["control_case_ids"])
            self.assertEqual(activation_case_ids, {"C3-0022", "C3-0023", "C3-0027", "C3-0030"})
            self.assertEqual(
                control_case_ids,
                {"C3-0003", "C3-0004", "C3-0005", "C3-0007", "C3-0008", "C3-0010", "C3-0011", "C3-0012"},
            )
            self.assertFalse({"C3-0002", "C3-0006"} & control_case_ids)
            self.assertFalse({"C3-0043", "C3-0050", "C3-0085", "C3-0093"} & activation_case_ids)

            labels = {
                str(item["case_id"]): item
                for item in map(
                    json.loads,
                    (root / "reference" / "labels.jsonl").read_text(encoding="utf-8").splitlines(),
                )
            }
            cases = {
                str(item["case_id"]): item
                for item in map(
                    json.loads,
                    (root / "reference" / "cases.jsonl").read_text(encoding="utf-8").splitlines(),
                )
            }

            for case_id in activation_case_ids:
                case = cases[case_id]
                label = labels[case_id]
                self.assertEqual(case["translation_mode"], "sv39")
                self.assertEqual(case["privilege"], "S")
                self.assertIn(case["access_type"], {"load", "store"})
                self.assertEqual(label["expected_stage"], "pte_permission")
                self.assertFalse(label["expected_allowed"])

            for case_id in control_case_ids:
                case = cases[case_id]
                label = labels[case_id]
                self.assertEqual(case["translation_mode"], "sv39")
                self.assertEqual(label["expected_stage"], "pte_permission")
                self.assertFalse(label["expected_allowed"])

    def test_m11_controls_avoid_success_sv39_cases_and_ad_update_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )

            manifests_dir = root / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            (manifests_dir / "mutants.json").write_text(
                json.dumps(
                    {
                        "entries": [
                            {
                                "dut": "rocket-clean",
                                "mutant_id": "M11",
                                "fault_family": "pte_ad",
                            }
                        ]
                    },
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            summary = build_directed_suite_plans(
                artifact_root=root,
                max_controls_per_mutant=8,
            )

            self.assertEqual(summary["plan_count"], 1)
            plan = json.loads(
                (root / "mutants" / "rocket-clean" / "M11" / "activation-plan.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                plan["selection_rule"],
                "ad_update_trigger_cases_vs_other_sv39_controls",
            )
            self.assertEqual(plan["activation_case_count"], 11)
            self.assertEqual(plan["control_case_count"], 8)

            activation_case_ids = set(str(item) for item in plan["activation_case_ids"])
            control_case_ids = set(str(item) for item in plan["control_case_ids"])
            self.assertEqual(
                activation_case_ids,
                {"C3-0007", "C3-0013", "C3-0049", "C3-0055", "C3-0070", "C3-0076", "C3-0091", "C5-0008", "C5-0011", "C5-0015", "C5-0018"},
            )
            self.assertEqual(
                control_case_ids,
                {"C3-0001", "C3-0003", "C3-0004", "C3-0005", "C3-0009", "C3-0011", "C3-0015", "C3-0016"},
            )
            self.assertFalse({"C3-0002", "C3-0006", "C3-0008", "C3-0010"} & control_case_ids)

            labels = {
                str(item["case_id"]): item
                for item in map(
                    json.loads,
                    (root / "reference" / "labels.jsonl").read_text(encoding="utf-8").splitlines(),
                )
            }
            cases = {
                str(item["case_id"]): item
                for item in map(
                    json.loads,
                    (root / "reference" / "cases.jsonl").read_text(encoding="utf-8").splitlines(),
                )
            }

            for case_id in control_case_ids:
                case = cases[case_id]
                label = labels[case_id]
                spec = case["scenario_spec"]
                pte = spec["sv39"]["pte"]
                self.assertEqual(case["translation_mode"], "sv39")
                self.assertNotEqual(label["expected_stage"], "none")
                self.assertTrue(pte["accessed"])
                if case["access_type"] == "store":
                    self.assertTrue(pte["dirty"])


if __name__ == "__main__":
    unittest.main()
