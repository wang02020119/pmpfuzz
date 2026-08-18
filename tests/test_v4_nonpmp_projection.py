from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

from pmpfuzz.v4_nonpmp_projection import (
    architectural_oracle_allow,
    build_v4_nonpmp_bin_ids,
    c910_target_operation,
    classify_scenario,
    map_target_operation,
    nonpmp_family_counts,
)

REPO = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = Path(os.environ.get("PMPFUZZ_EVIDENCE_ROOT", REPO / "artifacts"))
FROZEN_56 = EVIDENCE_ROOT / "hw-v2-m1" / "universes" / "v4-nonpmp-56.json"
C910_FORMAL = (
    EVIDENCE_ROOT
    / "c910-nonpmp-4x64-20260728-formal"
    / "round-0003"
    / "run-formal"
)


def _load_c910(name: str) -> tuple[dict, dict]:
    case = json.loads(
        (C910_FORMAL / "cases" / name / "case.json").read_text(encoding="utf-8")
    )
    result = json.loads(
        (C910_FORMAL / "results" / name / "result.json").read_text(encoding="utf-8")
    )
    return case, result


class TestV4NonPmpUniverse(unittest.TestCase):
    def test_universe_has_56_bins(self) -> None:
        bins = build_v4_nonpmp_bin_ids()
        self.assertEqual(len(bins), 56)

    def test_family_counts(self) -> None:
        counts = nonpmp_family_counts()
        self.assertEqual(counts, {"stimulus": 26, "decision": 12, "privilege-decision": 18})

    @unittest.skipUnless(
        FROZEN_56.is_file(),
        "requires external frozen v4 universe; set PMPFUZZ_EVIDENCE_ROOT",
    )
    def test_matches_frozen_projection(self) -> None:
        frozen = json.loads(FROZEN_56.read_text(encoding="utf-8"))
        self.assertEqual(build_v4_nonpmp_bin_ids(), sorted(frozen["bin_ids"]))
        self.assertEqual(len(frozen["bin_ids"]), 56)

    def test_no_pmp_families(self) -> None:
        for item in build_v4_nonpmp_bin_ids():
            self.assertFalse(item.startswith("family=config"))
            self.assertFalse(item.startswith("family=mode-decision"))

    def test_fetch_only_has_effective_equal_privilege(self) -> None:
        for item in build_v4_nonpmp_bin_ids():
            if not item.startswith("family=stimulus"):
                continue
            fields = dict(pair.split("=") for pair in item.split("|")[1:])
            if fields["access"] == "fetch":
                self.assertEqual(fields["privilege"], fields["effective_privilege"])


class TestMapTargetOperation(unittest.TestCase):
    def test_valid_operation_maps_three_bins(self) -> None:
        out = map_target_operation(
            privilege="s", effective_privilege="s", access="fetch",
            translation="sv39", allow_or_deny="allow",
        )
        self.assertEqual(out["status"], "mapped")
        self.assertEqual(len(out["bins"]), 3)
        self.assertIn(
            "family=stimulus|privilege=s|effective_privilege=s|access=fetch|translation=sv39",
            out["bins"],
        )
        self.assertIn(
            "family=decision|access=fetch|allow_or_deny=allow|mcause_class=none",
            out["bins"],
        )
        self.assertIn(
            "family=privilege-decision|effective_privilege=s|access=fetch|allow_or_deny=allow",
            out["bins"],
        )

    def test_deny_maps_decision_with_class(self) -> None:
        out = map_target_operation(
            privilege="s", effective_privilege="s", access="load",
            translation="sv39", allow_or_deny="deny", mcause_class="load_page_fault",
        )
        self.assertEqual(out["status"], "mapped")
        self.assertIn(
            "family=decision|access=load|allow_or_deny=deny|mcause_class=load_page_fault",
            out["bins"],
        )

    def test_fetch_with_mprv_effective_privilege_is_unsupported(self) -> None:
        out = map_target_operation(
            privilege="m", effective_privilege="u", access="fetch",
            translation="bare", allow_or_deny="allow",
        )
        self.assertEqual(out["status"], "unsupported")
        self.assertIn("v4-unreachable", out["reason"])

    def test_page_fault_without_sv39_is_unsupported(self) -> None:
        out = map_target_operation(
            privilege="s", effective_privilege="s", access="load",
            translation="bare", allow_or_deny="deny", mcause_class="load_page_fault",
        )
        self.assertEqual(out["status"], "unsupported")
        self.assertIn("page-fault-without-sv39", out["reason"])

    def test_deny_class_mismatch_is_unsupported(self) -> None:
        out = map_target_operation(
            privilege="s", effective_privilege="s", access="load",
            translation="sv39", allow_or_deny="deny", mcause_class="instruction_access_fault",
        )
        self.assertEqual(out["status"], "unsupported")
        self.assertIn("unrepresentable-deny-class", out["reason"])

    def test_unreachable_effective_privilege_is_unsupported(self) -> None:
        out = map_target_operation(
            privilege="s", effective_privilege="m", access="load",
            translation="bare", allow_or_deny="allow",
        )
        self.assertEqual(out["status"], "unsupported")


@unittest.skipUnless(
    C910_FORMAL.is_dir(),
    "requires external C910 formal evidence; set PMPFUZZ_EVIDENCE_ROOT",
)
class TestC910Bridge(unittest.TestCase):
    def test_sum_fetch_violation_is_allow_not_payload_trap(self) -> None:
        case, result = _load_c910("c910-nonpmp-fetch__s-fetch-u-page-sum1-slot3")
        report = classify_scenario(case, result)
        self.assertEqual(report["status"], "mapped")
        self.assertEqual(report["observed_outcome"], "allow")
        self.assertTrue(report["known_violation"])
        self.assertEqual(report["oracle_expected"], "deny")
        self.assertIn(
            "family=stimulus|privilege=s|effective_privilege=s|access=fetch|translation=sv39",
            report["bins"],
        )

    def test_sum_fetch_sum0_page_fault_is_compliant(self) -> None:
        case, result = _load_c910("c910-nonpmp-fetch__s-fetch-u-page-sum0-slot3")
        report = classify_scenario(case, result)
        self.assertEqual(report["status"], "mapped")
        self.assertFalse(report["known_violation"])
        self.assertIn(
            "family=decision|access=fetch|allow_or_deny=deny|mcause_class=instruction_page_fault",
            report["bins"],
        )

    def test_ecall_payload_is_not_a_protection_denial(self) -> None:
        case, result = _load_c910("c910-nonpmp-privilege__bare-s-ecall-fw-text-slot3")
        report = classify_scenario(case, result)
        self.assertEqual(report["status"], "mapped")
        self.assertEqual(report["observed_outcome"], "allow")
        self.assertFalse(report["known_violation"])

    def test_illegal_instruction_payload_is_not_a_protection_denial(self) -> None:
        case, result = _load_c910("c910-nonpmp-fetch__bare-u-exec-illegal-slot3")
        report = classify_scenario(case, result)
        self.assertEqual(report["status"], "mapped")
        self.assertEqual(report["observed_outcome"], "allow")

    def test_side_effect_is_not_a_v4_target_operation(self) -> None:
        case, result = _load_c910("c910-nonpmp-privilege__bare-u-store-slot3")
        report = c910_target_operation(case, result)
        self.assertEqual(report["status"], "unsupported")
        self.assertIn("side-effect", report["reason"])


class TestArchitecturalOracle(unittest.TestCase):
    def test_s_fetch_from_u_page_denied_regardless_of_sum(self) -> None:
        case = {
            "translation": "sv39",
            "effective_privilege": "s",
            "access": "fetch",
            "sum_enabled": True,
            "name": "s-fetch-u-page-sum1",
        }
        self.assertFalse(architectural_oracle_allow(case))

    def test_u_fetch_from_u_page_allowed(self) -> None:
        case = {
            "translation": "sv39",
            "effective_privilege": "u",
            "access": "fetch",
            "name": "u-fetch-u-page-control",
        }
        self.assertTrue(architectural_oracle_allow(case))

    def test_s_load_from_u_page_requires_sum(self) -> None:
        base = {
            "translation": "sv39",
            "effective_privilege": "s",
            "access": "load",
            "pte_permissions": {"valid": True, "accessed": True, "dirty": True, "rwx": "rw-", "user": True},
        }
        self.assertTrue(architectural_oracle_allow({**base, "sum_enabled": True}))
        self.assertFalse(architectural_oracle_allow({**base, "sum_enabled": False}))

    def test_u_load_from_u_page_allowed(self) -> None:
        case = {
            "translation": "sv39",
            "effective_privilege": "u",
            "access": "load",
            "pte_permissions": {"valid": True, "accessed": True, "dirty": True, "rwx": "rw-", "user": True},
        }
        self.assertTrue(architectural_oracle_allow(case))

    def test_mxr_allows_load_from_execute_only_page(self) -> None:
        case = {
            "translation": "sv39",
            "effective_privilege": "u",
            "access": "load",
            "mxr": True,
            "pte_permissions": {"valid": True, "accessed": True, "dirty": True, "rwx": "--x", "user": True},
        }
        self.assertTrue(architectural_oracle_allow(case))

    def test_bare_translation_allowed(self) -> None:
        self.assertTrue(architectural_oracle_allow({"translation": "bare", "effective_privilege": "u", "access": "load"}))

    def test_stateful_case_is_unqualified(self) -> None:
        case = {
            "translation": "sv39",
            "effective_privilege": "u",
            "access": "load",
            "profile": "c910-nonpmp-tlb",
            "name": "tlb-asid-return-nosfence",
            "pte_permissions": {"valid": True, "accessed": True, "dirty": True, "rwx": "---", "user": True},
        }
        self.assertIsNone(architectural_oracle_allow(case))

    def test_empty_pte_load_is_unqualified(self) -> None:
        case = {
            "translation": "sv39",
            "effective_privilege": "u",
            "access": "load",
            "pte_permissions": {},
        }
        self.assertIsNone(architectural_oracle_allow(case))


if __name__ == "__main__":
    unittest.main()
