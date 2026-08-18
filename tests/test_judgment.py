import unittest

from pmpfuzz.diagnostics import (
    ObservedEvent,
    ObservationKind,
    ObservationPhase,
    mepc_tag,
    mtval_fingerprint,
)
from pmpfuzz.judgment import judge_observation


class HostJudgmentTest(unittest.TestCase):
    def setUp(self):
        self.case = {
            "name": "ptw_l1_deny",
            "access": "fetch",
            "privilege": "U",
            "translation": "sv39",
            "address": "0x80000000",
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

    def test_wrong_ptw_level_cannot_pass_on_matching_mcause(self):
        event = ObservedEvent(
            kind=ObservationKind.TRAP,
            mcause=5,
            mtval_fingerprint=mtval_fingerprint(0x80000000),
            mepc_tag=mepc_tag(0x40000000),
            phase=ObservationPhase.PROBE,
        )

        result = judge_observation(
            self.case,
            event,
            observed_stage="ptw",
            observed_ptw_level="L0",
            observed_fault_address=0x80014000,
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.failure_class, "wrong_trap_stage")
        self.assertFalse(result.stage_verified)

    def test_matching_cause_phase_level_and_address_pass(self):
        event = ObservedEvent(
            kind=ObservationKind.TRAP,
            mcause=5,
            mtval_fingerprint=mtval_fingerprint(0x80000000),
            mepc_tag=mepc_tag(0x40000000),
            phase=ObservationPhase.PROBE,
        )

        result = judge_observation(
            self.case,
            event,
            observed_stage="ptw",
            observed_ptw_level="L1",
            observed_fault_address=0x80013000,
        )

        self.assertEqual(result.status, "pass")
        self.assertTrue(result.stage_verified)

    def test_mismatched_probe_vaddr_makes_stage_evidence_inconclusive(self):
        event = ObservedEvent(
            kind=ObservationKind.TRAP,
            mcause=2,
            mtval_fingerprint=mtval_fingerprint(0x80000000),
            mepc_tag=0,
            phase=ObservationPhase.PROBE,
        )

        result = judge_observation(
            self.case,
            event,
            observed_stage="ptw",
            observed_ptw_level="L1",
            observed_fault_address=0x80010008,
            observed_probe_vaddr=0x40000000,
        )

        self.assertEqual(result.status, "inconclusive")
        self.assertEqual(result.failure_class, "unverified_trap_stage")
        self.assertFalse(result.stage_verified)

    def test_non_ptw_expected_stage_ignores_mismatched_probe_vaddr(self):
        case = {
            "name": "pte_perm_deny",
            "access": "load",
            "privilege": "U",
            "translation": "sv39",
            "address": "0x80000000",
            "expected": {"allowed": False, "trap_cause": 15, "stage": "pte_permission"},
        }
        event = ObservedEvent(
            kind=ObservationKind.TRAP,
            mcause=15,
            mtval_fingerprint=mtval_fingerprint(0x80000000),
            mepc_tag=0,
            phase=ObservationPhase.PROBE,
        )

        result = judge_observation(
            case,
            event,
            observed_stage="ptw",
            observed_ptw_level="L0",
            observed_fault_address=0x80008000,
            observed_probe_vaddr=0x40000024,
        )

        self.assertEqual(result.status, "pass")
        self.assertIsNone(result.failure_class)

    def test_completion_is_judged_against_expected_denial_on_host(self):
        case = {
            "name": self.case["name"],
            "expected": dict(self.case["expected"]),
            "contract_trace": self.case["contract_trace"],
        }
        event = ObservedEvent(
            kind=ObservationKind.COMPLETION,
            mcause=8,
            mtval_fingerprint=mtval_fingerprint(0),
            mepc_tag=mepc_tag(0x80004010),
            phase=ObservationPhase.COMPLETED,
        )

        result = judge_observation(case, event)

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.failure_class, "unexpected_no_trap")

    def test_stateful_repeat_completion_is_generic_stale_permission(self):
        case = {
            "name": "stateful_repeat_after_mutation",
            "access": "load",
            "privilege": "S",
            "translation": "sv39",
            "address": "0x80008000",
            "expected": {"allowed": False, "trap_cause": 13, "stage": "stateful_final"},
            "stateful_sequence": {
                "final_probe": "repeat",
                "expected_final": "trap_after_mutation",
                "stale_failure_class": "STALE_TLB_PERMISSION",
            },
        }
        event = ObservedEvent(
            kind=ObservationKind.COMPLETION,
            mcause=9,
            mtval_fingerprint=mtval_fingerprint(0x80008000),
            mepc_tag=0,
            phase=ObservationPhase.FINAL,
        )

        result = judge_observation(case, event)

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.failure_class, "stale_permission")
        self.assertTrue(result.stage_verified)

    def test_completion_for_allowed_case_tolerates_nonzero_mtval_fingerprint(self):
        case = {
            "name": "allow_case",
            "access": "load",
            "privilege": "U",
            "translation": "bare",
            "address": "0x80008000",
            "expected": {"allowed": True, "trap_cause": None, "stage": "none"},
        }
        event = ObservedEvent(
            kind=ObservationKind.COMPLETION,
            mcause=8,
            mtval_fingerprint=115,
            mepc_tag=mepc_tag(0x80004010),
            phase=ObservationPhase.COMPLETED,
        )

        result = judge_observation(case, event)

        self.assertEqual(result.status, "pass")
        self.assertIsNone(result.failure_class)

    def test_wrong_mepc_is_rejected_even_when_mcause_matches(self):
        case = {
            **self.case,
            "access": "load",
            "privilege": "U",
            "translation": "sv39",
            "address": "0x80000000",
        }
        event = ObservedEvent(
            kind=ObservationKind.TRAP,
            mcause=5,
            mtval_fingerprint=mtval_fingerprint(0x80000000),
            mepc_tag=mepc_tag(0x80004000),
            phase=ObservationPhase.PROBE,
        )

        result = judge_observation(
            case,
            event,
            observed_stage="ptw",
            observed_ptw_level="L1",
            observed_fault_address=0x80013000,
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.failure_class, "wrong_mepc")

    def test_legacy_su_probe_uses_machine_text_mepc_window(self):
        case = {
            "name": "legacy_deny",
            "profile": "legacy-data",
            "access": "load",
            "privilege": "U",
            "translation": "bare",
            "address": "0x80008000",
            "expected": {"allowed": False, "trap_cause": 5, "stage": "pmp"},
        }
        event = ObservedEvent(
            kind=ObservationKind.TRAP,
            mcause=5,
            mtval_fingerprint=mtval_fingerprint(0x80008000),
            mepc_tag=mepc_tag(0x80000020),
            phase=ObservationPhase.PROBE,
        )

        result = judge_observation(case, event)

        self.assertEqual(result.status, "pass")


if __name__ == "__main__":
    unittest.main()
