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

    def test_completion_is_judged_against_expected_denial_on_host(self):
        event = ObservedEvent(
            kind=ObservationKind.COMPLETION,
            mcause=8,
            mtval_fingerprint=mtval_fingerprint(0),
            mepc_tag=mepc_tag(0x80004010),
            phase=ObservationPhase.COMPLETED,
        )

        result = judge_observation(self.case, event)

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.failure_class, "unexpected_no_trap")

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
