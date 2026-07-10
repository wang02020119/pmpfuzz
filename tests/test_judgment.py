import unittest

from pmpfuzz.diagnostics import ObservedEvent, ObservationKind, ObservationPhase
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
            mtval=0x80000000,
            mepc_low=0x4000,
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
            mtval=0x80000000,
            mepc_low=0x4000,
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
            mtval=0,
            mepc_low=0x4010,
            phase=ObservationPhase.COMPLETED,
        )

        result = judge_observation(self.case, event)

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.failure_class, "unexpected_no_trap")


if __name__ == "__main__":
    unittest.main()
