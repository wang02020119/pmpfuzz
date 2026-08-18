import unittest

from pmpfuzz.diagnostics import (
    ObservationKind,
    ObservationPhase,
    decode_observation_payload,
    encode_observation_payload,
)
from pmpfuzz.dut import DutRunResult
from pmpfuzz.runner import _bapc_actual_result


def _observed_event(
    *,
    kind: ObservationKind = ObservationKind.TRAP,
    mcause: int = 5,
    mtval: int = 0x80008020,
    mepc: int = 0x80000000,
    phase: ObservationPhase = ObservationPhase.PROBE,
):
    return decode_observation_payload(
        encode_observation_payload(
            kind,
            mcause=mcause,
            mtval=mtval,
            mepc=mepc,
            phase=phase,
        )
    )


class BapcRunResultContractTest(unittest.TestCase):
    def test_pass_marker_becomes_actual_completion_for_bapc(self):
        result = _bapc_actual_result(
            DutRunResult(
                dut="rocket-clean",
                status="pass",
                elapsed_seconds=0.25,
                returncode=0,
            )
        )

        self.assertTrue(result["observation_valid"])
        self.assertEqual(result["observed_event"], "completion")
        self.assertIsNone(result["observed_mcause"])

    def test_fail_marker_becomes_actual_trap_for_bapc(self):
        result = _bapc_actual_result(
            DutRunResult(
                dut="rocket-clean",
                status="fail",
                elapsed_seconds=0.25,
                returncode=1,
                observed_mcause=5,
            )
        )

        self.assertTrue(result["observation_valid"])
        self.assertEqual(result["observed_event"], "trap")
        self.assertEqual(result["observed_mcause"], 5)

    def test_xiangshan_goodtrap_without_structured_observation_is_not_bapc_valid(self):
        result = _bapc_actual_result(
            DutRunResult(
                dut="xiangshan-clean",
                status="pass",
                elapsed_seconds=0.25,
                returncode=0,
                reason="xiangshan good trap",
            )
        )

        self.assertFalse(result["observation_valid"])
        self.assertIsNone(result["observed_event"])

    def test_xiangshan_badtrap_without_structured_observation_is_not_bapc_valid(self):
        result = _bapc_actual_result(
            DutRunResult(
                dut="xiangshan-clean",
                status="fail",
                elapsed_seconds=0.25,
                returncode=0,
                observed_mcause=5,
                failure_class="xiangshan_bad_trap",
            )
        )

        self.assertFalse(result["observation_valid"])
        self.assertIsNone(result["observed_event"])

    def test_xiangshan_structured_observation_remains_bapc_valid(self):
        result = _bapc_actual_result(
            DutRunResult(
                dut="xiangshan-clean",
                status="observed",
                elapsed_seconds=0.25,
                returncode=0,
                observed_mcause=5,
                observed_stage="final",
                observed_fault_address=0x80008020,
                observation=_observed_event(),
            )
        )

        self.assertTrue(result["observation_valid"])
        self.assertEqual(result["observed_event"], "trap")
        self.assertEqual(result["observed_mcause"], 5)
        self.assertEqual(result["observed_stage"], "final")
        self.assertEqual(result["observed_fault_address"], 0x80008020)


if __name__ == "__main__":
    unittest.main()
