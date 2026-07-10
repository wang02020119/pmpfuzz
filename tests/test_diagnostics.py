import unittest

from pmpfuzz.diagnostics import (
    FailureClass,
    ObservationKind,
    ObservationPhase,
    classify_log_failure,
    decode_observation_payload,
    decode_tohost_payload,
    encode_failure_payload,
    encode_observation_payload,
    encode_tohost_failure,
)
from pmpfuzz.dut import parse_chipyard_log


class DiagnosticsTest(unittest.TestCase):
    def test_observation_payload_round_trips_raw_trap_event(self):
        payload = encode_observation_payload(
            ObservationKind.TRAP,
            mcause=5,
            mtval=0x80013000,
            mepc=0x80004024,
            phase=ObservationPhase.PROBE,
        )

        event = decode_observation_payload(payload)

        self.assertIsNotNone(event)
        self.assertEqual(event.kind, ObservationKind.TRAP)
        self.assertEqual(event.mcause, 5)
        self.assertEqual(event.mtval, 0x80013000)
        self.assertEqual(event.mepc_low, 0x4024)
        self.assertEqual(event.phase, ObservationPhase.PROBE)

    def test_tohost_failure_payload_round_trips_class_mcause_and_mtval(self):
        payload = encode_failure_payload(FailureClass.WRONG_MCAUSE, mcause=13, mtval=0x80001234)
        decoded = decode_tohost_payload(payload)

        self.assertEqual(decoded.failure_class, "wrong_mcause")
        self.assertEqual(decoded.observed_mcause, 13)
        self.assertEqual(decoded.observed_mtval, 0x80001234)

    def test_chipyard_parser_decodes_engineered_failure_payload(self):
        raw_tohost = encode_tohost_failure(FailureClass.UNEXPECTED_NO_TRAP, mcause=9, mtval=0x44) >> 1
        parsed = parse_chipyard_log(f"*** FAILED *** (tohost = {raw_tohost})", returncode=2)

        self.assertEqual(parsed.status, "fail")
        self.assertEqual(parsed.failure_class, "unexpected_no_trap")
        self.assertEqual(parsed.observed_mcause, 9)
        self.assertEqual(parsed.observed_mtval, 0x44)

    def test_log_classifier_detects_pipeline_hang(self):
        self.assertEqual(classify_log_failure("Assertion failed: Pipeline has hung.", 2), "pipeline_hung")

    def test_stateful_failure_classes_round_trip(self):
        for klass in [
            FailureClass.FORBIDDEN_SIDE_EFFECT,
            FailureClass.MISSING_EXPECTED_SIDE_EFFECT,
            FailureClass.STALE_PMP_PERMISSION,
            FailureClass.STALE_TLB_PERMISSION,
            FailureClass.STALE_PTW_PERMISSION,
        ]:
            payload = encode_failure_payload(klass, mcause=7, mtval=0x9000)
            decoded = decode_tohost_payload(payload)

            self.assertEqual(decoded.failure_class, klass.name.lower())
            self.assertEqual(decoded.observed_mcause, 7)
            self.assertEqual(decoded.observed_mtval, 0x9000)


if __name__ == "__main__":
    unittest.main()
