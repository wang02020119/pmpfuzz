import tempfile
import unittest
from pathlib import Path

from pmpfuzz.__main__ import main
from pmpfuzz.capabilities import oracle_applicability_for_case, required_capabilities_for_case
from pmpfuzz.coverage_universe import freeze_coverage_universes, validate_coverage_universe
from pmpfuzz.c910_nonpmp import (
    C910_NONPMP_TARGET,
    bootstrap_capability,
    bootstrap_cases,
    write_bootstrap_run,
)
from pmpfuzz.schema import read_json


SAMPLE_UART = """
[nonpmp-chain] real-mode record=bare-s-ecall-fw-text entry=0x80200000 mpp=1 arg0=0x0 arg1=0x0 satp=0x0 extra=0x0 result=trap cause=0x9 trap_name=supervisor_ecall tval=0x0 mepc=0x80200000 payload_result=0xfacefeeddeadbeef
[security-chain] mprv-load sv39-u-load-user-page addr=0x12346000 mpp=0 extra=0x0 result=allow val=0x1122334455667788
[uarch-chain] load record=tlb-clear-nosfence addr=0x12355000 mpp=0 extra=0x0 satp=0x8000000000000001 result=allow val=0xfeedfacecafebeef
[security-chain] fetch-test sv39-u-exec-nx-page entry=0x12347000 mpp=0 satp=0x8000000000000000 sfence=1 fencei=1 result=trap cause=0xc trap_name=fetch_page_fault tval=0x12347000 mepc=0x0
[security-chain] side-effect real-u-store-fw-data value=0x8877665544332211 expected_changed=0x8877665544332211
""".strip()


class C910NonPmpBootstrapTest(unittest.TestCase):
    def test_bootstrap_cases_use_explicit_non_pmp_capability_override(self):
        capability = bootstrap_capability()
        cases = bootstrap_cases(capability=capability)

        self.assertEqual(len(cases), 78)
        self.assertTrue(all("pmp" not in required_capabilities_for_case(case) for case in cases))

        sv39_case = next(case for case in cases if case["name"] == "c910-nonpmp-sv39__sv39-u-load-user-page")
        self.assertIn("sv39", required_capabilities_for_case(sv39_case))
        self.assertEqual(oracle_applicability_for_case(sv39_case, capability), "valid")

    def test_freeze_coverage_universes_supports_c910_nonpmp_target(self):
        bundle = freeze_coverage_universes(
            target=C910_NONPMP_TARGET,
            capability=bootstrap_capability(),
            include_experimental=False,
            seed=20260727,
        )

        self.assertEqual(set(bundle), {"semantic", "pairwise", "security_triples", "predicates"})
        self.assertGreater(bundle["semantic"]["bin_count"], 0)
        self.assertEqual(bundle["semantic"]["target"], C910_NONPMP_TARGET)
        validate_coverage_universe(bundle["semantic"])

    def test_write_bootstrap_run_parses_uart_into_results_and_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            uart_log = root / "uart.txt"
            uart_log.write_text(SAMPLE_UART, encoding="utf-8")

            payload = write_bootstrap_run(uart_log=uart_log, out_dir=root / "run")

            self.assertEqual(payload["dut"], "c910-nonpmp")

            pass_result = read_json(root / "run" / "results" / "c910-nonpmp-privilege__bare-s-ecall-fw-text" / "result.json")
            self.assertEqual(pass_result["status"], "pass")
            self.assertEqual(pass_result["observed_event"], "trap")
            self.assertEqual(pass_result["observed_phase"], "probe")

            side_effect = read_json(root / "run" / "results" / "c910-nonpmp-side-effect__real-u-store-fw-data" / "result.json")
            self.assertEqual(side_effect["status"], "pass")
            self.assertEqual(side_effect["observed_phase"], "final_sentinel_modified")

            missing = read_json(root / "run" / "results" / "c910-nonpmp-fetch__bare-u-exec-ecall" / "result.json")
            self.assertEqual(missing["status"], "inconclusive")
            self.assertFalse(missing["observation_valid"])

            coverage = read_json(Path(payload["coverage"]))
            self.assertEqual(coverage["target"], C910_NONPMP_TARGET)
            entry = coverage["execution_coverage"]["by_dut"]["c910-nonpmp"]
            self.assertGreaterEqual(entry["qualification"]["eligible_results"], 5)
            self.assertGreater(entry["semantic"]["covered_target_bins"], 0)

    def test_cli_accepts_c910_nonpmp_analyze(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            uart_log = root / "uart.txt"
            uart_log.write_text(SAMPLE_UART, encoding="utf-8")

            rc = main(
                [
                    "c910-nonpmp-analyze",
                    "--uart-log",
                    str(uart_log),
                    "--out",
                    str(root / "run"),
                ]
            )

            self.assertEqual(rc, 0)
            coverage = read_json(root / "run" / "coverage" / "coverage.json")
            self.assertEqual(coverage["target"], C910_NONPMP_TARGET)


if __name__ == "__main__":
    unittest.main()
