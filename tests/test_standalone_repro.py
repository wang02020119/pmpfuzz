import tempfile
import unittest
from pathlib import Path

from pmpfuzz.__main__ import _load_case
from pmpfuzz.dut import VarianeDirectDut, make_dut, parse_chipyard_log


class StandaloneReproTest(unittest.TestCase):
    def test_load_case_accepts_named_standalone_asm_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "cva6-defect-01"
            case_dir.mkdir()
            (case_dir / "cva6-defect-01.S").write_text(".section .text\n", encoding="ascii")
            (case_dir / "generated-seed.S").write_text(".section .text\n", encoding="ascii")

            loaded_dir, case, source = _load_case(case_dir)

        self.assertEqual(loaded_dir.name, "cva6-defect-01")
        self.assertEqual(case["name"], "cva6-defect-01")
        self.assertEqual(case["profile"], "standalone-poc")
        self.assertEqual(source["mode"], "standalone_asm")
        self.assertTrue(str(source["asm"]).endswith("cva6-defect-01.S"))

    def test_make_dut_uses_variane_direct_mode_for_variane_testharness(self):
        dut = make_dut(
            dut="cva6-clean",
            spike="spike",
            isa="rv64gc",
            dut_bin=Path("/tmp/Variane_testharness"),
        )

        self.assertIsInstance(dut, VarianeDirectDut)
        self.assertEqual(
            dut.command_for(Path("/tmp/cva6-defect-01.elf")),
            ["/tmp/Variane_testharness", "/tmp/cva6-defect-01.elf"],
        )

    def test_parse_chipyard_log_accepts_success_marker(self):
        parsed = parse_chipyard_log(
            "./cva6-defect-01.elf *** SUCCESS *** (tohost = 0) after 35528 cycles",
            0,
        )

        self.assertEqual(parsed.status, "pass")


if __name__ == "__main__":
    unittest.main()
