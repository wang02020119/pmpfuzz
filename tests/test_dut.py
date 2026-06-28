import unittest
from pathlib import Path

from pmpfuzz.dut import (
    CascadeRocketDut,
    ChipyardMakeDut,
    make_dut,
    parse_cascade_log,
    parse_chipyard_log,
    _subprocess_output_text,
)


class DutAdapterTest(unittest.TestCase):
    def test_cascade_log_parser_treats_result_dump_one_as_pass(self):
        result = parse_cascade_log(
            "Dump of reg x01: 0x0000000000000001.\n"
            "Found a stop request. Stopping the benchmark after 50 more ticks.\n",
            returncode=0,
        )

        self.assertEqual(result.status, "pass")
        self.assertEqual(result.observed_code, 1)

    def test_subprocess_output_text_accepts_bytes_for_timeout_logs(self):
        self.assertEqual(_subprocess_output_text(b"abc\xff"), "abc\ufffd")
        self.assertEqual(_subprocess_output_text("abc"), "abc")
        self.assertEqual(_subprocess_output_text(None), "")

    def test_cascade_log_parser_treats_non_one_result_dump_as_fail(self):
        result = parse_cascade_log(
            "Dump of reg x01: 0x0000000000000005.\n"
            "Found a stop request. Stopping the benchmark after 50 more ticks.\n",
            returncode=0,
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.observed_code, 5)

    def test_chipyard_log_parser_uses_returncode_and_failed_marker(self):
        self.assertEqual(parse_chipyard_log("*** PASSED ***", returncode=0).status, "pass")
        self.assertEqual(parse_chipyard_log("*** FAILED *** (tohost = 3)", returncode=0).status, "fail")
        self.assertEqual(parse_chipyard_log("assert failed", returncode=1).status, "infra_failure")

    def test_chipyard_make_command_uses_config_binary_and_hex_runner(self):
        dut = ChipyardMakeDut(
            dut_name="cva6",
            chipyard_dir=Path("/chipyard"),
            config="CVA6Config",
            verilator_bin_dir=Path("/tools/verilator/bin"),
            make_vars=("VERILATOR=/tools/verilator", "EXTRA_SIM_CXXFLAGS=-std=c++17"),
        )

        command = dut.command_for(Path("/tmp/case.elf"))

        self.assertEqual(command[:2], ["make", "CONFIG=CVA6Config"])
        self.assertIn("BINARY=/tmp/case.elf", command)
        self.assertIn("VERILATOR=/tools/verilator", command)
        self.assertIn("EXTRA_SIM_CXXFLAGS=-std=c++17", command)
        self.assertEqual(command[-1], "run-binary-fast-hex")

    def test_chipyard_env_prepends_required_tool_paths(self):
        dut = ChipyardMakeDut(
            dut_name="rocket",
            chipyard_dir=Path("/chipyard"),
            config="RocketConfig",
            verilator_bin_dir=Path("/tools/verilator/bin"),
            riscv=Path("/riscv"),
            java_home=Path("/jdk11"),
        )

        env = dut.env()

        self.assertEqual(env["RISCV"], "/riscv")
        self.assertEqual(env["JAVA_HOME"], "/jdk11")
        self.assertTrue(env["PATH"].startswith("/jdk11/bin:/riscv/bin:/tools/verilator/bin:"))

    def test_default_rocket_dut_uses_timing_option(self):
        dut = make_dut(dut="rocket", spike="spike", isa="rv64gc")

        command = dut.command_for(Path("/tmp/case.elf"))

        self.assertIn("VERILATOR=/home/dubhe/wjs/pmp-fuzz-stage1/scripts/verilator_rocket_wrapper.sh", command)
        self.assertIn("PLATFORM_OPTS=--timing", command)

    def test_clean_rocket_dut_uses_clean_chipyard_defaults(self):
        dut = make_dut(
            dut="rocket-clean",
            spike="spike",
            isa="rv64gc",
            chipyard_dir=Path("/clean-chipyard"),
        )

        command = dut.command_for(Path("/tmp/case.elf"))

        self.assertEqual(dut.config, "RocketConfig")
        self.assertIn("VERILATOR_THREADS=1", command)
        self.assertNotIn("PLATFORM_OPTS=--timing", command)

    def test_clean_boom_dut_uses_small_boom_config(self):
        dut = make_dut(
            dut="boom-clean",
            spike="spike",
            isa="rv64gc",
            chipyard_dir=Path("/clean-chipyard"),
        )

        self.assertEqual(dut.config, "SmallBoomV3Config")

    def test_cascade_rocket_command_uses_simlen_and_binary_env(self):
        dut = CascadeRocketDut(binary=Path("/rocket/Vtop_tiny_soc"), simlen=5000)

        command, env = dut.command_and_env(Path("/tmp/case.elf"))

        self.assertEqual(command, ["/rocket/Vtop_tiny_soc"])
        self.assertEqual(env["SIMLEN"], "5000")
        self.assertEqual(env["SIMSRAMELF"], "/tmp/case.elf")
        self.assertEqual(env["SIMROMELF"], "/tmp/case.elf")


if __name__ == "__main__":
    unittest.main()
