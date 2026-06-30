import unittest
from pathlib import Path

from pmpfuzz.diagnostics import FailureClass, PASS_TOHOST, encode_tohost_failure
from pmpfuzz.dut import (
    CascadeRocketDut,
    ChipyardMakeDut,
    DEFAULT_XIANGSHAN_EMU,
    XiangShanDut,
    make_dut,
    parse_cascade_log,
    parse_chipyard_log,
    parse_spike_log,
    parse_xiangshan_log,
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

    def test_spike_log_parser_treats_failed_marker_as_fail_even_with_zero_returncode(self):
        result = parse_spike_log("*** FAILED *** (tohost = 16384)\n", returncode=0)

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.observed_tohost, 16384)
        self.assertEqual(result.failure_class, "unknown_failure")

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

    def test_cva6_dut_uses_clean_chipyard_defaults_without_cascade_wrapper(self):
        dut = make_dut(
            dut="cva6",
            spike="spike",
            isa="rv64gc",
            chipyard_dir=Path("/clean-chipyard"),
        )

        command = dut.command_for(Path("/tmp/case.elf"))

        self.assertEqual(dut.config, "CVA6Config")
        self.assertIn("VERILATOR_THREADS=1", command)
        self.assertNotIn("verilator_cva6_wrapper.sh", " ".join(command))

    def test_cva6_clean_alias_uses_cva6_config(self):
        dut = make_dut(
            dut="cva6-clean",
            spike="spike",
            isa="rv64gc",
            chipyard_dir=Path("/clean-chipyard"),
        )

        self.assertEqual(dut.name, "cva6-clean")
        self.assertEqual(dut.config, "CVA6Config")

    def test_xiangshan_clean_uses_direct_openxiangshan_emu(self):
        dut = make_dut(
            dut="xiangshan-clean",
            spike="spike",
            isa="rv64gc",
            dut_bin=Path("/xs/build/native-tlminimal/verilator-compile/emu"),
            simlen=12345,
        )

        self.assertIsInstance(dut, XiangShanDut)
        command = dut.command_for(Path("/tmp/case.elf"))
        self.assertEqual(command[0], "/xs/build/native-tlminimal/verilator-compile/emu")
        self.assertIn("--no-diff", command)
        self.assertIn("-C", command)
        self.assertIn("12345", command)
        self.assertIn("-i", command)
        self.assertIn("/tmp/case.elf", command)

    def test_xiangshan_whitebox_artifact_command_enables_stable_commit_trace(self):
        dut = XiangShanDut(
            binary=Path("/xs/build/verilator-compile/emu"),
            simlen=100,
            whitebox_artifacts=True,
        )

        command = dut.command_for(Path("/tmp/case.elf"), artifact_prefix=Path("/tmp/result/case"))

        self.assertIn("--dump-commit-trace", command)
        self.assertNotIn("--dump-footprints=/tmp/result/case.footprints", command)

    def test_default_xiangshan_emu_points_to_vanilla_tree(self):
        self.assertIn("/home/dubhe/wjs/xiangshan_vanilla/", DEFAULT_XIANGSHAN_EMU.as_posix())
        self.assertNotIn("cascade", DEFAULT_XIANGSHAN_EMU.as_posix())

    def test_xiangshan_log_parser_distinguishes_good_bad_limit_and_no_marker(self):
        self.assertEqual(parse_xiangshan_log("HIT GOOD TRAP at pc = 0x80000000", returncode=0).status, "pass")

        bad = parse_xiangshan_log("HIT BAD TRAP at pc = 0x80000000", returncode=0)
        self.assertEqual(bad.status, "fail")
        self.assertEqual(bad.failure_class, "xiangshan_bad_trap")

        limit = parse_xiangshan_log("EXCEEDING CYCLE/INSTR LIMIT at pc = 0x80000000", returncode=0)
        self.assertEqual(limit.status, "infra_failure")
        self.assertEqual(limit.failure_class, "infra_unadapted")

        no_marker = parse_xiangshan_log("Guest cycle spent: 20,001", returncode=0)
        self.assertEqual(no_marker.status, "infra_failure")
        self.assertEqual(no_marker.failure_class, "infra_unadapted")

    def test_xiangshan_log_parser_extracts_structured_pmpfuzz_diag(self):
        payload = encode_tohost_failure(FailureClass.WRONG_MCAUSE, mcause=13, mtval=0x80008000)
        result = parse_xiangshan_log(
            f"PMFUZZ_DIAG tohost=0x{payload:x} mcause=0xd mtval=0x80008000\n"
            "HIT BAD TRAP at pc = 0x80004000\n",
            returncode=0,
        )

        self.assertEqual(result.status, "fail")
        self.assertEqual(result.failure_class, "wrong_mcause")
        self.assertEqual(result.observed_tohost, payload)
        self.assertEqual(result.observed_mcause, 13)
        self.assertEqual(result.observed_mtval, 0x80008000)
        self.assertIn("PMFUZZ_DIAG", result.reason)

    def test_xiangshan_log_parser_records_goodtrap_pc_and_pass_diag(self):
        result = parse_xiangshan_log(
            f"PMFUZZ_DIAG tohost=0x{PASS_TOHOST:x} mcause=0x0 mtval=0x0\n"
            "HIT GOOD TRAP at pc = 0x80000088\n",
            returncode=0,
        )

        self.assertEqual(result.status, "pass")
        self.assertEqual(result.observed_tohost, PASS_TOHOST)
        self.assertIn("0x80000088", result.reason)

    def test_cascade_rocket_command_uses_simlen_and_binary_env(self):
        dut = CascadeRocketDut(binary=Path("/rocket/Vtop_tiny_soc"), simlen=5000)

        command, env = dut.command_and_env(Path("/tmp/case.elf"))

        self.assertEqual(command, ["/rocket/Vtop_tiny_soc"])
        self.assertEqual(env["SIMLEN"], "5000")
        self.assertEqual(env["SIMSRAMELF"], "/tmp/case.elf")
        self.assertEqual(env["SIMROMELF"], "/tmp/case.elf")


if __name__ == "__main__":
    unittest.main()
