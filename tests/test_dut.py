import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pmpfuzz.diagnostics import (
    FailureClass,
    ObservationKind,
    ObservationPhase,
    PASS_TOHOST,
    encode_observation_payload,
    encode_tohost_failure,
    mtval_fingerprint,
)
from pmpfuzz.dut import (
    CascadeRocketDut,
    ChipyardDirectDut,
    ChipyardMakeDut,
    DEFAULT_ROCKET_VERILATOR,
    DEFAULT_XIANGSHAN_EMU,
    ParsedDutLog,
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

    def test_chipyard_explicit_failed_marker_without_tohost_is_not_infra_failure(self):
        result = parse_chipyard_log(
            "*** FAILED *** (timeout) after 50001 simulation cycles\n",
            returncode=255,
        )

        self.assertEqual(result.status, "fail")
        self.assertIsNone(result.observed_tohost)

    def test_empty_success_logs_are_infrastructure_failures(self):
        for parser in (parse_spike_log, parse_chipyard_log):
            with self.subTest(parser=parser.__name__):
                result = parser("", returncode=0)
                self.assertEqual(result.status, "infra_failure")
                self.assertEqual(result.failure_class, "missing_completion_marker")

    def test_observation_payload_is_returned_for_host_side_judgment(self):
        payload = encode_observation_payload(
            ObservationKind.TRAP,
            mcause=5,
            mtval=0x80013000,
            mepc=0x80004020,
            phase=ObservationPhase.PROBE,
        )

        result = parse_chipyard_log(f"*** FAILED *** (tohost = {payload})", returncode=1)

        self.assertEqual(result.status, "observed")
        self.assertIsNotNone(result.observation)
        self.assertEqual(result.observation.kind, ObservationKind.TRAP)
        self.assertEqual(result.observation.mcause, 5)

    def test_observation_parser_attaches_ptw_stage_evidence_to_its_result(self):
        payload = encode_observation_payload(
            ObservationKind.TRAP,
            mcause=5,
            mtval=0x80000000,
            mepc=0x40000020,
            phase=ObservationPhase.PROBE,
        )
        text = (
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_ptw_exception schema=2 role=diagnostic "
            "chain=ptw-response stage=ptw level=1 vaddr=0x40000000 paddr=0x80013000 allow=0 exception=1\n"
            f"*** FAILED *** (tohost = {payload})\n"
        )

        result = parse_chipyard_log(text, returncode=0)

        self.assertEqual(result.status, "observed")
        self.assertEqual(result.observed_stage, "ptw")
        self.assertEqual(result.observed_ptw_level, "L1")
        self.assertEqual(result.observed_fault_address, 0x80013000)
        self.assertEqual(result.observed_probe_vaddr, 0x40000000)

    def test_observation_parser_accepts_rocket_ptw_access_exception_probe(self):
        payload = encode_observation_payload(
            ObservationKind.TRAP,
            mcause=5,
            mtval=0x80000000,
            mepc=0x40000020,
            phase=ObservationPhase.PROBE,
        )
        text = (
            "PMFUZZ_PROBE dut=rocket-clean probe=rocket_ptw_access_exception chain=ptw-response "
            "stage=ptw level=L2 ae_ptw=1 ae_final=0 authoritative=1 paddr=0x80013000\n"
            f"*** FAILED *** (tohost = {payload})\n"
        )

        result = parse_chipyard_log(text, returncode=0)

        self.assertEqual(result.status, "observed")
        self.assertEqual(result.observed_stage, "ptw")
        self.assertEqual(result.observed_ptw_level, "L2")
        self.assertEqual(result.observed_fault_address, 0x80013000)
        self.assertIsNone(result.observed_probe_vaddr)

    def test_observation_parser_normalizes_numeric_rocket_ptw_level(self):
        payload = encode_observation_payload(
            ObservationKind.TRAP,
            mcause=5,
            mtval=0x80000000,
            mepc=0x40000020,
            phase=ObservationPhase.PROBE,
        )
        text = (
            "PMFUZZ_PROBE dut=rocket-clean probe=rocket_ptw_access_exception chain=ptw-response "
            "stage=ptw level=0 ae_ptw=1 ae_final=0 authoritative=1 paddr=0x80010010\n"
            f"*** FAILED *** (tohost = {payload})\n"
        )

        result = parse_chipyard_log(text, returncode=0)

        self.assertEqual(result.status, "observed")
        self.assertEqual(result.observed_stage, "ptw")
        self.assertEqual(result.observed_ptw_level, "L2")
        self.assertEqual(result.observed_fault_address, 0x80010010)

    def test_observation_parser_prefers_authoritative_rocket_final_stage_over_diagnostic_ptw_markers(self):
        payload = encode_observation_payload(
            ObservationKind.TRAP,
            mcause=5,
            mtval=0x80000000,
            mepc=0x40000020,
            phase=ObservationPhase.PROBE,
        )
        text = (
            "PMFUZZ_PROBE dut=rocket-clean probe=rocket_tlb_exception_arbitration chain=exception-arbitration "
            "stage=tlb vaddr=0x0080000000 ptw_ae=0x1c86 ae_ld=0x1fde ae_st=0x0000 pf_ld=0x011c pf_st=0x0000 pf_inst=0x013c\n"
            "PMFUZZ_PROBE dut=rocket-clean probe=rocket_ptw_access_exception chain=ptw-response "
            "stage=ptw level=0 ae_ptw=0 ae_final=1 authoritative=1 paddr=0x80010010\n"
            f"*** FAILED *** (tohost = {payload})\n"
        )

        result = parse_chipyard_log(text, returncode=0)

        self.assertEqual(result.status, "observed")
        self.assertEqual(result.observed_stage, "final")
        self.assertEqual(result.observed_ptw_level, "L2")
        self.assertEqual(result.observed_fault_address, 0x80010010)

    def test_observation_parser_does_not_treat_boom_tlb_page_base_as_authoritative_fault_address(self):
        payload = encode_observation_payload(
            ObservationKind.TRAP,
            mcause=5,
            mtval=0x80000000,
            mepc=0x40000020,
            phase=ObservationPhase.PROBE,
        )
        text = (
            "PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_response_ae chain=ptw-response "
            "stage=ptw level=L2 ae_ptw=0 ae_final=0 pte_page_base=0x80013000\n"
            "PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_ae_array chain=exception-arbitration "
            "stage=tlb vaddr=0x0080000000 ptw_ae=0x1a pf_ld=0x24 pf_st=0x00 pf_inst=0x24\n"
            f"*** FAILED *** (tohost = {payload})\n"
        )

        result = parse_chipyard_log(text, returncode=0)

        self.assertEqual(result.status, "observed")
        self.assertEqual(result.observed_stage, "ptw")
        self.assertEqual(result.observed_ptw_level, "L2")
        self.assertIsNone(result.observed_fault_address)

    def test_observation_parser_prefers_shared_ptw_address_over_boom_tlb_metadata(self):
        payload = encode_observation_payload(
            ObservationKind.TRAP,
            mcause=5,
            mtval=0x80000000,
            mepc=0x40000020,
            phase=ObservationPhase.PROBE,
        )
        text = (
            "PMFUZZ_PROBE dut=rocket-clean probe=rocket_ptw_access_exception chain=ptw-response "
            "stage=ptw level=L2 ae_ptw=1 ae_final=0 authoritative=1 paddr=0x80010010\n"
            "PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_response_ae chain=ptw-response "
            "stage=ptw level=L2 ae_ptw=0 ae_final=0 pte_page_base=0x80013000\n"
            "PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_ae_array chain=exception-arbitration "
            "stage=tlb vaddr=0x0080000000 ptw_ae=0x1a pf_ld=0x24 pf_st=0x00 pf_inst=0x24\n"
            f"*** FAILED *** (tohost = {payload})\n"
        )

        result = parse_chipyard_log(text, returncode=0)

        self.assertEqual(result.status, "observed")
        self.assertEqual(result.observed_stage, "ptw")
        self.assertEqual(result.observed_ptw_level, "L2")
        self.assertEqual(result.observed_fault_address, 0x80010010)

    def test_observation_parser_ignores_later_nonfault_ptw_response_after_fault(self):
        payload = encode_observation_payload(
            ObservationKind.TRAP,
            mcause=5,
            mtval=0x80000000,
            mepc=0x40000020,
            phase=ObservationPhase.PROBE,
        )
        text = (
            "PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_response_ae chain=ptw-response "
            "stage=ptw level=0 ae_ptw=1 ae_final=0 pte_page_base=0x80010000\n"
            "PMFUZZ_PROBE dut=rocket-clean probe=rocket_ptw_access_exception chain=ptw-response "
            "stage=ptw level=0 ae_ptw=1 ae_final=0 authoritative=1 paddr=0x80010010\n"
            "PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker chain=pmp-check "
            "stage=ptw addr=0x00000000 access=load allow=0 size=0 r=0 w=0 x=0\n"
            "PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_response_ae chain=ptw-response "
            "stage=ptw level=0 ae_ptw=0 ae_final=0 pte_page_base=0x00000000\n"
            "PMFUZZ_PROBE dut=rocket-clean probe=rocket_ptw_access_exception chain=ptw-response "
            "stage=ptw level=0 ae_ptw=0 ae_final=0 authoritative=1 paddr=0x00000000\n"
            f"*** FAILED *** (tohost = {payload})\n"
        )

        result = parse_chipyard_log(text, returncode=0)

        self.assertEqual(result.status, "observed")
        self.assertEqual(result.observed_stage, "ptw")
        self.assertEqual(result.observed_ptw_level, "L2")
        self.assertEqual(result.observed_fault_address, 0x80010010)

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

        self.assertIn(f"VERILATOR={DEFAULT_ROCKET_VERILATOR.as_posix()}", command)
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

    def test_clean_chipyard_dut_uses_explicit_simulator_binary_directly(self):
        for dut_name, config, binary in (
            ("rocket-clean", "RocketConfig", "/tmp/rocket-sim"),
            ("boom-clean", "SmallBoomV3Config", "/tmp/boom-sim"),
        ):
            with self.subTest(dut=dut_name):
                dut = make_dut(
                    dut=dut_name,
                    spike="spike",
                    isa="rv64gc",
                    chipyard_dir=Path("/clean-chipyard"),
                    dut_bin=Path(binary),
                )

                command = dut.command_for(Path("/tmp/case.elf"))

                self.assertIsInstance(dut, ChipyardDirectDut)
                self.assertEqual(dut.config, config)
                self.assertEqual(command[0], binary)
                self.assertIn("+loadmem=/tmp/case.elf", command)

    def test_clean_chipyard_make_duts_enable_verbose_logs_for_whitebox_artifacts(self):
        for dut_name, config in (("rocket-clean", "RocketConfig"), ("boom-clean", "SmallBoomV3Config")):
            with self.subTest(dut=dut_name):
                dut = make_dut(
                    dut=dut_name,
                    spike="spike",
                    isa="rv64gc",
                    chipyard_dir=Path("/clean-chipyard"),
                    whitebox_artifacts=True,
                )

                command = dut.command_for(Path("/tmp/case.elf"))

                self.assertIsInstance(dut, ChipyardMakeDut)
                self.assertEqual(dut.config, config)
                self.assertIn("EXTRA_SIM_FLAGS=+verbose", command)

    def test_clean_chipyard_make_duts_keep_verbose_logs_off_by_default(self):
        dut = make_dut(
            dut="rocket-clean",
            spike="spike",
            isa="rv64gc",
            chipyard_dir=Path("/clean-chipyard"),
        )

        self.assertNotIn("EXTRA_SIM_FLAGS=+verbose", dut.command_for(Path("/tmp/case.elf")))

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

        self.assertIsInstance(dut, ChipyardDirectDut)
        self.assertEqual(dut.config, "CVA6Config")
        self.assertEqual(command[0], "/clean-chipyard/sims/verilator/simulator-chipyard.harness-CVA6Config")
        self.assertIn("+dramsim", command)
        self.assertIn("+loadmem=/tmp/case.elf", command)
        self.assertNotIn("verilator_cva6_wrapper.sh", " ".join(command))

    def test_cva6_direct_dut_enables_verbose_logs_for_whitebox_artifacts(self):
        dut = make_dut(
            dut="cva6-clean",
            spike="spike",
            isa="rv64gc",
            chipyard_dir=Path("/clean-chipyard"),
            dut_bin=Path("/tmp/cva6-sim"),
            whitebox_artifacts=True,
        )

        command = dut.command_for(Path("/tmp/case.elf"))

        self.assertIsInstance(dut, ChipyardDirectDut)
        self.assertIn("+verbose", command)
        self.assertLess(command.index("+permissive"), command.index("+verbose"))
        self.assertLess(command.index("+verbose"), command.index("+permissive-off"))

    def test_cva6_direct_dut_keeps_verbose_logs_off_by_default(self):
        dut = make_dut(
            dut="cva6-clean",
            spike="spike",
            isa="rv64gc",
            chipyard_dir=Path("/clean-chipyard"),
            dut_bin=Path("/tmp/cva6-sim"),
        )

        self.assertNotIn("+verbose", dut.command_for(Path("/tmp/case.elf")))

    def test_cva6_clean_alias_uses_direct_simulator_binary_when_provided(self):
        dut = make_dut(
            dut="cva6-clean",
            spike="spike",
            isa="rv64gc",
            chipyard_dir=Path("/clean-chipyard"),
            dut_bin=Path("/tmp/cva6-sim"),
        )

        command = dut.command_for(Path("/tmp/case.elf"))

        self.assertIsInstance(dut, ChipyardDirectDut)
        self.assertEqual(dut.name, "cva6-clean")
        self.assertEqual(dut.config, "CVA6Config")
        self.assertEqual(command[0], "/tmp/cva6-sim")

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

    def test_xiangshan_run_exports_structured_diag_env_when_available(self):
        dut = XiangShanDut(
            binary=Path("/xs/build/verilator-compile/emu"),
            simlen=100,
        )
        captured: dict[str, object] = {}

        def fake_run(command, *, timeout_seconds, log_path, cwd=None, env=None):
            captured["command"] = command
            captured["env"] = env
            log_path.write_text("PMFUZZ_DIAG tohost=0x1\n", encoding="utf-8")
            return False, 0, "PMFUZZ_DIAG tohost=0x1\n"

        with TemporaryDirectory() as tmp:
            elf = Path(tmp) / "case.elf"
            elf.write_bytes(b"\x7fELFplaceholder")
            log_path = Path(tmp) / "case.log"
            with patch(
                "pmpfuzz.dut.xiangshan_diag_env_for_image",
                return_value={
                    "PMFUZZ_TOHOST_ADDR": "0x80002080",
                    "PMFUZZ_RESULT_SLOT_ADDR": "0x80002060",
                },
            ):
                with patch("pmpfuzz.dut._run_command_to_log", side_effect=fake_run):
                    with patch(
                        "pmpfuzz.dut.parse_xiangshan_log",
                        return_value=ParsedDutLog("observed", observed_tohost=1, reason="diag"),
                    ):
                        result = dut.run(elf, timeout_seconds=3, log_path=log_path)

        self.assertEqual(result.status, "observed")
        self.assertEqual(captured["env"]["PMFUZZ_TOHOST_ADDR"], "0x80002080")
        self.assertEqual(captured["env"]["PMFUZZ_RESULT_SLOT_ADDR"], "0x80002060")

    def test_default_xiangshan_emu_points_to_vanilla_tree(self):
        self.assertIn("xiangshan/build/verilator-compile/emu", DEFAULT_XIANGSHAN_EMU.as_posix())
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

    def test_xiangshan_log_parser_preserves_observation_tags_for_bapc_disambiguation(self):
        payload = encode_observation_payload(
            ObservationKind.TRAP,
            mcause=7,
            mtval=0x80008100,
            mepc=0x80002010,
            phase=ObservationPhase.PROBE,
        )
        result = parse_xiangshan_log(
            f"PMFUZZ_DIAG tohost=0x{payload:x} mcause=0x7 mtval=0x80008100\n"
            "HIT BAD TRAP at pc = 0x80002010\n",
            returncode=0,
        )

        self.assertEqual(result.status, "observed")
        self.assertIsNotNone(result.observation)
        self.assertEqual(result.observation.mcause, 7)
        self.assertEqual(result.observation.mepc_tag, 2)
        self.assertEqual(result.observation.mtval_fingerprint, mtval_fingerprint(0x80008100))

    def test_cascade_rocket_command_uses_simlen_and_binary_env(self):
        dut = CascadeRocketDut(binary=Path("/rocket/Vtop_tiny_soc"), simlen=5000)

        command, env = dut.command_and_env(Path("/tmp/case.elf"))

        self.assertEqual(command, ["/rocket/Vtop_tiny_soc"])
        self.assertEqual(env["SIMLEN"], "5000")
        self.assertEqual(env["SIMSRAMELF"], "/tmp/case.elf")
        self.assertEqual(env["SIMROMELF"], "/tmp/case.elf")


if __name__ == "__main__":
    unittest.main()
