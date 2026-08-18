import subprocess
import tempfile
import unittest
from pathlib import Path

from pmpfuzz.__main__ import build_parser, main
from pmpfuzz.source_probe import (
    default_source_probe_specs,
    discover_source_probes,
    write_source_probe_instrumentation,
    _boom_target_operation_runtime,
    _cva6_target_operation_issue,
    _cva6_target_operation_runtime,
    write_source_probe_manifest,
)


class SourceProbeTest(unittest.TestCase):
    def test_default_specs_cover_xiangshan_boom_and_rocket_security_chain(self):
        specs = default_source_probe_specs()
        by_dut = {}
        probe_ids = set()
        for spec in specs:
            by_dut.setdefault(spec.dut, set()).add(spec.security_chain)
            probe_ids.add(spec.probe_id)

        self.assertIn("xiangshan-clean", by_dut)
        self.assertIn("boom-clean", by_dut)
        self.assertIn("rocket-clean", by_dut)
        self.assertIn("cva6-clean", by_dut)
        self.assertIn("pmp-check", by_dut["xiangshan-clean"])
        self.assertIn("ptw-request", by_dut["boom-clean"])
        self.assertIn("exception-arbitration", by_dut["rocket-clean"])
        self.assertIn("pmp-csr", by_dut["cva6-clean"])
        self.assertIn("target-operation-runtime", by_dut["boom-clean"])
        self.assertIn("target-operation-runtime", by_dut["cva6-clean"])
        self.assertIn("boom_target_operation_runtime", probe_ids)
        self.assertIn("cva6_target_operation_issue", probe_ids)
        self.assertIn("cva6_target_operation_runtime", probe_ids)
        self.assertTrue(all("PMFUZZ_PROBE" in spec.instrumentation_hint for spec in specs))

    def test_discovers_cascade_runtime_probe_sites_in_fake_dut_trees(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chipyard = root / "chipyard"
            _write(
                chipyard / "generators/boom/src/main/scala/v3/lsu/lsu.scala",
                "class BoomLSU {\n"
                "  if (MEMTRACE_PRINTF) {\n"
                "    when (commit_store || commit_load) {\n"
                "      printf(\"MT %x %x %x %x %x %x %x\\n\", 0.U, 0.U, 0.U, 0.U, 0.U, 0.U, 0.U)\n"
                "    }\n"
                "  }\n"
                "  val mem_xcpt_vaddrs = RegNext(exe_tlb_vaddr)\n"
                "  for (w <- 0 until memWidth) {\n"
                "    assert(mem_xcpt_uops(w).uses_ldq ^ mem_xcpt_uops(w).uses_stq)\n"
                "  }\n"
                "}\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ariane.sv",
                "module ariane;\n"
                "  logic [63:0] pc_id_ex;\n"
                "  logic [3:0] load_trans_id_ex_id;\n"
                "  logic load_valid_ex_id;\n"
                "  logic [3:0] store_trans_id_ex_id;\n"
                "  logic store_valid_ex_id;\n"
                "  perf_counters i_perf_counters ();\n"
                "  controller controller_i ();\n"
                "endmodule\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/load_store_unit.sv",
                "module load_store_unit;\n"
                "  output logic load_valid_o;\n"
                "  output logic [3:0] load_trans_id_o;\n"
                "  output exception_t load_exception_o;\n"
                "  output logic store_valid_o;\n"
                "  output logic [3:0] store_trans_id_o;\n"
                "  output exception_t store_exception_o;\n"
                "  logic [63:0] mmu_paddr;\n"
                "  exception_t mmu_exception;\n"
                "  always_comb begin : which_op\n"
                "  end\n"
                "endmodule\n",
            )

            manifest = discover_source_probes(
                ["boom-clean", "cva6-clean"],
                roots={"boom-clean": chipyard, "cva6-clean": chipyard},
            )

        found = {probe["probe_id"] for probe in manifest["probes"] if probe["status"] == "source_found"}
        self.assertIn("boom_target_operation_runtime", found)
        self.assertIn("cva6_target_operation_issue", found)
        self.assertIn("cva6_target_operation_runtime", found)

    def test_write_source_probe_instrumentation_emits_cascade_runtime_contract_patches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chipyard = root / "chipyard"
            _write(
                chipyard / "generators/boom/src/main/scala/v3/lsu/lsu.scala",
                "class BoomLSU {\n"
                "  if (MEMTRACE_PRINTF) {\n"
                "    when (commit_store || commit_load) {\n"
                "      val uop    = Mux(commit_store, stq(idx).bits.uop, ldq(idx).bits.uop)\n"
                "      val addr   = Mux(commit_store, stq(idx).bits.addr.bits, ldq(idx).bits.addr.bits)\n"
                "      val stdata = Mux(commit_store, stq(idx).bits.data.bits, 0.U)\n"
                "      val wbdata = Mux(commit_store, stq(idx).bits.debug_wb_data, ldq(idx).bits.debug_wb_data)\n"
                "      printf(\"MT %x %x %x %x %x %x %x\\n\",\n"
                "        io.core.tsc_reg, uop.uopc, uop.mem_cmd, uop.mem_size, addr, stdata, wbdata)\n"
                "    }\n"
                "  }\n"
                "  val mem_xcpt_vaddrs = RegNext(exe_tlb_vaddr)\n"
                "  val exe_tlb_miss  = widthMap(w => dtlb.io.req(w).valid)\n"
                "  val exe_tlb_paddr = widthMap(w => Cat(dtlb.io.resp(w).paddr(paddrBits-1,corePgIdxBits),\n"
                "                                        exe_tlb_vaddr(w)(corePgIdxBits-1,0)))\n"
                "  val exe_tlb_uncacheable = widthMap(w => !(dtlb.io.resp(w).cacheable))\n"
                "  val mem_xcpt_valids = Wire(Vec(memWidth, Bool()))\n"
                "  val mem_xcpt_uops = Wire(Vec(memWidth, new MicroOp))\n"
                "  val mem_xcpt_causes = Wire(Vec(memWidth, UInt(xLen.W)))\n"
                "  for (w <- 0 until memWidth) {\n"
                "    when (mem_xcpt_valids(w)) {\n"
                "      assert(mem_xcpt_uops(w).uses_ldq ^ mem_xcpt_uops(w).uses_stq)\n"
                "    }\n"
                "  }\n"
                "}\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ariane.sv",
                "module ariane;\n"
                "  logic [63:0] pc_id_ex;\n"
                "  logic [3:0] load_trans_id_ex_id;\n"
                "  logic load_valid_ex_id;\n"
                "  logic [3:0] store_trans_id_ex_id;\n"
                "  logic store_valid_ex_id;\n"
                "  perf_counters i_perf_counters ();\n"
                "  controller controller_i ();\n"
                "endmodule\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/load_store_unit.sv",
                "module load_store_unit;\n"
                "  output logic load_valid_o;\n"
                "  output logic [3:0] load_trans_id_o;\n"
                "  output exception_t load_exception_o;\n"
                "  output logic store_valid_o;\n"
                "  output logic [3:0] store_trans_id_o;\n"
                "  output exception_t store_exception_o;\n"
                "  logic [63:0] mmu_paddr;\n"
                "  exception_t mmu_exception;\n"
                "  always_comb begin : which_op\n"
                "  end\n"
                "endmodule\n",
            )

            payload = write_source_probe_instrumentation(
                ["boom-clean", "cva6-clean"],
                roots={"boom-clean": chipyard, "cva6-clean": chipyard},
                out_dir=root / "out",
            )
            text = (root / "out" / "source_probe_instrumentation.json").read_text(encoding="ascii")

        probe_ids = {probe["probe_id"] for probe in payload["probes"] if probe["status"] in {"instrumented", "already_instrumented"}}
        self.assertIn("boom_target_operation_runtime", probe_ids)
        self.assertIn("cva6_target_operation_issue", probe_ids)
        self.assertIn("cva6_target_operation_runtime", probe_ids)
        self.assertIn("cascade-target-operation-v1", text)
        self.assertIn("boom_target_operation_runtime", text)
        self.assertIn("cva6_target_operation_issue", text)

    def test_boom_runtime_patch_emits_issue_phase_and_queue_indices(self):
        text = (
            "class BoomLSU\n"
            "  for (w <- 0 until coreWidth) {\n"
            "    when (dis_uops(w).valid && dis_uops(w).bits.uses_ldq) {\n"
            "      val ldq_idx = dis_uops(w).bits.ldq_idx\n"
            "    }\n"
            "    when (dis_uops(w).valid && dis_uops(w).bits.uses_stq) {\n"
            "      val stq_idx = dis_uops(w).bits.stq_idx\n"
            "    }\n"
            "  }\n"
            "  if (MEMTRACE_PRINTF) {\n"
            "    when (commit_store || commit_load) {\n"
            "      val uop    = Mux(commit_store, stq(idx).bits.uop, ldq(idx).bits.uop)\n"
            "      val addr   = Mux(commit_store, stq(idx).bits.addr.bits, ldq(idx).bits.addr.bits)\n"
            "      val stdata = Mux(commit_store, stq(idx).bits.data.bits, 0.U)\n"
            "      val wbdata = Mux(commit_store, stq(idx).bits.debug_wb_data, ldq(idx).bits.debug_wb_data)\n"
            '      printf("MT %x %x %x %x %x %x %x\n",\n'
            "        io.core.tsc_reg, uop.uopc, uop.mem_cmd, uop.mem_size, addr, stdata, wbdata)\n"
            "    }\n"
            "  }\n"
            "  val exe_tlb_uncacheable = widthMap(w => !(dtlb.io.resp(w).cacheable))\n"
            "  for (w <- 0 until memWidth) {\n"
            "    assert(mem_xcpt_uops(w).uses_ldq ^ mem_xcpt_uops(w).uses_stq)\n"
            "  }\n"
            "}\n"
        )

        updated, anchor = _boom_target_operation_runtime(text)

        self.assertIsNotNone(updated)
        self.assertIn("phase=issue pc=0x%x access=load ldq_idx=%d", updated)
        self.assertIn("phase=issue pc=0x%x access=store stq_idx=%d", updated)
        self.assertIn("status=completed pc=0x%x addr=0x%x access=load size=%d ldq_idx=%d", updated)
        self.assertIn("status=completed pc=0x%x addr=0x%x access=store size=%d stq_idx=%d", updated)
        self.assertIn("val pmpfuzz_runtime_uop =", updated)
        self.assertLess(updated.index("val pmpfuzz_runtime_uop ="), updated.index("if (MEMTRACE_PRINTF) {"))
        self.assertIn("status=trap pc=0x%x addr=0x%x access=load size=%d ldq_idx=%d mcause=%d mtval=0x%x", updated)
        self.assertIn("status=trap pc=0x%x addr=0x%x access=store size=%d stq_idx=%d mcause=%d mtval=0x%x", updated)

    def test_discovers_source_probe_sites_in_fake_dut_trees(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xiangshan = root / "xiangshan"
            chipyard = root / "chipyard"
            _write(
                xiangshan / "src/main/scala/xiangshan/backend/fu/PMP.scala",
                "class PMP { val pmp_hit = true }\n",
            )
            _write(
                xiangshan / "src/main/scala/xiangshan/cache/mmu/L2TLB.scala",
                "class L2TLB { val ptw_req_count = 0 }\n",
            )
            _write(
                chipyard / "generators/boom/src/main/scala/v3/lsu/tlb.scala",
                "val pmp = Module(new PMPChecker(lgMaxSize))\n"
                "newEntry.ae := io.ptw.resp.bits.ae_final\n"
                "val ptw_ae_array = Wire(Vec(nWays, Bool()))\n",
            )
            _write(
                chipyard / "generators/rocket-chip/src/main/scala/rocket/PMP.scala",
                "class PMPChecker(lgMaxSize: Int) extends Module\n",
            )
            _write(
                chipyard / "generators/rocket-chip/src/main/scala/rocket/PTW.scala",
                "class PTW { val ae_ptw = true; val ae_final = false }\n",
            )
            _write(
                chipyard / "generators/rocket-chip/src/main/scala/rocket/TLB.scala",
                "val ptw_ae_array = Reg(Vec(nWays, Bool()))\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/csr_regfile.sv",
                "module csr_regfile(input logic clk_i, input logic rst_ni);\n"
                "  logic [1:0] pmpcfg_q;\n"
                "  logic [1:0] pmpaddr_q;\n"
                "  assign pmpcfg_o = pmpcfg_q;\n"
                "  assign pmpaddr_o = pmpaddr_q;\n"
                "endmodule\n",
            )

            manifest = discover_source_probes(
                ["xiangshan-clean", "boom-clean", "rocket-clean", "cva6-clean"],
                roots={
                    "xiangshan-clean": xiangshan,
                    "boom-clean": chipyard,
                    "rocket-clean": chipyard,
                    "cva6-clean": chipyard,
                },
            )

        found = [probe for probe in manifest["probes"] if probe["status"] == "source_found"]
        self.assertGreaterEqual(len(found), 6)
        self.assertTrue(any(probe["probe_id"] == "boom_ptw_response_ae" for probe in found))
        self.assertTrue(any(probe["probe_id"] == "rocket_ptw_access_exception" for probe in found))
        self.assertTrue(any(probe["probe_id"] == "cva6_pmp_csr_state" for probe in found))
        self.assertEqual(
            next(probe for probe in found if probe["probe_id"] == "cva6_pmp_csr_state")["relative_path"],
            "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/csr_regfile.sv",
        )
        self.assertTrue(all(probe["line"] >= 1 for probe in found))
        self.assertTrue(all(probe["matched_text"] for probe in found))
        self.assertTrue(all("PMFUZZ_PROBE" in probe["instrumentation_hint"] for probe in found))

    def test_write_source_probe_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xiangshan = root / "xiangshan"
            _write(
                xiangshan / "src/main/scala/xiangshan/backend/fu/PMP.scala",
                "class PMP { val pmp_hit = true }\n",
            )

            out = write_source_probe_manifest(["xiangshan-clean"], roots={"xiangshan-clean": xiangshan}, out_dir=root / "out")

            text = out.read_text(encoding="ascii")

        self.assertEqual(out.name, "source_probe_manifest.json")
        self.assertIn("xiangshan_pmp_checker", text)

    def test_cli_accepts_probe_source_command(self):
        parser = build_parser()

        args = parser.parse_args(["probe-source", "--dut", "xiangshan-clean,boom-clean,rocket-clean,cva6-clean", "--out", "out"])

        self.assertEqual(args.command, "probe-source")
        self.assertEqual(args.dut, "xiangshan-clean,boom-clean,rocket-clean,cva6-clean")
        self.assertEqual(args.out, Path("out"))

    def test_cva6_probe_discovery_prefers_original_source_over_preprocessed_blob(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chipyard = root / "chipyard"
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/CVA6CoreBlackbox.preprocessed.sv",
                "assign exception_o = access_exception;\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/csr_regfile.sv",
                "module csr_regfile(input logic clk_i, input logic rst_ni);\n"
                "  logic [1:0] pmpcfg_q;\n"
                "  logic [1:0] pmpaddr_q;\n"
                "  assign pmpcfg_o = pmpcfg_q;\n"
                "  assign pmpaddr_o = pmpaddr_q;\n"
                "endmodule\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ptw.sv",
                "module ptw;\n"
                "  logic allow_access;\n"
                "  logic ptw_access_exception_o;\n"
                "  logic data_rvalid_q;\n"
                "  logic [63:0] ptw_pptr_q;\n"
                "  always_comb begin\n"
                "    if (data_rvalid_q) begin\n"
                "      if (!allow_access) begin\n"
                "      end\n"
                "    end\n"
                "  end\n"
                "endmodule\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/tlb.sv",
                "module tlb; input logic flush_i; endmodule\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/mmu.sv",
                "module mmu;\n"
                "  logic pmp_instr_allow;\n"
                "  logic pmp_data_allow;\n"
                "  pmp i_pmp_if();\n"
                "  pmp i_pmp_data();\n"
                "endmodule\n",
            )

            manifest = discover_source_probes(["cva6-clean"], roots={"cva6-clean": chipyard})

        by_probe = {probe["probe_id"]: probe for probe in manifest["probes"]}
        self.assertEqual(
            by_probe["cva6_pmp_csr_state"]["relative_path"],
            "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/csr_regfile.sv",
        )
        self.assertEqual(
            by_probe["cva6_ptw_exception"]["relative_path"],
            "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ptw.sv",
        )
        self.assertEqual(
            by_probe["cva6_ptw_pmp_check"]["relative_path"],
            "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ptw.sv",
        )
        self.assertEqual(
            by_probe["cva6_tlb_exception_arbitration"]["relative_path"],
            "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/tlb.sv",
        )
        self.assertEqual(
            by_probe["cva6_mmu_pmp_check"]["relative_path"],
            "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/mmu.sv",
        )

    def test_write_source_probe_instrumentation_emits_applyable_patches_without_mutating_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chipyard = root / "chipyard"
            _write(
                chipyard / "generators/rocket-chip/src/main/scala/rocket/PMP.scala",
                "class PMPChecker(lgMaxSize: Int)(implicit val p: Parameters) extends Module {\n"
                "  val io = IO(new Bundle {\n"
                "    val r = Output(Bool())\n"
                "    val w = Output(Bool())\n"
                "    val x = Output(Bool())\n"
                "  })\n"
                "  io.r := res.cfg.r\n"
                "  io.w := res.cfg.w\n"
                "  io.x := res.cfg.x\n"
                "}\n",
            )
            _write(
                chipyard / "generators/rocket-chip/src/main/scala/rocket/TLB.scala",
                "class TLB {\n"
                "  val pmp = Module(new PMPChecker(lgMaxSize))\n"
                "  pmp.io.prv := mpu_priv\n"
                "  val do_refill = false.B\n"
                "  val instruction = false\n"
                "  val ptw_ae_array = Cat(false.B, entries.map(_.ae_ptw).asUInt)\n"
                "  val ae_ld_array = Mux(cmd_read, ae_array, 0.U)\n"
                "  val ae_st_array = Mux(cmd_write, ae_array, 0.U)\n"
                "  val pf_ld_array = Mux(cmd_read, ptw_pf_array, 0.U)\n"
                "  val pf_st_array = Mux(cmd_write, ptw_pf_array, 0.U)\n"
                "  val pf_inst_array = ptw_pf_array\n"
                "  val cmd_read = isRead(io.req.bits.cmd)\n"
                "  val cmd_write = isWrite(io.req.bits.cmd)\n"
                "  val tlb_miss = vm_enabled && !tlb_hit\n"
                "}\n",
            )
            _write(
                chipyard / "generators/rocket-chip/src/main/scala/rocket/PTW.scala",
                "class PTW {\n"
                "  val pte_addr = 0.U\n"
                "  io.requestor(i).resp.bits.ae_final := resp_ae_final\n"
                "}\n",
            )
            _write(
                chipyard / "generators/boom/src/main/scala/v3/lsu/tlb.scala",
                "class BoomTLB {\n"
                "  val pmp = Seq.fill(memWidth) { Module(new PMPChecker(lgMaxSize)) }\n"
                "  val prot_x   = widthMap(w => fastCheck(_.executable, w) && pmp(w).io.x)\n"
                "  when (do_refill) {\n"
                "    newEntry.ae := io.ptw.resp.bits.ae_final\n"
                "  }\n"
                "  val ptw_ae_array = widthMap(w => Cat(false.B, entries(w).map(_.ae).asUInt))\n"
                "  val pf_ld_array = widthMap(w => Mux(cmd_read(w), ~(r_array(w) | ptw_ae_array(w)), 0.U))\n"
                "  val pf_st_array = widthMap(w => Mux(cmd_write_perms(w), ~(w_array(w) | ptw_ae_array(w)), 0.U))\n"
                "  val pf_inst_array = widthMap(w => ~(x_array(w) | ptw_ae_array(w)))\n"
                "  io.ptw.req.bits.bits.addr := r_refill_tag\n"
                "}\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/csr_regfile.sv",
                "module csr_regfile(input logic clk_i, input logic rst_ni);\n"
                "  logic [1:0] pmpcfg_q;\n"
                "  logic [1:0] pmpaddr_q;\n"
                "  assign pmpcfg_o = pmpcfg_q;\n"
                "  assign pmpaddr_o = pmpaddr_q;\n"
                "endmodule\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ptw.sv",
                "module ptw(input logic clk_i, input logic rst_ni);\n"
                "  logic allow_access; logic ptw_access_exception_o; logic data_rvalid_q; logic [63:0] ptw_pptr_q;\n"
                "  assign bad_paddr_o = ptw_access_exception_o ? ptw_pptr_q : 'b0;\n"
                "  always_comb begin\n"
                "    if (data_rvalid_q) begin\n"
                "    end\n"
                "  end\n"
                "endmodule\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/tlb.sv",
                "module tlb(input logic clk_i, input logic rst_ni, input logic flush_i, input logic lu_access_i);\n"
                "  logic lu_hit_o; logic [63:0] lu_vaddr_i; logic update_valid;\n"
                "endmodule\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/mmu.sv",
                "module mmu(input logic clk_i, input logic rst_ni, input logic enable_translation_i, input logic en_ld_st_translation_i);\n"
                "  logic match_any_execute_region; logic pmp_instr_allow; logic iaccess_err; logic itlb_lu_hit;\n"
                "  logic [63:0] icache_areq_o_fetch_paddr; logic icache_areq_i_fetch_req;\n"
                "  logic misaligned_ex_q_valid; logic lsu_req_q; logic [63:0] lsu_paddr_o; logic [1:0] priv_lvl_i; logic [1:0] ld_st_priv_lvl_i;\n"
                "  logic lsu_is_store_q; logic pmp_data_allow; logic daccess_err; logic dtlb_hit_q;\n"
                "  typedef struct packed { logic w; logic d; } pte_t;\n"
                "  pte_t dtlb_pte_q;\n"
                "  pmp #() i_pmp_if (\n"
                "    .allow_o(pmp_instr_allow)\n"
                "  );\n"
                "  pmp #() i_pmp_data (\n"
                "    .allow_o(pmp_data_allow)\n"
                "  );\n"
                "endmodule\n",
            )
            original = (
                chipyard / "generators/boom/src/main/scala/v3/lsu/tlb.scala"
            ).read_text(encoding="ascii")

            out = write_source_probe_instrumentation(
                ["rocket-clean", "boom-clean", "cva6-clean"],
                roots={"rocket-clean": chipyard, "boom-clean": chipyard, "cva6-clean": chipyard},
                out_dir=root / "out",
            )
            patch_text = "\n".join(path.read_text(encoding="ascii") for path in (root / "out" / "patches").glob("*.patch"))
            instrumented = [probe for probe in out["probes"] if probe["status"] == "instrumented"]
            instrumentation_json = root / "out" / "source_probe_instrumentation.json"
            current = (
                chipyard / "generators/boom/src/main/scala/v3/lsu/tlb.scala"
            ).read_text(encoding="ascii")

            self.assertGreaterEqual(len(instrumented), 5)
            self.assertIn("PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker", patch_text)
            self.assertIn("schema=2", patch_text)
            self.assertIn("val valid = Input(Bool())", patch_text)
            self.assertIn("when (io.valid)", patch_text)
            self.assertIn("probe=rocket_ptw_access_exception schema=3", patch_text)
            self.assertIn("authoritative=1", patch_text)
            self.assertIn("pte_addr", patch_text)
            self.assertIn("pmp.io.access := pmp_access", patch_text)
            self.assertIn("pmp.io.valid := do_refill || io.req.fire", patch_text)
            self.assertIn("stage=ptw", patch_text)
            self.assertIn("PMFUZZ_PROBE dut=boom-clean probe=boom_lsu_tlb_pmp_check schema=2 role=diagnostic", patch_text)
            self.assertIn("PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_ae_array schema=2 role=diagnostic", patch_text)
            self.assertIn("probe=boom_ptw_response_ae schema=3 role=diagnostic evidence=non_authoritative", patch_text)
            self.assertIn("pte_page_base=0x%x", patch_text)
            self.assertIn("probe=boom_ptw_request schema=3 role=diagnostic evidence=non_authoritative", patch_text)
            self.assertIn("refill_tag=0x%x", patch_text)
            self.assertIn("pmp(w).io.access :=", patch_text)
            self.assertIn("pmp(w).io.ptw :=", patch_text)
            self.assertIn("pmp(w).io.valid := do_refill || io.req(w).fire", patch_text)
            self.assertIn("when (io.ptw.req.fire)", patch_text)
            self.assertNotIn("io.req(w).valid || do_refill", patch_text)
            self.assertIn("PMFUZZ_PROBE dut=cva6-clean probe=cva6_ptw_exception", patch_text)
            self.assertIn("PMFUZZ_PROBE dut=cva6-clean probe=cva6_ptw_pmp_check", patch_text)
            self.assertIn("PMFUZZ_PROBE dut=cva6-clean probe=cva6_mmu_pmp_check", patch_text)
            self.assertIn("probe=cva6_pmp_csr_state chain=pmp-csr stage=csr entry=%0d cfg=0x%0h", patch_text)
            self.assertIn("pmpcfg_probe_entry_i", patch_text)
            self.assertIn("pmpcfg_probe_seen_q", patch_text)
            self.assertIn("pmpcfg_probe_prev_q", patch_text)
            self.assertIn("pmpaddr_probe_prev_q", patch_text)
            self.assertIn("if (!rst_ni)", patch_text)
            self.assertIn("!== pmpcfg_q[pmpcfg_probe_entry_i]", patch_text)
            self.assertIn("!== pmpaddr_q[pmpcfg_probe_entry_i]", patch_text)
            self.assertIn("+++ b/generators/cva6/src/main/resources/cva6/vsrc/cva6/src/csr_regfile.sv", patch_text)
            self.assertIn("+++ b/generators/cva6/src/main/resources/cva6/vsrc/cva6/src/mmu.sv", patch_text)
            self.assertNotIn("+++ b/generators/cva6/src/main/resources/cva6/vsrc/CVA6CoreBlackbox.preprocessed.sv", patch_text)
            self.assertIn("schema=2 role=diagnostic chain=ptw-response stage=ptw level=%0d vaddr=0x%0h paddr=0x%0h", patch_text)
            self.assertIn("schema=2 role=diagnostic chain=pmp-check stage=ptw addr=0x%0h prv=%0d access=load allow=%0d size=%0d", patch_text)
            self.assertIn("schema=2 role=diagnostic chain=pmp-check stage=final addr=0x%0h prv=%0d access=fetch allow=%0d", patch_text)
            self.assertIn("mmu_fetch_probe_seen_q", patch_text)
            self.assertIn("mmu_data_probe_seen_q", patch_text)
            self.assertNotIn("pmp(w).io.prv", patch_text)
            self.assertTrue(instrumentation_json.exists())
            self.assertEqual(current, original)

    def test_write_source_probe_instrumentation_applies_boom_runtime_probe_before_memtrace_printf(self):
        text = (
            "class BoomLSU {\n"
            "  val mem_xcpt_valids = RegNext(widthMap(w => true.B))\n"
            "  val mem_xcpt_uops   = RegNext(widthMap(w => UpdateBrMask(io.core.brupdate, exe_tlb_uop(w))))\n"
            "  val mem_xcpt_causes = RegNext(widthMap(w => rocket.Causes.load_access.U))\n"
            "  val mem_xcpt_vaddrs = RegNext(exe_tlb_vaddr)\n"
            "  val exe_tlb_miss  = widthMap(w => dtlb.io.req(w).valid)\n"
            "  val exe_tlb_paddr = widthMap(w => Cat(dtlb.io.resp(w).paddr(paddrBits-1,corePgIdxBits),\n"
            "                                        exe_tlb_vaddr(w)(corePgIdxBits-1,0)))\n"
            "  val exe_tlb_uncacheable = widthMap(w => !(dtlb.io.resp(w).cacheable))\n"
            "  for (w <- 0 until memWidth) {\n"
            "    when (mem_xcpt_valids(w)) {\n"
            "      assert(mem_xcpt_uops(w).uses_ldq ^ mem_xcpt_uops(w).uses_stq)\n"
            "    }\n"
            "  }\n"
            "  if (MEMTRACE_PRINTF) {\n"
            "    when (commit_store || commit_load) {\n"
            "      val uop    = Mux(commit_store, stq(idx).bits.uop, ldq(idx).bits.uop)\n"
            "      val addr   = Mux(commit_store, stq(idx).bits.addr.bits, ldq(idx).bits.addr.bits)\n"
            "      val stdata = Mux(commit_store, stq(idx).bits.data.bits, 0.U)\n"
            "      val wbdata = Mux(commit_store, stq(idx).bits.debug_wb_data, ldq(idx).bits.debug_wb_data)\n"
            "      printf(\"MT %x %x %x %x %x %x %x\\n\",\n"
            "        io.core.tsc_reg, uop.uopc, uop.mem_cmd, uop.mem_size, addr, stdata, wbdata)\n"
            "    }\n"
            "  }\n"
            "}\n"
        )
        instrumented, anchor = _boom_target_operation_runtime(text)

        self.assertIsNotNone(instrumented)
        self.assertEqual(anchor, 'assert(mem_xcpt_uops(w).uses_ldq ^ mem_xcpt_uops(w).uses_stq)')
        runtime_idx = instrumented.index("probe=boom_target_operation_runtime")
        memtrace_idx = instrumented.index('printf("MT %x %x %x %x %x %x %x\\n",')
        self.assertLess(runtime_idx, memtrace_idx)

    def test_boom_runtime_probe_registers_trap_paddr_after_exe_tlb_paddr_definition(self):
        text = (
            "class BoomLSU {\n"
            "  val mem_xcpt_valids = RegNext(widthMap(w => true.B))\n"
            "  val mem_xcpt_uops   = RegNext(widthMap(w => UpdateBrMask(io.core.brupdate, exe_tlb_uop(w))))\n"
            "  val mem_xcpt_causes = RegNext(widthMap(w => rocket.Causes.load_access.U))\n"
            "  val mem_xcpt_vaddrs = RegNext(exe_tlb_vaddr)\n"
            "  val exe_tlb_miss  = widthMap(w => dtlb.io.req(w).valid)\n"
            "  val exe_tlb_paddr = widthMap(w => Cat(dtlb.io.resp(w).paddr(paddrBits-1,corePgIdxBits),\n"
            "                                        exe_tlb_vaddr(w)(corePgIdxBits-1,0)))\n"
            "  val exe_tlb_uncacheable = widthMap(w => !(dtlb.io.resp(w).cacheable))\n"
            "  for (w <- 0 until memWidth) {\n"
            "    when (mem_xcpt_valids(w)) {\n"
            "      assert(mem_xcpt_uops(w).uses_ldq ^ mem_xcpt_uops(w).uses_stq)\n"
            "    }\n"
            "  }\n"
            "  if (MEMTRACE_PRINTF) {\n"
            "    when (commit_store || commit_load) {\n"
            "      val uop    = Mux(commit_store, stq(idx).bits.uop, ldq(idx).bits.uop)\n"
            "      val addr   = Mux(commit_store, stq(idx).bits.addr.bits, ldq(idx).bits.addr.bits)\n"
            "      val stdata = Mux(commit_store, stq(idx).bits.data.bits, 0.U)\n"
            "      val wbdata = Mux(commit_store, stq(idx).bits.debug_wb_data, ldq(idx).bits.debug_wb_data)\n"
            "      printf(\"MT %x %x %x %x %x %x %x\\n\",\n"
            "        io.core.tsc_reg, uop.uopc, uop.mem_cmd, uop.mem_size, addr, stdata, wbdata)\n"
            "    }\n"
            "  }\n"
            "}\n"
        )

        instrumented, _ = _boom_target_operation_runtime(text)

        self.assertIsNotNone(instrumented)
        paddr_reg_idx = instrumented.index("val mem_xcpt_paddrs = RegNext(exe_tlb_paddr)")
        exe_tlb_idx = instrumented.index("val exe_tlb_paddr = widthMap(")
        self.assertGreater(paddr_reg_idx, exe_tlb_idx)

    def test_cva6_issue_probe_uses_lsu_dispatch_signals(self):
        text = (
            "module ariane\n"
            "  logic clk_i;\n"
            "  logic rst_ni;\n"
            "  logic lsu_valid_id_ex;\n"
            "  logic [63:0] pc_id_ex;\n"
            "  fu_data_t fu_data_id_ex;\n"
            "  perf_counters i_perf_counters ();\n"
            "  controller controller_i ();\n"
            "endmodule\n"
        )

        instrumented, anchor = _cva6_target_operation_issue(text)

        self.assertIsNotNone(instrumented)
        self.assertIn("perf_counters i_perf_counters (", anchor)
        self.assertIn("if (lsu_valid_id_ex && fu_data_id_ex.fu == LOAD) begin", instrumented)
        self.assertIn("if (lsu_valid_id_ex && fu_data_id_ex.fu == STORE) begin", instrumented)
        self.assertIn('trans_id=%0d pc=0x%0h", fu_data_id_ex.trans_id, pc_id_ex);', instrumented)
        self.assertNotIn("load_valid_ex_id", instrumented)
        self.assertNotIn("store_valid_ex_id", instrumented)

    def test_cva6_runtime_probe_captures_aligned_paddr_per_pipeline(self):
        text = (
            "module load_store_unit;\n"
            "  logic clk_i;\n"
            "  logic rst_ni;\n"
            "  logic [63:0] mmu_paddr;\n"
            "  logic ld_valid;\n"
            "  logic [3:0] ld_trans_id;\n"
            "  riscv::xlen_t ld_result;\n"
            "  exception_t ld_ex;\n"
            "  logic st_valid;\n"
            "  logic [3:0] st_trans_id;\n"
            "  riscv::xlen_t st_result;\n"
            "  exception_t st_ex;\n"
            "  output logic load_valid_o;\n"
            "  output logic [3:0] load_trans_id_o;\n"
            "  output riscv::xlen_t load_result_o;\n"
            "  output exception_t load_exception_o;\n"
            "  output logic store_valid_o;\n"
            "  output logic [3:0] store_trans_id_o;\n"
            "  output riscv::xlen_t store_result_o;\n"
            "  output exception_t store_exception_o;\n"
            "  localparam int NR_LOAD_PIPE_REGS = 1;\n"
            "  localparam int NR_STORE_PIPE_REGS = 1;\n"
            "  shift_reg #(\n"
            "    .dtype(logic[0:0]),\n"
            "    .Depth(NR_LOAD_PIPE_REGS)\n"
            "  ) i_pipe_reg_load (\n"
            "    .clk_i(clk_i),\n"
            "    .rst_ni(rst_ni),\n"
            "    .d_i({ld_valid, ld_trans_id, ld_result, ld_ex}),\n"
            "    .d_o({load_valid_o, load_trans_id_o, load_result_o, load_exception_o})\n"
            "  );\n"
            "  shift_reg #(\n"
            "    .dtype(logic[0:0]),\n"
            "    .Depth(NR_STORE_PIPE_REGS)\n"
            "  ) i_pipe_reg_store (\n"
            "    .clk_i(clk_i),\n"
            "    .rst_ni(rst_ni),\n"
            "    .d_i({st_valid, st_trans_id, st_result, st_ex}),\n"
            "    .d_o({store_valid_o, store_trans_id_o, store_result_o, store_exception_o})\n"
            "  );\n"
            "  always_comb begin : which_op\n"
            "  end\n"
            "endmodule\n"
        )

        instrumented, anchor = _cva6_target_operation_runtime(text)

        self.assertIsNotNone(instrumented)
        self.assertIn("always_comb begin : which_op", anchor)
        self.assertIn("logic [riscv::PLEN-1:0] pmpfuzz_load_paddr;", instrumented)
        self.assertIn("logic [riscv::PLEN-1:0] pmpfuzz_store_paddr;", instrumented)
        self.assertIn("assign pmpfuzz_load_paddr = ld_valid ? mmu_paddr : '0;", instrumented)
        self.assertIn("assign pmpfuzz_store_paddr = st_valid ? mmu_paddr : '0;", instrumented)
        self.assertIn("pmpfuzz_load_paddr_o", instrumented)
        self.assertIn("pmpfuzz_store_paddr_o", instrumented)
        self.assertIn('status=completed access=load trans_id=%0d addr=0x%0h", load_trans_id_o, pmpfuzz_load_paddr_o);', instrumented)
        self.assertIn('status=completed access=store trans_id=%0d addr=0x%0h", store_trans_id_o, pmpfuzz_store_paddr_o);', instrumented)
        self.assertNotIn('status=completed access=load trans_id=%0d addr=0x%0h", load_trans_id_o, mmu_paddr);', instrumented)
        self.assertNotIn('status=completed access=store trans_id=%0d addr=0x%0h", store_trans_id_o, mmu_paddr);', instrumented)

    def test_write_source_probe_instrumentation_emits_v4_boom_schema2_fire_wiring(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chipyard = root / "chipyard"
            _write(
                chipyard / "generators/boom/src/main/scala/v4/lsu/tlb.scala",
                "class BoomTLBV4 {\n"
                "  val pmp = Seq.fill(memWidth) { Module(new PMPChecker(lgMaxSize)) }\n"
                "  val prot_x   = widthMap(w => fastCheck(_.executable, w) && pmp(w).io.x)\n"
                "  when (do_refill) {\n"
                "    newEntry.ae := io.ptw.resp.bits.ae_final\n"
                "    newEntry.fragmented_superpage := io.ptw.resp.bits.fragmented_superpage\n"
                "  }\n"
                "  val ptw_ae_array = widthMap(w => Cat(false.B, entries(w).map(_.ae).asUInt))\n"
                "  val pf_ld_array = widthMap(w => Mux(cmd_read(w), ~(r_array(w) | ptw_ae_array(w)), 0.U))\n"
                "  val pf_st_array = widthMap(w => Mux(cmd_write_perms(w), ~(w_array(w) | ptw_ae_array(w)), 0.U))\n"
                "  val pf_inst_array = widthMap(w => ~(x_array(w) | ptw_ae_array(w)))\n"
                "  io.ptw.req.bits.bits.addr := r_refill_tag\n"
                "}\n",
            )

            out = write_source_probe_instrumentation(
                ["boom-clean"],
                roots={"boom-clean": chipyard},
                out_dir=root / "out",
            )
            patch_text = "\n".join(path.read_text(encoding="ascii") for path in (root / "out" / "patches").glob("*.patch"))
            instrumented = [probe for probe in out["probes"] if probe["status"] == "instrumented"]

        self.assertGreaterEqual(len(instrumented), 4)
        self.assertIn("PMFUZZ_PROBE dut=boom-clean probe=boom_lsu_tlb_pmp_check schema=2 role=diagnostic", patch_text)
        self.assertIn("pmp(w).io.valid := do_refill || io.req(w).fire", patch_text)
        self.assertIn("when (io.ptw.req.fire)", patch_text)

    def test_write_source_probe_instrumentation_emits_both_boom_v3_and_v4_when_both_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chipyard = root / "chipyard"
            v3 = chipyard / "generators/boom/src/main/scala/v3/lsu/tlb.scala"
            v4 = chipyard / "generators/boom/src/main/scala/v4/lsu/tlb.scala"
            template = (
                "class BoomTLB {\n"
                "  val pmp = Seq.fill(memWidth) { Module(new PMPChecker(lgMaxSize)) }\n"
                "  val prot_x   = widthMap(w => fastCheck(_.executable, w) && pmp(w).io.x)\n"
                "  when (do_refill) {\n"
                "    newEntry.ae := io.ptw.resp.bits.ae_final\n"
                "    newEntry.fragmented_superpage := io.ptw.resp.bits.fragmented_superpage\n"
                "  }\n"
                "  val ptw_ae_array = widthMap(w => Cat(false.B, entries(w).map(_.ae).asUInt))\n"
                "  val pf_ld_array = widthMap(w => Mux(cmd_read(w), ~(r_array(w) | ptw_ae_array(w)), 0.U))\n"
                "  val pf_st_array = widthMap(w => Mux(cmd_write_perms(w), ~(w_array(w) | ptw_ae_array(w)), 0.U))\n"
                "  val pf_inst_array = widthMap(w => ~(x_array(w) | ptw_ae_array(w)))\n"
                "  io.ptw.req.bits.bits.addr := r_refill_tag\n"
                "}\n"
            )
            _write(v3, template)
            _write(v4, template)

            out = write_source_probe_instrumentation(
                ["boom-clean"],
                roots={"boom-clean": chipyard},
                out_dir=root / "out",
            )
            patch_text = "\n".join(path.read_text(encoding="ascii") for path in (root / "out" / "patches").glob("*.patch"))
            boom_probes = [probe for probe in out["probes"] if probe["dut"] == "boom-clean"]
            v3_hits = [probe for probe in boom_probes if probe.get("relative_path") == "generators/boom/src/main/scala/v3/lsu/tlb.scala"]
            v4_hits = [probe for probe in boom_probes if probe.get("relative_path") == "generators/boom/src/main/scala/v4/lsu/tlb.scala"]

        self.assertGreaterEqual(len(v3_hits), 4)
        self.assertGreaterEqual(len(v4_hits), 4)
        self.assertIn("+++ b/generators/boom/src/main/scala/v3/lsu/tlb.scala", patch_text)
        self.assertIn("+++ b/generators/boom/src/main/scala/v4/lsu/tlb.scala", patch_text)

    def test_source_probe_instrumentation_rejects_stale_marker_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chipyard = root / "chipyard"
            _write(
                chipyard / "generators/rocket-chip/src/main/scala/rocket/PMP.scala",
                "class PMPChecker(lgMaxSize: Int)(implicit val p: Parameters) extends Module {\n"
                "  val io = IO(new Bundle {\n"
                "    val x = Output(Bool())\n"
                "  })\n"
                "  io.x := res.cfg.x\n"
                "  printf(\"PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker "
                "chain=pmp-check stage=final access=load allow=%d\\n\", io.x)\n"
                "}\n",
            )

            out = write_source_probe_instrumentation(
                ["rocket-clean"],
                roots={"rocket-clean": chipyard},
                out_dir=root / "out",
            )

            by_probe = {probe["probe_id"]: probe for probe in out["probes"]}
            stale = by_probe["rocket_pmp_checker"]
            self.assertEqual(stale["status"], "stale_instrumentation")
            self.assertIn("schema=2", stale["instrumentation_error"])
            self.assertEqual(out["summary"]["already_instrumented"], 0)

    def test_source_probe_instrumentation_rejects_stale_cva6_target_issue_marker_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chipyard = root / "chipyard"
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ariane.sv",
                "module ariane;\n"
                "  logic [63:0] pc_id_ex;\n"
                "  logic [3:0] load_trans_id_ex_id;\n"
                "  logic load_valid_ex_id;\n"
                "  logic [3:0] store_trans_id_ex_id;\n"
                "  logic store_valid_ex_id;\n"
                "  perf_counters i_perf_counters ();\n"
                "  always_ff @(posedge clk_i) begin\n"
                "    if (rst_ni) begin\n"
                "      if (load_valid_ex_id) begin\n"
                '        $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_issue schema=cascade-target-operation-v1 role=runtime chain=target-operation phase=issue access=load trans_id=%0d pc=0x%0h", load_trans_id_ex_id, pc_id_ex);\n'
                "      end\n"
                "      if (store_valid_ex_id) begin\n"
                '        $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_issue schema=cascade-target-operation-v1 role=runtime chain=target-operation phase=issue access=store trans_id=%0d pc=0x%0h", store_trans_id_ex_id, pc_id_ex);\n'
                "      end\n"
                "    end\n"
                "  end\n"
                "  controller controller_i ();\n"
                "endmodule\n",
            )

            out = write_source_probe_instrumentation(
                ["cva6-clean"],
                roots={"cva6-clean": chipyard},
                out_dir=root / "out",
            )

        by_probe = {probe["probe_id"]: probe for probe in out["probes"]}
        stale = by_probe["cva6_target_operation_issue"]
        self.assertEqual(stale["status"], "stale_instrumentation")
        self.assertIn("phase=issue", stale["instrumentation_error"])

    def test_source_probe_instrumentation_rejects_stale_cva6_target_runtime_marker_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chipyard = root / "chipyard"
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/load_store_unit.sv",
                "module load_store_unit;\n"
                "  logic clk_i;\n"
                "  logic rst_ni;\n"
                "  output logic load_valid_o;\n"
                "  output logic [3:0] load_trans_id_o;\n"
                "  output exception_t load_exception_o;\n"
                "  output logic store_valid_o;\n"
                "  output logic [3:0] store_trans_id_o;\n"
                "  output exception_t store_exception_o;\n"
                "  logic [63:0] mmu_paddr;\n"
                "  always_ff @(posedge clk_i) begin\n"
                "    if (rst_ni) begin\n"
                "      if (load_valid_o) begin\n"
                '        $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation status=completed access=load trans_id=%0d addr=0x%0h", load_trans_id_o, mmu_paddr);\n'
                "      end\n"
                "      if (store_valid_o) begin\n"
                '        $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_runtime schema=cascade-target-operation-v1 role=runtime chain=target-operation status=completed access=store trans_id=%0d addr=0x%0h", store_trans_id_o, mmu_paddr);\n'
                "      end\n"
                "    end\n"
                "  end\n"
                "  always_comb begin : which_op\n"
                "  end\n"
                "endmodule\n",
            )

            out = write_source_probe_instrumentation(
                ["cva6-clean"],
                roots={"cva6-clean": chipyard},
                out_dir=root / "out",
            )

        by_probe = {probe["probe_id"]: probe for probe in out["probes"]}
        stale = by_probe["cva6_target_operation_runtime"]
        self.assertEqual(stale["status"], "stale_instrumentation")
        self.assertIn("status=", stale["instrumentation_error"])

    def test_source_probe_instrumentation_rejects_stale_boom_marker_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chipyard = root / "chipyard"
            _write(
                chipyard / "generators/boom/src/main/scala/v3/lsu/tlb.scala",
                "class BoomTLB {\n"
                "  val pmp = Seq.fill(memWidth) { Module(new PMPChecker(lgMaxSize)) }\n"
                "  printf(\"PMFUZZ_PROBE dut=boom-clean probe=boom_lsu_tlb_pmp_check "
                "chain=pmp-check stage=lsu addr=0x%x prv=%d r=%d w=%d x=%d\\n\", mpu_physaddr(0), 3.U, 1.U, 1.U, 1.U)\n"
                "}\n",
            )

            out = write_source_probe_instrumentation(
                ["boom-clean"],
                roots={"boom-clean": chipyard},
                out_dir=root / "out",
            )

            stale = next(
                probe
                for probe in out["probes"]
                if probe["probe_id"] == "boom_lsu_tlb_pmp_check"
                and probe.get("relative_path") == "generators/boom/src/main/scala/v3/lsu/tlb.scala"
            )

        self.assertEqual(stale["status"], "stale_instrumentation")
        self.assertIn("schema=2", stale["instrumentation_error"])
        self.assertEqual(out["summary"]["already_instrumented"], 0)

    def test_source_probe_instrumentation_rejects_stale_cva6_pmp_csr_marker_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chipyard = root / "chipyard"
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/csr_regfile.sv",
                "module csr_regfile(input logic clk_i, input logic rst_ni);\n"
                "  logic [1:0] pmpcfg_q;\n"
                "  logic [1:0] pmpaddr_q;\n"
                "  assign pmpcfg_o = pmpcfg_q;\n"
                "  assign pmpaddr_o = pmpaddr_q;\n"
                "  integer pmpcfg_probe_entry_i;\n"
                "  always_ff @(posedge clk_i) begin\n"
                "    if (rst_ni) begin\n"
                "      for (pmpcfg_probe_entry_i = 0; pmpcfg_probe_entry_i < $size(pmpcfg_q); pmpcfg_probe_entry_i++) begin\n"
                '        $display("PMFUZZ_PROBE dut=cva6-clean probe=cva6_pmp_csr_state chain=pmp-csr stage=csr entry=%0d cfg=0x%0h addr=0x%0h", pmpcfg_probe_entry_i, pmpcfg_q[pmpcfg_probe_entry_i], pmpaddr_q[pmpcfg_probe_entry_i]);\n'
                "      end\n"
                "    end\n"
                "  end\n"
                "endmodule\n",
            )

            out = write_source_probe_instrumentation(
                ["cva6-clean"],
                roots={"cva6-clean": chipyard},
                out_dir=root / "out",
            )

            stale = next(probe for probe in out["probes"] if probe["probe_id"] == "cva6_pmp_csr_state")

        self.assertEqual(stale["status"], "stale_instrumentation")
        self.assertIn("pmpcfg_probe_seen_q", stale["instrumentation_error"])
        self.assertEqual(out["summary"]["already_instrumented"], 0)

    def test_cli_accepts_source_probe_instrument_command(self):
        parser = build_parser()

        args = parser.parse_args(["source-probe-instrument", "--dut", "rocket-clean,cva6-clean", "--out", "out"])

        self.assertEqual(args.command, "source-probe-instrument")
        self.assertEqual(args.dut, "rocket-clean,cva6-clean")
        self.assertEqual(args.out, Path("out"))

    def test_cli_writes_probe_source_manifest_with_explicit_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xiangshan = root / "xiangshan"
            chipyard = root / "chipyard"
            _write(
                xiangshan / "src/main/scala/xiangshan/backend/fu/PMP.scala",
                "class PMP { val pmp_hit = true }\n",
            )
            _write(
                chipyard / "generators/rocket-chip/src/main/scala/rocket/PMP.scala",
                "class PMPChecker(lgMaxSize: Int) extends Module\n",
            )

            rc = main(
                [
                    "probe-source",
                    "--dut",
                    "xiangshan-clean,rocket-clean",
                    "--xiangshan-root",
                    str(xiangshan),
                    "--chipyard-dir",
                    str(chipyard),
                    "--out",
                    str(root / "out"),
                ]
            )

            manifest = root / "out" / "source_probe_manifest.json"
            exists = manifest.exists()

        self.assertEqual(rc, 0)
        self.assertTrue(exists)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="ascii")


if __name__ == "__main__":
    unittest.main()
