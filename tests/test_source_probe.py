import tempfile
import unittest
from pathlib import Path

from pmpfuzz.__main__ import build_parser, main
from pmpfuzz.source_probe import (
    default_source_probe_specs,
    discover_source_probes,
    write_source_probe_instrumentation,
    write_source_probe_manifest,
)


class SourceProbeTest(unittest.TestCase):
    def test_default_specs_cover_xiangshan_boom_and_rocket_security_chain(self):
        specs = default_source_probe_specs()
        by_dut = {}
        for spec in specs:
            by_dut.setdefault(spec.dut, set()).add(spec.security_chain)

        self.assertIn("xiangshan-clean", by_dut)
        self.assertIn("boom-clean", by_dut)
        self.assertIn("rocket-clean", by_dut)
        self.assertIn("cva6-clean", by_dut)
        self.assertIn("pmp-check", by_dut["xiangshan-clean"])
        self.assertIn("ptw-request", by_dut["boom-clean"])
        self.assertIn("exception-arbitration", by_dut["rocket-clean"])
        self.assertIn("pmp-csr", by_dut["cva6-clean"])
        self.assertTrue(all("PMFUZZ_PROBE" in spec.instrumentation_hint for spec in specs))

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
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/CVA6CoreBlackbox.preprocessed.sv",
                "assign pmpcfg_o = pmpcfg_q;\n"
                "always_comb begin : exception_handling exception_o.valid = access_exception; end\n"
                "assign flush_tlb_o = sfence_vma_i;\n",
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
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ptw.sv",
                "module ptw; output logic ptw_access_exception_o; endmodule\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/tlb.sv",
                "module tlb; input logic flush_i; endmodule\n",
            )

            manifest = discover_source_probes(["cva6-clean"], roots={"cva6-clean": chipyard})

        by_probe = {probe["probe_id"]: probe for probe in manifest["probes"]}
        self.assertEqual(
            by_probe["cva6_ptw_exception"]["relative_path"],
            "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ptw.sv",
        )
        self.assertEqual(
            by_probe["cva6_tlb_exception_arbitration"]["relative_path"],
            "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/tlb.sv",
        )

    def test_write_source_probe_instrumentation_emits_applyable_patches_without_mutating_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chipyard = root / "chipyard"
            _write(
                chipyard / "generators/rocket-chip/src/main/scala/rocket/PMP.scala",
                "class PMPChecker(lgMaxSize: Int)(implicit val p: Parameters) extends Module {\n"
                "  val io = IO(new Bundle {})\n"
                "  io.r := res.cfg.r\n"
                "  io.w := res.cfg.w\n"
                "  io.x := res.cfg.x\n"
                "}\n",
            )
            _write(
                chipyard / "generators/rocket-chip/src/main/scala/rocket/TLB.scala",
                "class TLB {\n"
                "  val ptw_ae_array = Cat(false.B, entries.map(_.ae_ptw).asUInt)\n"
                "  val ae_ld_array = Mux(cmd_read, ae_array, 0.U)\n"
                "  val ae_st_array = Mux(cmd_write, ae_array, 0.U)\n"
                "  val pf_ld_array = Mux(cmd_read, ptw_pf_array, 0.U)\n"
                "  val pf_st_array = Mux(cmd_write, ptw_pf_array, 0.U)\n"
                "  val pf_inst_array = ptw_pf_array\n"
                "  val tlb_miss = vm_enabled && !tlb_hit\n"
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
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/CVA6CoreBlackbox.preprocessed.sv",
                "module CVA6CoreBlackbox; logic clk_i; logic rst_ni; logic [1:0] pmpcfg; logic [1:0] pmpaddr;\n"
                "  .pmpcfg_o               ( pmpcfg                        ),\n"
                "  .pmpaddr_o              ( pmpaddr                       )\n"
                "endmodule\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ptw.sv",
                "module ptw(input logic clk_i, input logic rst_ni);\n"
                "  logic allow_access; logic ptw_access_exception_o; logic [63:0] ptw_pptr_q;\n"
                "  assign bad_paddr_o = ptw_access_exception_o ? ptw_pptr_q : 'b0;\n"
                "endmodule\n",
            )
            _write(
                chipyard / "generators/cva6/src/main/resources/cva6/vsrc/cva6/src/tlb.sv",
                "module tlb(input logic clk_i, input logic rst_ni, input logic flush_i, input logic lu_access_i);\n"
                "  logic lu_hit_o; logic [63:0] lu_vaddr_i; logic update_valid;\n"
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
            self.assertIn("PMFUZZ_PROBE dut=boom-clean probe=boom_ptw_request", patch_text)
            self.assertIn("PMFUZZ_PROBE dut=cva6-clean probe=cva6_ptw_exception", patch_text)
            self.assertTrue(instrumentation_json.exists())
            self.assertEqual(current, original)

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
