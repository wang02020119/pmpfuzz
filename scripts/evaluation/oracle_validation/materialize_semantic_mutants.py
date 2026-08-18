from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from pmpfuzz.dut import DEFAULT_CLEAN_CHIPYARD_DIR


SCHEMA_VERSION = 1
REQUIRED_SOURCE_SYMLINK_PATHS = [".conda-env", "tools/circt"]


@dataclass(frozen=True)
class TextEdit:
    relative_path: str
    before: str
    after: str
    expected_matches: int = 1


@dataclass(frozen=True)
class BuildRecipe:
    config: str
    expected_binary_relative_path: str
    build_script_relative_path: str = "scripts/build/build_clean_chipyard_dut.sh"
    jobs: int = 1
    timeout: str = "6h"
    verilator_threads: int = 1


@dataclass(frozen=True)
class MutantDefinition:
    dut: str
    mutant_id: str
    injection_layer: str
    source_root_kind: str
    edits: tuple[TextEdit, ...]
    build_recipe: BuildRecipe
    notes: str = ""


ROCKET_BUILD = BuildRecipe(
    config="RocketConfig",
    expected_binary_relative_path="sims/verilator/simulator-chipyard.harness-RocketConfig",
)
BOOM_BUILD = BuildRecipe(
    config="SmallBoomV3Config",
    expected_binary_relative_path="sims/verilator/simulator-chipyard.harness-SmallBoomV3Config",
)
CVA6_BUILD = BuildRecipe(
    config="CVA6Config",
    expected_binary_relative_path="sims/verilator/simulator-chipyard.harness-CVA6Config",
)


def _pmp_edit(before: str, after: str, *, expected_matches: int = 1) -> TextEdit:
    return TextEdit(
        relative_path="generators/rocket-chip/src/main/scala/rocket/PMP.scala",
        before=before,
        after=after,
        expected_matches=expected_matches,
    )


def _rocket_tlb_edit(before: str, after: str, *, expected_matches: int = 1) -> TextEdit:
    return TextEdit(
        relative_path="generators/rocket-chip/src/main/scala/rocket/TLB.scala",
        before=before,
        after=after,
        expected_matches=expected_matches,
    )


def _rocket_dcache_edit(before: str, after: str, *, expected_matches: int = 1) -> TextEdit:
    return TextEdit(
        relative_path="generators/rocket-chip/src/main/scala/rocket/DCache.scala",
        before=before,
        after=after,
        expected_matches=expected_matches,
    )


def _rocket_ptw_edit(before: str, after: str, *, expected_matches: int = 1) -> TextEdit:
    return TextEdit(
        relative_path="generators/rocket-chip/src/main/scala/rocket/PTW.scala",
        before=before,
        after=after,
        expected_matches=expected_matches,
    )


def _rocket_csr_edit(before: str, after: str, *, expected_matches: int = 1) -> TextEdit:
    return TextEdit(
        relative_path="generators/rocket-chip/src/main/scala/rocket/CSR.scala",
        before=before,
        after=after,
        expected_matches=expected_matches,
    )


def _boom_v3_tlb_edit(before: str, after: str, *, expected_matches: int = 1) -> TextEdit:
    return TextEdit(
        relative_path="generators/boom/src/main/scala/v3/lsu/tlb.scala",
        before=before,
        after=after,
        expected_matches=expected_matches,
    )


def _boom_v3_lsu_edit(before: str, after: str, *, expected_matches: int = 1) -> TextEdit:
    return TextEdit(
        relative_path="generators/boom/src/main/scala/v3/lsu/lsu.scala",
        before=before,
        after=after,
        expected_matches=expected_matches,
    )


def _cva6_ptw_edit(before: str, after: str, *, expected_matches: int = 1) -> TextEdit:
    return TextEdit(
        relative_path="generators/cva6/src/main/resources/cva6/vsrc/cva6/src/ptw.sv",
        before=before,
        after=after,
        expected_matches=expected_matches,
    )


def _cva6_tlb_edit(before: str, after: str, *, expected_matches: int = 1) -> TextEdit:
    return TextEdit(
        relative_path="generators/cva6/src/main/resources/cva6/vsrc/cva6/src/tlb.sv",
        before=before,
        after=after,
        expected_matches=expected_matches,
    )


def _cva6_pmp_edit(before: str, after: str, *, expected_matches: int = 1) -> TextEdit:
    return TextEdit(
        relative_path="generators/cva6/src/main/resources/cva6/vsrc/cva6/src/pmp/src/pmp.sv",
        before=before,
        after=after,
        expected_matches=expected_matches,
    )


def _cva6_mmu_edit(before: str, after: str, *, expected_matches: int = 1) -> TextEdit:
    return TextEdit(
        relative_path="generators/cva6/src/main/resources/cva6/vsrc/cva6/src/mmu.sv",
        before=before,
        after=after,
        expected_matches=expected_matches,
    )


def _cva6_commit_edit(before: str, after: str, *, expected_matches: int = 1) -> TextEdit:
    return TextEdit(
        relative_path="generators/cva6/src/main/resources/cva6/vsrc/cva6/src/commit_stage.sv",
        before=before,
        after=after,
        expected_matches=expected_matches,
    )


MUTANT_DEFINITIONS: dict[tuple[str, str], MutantDefinition] = {
    ("rocket-clean", "M01"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M01",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _pmp_edit(
                "cur.cfg.r := aligned && (pmp.cfg.r || ignore)",
                "cur.cfg.r := aligned // MUTANT M01: ignore read permission bit",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M02"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M02",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _pmp_edit(
                "cur.cfg.w := aligned && (pmp.cfg.w || ignore)",
                "cur.cfg.w := aligned // MUTANT M02: ignore write permission bit",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M03"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M03",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _pmp_edit(
                "cur.cfg.x := aligned && (pmp.cfg.x || ignore)",
                "cur.cfg.x := aligned // MUTANT M03: ignore execute permission bit",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M04"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M04",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _pmp_edit(
                "val res = (io.pmp zip (pmp0 +: io.pmp)).reverse.foldLeft(pmp0) { case (prev, (pmp, prevPMP)) =>",
                "val res = (io.pmp zip (pmp0 +: io.pmp)).foldLeft(pmp0) { case (prev, (pmp, prevPMP)) => // MUTANT M04: later match wins",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M05"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M05",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _pmp_edit(
                "private def pow2Match(x: UInt, lgSize: UInt, lgMaxSize: Int) = {\n    def eval(a: UInt, b: UInt, m: UInt) = ((a ^ b) & ~m) === 0.U\n    if (lgMaxSize <= pmpGranularity.log2) {\n      eval(x, comparand, mask)\n    } else {\n      // break up the circuit; the MSB part will be CSE'd\n      val lsbMask = mask | UIntToOH1(lgSize, lgMaxSize)\n      val msbMatch = eval(x >> lgMaxSize, comparand >> lgMaxSize, mask >> lgMaxSize)\n      val lsbMatch = eval(x(lgMaxSize-1, 0), comparand(lgMaxSize-1, 0), lsbMask(lgMaxSize-1, 0))\n      msbMatch && lsbMatch\n    }\n  }",
                "private def pow2Match(x: UInt, lgSize: UInt, lgMaxSize: Int) = {\n    def eval(a: UInt, b: UInt, m: UInt) = ((a ^ b) & ~m) === 0.U\n    val biasedX = x + (1.U << lgSize) // MUTANT M05: exclude the last aligned access ending at a pow2 PMP upper boundary\n    if (lgMaxSize <= pmpGranularity.log2) {\n      eval(biasedX, comparand, mask)\n    } else {\n      // break up the circuit; the MSB part will be CSE'd\n      val lsbMask = mask | UIntToOH1(lgSize, lgMaxSize)\n      val msbMatch = eval(biasedX >> lgMaxSize, comparand >> lgMaxSize, mask >> lgMaxSize)\n      val lsbMatch = eval(biasedX(lgMaxSize-1, 0), comparand(lgMaxSize-1, 0), lsbMask(lgMaxSize-1, 0))\n      msbMatch && lsbMatch\n    }\n  }",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M06"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M06",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _pmp_edit(
                "val default = if (io.pmp.isEmpty) true.B else io.prv > PRV.S.U",
                "val default = true.B // MUTANT M06: incorrectly allow unmatched S/U accesses",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M07"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M07",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _rocket_csr_edit(
                "io.status.dprv := Mux(reg_mstatus.mprv && !reg_debug, reg_mstatus.mpp, reg_mstatus.prv)",
                "io.status.dprv := reg_mstatus.prv // MUTANT M07: ignore MPRV-derived effective privilege",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M08"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M08",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _rocket_tlb_edit(
                "val mpu_priv = Mux[UInt](usingVM.B && (do_refill || io.req.bits.passthrough /* PTW */), PRV.S.U, Cat(io.ptw.status.debug, priv))",
                "val mpu_priv = Mux[UInt](usingVM.B && io.req.bits.passthrough /* PTW */ && !do_refill, PRV.M.U, Mux[UInt](usingVM.B && do_refill, PRV.S.U, Cat(io.ptw.status.debug, priv))) // MUTANT M08: PTW request accesses bypass PMP as M-mode",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M09"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M09",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _rocket_tlb_edit(
                "    newEntry.ae_final := io.ptw.resp.bits.ae_final",
                "    newEntry.ae_final := false.B // MUTANT M09: ignore final-access PMP faults",
            ),
            _rocket_tlb_edit(
                "    newEntry.pr := prot_r",
                "    newEntry.pr := pma.io.resp.r && !deny_access_to_debug // MUTANT M09: ignore translated final-access PMP read permission",
            ),
            _rocket_tlb_edit(
                "    newEntry.pw := prot_w",
                "    newEntry.pw := pma.io.resp.w && !deny_access_to_debug // MUTANT M09: ignore translated final-access PMP write permission",
            ),
            _rocket_tlb_edit(
                "    newEntry.px := prot_x",
                "    newEntry.px := pma.io.resp.x && !deny_access_to_debug // MUTANT M09: ignore translated final-access PMP execute permission",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M10"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M10",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _rocket_tlb_edit(
                "val sum = Mux(priv_v, io.ptw.gstatus.sum, io.ptw.status.sum)",
                "val sum = true.B // MUTANT M10: ignore SUM restrictions",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M11"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M11",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _rocket_ptw_edit(
                "  def leaf(dummy: Int = 0) = v && (r || (x && !w)) && a",
                "  def leaf(dummy: Int = 0) = v && (r || (x && !w)) // MUTANT M11: ignore accessed-bit requirement",
            ),
            _rocket_ptw_edit(
                "  def sw(dummy: Int = 0) = leaf() && w && d",
                "  def sw(dummy: Int = 0) = leaf() && w // MUTANT M11: ignore dirty-bit requirement",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M12"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M12",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _rocket_tlb_edit(
                "io.resp.pf.ld := (bad_va && cmd_read) || (pf_ld_array & hits).orR",
                "io.resp.pf.ld := bad_va && cmd_read // MUTANT M12: load page faults become access faults",
            ),
            _rocket_tlb_edit(
                "io.resp.pf.st := (bad_va && cmd_write_perms) || (pf_st_array & hits).orR",
                "io.resp.pf.st := bad_va && cmd_write_perms // MUTANT M12: store page faults become access faults",
            ),
            _rocket_tlb_edit(
                "io.resp.ae.ld := (ae_ld_array & hits).orR",
                "io.resp.ae.ld := (ae_ld_array & hits).orR || (pf_ld_array & hits).orR // MUTANT M12: misclassify page fault as access fault",
            ),
            _rocket_tlb_edit(
                "io.resp.ae.st := (ae_st_array & hits).orR",
                "io.resp.ae.st := (ae_st_array & hits).orR || (pf_st_array & hits).orR // MUTANT M12: misclassify page fault as access fault",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M13"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M13",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _rocket_ptw_edit(
                "        resp_ae_ptw := true.B",
                "        resp_ae_final := true.B // MUTANT M13: attribute PTW access exception to final-access stage",
            ),
            _rocket_ptw_edit(
                "resp_ae_ptw := ae && ((count < (pgLevels-1).U && pte.table()) || (do_both_stages && !stage2_final))",
                "resp_ae_ptw := false.B // MUTANT M13: drop PTW-stage attribution",
            ),
            _rocket_ptw_edit(
                "resp_ae_final := ae && pte.leaf() && !(do_both_stages && !stage2_final)",
                "resp_ae_final := ae // MUTANT M13: attribute PTW faults to final-access stage",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M14"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M14",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _rocket_csr_edit(
                "      reg_mtval := tval",
                "      reg_mtval := 0.U // MUTANT M14: corrupt the architectural fault address",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M15"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M15",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _rocket_csr_edit(
                "      when (decoded_addr(CSRs.pmpcfg0 + pmpCfgIndex(i)) && !pmp.cfgLocked) {\n        val newCfg = (wdata >> ((i * pmp.cfg.getWidth) % xLen)).asTypeOf(new PMPConfig())\n        pmp.cfg := newCfg\n        // disallow unreadable but writable PMPs\n        pmp.cfg.w := newCfg.w && newCfg.r\n        // can't select a=NA4 with coarse-grained PMPs\n        if (pmpGranularity.log2 > PMP.lgAlign)\n          pmp.cfg.a := Cat(newCfg.a(1), newCfg.a.orR)\n      }",
                "      when (decoded_addr(CSRs.pmpcfg0 + pmpCfgIndex(i)) && !pmp.cfgLocked) {\n        val newCfg = (wdata >> ((i * pmp.cfg.getWidth) % xLen)).asTypeOf(new PMPConfig())\n        if (i == 5) {\n          val clearsPermissions = (pmp.cfg.r || pmp.cfg.w || pmp.cfg.x) && !newCfg.r && !newCfg.w && !newCfg.x\n          when (!clearsPermissions) {\n            pmp.cfg := newCfg\n            // disallow unreadable but writable PMPs\n            pmp.cfg.w := newCfg.w && newCfg.r\n            // can't select a=NA4 with coarse-grained PMPs\n            if (pmpGranularity.log2 > PMP.lgAlign)\n              pmp.cfg.a := Cat(newCfg.a(1), newCfg.a.orR)\n          }\n        } else {\n          pmp.cfg := newCfg\n          // disallow unreadable but writable PMPs\n          pmp.cfg.w := newCfg.w && newCfg.r\n          // can't select a=NA4 with coarse-grained PMPs\n          if (pmpGranularity.log2 > PMP.lgAlign)\n            pmp.cfg.a := Cat(newCfg.a(1), newCfg.a.orR)\n        }\n      }",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M16"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M16",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _rocket_tlb_edit(
                "val sfence = io.sfence.valid",
                "val sfence = false.B // MUTANT M16: ignore TLB invalidation",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M17"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M17",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _rocket_dcache_edit(
                "  val s2_valid_no_xcpt = s2_valid && !io.cpu.s2_xcpt.asUInt.orR",
                "  val s2_store_xcpt = io.cpu.s2_xcpt.pf.st || io.cpu.s2_xcpt.gf.st || io.cpu.s2_xcpt.ae.st || io.cpu.s2_xcpt.ma.st\n  val s2_valid_no_xcpt = s2_valid && (!io.cpu.s2_xcpt.asUInt.orR || s2_store_xcpt) // MUTANT M17: keep faulting stores alive into the D$ pipeline",
            ),
            _rocket_dcache_edit(
                "  val s2_valid_correct = s2_valid_hit_pre_data_ecc_and_waw && s2_correct && !io.cpu.s2_kill\n  def s2_store_valid_pre_kill = s2_valid_hit && s2_write && !s2_sc_fail\n  def s2_store_valid = s2_store_valid_pre_kill && !io.cpu.s2_kill",
                "  val s2_valid_correct = s2_valid_hit_pre_data_ecc_and_waw && s2_correct && !io.cpu.s2_kill\n  def s2_store_valid_pre_kill = s2_valid_hit && s2_write && !s2_sc_fail\n  def s2_store_valid = s2_store_valid_pre_kill && (!io.cpu.s2_kill || s2_store_xcpt) // MUTANT M17: let denied stores reach the store buffer",
            ),
            _rocket_dcache_edit(
                "  def pstore1_valid_not_rmw(s2_kill: Bool) = s2_valid_hit_pre_data_ecc && s2_write && !s2_kill || pstore1_held",
                "  def pstore1_valid_not_rmw(s2_kill: Bool) = s2_valid_hit_pre_data_ecc && s2_write && (!s2_kill || s2_store_xcpt) || pstore1_held // MUTANT M17: keep faulting stores live long enough to commit",
            ),
            _rocket_dcache_edit(
                "  val pstore_drain = should_pstore_drain(true.B)",
                "  val pstore_drain = should_pstore_drain(!s2_store_xcpt) // MUTANT M17: drain faulting stores into the data array before trapping",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("rocket-clean", "M18"): MutantDefinition(
        dut="rocket-clean",
        mutant_id="M18",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _rocket_dcache_edit(
                "  val pstore1_mask = RegEnable(s1_mask, s1_valid_not_nacked && s1_write)",
                "  val pstore1_mask = RegEnable(Mux(s1_vaddr === 0x80008000L.U, 0.U.asTypeOf(s1_mask), s1_mask), s1_valid_not_nacked && s1_write) // MUTANT M18: suppress the sentinel store side effect while leaving other stores intact",
            ),
        ),
        build_recipe=ROCKET_BUILD,
    ),
    ("boom-clean", "M02"): MutantDefinition(
        dut="boom-clean",
        mutant_id="M02",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _pmp_edit(
                "cur.cfg.w := aligned && (pmp.cfg.w || ignore)",
                "cur.cfg.w := aligned // MUTANT M02: ignore write permission bit",
            ),
        ),
        build_recipe=BOOM_BUILD,
    ),
    ("boom-clean", "M04"): MutantDefinition(
        dut="boom-clean",
        mutant_id="M04",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _pmp_edit(
                "val res = (io.pmp zip (pmp0 +: io.pmp)).reverse.foldLeft(pmp0) { case (prev, (pmp, prevPMP)) =>",
                "val res = (io.pmp zip (pmp0 +: io.pmp)).foldLeft(pmp0) { case (prev, (pmp, prevPMP)) => // MUTANT M04: later match wins",
            ),
        ),
        build_recipe=BOOM_BUILD,
    ),
    ("boom-clean", "M08"): MutantDefinition(
        dut="boom-clean",
        mutant_id="M08",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _boom_v3_tlb_edit(
                "pmp(w).io.prv := Mux(usingVM.B && (do_refill || io.req(w).bits.passthrough /* PTW */), PRV.S.U, priv) // TODO should add separate bit to track PTW",
                "pmp(w).io.prv := Mux(usingVM.B && (do_refill || io.req(w).bits.passthrough /* PTW */), PRV.M.U, priv) // MUTANT M08: PTW bypasses PMP as M-mode",
            ),
        ),
        build_recipe=BOOM_BUILD,
    ),
    ("boom-clean", "M12"): MutantDefinition(
        dut="boom-clean",
        mutant_id="M12",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _boom_v3_tlb_edit(
                "io.resp(w).pf.ld   := (bad_va(w) && cmd_read(w)) || (pf_ld_array(w) & hits(w)).orR",
                "io.resp(w).pf.ld   := bad_va(w) && cmd_read(w) // MUTANT M12: load page faults become access faults",
            ),
            _boom_v3_tlb_edit(
                "io.resp(w).pf.st   := (bad_va(w) && cmd_write_perms(w)) || (pf_st_array(w) & hits(w)).orR",
                "io.resp(w).pf.st   := bad_va(w) && cmd_write_perms(w) // MUTANT M12: store page faults become access faults",
            ),
            _boom_v3_tlb_edit(
                "io.resp(w).ae.ld   := (ae_valid_array(w) & ae_ld_array(w) & hits(w)).orR",
                "io.resp(w).ae.ld   := (ae_valid_array(w) & ae_ld_array(w) & hits(w)).orR || (pf_ld_array(w) & hits(w)).orR // MUTANT M12: misclassify page fault as access fault",
            ),
            _boom_v3_tlb_edit(
                "io.resp(w).ae.st   := (ae_valid_array(w) & ae_st_array(w) & hits(w)).orR",
                "io.resp(w).ae.st   := (ae_valid_array(w) & ae_st_array(w) & hits(w)).orR || (pf_st_array(w) & hits(w)).orR // MUTANT M12: misclassify page fault as access fault",
            ),
        ),
        build_recipe=BOOM_BUILD,
    ),
    ("boom-clean", "M16"): MutantDefinition(
        dut="boom-clean",
        mutant_id="M16",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _boom_v3_tlb_edit(
                "val sfence = io.sfence.valid",
                "val sfence = false.B // MUTANT M16: ignore TLB invalidation",
            ),
        ),
        build_recipe=BOOM_BUILD,
    ),
    ("boom-clean", "M17"): MutantDefinition(
        dut="boom-clean",
        mutant_id="M17",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _boom_v3_tlb_edit(
                "io.resp(w).ae.st   := (ae_valid_array(w) & ae_st_array(w) & hits(w)).orR",
                "io.resp(w).ae.st   := false.B // MUTANT M17: suppress store access faults so denied stores still update memory",
            ),
        ),
        build_recipe=BOOM_BUILD,
    ),
    ("cva6-clean", "M02"): MutantDefinition(
        dut="cva6-clean",
        mutant_id="M02",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _cva6_pmp_edit(
                "                        if ((access_type_i & conf_i[i].access_type) != access_type_i) allow_o = 1'b0;\n                        else allow_o = 1'b1;",
                "                        if (access_type_i == riscv::ACCESS_WRITE) allow_o = 1'b1; // MUTANT M02: ignore store-write permission bit\n                        else if ((access_type_i & conf_i[i].access_type) != access_type_i) allow_o = 1'b0;\n                        else allow_o = 1'b1;",
            ),
        ),
        build_recipe=CVA6_BUILD,
    ),
    ("cva6-clean", "M04"): MutantDefinition(
        dut="cva6-clean",
        mutant_id="M04",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _cva6_pmp_edit(
                "            int i;\n\n            allow_o = 1'b0;",
                "            int i;\n            bit matched;\n\n            allow_o = 1'b0;\n            matched = 1'b0;",
            ),
            _cva6_pmp_edit(
                "                    if (match[i]) begin\n                        if ((access_type_i & conf_i[i].access_type) != access_type_i) allow_o = 1'b0;",
                "                    if (match[i]) begin\n                        matched = 1'b1;\n                        if ((access_type_i & conf_i[i].access_type) != access_type_i) allow_o = 1'b0;",
            ),
            _cva6_pmp_edit(
                "                        break;",
                "                        // MUTANT M04: later matching entries override the first match",
            ),
            _cva6_pmp_edit(
                "            if (i == NR_ENTRIES) begin // no PMP entry matched the address",
                "            if (!matched) begin // MUTANT M04: only use the default path when no PMP entry matched",
            ),
        ),
        build_recipe=CVA6_BUILD,
    ),
    ("cva6-clean", "M08"): MutantDefinition(
        dut="cva6-clean",
        mutant_id="M08",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _cva6_ptw_edit(
                ".priv_lvl_i    ( riscv::PRIV_LVL_S  ),",
                ".priv_lvl_i    ( riscv::PRIV_LVL_M  ), // MUTANT M08: PTW bypasses PMP as M-mode",
            ),
        ),
        build_recipe=CVA6_BUILD,
    ),
    ("cva6-clean", "M12"): MutantDefinition(
        dut="cva6-clean",
        mutant_id="M12",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _cva6_mmu_edit(
                "                        lsu_exception_o = {riscv::STORE_PAGE_FAULT, {{riscv::XLEN-riscv::VLEN{lsu_vaddr_q[riscv::VLEN-1]}},lsu_vaddr_q}, 1'b1};",
                "                        lsu_exception_o = {riscv::ST_ACCESS_FAULT, {{riscv::XLEN-riscv::VLEN{lsu_vaddr_q[riscv::VLEN-1]}},lsu_vaddr_q}, 1'b1}; // MUTANT M12: misclassify store page fault as access fault",
            ),
            _cva6_mmu_edit(
                "                        lsu_exception_o = {riscv::LOAD_PAGE_FAULT, {{riscv::XLEN-riscv::VLEN{lsu_vaddr_q[riscv::VLEN-1]}},lsu_vaddr_q}, 1'b1};",
                "                        lsu_exception_o = {riscv::LD_ACCESS_FAULT, {{riscv::XLEN-riscv::VLEN{lsu_vaddr_q[riscv::VLEN-1]}},lsu_vaddr_q}, 1'b1}; // MUTANT M12: misclassify load page fault as access fault",
            ),
            _cva6_mmu_edit(
                "                        lsu_exception_o = {riscv::STORE_PAGE_FAULT, {{riscv::XLEN-riscv::VLEN{lsu_vaddr_q[riscv::VLEN-1]}},update_vaddr}, 1'b1};",
                "                        lsu_exception_o = {riscv::ST_ACCESS_FAULT, {{riscv::XLEN-riscv::VLEN{lsu_vaddr_q[riscv::VLEN-1]}},update_vaddr}, 1'b1}; // MUTANT M12: misclassify PTW store page fault as access fault",
            ),
            _cva6_mmu_edit(
                "                        lsu_exception_o = {riscv::LOAD_PAGE_FAULT, {{riscv::XLEN-riscv::VLEN{lsu_vaddr_q[riscv::VLEN-1]}},update_vaddr}, 1'b1};",
                "                        lsu_exception_o = {riscv::LD_ACCESS_FAULT, {{riscv::XLEN-riscv::VLEN{lsu_vaddr_q[riscv::VLEN-1]}},update_vaddr}, 1'b1}; // MUTANT M12: misclassify PTW load page fault as access fault",
            ),
        ),
        build_recipe=CVA6_BUILD,
    ),
    ("cva6-clean", "M16"): MutantDefinition(
        dut="cva6-clean",
        mutant_id="M16",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _cva6_tlb_edit(
                "if (flush_i) begin",
                "if (1'b0) begin // MUTANT M16: ignore TLB invalidation",
            ),
        ),
        build_recipe=CVA6_BUILD,
    ),
    ("cva6-clean", "M17"): MutantDefinition(
        dut="cva6-clean",
        mutant_id="M17",
        injection_layer="rtl_core",
        source_root_kind="chipyard-clean",
        edits=(
            _cva6_mmu_edit(
                "                        lsu_exception_o = {riscv::ST_ACCESS_FAULT, {{riscv::XLEN-riscv::PLEN{1'b0}}, lsu_paddr_o}, 1'b1};",
                "                        lsu_exception_o = misaligned_ex_q; // MUTANT M17: suppress translated store access faults so denied stores still update memory",
            ),
            _cva6_mmu_edit(
                "                lsu_exception_o = {riscv::ST_ACCESS_FAULT, {{riscv::XLEN-riscv::PLEN{1'b0}}, lsu_paddr_o}, 1'b1};",
                "                lsu_exception_o = misaligned_ex_q; // MUTANT M17: suppress bare store access faults so denied stores still update memory",
            ),
        ),
        build_recipe=CVA6_BUILD,
    ),
}


def materialize_semantic_mutants(
    *,
    artifact_root: Path,
    source_roots: Mapping[str, Path | str | None] | None = None,
    select: set[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    artifact_root = Path(artifact_root)
    manifest = json.loads((artifact_root / "manifests" / "mutants.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("mutants.json must be an object")

    results: list[dict[str, Any]] = []
    selected_entries = sorted(
        (
            entry
            for entry in manifest.get("entries") or []
            if isinstance(entry, dict)
            and (
                not select
                or (str(entry.get("dut") or ""), str(entry.get("mutant_id") or "")) in select
            )
        ),
        key=lambda item: (str(item.get("dut") or ""), str(item.get("mutant_id") or "")),
    )
    if not selected_entries:
        raise ValueError("no selected mutant entries")

    root_map = {
        dut: Path(value).expanduser().resolve()
        for dut, value in (source_roots or {}).items()
        if value is not None
    }

    for entry in selected_entries:
        dut = str(entry.get("dut") or "")
        mutant_id = str(entry.get("mutant_id") or "")
        definition = MUTANT_DEFINITIONS.get((dut, mutant_id))
        if definition is None:
            raise ValueError(f"unsupported semantic mutant definition: {dut}/{mutant_id}")
        source_root = root_map.get(dut) or _default_source_root_for_dut(dut)
        results.append(
            _materialize_one(
                artifact_root=artifact_root,
                entry=entry,
                definition=definition,
                source_root=source_root,
            )
        )

    summary = {
        "schema_version": SCHEMA_VERSION,
        "artifact_root": str(artifact_root),
        "materialized_count": len(results),
        "results": results,
    }
    _write_json(artifact_root / "manifests" / "mutant-materialization-summary.json", summary)
    return summary


def record_built_mutant_binary(
    *,
    artifact_root: Path,
    dut: str,
    mutant_id: str,
    binary_path: Path | str,
    target_root: Path | str | None = None,
) -> dict[str, Any]:
    artifact_root = Path(artifact_root)
    resolved_binary = Path(binary_path).expanduser().resolve()
    if not resolved_binary.exists():
        raise ValueError(f"built binary does not exist: {resolved_binary}")

    mutant_root = artifact_root / "mutants" / dut / mutant_id
    manifest_path = mutant_root / "build-manifest.json"
    if not manifest_path.exists():
        raise ValueError(f"missing build-manifest.json for {dut}/{mutant_id}: {manifest_path}")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"build-manifest.json must be an object for {dut}/{mutant_id}")

    digest = _file_sha256(resolved_binary)
    (mutant_root / "binary.sha256").write_text(digest + "\n", encoding="ascii")
    payload["status"] = "built"
    payload["binary_path"] = str(resolved_binary)
    payload["dut_bin"] = str(resolved_binary)
    payload["simulator_binary"] = str(resolved_binary)
    payload["binary_sha256"] = digest
    if target_root is not None:
        payload["target_root"] = str(Path(target_root).expanduser().resolve())
    _write_json(manifest_path, payload)

    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_root": str(artifact_root),
        "dut": dut,
        "mutant_id": mutant_id,
        "binary_path": str(resolved_binary),
        "binary_sha256": digest,
        "status": "built",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Materialize Section 7.6 semantic mutant patch/build artifacts")
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--dut", action="append", default=[])
    parser.add_argument("--mutant-id", action="append", default=[])
    parser.add_argument("--source-root", action="append", default=[])
    parser.add_argument("--record-built-binary", action="store_true")
    parser.add_argument("--binary-path", type=Path)
    parser.add_argument("--target-root", type=Path)
    args = parser.parse_args(argv)

    selection = _parse_selection(args.dut, args.mutant_id)
    if args.record_built_binary:
        if not selection or len(selection) != 1:
            raise ValueError("--record-built-binary requires exactly one DUT/mutant-id selection")
        if args.binary_path is None:
            raise ValueError("--record-built-binary requires --binary-path")
        dut, mutant_id = next(iter(selection))
        summary = record_built_mutant_binary(
            artifact_root=args.artifact_root,
            dut=dut,
            mutant_id=mutant_id,
            binary_path=args.binary_path,
            target_root=args.target_root,
        )
        print(
            f"recorded={summary['dut']}/{summary['mutant_id']} "
            f"binary_sha256={summary['binary_sha256']}"
        )
    else:
        summary = materialize_semantic_mutants(
            artifact_root=args.artifact_root,
            source_roots=_parse_source_roots(args.source_root),
            select=selection,
        )
        print(
            f"materialized={summary['materialized_count']} "
            f"summary={args.artifact_root / 'manifests' / 'mutant-materialization-summary.json'}"
        )
    return 0


def _materialize_one(
    *,
    artifact_root: Path,
    entry: Mapping[str, Any],
    definition: MutantDefinition,
    source_root: Path,
) -> dict[str, Any]:
    changed_files: dict[str, dict[str, str]] = {}
    target_files: list[str] = []
    for edit in definition.edits:
        path = source_root / edit.relative_path
        if not path.exists():
            raise ValueError(f"missing source file for {definition.dut}/{definition.mutant_id}: {path}")
        before = changed_files.get(edit.relative_path, {}).get("after")
        if before is None:
            before = path.read_text(encoding="utf-8", errors="replace")
        after = _apply_exact_replace(
            before=before,
            edit=edit,
            dut=definition.dut,
            mutant_id=definition.mutant_id,
        )
        previous_before = changed_files.get(edit.relative_path, {}).get("before", before)
        changed_files[edit.relative_path] = {"before": previous_before, "after": after}
        if edit.relative_path not in target_files:
            target_files.append(edit.relative_path)

    mutant_root = artifact_root / "mutants" / definition.dut / definition.mutant_id
    mutant_root.mkdir(parents=True, exist_ok=True)
    patch_text = "".join(
        _unified_diff(relative_path, payload["before"], payload["after"])
        for relative_path, payload in changed_files.items()
    )
    if not patch_text:
        raise ValueError(f"empty patch for {definition.dut}/{definition.mutant_id}")
    patch_path = mutant_root / "patch.diff"
    patch_path.write_text(patch_text, encoding="ascii")

    prepare_script_path = mutant_root / "prepare_source_root.sh"
    sync_paths = _working_tree_sync_paths(definition)
    _write_prepare_source_root_script(
        prepare_script_path,
        source_root=source_root,
        sync_paths=sync_paths,
        cleanup_paths=_stale_build_cleanup_paths(definition),
    )

    apply_script_path = mutant_root / "apply_patch.sh"
    _write_apply_script(apply_script_path, source_root=source_root, patch_path=patch_path)
    build_driver_path = mutant_root / "build_mutant.sh"
    _write_build_driver_script(
        build_driver_path,
        driver_root=_project_root(),
        build_recipe=definition.build_recipe,
    )

    build_manifest = {
        "schema_version": SCHEMA_VERSION,
        "dut": definition.dut,
        "mutant_id": definition.mutant_id,
        "fault_family": str(entry.get("fault_family") or ""),
        "injected_semantic_deviation": str(entry.get("injected_semantic_deviation") or ""),
        "source_root_kind": definition.source_root_kind,
        "source_root": str(source_root),
        "injection_layer": definition.injection_layer,
        "status": "patch_materialized_unbuilt",
        "notes": definition.notes,
        "patch_path": _relpath(artifact_root, patch_path),
        "apply_script": _relpath(artifact_root, apply_script_path),
        "apply_requires_target_root_argument": True,
        "source_root_preparation": {
            "strategy": "git_clone_shared_then_rsync_working_tree",
            "script": _relpath(artifact_root, prepare_script_path),
            "requires_target_root_argument": True,
            "initializes_submodule_metadata": True,
            "sync_working_tree_paths": sync_paths,
            "symlink_paths": list(REQUIRED_SOURCE_SYMLINK_PATHS),
        },
        "target_files": target_files,
        "builder": {
            "driver_root_kind": "pmpfuzz_checkout",
            "driver_root": str(_project_root()),
            "build_driver_script": _relpath(artifact_root, build_driver_path),
            "requires_target_root_argument": True,
            "script_relative_path": definition.build_recipe.build_script_relative_path,
            "env": {
                "CHIPYARD_DIR": "<mutant_source_root>",
                "CONFIG": definition.build_recipe.config,
                "JOBS": definition.build_recipe.jobs,
                "TIMEOUT": definition.build_recipe.timeout,
                "VERILATOR_THREADS": definition.build_recipe.verilator_threads,
            },
            "expected_binary_relative_path": definition.build_recipe.expected_binary_relative_path,
        },
    }
    _write_json(mutant_root / "build-manifest.json", build_manifest)

    return {
        "dut": definition.dut,
        "mutant_id": definition.mutant_id,
        "status": build_manifest["status"],
        "target_files": list(target_files),
        "patch_path": build_manifest["patch_path"],
    }


def _apply_exact_replace(*, edit: TextEdit, dut: str, mutant_id: str, before: str) -> str:
    count = before.count(edit.before)
    if count != edit.expected_matches:
        raise ValueError(
            f"{dut}/{mutant_id} expected {edit.expected_matches} match(es) for {edit.relative_path}, found {count}"
        )
    after = before.replace(edit.before, edit.after, edit.expected_matches)
    if after == before:
        raise ValueError(f"{dut}/{mutant_id} replacement left {edit.relative_path} unchanged")
    return after


def _default_source_root_for_dut(dut: str) -> Path:
    if dut not in {"rocket-clean", "boom-clean", "cva6-clean"}:
        raise ValueError(f"no default source root for DUT: {dut}")
    return DEFAULT_CLEAN_CHIPYARD_DIR.resolve()


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _parse_selection(duts: list[str], mutant_ids: list[str]) -> set[tuple[str, str]] | None:
    normalized_duts = [item.strip() for item in duts if item.strip()]
    normalized_mutants = [item.strip() for item in mutant_ids if item.strip()]
    if not normalized_duts and not normalized_mutants:
        return None
    if not normalized_duts or not normalized_mutants:
        raise ValueError("selection requires both --dut and --mutant-id")
    return {(dut, mutant_id) for dut in normalized_duts for mutant_id in normalized_mutants}


def _parse_source_roots(items: list[str]) -> dict[str, Path]:
    mapping: dict[str, Path] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"expected DUT=PATH mapping, got {item!r}")
        dut, raw_path = item.split("=", 1)
        if not dut.strip() or not raw_path.strip():
            raise ValueError(f"invalid DUT=PATH mapping: {item!r}")
        mapping[dut.strip()] = Path(raw_path.strip()).expanduser().resolve()
    return mapping


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _relpath(root: Path, target: Path) -> str:
    return target.relative_to(root).as_posix()


def _working_tree_sync_paths(definition: MutantDefinition) -> list[str]:
    sync_paths = {edit.relative_path.split("/", 1)[0] + "/" for edit in definition.edits}
    return sorted(sync_paths)


def _stale_build_cleanup_paths(definition: MutantDefinition) -> list[str]:
    if definition.dut != "cva6-clean":
        return []
    return [
        ".classpath_cache/chipyard.jar",
        "generators/chipyard/target",
        "generators/cva6/target",
        "project/target",
    ]


def _unified_diff(relative_path: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{relative_path}",
            tofile=f"b/{relative_path}",
        )
    )


def _write_prepare_source_root_script(
    path: Path,
    *,
    source_root: Path,
    sync_paths: list[str],
    cleanup_paths: list[str] | None = None,
) -> None:
    quoted_source_root = shlex.quote(str(source_root))
    cleanup_paths = list(cleanup_paths or [])
    lines = [
        "#!/usr/bin/env sh",
        "set -eu",
        "",
        f"SOURCE_ROOT={quoted_source_root}",
        'if [ "$#" -lt 1 ]; then',
        '  echo "usage: $0 <isolated-target-root>" >&2',
        "  exit 2",
        "fi",
        'TARGET_ROOT="$1"',
        'if [ "$TARGET_ROOT" = "$SOURCE_ROOT" ]; then',
        '  echo "target root must not equal source root: $TARGET_ROOT" >&2',
        "  exit 2",
        "fi",
        'if [ ! -d "$SOURCE_ROOT/generators" ]; then',
        '  echo "missing generators tree in source root: $SOURCE_ROOT" >&2',
        "  exit 2",
        "fi",
        'if [ ! -e "$SOURCE_ROOT/.conda-env" ]; then',
        '  echo "missing .conda-env in source root: $SOURCE_ROOT/.conda-env" >&2',
        "  exit 2",
        "fi",
        'if [ ! -x "$SOURCE_ROOT/tools/circt/bin/firtool" ]; then',
        '  echo "missing firtool in source root: $SOURCE_ROOT/tools/circt/bin/firtool" >&2',
        "  exit 2",
        "fi",
        'PREPARED_STAMP="$TARGET_ROOT/.pmpfuzz-mutant-source-ready"',
        'if [ ! -e "$TARGET_ROOT" ]; then',
        '  git clone --shared "$SOURCE_ROOT" "$TARGET_ROOT"',
        '  NEED_SUBMODULE_BOOTSTRAP=1',
        "elif [ ! -d \"$TARGET_ROOT/.git\" ]; then",
        '  echo "target root exists but is not a git worktree: $TARGET_ROOT" >&2',
        "  exit 2",
        'elif [ -f "$PREPARED_STAMP" ]; then',
        '  NEED_SUBMODULE_BOOTSTRAP=0',
        "else",
        '  NEED_SUBMODULE_BOOTSTRAP=1',
        "fi",
        'if [ "$NEED_SUBMODULE_BOOTSTRAP" = "1" ]; then',
        '  if [ -f "$TARGET_ROOT/scripts/init-submodules-no-riscv-tools-nolog.sh" ]; then',
        '    (cd "$TARGET_ROOT" && bash scripts/init-submodules-no-riscv-tools-nolog.sh)',
        "  else",
        '    git -C "$TARGET_ROOT" submodule update --init --recursive',
        "  fi",
        "fi",
    ]
    for sync_path in sync_paths:
        quoted_sync_path = shlex.quote(sync_path)
        lines.extend(
            [
                f'mkdir -p "$TARGET_ROOT/{sync_path.rstrip("/")}"',
                f'rsync -a --delete --exclude=.git "$SOURCE_ROOT"/{quoted_sync_path} "$TARGET_ROOT"/{quoted_sync_path}',
            ]
        )
        if sync_path.rstrip("/") == "generators":
            lines.extend(
                [
                    "# Preserve immediate generator submodule markers so build.sbt discovers optional DUT projects.",
                    'for marker in "$SOURCE_ROOT"/generators/*/.git; do',
                    '  [ -e "$marker" ] || continue',
                    '  module_dir="$(dirname "$marker")"',
                    '  module_name="$(basename "$module_dir")"',
                    '  target_module_dir="$TARGET_ROOT/generators/$module_name"',
                    '  target_marker="$target_module_dir/.git"',
                    '  source_module_meta="$SOURCE_ROOT/.git/modules/generators/$module_name"',
                    '  target_module_meta="$TARGET_ROOT/.git/modules/generators/$module_name"',
                    '  if [ -d "$marker" ]; then',
                    '    rm -rf "$target_marker"',
                    '    cp -R "$marker" "$target_marker"',
                    '    continue',
                    '  fi',
                    '  if [ -d "$source_module_meta" ]; then',
                    '    mkdir -p "$TARGET_ROOT/.git/modules/generators"',
                    '    rsync -a --delete "$source_module_meta"/ "$target_module_meta"/',
                    '  fi',
                    '  cp "$marker" "$target_marker"',
                    'done',
                ]
            )
    lines.extend(
        [
            'if [ ! -e "$TARGET_ROOT/.conda-env" ]; then',
            '  ln -s "$SOURCE_ROOT/.conda-env" "$TARGET_ROOT/.conda-env"',
            "fi",
            'if [ -e "$TARGET_ROOT/tools/circt" ] && [ ! -x "$TARGET_ROOT/tools/circt/bin/firtool" ]; then',
            '  if [ -L "$TARGET_ROOT/tools/circt" ]; then',
            '    rm "$TARGET_ROOT/tools/circt"',
            "  else",
            '    rmdir "$TARGET_ROOT/tools/circt" 2>/dev/null || {',
            '      echo "target tools/circt exists but is unusable: $TARGET_ROOT/tools/circt" >&2',
            "      exit 2",
            "    }",
            "  fi",
            "fi",
            'if [ ! -e "$TARGET_ROOT/tools/circt" ]; then',
            '  mkdir -p "$TARGET_ROOT/tools"',
            '  ln -s "$SOURCE_ROOT/tools/circt" "$TARGET_ROOT/tools/circt"',
            "fi",
        ]
    )
    if cleanup_paths:
        lines.append("# Remove stale build outputs that can hide newly synced DUT sources.")
        for cleanup_path in cleanup_paths:
            lines.append(f'rm -rf "$TARGET_ROOT/{cleanup_path}"')
    lines.extend(
        [
            'touch "$PREPARED_STAMP"',
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="ascii")
    try:
        path.chmod(0o755)
    except OSError:
        pass


def _write_build_driver_script(path: Path, *, driver_root: Path, build_recipe: BuildRecipe) -> None:
    quoted_driver_root = shlex.quote(str(driver_root.resolve()))
    quoted_relative_script = shlex.quote(build_recipe.build_script_relative_path)
    shared_cache_root = driver_root.resolve().parent / ".pmpfuzz-sbt-cache"
    quoted_shared_cache_root = shlex.quote(str(shared_cache_root))
    lines = [
        "#!/usr/bin/env sh",
        "set -eu",
        "",
        f"DRIVER_ROOT={quoted_driver_root}",
        f"SHARED_SBT_CACHE_ROOT={quoted_shared_cache_root}",
        'if [ "$#" -lt 1 ]; then',
        '  echo "usage: $0 <isolated-target-root>" >&2',
        "  exit 2",
        "fi",
        'TARGET_ROOT="$1"',
        "if [ ! -d \"$DRIVER_ROOT/.git\" ]; then",
        '  echo "driver root must be a PMPFuzz git worktree: $DRIVER_ROOT" >&2',
        "  exit 2",
        "fi",
        "if [ ! -d \"$TARGET_ROOT/.git\" ]; then",
        '  echo "target root must be a git worktree: $TARGET_ROOT" >&2',
        "  exit 2",
        "fi",
        'export CHIPYARD_DIR="$TARGET_ROOT"',
        f'export CONFIG="{build_recipe.config}"',
        f'export JOBS="{build_recipe.jobs}"',
        f'export TIMEOUT="{build_recipe.timeout}"',
        f'export VERILATOR_THREADS="{build_recipe.verilator_threads}"',
        'mkdir -p "$SHARED_SBT_CACHE_ROOT/.ivy2" "$SHARED_SBT_CACHE_ROOT/.sbt/boot"',
        'if [ -z "${SBT_OPTS:-}" ]; then',
        '  export SBT_OPTS="-Dsbt.ivy.home=$SHARED_SBT_CACHE_ROOT/.ivy2 -Dsbt.global.base=$SHARED_SBT_CACHE_ROOT/.sbt -Dsbt.boot.directory=$SHARED_SBT_CACHE_ROOT/.sbt/boot/ -Dsbt.color=always -Dsbt.supershell=false -Dsbt.server.forcestart=true"',
        "fi",
        'cd "$DRIVER_ROOT"',
        f'exec bash "./{quoted_relative_script}"',
        "",
    ]
    path.write_text("\n".join(lines), encoding="ascii")
    try:
        path.chmod(0o755)
    except OSError:
        pass


def _write_apply_script(path: Path, *, source_root: Path, patch_path: Path) -> None:
    quoted_source_root = shlex.quote(str(source_root))
    quoted_patch = shlex.quote(str(patch_path.resolve()))
    lines = [
        "#!/usr/bin/env sh",
        "set -eu",
        "",
        f"SOURCE_ROOT={quoted_source_root}",
        'if [ "$#" -lt 1 ]; then',
        '  echo "usage: $0 <isolated-target-root>" >&2',
        "  exit 2",
        "fi",
        'TARGET_ROOT="$1"',
        "if [ ! -d \"$TARGET_ROOT/.git\" ]; then",
        "  echo \"target root must be a git worktree: $TARGET_ROOT\" >&2",
        "  exit 2",
        "fi",
        'SOURCE_CANON="$(cd "$SOURCE_ROOT" && pwd -P)"',
        'TARGET_CANON="$(cd "$TARGET_ROOT" && pwd -P)"',
        'if [ "$TARGET_CANON" = "$SOURCE_CANON" ]; then',
        '  echo "refusing to patch source root directly: $TARGET_ROOT" >&2',
        "  exit 2",
        "fi",
        f"(cd \"$TARGET_ROOT\" && git apply --check {quoted_patch})",
        f"(cd \"$TARGET_ROOT\" && git apply {quoted_patch})",
        "",
    ]
    path.write_text("\n".join(lines), encoding="ascii")
    try:
        path.chmod(0o755)
    except OSError:
        # Windows may ignore or reject POSIX mode bits; the content remains usable via `sh script`.
        pass


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
