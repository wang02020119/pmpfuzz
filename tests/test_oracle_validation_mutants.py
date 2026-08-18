from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.evaluation.oracle_validation.materialize_semantic_mutants import (
    MUTANT_DEFINITIONS,
    _stale_build_cleanup_paths,
    _write_prepare_source_root_script,
)


class OracleValidationMutantDefinitionTest(unittest.TestCase):
    def test_boom_m17_suppresses_store_access_fault_delivery_at_boom_tlb_response(self):
        mutant = MUTANT_DEFINITIONS[("boom-clean", "M17")]

        self.assertEqual(len(mutant.edits), 1)
        self.assertEqual(
            [edit.relative_path for edit in mutant.edits],
            [
                "generators/boom/src/main/scala/v3/lsu/tlb.scala",
            ],
        )
        befores = [edit.before for edit in mutant.edits]
        afters = [edit.after for edit in mutant.edits]

        self.assertTrue(
            any(
                "io.resp(w).ae.st   := (ae_valid_array(w) & ae_st_array(w) & hits(w)).orR"
                in item
                for item in befores
            )
        )
        self.assertTrue(
            any(
                "io.resp(w).ae.st   := false.B // MUTANT M17: suppress store access faults so denied stores still update memory"
                in item
                for item in afters
            )
        )

    def test_cva6_m04_tracks_match_state_when_later_entries_override_priority(self):
        mutant = MUTANT_DEFINITIONS[("cva6-clean", "M04")]

        self.assertEqual(len(mutant.edits), 4)
        self.assertTrue(all(edit.relative_path.endswith("pmp.sv") for edit in mutant.edits))

        befores = [edit.before for edit in mutant.edits]
        afters = [edit.after for edit in mutant.edits]

        self.assertTrue(any("int i;\n\n            allow_o = 1'b0;" in item for item in befores))
        self.assertTrue(any("bit matched;" in item and "matched = 1'b0;" in item for item in afters))
        self.assertTrue(any("if (match[i]) begin\n                        if ((access_type_i & conf_i[i].access_type) != access_type_i) allow_o = 1'b0;" in item for item in befores))
        self.assertTrue(any("if (match[i]) begin\n                        matched = 1'b1;" in item for item in afters))
        self.assertTrue(any("break;" in item for item in befores))
        self.assertTrue(any("later matching entries override the first match" in item for item in afters))
        self.assertTrue(any("if (i == NR_ENTRIES) begin // no PMP entry matched the address" in item for item in befores))
        self.assertTrue(any("if (!matched) begin // MUTANT M04: only use the default path when no PMP entry matched" in item for item in afters))

    def test_cva6_m12_misclassifies_dtlb_and_ptw_page_faults_as_access_faults(self):
        mutant = MUTANT_DEFINITIONS[("cva6-clean", "M12")]

        self.assertEqual(len(mutant.edits), 4)
        self.assertTrue(all(edit.relative_path.endswith("mmu.sv") for edit in mutant.edits))

        befores = [edit.before for edit in mutant.edits]
        afters = [edit.after for edit in mutant.edits]

        self.assertTrue(any("STORE_PAGE_FAULT" in item and "lsu_vaddr_q" in item for item in befores))
        self.assertTrue(any("LOAD_PAGE_FAULT" in item and "lsu_vaddr_q" in item for item in befores))
        self.assertTrue(any("STORE_PAGE_FAULT" in item and "update_vaddr" in item for item in befores))
        self.assertTrue(any("LOAD_PAGE_FAULT" in item and "update_vaddr" in item for item in befores))
        self.assertTrue(any("ST_ACCESS_FAULT" in item and "misclassify store page fault as access fault" in item for item in afters))
        self.assertTrue(any("LD_ACCESS_FAULT" in item and "misclassify load page fault as access fault" in item for item in afters))
        self.assertTrue(any("ST_ACCESS_FAULT" in item and "misclassify PTW store page fault as access fault" in item for item in afters))
        self.assertTrue(any("LD_ACCESS_FAULT" in item and "misclassify PTW load page fault as access fault" in item for item in afters))

    def test_cva6_m17_suppresses_store_access_fault_delivery_in_mmu(self):
        mutant = MUTANT_DEFINITIONS[("cva6-clean", "M17")]

        self.assertEqual(len(mutant.edits), 2)
        self.assertTrue(all(edit.relative_path.endswith("mmu.sv") for edit in mutant.edits))

        befores = [edit.before for edit in mutant.edits]
        afters = [edit.after for edit in mutant.edits]

        self.assertEqual(
            sum("lsu_exception_o = {riscv::ST_ACCESS_FAULT" in item for item in befores),
            2,
        )
        self.assertTrue(any("lsu_exception_o = misaligned_ex_q; // MUTANT M17: suppress translated store access faults so denied stores still update memory" in item for item in afters))
        self.assertTrue(any("lsu_exception_o = misaligned_ex_q; // MUTANT M17: suppress bare store access faults so denied stores still update memory" in item for item in afters))

    def test_m09_bypasses_translated_final_access_permissions_and_exception(self):
        mutant = MUTANT_DEFINITIONS[("rocket-clean", "M09")]

        self.assertEqual(len(mutant.edits), 4)
        relative_paths = [edit.relative_path for edit in mutant.edits]
        self.assertEqual(
            relative_paths,
            [
                "generators/rocket-chip/src/main/scala/rocket/TLB.scala",
                "generators/rocket-chip/src/main/scala/rocket/TLB.scala",
                "generators/rocket-chip/src/main/scala/rocket/TLB.scala",
                "generators/rocket-chip/src/main/scala/rocket/TLB.scala",
            ],
        )
        befores = [edit.before for edit in mutant.edits]
        afters = [edit.after for edit in mutant.edits]

        self.assertTrue(any("newEntry.ae_final := io.ptw.resp.bits.ae_final" in item for item in befores))
        self.assertTrue(any("newEntry.ae_final := false.B // MUTANT M09: ignore final-access PMP faults" in item for item in afters))
        self.assertTrue(any("newEntry.pr := prot_r" in item for item in befores))
        self.assertTrue(
            any(
                "newEntry.pr := pma.io.resp.r && !deny_access_to_debug // MUTANT M09: ignore translated final-access PMP read permission" in item
                for item in afters
            )
        )
        self.assertTrue(any("newEntry.pw := prot_w" in item for item in befores))
        self.assertTrue(
            any(
                "newEntry.pw := pma.io.resp.w && !deny_access_to_debug // MUTANT M09: ignore translated final-access PMP write permission" in item
                for item in afters
            )
        )
        self.assertTrue(any("newEntry.px := prot_x" in item for item in befores))
        self.assertTrue(
            any(
                "newEntry.px := pma.io.resp.x && !deny_access_to_debug // MUTANT M09: ignore translated final-access PMP execute permission" in item
                for item in afters
            )
        )

    def test_prepare_source_root_script_supports_fast_reuse_after_first_bootstrap(self):
        with tempfile.TemporaryDirectory() as tmp:
            script_path = Path(tmp) / "prepare_source_root.sh"
            _write_prepare_source_root_script(
                script_path,
                source_root=Path("/tmp/source-root"),
                sync_paths=["generators/", "tools/"],
            )
            text = script_path.read_text(encoding="ascii")

        self.assertIn('PREPARED_STAMP="$TARGET_ROOT/.pmpfuzz-mutant-source-ready"', text)
        self.assertIn('elif [ -f "$PREPARED_STAMP" ]; then', text)
        self.assertIn('NEED_SUBMODULE_BOOTSTRAP=0', text)
        self.assertIn('if [ "$NEED_SUBMODULE_BOOTSTRAP" = "1" ]; then', text)
        self.assertIn('git -C "$TARGET_ROOT" submodule update --init --recursive', text)
        self.assertIn('touch "$PREPARED_STAMP"', text)

    def test_cva6_prepare_source_root_script_cleans_stale_build_outputs(self):
        cleanup_paths = _stale_build_cleanup_paths(MUTANT_DEFINITIONS[("cva6-clean", "M02")])

        with tempfile.TemporaryDirectory() as tmp:
            script_path = Path(tmp) / "prepare_source_root.sh"
            _write_prepare_source_root_script(
                script_path,
                source_root=Path("/tmp/source-root"),
                sync_paths=["generators/"],
                cleanup_paths=cleanup_paths,
            )
            text = script_path.read_text(encoding="ascii")

        self.assertEqual(
            cleanup_paths,
            [
                ".classpath_cache/chipyard.jar",
                "generators/chipyard/target",
                "generators/cva6/target",
                "project/target",
            ],
        )
        self.assertIn('rm -rf "$TARGET_ROOT/.classpath_cache/chipyard.jar"', text)
        self.assertIn('rm -rf "$TARGET_ROOT/generators/chipyard/target"', text)
        self.assertIn('rm -rf "$TARGET_ROOT/generators/cva6/target"', text)
        self.assertIn('rm -rf "$TARGET_ROOT/project/target"', text)

    def test_generators_sync_preserves_submodule_markers_for_optional_dut_projects(self):
        with tempfile.TemporaryDirectory() as tmp:
            script_path = Path(tmp) / "prepare_source_root.sh"
            _write_prepare_source_root_script(
                script_path,
                source_root=Path("/tmp/source-root"),
                sync_paths=["generators/"],
            )
            text = script_path.read_text(encoding="ascii")

        self.assertIn('for marker in "$SOURCE_ROOT"/generators/*/.git; do', text)
        self.assertIn('source_module_meta="$SOURCE_ROOT/.git/modules/generators/$module_name"', text)
        self.assertIn('target_module_meta="$TARGET_ROOT/.git/modules/generators/$module_name"', text)
        self.assertIn('mkdir -p "$TARGET_ROOT/.git/modules/generators"', text)
        self.assertIn('rsync -a --delete "$source_module_meta"/ "$target_module_meta"/', text)
        self.assertIn('cp "$marker" "$target_marker"', text)


if __name__ == "__main__":
    unittest.main()
