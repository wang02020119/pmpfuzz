from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pmpfuzz.mmu import PageTableEntry, Sv39Mapping, TranslationMode
from pmpfuzz.pmp import Access, AddressMode, Mseccfg, PmpEntry, Privilege
from pmpfuzz.scenario import AccessProbe, PmpScenario, TARGET_BASE, TARGET_VA
from pmpfuzz.scenario_codec import scenario_to_spec
from scripts.evaluation.oracle_validation.generate_reference_cases import build_reference_corpus
from scripts.evaluation.oracle_validation.reference_model import (
    PRIMARY_SPEC_REVISION,
    build_reference_label,
)


def _napot(base: int, size: int, *, index: int, read: bool, write: bool, execute: bool) -> PmpEntry:
    return PmpEntry(
        index=index,
        address_mode=AddressMode.NAPOT,
        pmpaddr=PmpEntry.encode_napot(base=base, size=size),
        read=read,
        write=write,
        execute=execute,
        locked=False,
    )


class OracleValidationReferenceModelTest(unittest.TestCase):
    def test_reference_model_does_not_import_production_oracle_or_judgment(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "evaluation"
            / "oracle_validation"
            / "reference_model.py"
        )
        text = path.read_text(encoding="utf-8")
        self.assertNotIn("pmpfuzz.oracle", text)
        self.assertNotIn("pmpfuzz.judgment", text)

    def test_bare_pmp_allow_label(self):
        scenario = PmpScenario(
            name="bare_allow",
            entries=[_napot(TARGET_BASE, 0x1000, index=0, read=True, write=False, execute=False)],
            privilege=Privilege.U,
            probe=AccessProbe(access=Access.LOAD, physical_address=TARGET_BASE, size=4, offset_name="inside"),
            mprv=False,
            mpp=Privilege.M,
            mseccfg=Mseccfg(),
            profile="unit-bare",
        )
        label = build_reference_label(
            {
                "case_id": "C1-0001",
                "family": "C1.bare_pmp_decisions",
                "scenario_spec": scenario_to_spec(scenario),
            },
            spec_revision=PRIMARY_SPEC_REVISION,
        )

        self.assertTrue(label["expected_allowed"])
        self.assertIsNone(label["expected_trap_cause"])
        self.assertEqual(label["expected_stage"], "none")
        self.assertEqual(label["expected_side_effect"], "not_applicable")

    def test_sv39_ptw_l1_deny_label(self):
        mapping = Sv39Mapping(
            virtual_page=TARGET_VA,
            physical_page=TARGET_BASE,
            root_table=0x80010000,
            walk_addresses=(0x80010010, 0x80013000, 0x80014000),
            pte=PageTableEntry(
                read=True,
                write=False,
                execute=False,
                user=True,
                accessed=True,
                dirty=False,
                valid=True,
            ),
        )
        scenario = PmpScenario(
            name="ptw_l1_deny",
            entries=[
                _napot(0x80010000, 0x1000, index=0, read=True, write=False, execute=False),
                _napot(0x80013000, 0x1000, index=1, read=False, write=False, execute=False),
                _napot(0x80014000, 0x1000, index=2, read=True, write=True, execute=False),
                _napot(TARGET_BASE, 0x1000, index=3, read=True, write=False, execute=False),
            ],
            privilege=Privilege.U,
            probe=AccessProbe(
                access=Access.LOAD,
                physical_address=TARGET_BASE,
                virtual_address=TARGET_VA,
                size=4,
                offset_name="inside",
            ),
            mprv=False,
            mpp=Privilege.M,
            mseccfg=Mseccfg(),
            translation=TranslationMode.SV39,
            sv39=mapping,
            profile="unit-sv39-ptw",
        )
        label = build_reference_label(
            {
                "case_id": "C4-0001",
                "family": "C4.ptw_and_translated_access",
                "scenario_spec": scenario_to_spec(scenario),
            },
            spec_revision=PRIMARY_SPEC_REVISION,
        )

        self.assertFalse(label["expected_allowed"])
        self.assertEqual(label["expected_trap_cause"], 5)
        self.assertEqual(label["expected_stage"], "page_table_walk")
        self.assertEqual(label["expected_ptw_level"], "L1")
        self.assertEqual(label["expected_fault_address"], "0x80013000")

    def test_stateful_store_label_requires_side_effect(self):
        scenario = PmpScenario(
            name="stateful_store",
            entries=[_napot(TARGET_BASE, 0x1000, index=0, read=True, write=True, execute=False)],
            privilege=Privilege.S,
            probe=AccessProbe(access=Access.STORE, physical_address=TARGET_BASE, size=4, offset_name="inside"),
            mprv=False,
            mpp=Privilege.M,
            mseccfg=Mseccfg(),
            profile="unit-stateful",
            stateful_sequence={
                "kind": "unit-stateful",
                "warmup": False,
                "mutation": "none",
                "fence": "none",
                "final_probe": "repeat",
            },
        )
        label = build_reference_label(
            {
                "case_id": "C6-0001",
                "family": "C6.stateful_transitions_side_effects",
                "scenario_spec": scenario_to_spec(scenario),
            },
            spec_revision=PRIMARY_SPEC_REVISION,
        )

        self.assertTrue(label["expected_allowed"])
        self.assertEqual(label["expected_stage"], "stateful_final")
        self.assertEqual(label["expected_side_effect"], "required_store_side_effect")

    def test_reference_corpus_has_432_cases_and_matching_labels(self):
        cases, labels, factor_report = build_reference_corpus(
            generator_seed=7601,
            spec_revision=PRIMARY_SPEC_REVISION,
        )
        self.assertEqual(len(cases), 432)
        self.assertEqual(len(labels), 432)
        self.assertEqual(factor_report["case_count"], 432)
        self.assertEqual(factor_report["family_counts"]["C1.bare_pmp_decisions"], 72)
        self.assertEqual(factor_report["family_counts"]["C2.matching_priority_boundaries"], 72)
        self.assertEqual(factor_report["family_counts"]["C3.sv39_pte_permissions"], 96)
        self.assertEqual(factor_report["family_counts"]["C4.ptw_and_translated_access"], 72)
        self.assertEqual(factor_report["family_counts"]["C5.exception_precedence_metadata"], 48)
        self.assertEqual(factor_report["family_counts"]["C6.stateful_transitions_side_effects"], 72)

    def test_reference_corpus_accepts_custom_family_plan(self):
        cases, labels, factor_report = build_reference_corpus(
            generator_seed=7607,
            spec_revision=PRIMARY_SPEC_REVISION,
            family_plan=[
                {
                    "family": "C1.bare_pmp_decisions",
                    "profile": "pmp-boundary",
                    "start": 0,
                    "count": 2,
                },
                {
                    "family": "C6.stateful_transitions_side_effects",
                    "profile": "pmp-side-effect",
                    "start": 0,
                    "count": 1,
                },
            ],
        )

        self.assertEqual(len(cases), 3)
        self.assertEqual(len(labels), 3)
        self.assertEqual(factor_report["case_count"], 3)
        self.assertEqual(factor_report["family_counts"]["C1.bare_pmp_decisions"], 2)
        self.assertEqual(factor_report["family_counts"]["C6.stateful_transitions_side_effects"], 1)
        self.assertEqual(len(factor_report["family_plan"]), 2)

    def test_reference_corpus_accepts_case_id_offsets(self):
        cases, labels, factor_report = build_reference_corpus(
            generator_seed=7608,
            spec_revision=PRIMARY_SPEC_REVISION,
            family_plan=[
                {
                    "family": "C1.bare_pmp_decisions",
                    "profile": "pmp-boundary",
                    "start": 0,
                    "count": 2,
                }
            ],
            case_id_offsets={"C1.bare_pmp_decisions": 72},
        )

        self.assertEqual([case["case_id"] for case in cases], ["C1-0073", "C1-0074"])
        self.assertEqual([label["case_id"] for label in labels], ["C1-0073", "C1-0074"])
        self.assertEqual(factor_report["case_id_offsets"]["C1.bare_pmp_decisions"], 72)


if __name__ == "__main__":
    unittest.main()
