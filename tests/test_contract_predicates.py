import tempfile
import unittest
from pathlib import Path

from pmpfuzz.coverage import coverage_from_run
from pmpfuzz.mmu import PageTableEntry, Sv39Mapping, TranslationMode
from pmpfuzz.pmp import Access, AddressMode, PmpEntry, Privilege
from pmpfuzz.scenario import AccessProbe, PmpScenario, ScenarioGenerator
from pmpfuzz.schema import scenario_to_case_dict, write_json
from pmpfuzz.semantic_coverage import (
    CORE_STATEFUL_TARGET,
    build_schedule,
    contract_predicates_for_case,
    predicate_gap_from_runs,
)
from pmpfuzz.triage import write_report


class ContractPredicatesTest(unittest.TestCase):
    def test_case_schema_embeds_predicates_derived_from_contract_trace(self):
        scenario = ScenarioGenerator(seed=2, include_smepmp=False, profile="sv39-ptw-pmp-matrix").generate_batch(1)[0]

        case = scenario_to_case_dict(scenario, seed=2, index=0)

        self.assertIn("contract_predicates", case)
        self.assertIn("sv39.ptw_pmp_deny_before_final", case["contract_predicates"])
        self.assertIn("pmp.ptw_match_napot", case["contract_predicates"])
        self.assertEqual(case["contract_predicates"], contract_predicates_for_case(case))

    def test_predicates_capture_no_match_and_pte_fault_rules_without_profile_names(self):
        no_match = PmpScenario(
            name="su_no_match",
            entries=[],
            privilege=Privilege.U,
            probe=AccessProbe(access=Access.LOAD, physical_address=0x90000000, size=4, offset_name="unmatched"),
            mprv=False,
            mpp=Privilege.M,
        )
        invalid_pte = PmpScenario(
            name="pte_invalid",
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80010000, size=0x8000),
                    read=True,
                    write=False,
                    execute=False,
                    locked=False,
                )
            ],
            privilege=Privilege.U,
            probe=AccessProbe(
                access=Access.LOAD,
                physical_address=0x80008000,
                virtual_address=0x80000000,
                size=4,
                offset_name="inside",
            ),
            mprv=False,
            mpp=Privilege.M,
            translation=TranslationMode.SV39,
            sv39=Sv39Mapping(
                virtual_page=0x80000000,
                physical_page=0x80008000,
                root_table=0x80010000,
                walk_addresses=(0x80010010, 0x80011000, 0x80012000),
                pte=PageTableEntry(read=True, write=False, execute=False, user=True, accessed=True, dirty=False, valid=False),
            ),
        )

        no_match_case = scenario_to_case_dict(no_match, seed=1, index=0)
        invalid_case = scenario_to_case_dict(invalid_pte, seed=1, index=1)

        self.assertIn("pmp.su_no_match_default_deny", no_match_case["contract_predicates"])
        self.assertIn("sv39.pte_invalid_page_fault", invalid_case["contract_predicates"])
        self.assertNotIn("profile=", "\n".join(no_match_case["contract_predicates"]))

    def test_coverage_and_report_include_predicate_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=5, include_smepmp=False, profile="pmp-side-effect").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=5, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            coverage = coverage_from_run(run_dir)
            gap = predicate_gap_from_runs([run_dir], target=CORE_STATEFUL_TARGET,
                                          coverage_basis="manifest")
            report_path = write_report(run_dir)
            report = report_path.read_text(encoding="ascii")

        self.assertIn("stateful.denied_store_no_side_effect", coverage["contract_predicates"])
        self.assertGreater(gap["total_target_predicates"], gap["covered_target_predicates"])
        self.assertTrue(gap["top_predicate_gaps"])
        self.assertIn("Execution-Qualified Coverage", report)

    def test_predicate_scheduler_prioritizes_missing_contract_predicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "seed"
            scenario = ScenarioGenerator(seed=7, include_smepmp=False, profile="pmp-boundary").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=7, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)

            first = build_schedule(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                coverage_mode="predicates",
                max_cases=8,
                seed=20260628,
                coverage_basis="manifest",
            )
            second = build_schedule(
                [run_dir],
                target=CORE_STATEFUL_TARGET,
                coverage_mode="predicates",
                max_cases=8,
                seed=20260628,
                coverage_basis="manifest",
            )

        self.assertEqual(first, second)
        self.assertEqual(first["coverage_mode"], "predicates")
        self.assertEqual(len(first["entries"]), 8)
        self.assertTrue(all(entry["contract_predicates"] for entry in first["entries"]))
        self.assertTrue(all(entry["covers_missing_predicates"] for entry in first["entries"]))


if __name__ == "__main__":
    unittest.main()
