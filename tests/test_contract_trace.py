import unittest

from pmpfuzz.mmu import PageTableEntry, Sv39Mapping, TranslationMode
from pmpfuzz.oracle import contract_trace_for_scenario
from pmpfuzz.pmp import Access, AddressMode, PmpEntry, Privilege
from pmpfuzz.scenario import AccessProbe, PmpScenario, ScenarioGenerator
from pmpfuzz.schema import scenario_to_case_dict


class ContractTraceTest(unittest.TestCase):
    def test_bare_pmp_denial_records_effective_privilege_and_match(self):
        scenario = PmpScenario(
            name="deny_s_load",
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80008000, size=0x1000),
                    read=False,
                    write=False,
                    execute=False,
                    locked=True,
                )
            ],
            privilege=Privilege.S,
            probe=AccessProbe(access=Access.LOAD, physical_address=0x80008000, size=4, offset_name="inside"),
            mprv=False,
            mpp=Privilege.M,
        )

        trace = contract_trace_for_scenario(scenario)

        self.assertEqual(trace["schema_version"], 1)
        self.assertEqual(trace["translation_mode"], "bare")
        self.assertEqual(trace["translation_stage"], "none")
        self.assertEqual(trace["trap_priority"], "access_fault")
        self.assertEqual(trace["effective_privilege"], "S")
        self.assertEqual(trace["pmp_checks"][0]["stage"], "bare")
        self.assertEqual(trace["pmp_checks"][0]["match_index"], 0)
        self.assertEqual(trace["pmp_checks"][0]["match_mode"], "napot")
        self.assertFalse(trace["pmp_checks"][0]["allowed"])

    def test_sv39_ptw_pmp_denial_records_walk_level_before_pte_and_final(self):
        scenario = ScenarioGenerator(seed=2, include_smepmp=False, profile="sv39-ptw-pmp-matrix").generate_batch(1)[0]

        trace = contract_trace_for_scenario(scenario)

        self.assertEqual(trace["translation_mode"], "sv39")
        self.assertEqual(trace["translation_stage"], "page_table_walk")
        self.assertEqual(trace["trap_priority"], "access_fault")
        self.assertEqual(trace["pmp_checks"][0]["stage"], "ptw")
        self.assertEqual(trace["pmp_checks"][0]["ptw_level"], "L2")
        self.assertFalse(trace["pmp_checks"][0]["allowed"])
        self.assertEqual(trace["pte_decision"]["decision"], "not_evaluated")
        self.assertFalse(any(check["stage"] == "final" for check in trace["pmp_checks"]))

    def test_sv39_pte_decision_records_permission_reason(self):
        scenario = PmpScenario(
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

        trace = contract_trace_for_scenario(scenario)

        self.assertEqual(trace["translation_stage"], "pte_permission")
        self.assertEqual(trace["trap_priority"], "page_fault")
        self.assertEqual(trace["pte_decision"]["decision"], "invalid")
        self.assertFalse(any(check["stage"] == "final" for check in trace["pmp_checks"]))

    def test_schema_embeds_contract_trace_and_stateful_phase_metadata(self):
        scenario = ScenarioGenerator(seed=3, include_smepmp=False, profile="tlb-stale-pmp").generate_batch(1)[0]

        case = scenario_to_case_dict(scenario, seed=3, index=0)
        trace = case["contract_trace"]

        self.assertEqual(trace["schema_version"], 1)
        self.assertEqual(trace["stateful"]["kind"], "tlb-stale-pmp")
        self.assertEqual(trace["stateful"]["mutation"], "pmpcfg-deny-target")
        self.assertEqual(trace["stateful"]["fence"], "with-sfence")
        self.assertEqual(trace["side_effect_policy"], "not_applicable")


if __name__ == "__main__":
    unittest.main()
