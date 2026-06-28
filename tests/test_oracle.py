import unittest

from pmpfuzz.mmu import PageTableEntry, Sv39Mapping, TranslationMode
from pmpfuzz.oracle import TrapCause, evaluate_scenario
from pmpfuzz.pmp import Access, AddressMode, Mseccfg, PmpEntry, Privilege
from pmpfuzz.scenario import AccessProbe, PmpScenario


class ScenarioOracleTest(unittest.TestCase):
    def test_bare_pmp_denial_maps_to_access_fault_cause(self):
        scenario = PmpScenario(
            name="deny_store",
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80008000, size=0x1000),
                    read=True,
                    write=False,
                    execute=False,
                    locked=True,
                )
            ],
            privilege=Privilege.S,
            probe=AccessProbe(
                access=Access.STORE,
                physical_address=0x80008000,
                size=4,
                offset_name="inside",
            ),
            mprv=False,
            mpp=Privilege.M,
        )

        outcome = evaluate_scenario(scenario)

        self.assertFalse(outcome.allowed)
        self.assertEqual(outcome.trap_cause, TrapCause.STORE_ACCESS_FAULT)
        self.assertEqual(outcome.stage, "pmp")

    def test_sv39_page_walk_pmp_denial_keeps_original_access_fault_cause(self):
        scenario = PmpScenario(
            name="ptw_deny_load",
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80013000, size=0x1000),
                    read=False,
                    write=False,
                    execute=False,
                    locked=True,
                ),
                PmpEntry(
                    index=1,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80010000, size=0x8000),
                    read=True,
                    write=False,
                    execute=False,
                    locked=False,
                ),
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
                walk_addresses=(0x80010010, 0x80013000, 0x80014000),
                pte=PageTableEntry(read=True, write=False, execute=False, user=True, accessed=True, dirty=False),
            ),
        )

        outcome = evaluate_scenario(scenario)

        self.assertFalse(outcome.allowed)
        self.assertEqual(outcome.trap_cause, TrapCause.LOAD_ACCESS_FAULT)
        self.assertEqual(outcome.stage, "page_table_walk")


if __name__ == "__main__":
    unittest.main()
