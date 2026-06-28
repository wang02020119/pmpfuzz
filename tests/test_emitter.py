import unittest

from pmpfuzz.emitter import AssemblyEmitter
from pmpfuzz.mmu import PageTableEntry, Sv39Mapping, TranslationMode
from pmpfuzz.pmp import Access, AddressMode, PmpEntry, Privilege
from pmpfuzz.scenario import AccessProbe, PmpScenario


class AssemblyEmitterTest(unittest.TestCase):
    def test_emits_machine_mode_probe_with_trap_handler_and_tohost(self):
        scenario = PmpScenario(
            name="deny_s_load",
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80002000, size=0x1000),
                    read=False,
                    write=False,
                    execute=False,
                    locked=False,
                )
            ],
            privilege=Privilege.S,
            probe=AccessProbe(
                access=Access.LOAD,
                physical_address=0x80002010,
                size=4,
                offset_name="inside",
            ),
            mprv=False,
            mpp=Privilege.M,
        )

        asm = AssemblyEmitter().emit(scenario)

        self.assertIn("_start:", asm)
        self.assertIn("mtvec", asm)
        self.assertIn("pmpaddr0", asm)
        self.assertIn("pmpcfg0", asm)
        self.assertIn("mret", asm)
        self.assertIn("tohost", asm)

    def test_sv39_emitter_sets_satp_and_emits_page_tables(self):
        scenario = PmpScenario(
            name="sv39_load",
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80000000, size=0x2000),
                    read=True,
                    write=False,
                    execute=True,
                    locked=True,
                ),
                PmpEntry(
                    index=1,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80002000, size=0x2000),
                    read=True,
                    write=True,
                    execute=False,
                    locked=True,
                ),
                PmpEntry(
                    index=2,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80004000, size=0x1000),
                    read=True,
                    write=False,
                    execute=True,
                    locked=False,
                ),
                PmpEntry(
                    index=3,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80010000, size=0x8000),
                    read=True,
                    write=False,
                    execute=False,
                    locked=False,
                ),
                PmpEntry(
                    index=4,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80008000, size=0x1000),
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
                walk_addresses=(0x80010010, 0x80011000, 0x80012000),
                pte=PageTableEntry(read=True, write=False, execute=False, user=True, accessed=True, dirty=False),
            ),
        )

        asm = AssemblyEmitter().emit(scenario)

        self.assertIn("csrw satp", asm)
        self.assertIn("sfence.vma", asm)
        self.assertIn("sv39_root_table", asm)
        self.assertIn("li t0, 0x80000000", asm)

    def test_cascade_mmio_backend_emits_result_dump_and_stop_registers(self):
        scenario = PmpScenario(
            name="allow_m_load",
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80000000, size=0x20000),
                    read=True,
                    write=True,
                    execute=True,
                    locked=False,
                )
            ],
            privilege=Privilege.M,
            probe=AccessProbe(
                access=Access.LOAD,
                physical_address=0x80008000,
                size=4,
                offset_name="inside",
            ),
            mprv=False,
            mpp=Privilege.M,
            profile="bare-pmp",
        )

        asm = AssemblyEmitter().emit(scenario, backend="cascade-mmio")

        self.assertIn("0x60000010", asm)
        self.assertIn("0x60000000", asm)
        self.assertNotIn("sd a0, 0(t0)\n1:  j 1b", asm)

    def test_cascade_mmio_legacy_backend_keeps_runtime_storage_labels(self):
        scenario = PmpScenario(
            name="legacy_allow_m_load",
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80000000, size=0x20000),
                    read=True,
                    write=True,
                    execute=True,
                    locked=False,
                )
            ],
            privilege=Privilege.M,
            probe=AccessProbe(
                access=Access.LOAD,
                physical_address=0x80008000,
                size=4,
                offset_name="inside",
            ),
            mprv=False,
            mpp=Privilege.M,
        )

        asm = AssemblyEmitter().emit(scenario, backend="cascade-mmio")

        self.assertIn("stack_top:", asm)
        self.assertIn("result:", asm)
        self.assertIn("0x60000010", asm)


if __name__ == "__main__":
    unittest.main()
