import unittest

from pmpfuzz.mmu import (
    AdUpdateMode,
    PageFaultKind,
    PageTableEntry,
    Sv39Mapping,
    Sv39Model,
    TranslationStage,
)
from pmpfuzz.pmp import Access, AddressMode, PmpEntry, PmpModel, Privilege


class Sv39ModelTest(unittest.TestCase):
    def test_hardware_ad_update_is_checked_as_pmp_store_to_leaf_pte(self):
        target_va = 0x80000000
        leaf_pte = 0x80012000
        mapping = Sv39Mapping(
            virtual_page=target_va,
            physical_page=0x80008000,
            root_table=0x80010000,
            walk_addresses=(0x80010010, 0x80011000, leaf_pte),
            pte=PageTableEntry(read=True, write=False, execute=False, user=True, accessed=False, dirty=False),
        )
        model = Sv39Model(
            mappings=[mapping],
            ad_update_mode=AdUpdateMode.HARDWARE,
            pmp_model=PmpModel(
                entries=[
                    PmpEntry(
                        index=0,
                        address_mode=AddressMode.NAPOT,
                        pmpaddr=PmpEntry.encode_napot(base=leaf_pte, size=8),
                        read=True,
                        write=False,
                        execute=False,
                        locked=False,
                    ),
                    PmpEntry(
                        index=1,
                        address_mode=AddressMode.NAPOT,
                        pmpaddr=PmpEntry.encode_napot(base=0x80010000, size=0x8000),
                        read=True,
                        write=True,
                        execute=False,
                        locked=False,
                    ),
                    PmpEntry(
                        index=2,
                        address_mode=AddressMode.NAPOT,
                        pmpaddr=PmpEntry.encode_napot(base=0x80008000, size=0x1000),
                        read=True,
                        write=False,
                        execute=False,
                        locked=False,
                    ),
                ]
            ),
        )

        result = model.check(
            privilege=Privilege.U,
            access=Access.LOAD,
            virtual_address=target_va,
            size=4,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.kind, PageFaultKind.ACCESS_FAULT)
        self.assertEqual(result.stage, TranslationStage.PAGE_TABLE_WALK)
        self.assertEqual(result.fault_address, leaf_pte)
        self.assertEqual(result.pmp_match_index, 0)
        self.assertIn("A/D update", result.reason)

    def test_hardware_ad_update_continues_when_leaf_pte_is_writable(self):
        target_va = 0x80000000
        mapping = Sv39Mapping(
            virtual_page=target_va,
            physical_page=0x80008000,
            root_table=0x80010000,
            walk_addresses=(0x80010010, 0x80011000, 0x80012000),
            pte=PageTableEntry(read=True, write=False, execute=False, user=True, accessed=False, dirty=False),
        )
        model = Sv39Model(
            mappings=[mapping],
            ad_update_mode=AdUpdateMode.HARDWARE,
            pmp_model=PmpModel(
                entries=[
                    PmpEntry(
                        index=0,
                        address_mode=AddressMode.NAPOT,
                        pmpaddr=PmpEntry.encode_napot(base=0x80010000, size=0x8000),
                        read=True,
                        write=True,
                        execute=False,
                        locked=False,
                    ),
                    PmpEntry(
                        index=1,
                        address_mode=AddressMode.NAPOT,
                        pmpaddr=PmpEntry.encode_napot(base=0x80008000, size=0x1000),
                        read=True,
                        write=False,
                        execute=False,
                        locked=False,
                    ),
                ]
            ),
        )

        result = model.check(
            privilege=Privilege.U,
            access=Access.LOAD,
            virtual_address=target_va,
            size=4,
        )

        self.assertTrue(result.allowed)
        self.assertTrue(result.ad_updated)
    def test_page_table_walk_is_checked_by_pmp_with_s_effective_privilege(self):
        target_va = 0x80000000
        mapping = Sv39Mapping(
            virtual_page=target_va,
            physical_page=0x80008000,
            root_table=0x80010000,
            walk_addresses=(0x80010010, 0x80013000, 0x80014000),
            pte=PageTableEntry(read=True, write=False, execute=False, user=True, accessed=True, dirty=False),
        )
        model = Sv39Model(
            mappings=[mapping],
            pmp_model=PmpModel(
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
                ]
            ),
        )

        result = model.check(
            privilege=Privilege.U,
            access=Access.LOAD,
            virtual_address=target_va,
            size=4,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.kind, PageFaultKind.ACCESS_FAULT)
        self.assertEqual(result.stage, TranslationStage.PAGE_TABLE_WALK)
        self.assertEqual(result.fault_address, 0x80013000)

    def test_final_physical_address_is_checked_after_successful_translation(self):
        target_va = 0x80000000
        mapping = Sv39Mapping(
            virtual_page=target_va,
            physical_page=0x80008000,
            root_table=0x80010000,
            walk_addresses=(0x80010010, 0x80011000, 0x80012000),
            pte=PageTableEntry(read=True, write=False, execute=False, user=True, accessed=True, dirty=False),
        )
        model = Sv39Model(
            mappings=[mapping],
            pmp_model=PmpModel(
                entries=[
                    PmpEntry(
                        index=0,
                        address_mode=AddressMode.NAPOT,
                        pmpaddr=PmpEntry.encode_napot(base=0x80008000, size=0x1000),
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
                ]
            ),
        )

        result = model.check(
            privilege=Privilege.U,
            access=Access.LOAD,
            virtual_address=target_va,
            size=4,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.kind, PageFaultKind.ACCESS_FAULT)
        self.assertEqual(result.stage, TranslationStage.FINAL_ACCESS)
        self.assertEqual(result.physical_address, 0x80008000)

    def test_s_mode_sum_and_mxr_modify_page_permissions_not_pmp_permissions(self):
        target_va = 0x80000000
        mapping = Sv39Mapping(
            virtual_page=target_va,
            physical_page=0x80008000,
            root_table=0x80010000,
            walk_addresses=(0x80010010, 0x80011000, 0x80012000),
            pte=PageTableEntry(read=False, write=False, execute=True, user=True, accessed=True, dirty=False),
        )
        model = Sv39Model(
            mappings=[mapping],
            pmp_model=PmpModel(
                entries=[
                    PmpEntry(
                        index=0,
                        address_mode=AddressMode.NAPOT,
                        pmpaddr=PmpEntry.encode_napot(base=0x80010000, size=0x8000),
                        read=True,
                        write=False,
                        execute=False,
                        locked=False,
                    ),
                    PmpEntry(
                        index=1,
                        address_mode=AddressMode.NAPOT,
                        pmpaddr=PmpEntry.encode_napot(base=0x80008000, size=0x1000),
                        read=True,
                        write=False,
                        execute=False,
                        locked=False,
                    ),
                ]
            ),
        )

        without_bits = model.check(
            privilege=Privilege.S,
            access=Access.LOAD,
            virtual_address=target_va,
            size=4,
            sum_enabled=False,
            mxr=False,
        )
        with_bits = model.check(
            privilege=Privilege.S,
            access=Access.LOAD,
            virtual_address=target_va,
            size=4,
            sum_enabled=True,
            mxr=True,
        )

        self.assertFalse(without_bits.allowed)
        self.assertEqual(without_bits.kind, PageFaultKind.PAGE_FAULT)
        self.assertTrue(with_bits.allowed)
        self.assertEqual(with_bits.physical_address, 0x80008000)


if __name__ == "__main__":
    unittest.main()
