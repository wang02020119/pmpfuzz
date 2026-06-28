import unittest

from pmpfuzz.pmp import Access, AddressMode, Mseccfg, PmpEntry, PmpModel, Privilege


class PmpModelTest(unittest.TestCase):
    def test_tor_entry_denies_s_mode_load_without_read_permission(self):
        model = PmpModel(
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.TOR,
                    pmpaddr=0x2000 >> 2,
                    read=False,
                    write=False,
                    execute=False,
                    locked=False,
                )
            ]
        )

        result = model.check(
            privilege=Privilege.S,
            access=Access.LOAD,
            physical_address=0x1000,
            size=4,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.match_index, 0)
        self.assertIn("permission", result.reason)

    def test_lower_index_entry_has_priority_over_later_overlapping_entry(self):
        model = PmpModel(
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.TOR,
                    pmpaddr=0x2000 >> 2,
                    read=False,
                    write=False,
                    execute=False,
                    locked=False,
                ),
                PmpEntry(
                    index=1,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x1000, size=0x1000),
                    read=True,
                    write=True,
                    execute=True,
                    locked=False,
                ),
            ]
        )

        result = model.check(
            privilege=Privilege.U,
            access=Access.LOAD,
            physical_address=0x1800,
            size=4,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.match_index, 0)

    def test_napot_encoding_covers_the_full_requested_power_of_two_region(self):
        model = PmpModel(
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
            ]
        )

        last_word = model.check(
            privilege=Privilege.S,
            access=Access.LOAD,
            physical_address=0x80017ffc,
            size=4,
        )
        outside = model.check(
            privilege=Privilege.S,
            access=Access.LOAD,
            physical_address=0x80018000,
            size=4,
        )

        self.assertTrue(last_word.allowed)
        self.assertFalse(outside.allowed)

    def test_mprv_uses_mpp_as_effective_privilege_for_data_access(self):
        model = PmpModel(
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80000000, size=0x1000),
                    read=False,
                    write=False,
                    execute=True,
                    locked=False,
                )
            ]
        )

        result = model.check(
            privilege=Privilege.M,
            access=Access.LOAD,
            physical_address=0x80000040,
            size=4,
            mprv=True,
            mpp=Privilege.S,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.effective_privilege, Privilege.S)

    def test_locked_entry_restricts_m_mode_without_smepmp(self):
        model = PmpModel(
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80000000, size=0x1000),
                    read=False,
                    write=False,
                    execute=False,
                    locked=True,
                )
            ]
        )

        result = model.check(
            privilege=Privilege.M,
            access=Access.STORE,
            physical_address=0x80000080,
            size=8,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.match_index, 0)

    def test_write_without_read_is_reserved_without_smepmp(self):
        model = PmpModel(
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80008000, size=0x1000),
                    read=False,
                    write=True,
                    execute=False,
                    locked=False,
                )
            ]
        )

        result = model.check(
            privilege=Privilege.S,
            access=Access.STORE,
            physical_address=0x80008000,
            size=4,
        )

        self.assertFalse(result.allowed)

    def test_smepmp_mmwp_denies_unmatched_m_mode_access(self):
        model = PmpModel(entries=[], mseccfg=Mseccfg(mmwp=True))

        result = model.check(
            privilege=Privilege.M,
            access=Access.LOAD,
            physical_address=0x90000000,
            size=4,
        )

        self.assertFalse(result.allowed)
        self.assertIn("MMWP", result.reason)

    def test_smepmp_mml_su_only_rule_denies_m_mode_but_allows_s_mode(self):
        model = PmpModel(
            mseccfg=Mseccfg(mml=True),
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80000000, size=0x1000),
                    read=True,
                    write=False,
                    execute=False,
                    locked=False,
                )
            ],
        )

        m_result = model.check(
            privilege=Privilege.M,
            access=Access.LOAD,
            physical_address=0x80000008,
            size=4,
        )
        s_result = model.check(
            privilege=Privilege.S,
            access=Access.LOAD,
            physical_address=0x80000008,
            size=4,
        )

        self.assertFalse(m_result.allowed)
        self.assertTrue(s_result.allowed)

    def test_smepmp_mml_shared_data_region_uses_rw01_encoding(self):
        model = PmpModel(
            mseccfg=Mseccfg(mml=True),
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80008000, size=0x1000),
                    read=False,
                    write=True,
                    execute=True,
                    locked=False,
                )
            ],
        )

        for privilege in [Privilege.M, Privilege.S, Privilege.U]:
            with self.subTest(privilege=privilege):
                self.assertTrue(
                    model.check(
                        privilege=privilege,
                        access=Access.LOAD,
                        physical_address=0x80008000,
                        size=4,
                    ).allowed
                )
                self.assertTrue(
                    model.check(
                        privilege=privilege,
                        access=Access.STORE,
                        physical_address=0x80008000,
                        size=4,
                    ).allowed
                )
                self.assertFalse(
                    model.check(
                        privilege=privilege,
                        access=Access.FETCH,
                        physical_address=0x80008000,
                        size=4,
                    ).allowed
                )

    def test_smepmp_mml_locked_shared_code_region_is_execute_only_for_su(self):
        model = PmpModel(
            mseccfg=Mseccfg(mml=True),
            entries=[
                PmpEntry(
                    index=0,
                    address_mode=AddressMode.NAPOT,
                    pmpaddr=PmpEntry.encode_napot(base=0x80008000, size=0x1000),
                    read=False,
                    write=True,
                    execute=False,
                    locked=True,
                )
            ],
        )

        self.assertTrue(
            model.check(
                privilege=Privilege.M,
                access=Access.FETCH,
                physical_address=0x80008000,
                size=4,
            ).allowed
        )
        self.assertTrue(
            model.check(
                privilege=Privilege.S,
                access=Access.FETCH,
                physical_address=0x80008000,
                size=4,
            ).allowed
        )
        self.assertFalse(
            model.check(
                privilege=Privilege.S,
                access=Access.LOAD,
                physical_address=0x80008000,
                size=4,
            ).allowed
        )


if __name__ == "__main__":
    unittest.main()
