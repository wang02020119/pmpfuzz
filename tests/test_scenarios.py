import unittest

from pmpfuzz.mmu import TranslationMode
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.pmp import Access, AddressMode, Privilege


class ScenarioGeneratorTest(unittest.TestCase):
    def test_seeded_generation_is_reproducible(self):
        first = ScenarioGenerator(seed=7).generate_batch(count=8)
        second = ScenarioGenerator(seed=7).generate_batch(count=8)

        self.assertEqual(first, second)

    def test_generated_scenarios_include_boundary_probes(self):
        scenarios = ScenarioGenerator(seed=11).generate_batch(count=32)
        offsets = {scenario.probe.offset_name for scenario in scenarios}

        self.assertIn("lower_bound", offsets)
        self.assertIn("last_byte", offsets)
        self.assertIn("upper_bound", offsets)

    def test_generated_scenarios_cover_privilege_and_access_mix(self):
        scenarios = ScenarioGenerator(seed=19).generate_batch(count=64)
        privileges = {scenario.privilege for scenario in scenarios}
        accesses = {scenario.probe.access for scenario in scenarios}
        modes = {entry.address_mode for scenario in scenarios for entry in scenario.entries}

        self.assertGreaterEqual({Privilege.M, Privilege.S, Privilege.U} & privileges, {Privilege.S, Privilege.U})
        self.assertIn(Access.LOAD, accesses)
        self.assertIn(Access.STORE, accesses)
        self.assertIn(Access.FETCH, accesses)
        self.assertIn(AddressMode.TOR, modes)
        self.assertIn(AddressMode.NAPOT, modes)

    def test_mixed_smepmp_mmu_profile_emits_sv39_and_smepmp_cases(self):
        scenarios = ScenarioGenerator(seed=23, profile="mixed-smepmp-mmu").generate_batch(count=24)

        self.assertTrue(any(scenario.translation == TranslationMode.SV39 for scenario in scenarios))
        self.assertTrue(any(scenario.mseccfg.mml or scenario.mseccfg.mmwp for scenario in scenarios))
        self.assertTrue(any(scenario.sv39 is not None for scenario in scenarios))

    def test_smepmp_table_profile_covers_all_l_r_w_x_encodings(self):
        scenarios = ScenarioGenerator(seed=29, profile="smepmp-table").generate_batch(count=16)
        encodings = {
            (
                scenario.entries[-1].locked,
                scenario.entries[-1].read,
                scenario.entries[-1].write,
                scenario.entries[-1].execute,
            )
            for scenario in scenarios
        }

        self.assertEqual(len(encodings), 16)
        self.assertTrue(all(scenario.mseccfg.mml for scenario in scenarios))

    def test_no_smepmp_generation_avoids_reserved_write_without_read_pmp(self):
        scenarios = ScenarioGenerator(seed=31, include_smepmp=False, profile="legacy").generate_batch(count=64)

        self.assertFalse(
            any(entry.write and not entry.read for scenario in scenarios for entry in scenario.entries),
        )

    def test_legacy_data_profile_excludes_fetch(self):
        scenarios = ScenarioGenerator(seed=33, include_smepmp=False, profile="legacy-data").generate_batch(count=32)

        self.assertEqual({scenario.profile for scenario in scenarios}, {"legacy-data"})
        self.assertNotIn(Access.FETCH, {scenario.probe.access for scenario in scenarios})
        self.assertGreaterEqual({Access.LOAD, Access.STORE} & {scenario.probe.access for scenario in scenarios}, {Access.LOAD, Access.STORE})

    def test_no_smepmp_sv39_store_target_uses_valid_read_write_pmp(self):
        scenario = ScenarioGenerator(seed=37, include_smepmp=False, profile="sv39-final-pmp").generate_batch(count=2)[1]
        target = scenario.entries[-1]

        self.assertEqual(scenario.probe.access, Access.STORE)
        self.assertTrue(target.read)
        self.assertTrue(target.write)

    def test_pmp_boundary_profile_covers_na4_tor_napot_and_first_match(self):
        scenarios = ScenarioGenerator(seed=41, include_smepmp=False, profile="pmp-boundary").generate_batch(count=24)
        modes = {scenario.pmp_match_mode for scenario in scenarios}
        address_modes = {entry.address_mode for scenario in scenarios for entry in scenario.entries}

        self.assertEqual({scenario.profile for scenario in scenarios}, {"pmp-boundary"})
        self.assertIn(AddressMode.NA4, address_modes)
        self.assertIn(AddressMode.TOR, address_modes)
        self.assertIn(AddressMode.NAPOT, address_modes)
        self.assertIn("first-match-overlap", modes)
        self.assertTrue(all("pmp" in scenario.coverage_tags for scenario in scenarios))

    def test_sv39_matrix_profiles_expose_permission_and_ptw_metadata(self):
        perm = ScenarioGenerator(seed=43, include_smepmp=False, profile="sv39-perm-matrix").generate_batch(count=16)
        ptw = ScenarioGenerator(seed=47, include_smepmp=False, profile="sv39-ptw-pmp-matrix").generate_batch(count=18)

        self.assertTrue(all(scenario.translation == TranslationMode.SV39 for scenario in perm + ptw))
        self.assertGreaterEqual(len({scenario.pte_permissions["rwx"] for scenario in perm}), 3)
        self.assertGreaterEqual({"L2", "L1", "L0"} & {scenario.ptw_fault_level for scenario in ptw}, {"L1", "L0"})
        self.assertIn("cold", {scenario.preload_mode for scenario in ptw})

    def test_boom_ptw_pmp_regression_profile_starts_with_hang_candidate_and_controls(self):
        scenarios = ScenarioGenerator(seed=53, include_smepmp=False, profile="boom-ptw-pmp-regression").generate_batch(count=4)

        self.assertEqual(scenarios[0].security_focus, "boom-ptw-pmp-hang")
        self.assertTrue(scenarios[0].mxr)
        self.assertEqual(scenarios[0].preload_mode, "cold")
        self.assertIn("boom-regression", scenarios[0].coverage_tags)
        self.assertIn("mxr-off-control", {scenario.security_focus for scenario in scenarios})


if __name__ == "__main__":
    unittest.main()
