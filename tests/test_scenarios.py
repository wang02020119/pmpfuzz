import unittest

from pmpfuzz.mmu import TranslationMode
from pmpfuzz.schema import scenario_to_case_dict
from pmpfuzz.scenario import SU_CODE_BASE, SU_CODE_SIZE, ScenarioGenerator
from pmpfuzz.pmp import Access, AddressMode, PmpEntry, Privilege


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

    def test_stable_smepmp_profiles_generate_schema_and_coverage_metadata(self):
        profiles = (
            "smepmp-mmwp-mmode-default-deny",
            "smepmp-mml-shared-code",
            "smepmp-mml-shared-data",
            "smepmp-locked-entry",
            "smepmp-rlb-setup",
        )

        for profile in profiles:
            with self.subTest(profile=profile):
                scenario = ScenarioGenerator(seed=30, include_smepmp=True, profile=profile).generate_batch(count=1)[0]
                case = scenario_to_case_dict(scenario, seed=30, index=0)

                self.assertEqual(case["profile"], profile)
                self.assertIn("smepmp", case["required_capabilities"])
                self.assertTrue(case["mseccfg"]["mml"] or case["mseccfg"]["mmwp"] or case["mseccfg"]["rlb"])
                self.assertTrue(case["coverage_tags"])
                self.assertTrue(case["semantic_bins"])
                self.assertTrue(case["combo_bins"])
                self.assertTrue(case.get("smepmp_rule"))
                self.assertIn(case["smepmp_rule"], case["coverage_tags"])

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

    def test_pmp_boundary_profile_reaches_pairwise_combo_dimensions(self):
        scenarios = ScenarioGenerator(seed=42, include_smepmp=False, profile="pmp-boundary").generate_batch(count=144)
        cases = [scenario_to_case_dict(scenario, seed=42, index=index) for index, scenario in enumerate(scenarios)]

        self.assertEqual({case["privilege"] for case in cases}, {"M", "S", "U"})
        self.assertEqual({case["access"] for case in cases}, {"fetch", "load", "store"})
        self.assertGreaterEqual(
            {"tor", "na4", "napot", "first-match-overlap"} & {case["pmp_match_mode"] for case in cases},
            {"tor", "na4", "napot", "first-match-overlap"},
        )
        self.assertEqual({case["pmp_locked"] for case in cases}, {False, True})
        self.assertEqual({case["expected_allowed"] for case in cases}, {False, True})
        self.assertIn("upper_bound", {case["probe_offset"] for case in cases})
        self.assertTrue(all(case["combo_bins"] for case in cases))

    def test_pmp_boundary_su_cases_allow_probe_fetch_harness(self):
        scenarios = ScenarioGenerator(seed=71, include_smepmp=False, profile="pmp-boundary").generate_batch(count=12)

        for scenario in scenarios:
            if scenario.privilege == Privilege.M:
                continue
            su_entries = [
                entry
                for entry in scenario.entries
                if entry.execute
                and entry.address_mode == AddressMode.NAPOT
                and entry.pmpaddr == entry.encode_napot(base=SU_CODE_BASE, size=SU_CODE_SIZE)
            ]
            self.assertTrue(su_entries, scenario.name)

    def test_harness_entries_stay_in_low_pmp_indices_for_dut_compatibility(self):
        profiles = ("legacy-data", "pmp-boundary")

        for profile in profiles:
            scenarios = ScenarioGenerator(seed=72, include_smepmp=False, profile=profile).generate_batch(count=12)
            for scenario in scenarios:
                harness_entries = [
                    entry
                    for entry in scenario.entries
                    if entry.address_mode == AddressMode.NAPOT
                    and entry.execute
                    and entry.pmpaddr
                    in {
                        PmpEntry.encode_napot(base=0x80000000, size=0x4000),
                        PmpEntry.encode_napot(base=SU_CODE_BASE, size=SU_CODE_SIZE),
                    }
                ]

                self.assertTrue(harness_entries, scenario.name)
                self.assertTrue(all(entry.index <= 3 for entry in harness_entries), scenario.name)

    def test_sv39_matrix_profiles_expose_permission_and_ptw_metadata(self):
        perm = ScenarioGenerator(seed=43, include_smepmp=False, profile="sv39-perm-matrix").generate_batch(count=16)
        ptw = ScenarioGenerator(seed=47, include_smepmp=False, profile="sv39-ptw-pmp-matrix").generate_batch(count=18)

        self.assertTrue(all(scenario.translation == TranslationMode.SV39 for scenario in perm + ptw))
        self.assertGreaterEqual(len({scenario.pte_permissions["rwx"] for scenario in perm}), 3)
        self.assertGreaterEqual({"L2", "L1", "L0"} & {scenario.ptw_fault_level for scenario in ptw}, {"L1", "L0"})
        self.assertIn("cold", {scenario.preload_mode for scenario in ptw})

    def test_sv39_matrix_profiles_reach_combo_dimensions(self):
        perm = [
            scenario_to_case_dict(scenario, seed=44, index=index)
            for index, scenario in enumerate(
                ScenarioGenerator(seed=44, include_smepmp=False, profile="sv39-perm-matrix").generate_batch(count=168)
            )
        ]
        ptw = [
            scenario_to_case_dict(scenario, seed=48, index=index)
            for index, scenario in enumerate(
                ScenarioGenerator(seed=48, include_smepmp=False, profile="sv39-ptw-pmp-matrix").generate_batch(count=288)
            )
        ]

        self.assertEqual({case["privilege"] for case in perm}, {"S", "U"})
        self.assertEqual({case["access"] for case in perm}, {"fetch", "load", "store"})
        self.assertEqual({case["sum_enabled"] for case in perm}, {False, True})
        self.assertEqual({case["mxr"] for case in perm}, {False, True})
        self.assertGreaterEqual(len({case["pte_permissions"]["rwx"] for case in perm}), 5)

        self.assertEqual({case["ptw_fault_level"] for case in ptw}, {"L0", "L1", "L2"})
        self.assertEqual({case["preload_mode"] for case in ptw}, {"all", "cold", "denied-l1", "root-target"})
        self.assertEqual({case["mxr"] for case in ptw}, {False, True})
        self.assertEqual({case["pmp_locked"] for case in ptw}, {False, True})
        self.assertTrue(all(case["combo_bins"] for case in perm + ptw))

    def test_pmp_side_effect_profile_reaches_locked_privilege_and_outcome_dimensions(self):
        cases = [
            scenario_to_case_dict(scenario, seed=50, index=index)
            for index, scenario in enumerate(
                ScenarioGenerator(seed=50, include_smepmp=False, profile="pmp-side-effect").generate_batch(count=8)
            )
        ]

        self.assertEqual({case["privilege"] for case in cases}, {"S", "U"})
        self.assertEqual({case["expected_allowed"] for case in cases}, {False, True})
        self.assertEqual({case["pmp_locked"] for case in cases}, {False, True})
        self.assertTrue(all(case["access"] == "store" for case in cases))

    def test_boom_ptw_pmp_regression_profile_starts_with_hang_candidate_and_controls(self):
        scenarios = ScenarioGenerator(seed=53, include_smepmp=False, profile="boom-ptw-pmp-regression").generate_batch(count=4)

        self.assertEqual(scenarios[0].security_focus, "boom-ptw-pmp-hang")
        self.assertTrue(scenarios[0].mxr)
        self.assertEqual(scenarios[0].preload_mode, "cold")
        self.assertIn("boom-regression", scenarios[0].coverage_tags)
        self.assertIn("mxr-off-control", {scenario.security_focus for scenario in scenarios})

    def test_stateful_profiles_generate_sequence_metadata_and_schema_v3(self):
        expected = {
            "pmp-side-effect": "side-effect",
            "tlb-stale-pte": "stale-pte",
            "tlb-stale-pmp": "stale-pmp",
            "ptw-stale-pmp": "stale-ptw-pmp",
        }
        for profile, tag in expected.items():
            scenario = ScenarioGenerator(seed=61, include_smepmp=False, profile=profile).generate_batch(count=1)[0]
            case = scenario_to_case_dict(scenario, seed=61, index=0)

            self.assertEqual(case["schema_version"], 3)
            self.assertEqual(case["profile"], profile)
            self.assertIn(tag, case["coverage_tags"])
            self.assertIn("stateful_sequence", case)
            self.assertEqual(case["stateful_sequence"]["kind"], profile)
            self.assertIn(case["stateful_sequence"]["fence"], {"with-sfence", "no-fence-experimental", "none"})

    def test_non_stateful_cases_keep_schema_v2_compatibility(self):
        scenario = ScenarioGenerator(seed=67, include_smepmp=False, profile="legacy-data").generate_batch(count=1)[0]
        case = scenario_to_case_dict(scenario, seed=67, index=0)

        self.assertEqual(case["schema_version"], 2)
        self.assertNotIn("stateful_sequence", case)


if __name__ == "__main__":
    unittest.main()
