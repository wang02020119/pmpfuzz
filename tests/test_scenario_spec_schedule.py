import json
import tempfile
import unittest
from pathlib import Path

from pmpfuzz.__main__ import _scenario_from_case
from pmpfuzz.emitter import AssemblyEmitter
from pmpfuzz.oracle import evaluate_scenario, final_stateful_scenario
from pmpfuzz.pmp import AddressMode, PmpEntry
from pmpfuzz.scenario import PAGE_TABLE_BASE, PAGE_TABLE_SIZE, TARGET_BASE, TARGET_SIZE, ScenarioGenerator
from pmpfuzz.scenario_codec import scenario_from_spec, scenario_hash, scenario_to_spec
from pmpfuzz.schema import scenario_to_case_dict, write_json
from pmpfuzz.semantic_coverage import scenarios_from_schedule
from pmpfuzz.stateful import canonical_stateful_sequence, validate_stateful_contract


class ScenarioSpecScheduleTest(unittest.TestCase):
    def test_generate_one_matches_batch(self):
        generator = ScenarioGenerator(seed=71, include_smepmp=False, profile="pmp-boundary")
        batch = generator.generate_batch(4)

        direct = ScenarioGenerator(seed=71, include_smepmp=False, profile="pmp-boundary").generate_one(3)

        self.assertEqual(scenario_to_spec(direct), scenario_to_spec(batch[3]))

    def test_case_dict_embeds_scenario_spec_and_hash(self):
        scenario = ScenarioGenerator(seed=20260714, include_smepmp=False, profile="sv39-ptw-pmp-matrix").generate_one(0)

        case = scenario_to_case_dict(scenario, seed=20260714, index=0)

        self.assertIn("scenario_spec", case)
        self.assertIn("scenario_hash", case)
        self.assertEqual(case["scenario_hash"], scenario_hash(case["scenario_spec"]))
        rebuilt = _scenario_from_case(case)
        self.assertEqual(scenario_to_spec(rebuilt), case["scenario_spec"])

    def test_schedule_prefers_embedded_scenario_spec(self):
        scenario = ScenarioGenerator(seed=17, include_smepmp=False, profile="pmp-boundary").generate_one(0)
        spec = scenario_to_spec(scenario)
        embedded_hash = scenario_hash(spec)

        with tempfile.TemporaryDirectory() as tmp:
            schedule_path = Path(tmp) / "schedule.json"
            write_json(
                schedule_path,
                {
                    "schema_version": 1,
                    "seed": 999,
                    "entries": [
                        {
                            "profile": "pmp-boundary",
                            "index": 7,
                            "name": "embedded-spec-case",
                            "seed": 999,
                            "include_smepmp": False,
                            "scenario_spec": spec,
                            "scenario_hash": embedded_hash,
                        }
                    ],
                },
            )

            loaded = scenarios_from_schedule(schedule_path)

        self.assertEqual(len(loaded), 1)
        _, loaded_scenario = loaded[0]
        loaded_spec = scenario_to_spec(loaded_scenario)
        self.assertEqual(loaded_scenario.name, "embedded-spec-case")
        self.assertEqual(scenario_hash(loaded_spec), embedded_hash)

    def test_schedule_rejects_mismatched_embedded_hash(self):
        scenario = ScenarioGenerator(seed=23, include_smepmp=False, profile="pmp-boundary").generate_one(0)
        spec = scenario_to_spec(scenario)

        with tempfile.TemporaryDirectory() as tmp:
            schedule_path = Path(tmp) / "schedule.json"
            write_json(
                schedule_path,
                {
                    "schema_version": 1,
                    "entries": [
                        {
                            "profile": "pmp-boundary",
                            "index": 0,
                            "name": "bad-hash",
                            "seed": 23,
                            "include_smepmp": False,
                            "scenario_spec": spec,
                            "scenario_hash": "0" * 64,
                        }
                    ],
                },
            )

            with self.assertRaises(ValueError):
                scenarios_from_schedule(schedule_path)

    def test_case_rejects_mismatched_embedded_hash(self):
        scenario = ScenarioGenerator(seed=29, include_smepmp=False, profile="pmp-boundary").generate_one(0)
        case = scenario_to_case_dict(scenario, seed=29, index=0)
        case["scenario_hash"] = "f" * 64

        with self.assertRaises(ValueError):
            _scenario_from_case(case)

    def test_scenario_spec_round_trips_strictly(self):
        scenario = ScenarioGenerator(seed=31, include_smepmp=False, profile="pmp-side-effect").generate_one(0)
        spec = scenario_to_spec(scenario)
        rebuilt = scenario_from_spec(spec)

        self.assertEqual(scenario_to_spec(rebuilt), spec)

    def test_stateful_expected_fields_do_not_change_scenario_identity(self):
        scenario = ScenarioGenerator(seed=41, include_smepmp=False, profile="tlb-stale-pmp").generate_one(0)
        spec = scenario_to_spec(scenario)
        mutated = json.loads(json.dumps(spec))
        sequence = mutated["stateful_sequence"]
        sequence["expected_final"] = "store_side_effect"
        sequence["expected_cause"] = None
        sequence["stale_failure_class"] = None

        self.assertEqual(scenario_hash(mutated), scenario_hash(spec))

    def test_case_dict_rederives_stateful_expected_and_bins_from_stimulus(self):
        scenario = ScenarioGenerator(seed=43, include_smepmp=False, profile="tlb-stale-pmp").generate_one(0)
        spec = scenario_to_spec(scenario)
        spec["stateful_sequence"]["expected_final"] = "store_side_effect"
        spec["stateful_sequence"]["expected_cause"] = None
        spec["stateful_sequence"]["stale_failure_class"] = None

        rebuilt = scenario_from_spec(spec)
        case = scenario_to_case_dict(rebuilt, seed=43, index=0)

        self.assertFalse(case["expected"]["allowed"])
        self.assertEqual(case["expected"]["trap_cause"], 5)
        self.assertEqual(case["stateful_sequence"]["expected_final"], "trap_after_mutation")
        self.assertEqual(case["stateful_sequence"]["stale_failure_class"], "STALE_PMP_PERMISSION")
        self.assertIn("profile=tlb-stale-pmp|final=trap_after_mutation", case["semantic_bins"])
        self.assertNotIn("profile=tlb-stale-pmp|final=store_side_effect", case["semantic_bins"])

    def test_stateful_mutation_none_clears_residual_payload_for_emitter_and_model(self):
        scenario = ScenarioGenerator(seed=47, include_smepmp=False, profile="tlb-stale-pmp").generate_one(0)
        spec = scenario_to_spec(scenario)
        self.assertIn("pmpcfg0_after", spec["stateful_sequence"])
        spec["stateful_sequence"]["mutation"] = "none"

        rebuilt = scenario_from_spec(spec)
        normalized = scenario_to_spec(rebuilt)
        sequence = normalized["stateful_sequence"]
        asm = AssemblyEmitter().emit(rebuilt)

        self.assertEqual(sequence["mutation"], "none")
        self.assertNotIn("pmpcfg0_after", sequence)
        self.assertNotIn("pmpaddr_writes", sequence)
        self.assertEqual(final_stateful_scenario(rebuilt), rebuilt)
        self.assertNotIn("apply_stateful_setup_transition:", asm)

    def test_stateful_warmup_false_applies_transition_during_setup(self):
        scenario = ScenarioGenerator(seed=53, include_smepmp=False, profile="tlb-stale-pmp").generate_one(0)
        spec = scenario_to_spec(scenario)
        spec["stateful_sequence"]["warmup"] = False

        rebuilt = scenario_from_spec(spec)
        final_case = scenario_to_case_dict(rebuilt, seed=53, index=0)
        asm = AssemblyEmitter().emit(rebuilt)

        self.assertFalse(final_case["expected"]["allowed"])
        self.assertEqual(final_case["expected"]["trap_cause"], 5)
        self.assertEqual(final_case["stateful_sequence"]["fence"], "none")
        self.assertIn("apply_stateful_setup_transition:", asm)
        self.assertIn("stateful_handle_final:", asm)

    def test_stateful_contract_rejects_store_warmup_sequences(self):
        scenario = ScenarioGenerator(seed=21, include_smepmp=False, profile="pmp-side-effect").generate_one(1)
        spec = scenario_to_spec(scenario)
        aligned_address = spec["probe"]["physical_address"] & ~0x3
        spec["access"] = "store"
        spec["probe"]["size"] = 4
        spec["probe"]["physical_address"] = aligned_address
        spec["probe"]["virtual_address"] = aligned_address
        spec["stateful_sequence"]["warmup"] = True
        spec["stateful_sequence"]["warmup_access"] = "store"
        spec["stateful_sequence"].setdefault("sentinel", {})["physical_address"] = aligned_address

        rebuilt = scenario_from_spec(spec)
        valid, reason = validate_stateful_contract(rebuilt)

        self.assertFalse(valid)
        self.assertIn("store", reason)

    def test_stateful_contract_allows_nonwarmup_store_probe_without_sentinel_restrictions(self):
        scenario = ScenarioGenerator(seed=21, include_smepmp=False, profile="pmp-side-effect").generate_one(1)
        spec = scenario_to_spec(scenario)
        spec["access"] = "store"
        spec["probe"]["size"] = 8
        spec["probe"]["physical_address"] += 4
        spec["probe"]["virtual_address"] = spec["probe"]["physical_address"]
        spec["stateful_sequence"]["warmup"] = False

        rebuilt = scenario_from_spec(spec)
        valid, reason = validate_stateful_contract(rebuilt)

        self.assertTrue(valid, reason)
        self.assertEqual(reason, "")

    def test_stateful_contract_rejects_non_sv39_pte_mutation(self):
        scenario = ScenarioGenerator(seed=61, include_smepmp=False, profile="pmp-side-effect").generate_one(0)
        spec = scenario_to_spec(scenario)
        spec["stateful_sequence"]["mutation"] = "pte-deny-leaf"

        rebuilt = scenario_from_spec(spec)
        valid, reason = validate_stateful_contract(rebuilt)

        self.assertFalse(valid)
        self.assertIn("Sv39", reason)

    def test_stateful_contract_rejects_warmup_sequences_that_trap_before_mutation(self):
        scenario = ScenarioGenerator(seed=67, include_smepmp=False, profile="tlb-stale-pmp").generate_one(0)
        spec = scenario_to_spec(scenario)
        target_pmpaddr = PmpEntry.encode_napot(base=TARGET_BASE, size=TARGET_SIZE)
        for entry in spec["entries"]:
            if entry["pmpaddr"] == target_pmpaddr:
                entry["read"] = False
                entry["write"] = False
                entry["execute"] = False
                break
        rebuilt = scenario_from_spec(spec)

        self.assertFalse(evaluate_scenario(rebuilt).allowed)
        valid, reason = validate_stateful_contract(rebuilt)

        self.assertFalse(valid)
        self.assertIn("warmup", reason)

    def test_stateful_target_mutation_tracks_actual_target_entry_after_topology_swap(self):
        scenario = ScenarioGenerator(seed=71, include_smepmp=False, profile="tlb-stale-pmp").generate_one(0)
        spec = scenario_to_spec(scenario)
        target_pmpaddr = PmpEntry.encode_napot(base=TARGET_BASE, size=TARGET_SIZE)
        ptw_pmpaddr = PmpEntry.encode_napot(base=PAGE_TABLE_BASE, size=PAGE_TABLE_SIZE)
        target_entry = next(entry for entry in spec["entries"] if entry["pmpaddr"] == target_pmpaddr)
        ptw_entry = next(entry for entry in spec["entries"] if entry["pmpaddr"] == ptw_pmpaddr)
        target_entry["index"], ptw_entry["index"] = ptw_entry["index"], target_entry["index"]

        rebuilt = scenario_from_spec(spec)
        sequence = canonical_stateful_sequence(rebuilt)
        cfg_after = int(sequence["pmpcfg0_after"], 16)
        target_cfg = (cfg_after >> (target_entry["index"] * 8)) & 0xFF
        ptw_cfg = (cfg_after >> (ptw_entry["index"] * 8)) & 0xFF

        self.assertEqual(target_cfg & 0x07, 0x00)
        self.assertNotEqual(ptw_cfg & 0x07, 0x00)

    def test_stateful_ptw_mutation_tracks_actual_walk_entry_after_topology_swap(self):
        scenario = ScenarioGenerator(seed=73, include_smepmp=False, profile="ptw-stale-pmp").generate_one(0)
        spec = scenario_to_spec(scenario)
        target_pmpaddr = PmpEntry.encode_napot(base=TARGET_BASE, size=TARGET_SIZE)
        ptw_pmpaddr = PmpEntry.encode_napot(base=PAGE_TABLE_BASE, size=PAGE_TABLE_SIZE)
        target_entry = next(entry for entry in spec["entries"] if entry["pmpaddr"] == target_pmpaddr)
        ptw_entry = next(entry for entry in spec["entries"] if entry["pmpaddr"] == ptw_pmpaddr)
        spare_entry = next(entry for entry in spec["entries"] if entry["address_mode"] == AddressMode.OFF.value)
        target_entry["index"], ptw_entry["index"] = ptw_entry["index"], target_entry["index"]

        rebuilt = scenario_from_spec(spec)
        sequence = canonical_stateful_sequence(rebuilt)
        cfg_after = int(sequence["pmpcfg0_after"], 16)
        ptw_cfg = (cfg_after >> (ptw_entry["index"] * 8)) & 0xFF
        deny_cfg = (cfg_after >> (spare_entry["index"] * 8)) & 0xFF
        walk_base = rebuilt.sv39.walk_addresses[1] & ~0xFFF
        expected_pmpaddr = PmpEntry.encode_napot(base=walk_base, size=0x1000)

        self.assertNotEqual(ptw_cfg & 0x07, 0x00)
        self.assertEqual(deny_cfg & 0x1F, AddressMode.NAPOT.value << 3)
        self.assertEqual(
            sequence["pmpaddr_writes"],
            [{"index": spare_entry["index"], "pmpaddr": f"0x{expected_pmpaddr:x}"}],
        )


if __name__ == "__main__":
    unittest.main()
