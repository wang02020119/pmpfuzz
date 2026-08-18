import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pmpfuzz import off_state
from scripts.evaluation.off_state import analyze_pmp_off_states as analyzer
from scripts.evaluation.off_state import characterize_pmp_off_states as characterizer
from scripts.evaluation.validation import validate_bapc_universe as validator


def _readback_record(
    *,
    profile_requested: str = "base-pmp",
    profile_observed: str | None = None,
    entry_index: int = 0,
    reset_id: str = "reset-000",
    requested_bits: dict[str, int] | None = None,
    spec_status: str | None = None,
    execution_status: str = "completed",
    unsupported_profile_reason: str | None = None,
    readback_relation: str = "exact",
    readback_bits_1: dict[str, int] | None = None,
    readback_bits_2: dict[str, int] | None = None,
) -> dict:
    bits = dict(requested_bits or {"l": 0, "r": 0, "w": 1, "x": 0})
    record = {
        "record_schema_version": off_state.OFF_STATE_RECORD_SCHEMA_VERSION,
        "dut": "cva6",
        "profile_requested": profile_requested,
        "profile_observed": profile_requested if profile_observed is None else profile_observed,
        "entry_index": entry_index,
        "reset_id": reset_id,
        "subexperiment": "readback",
        "requested_bits": bits,
        "spec_status": spec_status or off_state.spec_status_for_off_state(profile_requested, bits),
        "execution_status": execution_status,
        "write_outcome": "accepted",
        "readback_relation": readback_relation,
        "readback_bits_1": dict(readback_bits_1 or bits),
        "readback_bits_2": dict(readback_bits_2 or bits),
    }
    if unsupported_profile_reason is not None:
        record["unsupported_profile_reason"] = unsupported_profile_reason
    return record


def _behavior_record(
    normalized_record: dict,
    *,
    profile_requested: str = "base-pmp",
    profile_observed: str = "base-pmp",
    entry_index: int = 0,
    reset_id: str = "reset-000",
    requested_bits: dict[str, int] | None = None,
    spec_status: str | None = None,
    execution_status: str = "completed",
    unsupported_profile_reason: str | None = None,
) -> dict:
    bits = dict(requested_bits or {"l": 0, "r": 0, "w": 1, "x": 0})
    record = {
        "record_schema_version": off_state.OFF_STATE_RECORD_SCHEMA_VERSION,
        "dut": "cva6",
        "profile_requested": profile_requested,
        "profile_observed": profile_observed,
        "entry_index": entry_index,
        "reset_id": reset_id,
        "subexperiment": "behavior",
        "requested_bits": bits,
        "spec_status": spec_status or off_state.spec_status_for_off_state(profile_requested, bits),
        "execution_status": execution_status,
        "probe_result": "expected-nonmatch",
        "access": "load",
        "size": 4,
        "current_privilege": "u",
        "effective_privilege": "u",
        "exception_cause": "load_access_fault",
        "fault_address": "0x80000000",
        "matched_control_case": "napot-deny",
        "normalized_record": dict(normalized_record),
        "raw_trace_sha256": "a" * 64,
        "supports_fault_stage": True,
        "supports_smepmp": False,
    }
    if unsupported_profile_reason is not None:
        record["unsupported_profile_reason"] = unsupported_profile_reason
    return record


class PmpOffStateCharacterizationTest(unittest.TestCase):
    def test_spec_encoding_sets_cover_all_16_encodings_per_profile(self):
        spec_sets = characterizer.build_spec_encoding_sets()

        self.assertEqual(sum(len(items) for items in spec_sets["base-pmp"].values()), 16)
        self.assertEqual(sum(len(items) for items in spec_sets["smepmp-mml0"].values()), 16)
        self.assertEqual(sum(len(items) for items in spec_sets["smepmp-mml1"].values()), 16)
        self.assertEqual(len(spec_sets["base-pmp"]["spec-reserved"]), 4)
        self.assertEqual(len(spec_sets["base-pmp"]["spec-defined"]), 12)
        self.assertEqual(len(spec_sets["smepmp-mml0"]["spec-reserved"]), 4)
        self.assertEqual(len(spec_sets["smepmp-mml0"]["spec-defined"]), 12)
        self.assertEqual(len(spec_sets["smepmp-mml1"]["profile-dependent"]), 16)
        self.assertEqual(
            spec_sets["base-pmp"]["spec-reserved"],
            [
                "pmpcfg-raw-v1|profile=base-pmp|a=off|l=0|r=0|w=1|x=0",
                "pmpcfg-raw-v1|profile=base-pmp|a=off|l=0|r=0|w=1|x=1",
                "pmpcfg-raw-v1|profile=base-pmp|a=off|l=1|r=0|w=1|x=0",
                "pmpcfg-raw-v1|profile=base-pmp|a=off|l=1|r=0|w=1|x=1",
            ],
        )
        self.assertEqual(
            spec_sets["smepmp-mml0"]["spec-reserved"],
            [
                "pmpcfg-raw-v1|profile=smepmp-mml0|a=off|l=0|r=0|w=1|x=0",
                "pmpcfg-raw-v1|profile=smepmp-mml0|a=off|l=0|r=0|w=1|x=1",
                "pmpcfg-raw-v1|profile=smepmp-mml0|a=off|l=1|r=0|w=1|x=0",
                "pmpcfg-raw-v1|profile=smepmp-mml0|a=off|l=1|r=0|w=1|x=1",
            ],
        )

    def test_plan_enumerates_profiles_entries_resets_and_subexperiments(self):
        plan = characterizer.build_characterization_plan(
            dut="cva6",
            profiles=["base-pmp", "smepmp-mml0"],
            entry_indices=[0, 7],
            reset_count=3,
        )

        self.assertEqual(plan["dut"], "cva6")
        self.assertEqual(len(plan["main_cases"]), 2 * 2 * 3 * 3 * 16)
        self.assertEqual(len(plan["lock_control_cases"]), 2 * 2 * 3)
        self.assertEqual(plan["schema_version"], off_state.OFF_STATE_PLAN_SCHEMA_VERSION)
        first_case = plan["main_cases"][0]
        self.assertEqual(first_case["subexperiment"], "readback")
        self.assertIn("requested_bits", first_case)
        self.assertIn("spec_status", first_case)

    def test_raw_state_universe_manifest_is_versioned_and_hashed(self):
        universe = off_state.build_raw_state_universe("base-pmp")

        self.assertEqual(universe["schema_version"], off_state.OFF_STATE_RAW_UNIVERSE_SCHEMA_VERSION)
        self.assertEqual(universe["artifact_kind"], "pmpcfg-raw-v1")
        self.assertEqual(universe["profile"], "base-pmp")
        self.assertEqual(universe["bin_count"], 16)
        self.assertEqual(universe["bin_ids"][0], "pmpcfg-raw-v1|profile=base-pmp|a=off|l=0|r=0|w=0|x=0")
        self.assertEqual(
            universe["bin_set_sha256"],
            off_state.raw_state_universe_bin_set_sha256(universe["bin_ids"]),
        )
        self.assertEqual(universe, off_state.validate_raw_state_universe(universe))

    def test_analysis_replays_current_bapc_mappers(self):
        witness_report = validator.build_validation_report(
            dut="cva6",
            bapc_core_version="v3",
            generator_seed=7,
        )
        normalized_record = dict(witness_report["witnesses"][0]["normalized_record"])
        records = [
            _readback_record(reset_id="reset-000"),
            _behavior_record(normalized_record, reset_id="reset-000"),
        ]

        report = analyzer.analyze_characterization_records(records)

        dut_set = report["stable_readback_set"]["cva6"]["base-pmp"]["0"]
        self.assertEqual(len(dut_set), 1)
        self.assertIn("pmpcfg-raw-v1|profile=base-pmp|a=off|l=0|r=0|w=1|x=0", dut_set)
        self.assertEqual(len(report["mapper_validations"]), 2)
        self.assertTrue(all(item["replay_equal"] for item in report["mapper_validations"]))
        self.assertTrue(all(item["in_universe"] for item in report["mapper_validations"]))
        self.assertTrue(report["mapper_witness_set"]["v2"])
        self.assertTrue(report["mapper_witness_set"]["v3"])
        self.assertIn("base-pmp", report["requested_raw_vocabularies"])
        self.assertEqual(report["requested_raw_vocabularies"]["base-pmp"]["bin_count"], 16)
        self.assertEqual(len(report["requested_raw_set"]["base-pmp"]), 16)
        self.assertEqual(len(report["spec_defined_set"]["base-pmp"]), 12)

    def test_incomplete_record_fails_closed(self):
        bad = _readback_record()
        del bad["reset_id"]

        errors = off_state.validate_characterization_record(bad)

        self.assertTrue(errors)
        self.assertIn("missing field reset_id", errors[0])

    def test_completed_profile_mismatch_fails_closed(self):
        errors = off_state.validate_characterization_record(
            _readback_record(profile_requested="smepmp-mml0", profile_observed="base-pmp")
        )

        self.assertTrue(any("profile_observed mismatch" in item for item in errors))

    def test_unsupported_profile_record_is_archivable_but_excluded(self):
        record = _readback_record(
            profile_requested="smepmp-mml0",
            profile_observed="base-pmp",
            execution_status="unsupported",
            unsupported_profile_reason="field_read_only_zero",
        )

        self.assertEqual(off_state.validate_characterization_record(record), [])
        report = analyzer.analyze_characterization_records(
            [
                _readback_record(reset_id="reset-000"),
                record,
            ]
        )

        self.assertEqual(report["execution_status_counts"]["unsupported"], 1)
        self.assertEqual(
            report["stable_readback_set"]["cva6"]["base-pmp"]["0"],
            ["pmpcfg-raw-v1|profile=base-pmp|a=off|l=0|r=0|w=1|x=0"],
        )
        self.assertNotIn("smepmp-mml0", report["stable_readback_set"]["cva6"])

    def test_completed_unstable_readback_fails_closed(self):
        errors = off_state.validate_characterization_record(
            _readback_record(
                reset_id="reset-000",
                execution_status="completed",
                readback_relation="unstable",
                readback_bits_2={"l": 1, "r": 0, "w": 1, "x": 0},
            )
        )

        self.assertTrue(any("completed readback record cannot be unstable" in item for item in errors))

    def test_non_completed_records_do_not_generate_mapper_witness(self):
        witness_report = validator.build_validation_report(
            dut="cva6",
            bapc_core_version="v3",
            generator_seed=7,
        )
        normalized_record = dict(witness_report["witnesses"][0]["normalized_record"])

        report = analyzer.analyze_characterization_records(
            [
                _readback_record(reset_id="reset-000"),
                _behavior_record(
                    normalized_record,
                    reset_id="reset-000",
                    execution_status="inconclusive",
                ),
            ]
        )

        self.assertEqual(report["mapper_validations"], [])
        self.assertEqual(report["mapper_witness_set"]["v2"], [])
        self.assertEqual(report["mapper_witness_set"]["v3"], [])

    def test_missing_reset_evidence_fails_closed(self):
        artifact = {
            "schema_version": off_state.OFF_STATE_SCHEMA_VERSION,
            "artifact_kind": off_state.OFF_STATE_ARTIFACT_KIND,
            "record_schema_version": off_state.OFF_STATE_RECORD_SCHEMA_VERSION,
            "dut": "cva6",
            "profiles": ["base-pmp"],
            "entry_indices": [0],
            "reset_count": 3,
            "records": [_readback_record(reset_id="reset-000")],
        }

        with self.assertRaisesRegex(ValueError, "missing reset evidence"):
            analyzer.analyze_characterization_artifact(artifact)

    def test_mapper_out_of_universe_fails_closed(self):
        witness_report = validator.build_validation_report(
            dut="cva6",
            bapc_core_version="v3",
            generator_seed=7,
        )
        normalized_record = dict(witness_report["witnesses"][0]["normalized_record"])

        with patch(
            "pmpfuzz.off_state.map_bapc_normalized_record",
            return_value={"eligible": True, "observed_bins": ["family=config|bogus=true"]},
        ):
            with self.assertRaisesRegex(ValueError, "out-of-universe"):
                analyzer.analyze_characterization_records(
                    [
                        _readback_record(reset_id="reset-000"),
                        _behavior_record(normalized_record, reset_id="reset-000"),
                    ]
                )

    def test_scripts_write_machine_readable_plan_and_analysis(self):
        witness_report = validator.build_validation_report(
            dut="cva6",
            bapc_core_version="v3",
            generator_seed=7,
        )
        normalized_record = dict(witness_report["witnesses"][0]["normalized_record"])

        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plan_output = tmp_path / "artifacts" / "off-state-plan.json"
            characterization_output = tmp_path / "artifacts" / "off-state-characterization.json"
            records_path = tmp_path / "records.jsonl"
            analysis_output = tmp_path / "artifacts" / "off-state-analysis.json"
            original_records = [
                _readback_record(reset_id="reset-000"),
                _behavior_record(normalized_record, reset_id="reset-000"),
            ]
            off_state.append_characterization_records(records_path, original_records)
            original_bytes = records_path.read_bytes()

            rc1 = characterizer.main(
                [
                    "--dut",
                    "cva6",
                    "--entry-index",
                    "0",
                    "--reset-count",
                    "1",
                    "--plan-output",
                    str(plan_output),
                    "--input-records",
                    str(records_path),
                    "--output",
                    str(characterization_output),
                ]
            )
            rc2 = analyzer.main(
                [
                    "--input",
                    str(characterization_output),
                    "--output",
                    str(analysis_output),
                ]
            )

            plan = json.loads(plan_output.read_text(encoding="ascii"))
            characterization = json.loads(characterization_output.read_text(encoding="ascii"))
            analysis = json.loads(analysis_output.read_text(encoding="ascii"))
            rewritten_bytes = records_path.read_bytes()

        self.assertEqual((rc1, rc2), (0, 0))
        self.assertEqual(plan["artifact_kind"], "pmp-off-state-plan-v1")
        self.assertEqual(plan["schema_version"], off_state.OFF_STATE_PLAN_SCHEMA_VERSION)
        self.assertEqual(characterization["artifact_kind"], "pmp-off-state-characterization-v1")
        self.assertEqual(characterization["record_schema_version"], off_state.OFF_STATE_RECORD_SCHEMA_VERSION)
        self.assertEqual(characterization["record_count"], 2)
        self.assertEqual(analysis["artifact_kind"], "pmp-off-state-analysis-v1")
        self.assertIn("base-pmp", analysis["requested_raw_vocabularies"])
        self.assertIn("base-pmp", analysis["requested_raw_set"])
        self.assertIn("base-pmp", analysis["spec_defined_set"])
        self.assertIn("behavioral_equivalence_set", analysis)
        self.assertEqual(rewritten_bytes, original_bytes)


if __name__ == "__main__":
    unittest.main()
