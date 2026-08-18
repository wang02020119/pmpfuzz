import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmpfuzz import off_state
from pmpfuzz.bapc import map_bapc_normalized_record
from scripts.evaluation.validation import validate_bapc_universe as validator


class ValidateBapcUniverseTest(unittest.TestCase):
    def test_build_validation_report_closes_v3_universe(self):
        report = validator.build_validation_report(dut="cva6", bapc_core_version="v3", generator_seed=7)

        self.assertEqual(report["bapc_core_version"], "v3")
        self.assertEqual(report["candidate_vocabulary_size"], 129)
        self.assertEqual(report["family_sizes"]["config"], 49)
        self.assertEqual(report["family_sizes"]["stimulus"], 26)
        self.assertEqual(report["family_sizes"]["decision"], 12)
        self.assertEqual(report["family_sizes"]["privilege-decision"], 18)
        self.assertEqual(report["family_sizes"]["mode-decision"], 24)
        self.assertEqual(report["witnessed_bin_count"], 129)
        self.assertEqual(report["unwitnessed_bin_count"], 0)
        self.assertEqual(report["unexpected_mapper_bin_count"], 0)
        self.assertEqual(len(report["witnesses"]), 129)
        self.assertTrue(all("normalized_record" in item for item in report["witnesses"]))

    def test_main_writes_machine_readable_report(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "artifacts" / "bapc-v3-selfcheck.json"
            rc = validator.main(
                [
                    "--dut",
                    "cva6",
                    "--bapc-core-version",
                    "v3",
                    "--generator-seed",
                    "7",
                    "--output",
                    str(output),
                ]
            )
            report = json.loads(output.read_text(encoding="ascii"))

        self.assertEqual(rc, 0)
        self.assertEqual(report["unwitnessed_bin_count"], 0)
        self.assertEqual(report["unexpected_mapper_bin_count"], 0)

    def test_build_validation_report_closes_v4_universe_with_off_state_artifact(self):
        records = []
        for index, encoding in enumerate(off_state.off_state_encodings()):
            bits = encoding.as_dict()
            records.append(
                {
                    "record_schema_version": off_state.OFF_STATE_RECORD_SCHEMA_VERSION,
                    "dut": "cva6",
                    "profile_requested": "base-pmp",
                    "profile_observed": "base-pmp",
                    "entry_index": 0,
                    "reset_id": f"reset-{index:03d}",
                    "subexperiment": "readback",
                    "requested_bits": bits,
                    "spec_status": off_state.spec_status_for_off_state("base-pmp", bits),
                    "execution_status": "completed",
                    "write_outcome": "accepted",
                    "readback_relation": "exact",
                    "readback_bits_1": bits,
                    "readback_bits_2": bits,
                    "pmpaddr_value": "0x0",
                    "raw_log_sha256": f"{index:064x}",
                }
            )
        artifact = {
            "schema_version": off_state.OFF_STATE_SCHEMA_VERSION,
            "artifact_kind": off_state.OFF_STATE_ARTIFACT_KIND,
            "record_schema_version": off_state.OFF_STATE_RECORD_SCHEMA_VERSION,
            "reset_count": 1,
            "records": records,
        }

        with TemporaryDirectory() as tmp:
            artifact_path = Path(tmp) / "off-state.json"
            artifact_path.write_text(json.dumps(artifact, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
            report = validator.build_validation_report(
                dut="cva6",
                bapc_core_version="v4",
                generator_seed=7,
                off_state_artifact=artifact_path,
            )

        self.assertEqual(report["candidate_vocabulary_size"], 144)
        self.assertEqual(report["witnessed_bin_count"], 144)
        self.assertEqual(report["unwitnessed_bin_count"], 0)
        self.assertEqual(report["unexpected_mapper_bin_count"], 0)

    def test_machine_readable_report_witnesses_are_fully_replayable_from_disk(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "artifacts" / "bapc-v3-selfcheck.json"
            rc = validator.main(
                [
                    "--dut",
                    "cva6",
                    "--bapc-core-version",
                    "v3",
                    "--generator-seed",
                    "7",
                    "--output",
                    str(output),
                ]
            )
            report = json.loads(output.read_text(encoding="ascii"))

        replayed_bins = set()
        for witness in report["witnesses"]:
            record = dict(witness["normalized_record"])
            self.assertIn("pmp_entries", record)
            self.assertIn("size", record)
            self.assertIn("address", record)
            self.assertIn("access", record)
            self.assertIn("privilege", record)
            mapped = map_bapc_normalized_record(record, bapc_core_version="v3")
            self.assertTrue(mapped["eligible"], witness["bin_id"])
            self.assertIn(witness["bin_id"], mapped["observed_bins"])
            self.assertEqual(mapped["observed_bins"], witness["all_bins_emitted_by_record"])
            replayed_bins.update(mapped["observed_bins"])

        self.assertEqual(rc, 0)
        self.assertEqual(replayed_bins, set(report["universe_bins"]))
        self.assertEqual(report["unexpected_mapper_bins"], [])
        self.assertEqual(report["unwitnessed_bins"], [])


if __name__ == "__main__":
    unittest.main()
