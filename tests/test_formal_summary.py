import csv
import json
import tempfile
import unittest
from pathlib import Path

from scripts.evaluation.analysis.summarize_formal_results import main as summarize_formal_results_main


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n", encoding="ascii")


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="ascii", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


class FormalSummaryTest(unittest.TestCase):
    def _write_campaign_artifact(
        self,
        artifact_path: Path,
        *,
        experiment_id: str,
        campaign_id: str,
        dut: str,
        seed: int,
        variant: str,
        generator_variant: str,
        covered_bin_count: int,
        coverage_denominator: int,
        eligible_bapc_cases: int,
        method: str = "pmpfuzz",
    ) -> None:
        _write_json(
            artifact_path / "metrics" / "campaign_metadata.json",
            {
                "schema_version": "1.0",
                "experiment_id": experiment_id,
                "campaign_id": campaign_id,
                "method": method,
                "variant": variant,
                "generator_variant": generator_variant,
                "dut": dut,
                "seed": seed,
                "coverage_mode": "bapc",
                "bapc_core_version": "v4",
                "bapc_target": coverage_denominator,
                "completed_cases": 1024 if "8.5" in experiment_id else 2048,
                "eligible_cases": eligible_bapc_cases,
                "eligible_hpm_cases": 0,
                "eligible_bapc_cases": eligible_bapc_cases,
            },
        )
        _write_json(
            artifact_path / "coverage" / "coverage.json",
            {
                "covered_target_bapc_bins": covered_bin_count,
                "coverage_universe_hashes": {"bapc": "test-hash"},
                "execution_coverage": {
                    "by_dut": {
                        dut: {
                            "bapc": {
                                "covered_bins": [f"bin-{i}" for i in range(covered_bin_count)],
                            }
                        }
                    }
                },
            },
        )

    def test_summary_uses_generator_variant_field_and_preserves_censored_pairs(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            main_root = tmp_root / "main"
            cascade_root = tmp_root / "cascade"
            section85_root = tmp_root / "section85"
            out_root = tmp_root / "summary"

            _write_json(
                main_root / "section-8.2" / "pmpfuzz" / "rocket" / "seed-0004" / "batch_manifest.json",
                {
                    "batch_id": "00-pmpfuzz-rocket-seed-0004",
                    "generated_elf_count": 300,
                    "elfs_per_second": 80.0,
                    "static_instructions_per_second": 15000.0,
                    "instructions_per_elf": 188.0,
                    "timed_generation_seconds": 3.75,
                    "total_static_instructions": 56400,
                },
            )
            _write_json(
                main_root / "manifests" / "formal-freeze.json",
                {
                    "bapc_core_version": "v4",
                    "bapc_target": 144,
                    "bin_set_sha256": "7e142506fe8566ac33198039caaf2c0da98473feadd826becc8dff785bb5df07",
                    "source_sha": "654dfa10da42076e9282f40ef3f6ce8d4a5acc89",
                },
            )
            _write_json(
                cascade_root / "manifests" / "formal-freeze.json",
                {
                    "bapc_core_version": "v4",
                    "bapc_target": 144,
                    "bin_set_sha256": "7e142506fe8566ac33198039caaf2c0da98473feadd826becc8dff785bb5df07",
                    "source_sha": "fixsha0000000000000000000000000000000000",
                },
            )
            _write_json(
                section85_root / "manifests" / "formal-freeze.json",
                {
                    "bapc_core_version": "v4",
                    "bapc_target": 144,
                    "bin_set_sha256": "7e142506fe8566ac33198039caaf2c0da98473feadd826becc8dff785bb5df07",
                    "source_sha": "654dfa10da42076e9282f40ef3f6ce8d4a5acc89",
                },
            )

            coverage_final_rows = [
                {
                    "schema_version": "1.0",
                    "experiment_id": "section-8.3-8.4-formal-v4",
                    "campaign_id": "random-seed-6",
                    "method": "pmpfuzz",
                    "variant": "random-mutation",
                    "generator_variant": "full",
                    "dut": "rocket-clean",
                    "seed": "6",
                    "coverage_mode": "bapc",
                    "bapc_rate": str(122 / 144),
                    "completed_cases": "3080",
                    "eligible_cases": "2400",
                    "eligible_hpm_cases": "0",
                    "eligible_bapc_cases": "2349",
                    "effective_eligible_cases": "2349",
                    "artifact_path": str(main_root / "artifacts" / "random-seed-6"),
                },
                {
                    "schema_version": "1.0",
                    "experiment_id": "section-8.3-8.4-formal-v4",
                    "campaign_id": "guided-seed-6",
                    "method": "pmpfuzz",
                    "variant": "bb-guided",
                    "generator_variant": "full",
                    "dut": "rocket-clean",
                    "seed": "6",
                    "coverage_mode": "bapc",
                    "bapc_rate": str(121 / 144),
                    "completed_cases": "2056",
                    "eligible_cases": "1700",
                    "eligible_hpm_cases": "0",
                    "eligible_bapc_cases": "1637",
                    "effective_eligible_cases": "1637",
                    "artifact_path": str(main_root / "artifacts" / "guided-seed-6"),
                },
            ]
            timeseries_rows = [
                {
                    "schema_version": "1.0",
                    "experiment_id": "section-8.3-8.4-formal-v4",
                    "campaign_id": "random-seed-6",
                    "method": "pmpfuzz",
                    "variant": "random-mutation",
                    "generator_variant": "full",
                    "dut": "rocket-clean",
                    "seed": "6",
                    "coverage_mode": "bapc",
                    "completion_seq": "2601",
                    "elapsed_wall_seconds": "2752.2",
                    "completed_cases": "2601",
                    "eligible_cases": "2200",
                    "eligible_hpm_cases": "0",
                    "eligible_bapc_cases": "2100",
                    "covered_bins": "122",
                    "target_bins": "144",
                    "coverage_rate": str(122 / 144),
                    "new_bins": "1",
                    "status": "pass",
                    "failure_class": "",
                    "case_id": "case-r",
                },
                {
                    "schema_version": "1.0",
                    "experiment_id": "section-8.3-8.4-formal-v4",
                    "campaign_id": "guided-seed-6",
                    "method": "pmpfuzz",
                    "variant": "bb-guided",
                    "generator_variant": "full",
                    "dut": "rocket-clean",
                    "seed": "6",
                    "coverage_mode": "bapc",
                    "completion_seq": "2056",
                    "elapsed_wall_seconds": "2245.8",
                    "completed_cases": "2056",
                    "eligible_cases": "1600",
                    "eligible_hpm_cases": "0",
                    "eligible_bapc_cases": "1637",
                    "covered_bins": "121",
                    "target_bins": "144",
                    "coverage_rate": str(121 / 144),
                    "new_bins": "0",
                    "status": "pass",
                    "failure_class": "",
                    "case_id": "case-g",
                },
            ]
            _write_csv(main_root / "dut-roots" / "rocket-clean" / "aggregate" / "coverage_final.csv", coverage_final_rows)
            _write_csv(main_root / "dut-roots" / "rocket-clean" / "aggregate" / "coverage_timeseries.csv", timeseries_rows)
            main_campaign_index_rows = [
                {
                    **row,
                    "artifact_path": str(main_root / "artifacts" / row["campaign_id"]),
                }
                for row in coverage_final_rows
            ]
            _write_csv(main_root / "dut-roots" / "rocket-clean" / "aggregate" / "campaign_index.csv", main_campaign_index_rows)
            self._write_campaign_artifact(
                main_root / "artifacts" / "random-seed-6",
                experiment_id="section-8.3-8.4-formal-v4",
                campaign_id="random-seed-6",
                dut="rocket-clean",
                seed=6,
                variant="random-mutation",
                generator_variant="full",
                covered_bin_count=122,
                coverage_denominator=144,
                eligible_bapc_cases=2349,
            )
            self._write_campaign_artifact(
                main_root / "artifacts" / "guided-seed-6",
                experiment_id="section-8.3-8.4-formal-v4",
                campaign_id="guided-seed-6",
                dut="rocket-clean",
                seed=6,
                variant="bb-guided",
                generator_variant="full",
                covered_bin_count=121,
                coverage_denominator=144,
                eligible_bapc_cases=1637,
            )

            section85_rows = [
                {
                    "schema_version": "1.0",
                    "experiment_id": "section-8.5-formal-v4",
                    "campaign_id": "pair-a",
                    "method": "pmpfuzz",
                    "variant": "bb-guided",
                    "dut": "rocket-clean",
                    "seed": "4",
                    "coverage_mode": "bapc",
                    "bapc_rate": str(116 / 144),
                    "completed_cases": "1024",
                    "eligible_cases": "820",
                    "eligible_hpm_cases": "0",
                    "eligible_bapc_cases": "818",
                    "effective_eligible_cases": "818",
                },
                {
                    "schema_version": "1.0",
                    "experiment_id": "section-8.5-formal-v4",
                    "campaign_id": "pair-b",
                    "method": "pmpfuzz",
                    "variant": "bb-guided",
                    "dut": "rocket-clean",
                    "seed": "4",
                    "coverage_mode": "bapc",
                    "bapc_rate": str(85 / 144),
                    "completed_cases": "1024",
                    "eligible_cases": "780",
                    "eligible_hpm_cases": "0",
                    "eligible_bapc_cases": "778",
                    "effective_eligible_cases": "778",
                },
            ]
            _write_csv(section85_root / "dut-roots" / "rocket-clean" / "aggregate" / "coverage_final.csv", section85_rows)
            section85_index_rows = [
                {
                    **row,
                    "artifact_path": str(section85_root / "artifacts" / row["campaign_id"]),
                }
                for row in section85_rows
            ]
            _write_csv(section85_root / "dut-roots" / "rocket-clean" / "aggregate" / "campaign_index.csv", section85_index_rows)
            self._write_campaign_artifact(
                section85_root / "artifacts" / "pair-a",
                experiment_id="section-8.5-formal-v4",
                campaign_id="pair-a",
                dut="rocket-clean",
                seed=4,
                variant="bb-guided",
                generator_variant="full",
                covered_bin_count=116,
                coverage_denominator=144,
                eligible_bapc_cases=818,
            )
            self._write_campaign_artifact(
                section85_root / "artifacts" / "pair-b",
                experiment_id="section-8.5-formal-v4",
                campaign_id="pair-b",
                dut="rocket-clean",
                seed=4,
                variant="bb-guided",
                generator_variant="syntax",
                covered_bin_count=85,
                coverage_denominator=144,
                eligible_bapc_cases=778,
            )

            rc = summarize_formal_results_main(
                [
                    "--main-root",
                    str(main_root),
                    "--cascade-root",
                    str(cascade_root),
                    "--section85-root",
                    str(section85_root),
                    "--output-root",
                    str(out_root),
                    "--allow-partial-counts",
                ]
            )
            self.assertEqual(rc, 0)

            paired = json.loads((out_root / "section-8.4-paired-endpoints.json").read_text(encoding="ascii"))
            campaigns_85 = json.loads((out_root / "section-8.5-campaigns.json").read_text(encoding="ascii"))

            self.assertEqual(len(paired), 1)
            self.assertEqual(paired[0]["guided_status"], "censored")
            self.assertIsNone(paired[0]["guided_elapsed_wall_seconds"])
            self.assertEqual(paired[0]["guided_censor_time_seconds"], 2245.8)
            by_id = {row["campaign_id"]: row for row in campaigns_85}
            self.assertEqual(len(campaigns_85), 2)
            self.assertEqual(by_id["pair-a"]["generator_variant"], "full")
            self.assertEqual(by_id["pair-b"]["generator_variant"], "syntax")
            self.assertEqual(by_id["pair-a"]["covered_bin_count"], 116)
            self.assertEqual(by_id["pair-a"]["coverage_denominator"], 144)
            self.assertEqual(by_id["pair-b"]["covered_bin_count"], 85)
            self.assertEqual(by_id["pair-b"]["coverage_denominator"], 144)

    def test_summary_reads_campaign_coverage_from_metrics_subdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            main_root = tmp_root / "main"
            cascade_root = tmp_root / "cascade"
            out_root = tmp_root / "summary"

            for root, source_sha in (
                (main_root, "654dfa10da42076e9282f40ef3f6ce8d4a5acc89"),
                (cascade_root, "b0686537aad75e47b27f1618d9518d8e2045afbb"),
            ):
                _write_json(
                    root / "manifests" / "formal-freeze.json",
                    {
                        "bapc_core_version": "v4",
                        "bapc_target": 144,
                        "bin_set_sha256": "7e142506fe8566ac33198039caaf2c0da98473feadd826becc8dff785bb5df07",
                        "source_sha": source_sha,
                    },
                )

            artifact_path = (
                cascade_root
                / "dut-roots"
                / "rocket-clean"
                / "campaigns"
                / "section-8.3-8.4-formal-v4"
                / "rocket-clean"
                / "cascade"
                / "bapc"
                / "seed-0004"
            )
            self._write_campaign_artifact(
                artifact_path,
                experiment_id="section-8.3-8.4-formal-v4",
                campaign_id="cascade__rocket-clean__seed-0004",
                dut="rocket-clean",
                seed=4,
                variant="cascade",
                generator_variant="",
                covered_bin_count=9,
                coverage_denominator=144,
                eligible_bapc_cases=302,
                method="cascade",
            )
            legacy_coverage_path = artifact_path / "coverage" / "coverage.json"
            metrics_coverage_path = artifact_path / "metrics" / "coverage" / "coverage.json"
            metrics_coverage_path.parent.mkdir(parents=True, exist_ok=True)
            metrics_coverage_path.write_text(legacy_coverage_path.read_text(encoding="ascii"), encoding="ascii")
            legacy_coverage_path.unlink()
            _write_json(
                artifact_path / "metrics" / "cascade_runtime_validation.json",
                {
                    "schema_version": "cascade-runtime-validation-v1",
                    "campaign_dir": str(artifact_path),
                    "bapc_core_version": "v4",
                    "completed_cases": 342,
                    "artifact_valid": True,
                    "artifact_valid_cases": 342,
                    "measurement_valid": True,
                    "measurement_valid_cases": 342,
                    "runtime_record_cases": 302,
                    "runtime_record_rate": 302 / 342,
                    "eligible_bapc_cases": 302,
                    "eligible_bapc_rate": 302 / 342,
                    "covered_bin_count": None,
                    "coverage_denominator": None,
                    "covered_bins": [f"bin-{idx}" for idx in range(9)],
                    "family_coverage": {"configuration": 1, "stimulus": 2, "decision": 2, "privilege-decision": 2, "mode-decision": 2},
                    "qualification_reason_counts": {"eligible": 302},
                    "out_of_contract_bins": [],
                    "unexpected_mapper_bins": [],
                    "replay_failure_count": 0,
                    "replay_failures": [],
                },
            )

            rc = summarize_formal_results_main(
                ["--main-root", str(main_root), "--cascade-root", str(cascade_root), "--output-root", str(out_root), "--allow-partial-counts"]
            )
            self.assertEqual(rc, 0)

            campaigns = json.loads((out_root / "section-8.3-8.4-campaigns.json").read_text(encoding="ascii"))
            self.assertEqual(len(campaigns), 1)
            self.assertEqual(campaigns[0]["campaign_id"], "cascade__rocket-clean__seed-0004")
            self.assertEqual(campaigns[0]["covered_bin_count"], 9)
            self.assertEqual(campaigns[0]["coverage_denominator"], 144)
            self.assertAlmostEqual(campaigns[0]["bapc_rate"], 9 / 144)

    def test_summary_fails_closed_on_incomplete_formal_counts_and_counts_section82_batches_by_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            main_root = tmp_root / "main"
            cascade_root = tmp_root / "cascade"
            section85_root = tmp_root / "section85"
            out_root = tmp_root / "summary"

            for root, source_sha in (
                (main_root, "654dfa10da42076e9282f40ef3f6ce8d4a5acc89"),
                (cascade_root, "0a19f04f511eb9942ce011c8952fcd9d5d3dc7eb"),
                (section85_root, "654dfa10da42076e9282f40ef3f6ce8d4a5acc89"),
            ):
                _write_json(
                    root / "manifests" / "formal-freeze.json",
                    {
                        "bapc_core_version": "v4",
                        "bapc_target": 144,
                        "bin_set_sha256": "7e142506fe8566ac33198039caaf2c0da98473feadd826becc8dff785bb5df07",
                        "source_sha": source_sha,
                    },
                )

            for tool, dut in (("pmpfuzz", "rocket"), ("cascade", "boom")):
                _write_json(
                    main_root / "section-8.2" / tool / dut / "seed-0004" / "batch_manifest.json",
                    {
                        "generated_elf_count": 300,
                        "elfs_per_second": 10.0,
                        "static_instructions_per_second": 1000.0,
                        "instructions_per_elf": 100.0,
                        "timed_generation_seconds": 30.0,
                    },
                )

            rc = summarize_formal_results_main(
                [
                    "--main-root",
                    str(main_root),
                    "--cascade-root",
                    str(cascade_root),
                    "--section85-root",
                    str(section85_root),
                    "--output-root",
                    str(out_root),
                ]
            )
            self.assertEqual(rc, 1)

            validation = json.loads((out_root / "validation_report.json").read_text(encoding="ascii"))
            self.assertFalse(validation["valid"])
            self.assertEqual(validation["counts"]["section_8_2_batches"], 2)
            self.assertEqual(validation["expected_counts"]["section_8_2_batches"], 18)
            error_kinds = {row["kind"] for row in validation["errors"]}
            self.assertIn("unexpected-section-8-2-batches-count", error_kinds)
            self.assertIn("unexpected-section-8-3-8-4-campaigns-count", error_kinds)
            self.assertIn("unexpected-section-8-4-pairs-count", error_kinds)
            self.assertIn("unexpected-section-8-5-campaigns-count", error_kinds)

    def test_summary_nulls_invalid_direct_cascade_measurement_without_aggregate_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            main_root = tmp_root / "main"
            cascade_root = tmp_root / "cascade"
            out_root = tmp_root / "summary"

            for root, source_sha in (
                (main_root, "654dfa10da42076e9282f40ef3f6ce8d4a5acc89"),
                (cascade_root, "0a19f04f511eb9942ce011c8952fcd9d5d3dc7eb"),
            ):
                _write_json(
                    root / "manifests" / "formal-freeze.json",
                    {
                        "bapc_core_version": "v4",
                        "bapc_target": 144,
                        "bin_set_sha256": "7e142506fe8566ac33198039caaf2c0da98473feadd826becc8dff785bb5df07",
                        "source_sha": source_sha,
                    },
                )

            artifact_path = (
                cascade_root
                / "dut-roots"
                / "cva6-clean"
                / "campaigns"
                / "section-8.3-8.4-formal-v4"
                / "cva6-clean"
                / "cascade"
                / "bapc"
                / "seed-0004"
            )
            self._write_campaign_artifact(
                artifact_path,
                experiment_id="section-8.3-8.4-formal-v4",
                campaign_id="cascade__cva6-clean__seed-0004",
                dut="cva6-clean",
                seed=4,
                variant="cascade",
                generator_variant="",
                covered_bin_count=0,
                coverage_denominator=144,
                eligible_bapc_cases=0,
                method="cascade",
            )
            (artifact_path / "metrics" / "coverage_timeline.jsonl").write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "experiment_id": "section-8.3-8.4-formal-v4",
                        "campaign_id": "cascade__cva6-clean__seed-0004",
                        "completion_seq": 925,
                        "elapsed_wall_seconds": 7203.8,
                        "completed_cases": 925,
                        "eligible_cases": 925,
                        "eligible_bapc_cases": 0,
                        "covered_bins": 0,
                        "target_bins": 144,
                        "coverage_rate": 0.0,
                        "new_bins": 0,
                        "status": "completed",
                        "case_id": "cascade_cva6_0004",
                    },
                    ensure_ascii=True,
                    sort_keys=True,
                )
                + "\n",
                encoding="ascii",
            )
            _write_json(
                artifact_path / "metrics" / "cascade_runtime_validation.json",
                {
                    "schema_version": "cascade-runtime-validation-v1",
                    "campaign_dir": str(artifact_path),
                    "bapc_core_version": "v4",
                    "completed_cases": 925,
                    "artifact_valid": True,
                    "artifact_valid_cases": 925,
                    "measurement_valid": False,
                    "measurement_valid_cases": 0,
                    "runtime_record_cases": 741,
                    "runtime_record_rate": 741 / 925,
                    "eligible_bapc_cases": 0,
                    "eligible_bapc_rate": 0.0,
                    "covered_bin_count": None,
                    "coverage_denominator": None,
                    "covered_bins": [],
                    "family_coverage": {},
                    "qualification_reason_counts": {
                        "missing-actual-runtime-record": 925,
                    },
                    "out_of_contract_bins": [],
                    "unexpected_mapper_bins": [],
                    "replay_failure_count": 0,
                    "replay_failures": [],
                },
            )

            rc = summarize_formal_results_main(
                [
                    "--main-root",
                    str(main_root),
                    "--cascade-root",
                    str(cascade_root),
                    "--output-root",
                    str(out_root),
                    "--allow-partial-counts",
                ]
            )
            self.assertEqual(rc, 1)

            campaigns = json.loads((out_root / "section-8.3-8.4-campaigns.json").read_text(encoding="ascii"))
            self.assertEqual(len(campaigns), 1)
            self.assertEqual(campaigns[0]["campaign_id"], "cascade__cva6-clean__seed-0004")
            self.assertEqual(campaigns[0]["method"], "cascade")
            self.assertEqual(campaigns[0]["variant"], "cascade")
            self.assertTrue(campaigns[0]["artifact_valid"])
            self.assertFalse(campaigns[0]["measurement_valid"])
            self.assertEqual(campaigns[0]["runtime_record_rate"], 741 / 925)
            self.assertEqual(
                campaigns[0]["qualification_reason_counts"],
                {"missing-actual-runtime-record": 925},
            )
            self.assertIsNone(campaigns[0]["covered_bin_count"])
            self.assertIsNone(campaigns[0]["coverage_denominator"])
            self.assertIsNone(campaigns[0]["bapc_rate"])

            validation = json.loads((out_root / "validation_report.json").read_text(encoding="ascii"))
            self.assertFalse(validation["valid"])
            self.assertIn(
                "measurement-invalid-campaign",
                {error["kind"] for error in validation["errors"]},
            )


if __name__ == "__main__":
    unittest.main()
