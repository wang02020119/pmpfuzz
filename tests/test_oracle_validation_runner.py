from __future__ import annotations

import tempfile
import unittest
from unittest import mock
from pathlib import Path

from pmpfuzz.dut import DutRunResult
from scripts.evaluation.oracle_validation.generate_reference_cases import write_reference_corpus
from scripts.evaluation.oracle_validation.mutate_observations import build_counterfactuals
from scripts.evaluation.oracle_validation.run_oracle_validation import (
    run_clean_suite,
    run_counterfactual_suite,
    run_directed_suite,
    run_online_campaign,
)


class OracleValidationRunnerTest(unittest.TestCase):
    def test_clean_suite_requests_whitebox_artifacts_for_clean_dut_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )

            fake_runner = mock.Mock()
            fake_runner.run.return_value = DutRunResult(
                dut="rocket-clean",
                status="timeout",
                elapsed_seconds=0.0,
                failure_class="timeout",
                reason="synthetic timeout",
            )

            with (
                mock.patch(
                    "scripts.evaluation.oracle_validation.run_oracle_validation.make_dut",
                    return_value=fake_runner,
                ) as make_dut_mock,
                mock.patch(
                    "scripts.evaluation.oracle_validation.run_oracle_validation.subprocess.run",
                    return_value=mock.Mock(returncode=0, stdout=""),
                ),
            ):
                summary = run_clean_suite(
                    cases_path=root / "reference" / "cases.jsonl",
                    labels_path=root / "reference" / "labels.jsonl",
                    out_dir=root / "phase0",
                    dut="rocket-clean",
                    order_seed=4,
                    limit=1,
                    dut_bin=root / "fake-simulator",
                )

            self.assertTrue(summary["whitebox_artifacts"])
            self.assertEqual(summary["results"][0]["status"], "timeout")
            self.assertTrue(make_dut_mock.called)
            self.assertTrue(make_dut_mock.call_args.kwargs["whitebox_artifacts"])

    def test_clean_suite_materialize_only_writes_formal_case_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )
            summary = run_clean_suite(
                cases_path=root / "reference" / "cases.jsonl",
                labels_path=root / "reference" / "labels.jsonl",
                out_dir=root / "phase0",
                dut="spike",
                order_seed=4,
                limit=2,
                materialize_only=True,
            )

            seed_root = root / "phase0" / "clean" / "spike" / "seed-0004"
            case_dirs = sorted(item for item in seed_root.iterdir() if item.is_dir())
            self.assertEqual(summary["case_count"], 2)
            self.assertEqual(len(case_dirs), 2)
            for case_dir in case_dirs:
                self.assertTrue((case_dir / "scenario.json").is_file())
                self.assertTrue((case_dir / "case.json").is_file())
                self.assertTrue((case_dir / "reference-label.json").is_file())
                self.assertTrue((case_dir / "contract-trace.json").is_file())
                self.assertTrue((case_dir / "result.json").is_file())

    def test_counterfactual_suite_runs_offline_judgment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )
            clean_summary = run_clean_suite(
                cases_path=root / "reference" / "cases.jsonl",
                labels_path=root / "reference" / "labels.jsonl",
                out_dir=root / "phase0",
                dut="spike",
                order_seed=4,
                limit=1,
                materialize_only=True,
            )
            seed_root = root / "phase0" / "clean" / "spike" / "seed-0004"
            case_dir = next(item for item in seed_root.iterdir() if item.is_dir())
            case_payload = __import__("json").loads((case_dir / "case.json").read_text(encoding="utf-8"))
            label_payload = __import__("json").loads((case_dir / "reference-label.json").read_text(encoding="utf-8"))

            counterfactuals = build_counterfactuals(
                case_record=case_payload,
                reference_label=label_payload,
                result_record={
                    "observed_event": "completion",
                    "observed_mcause": 8,
                    "observed_mtval_fingerprint": 0,
                    "observed_mepc_tag": 4,
                    "observed_phase": "completed",
                    "observed_stage": None,
                    "observed_ptw_level": None,
                    "observed_fault_address": None,
                },
            )
            counterfactual_path = root / "phase0" / "counterfactuals.jsonl"
            with counterfactual_path.open("w", encoding="utf-8") as handle:
                import json

                for item in counterfactuals:
                    handle.write(json.dumps(item, ensure_ascii=True, sort_keys=True) + "\n")

            summary = run_counterfactual_suite(
                cases_path=root / "reference" / "cases.jsonl",
                counterfactuals_path=counterfactual_path,
                out_dir=root / "phase0",
            )

            self.assertEqual(summary["counterfactual_count"], len(counterfactuals))
            self.assertTrue((root / "phase0" / "counterfactual" / "summary.json").is_file())

    def test_clean_suite_can_archive_existing_suite_root_before_rerun(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )
            seed_root = root / "phase0" / "clean" / "spike" / "seed-0004"

            first = run_clean_suite(
                cases_path=root / "reference" / "cases.jsonl",
                labels_path=root / "reference" / "labels.jsonl",
                out_dir=root / "phase0",
                dut="spike",
                order_seed=4,
                limit=1,
                materialize_only=True,
                suite_root=seed_root,
            )
            self.assertIsNone(first["archived_previous_suite_root"])
            marker = seed_root / "sentinel.txt"
            marker.write_text("old-run", encoding="utf-8")

            second = run_clean_suite(
                cases_path=root / "reference" / "cases.jsonl",
                labels_path=root / "reference" / "labels.jsonl",
                out_dir=root / "phase0",
                dut="spike",
                order_seed=4,
                limit=1,
                materialize_only=True,
                suite_root=seed_root,
                archive_existing=True,
            )

            archived_root = Path(second["archived_previous_suite_root"])
            self.assertTrue(archived_root.is_dir())
            self.assertTrue((archived_root / "summary.json").is_file())
            self.assertEqual((archived_root / "sentinel.txt").read_text(encoding="utf-8"), "old-run")
            self.assertTrue((seed_root / "summary.json").is_file())
            self.assertFalse((seed_root / "sentinel.txt").exists())

    def test_online_campaign_uses_contract_layout_and_validates_after_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifests_dir = root / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            binary_path = root / "rocket-mutant.bin"
            binary_path.write_bytes(b"mutant-binary\n")

            (manifests_dir / "experiment-contract.json").write_text(
                __import__("json").dumps({"experiment_protocol_id": "oracle-validation-v1"}, indent=2),
                encoding="utf-8",
            )
            (manifests_dir / "mutants.json").write_text(
                __import__("json").dumps(
                    {
                        "schema_version": 1,
                        "entries": [
                            {
                                "dut": "rocket-clean",
                                "mutant_id": "M08",
                                "fault_family": "ptw_bypass",
                                "critical_family": True,
                            }
                        ],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            mutant_root = root / "mutants" / "rocket-clean" / "M08"
            mutant_root.mkdir(parents=True, exist_ok=True)
            (mutant_root / "build-manifest.json").write_text(
                __import__("json").dumps({"schema_version": 1, "binary_path": str(binary_path)}, indent=2),
                encoding="utf-8",
            )

            with mock.patch(
                "scripts.evaluation.oracle_validation.run_oracle_validation.subprocess.run"
            ) as run_mock:
                summary = run_online_campaign(
                    artifact_root=root,
                    dut="rocket-clean",
                    mutant_id="M08",
                    seed=4,
                    chipyard_dir=root,
                )

            self.assertEqual(summary["mutant_id"], "M08")
            self.assertEqual(
                summary["campaign_root"],
                str(root / "mutants" / "rocket-clean" / "M08" / "campaigns" / "seed-0004"),
            )
            self.assertEqual(run_mock.call_count, 2)
            driver_cmd = run_mock.call_args_list[0].args[0]
            validate_cmd = run_mock.call_args_list[1].args[0]
            self.assertIn("--campaign-dir", driver_cmd)
            self.assertIn(str(root / "mutants" / "rocket-clean" / "M08" / "campaigns" / "seed-0004"), driver_cmd)
            self.assertIn("--max-completed-cases", driver_cmd)
            self.assertIn("2048", driver_cmd)
            self.assertIn("--fault-family", driver_cmd)
            self.assertIn("ptw_bypass", driver_cmd)
            self.assertIn("--critical-family", driver_cmd)
            self.assertIn("scripts.evaluation.validation.validate_timeline", validate_cmd)

    def test_directed_suite_rejects_build_manifest_binary_sha_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            import hashlib
            import json

            root = Path(tmp)
            write_reference_corpus(
                artifact_root=root,
                generator_seed=7601,
                spec_revision="unit-spec",
            )
            cases = [
                json.loads(line)
                for line in (root / "reference" / "cases.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            activation_case_id = str(cases[0]["case_id"])
            control_case_id = str(cases[1]["case_id"])

            binary_path = root / "rocket-mutant.bin"
            binary_path.write_bytes(b"original-mutant-binary\n")
            recorded_sha256 = hashlib.sha256(binary_path.read_bytes()).hexdigest()
            binary_path.write_bytes(b"overwritten-mutant-binary\n")

            mutant_root = root / "mutants" / "rocket-clean" / "M08"
            mutant_root.mkdir(parents=True, exist_ok=True)
            (mutant_root / "build-manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "status": "built",
                        "binary_path": str(binary_path),
                        "binary_sha256": recorded_sha256,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            (mutant_root / "activation-plan.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "dut": "rocket-clean",
                        "mutant_id": "M08",
                        "activation_case_ids": [activation_case_id],
                        "control_case_ids": [control_case_id],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "build-manifest binary sha256 mismatch"):
                run_directed_suite(
                    artifact_root=root,
                    dut="rocket-clean",
                    mutant_id="M08",
                    order_seed=4,
                )


if __name__ == "__main__":
    unittest.main()
