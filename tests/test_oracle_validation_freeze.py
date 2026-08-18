from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pmpfuzz.capabilities import capability_for_dut
from scripts.evaluation.oracle_validation.freeze_formal_artifact import (
    freeze_formal_artifact,
    build_section76_bapc_universe,
)


class OracleValidationFormalFreezeTest(unittest.TestCase):
    def test_build_section76_bapc_universe_is_canonical_208_bin_contract(self):
        universe = build_section76_bapc_universe(generator_seed=20260628)

        self.assertEqual(universe["bin_count"], 208)
        self.assertEqual(universe["dut"], "section76-primary-clean-duts")
        self.assertEqual(
            universe["capability_fingerprint"],
            "bapc:section76-primary-clean-duts:fault-stage=1:smepmp=0",
        )
        self.assertFalse(any("family=translation-stage" in item for item in universe["bin_ids"]))

    def test_freeze_formal_artifact_writes_contracts_and_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root = root / "artifact"
            binaries = {}
            capabilities = {}
            for dut in ("rocket-clean", "boom-clean", "cva6-clean"):
                binary = root / f"{dut}.bin"
                binary.write_bytes(f"{dut}-binary".encode("ascii"))
                binaries[dut] = binary
                capabilities[dut] = capability_for_dut(dut, available=True, path=binary)

            summary = freeze_formal_artifact(
                artifact_root=artifact_root,
                source_root=root,
                dut_binary_paths=binaries,
                capabilities_by_dut=capabilities,
                source_provenance={
                    "source_sha": "a" * 40,
                    "source_tree_sha256": "b" * 64,
                    "source_dirty": False,
                },
            )

            self.assertEqual(summary["bapc_bin_count"], 208)

            coverage_contract = json.loads(
                (artifact_root / "manifests" / "coverage-contract.json").read_text(encoding="utf-8")
            )
            self.assertEqual(coverage_contract["bapc_v2"]["bin_count"], 208)
            self.assertEqual(sorted(coverage_contract["secondary_pmpfuzz_coverage"]["duts"].keys()), ["boom-clean", "cva6-clean", "rocket-clean"])

            experiment_contract = json.loads(
                (artifact_root / "manifests" / "experiment-contract.json").read_text(encoding="utf-8")
            )
            self.assertEqual(experiment_contract["primary_duts"], ["rocket-clean", "boom-clean", "cva6-clean"])
            self.assertEqual(experiment_contract["clean_suite"]["max_clean_executions"], 3888)
            self.assertEqual(experiment_contract["excluded_duts"][0]["dut"], "xiangshan-clean")
            self.assertIn("O11", experiment_contract["counterfactual_suite"]["mutation_ids"])
            self.assertEqual(experiment_contract["mutants_manifest_path"], "manifests/mutants.json")

            capabilities_manifest = json.loads(
                (artifact_root / "manifests" / "capabilities.json").read_text(encoding="utf-8")
            )
            self.assertEqual(capabilities_manifest["reference_case_count"], 432)
            for dut in ("rocket-clean", "boom-clean", "cva6-clean"):
                applicability_counts = capabilities_manifest["duts"][dut]["applicability_counts"]
                self.assertEqual(sum(applicability_counts.values()), 432)
            self.assertEqual(
                capabilities_manifest["duts"]["rocket-clean"]["applicability_by_case"]["C4-0045"],
                "valid",
            )
            self.assertEqual(
                capabilities_manifest["duts"]["cva6-clean"]["applicability_by_case"]["C4-0045"],
                "capability_dependent",
            )
            self.assertEqual(
                capabilities_manifest["duts"]["rocket-clean"]["applicability_by_case"]["C3-0069"],
                "valid",
            )
            self.assertEqual(
                capabilities_manifest["duts"]["cva6-clean"]["applicability_by_case"]["C3-0069"],
                "capability_dependent",
            )
            self.assertEqual(
                capabilities_manifest["duts"]["rocket-clean"]["applicability_by_case"]["C6-0055"],
                "valid",
            )
            self.assertEqual(
                capabilities_manifest["duts"]["cva6-clean"]["applicability_by_case"]["C6-0055"],
                "capability_dependent",
            )

            binaries_manifest = json.loads(
                (artifact_root / "manifests" / "dut-binaries.json").read_text(encoding="utf-8")
            )
            for dut in ("rocket-clean", "boom-clean", "cva6-clean"):
                self.assertTrue(binaries_manifest["duts"][dut]["sha256"])
                self.assertTrue(binaries_manifest["duts"][dut]["exists"])

            self.assertTrue((artifact_root / "manifests" / "mutants.json").is_file())

    def test_freeze_formal_artifact_rejects_dirty_source_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root = root / "artifact"
            binary = root / "rocket-clean.bin"
            binary.write_bytes(b"rocket-clean-binary")

            with self.assertRaisesRegex(ValueError, "source_dirty=False"):
                freeze_formal_artifact(
                    artifact_root=artifact_root,
                    source_root=root,
                    primary_duts=("rocket-clean",),
                    dut_binary_paths={"rocket-clean": binary},
                    capabilities_by_dut={
                        "rocket-clean": capability_for_dut("rocket-clean", available=True, path=binary),
                    },
                    source_provenance={
                        "source_sha": "a" * 40,
                        "source_tree_sha256": "b" * 64,
                        "source_dirty": True,
                    },
                )

    def test_freeze_formal_artifact_accepts_custom_reference_family_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root = root / "artifact"
            binary = root / "rocket-clean.bin"
            binary.write_bytes(b"rocket-clean-binary")

            summary = freeze_formal_artifact(
                artifact_root=artifact_root,
                source_root=root,
                primary_duts=("rocket-clean",),
                reference_family_plan=[
                    {
                        "family": "C1.bare_pmp_decisions",
                        "profile": "pmp-boundary",
                        "start": 0,
                        "count": 2,
                    }
                ],
                dut_binary_paths={"rocket-clean": binary},
                capabilities_by_dut={
                    "rocket-clean": capability_for_dut("rocket-clean", available=True, path=binary),
                },
                source_provenance={
                    "source_sha": "a" * 40,
                    "source_tree_sha256": "b" * 64,
                    "source_dirty": False,
                },
            )

            self.assertEqual(summary["cases_sha256"], json.loads((artifact_root / "manifests" / "experiment-contract.json").read_text(encoding="utf-8"))["reference_hashes"]["cases_sha256"])
            capabilities_manifest = json.loads((artifact_root / "manifests" / "capabilities.json").read_text(encoding="utf-8"))
            self.assertEqual(capabilities_manifest["reference_case_count"], 2)
            self.assertEqual(sum(capabilities_manifest["duts"]["rocket-clean"]["applicability_counts"].values()), 2)

    def test_freeze_formal_artifact_supports_core_remediation_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root = root / "artifact"
            binary = root / "rocket-clean.bin"
            binary.write_bytes(b"rocket-clean-binary")

            freeze_formal_artifact(
                artifact_root=artifact_root,
                source_root=root,
                primary_duts=("rocket-clean",),
                order_seeds=(7, 8, 9),
                online_seeds=(),
                replay_count=0,
                online_candidate_budget=0,
                wall_clock_horizon_seconds=0,
                dut_binary_paths={"rocket-clean": binary},
                capabilities_by_dut={
                    "rocket-clean": capability_for_dut("rocket-clean", available=True, path=binary),
                },
                source_provenance={
                    "source_sha": "a" * 40,
                    "source_tree_sha256": "b" * 64,
                    "source_dirty": False,
                },
            )

            contract = json.loads((artifact_root / "manifests" / "experiment-contract.json").read_text(encoding="utf-8"))
            self.assertEqual(contract["order_seeds"], [7, 8, 9])
            self.assertEqual(contract["online_seeds"], [])
            self.assertEqual(contract["mutation_suite"]["replay_count"], 0)
            self.assertEqual(contract["mutation_suite"]["planned_online_campaigns"], 0)
            self.assertNotIn("replay_success_fraction", contract["acceptance_thresholds"])


if __name__ == "__main__":
    unittest.main()
