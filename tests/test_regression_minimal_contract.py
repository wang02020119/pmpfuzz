"""Regression tests for fail-closed validation gate, idempotent exclusions,
and runner metadata completeness.

These tests verify the minimum data contract required for Phase 2 paired smoke.
"""

import csv
import hashlib
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmpfuzz.bapc import build_bapc_coverage_universe
from pmpfuzz.experiment_protocols import (
    BAPC_CONVERGENCE_FORMAL,
    BAPC_CONVERGENCE_PROTOCOL_ID,
)

# Ensure aggregate is importable
import sys
_script_dir = Path(__file__).resolve().parents[1]
if str(_script_dir) not in sys.path:
    sys.path.insert(0, str(_script_dir))


# ── helpers ────────────────────────────────────────────────────────────────────

def _write_validation(campaign_dir: Path, valid=True, corrupt=False):
    """Write a validation.json to a campaign directory."""
    val_path = campaign_dir / "validation.json"
    if corrupt:
        val_path.write_text("not-valid-json{{{{", encoding="ascii")
    else:
        inputs = {}
        for label, rel_path in (
            ("metadata", Path("metrics/campaign_metadata.json")),
            ("timeline", Path("metrics/coverage_timeline.jsonl")),
            ("coverage", Path("coverage/coverage.json")),
        ):
            path = campaign_dir / rel_path
            if path.exists():
                inputs[label] = {
                    "path": str(rel_path),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
        artifact_root = campaign_dir.parents[5]
        contract_path = artifact_root / "manifests" / "experiment-contract.json"
        if contract_path.exists():
            inputs["experiment_contract"] = {
                "path": Path(os.path.relpath(contract_path, campaign_dir)).as_posix(),
                "sha256": hashlib.sha256(contract_path.read_bytes()).hexdigest(),
            }
        campaign_id = json.loads((campaign_dir / "metrics" / "campaign_metadata.json").read_text(encoding="ascii")).get("campaign_id")
        val_path.write_text(json.dumps({
            "schema_version": "1.0",
            "campaign_id": campaign_id,
            "valid": valid,
            "error_count": 0 if valid else 1,
            "warning_count": 0,
            "inputs": inputs,
        }, ensure_ascii=True), encoding="ascii")


def _write_minimal_campaign(root: Path, campaign_id: str,
                            variant: str = "random",
                            validation: bool = True,
                            corrupt_validation: bool = False):
    """Create a minimal campaign under *root*.

    If *validation* is False, no validation.json is written.
    If *corrupt_validation* is True, an unparseable validation.json is written.
    """
    try:
        seed_num = int(campaign_id)
    except (ValueError, TypeError):
        seed_num = abs(hash(str(campaign_id))) % 10000
    camp = (root / "campaigns" / "test-exp" / "rocket-clean"
            / variant / "semantic" / f"seed-{seed_num:04d}")
    camp.mkdir(parents=True)
    (camp / "metrics").mkdir()

    # timeline
    tl = [
        {"schema_version": 1, "campaign_id": campaign_id, "variant": variant,
         "dut": "rocket-clean", "seed": seed_num,
         "completion_seq": 0, "case_id": None,
         "elapsed_wall_seconds": 0, "case_elapsed_seconds": 0,
         "completed_cases": 0, "eligible_cases": 0,
         "status": None, "failure_class": None,
         "coverage_eligible": False, "qualification_reason": None,
         "semantic_covered": 0, "semantic_target": 10, "semantic_rate": 0.0,
         "pairwise_covered": 0, "pairwise_target": 20, "pairwise_rate": 0.0,
         "security_triples_covered": 0, "security_triples_target": 30, "security_triples_rate": 0.0,
         "predicates_covered": 0, "predicates_target": 5, "predicates_rate": 0.0,
         "new_semantic_bins": 0, "new_pairwise_bins": 0,
         "new_security_triple_bins": 0, "new_predicate_bins": 0,
         "whitebox_distinct_events": 0, "new_whitebox_events": 0},
        {"schema_version": 1, "campaign_id": campaign_id, "variant": variant,
         "dut": "rocket-clean", "seed": seed_num,
         "completion_seq": 1, "case_id": "case-1",
         "elapsed_wall_seconds": 5.0, "case_elapsed_seconds": 2.0,
         "completed_cases": 1, "eligible_cases": 1,
         "status": "pass", "failure_class": None,
         "coverage_eligible": True, "qualification_reason": "eligible",
         "semantic_covered": 4, "semantic_target": 10, "semantic_rate": 0.4,
         "pairwise_covered": 8, "pairwise_target": 20, "pairwise_rate": 0.4,
         "security_triples_covered": 12, "security_triples_target": 30, "security_triples_rate": 0.4,
         "predicates_covered": 2, "predicates_target": 5, "predicates_rate": 0.4,
         "new_semantic_bins": 4, "new_pairwise_bins": 8,
         "new_security_triple_bins": 12, "new_predicate_bins": 2,
         "whitebox_distinct_events": 0, "new_whitebox_events": 0},
    ]
    (camp / "metrics" / "coverage_timeline.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=True, sort_keys=True)
                  for r in tl) + "\n",
        encoding="ascii")

    # metadata
    (camp / "metrics" / "campaign_metadata.json").write_text(json.dumps({
        "campaign_id": campaign_id, "variant": variant,
        "dut": "rocket-clean", "seed": seed_num,
        "coverage_mode": "semantic",
        "source_sha": "a" * 40,
        "run_class": "pilot",
        "budget_class": "primary-wall-clock",
        "wall_clock_horizon_seconds": 300,
    }, ensure_ascii=True), encoding="ascii")

    if validation:
        _write_validation(camp, corrupt=corrupt_validation)

    return camp


def _write_formal_contract(
    root: Path,
    *,
    dut: str = "boom-clean",
    source_sha: str = "a" * 40,
    source_tree_sha256: str = "b" * 64,
    dut_sha: str = "c" * 40,
    dut_binary_sha256: str = "d" * 64,
) -> dict:
    universe = build_bapc_coverage_universe(
        dut=dut,
        generator_seed=1,
        supports_fault_stage=True,
        supports_smepmp=False,
    )
    manifests = root / "manifests"
    manifests.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "experiment_protocol_id": BAPC_CONVERGENCE_PROTOCOL_ID,
        "dut": dut,
        "coverage_mode": "bapc",
        "bin_count": int(universe["bin_count"]),
        "bin_set_sha256": str(universe["bin_set_sha256"]),
        "variants": ["random-mutation", "bb-guided", "cascade"],
        "seeds": [4, 5, 6],
        "source_sha": source_sha,
        "source_tree_sha256": source_tree_sha256,
        "dut_sha": dut_sha,
        "dut_binary_sha256": dut_binary_sha256,
        **BAPC_CONVERGENCE_FORMAL,
    }
    (manifests / "experiment-contract.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=True),
        encoding="ascii",
    )
    return universe


def _write_formal_bapc_campaign(
    root: Path,
    *,
    method: str,
    variant: str,
    seed: int,
    dut: str = "boom-clean",
    protocol_id: str = BAPC_CONVERGENCE_PROTOCOL_ID,
    run_class: str | None = None,
    universe_sha: str,
    source_sha: str = "a" * 40,
    source_tree_sha256: str = "b" * 64,
    dut_sha: str = "c" * 40,
    dut_binary_sha256: str | None = None,
    validation: bool = True,
) -> Path:
    campaign_id = f"{method}-{variant}-{seed}"
    camp = (root / "campaigns" / "formal-exp" / dut / variant / "bapc" / f"seed-{seed:04d}")
    camp.mkdir(parents=True, exist_ok=True)
    (camp / "metrics").mkdir(exist_ok=True)
    timeline = [
        {
            "schema_version": 1,
            "campaign_id": campaign_id,
            "variant": variant,
            "dut": dut,
            "seed": seed,
            "completion_seq": 0,
            "case_id": None,
            "elapsed_wall_seconds": 0.0,
            "case_elapsed_seconds": 0.0,
            "completed_cases": 0,
            "eligible_cases": 0,
            "eligible_bapc_cases": 0,
            "status": None,
            "failure_class": None,
            "coverage_eligible": False,
            "qualification_reason": None,
            "semantic_covered": 0,
            "semantic_target": 0,
            "semantic_rate": None,
            "pairwise_covered": 0,
            "pairwise_target": 0,
            "pairwise_rate": None,
            "security_triples_covered": 0,
            "security_triples_target": 0,
            "security_triples_rate": None,
            "predicates_covered": 0,
            "predicates_target": 0,
            "predicates_rate": None,
            "bapc_covered": 0,
            "bapc_target": 208,
            "bapc_rate": 0.0,
            "new_bapc_bins": 0,
            "bapc_eligible": False,
            "last_bapc_novelty_time": 0.0,
            "whitebox_distinct_events": 0,
            "new_whitebox_events": 0,
        },
        {
            "schema_version": 1,
            "campaign_id": campaign_id,
            "variant": variant,
            "dut": dut,
            "seed": seed,
            "completion_seq": 1,
            "case_id": "case-0001",
            "elapsed_wall_seconds": 12.0,
            "case_elapsed_seconds": 2.0,
            "completed_cases": 1,
            "eligible_cases": 1,
            "eligible_bapc_cases": 1,
            "status": "observed",
            "failure_class": None,
            "coverage_eligible": True,
            "qualification_reason": "eligible",
            "semantic_covered": 0,
            "semantic_target": 0,
            "semantic_rate": None,
            "pairwise_covered": 0,
            "pairwise_target": 0,
            "pairwise_rate": None,
            "security_triples_covered": 0,
            "security_triples_target": 0,
            "security_triples_rate": None,
            "predicates_covered": 0,
            "predicates_target": 0,
            "predicates_rate": None,
            "bapc_covered": 1,
            "bapc_target": 208,
            "bapc_rate": 1 / 208,
            "new_bapc_bins": 1,
            "bapc_eligible": True,
            "last_bapc_novelty_time": 12.0,
            "whitebox_distinct_events": 0,
            "new_whitebox_events": 0,
        },
    ]
    (camp / "metrics" / "coverage_timeline.jsonl").write_text(
        "\n".join(json.dumps(row, ensure_ascii=True, sort_keys=True) for row in timeline) + "\n",
        encoding="ascii",
    )
    metadata = {
        "schema_version": "1.0",
        "experiment_id": "formal-exp",
        "campaign_id": campaign_id,
        "experiment_protocol_id": protocol_id,
        "method": method,
        "variant": variant,
        "dut": dut,
        "seed": seed,
        "coverage_mode": "bapc",
        "source_sha": source_sha,
        "source_tree_sha256": source_tree_sha256,
        "source_dirty": False,
        "dut_sha": dut_sha,
        "dut_binary_path": str(camp / "fixtures" / "dut.bin"),
        "dut_binary_sha256": dut_binary_sha256 or ("d" * 64),
        "capability_fingerprint": "cap",
        "run_class": run_class or ("baseline-formal" if method == "cascade" else "formal"),
        "budget_class": "primary-wall-clock",
        "time_budget_seconds": 7200,
        "wall_clock_horizon_seconds": 7200,
        "convergence_enabled": True,
        "convergence_min_runtime_seconds": 0,
        "convergence_confirmation_seconds": 600,
        "convergence_confirmation_eligible_cases": 300,
        "max_wall_time_seconds": 7200,
        "stop_reason": "coverage_converged",
        "jobs": 1 if method == "cascade" else 8,
        "per_case_timeout_seconds": 10,
        "coverage_universe_hashes": {"bapc": universe_sha},
    }
    (camp / "fixtures").mkdir(exist_ok=True)
    (camp / "fixtures" / "dut.bin").write_bytes(b"dut")
    if dut_binary_sha256 is None:
        metadata["dut_binary_sha256"] = hashlib.sha256((camp / "fixtures" / "dut.bin").read_bytes()).hexdigest()
    (camp / "metrics" / "campaign_metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=True),
        encoding="ascii",
    )
    coverage_dir = camp / "coverage"
    coverage_dir.mkdir(exist_ok=True)
    universe = build_bapc_coverage_universe(
        dut=dut,
        generator_seed=1,
        supports_fault_stage=True,
        supports_smepmp=False,
    )
    (coverage_dir / "bapc_v2.json").write_text(json.dumps(universe, ensure_ascii=True), encoding="ascii")
    metadata["coverage_universe_files"] = {"bapc": "coverage/bapc_v2.json"}
    (camp / "metrics" / "campaign_metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=True),
        encoding="ascii",
    )
    (coverage_dir / "coverage.json").write_text(
        json.dumps(
            {
                "schema_version": 6,
                "driver_mode": "campaign",
                "execution_coverage": {
                    "by_dut": {
                        dut: {
                            "bapc": {
                                "covered_target_bins": 1,
                                "total_target_bins": 208,
                                "covered_bins": [str(universe["bin_ids"][0])],
                                "target": "black-box-architectural-pmp-target-operation",
                                "universe_sha256": universe_sha,
                            }
                        }
                    }
                },
            },
            ensure_ascii=True,
        ),
        encoding="ascii",
    )
    if validation:
        _write_validation(camp, valid=True)
    return camp


# ── tests ──────────────────────────────────────────────────────────────────────


class TestValidationGateFailClosed(unittest.TestCase):
    """Fail-closed: missing, corrupt, or invalid validation.json excludes campaign."""

    def test_missing_validation_excludes_campaign(self):
        """Campaign without validation.json must be excluded."""
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_minimal_campaign(root, "1", validation=False)
            aggregate(root, "test-exp")

            excl = root / "aggregate" / "exclusions.csv"
            self.assertTrue(excl.exists(), "exclusions.csv must exist")
            with excl.open("r", encoding="ascii", newline="") as f:
                rows = list(csv.DictReader(f))
            excluded_ids = [r["campaign_id"] for r in rows]
            self.assertIn("1", excluded_ids,
                          "campaign missing validation.json must be excluded")

            # No campaign data in output
            camp_csv = root / "aggregate" / "campaign_index.csv"
            # campaign_index.csv may exist but be empty/header-only
            self.assertFalse(
                camp_csv.exists() and camp_csv.stat().st_size > 50,
                "No valid campaigns => campaign_index should be empty or absent")

    def test_corrupt_validation_excludes_campaign(self):
        """Campaign with unparseable validation.json must be excluded."""
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_minimal_campaign(root, "2", corrupt_validation=True)
            aggregate(root, "test-exp")

            excl = root / "aggregate" / "exclusions.csv"
            self.assertTrue(excl.exists())
            with excl.open("r", encoding="ascii", newline="") as f:
                rows = list(csv.DictReader(f))
            reasons = [r["reason"] for r in rows]
            self.assertTrue(any("corrupt" in reason.lower()
                                for reason in reasons),
                            "Corrupt validation.json must be recorded")

    def test_valid_false_excludes_campaign(self):
        """Campaign with valid=false must be excluded."""
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            camp = _write_minimal_campaign(root, "3")
            _write_validation(camp, valid=False)  # overwrite with valid=False
            aggregate(root, "test-exp")

            excl = root / "aggregate" / "exclusions.csv"
            self.assertTrue(excl.exists())
            with excl.open("r", encoding="ascii", newline="") as f:
                rows = list(csv.DictReader(f))
            excluded_ids = [r["campaign_id"] for r in rows]
            self.assertIn("3", excluded_ids,
                          "Campaign with valid=false must be excluded")

    def test_valid_true_includes_campaign(self):
        """Campaign with valid=true must be included."""
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_minimal_campaign(root, "4", validation=True)
            aggregate(root, "test-exp")

            camp_csv = root / "normalized" / "campaigns.csv"
            self.assertTrue(camp_csv.exists(), "normalized/campaigns.csv must exist")
            with camp_csv.open("r", encoding="ascii", newline="") as f:
                rows = list(csv.DictReader(f))
            ids = [r["campaign_id"] for r in rows]
            self.assertIn("4", ids, "Valid campaign must be in normalized output")

    def test_missing_validation_excludes_complete_strict_campaign(self):
        """Strict metadata completeness must not relax missing validation.json."""
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            camp = _write_minimal_campaign(root, "strict-complete", validation=False)
            meta_path = camp / "metrics" / "campaign_metadata.json"
            meta = json.loads(meta_path.read_text(encoding="ascii"))
            meta.update({
                "method": "pmpfuzz",
                "dut_sha": "b" * 40,
                "dut_binary_sha256": "c" * 64,
                "capability_fingerprint": "d" * 64,
                "jobs": 1,
                "time_budget_seconds": 30,
            })
            meta_path.write_text(json.dumps(meta, ensure_ascii=True), encoding="ascii")

            aggregate(root, "test-exp")

            excl = root / "aggregate" / "exclusions.csv"
            with excl.open("r", encoding="ascii", newline="") as f:
                rows = list(csv.DictReader(f))
            excluded_ids = [r["campaign_id"] for r in rows]
            self.assertIn("strict-complete", excluded_ids)

    def test_string_false_validation_excludes_campaign(self):
        """validation.valid must be strict bool true, not a truthy string."""
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            camp = _write_minimal_campaign(root, "string-false", validation=False)
            (camp / "validation.json").write_text(json.dumps({
                "schema_version": "1.0",
                "valid": "false",
                "error_count": 0,
                "warning_count": 0,
            }, ensure_ascii=True), encoding="ascii")

            aggregate(root, "test-exp")

            excl = root / "aggregate" / "exclusions.csv"
            with excl.open("r", encoding="ascii", newline="") as f:
                rows = list(csv.DictReader(f))
            excluded_ids = [r["campaign_id"] for r in rows]
            self.assertIn("string-false", excluded_ids)

    def test_stale_timeline_digest_excludes_campaign(self):
        """Strict validation must be bound to the current timeline bytes."""
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            camp = _write_minimal_campaign(root, "stale-digest", validation=True)
            timeline = camp / "metrics" / "coverage_timeline.jsonl"
            original_lines = timeline.read_text(encoding="ascii").splitlines()
            mutated = json.loads(original_lines[-1])
            mutated["semantic_covered"] = 9
            mutated["semantic_rate"] = 0.9
            original_lines[-1] = json.dumps(mutated, ensure_ascii=True, sort_keys=True)
            timeline.write_text("\n".join(original_lines) + "\n", encoding="ascii")

            aggregate(root, "test-exp")

            excl = root / "aggregate" / "exclusions.csv"
            with excl.open("r", encoding="ascii", newline="") as f:
                rows = list(csv.DictReader(f))
            reasons = {row["campaign_id"]: row["reason"] for row in rows}
            self.assertIn("stale-digest", reasons)
            self.assertIn("validation bindings", reasons["stale-digest"])

    def test_unknown_run_class_excludes_campaign(self):
        """Unknown non-empty run_class must not silently degrade to legacy."""
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            camp = _write_minimal_campaign(root, "bad-run-class", validation=True)
            meta_path = camp / "metrics" / "campaign_metadata.json"
            meta = json.loads(meta_path.read_text(encoding="ascii"))
            meta["run_class"] = "fomral"
            meta_path.write_text(json.dumps(meta, ensure_ascii=True), encoding="ascii")
            _write_validation(camp, valid=True)

            aggregate(root, "test-exp")

            excl = root / "aggregate" / "exclusions.csv"
            with excl.open("r", encoding="ascii", newline="") as f:
                rows = list(csv.DictReader(f))
            reasons = {row["campaign_id"]: row["reason"] for row in rows}
            self.assertIn("bad-run-class", reasons)
            self.assertIn("unknown run_class", reasons["bad-run-class"])

            report = json.loads((root / "aggregate" / "validation_report.json").read_text(encoding="ascii"))
            self.assertFalse(report["valid"])
            self.assertTrue(any("unknown run_class" in err for err in report.get("errors", [])))


class TestExclusionsIdempotent(unittest.TestCase):
    """Exclusions must use real campaign_id from metadata and be idempotent."""

    def test_exclusions_use_metadata_campaign_id(self):
        """Exclusion records must use campaign_id from metadata, not dir name."""
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_minimal_campaign(root, "metadata-cid-42", validation=False)
            aggregate(root, "test-exp")

            excl = root / "aggregate" / "exclusions.csv"
            with excl.open("r", encoding="ascii", newline="") as f:
                rows = list(csv.DictReader(f))
            excluded_ids = [r["campaign_id"] for r in rows]
            self.assertIn("metadata-cid-42", excluded_ids,
                          "Must use metadata campaign_id, not directory name")

    def test_exclusions_idempotent(self):
        """Repeated aggregate must not create duplicate exclusion rows."""
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_minimal_campaign(root, "dup-test", validation=False)

            aggregate(root, "test-exp")
            aggregate(root, "test-exp")  # second run

            excl = root / "aggregate" / "exclusions.csv"
            with excl.open("r", encoding="ascii", newline="") as f:
                rows = list(csv.DictReader(f))
            dup_count = sum(1 for r in rows if r["campaign_id"] == "dup-test")
            self.assertEqual(1, dup_count,
                             f"Expected 1 exclusion row for dup-test, got {dup_count}")


class TestRunnerMetadataCompleteness(unittest.TestCase):
    """Campaign metadata must include all required provenance fields."""

    REQUIRED_FIELDS = [
        "method", "variant", "dut", "seed", "coverage_mode",
        "source_sha", "dut_sha", "dut_binary_sha256",
        "capability_fingerprint", "jobs", "run_class",
        "budget_class", "wall_clock_horizon_seconds",
        "time_budget_seconds",
    ]

    def test_metadata_contains_all_required_fields(self):
        """Strict metadata must include all 14+ provenance fields."""
        # This test verifies the contract, not a specific campaign on disk.
        # The aggregate's _build_campaign_row reads these fields from metadata.
        # We check that the CAMPAIGN_FIELDS constant covers them.
        from scripts.evaluation.analysis.aggregate_results import CAMPAIGN_FIELDS

        for field in self.REQUIRED_FIELDS:
            self.assertIn(field, CAMPAIGN_FIELDS,
                          f"Required metadata field '{field}' missing from CAMPAIGN_FIELDS")


class TestArtifactManifestTamper(unittest.TestCase):
    """Tampering with an artifact must cause validator failure."""

    def test_tampered_hash_causes_manifest_failure(self):
        """Modifying a file after manifest generation invalidates it."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            camp = _write_minimal_campaign(root, "tamper")

            # Generate manifest manually by running aggregate
            from scripts.evaluation.analysis.aggregate_results import aggregate
            aggregate(root, "test-exp")

            # Manually add a raw campaign file to the manifest
            # (aggregate only adds output files; the driver adds raw files)
            import hashlib
            manifests_dir = root / "manifests"
            manifest_path = manifests_dir / "artifact-sha256.txt"
            tl_path = camp / "metrics" / "coverage_timeline.jsonl"
            original = tl_path.read_text(encoding="ascii")
            tl_digest = hashlib.sha256(tl_path.read_bytes()).hexdigest()
            tl_rel = tl_path.resolve().relative_to(root.resolve()).as_posix()
            with open(manifest_path, "a", encoding="ascii") as mf:
                mf.write(f"{tl_digest}  {tl_rel}\n")

            self.assertTrue(manifest_path.exists(),
                            "artifact-sha256.txt must be generated")

            # Tamper: modify the file
            tl_path.write_text(original + "/* tampered */\n", encoding="ascii")

            # Re-validate using the validator
            from scripts.evaluation.validation.validate_timeline import validate_timeline
            report = validate_timeline(camp)

            # The manifest integrity check should fail because the hash changed
            manifest_checks = [c for c in report["checks"]
                               if "artifact_sha" in c["name"]]
            hash_ok = any(
                c["name"] == "artifact_sha_manifest_integrity" and c["passed"]
                for c in manifest_checks
            )
            self.assertFalse(hash_ok,
                             "Tampered file must cause manifest integrity failure")

            # Restore original for cleanup
            tl_path.write_text(original, encoding="ascii")


class TestFormalAggregateContract(unittest.TestCase):
    def test_formal_bapc_aggregate_rejects_single_campaign_against_full_contract(self):
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = _write_formal_contract(root)
            _write_formal_bapc_campaign(
                root,
                method="pmpfuzz",
                variant="random-mutation",
                seed=4,
                universe_sha=str(universe["sha256"]),
            )

            aggregate(root, "formal-exp")

            report = json.loads((root / "aggregate" / "validation_report.json").read_text(encoding="ascii"))

        self.assertFalse(report["valid"], report)
        self.assertTrue(any("missing" in err.lower() and "campaign" in err.lower() for err in report["errors"]), report)

    def test_formal_bapc_aggregate_rejects_missing_campaign_from_contract_matrix(self):
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = _write_formal_contract(root)
            for variant in ("random-mutation", "bb-guided", "cascade"):
                for seed in (4, 5):
                    _write_formal_bapc_campaign(
                        root,
                        method="cascade" if variant == "cascade" else "pmpfuzz",
                        variant=variant,
                        seed=seed,
                        universe_sha=str(universe["sha256"]),
                    )

            aggregate(root, "formal-exp")

            report = json.loads((root / "aggregate" / "validation_report.json").read_text(encoding="ascii"))

        self.assertFalse(report["valid"], report)
        self.assertTrue(any("missing" in err.lower() and "campaign" in err.lower() for err in report["errors"]), report)

    def test_formal_bapc_aggregate_rejects_duplicate_campaign_key(self):
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = _write_formal_contract(root)
            for variant in ("random-mutation", "bb-guided", "cascade"):
                for seed in (4, 5, 6):
                    _write_formal_bapc_campaign(
                        root,
                        method="cascade" if variant == "cascade" else "pmpfuzz",
                        variant=variant,
                        seed=seed,
                        universe_sha=str(universe["sha256"]),
                    )
            _write_formal_bapc_campaign(
                root,
                method="cascade",
                variant="shadow-cascade",
                seed=4,
                universe_sha=str(universe["sha256"]),
            )

            aggregate(root, "formal-exp")

            report = json.loads((root / "aggregate" / "validation_report.json").read_text(encoding="ascii"))

        self.assertFalse(report["valid"], report)
        self.assertTrue(any("duplicate" in err.lower() for err in report["errors"]), report)

    def test_formal_bapc_aggregate_rejects_protocol_and_universe_mismatch(self):
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = _write_formal_contract(root)
            for variant in ("random-mutation", "bb-guided", "cascade"):
                for seed in (4, 5, 6):
                    _write_formal_bapc_campaign(
                        root,
                        method="cascade" if variant == "cascade" else "pmpfuzz",
                        variant=variant,
                        seed=seed,
                        universe_sha=str(universe["sha256"]),
                    )
            bad = _write_formal_bapc_campaign(
                root,
                method="cascade",
                variant="cascade",
                seed=6,
                universe_sha="f" * 64,
            )
            meta_path = bad / "metrics" / "campaign_metadata.json"
            meta = json.loads(meta_path.read_text(encoding="ascii"))
            meta["experiment_protocol_id"] = "wrong-protocol"
            meta_path.write_text(json.dumps(meta, ensure_ascii=True), encoding="ascii")
            _write_validation(bad, valid=True)

            aggregate(root, "formal-exp")

            report = json.loads((root / "aggregate" / "validation_report.json").read_text(encoding="ascii"))

        self.assertFalse(report["valid"], report)
        self.assertTrue(
            any(
                "protocol" in err.lower()
                or "universe" in err.lower()
                for err in report["errors"]
            ),
            report,
        )

    def test_formal_bapc_validation_binding_rejects_contract_tamper(self):
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = _write_formal_contract(root)
            for variant in ("random-mutation", "bb-guided", "cascade"):
                for seed in (4, 5, 6):
                    _write_formal_bapc_campaign(
                        root,
                        method="cascade" if variant == "cascade" else "pmpfuzz",
                        variant=variant,
                        seed=seed,
                        universe_sha=str(universe["sha256"]),
                    )
            contract_path = root / "manifests" / "experiment-contract.json"
            payload = json.loads(contract_path.read_text(encoding="ascii"))
            payload["dut_binary_sha256"] = "f" * 64
            contract_path.write_text(json.dumps(payload, ensure_ascii=True), encoding="ascii")

            aggregate(root, "formal-exp")

            report = json.loads((root / "aggregate" / "validation_report.json").read_text(encoding="ascii"))

        self.assertFalse(report["valid"], report)
        self.assertTrue(
            any("validation bindings mismatch" in err.lower() and "experiment contract" in err.lower() for err in report["errors"]),
            report,
        )

    def test_formal_bapc_aggregate_rejects_uniform_wrong_binary_sha_vs_contract(self):
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = _write_formal_contract(root, dut_binary_sha256="4" * 64)
            for variant in ("random-mutation", "bb-guided", "cascade"):
                for seed in (4, 5, 6):
                    _write_formal_bapc_campaign(
                        root,
                        method="cascade" if variant == "cascade" else "pmpfuzz",
                        variant=variant,
                        seed=seed,
                        universe_sha=str(universe["sha256"]),
                        dut_binary_sha256="e" * 64,
                    )

            aggregate(root, "formal-exp")

            report = json.loads((root / "aggregate" / "validation_report.json").read_text(encoding="ascii"))

        self.assertFalse(report["valid"], report)
        self.assertTrue(any("dut_binary_sha256" in err for err in report["errors"]), report)

    def test_formal_bapc_aggregate_rejects_source_tree_sha_mismatch(self):
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = _write_formal_contract(root)
            for variant in ("random-mutation", "bb-guided", "cascade"):
                for seed in (4, 5, 6):
                    _write_formal_bapc_campaign(
                        root,
                        method="cascade" if variant == "cascade" else "pmpfuzz",
                        variant=variant,
                        seed=seed,
                        universe_sha=str(universe["sha256"]),
                        source_tree_sha256=("f" * 64) if (variant, seed) == ("bb-guided", 5) else ("b" * 64),
                    )

            aggregate(root, "formal-exp")

            report = json.loads((root / "aggregate" / "validation_report.json").read_text(encoding="ascii"))

        self.assertFalse(report["valid"], report)
        self.assertTrue(any("source_tree_sha256" in err for err in report["errors"]), report)

    def test_formal_bapc_aggregate_accepts_allowed_legacy_source_provenance(self):
        from scripts.evaluation.analysis.aggregate_results import aggregate

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = _write_formal_contract(root, source_sha="a" * 40, source_tree_sha256="b" * 64)
            contract_path = root / "manifests" / "experiment-contract.json"
            contract = json.loads(contract_path.read_text(encoding="ascii"))
            contract["allowed_source_shas"] = ["a" * 40, "1" * 40]
            contract["allowed_source_tree_sha256s"] = ["b" * 64, "2" * 64]
            fixture_hash = None
            campaigns: list[Path] = []
            for variant in ("random-mutation", "bb-guided", "cascade"):
                for seed in (4, 5, 6):
                    use_legacy = (variant, seed) == ("bb-guided", 5)
                    campaign = _write_formal_bapc_campaign(
                        root,
                        method="cascade" if variant == "cascade" else "pmpfuzz",
                        variant=variant,
                        seed=seed,
                        universe_sha=str(universe["sha256"]),
                        source_sha=("1" * 40) if use_legacy else ("a" * 40),
                        source_tree_sha256=("2" * 64) if use_legacy else ("b" * 64),
                    )
                    campaigns.append(campaign)
                    if fixture_hash is None:
                        fixture_hash = hashlib.sha256((campaign / "fixtures" / "dut.bin").read_bytes()).hexdigest()
            contract["dut_binary_sha256"] = fixture_hash
            contract_path.write_text(json.dumps(contract, ensure_ascii=True), encoding="ascii")
            for campaign in campaigns:
                _write_validation(campaign, valid=True)

            aggregate(root, "formal-exp")

            report = json.loads((root / "aggregate" / "validation_report.json").read_text(encoding="ascii"))

        self.assertTrue(report["valid"], report)


if __name__ == "__main__":
    raise SystemExit(
        0 if unittest.main(verbosity=2, exit=False).result.wasSuccessful()
        else 1)
