import csv
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

import pmpfuzz.coverage_universe as coverage_universe_module
from pmpfuzz.bapc import (
    build_bapc_coverage_universe,
    load_bapc_coverage_universe,
    runtime_bapc_event_records_for_cascade_execution,
    summarize_bapc_for_cascade_execution,
    validate_bapc_coverage_universe,
)
from pmpfuzz.coverage_universe import classify_observed_bins, make_coverage_universe
from pmpfuzz.experiment_protocols import BAPC_CONVERGENCE_PROTOCOL_ID
from pmpfuzz.scenario_codec import scenario_hash
from scripts.evaluation.analysis.aggregate_results import aggregate
from scripts.evaluation.validation.validate_timeline import main as validate_timeline_main
from scripts.evaluation.validation.validate_timeline import validate_timeline


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n", encoding="ascii")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row, ensure_ascii=True, sort_keys=True) for row in rows) + "\n", encoding="ascii")


def _campaign_root(root: Path, seed: int) -> Path:
    return root / "campaigns" / "exp" / "rocket-clean" / "bb-guided" / "bapc" / f"seed-{seed:04d}"


def _sha_tree(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _make_bapc_campaign(
    root: Path,
    *,
    seed: int,
    universe: dict,
    covered_bins: list[str],
    universe_filename: str = "bapc_v2.json",
) -> Path:
    campaign_dir = _campaign_root(root, seed)
    metrics_dir = campaign_dir / "metrics"
    coverage_dir = campaign_dir / "coverage"
    universe_dir = metrics_dir / "coverage_universe"
    universe_path = universe_dir / universe_filename
    spec = {"name": f"case-{seed}", "profile": "pmp-boundary"}
    spec_hash = scenario_hash(spec)
    _write_jsonl(
        metrics_dir / "schedule_v4.jsonl",
        [
            {
                "schema_version": 4,
                "event_seq": 1,
                "event": "candidate_admitted",
                "scenario_hash": spec_hash,
                "scenario_spec": spec,
                "profile": "pmp-boundary",
                "name": f"case-{seed}",
                "parent_hash": None,
                "mutation_operator": "root",
                "mutation_seed": 0,
                "generation_seq": 1,
                "mutation_depth": 0,
                "root_sequence": 0,
                "rejection_reason": None,
            },
            {
                "schema_version": 4,
                "event_seq": 2,
                "event": "execution_committed",
                "scenario_hash": spec_hash,
                "candidate_id": f"cand-{seed}",
                "case_id": f"case-{seed}",
                "profile": "pmp-boundary",
                "status": "pass",
                "failure_class": None,
                "eligible": True,
                "qualification_reason": "eligible",
                "elapsed_wall_seconds": 1.0,
                "case_elapsed_seconds": 0.2,
                "execution_cost": 0.2,
                "new_bins": {"semantic": [], "pairwise": [], "security_triples": [], "predicates": [], "bapc": covered_bins},
                "promoted": True,
                "evicted_hashes": [],
                "retained_without_novelty": False,
                "security_events": [],
                "new_whitebox_events": 0,
            },
        ],
    )
    _write_json(universe_path, universe)
    _write_json(
        universe_dir / "coverage_contract_v1.json",
        {"schema_version": 1, "modes": {"bapc": universe_filename}, "hashes": {"bapc": universe["sha256"]}},
    )
    timeline = [
        {
            "schema_version": 1,
            "campaign_id": f"camp-{seed}",
            "variant": "bb-guided",
            "dut": "rocket-clean",
            "seed": seed,
            "completion_seq": 0,
            "case_id": None,
            "profile": None,
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
            "semantic_target": 1,
            "semantic_rate": 0.0,
            "pairwise_covered": 0,
            "pairwise_target": 1,
            "pairwise_rate": 0.0,
            "security_triples_covered": 0,
            "security_triples_target": 1,
            "security_triples_rate": 0.0,
            "predicates_covered": 0,
            "predicates_target": 1,
            "predicates_rate": 0.0,
            "bapc_covered": 0,
            "bapc_target": universe["bin_count"],
            "bapc_rate": 0.0,
            "new_semantic_bins": 0,
            "new_pairwise_bins": 0,
            "new_security_triple_bins": 0,
            "new_predicate_bins": 0,
            "new_bapc_bins": 0,
            "bapc_eligible": False,
            "last_bapc_novelty_time": 0.0,
            "whitebox_distinct_events": 0,
            "new_whitebox_events": 0,
        },
        {
            "schema_version": 1,
            "campaign_id": f"camp-{seed}",
            "variant": "bb-guided",
            "dut": "rocket-clean",
            "seed": seed,
            "completion_seq": 1,
            "case_id": f"case-{seed}",
            "profile": "pmp-boundary",
            "elapsed_wall_seconds": 1.0,
            "case_elapsed_seconds": 0.2,
            "completed_cases": 1,
            "eligible_cases": 1,
            "eligible_bapc_cases": 1,
            "status": "pass",
            "failure_class": None,
            "coverage_eligible": True,
            "qualification_reason": "eligible",
            "semantic_covered": 0,
            "semantic_target": 1,
            "semantic_rate": 0.0,
            "pairwise_covered": 0,
            "pairwise_target": 1,
            "pairwise_rate": 0.0,
            "security_triples_covered": 0,
            "security_triples_target": 1,
            "security_triples_rate": 0.0,
            "predicates_covered": 0,
            "predicates_target": 1,
            "predicates_rate": 0.0,
            "bapc_covered": len(covered_bins),
            "bapc_target": universe["bin_count"],
            "bapc_rate": len(covered_bins) / universe["bin_count"],
            "new_semantic_bins": 0,
            "new_pairwise_bins": 0,
            "new_security_triple_bins": 0,
            "new_predicate_bins": 0,
            "new_bapc_bins": len(covered_bins),
            "bapc_eligible": True,
            "last_bapc_novelty_time": 1.0,
            "whitebox_distinct_events": 0,
            "new_whitebox_events": 0,
        },
    ]
    _write_jsonl(metrics_dir / "coverage_timeline.jsonl", timeline)
    _write_json(
        metrics_dir / "campaign_metadata.json",
        {
            "schema_version": "1.0",
            "experiment_id": "exp",
            "campaign_id": f"camp-{seed}",
            "method": "pmpfuzz",
            "variant": "bb-guided",
            "coverage_mode": "bapc",
            "driver_mode": "continuous",
            "dut": "rocket-clean",
            "seed": seed,
            "jobs": 8,
            "time_budget_seconds": 60,
            "wall_clock_horizon_seconds": 60,
            "per_case_timeout_seconds": 10,
            "round_size": 8,
            "run_class": "development-smoke",
            "budget_class": "primary-wall-clock",
            "schedule_v4": "metrics/schedule_v4.jsonl",
            "source_sha": "a" * 40,
            "source_tree_sha256": "b" * 64,
            "source_dirty": False,
            "dut_sha": "c" * 40,
            "dut_sha_status": "available",
            "dut_binary_sha256": "d" * 64,
            "dut_binary_path": "/dut",
            "capability_fingerprint": "cap",
            "coverage_universe_hashes": {"bapc": universe["sha256"]},
            "coverage_universe_files": {"bapc": str(universe_path.relative_to(campaign_dir))},
            "analysis_scope": {
                "guidance_mode": "bapc",
                "primary_metric": "bapc",
                "coverage_modes": ["bapc"],
            },
        },
    )
    _write_json(
        coverage_dir / "coverage.json",
        {
            "schema_version": 6,
            "driver_mode": "campaign",
            "coverage_universe_hashes": {"bapc": universe["sha256"]},
            "execution_coverage": {
                "by_dut": {
                    "rocket-clean": {
                        "bapc": {
                            "covered_target_bins": len(covered_bins),
                            "total_target_bins": universe["bin_count"],
                            "covered_bins": covered_bins,
                            "target": "black-box-architectural-pmp-target-operation",
                            "universe_sha256": universe["sha256"],
                        }
                    }
                }
            },
        },
    )
    _write_json(
        campaign_dir / "validation.json",
        {"campaign_id": f"camp-{seed}", "valid": True, "inputs": {}, "checked_utc": "2026-07-15T00:00:00Z"},
    )
    return campaign_dir


def _legacy_bapc_universe(*, generator_seed: int, dut: str = "rocket-clean") -> dict:
    legacy = make_coverage_universe(
        coverage_mode="bapc",
        bin_ids=[f"legacy:{index}" for index in range(220)],
        capability_fingerprint=f"legacy:{dut}",
        target="black-box-architectural-pmp-behavior",
        include_experimental=False,
        generator_seed=generator_seed,
        generation_rule_version="bapc-coverage-universe-v1",
    )
    legacy["dut"] = dut
    legacy["capabilities"] = {"fault_stage": True, "smepmp": False}
    legacy["bin_families"] = ["config", "stimulus", "decision", "privilege-decision", "mode-decision", "translation-stage"]
    return legacy


def _write_raw_pmpfuzz_bapc_campaign(root: Path, *, seed: int, dut_bin: Path) -> Path:
    campaign_dir = root / "campaigns" / "raw-exp" / "rocket-clean" / "random-mutation" / "bapc" / f"seed-{seed:04d}"
    metrics_dir = campaign_dir / "metrics"
    coverage_dir = campaign_dir / "coverage"
    round_dir = campaign_dir / "rounds" / "round_0000"
    case_id = "root_00000000"
    case = {
        "name": case_id,
        "profile": "sv39-final-pmp",
        "translation": "sv39",
        "privilege": "s",
        "access": "load",
        "physical_address": "0x80008000",
        "mprv": False,
        "mpp": "m",
        "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
        "pmp_entries": [
            {"index": 0, "address_mode": "napot", "pmpaddr": "0xffffffffffffffff", "read": True, "write": False, "execute": True, "locked": False},
            {"index": 1, "address_mode": "napot", "pmpaddr": "0x80008fff", "read": True, "write": False, "execute": False, "locked": True},
        ],
    }
    result = {
        "case_id": case_id,
        "status": "fail",
        "failure_class": "unexpected_trap",
        "observation_valid": True,
        "observed_event": "trap",
        "observed_mcause": 13,
        "observed_stage": "final",
    }
    legacy = _legacy_bapc_universe(generator_seed=seed)
    raw_timeline = [
        {
            "schema_version": 1,
            "campaign_id": "raw-pmpfuzz",
            "variant": "random-mutation",
            "dut": "rocket-clean",
            "seed": seed,
            "completion_seq": 0,
            "case_id": None,
            "profile": None,
            "elapsed_wall_seconds": 0.0,
            "case_elapsed_seconds": 0.0,
            "completed_cases": 0,
            "eligible_cases": 0,
            "eligible_bapc_cases": 0,
            "status": None,
            "failure_class": None,
            "coverage_eligible": False,
            "qualification_reason": None,
            "bapc_covered": 0,
            "bapc_target": 220,
            "bapc_rate": 0.0,
            "new_bapc_bins": 0,
            "last_bapc_novelty_time": 0.0,
        },
        {
            "schema_version": 1,
            "campaign_id": "raw-pmpfuzz",
            "variant": "random-mutation",
            "dut": "rocket-clean",
            "seed": seed,
            "completion_seq": 1,
            "case_id": case_id,
            "profile": "sv39-final-pmp",
            "elapsed_wall_seconds": 3.0,
            "case_elapsed_seconds": 0.5,
            "completed_cases": 1,
            "eligible_cases": 1,
            "eligible_bapc_cases": 1,
            "status": "fail",
            "failure_class": "unexpected_trap",
            "coverage_eligible": True,
            "qualification_reason": "eligible",
            "bapc_covered": 9,
            "bapc_target": 220,
            "bapc_rate": 9 / 220,
            "new_bapc_bins": 9,
            "last_bapc_novelty_time": 3.0,
        },
    ]
    _write_json(round_dir / "cases" / case_id / "case.json", case)
    _write_json(round_dir / "results" / case_id / "result.json", result)
    (round_dir / "results" / case_id / f"{case_id}.log").parent.mkdir(parents=True, exist_ok=True)
    (round_dir / "results" / case_id / f"{case_id}.log").write_text("boot noise\n", encoding="ascii")
    _write_json(metrics_dir / "coverage_universe" / "bapc_v1.json", legacy)
    _write_json(
        metrics_dir / "campaign_metadata.json",
        {
            "schema_version": "1.0",
            "experiment_id": "raw-exp",
            "campaign_id": "raw-pmpfuzz",
            "method": "pmpfuzz",
            "variant": "random-mutation",
            "coverage_mode": "bapc",
            "driver_mode": "continuous",
            "coverage_schema": "pmpfuzz-v1-single-mode",
            "dut": "rocket-clean",
            "seed": seed,
            "jobs": 8,
            "time_budget_seconds": 60,
            "wall_clock_horizon_seconds": 60,
            "per_case_timeout_seconds": 10,
            "round_size": 8,
            "run_class": "development-smoke",
            "budget_class": "primary-wall-clock",
            "source_sha": "a" * 40,
            "source_tree_sha256": "b" * 64,
            "source_dirty": False,
            "dut_sha": "c" * 40,
            "dut_sha_status": "explicit",
            "dut_binary_sha256": hashlib.sha256(dut_bin.read_bytes()).hexdigest(),
            "dut_binary_path": str(dut_bin),
            "capability_fingerprint": "cap",
            "coverage_universe_hashes": {"bapc": legacy["sha256"]},
            "coverage_universe_files": {"bapc": "metrics/coverage_universe/bapc_v1.json"},
            "schedule_v4": "metrics/schedule_v4.jsonl",
        },
    )
    _write_jsonl(metrics_dir / "schedule_v4.jsonl", [])
    _write_jsonl(metrics_dir / "coverage_timeline.jsonl", raw_timeline)
    _write_json(
        coverage_dir / "coverage.json",
        {
            "schema_version": 6,
            "driver_mode": "campaign",
            "coverage_universe_hashes": {"bapc": legacy["sha256"]},
            "execution_coverage": {"by_dut": {"rocket-clean": {"bapc": {"covered_target_bins": 9, "total_target_bins": 220, "covered_bins": [], "target": "black-box-architectural-pmp-behavior", "universe_sha256": legacy["sha256"]}}}},
        },
    )
    return campaign_dir


def _write_raw_cascade_bapc_campaign(root: Path, *, seed: int, dut_bin: Path) -> Path:
    campaign_dir = root / "campaigns" / "raw-exp" / "rocket-clean" / "cascade" / "bapc" / f"seed-{seed:04d}"
    metrics_dir = campaign_dir / "metrics"
    coverage_dir = campaign_dir / "coverage"
    elfs_dir = campaign_dir / "elfs"
    logs_dir = campaign_dir / "logs"
    case_id = "cascade_rocket-clean_0000"
    sidecar = {
        "campaign_seed": seed,
        "case_index": 0,
        "translation": "bare",
        "privilege": "S",
        "access": "load",
        "size": 4,
        "physical_address": "0x80008020",
        "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
        "pmp_entries": [
            {"index": 0, "address_mode": "napot", "pmpaddr": "0xffffffffffffffff", "read": True, "write": True, "execute": True, "locked": False}
        ],
        "actual_csr_state": {"mstatus": 0},
    }
    legacy = _legacy_bapc_universe(generator_seed=seed)
    raw_timeline = [
        {
            "schema_version": 1,
            "campaign_id": "raw-cascade",
            "variant": "baseline",
            "dut": "rocket-clean",
            "seed": seed,
            "completion_seq": 0,
            "case_id": None,
            "profile": None,
            "elapsed_wall_seconds": 0.0,
            "case_elapsed_seconds": 0.0,
            "completed_cases": 0,
            "eligible_cases": 0,
            "eligible_bapc_cases": 0,
            "status": None,
            "failure_class": None,
            "coverage_eligible": False,
            "qualification_reason": None,
            "bapc_covered": 0,
            "bapc_target": 220,
            "bapc_rate": 0.0,
            "new_bapc_bins": 0,
            "last_bapc_novelty_time": 0.0,
        },
        {
            "schema_version": 1,
            "campaign_id": "raw-cascade",
            "variant": "baseline",
            "dut": "rocket-clean",
            "seed": seed,
            "completion_seq": 1,
            "case_id": case_id,
            "profile": "cascade-baseline",
            "elapsed_wall_seconds": 4.0,
            "case_elapsed_seconds": 3.5,
            "completed_cases": 1,
            "eligible_cases": 1,
            "eligible_bapc_cases": 1,
            "status": "completed",
            "failure_class": None,
            "coverage_eligible": True,
            "qualification_reason": "eligible",
            "bapc_covered": 14,
            "bapc_target": 220,
            "bapc_rate": 14 / 220,
            "new_bapc_bins": 14,
            "last_bapc_novelty_time": 4.0,
        },
    ]
    _write_json(elfs_dir / "rocket_0.json", sidecar)
    (logs_dir / f"{case_id}.stdout.log").parent.mkdir(parents=True, exist_ok=True)
    (logs_dir / f"{case_id}.stdout.log").write_text("*** PASSED ***\n", encoding="ascii")
    (logs_dir / f"{case_id}.stderr.log").write_text("", encoding="ascii")
    _write_json(metrics_dir / "coverage_universe" / "bapc_v1.json", legacy)
    _write_json(
        metrics_dir / "campaign_metadata.json",
        {
            "schema_version": "1.0",
            "experiment_id": "raw-exp",
            "campaign_id": "raw-cascade",
            "method": "cascade",
            "variant": "baseline",
            "coverage_mode": "bapc",
            "driver_mode": "campaign",
            "dut": "rocket-clean",
            "seed": seed,
            "jobs": 1,
            "time_budget_seconds": 60,
            "wall_clock_horizon_seconds": 60,
            "per_case_timeout_seconds": 10,
            "run_class": "development-smoke",
            "budget_class": "primary-wall-clock",
            "source_sha": "a" * 40,
            "source_tree_sha256": "b" * 64,
            "source_dirty": False,
            "dut_sha": "c" * 40,
            "dut_sha_status": "explicit",
            "dut_binary_sha256": hashlib.sha256(dut_bin.read_bytes()).hexdigest(),
            "dut_binary_path": str(dut_bin),
            "capability_fingerprint": "cap",
            "coverage_universe_hashes": {"bapc": legacy["sha256"]},
            "coverage_universe_files": {"bapc": "metrics/coverage_universe/bapc_v1.json"},
        },
    )
    _write_jsonl(metrics_dir / "coverage_timeline.jsonl", raw_timeline)
    _write_json(
        campaign_dir / "events.json",
        [
            {
                "case_id": case_id,
                "completion_seq": 1,
                "status": "completed",
                "elapsed_wall_seconds": 4.0,
                "case_elapsed_seconds": 3.5,
                "returncode": 0,
                "probe_event_count": 100,
                "stdout_log": f"logs/{case_id}.stdout.log",
                "stderr_log": f"logs/{case_id}.stderr.log",
                "elf_sha256": "f" * 64,
                "bapc_coverage": {
                    "eligible": True,
                    "qualification_reason": "eligible",
                    "observed_bins": [],
                    "event_records": [
                        {
                            "address": "0x10000",
                            "privilege": "m",
                            "effective_privilege": "m",
                            "access": "fetch",
                            "translation": "bare",
                            "allow_or_deny": "allow",
                            "mcause_class": "none",
                            "fault_stage": "none",
                            "matched_pmp_mode": "napot",
                        }
                    ],
                    "ignored_probe_events": 100,
                },
            }
        ],
    )
    _write_json(
        coverage_dir / "coverage.json",
        {
            "schema_version": 6,
            "driver_mode": "campaign",
            "coverage_universe_hashes": {"bapc": legacy["sha256"]},
            "execution_coverage": {"by_dut": {"rocket-clean": {"bapc": {"covered_target_bins": 14, "total_target_bins": 220, "covered_bins": [], "target": "black-box-architectural-pmp-behavior", "universe_sha256": legacy["sha256"]}}}},
        },
    )
    return campaign_dir


def _write_raw_cascade_bapc_v4_campaign(root: Path, *, seed: int, dut_bin: Path) -> Path:
    campaign_dir = (
        root
        / "campaigns"
        / "section-8.3-8.4-formal-v4"
        / "rocket-clean"
        / "cascade"
        / "bapc"
        / f"seed-{seed:04d}"
    )
    metrics_dir = campaign_dir / "metrics"
    coverage_dir = campaign_dir / "coverage"
    elfs_dir = campaign_dir / "elfs"
    logs_dir = campaign_dir / "logs"
    case_id = "cascade_rocket-clean_0000"
    campaign_id = f"cascade__rocket-clean__seed-{seed:04d}"
    universe = build_bapc_coverage_universe(
        dut="rocket-clean",
        generator_seed=seed,
        supports_fault_stage=True,
        supports_smepmp=False,
        bapc_core_version="v4",
    )
    sidecar = {
        "campaign_seed": seed,
        "case_index": 0,
        "translation": "bare",
        "privilege": "M",
        "access": "load",
        "size": 4,
        "physical_address": "0x8020",
        "instruction_address": "0x80001000",
        "target_operation_candidates": [
            {
                "target_operation_id": "bb1-i0",
                "privilege": "M",
                "access": "load",
                "size": 4,
                "physical_address": "0x8020",
                "instruction_address": "0x80001000",
                "instruction_page_tag": 1,
            }
        ],
        "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
        "supports_smepmp": False,
        "pmp_entries": [
            {
                "index": 0,
                "address_mode": "napot",
                "pmpaddr": "0xffffffffffffffff",
                "read": True,
                "write": True,
                "execute": True,
                "locked": False,
            }
        ],
        "actual_csr_state": {"mstatus": 0},
    }
    raw_timeline = [
        {
            "schema_version": 1,
            "campaign_id": campaign_id,
            "variant": "cascade",
            "dut": "rocket-clean",
            "seed": seed,
            "completion_seq": 0,
            "case_id": None,
            "profile": None,
            "elapsed_wall_seconds": 0.0,
            "case_elapsed_seconds": 0.0,
            "completed_cases": 0,
            "eligible_cases": 0,
            "eligible_bapc_cases": 0,
            "status": None,
            "failure_class": None,
            "coverage_eligible": False,
            "qualification_reason": None,
            "bapc_covered": 0,
            "bapc_target": 144,
            "bapc_rate": 0.0,
            "new_bapc_bins": 0,
            "last_bapc_novelty_time": 0.0,
        },
        {
            "schema_version": 1,
            "campaign_id": campaign_id,
            "variant": "cascade",
            "dut": "rocket-clean",
            "seed": seed,
            "completion_seq": 1,
            "case_id": case_id,
            "profile": "cascade-baseline",
            "elapsed_wall_seconds": 4.0,
            "case_elapsed_seconds": 3.5,
            "completed_cases": 1,
            "eligible_cases": 1,
            "eligible_bapc_cases": 1,
            "status": "completed",
            "failure_class": None,
            "coverage_eligible": True,
            "qualification_reason": "eligible",
            "bapc_covered": 9,
            "bapc_target": 144,
            "bapc_rate": 9 / 144,
            "new_bapc_bins": 9,
            "last_bapc_novelty_time": 4.0,
        },
    ]
    stdout_text = "\n".join(
        [
            "PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker "
            "chain=pmp-check stage=final prv=3 access=fetch allow=1 addr=0x80001000 r=1 w=1 x=1",
            "PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker "
            "chain=pmp-check stage=final prv=3 access=load allow=1 addr=0x80008020 r=1 w=1 x=1",
            "*** PASSED ***",
            "",
        ]
    )
    stale_event_record = {
        "address": "0x80008020",
        "privilege": "m",
        "effective_privilege": "m",
        "access": "fetch",
        "translation": "bare",
        "allow_or_deny": "allow",
        "mcause_class": "none",
        "fault_stage": "none",
        "matched_pmp_mode": "napot",
    }
    _write_json(elfs_dir / "rocket_0.json", sidecar)
    (logs_dir / f"{case_id}.stdout.log").parent.mkdir(parents=True, exist_ok=True)
    (logs_dir / f"{case_id}.stdout.log").write_text(stdout_text, encoding="ascii")
    (logs_dir / f"{case_id}.stderr.log").write_text("", encoding="ascii")
    _write_json(metrics_dir / "coverage_universe" / "bapc_v4.json", universe)
    _write_json(
        metrics_dir / "campaign_metadata.json",
        {
            "schema_version": "1.0",
            "experiment_id": "section-8.3-8.4-formal-v4",
            "campaign_id": campaign_id,
            "method": "cascade",
            "variant": "cascade",
            "coverage_mode": "bapc",
            "driver_mode": "campaign",
            "dut": "rocket-clean",
            "seed": seed,
            "jobs": 1,
            "time_budget_seconds": 7200,
            "wall_clock_horizon_seconds": 7200,
            "per_case_timeout_seconds": 10,
            "run_class": "baseline-formal",
            "budget_class": "primary-wall-clock",
            "experiment_protocol_id": BAPC_CONVERGENCE_PROTOCOL_ID,
            "source_sha": "a" * 40,
            "source_tree_sha256": "b" * 64,
            "source_dirty": False,
            "dut_sha": "c" * 40,
            "dut_sha_status": "explicit",
            "dut_binary_sha256": hashlib.sha256(dut_bin.read_bytes()).hexdigest(),
            "dut_binary_path": str(dut_bin),
            "capability_fingerprint": "cap",
            "bapc_core_version": "v4",
            "bapc_target": 144,
            "stop_reason": "coverage_converged",
            "coverage_universe_hashes": {"bapc": universe["sha256"]},
            "coverage_universe_files": {"bapc": "metrics/coverage_universe/bapc_v4.json"},
        },
    )
    _write_jsonl(metrics_dir / "coverage_timeline.jsonl", raw_timeline)
    _write_json(
        campaign_dir / "events.json",
        [
            {
                "case_id": case_id,
                "completion_seq": 1,
                "status": "completed",
                "elapsed_wall_seconds": 4.0,
                "case_elapsed_seconds": 3.5,
                "returncode": 0,
                "probe_event_count": 2,
                "stdout_log": f"logs/{case_id}.stdout.log",
                "stderr_log": f"logs/{case_id}.stderr.log",
                "elf_sha256": "f" * 64,
                "bapc_coverage": {
                    "eligible": True,
                    "qualification_reason": "eligible",
                    "observed_bins": [],
                    "event_records": [stale_event_record],
                    "ignored_probe_events": 2,
                },
            }
        ],
    )
    _write_json(
        coverage_dir / "coverage.json",
        {
            "schema_version": 6,
            "driver_mode": "campaign",
            "coverage_universe_hashes": {"bapc": universe["sha256"]},
            "execution_coverage": {
                "by_dut": {
                    "rocket-clean": {
                        "bapc": {
                            "covered_target_bins": 9,
                            "total_target_bins": 144,
                            "covered_bins": [],
                            "target": "black-box-architectural-pmp-behavior",
                            "universe_sha256": universe["sha256"],
                        }
                    }
                }
            },
        },
    )
    return campaign_dir


class BapcAnalysisContractTest(unittest.TestCase):
    def test_validate_timeline_accepts_single_mode_bapc_campaign(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = build_bapc_coverage_universe(
                dut="rocket-clean",
                generator_seed=1,
                supports_fault_stage=True,
                supports_smepmp=False,
            )
            campaign_dir = _make_bapc_campaign(root, seed=1, universe=universe, covered_bins=[universe["bin_ids"][0]])

            report = validate_timeline(campaign_dir)

        self.assertTrue(report["valid"], report)

    def test_validate_timeline_rejects_legacy_bapc_v1_universe_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy = make_coverage_universe(
                coverage_mode="bapc",
                bin_ids=["legacy:0"],
                capability_fingerprint="cap-legacy",
                target="black-box-architectural-pmp-behavior",
                include_experimental=False,
                generator_seed=1,
                generation_rule_version="bapc-coverage-universe-v1",
            )
            campaign_dir = _make_bapc_campaign(
                root,
                seed=1,
                universe=legacy,
                covered_bins=[],
                universe_filename="bapc_v1.json",
            )

            report = validate_timeline(campaign_dir)

        self.assertFalse(report["valid"])
        self.assertTrue(
            any(
                check["name"] == "coverage_universe_file_bapc" and not check["passed"]
                for check in report["checks"]
            ),
            report,
        )

    def test_validate_timeline_defers_cross_campaign_artifact_manifest_hashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            dut_root = Path(tmp)
            universe = build_bapc_coverage_universe(
                dut="rocket-clean",
                generator_seed=1,
                supports_fault_stage=True,
                supports_smepmp=False,
            )
            covered_bin = universe["bin_ids"][0]
            campaign_dir = _make_bapc_campaign(dut_root, seed=1, universe=universe, covered_bins=[covered_bin])
            sibling_dir = _make_bapc_campaign(dut_root, seed=2, universe=universe, covered_bins=[covered_bin])

            manifests_dir = dut_root / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            sibling_log = sibling_dir / "rounds" / "round_0001" / "failures" / "huge" / "old.log"
            sibling_log.parent.mkdir(parents=True, exist_ok=True)
            sibling_log.write_text("old-data\n", encoding="ascii")
            sibling_hash = hashlib.sha256(sibling_log.read_bytes()).hexdigest()
            (manifests_dir / "artifact-sha256.txt").write_text(
                f"{sibling_hash}  {sibling_log.relative_to(dut_root).as_posix()}\n",
                encoding="ascii",
            )
            sibling_log.unlink()

            rc = validate_timeline_main(
                [
                    "--campaign",
                    str(campaign_dir),
                    "--defer-cross-campaign-artifact-manifest",
                ]
            )
            self.assertEqual(rc, 0)
            report = json.loads((campaign_dir / "validation.json").read_text(encoding="ascii"))

        self.assertTrue(report["valid"], report)
        self.assertTrue(
            any(
                check["name"] == "artifact_sha_manifest_deferred" and check["passed"]
                for check in report["checks"]
            ),
            report,
        )
        self.assertFalse(
            any(check["name"] == "artifact_sha_manifest_files_exist" for check in report["checks"]),
            report,
        )

    def test_validate_timeline_keeps_campaign_local_artifact_manifest_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = build_bapc_coverage_universe(
                dut="rocket-clean",
                generator_seed=1,
                supports_fault_stage=True,
                supports_smepmp=False,
            )
            covered_bin = universe["bin_ids"][0]
            campaign_dir = _make_bapc_campaign(root, seed=1, universe=universe, covered_bins=[covered_bin])

            metadata_path = campaign_dir / "metrics" / "campaign_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
            metadata["run_class"] = "formal"
            metadata["experiment_protocol_id"] = BAPC_CONVERGENCE_PROTOCOL_ID
            _write_json(metadata_path, metadata)

            manifests_dir = campaign_dir / "manifests"
            _write_json(manifests_dir / "environment.json", {"hostname": "test-host"})
            (manifests_dir / "git-shas.txt").write_text("a" * 40 + "  pmpfuzz\n", encoding="ascii")
            _write_json(manifests_dir / "experiment-contract.json", {"schema_version": "1.0"})
            (manifests_dir / "artifact-sha256.txt").write_text(
                "0" * 64 + "  missing.log\n",
                encoding="ascii",
            )

            report = validate_timeline(campaign_dir)

        self.assertFalse(report["valid"])
        self.assertTrue(
            any(
                check["name"] == "artifact_sha_manifest_files_exist" and not check["passed"]
                for check in report["checks"]
            ),
            report,
        )
        self.assertFalse(
            any(check["name"] == "artifact_sha_manifest_deferred" for check in report["checks"]),
            report,
        )

    def test_aggregate_exports_bapc_mode_and_uses_bin_set_comparability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = build_bapc_coverage_universe(
                dut="rocket-clean",
                generator_seed=1,
                supports_fault_stage=True,
                supports_smepmp=False,
            )
            second = build_bapc_coverage_universe(
                dut="rocket-clean",
                generator_seed=2,
                supports_fault_stage=True,
                supports_smepmp=False,
            )
            self.assertNotEqual(first["sha256"], second["sha256"])
            self.assertEqual(first["bin_set_sha256"], second["bin_set_sha256"])
            _make_bapc_campaign(root, seed=1, universe=first, covered_bins=[first["bin_ids"][0]])
            _make_bapc_campaign(root, seed=2, universe=second, covered_bins=[second["bin_ids"][0]])

            aggregate(root, "exp")

            with (root / "aggregate" / "validation_report.json").open(encoding="ascii") as handle:
                report = json.load(handle)
            with (root / "aggregate" / "coverage_timeseries.csv").open(encoding="ascii", newline="") as handle:
                rows = list(csv.DictReader(handle))

        self.assertTrue(report["valid"], report)
        self.assertEqual({row["coverage_mode"] for row in rows}, {"bapc"})

    def test_aggregate_normalizes_legacy_hard_cap_stop_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = build_bapc_coverage_universe(
                dut="rocket-clean",
                generator_seed=1,
                supports_fault_stage=True,
                supports_smepmp=False,
            )
            campaign_dir = _make_bapc_campaign(root, seed=1, universe=universe, covered_bins=[universe["bin_ids"][0]])
            metadata_path = campaign_dir / "metrics" / "campaign_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
            metadata["stop_reason"] = "right_censored_not_converged"
            metadata_path.write_text(
                json.dumps(metadata, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
                encoding="ascii",
            )

            aggregate(root, "exp")

            with (root / "normalized" / "campaigns.csv").open(encoding="ascii", newline="") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(rows[0]["stop_reason"], "hard_cap_censored")

    def test_reanalysis_rebuilds_bapc_v2_without_mutating_raw_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            raw_root = tmp_root / "raw"
            out_root = tmp_root / "analysis-v2"
            dut_bin = tmp_root / "dut.bin"
            dut_bin.write_bytes(b"boom-or-rocket")
            _write_raw_pmpfuzz_bapc_campaign(raw_root, seed=1, dut_bin=dut_bin)
            _write_raw_cascade_bapc_campaign(raw_root, seed=1, dut_bin=dut_bin)
            before = _sha_tree(raw_root)

            from scripts.evaluation.analysis.reanalyze_bapc_v2 import reanalyze_bapc_artifact

            reanalyze_bapc_artifact(raw_root, out_root)
            after = _sha_tree(raw_root)

            pmf_campaign = out_root / "campaigns" / "raw-exp" / "rocket-clean" / "random-mutation" / "bapc" / "seed-0001"
            cascade_campaign = out_root / "campaigns" / "raw-exp" / "rocket-clean" / "cascade" / "bapc" / "seed-0001"
            pmf_universe = json.loads((pmf_campaign / "metrics" / "coverage_universe" / "bapc_v2.json").read_text(encoding="ascii"))
            cascade_universe = json.loads((cascade_campaign / "metrics" / "coverage_universe" / "bapc_v2.json").read_text(encoding="ascii"))
            pmf_validation = json.loads((pmf_campaign / "validation.json").read_text(encoding="ascii"))
            cascade_validation = json.loads((cascade_campaign / "validation.json").read_text(encoding="ascii"))
            aggregate_validation = json.loads((out_root / "aggregate" / "validation_report.json").read_text(encoding="ascii"))
            cascade_meta = json.loads((cascade_campaign / "metrics" / "campaign_metadata.json").read_text(encoding="ascii"))
            cascade_last = json.loads(
                (cascade_campaign / "metrics" / "coverage_timeline.jsonl").read_text(encoding="ascii").splitlines()[-1]
            )

        self.assertEqual(before, after)
        self.assertEqual(pmf_universe["bin_count"], 208)
        self.assertEqual(cascade_universe["bin_count"], 208)
        self.assertEqual(pmf_universe["bin_set_sha256"], cascade_universe["bin_set_sha256"])
        self.assertFalse(any("translation-stage" in bin_id for bin_id in pmf_universe["bin_ids"]))
        self.assertTrue(pmf_validation["valid"], pmf_validation)
        self.assertTrue(cascade_validation["valid"], cascade_validation)
        self.assertTrue(aggregate_validation["valid"], aggregate_validation)
        self.assertEqual(cascade_meta["eligible_bapc_cases"], 1)
        self.assertGreater(cascade_last["bapc_covered"], 0)
        self.assertEqual(cascade_meta["variant"], "cascade")

    def test_reanalysis_rebuilds_bapc_v4_cascade_from_probe_events_without_mutating_raw_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            raw_root = tmp_root / "raw"
            out_root = tmp_root / "analysis-v4"
            dut_bin = tmp_root / "dut.bin"
            dut_bin.write_bytes(b"rocket-clean")
            raw_campaign = _write_raw_cascade_bapc_v4_campaign(raw_root, seed=4, dut_bin=dut_bin)
            before = _sha_tree(raw_root)

            sidecar = json.loads((raw_campaign / "elfs" / "rocket_0.json").read_text(encoding="ascii"))
            stdout_text = (raw_campaign / "logs" / "cascade_rocket-clean_0000.stdout.log").read_text(encoding="ascii")
            result = {"status": "pass"}
            stale_summary = summarize_bapc_for_cascade_execution(
                sidecar,
                result,
                stdout_text="",
                event_records=[
                    {
                        "address": "0x80008020",
                        "privilege": "m",
                        "effective_privilege": "m",
                        "access": "fetch",
                        "translation": "bare",
                        "allow_or_deny": "allow",
                        "mcause_class": "none",
                        "fault_stage": "none",
                        "matched_pmp_mode": "napot",
                    }
                ],
                bapc_core_version="v4",
            )
            runtime_records = runtime_bapc_event_records_for_cascade_execution(
                sidecar,
                result,
                stdout_text=stdout_text,
            )
            live_summary = summarize_bapc_for_cascade_execution(
                sidecar,
                result,
                stdout_text=stdout_text,
                event_records=runtime_records,
                bapc_core_version="v4",
            )

            from scripts.evaluation.analysis.reanalyze_bapc_v4_cascade import reanalyze_bapc_v4_cascade_artifact

            reanalyze_bapc_v4_cascade_artifact(raw_root, out_root)
            after = _sha_tree(raw_root)

            campaign = (
                out_root
                / "dut-roots"
                / "rocket-clean"
                / "campaigns"
                / "section-8.3-8.4-formal-v4"
                / "rocket-clean"
                / "cascade"
                / "bapc"
                / "seed-0004"
            )
            universe = json.loads((campaign / "metrics" / "coverage_universe" / "bapc_v4.json").read_text(encoding="ascii"))
            meta = json.loads((campaign / "metrics" / "campaign_metadata.json").read_text(encoding="ascii"))
            coverage = json.loads((campaign / "coverage" / "coverage.json").read_text(encoding="ascii"))
            validation = json.loads((campaign / "validation.json").read_text(encoding="ascii"))
            aggregate_validation = json.loads(
                (out_root / "dut-roots" / "rocket-clean" / "aggregate" / "validation_report.json").read_text(
                    encoding="ascii"
                )
            )
            last = json.loads((campaign / "metrics" / "coverage_timeline.jsonl").read_text(encoding="ascii").splitlines()[-1])

        self.assertEqual(before, after)
        self.assertEqual(universe["bapc_core_version"], "v4")
        self.assertEqual(universe["bin_count"], 144)
        self.assertTrue(stale_summary["eligible"], stale_summary)
        self.assertTrue(live_summary["eligible"], live_summary)
        self.assertEqual(stale_summary["event_records"][0]["access"], "fetch")
        self.assertEqual(runtime_records[0]["address"], "0x80008020")
        self.assertEqual(live_summary["event_records"][0]["access"], "load")
        self.assertEqual(live_summary["event_records"][0]["address"], "0x80008020")
        self.assertTrue(validation["valid"], validation)
        self.assertTrue(aggregate_validation["valid"], aggregate_validation)
        self.assertEqual(meta["bapc_core_version"], "v4")
        self.assertEqual(meta["bapc_target"], 144)
        self.assertEqual(meta["coverage_universe_files"]["bapc"], "metrics/coverage_universe/bapc_v4.json")
        self.assertEqual(meta["eligible_bapc_cases"], 1)
        self.assertEqual(last["bapc_covered"], len(live_summary["observed_bins"]))
        self.assertEqual(
            coverage["execution_coverage"]["by_dut"]["rocket-clean"]["bapc"]["covered_target_bins"],
            last["bapc_covered"],
        )

    def test_reanalysis_v4_ignores_unexecuted_cascade_sidecars_without_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            raw_root = tmp_root / "raw"
            out_root = tmp_root / "analysis-v4"
            dut_bin = tmp_root / "dut.bin"
            dut_bin.write_bytes(b"rocket-clean")
            raw_campaign = _write_raw_cascade_bapc_v4_campaign(raw_root, seed=4, dut_bin=dut_bin)
            unused_sidecar = json.loads((raw_campaign / "elfs" / "rocket_0.json").read_text(encoding="ascii"))
            unused_sidecar["case_index"] = 526
            _write_json(raw_campaign / "elfs" / "rocket_526.json", unused_sidecar)

            from scripts.evaluation.analysis.reanalyze_bapc_v4_cascade import reanalyze_bapc_v4_cascade_artifact

            reanalyze_bapc_v4_cascade_artifact(raw_root, out_root)

            campaign = (
                out_root
                / "dut-roots"
                / "rocket-clean"
                / "campaigns"
                / "section-8.3-8.4-formal-v4"
                / "rocket-clean"
                / "cascade"
                / "bapc"
                / "seed-0004"
            )
            meta = json.loads((campaign / "metrics" / "campaign_metadata.json").read_text(encoding="ascii"))
            validation = json.loads((campaign / "validation.json").read_text(encoding="ascii"))

        self.assertEqual(meta["eligible_bapc_cases"], 1)
        self.assertTrue(validation["valid"], validation)

    def test_reanalysis_v4_contract_allows_multiple_known_source_shas(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            raw_root = tmp_root / "raw"
            out_root = tmp_root / "analysis-v4"
            dut_bin = tmp_root / "dut.bin"
            dut_bin.write_bytes(b"rocket-clean")
            first = _write_raw_cascade_bapc_v4_campaign(raw_root, seed=4, dut_bin=dut_bin)
            second = _write_raw_cascade_bapc_v4_campaign(raw_root, seed=5, dut_bin=dut_bin)

            second_meta_path = second / "metrics" / "campaign_metadata.json"
            second_meta = json.loads(second_meta_path.read_text(encoding="ascii"))
            second_meta["source_sha"] = "d" * 40
            second_meta["source_tree_sha256"] = "e" * 64
            _write_json(second_meta_path, second_meta)

            from scripts.evaluation.analysis.reanalyze_bapc_v4_cascade import reanalyze_bapc_v4_cascade_artifact

            reanalyze_bapc_v4_cascade_artifact(raw_root, out_root)

            rocket_root = out_root / "dut-roots" / "rocket-clean"
            aggregate_validation = json.loads((rocket_root / "aggregate" / "validation_report.json").read_text(encoding="ascii"))
            campaign_index = (rocket_root / "aggregate" / "campaign_index.csv").read_text(encoding="ascii")
            contract = json.loads((rocket_root / "manifests" / "experiment-contract.json").read_text(encoding="ascii"))

        self.assertTrue(aggregate_validation["valid"], aggregate_validation)
        self.assertIn("seed-0004", campaign_index)
        self.assertIn("seed-0005", campaign_index)
        self.assertEqual(contract["source_sha"], "a" * 40)
        self.assertEqual(contract["allowed_source_shas"], ["a" * 40, "d" * 40])
        self.assertEqual(len(contract["source_tree_sha256"]), 64)
        self.assertIn(contract["source_tree_sha256"], contract["allowed_source_tree_sha256s"])

    def test_legacy_v2_universe_can_be_revalidated_loaded_and_classified_twice_without_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe = build_bapc_coverage_universe(
                dut="rocket-clean",
                generator_seed=1,
                supports_fault_stage=True,
                supports_smepmp=False,
            )
            legacy = dict(universe)
            legacy.pop("bapc_core_version", None)
            legacy["sha256"] = coverage_universe_module._coverage_universe_hash(legacy)
            path = root / "bapc_v2_legacy.json"
            _write_json(path, legacy)
            before_text = path.read_text(encoding="ascii")
            before_object = json.loads(before_text)
            mutable = json.loads(before_text)
            observed_bins = [legacy["bin_ids"][0], "out-of-contract"]

            first_validated = validate_bapc_coverage_universe(mutable)
            first_classified = classify_observed_bins(first_validated, observed_bins)
            second_validated = validate_bapc_coverage_universe(mutable)
            second_classified = classify_observed_bins(second_validated, observed_bins)
            loaded_once = load_bapc_coverage_universe(path)
            loaded_twice = load_bapc_coverage_universe(path)
            after_text = path.read_text(encoding="ascii")

        self.assertEqual(before_text, after_text)
        self.assertEqual(mutable, before_object)
        self.assertEqual(first_classified, second_classified)
        self.assertEqual(loaded_once, loaded_twice)
        self.assertNotIn("bapc_core_version", mutable)
        self.assertNotIn("bapc_core_version", loaded_once)
        self.assertEqual(first_classified["covered"], [legacy["bin_ids"][0]])
        self.assertEqual(first_classified["out_of_contract"], ["out-of-contract"])


if __name__ == "__main__":
    unittest.main()
