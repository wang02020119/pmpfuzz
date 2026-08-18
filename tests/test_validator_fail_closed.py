
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pmpfuzz.bapc import build_bapc_coverage_universe
from pmpfuzz.coverage_universe import make_coverage_universe
from pmpfuzz.experiment_protocols import (
    BAPC_CONVERGENCE_FORMAL,
    BAPC_CONVERGENCE_PROTOCOL_ID,
)
from pmpfuzz.schedule_v4 import ScheduleV4Writer
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.scenario_codec import scenario_hash, scenario_to_spec
from scripts.evaluation.validation.validate_timeline import main, validate_timeline

_CAMPAIGN_DIR_DEPTH = 6


def _artifact_root_from_campaign(campaign_dir: Path) -> Path:
    p = campaign_dir
    for _ in range(_CAMPAIGN_DIR_DEPTH):
        p = p.parent
    return p


def _build_minimal_campaign(root: Path, *, campaign_id: str = "e1-rocket-random-0101",
                            seed: int = 101, variant: str = "random",
                            dut: str = "rocket-clean",
                            coverage_mode: str = "semantic",
                            experiment_id: str = "E1-COVERAGE-FEEDBACK",
                            ) -> Path:
    campaign = (root / "campaigns" / experiment_id / dut / variant
                / coverage_mode / f"seed-{seed:04d}")
    campaign.mkdir(parents=True)
    return campaign


def _write_timeline(campaign: Path, campaign_id: str, variant: str = "random",
                    dut: str = "rocket-clean", seed: int = 101,
                    case_ids: list[str] | None = None,
                    completion_seqs: list[int] | None = None,
                    wall_times: list[float] | None = None,
                    ) -> Path:
    metrics = campaign / "metrics"
    metrics.mkdir(parents=True, exist_ok=True)
    if case_ids is None:
        case_ids = [f"case-{i:04d}" for i in range(1, 4)]
    if completion_seqs is None:
        completion_seqs = list(range(len(case_ids) + 1))
    if wall_times is None:
        wall_times = [i * 10.0 for i in range(len(case_ids) + 1)]

    baseline = {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "variant": variant,
        "dut": dut,
        "seed": seed,
        "completion_seq": completion_seqs[0],
        "case_id": None,
        "elapsed_wall_seconds": wall_times[0],
        "case_elapsed_seconds": 0.0,
        "completed_cases": 0,
        "eligible_cases": 0,
        "status": None,
        "failure_class": None,
        "coverage_eligible": False,
        "qualification_reason": None,
        "semantic_covered": 0,
        "semantic_target": 10,
        "semantic_rate": 0.0,
        "pairwise_covered": 0,
        "pairwise_target": 5,
        "pairwise_rate": 0.0,
        "security_triples_covered": 0,
        "security_triples_target": 3,
        "security_triples_rate": 0.0,
        "predicates_covered": 0,
        "predicates_target": 2,
        "predicates_rate": 0.0,
        "new_semantic_bins": 0,
        "new_pairwise_bins": 0,
        "new_security_triple_bins": 0,
        "new_predicate_bins": 0,
        "whitebox_distinct_events": 0,
        "new_whitebox_events": 0,
        "completion_monotonic_seconds": 0.0,
    }

    rows = [baseline]
    for i, cid in enumerate(case_ids):
        si = i + 1
        seq = completion_seqs[si] if si < len(completion_seqs) else si
        wt = wall_times[si] if si < len(wall_times) else si * 10.0
        row = {
            **baseline,
            "completion_seq": seq,
            "case_id": cid,
            "elapsed_wall_seconds": wt,
            "case_elapsed_seconds": 2.0,
            "completed_cases": seq,
            "eligible_cases": seq,
            "status": "pass",
            "failure_class": None,
            "coverage_eligible": True,
            "qualification_reason": "eligible",
            "semantic_covered": seq * 2,
            "semantic_rate": (seq * 2) / 10.0,
            "new_semantic_bins": 2,
            "completion_monotonic_seconds": wt * 100.0,
        }
        rows.append(row)

    tl_path = metrics / "coverage_timeline.jsonl"
    tl_path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=True, sort_keys=True) for r in rows) + "\n",
        encoding="ascii",
    )
    return tl_path


def _write_metadata(campaign: Path, campaign_id: str,
                    variant: str = "random", dut: str = "rocket-clean",
                    seed: int = 101, run_class: str | None = "pilot",
                    source_sha: str = "a" * 40, dut_sha: str = "b" * 40,
                    dut_binary_sha256: str = "c" * 64,
                    capability_fingerprint: str = "d" * 64,
                    source_tree_sha256: str = "e" * 64,
                    source_dirty: bool = False,
                    dut_binary_path: str | None = None,
                    dut_sha_status: str | None = None,
                    dut_sha_reason: str | None = None,
                    coverage_mode: str = "semantic",
                    experiment_id: str = "E1-COVERAGE-FEEDBACK",
                    method: str = "pmpfuzz",
                    ) -> Path:
    metrics = campaign / "metrics"
    metrics.mkdir(parents=True, exist_ok=True)
    meta = {
        "schema_version": "1.0",
        "experiment_id": experiment_id,
        "campaign_id": campaign_id,
        "method": method,
        "variant": variant,
        "coverage_mode": coverage_mode,
        "dut": dut,
        "seed": seed,
        "source_sha": source_sha,
        "source_tree_sha256": source_tree_sha256,
        "source_dirty": source_dirty,
        "dut_sha": dut_sha,
        "dut_binary_sha256": dut_binary_sha256,
        "capability_fingerprint": capability_fingerprint,
        "start_utc": "2026-07-13T00:00:00+00:00",
        "end_utc": "2026-07-13T00:00:30+00:00",
        "time_budget_seconds": 30,
        "round_size": 2,
        "jobs": 1,
        "per_case_timeout_seconds": 10,
    }
    fixture_dir = campaign / "fixtures"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    if dut_binary_path is None:
        binary_path = fixture_dir / "dut.bin"
        binary_path.write_bytes(b"validator-dut\n")
        meta["dut_binary_path"] = str(binary_path)
        if dut_binary_sha256 == "c" * 64:
            meta["dut_binary_sha256"] = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    else:
        meta["dut_binary_path"] = dut_binary_path
    if dut_sha_status is not None:
        meta["dut_sha_status"] = dut_sha_status
    if dut_sha_reason is not None:
        meta["dut_sha_reason"] = dut_sha_reason
    if run_class is not None:
        meta["run_class"] = run_class
    mp = metrics / "campaign_metadata.json"
    mp.write_text(json.dumps(meta, indent=2, ensure_ascii=True), encoding="ascii")
    return mp


def _write_case(campaign: Path, case_id: str) -> Path:
    d = campaign / "cases" / case_id
    d.mkdir(parents=True, exist_ok=True)
    p = d / "case.json"
    p.write_text(json.dumps({
        "name": case_id,
        "profile": "pmp-boundary",
        "privilege": "M",
        "access": "load",
        "translation": "bare",
        "pmp_match_mode": "OFF",
        "expected_allowed": True,
        "expected_trap_cause": None,
        "expected_stage": "normal",
        "coverage_tags": [],
    }, ensure_ascii=True), encoding="ascii")
    return p


def _write_result(campaign: Path, case_id: str, status: str = "pass") -> Path:
    d = campaign / "results" / case_id
    d.mkdir(parents=True, exist_ok=True)
    p = d / "result.json"
    p.write_text(json.dumps({
        "name": case_id,
        "status": status,
        "failure_class": None,
        "observation_valid": True,
        "stage_verified": True,
        "observed_event": "completion",
        "observed_phase": "completed",
        "observed_tohost": 0,
        "oracle_applicability": "valid",
        "dut": "rocket-clean",
    }, ensure_ascii=True), encoding="ascii")
    return p


def _write_cases_and_results(campaign: Path, case_ids: list[str]) -> None:
    for cid in case_ids:
        _write_case(campaign, cid)
        _write_result(campaign, cid)


def _write_child_round(campaign: Path, round_name: str = "round_0000",
                       case_ids: list[str] | None = None) -> Path:
    rd = campaign / "rounds" / round_name
    rd.mkdir(parents=True, exist_ok=True)
    if case_ids is None:
        case_ids = [f"child-case-{i:04d}" for i in range(1, 3)]
    _write_timeline(rd, "round", case_ids=case_ids)
    return rd


def _write_manifests(artifact_root: Path, *,
                     include_environment: bool = True,
                     include_git_shas: bool = True,
                     include_artifact_sha: bool = True,
                     artifact_sha_files: list[tuple[str, str]] | None = None,
                     experiment_contract: dict[str, object] | None = None,
                     ) -> Path:
    mdir = artifact_root / "manifests"
    mdir.mkdir(parents=True, exist_ok=True)
    if include_environment:
        (mdir / "environment.json").write_text(json.dumps({
            "python_version": "3.11.9",
            "platform": "linux",
        }), encoding="ascii")
    if include_git_shas:
        (mdir / "git-shas.txt").write_text(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0  pmpfuzz\n"
            "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0  riscv-isac\n",
            encoding="ascii",
        )
    if include_artifact_sha:
        if artifact_sha_files is None:
            artifact_sha_files = []
        lines = []
        for rel, content in artifact_sha_files:
            target = artifact_root / Path(rel)
            if target.exists():
                h = hashlib.sha256(target.read_bytes()).hexdigest()
            else:
                h = hashlib.sha256(content.encode("ascii")).hexdigest()
            lines.append(f"{h}  {rel}")
        if lines:
            (mdir / "artifact-sha256.txt").write_text(
                "\n".join(lines) + "\n", encoding="ascii"
            )
        else:
            (mdir / "artifact-sha256.txt").write_text("", encoding="ascii")
    if experiment_contract is not None:
        (mdir / "experiment-contract.json").write_text(
            json.dumps(experiment_contract, indent=2, ensure_ascii=True),
            encoding="ascii",
        )
    return mdir


def _write_bapc_formal_contract(
    artifact_root: Path,
    *,
    dut: str = "boom-clean",
    bin_set_sha256: str = "240adc7f9ce2b9f554317ca854af444d8dfb90e6c613012c23c2144cd3b8dd5e",
    variants: list[str] | None = None,
    seeds: list[int] | None = None,
) -> dict[str, object]:
    payload = {
        "schema_version": 1,
        "experiment_protocol_id": BAPC_CONVERGENCE_PROTOCOL_ID,
        "dut": dut,
        "coverage_mode": "bapc",
        "bin_count": 208,
        "bin_set_sha256": bin_set_sha256,
        "variants": list(variants or ["random-mutation", "bb-guided", "cascade"]),
        "seeds": list(seeds or [4, 5, 6]),
        **BAPC_CONVERGENCE_FORMAL,
    }
    _write_manifests(artifact_root, experiment_contract=payload)
    return payload


def _write_continuous_schedule(campaign: Path, *, semantic_bins: list[str]) -> None:
    scenario = ScenarioGenerator(seed=101, include_smepmp=False, profile="pmp-boundary").generate_one(0)
    spec = scenario_to_spec(scenario)
    spec_hash = scenario_hash(spec)
    writer = ScheduleV4Writer(campaign / "metrics" / "schedule_v4.jsonl")
    writer.append(
        "candidate_admitted",
        scenario_hash=spec_hash,
        scenario_spec=spec,
        generation_seq=1,
        parent_hash=None,
        mutation_operator="root",
    )
    writer.append(
        "execution_committed",
        scenario_hash=spec_hash,
        candidate_id=spec_hash,
        case_id="case-0001",
        profile="pmp-boundary",
        status="pass",
        failure_class=None,
        eligible=True,
        qualification_reason="eligible",
        elapsed_wall_seconds=10.0,
        case_elapsed_seconds=2.0,
        execution_cost=2.0,
        new_bins={
            "semantic": list(semantic_bins),
            "pairwise": [],
            "security_triples": [],
            "predicates": [],
        },
        promoted=False,
        evicted_hashes=[],
        retained_without_novelty=False,
        new_whitebox_events=0,
    )


def _mark_metadata_continuous(campaign: Path) -> None:
    metadata_path = campaign / "metrics" / "campaign_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="ascii"))
    metadata["driver_mode"] = "continuous"
    metadata["coverage_schema"] = "pmpfuzz-v1-four-mode"
    metadata["schedule_v4"] = "metrics/schedule_v4.jsonl"
    metadata["coverage_universe_hashes"] = {
        "semantic": "1" * 64,
        "pairwise": "2" * 64,
        "security_triples": "3" * 64,
        "predicates": "4" * 64,
    }
    metadata_path.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=True),
        encoding="ascii",
    )


def _write_continuous_universe_files(campaign: Path) -> dict[str, dict[str, object]]:
    coverage_dir = campaign / "coverage"
    coverage_dir.mkdir(parents=True, exist_ok=True)
    universes = {
        "semantic": make_coverage_universe(
            coverage_mode="semantic",
            bin_ids=[f"sem:{i}" for i in range(10)],
            capability_fingerprint="cap",
            target="core-stateful",
            include_experimental=False,
            generator_seed=1,
        ),
        "pairwise": make_coverage_universe(
            coverage_mode="pairwise",
            bin_ids=[f"pair:{i}" for i in range(5)],
            capability_fingerprint="cap",
            target="core-stateful",
            include_experimental=False,
            generator_seed=1,
        ),
        "security_triples": make_coverage_universe(
            coverage_mode="security_triples",
            bin_ids=[f"triple:{i}" for i in range(3)],
            capability_fingerprint="cap",
            target="core-stateful",
            include_experimental=False,
            generator_seed=1,
        ),
        "predicates": make_coverage_universe(
            coverage_mode="predicates",
            bin_ids=[f"pred:{i}" for i in range(2)],
            capability_fingerprint="cap",
            target="core-stateful",
            include_experimental=False,
            generator_seed=1,
        ),
    }
    for mode, payload in universes.items():
        (coverage_dir / f"{mode}_v1.json").write_text(
            json.dumps(payload, ensure_ascii=True, sort_keys=True),
            encoding="ascii",
        )
    metadata_path = campaign / "metrics" / "campaign_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="ascii"))
    metadata["coverage_universe_hashes"] = {
        mode: str(payload["sha256"]) for mode, payload in universes.items()
    }
    metadata["coverage_universe_files"] = {
        mode: f"coverage/{mode}_v1.json" for mode in universes
    }
    metadata_path.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=True),
        encoding="ascii",
    )
    return universes


def _write_continuous_coverage_json(
    campaign: Path,
    *,
    dut_name: str = "rocket-clean",
    semantic_bins: list[str] | None = None,
    pairwise_bins: list[str] | None = None,
    triples_bins: list[str] | None = None,
    predicate_bins: list[str] | None = None,
    semantic_hash: str = "",
    pairwise_hash: str = "",
    triples_hash: str = "",
    predicates_hash: str = "",
    semantic_target: int = 10,
    pairwise_target: int = 5,
    triples_target: int = 3,
    predicates_target: int = 2,
) -> None:
    semantic_bins = semantic_bins or ["sem:0", "sem:1"]
    pairwise_bins = pairwise_bins or []
    triples_bins = triples_bins or []
    predicate_bins = predicate_bins or []
    coverage_dir = campaign / "coverage"
    coverage_dir.mkdir(parents=True, exist_ok=True)
    (coverage_dir / "coverage.json").write_text(
        json.dumps(
            {
                "schema_version": 6,
                "driver_mode": "campaign",
                "run_dir": str(campaign),
                "target": "core-stateful",
                "target_bins": semantic_target,
                "covered_target_bins": len(semantic_bins),
                "coverage_rate": (len(semantic_bins) / semantic_target) if semantic_target else 0.0,
                "target_combo_bins": pairwise_target,
                "covered_target_combo_bins": len(pairwise_bins),
                "combo_coverage_rate": (len(pairwise_bins) / pairwise_target) if pairwise_target else 0.0,
                "target_triples": triples_target,
                "covered_target_triples": len(triples_bins),
                "triples_coverage_rate": (len(triples_bins) / triples_target) if triples_target else 0.0,
                "target_predicates": predicates_target,
                "covered_target_predicates": len(predicate_bins),
                "predicate_coverage_rate": (len(predicate_bins) / predicates_target) if predicates_target else 0.0,
                "semantic_bins": list(semantic_bins),
                "pairwise_bins": list(pairwise_bins),
                "security_triples_bins": list(triples_bins),
                "predicate_bins": list(predicate_bins),
                "execution_coverage": {
                    "by_dut": {
                        dut_name: {
                            "semantic": {
                                "covered_target_bins": len(semantic_bins),
                                "total_target_bins": semantic_target,
                                "covered_bins": list(semantic_bins),
                                "target": "core-stateful",
                                "universe_sha256": semantic_hash,
                            },
                            "pairwise": {
                                "covered_target_bins": len(pairwise_bins),
                                "total_target_bins": pairwise_target,
                                "covered_bins": list(pairwise_bins),
                                "target": "core-stateful",
                                "universe_sha256": pairwise_hash,
                            },
                            "security_triples": {
                                "covered_target_bins": len(triples_bins),
                                "total_target_bins": triples_target,
                                "covered_bins": list(triples_bins),
                                "target": "core-stateful",
                                "universe_sha256": triples_hash,
                            },
                            "predicates": {
                                "covered_target_bins": len(predicate_bins),
                                "total_target_bins": predicates_target,
                                "covered_bins": list(predicate_bins),
                                "target": "core-stateful",
                                "universe_sha256": predicates_hash,
                            },
                        }
                    }
                },
            },
            ensure_ascii=True,
        ),
        encoding="ascii",
    )


def _write_bapc_timeline(
    campaign: Path,
    campaign_id: str,
    *,
    dut: str = "rocket-clean",
    seed: int = 101,
    bapc_bins: list[str] | None = None,
    bapc_target: int = 208,
) -> Path:
    metrics = campaign / "metrics"
    metrics.mkdir(parents=True, exist_ok=True)
    bapc_bins = bapc_bins or ["family=config|pmp_mode=off|permission_rwx=000|locked=false"]
    rows = [
        {
            "schema_version": 1,
            "campaign_id": campaign_id,
            "variant": "random",
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
            "bapc_target": bapc_target,
            "bapc_rate": 0.0 if bapc_target > 0 else None,
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
            "campaign_id": campaign_id,
            "variant": "random",
            "dut": dut,
            "seed": seed,
            "completion_seq": 1,
            "case_id": "case-0001",
            "elapsed_wall_seconds": 10.0,
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
            "bapc_covered": len(bapc_bins),
            "bapc_target": bapc_target,
            "bapc_rate": len(bapc_bins) / bapc_target if bapc_target > 0 else None,
            "new_semantic_bins": 0,
            "new_pairwise_bins": 0,
            "new_security_triple_bins": 0,
            "new_predicate_bins": 0,
            "new_bapc_bins": len(bapc_bins),
            "bapc_eligible": True,
            "last_bapc_novelty_time": 10.0,
            "whitebox_distinct_events": 0,
            "new_whitebox_events": 0,
        },
    ]
    path = metrics / "coverage_timeline.jsonl"
    path.write_text(
        "\n".join(json.dumps(row, ensure_ascii=True, sort_keys=True) for row in rows) + "\n",
        encoding="ascii",
    )
    return path


def _write_continuous_bapc_schedule(campaign: Path, *, bapc_bins: list[str]) -> None:
    scenario = ScenarioGenerator(seed=101, include_smepmp=False, profile="pmp-boundary").generate_one(0)
    spec = scenario_to_spec(scenario)
    spec_hash = scenario_hash(spec)
    writer = ScheduleV4Writer(campaign / "metrics" / "schedule_v4.jsonl")
    writer.append(
        "candidate_admitted",
        scenario_hash=spec_hash,
        scenario_spec=spec,
        generation_seq=1,
        parent_hash=None,
        mutation_operator="root",
    )
    writer.append(
        "execution_committed",
        scenario_hash=spec_hash,
        candidate_id=spec_hash,
        case_id="case-0001",
        profile="pmp-boundary",
        status="observed",
        failure_class=None,
        eligible=True,
        qualification_reason="eligible",
        elapsed_wall_seconds=10.0,
        case_elapsed_seconds=2.0,
        execution_cost=2.0,
        new_bins={
            "semantic": [],
            "pairwise": [],
            "security_triples": [],
            "predicates": [],
            "bapc": list(bapc_bins),
        },
        promoted=False,
        evicted_hashes=[],
        retained_without_novelty=False,
        new_whitebox_events=0,
    )


def _write_continuous_bapc_universe_file(campaign: Path, *, dut: str | None = None) -> dict[str, object]:
    coverage_dir = campaign / "coverage"
    coverage_dir.mkdir(parents=True, exist_ok=True)
    if dut is None:
        metadata_path = campaign / "metrics" / "campaign_metadata.json"
        if metadata_path.exists():
            dut = str(json.loads(metadata_path.read_text(encoding="ascii")).get("dut") or "")
    dut = dut or "xiangshan-clean"
    universe = build_bapc_coverage_universe(
        dut=dut,
        generator_seed=1,
        supports_fault_stage=True,
        supports_smepmp=False,
    )
    (coverage_dir / "bapc_v2.json").write_text(
        json.dumps(universe, ensure_ascii=True, sort_keys=True),
        encoding="ascii",
    )
    metadata_path = campaign / "metrics" / "campaign_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="ascii"))
    metadata["driver_mode"] = "continuous"
    metadata["coverage_schema"] = "pmpfuzz-v1-four-mode"
    metadata["schedule_v4"] = "metrics/schedule_v4.jsonl"
    metadata["bapc_schema_version"] = 2
    metadata["bapc_measurement_mode"] = "target-operation"
    metadata["probe_required"] = False
    metadata["instrumented_supplemental_enabled"] = False
    metadata["coverage_universe_hashes"] = {"bapc": str(universe["sha256"])}
    metadata["coverage_universe_files"] = {"bapc": "coverage/bapc_v2.json"}
    metadata_path.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=True),
        encoding="ascii",
    )
    return universe


def _write_continuous_bapc_coverage_json(
    campaign: Path,
    *,
    dut_name: str = "rocket-clean",
    bapc_bins: list[str] | None = None,
    bapc_hash: str = "",
    bapc_target: int = 208,
) -> None:
    bapc_bins = bapc_bins or ["family=config|pmp_mode=off|permission_rwx=000|locked=false"]
    coverage_dir = campaign / "coverage"
    coverage_dir.mkdir(parents=True, exist_ok=True)
    (coverage_dir / "coverage.json").write_text(
        json.dumps(
            {
                "schema_version": 6,
                "driver_mode": "campaign",
                "run_dir": str(campaign),
                "target_bapc_bins": bapc_target,
                "covered_target_bapc_bins": len(bapc_bins),
                "bapc_coverage_rate": (len(bapc_bins) / bapc_target) if bapc_target else 0.0,
                "bapc_bins": list(bapc_bins),
                "execution_coverage": {
                    "by_dut": {
                        dut_name: {
                            "bapc": {
                                "covered_target_bins": len(bapc_bins),
                                "total_target_bins": bapc_target,
                                "covered_bins": list(bapc_bins),
                                "target": "black-box-architectural-pmp-target-operation",
                                "universe_sha256": bapc_hash,
                            }
                        }
                    }
                },
            },
            ensure_ascii=True,
        ),
        encoding="ascii",
    )


def _build_strict_fixture(root: Path) -> Path:
    campaign = _build_minimal_campaign(root)
    case_ids = [f"case-{i:04d}" for i in range(1, 4)]
    _write_timeline(campaign, "e1-rocket-random-0101", case_ids=case_ids)
    _write_metadata(campaign, "e1-rocket-random-0101", run_class="pilot")
    _write_cases_and_results(campaign, case_ids)
    _write_child_round(campaign, "round_0000", [f"child-case-{i:04d}" for i in range(1, 3)])
    _write_child_round(campaign, "round_0001", [f"child-case-{i:04d}" for i in range(3, 5)])
    artifact_root = _artifact_root_from_campaign(campaign)


    tl_path = campaign / "metrics" / "coverage_timeline.jsonl"
    tl_bytes = tl_path.read_bytes()
    tl_rel = ("campaigns/E1-COVERAGE-FEEDBACK/rocket-clean/random/semantic/"
              "seed-0101/metrics/coverage_timeline.jsonl")
    _write_manifests(artifact_root, include_artifact_sha=True,
                     artifact_sha_files=[(tl_rel, tl_bytes.decode("ascii"))])
    return campaign





class TestStrictValidFixture(unittest.TestCase):

    def test_strict_complete_fixture_is_valid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_strict_fixture(root)
            report = validate_timeline(campaign)
            self.assertTrue(report["valid"],
                            f"strict complete fixture should be valid, got checks: {report['checks']}")
            self.assertEqual(report["error_count"], 0)


class TestStrictMissingMetadata(unittest.TestCase):

    def test_strict_missing_metadata_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_cases_and_results(campaign, case_ids)

            report = validate_timeline(campaign)



            self.assertFalse(report["valid"],
                             "strict campaign missing metadata must be invalid")
            meta_check = [c for c in report["checks"] if c["name"] == "metadata_exists"]
            self.assertTrue(len(meta_check) > 0, "should have metadata_exists check")
            self.assertFalse(meta_check[0]["passed"],
                             "metadata_exists must fail for missing metadata")


class TestStrictMissingTimeline(unittest.TestCase):

    def test_strict_missing_timeline_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            _write_metadata(campaign, "test-campaign", run_class="pilot")

            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "strict campaign missing timeline must be invalid")


class TestStrictMissingChildTimeline(unittest.TestCase):

    def test_strict_missing_child_timeline_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)

            rd = campaign / "rounds" / "round_0000"
            rd.mkdir(parents=True)
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "missing child round timeline must be error, not warning")
            round_checks = [c for c in report["checks"]
                            if c["name"].startswith("round_timeline")]
            self.assertTrue(len(round_checks) > 0, "should have round timeline checks")
            for rc in round_checks:
                self.assertFalse(rc["passed"], f"round timeline check {rc['name']} should fail")
                self.assertEqual(rc["severity"], "error",
                                 f"missing child timeline severity must be error, got {rc['severity']}")


class TestCorruptChildTimeline(unittest.TestCase):

    def test_corrupt_child_timeline_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)

            rd = campaign / "rounds" / "round_0000"
            rd_metrics = rd / "metrics"
            rd_metrics.mkdir(parents=True)
            (rd_metrics / "coverage_timeline.jsonl").write_text(
                '{"valid": "json"}\nNOT JSON HERE\n', encoding="ascii")
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "corrupted child timeline JSON must be invalid")


class TestCompletionSeqErrors(unittest.TestCase):

    def test_completion_seq_gap_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002", "case-0003"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids,
                            completion_seqs=[0, 1, 3, 4])
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "completion_seq gap must be invalid")

    def test_completion_seq_duplicate_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002", "case-0003"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids,
                            completion_seqs=[0, 1, 1, 2])
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "completion_seq duplicate must be invalid")

    def test_completion_seq_not_starting_at_zero_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids,
                            completion_seqs=[1, 2, 3])
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "completion_seq without baseline 0 must be invalid")


class TestWallTimeRegression(unittest.TestCase):

    def test_wall_time_regression_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002", "case-0003"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids,
                            wall_times=[0.0, 30.0, 10.0, 20.0])
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "wall time regression must be invalid")


class TestMissingRawCase(unittest.TestCase):

    def test_missing_raw_case_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")

            _write_case(campaign, "case-0001")
            _write_result(campaign, "case-0001")
            _write_result(campaign, "case-0002")
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "missing raw case.json must be invalid")


class TestMissingRawResult(unittest.TestCase):

    def test_missing_raw_result_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_case(campaign, "case-0001")
            _write_result(campaign, "case-0001")
            _write_case(campaign, "case-0002")
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "missing raw result.json must be invalid")


class TestDuplicateResult(unittest.TestCase):

    def test_duplicate_result_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_case(campaign, "case-0001")
            _write_result(campaign, "case-0001")

            d = campaign / "results" / "case-0001"
            (d / "result-2.json").write_text(json.dumps({
                "name": "case-0001", "status": "fail",
                "dut": "rocket-clean",
            }), encoding="ascii")
            _write_case(campaign, "case-0002")
            _write_result(campaign, "case-0002")
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "duplicate results for same case must be invalid")


class TestOrphanResultCase(unittest.TestCase):

    def test_orphan_case_file_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_case(campaign, "case-0001")
            _write_result(campaign, "case-0001")

            _write_case(campaign, "orphan-case")
            _write_result(campaign, "orphan-case")
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "orphan case/result not in timeline must be invalid")

    def test_orphan_result_file_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_case(campaign, "case-0001")
            _write_result(campaign, "case-0001")

            d = campaign / "results" / "orphan-result"
            d.mkdir(parents=True)
            (d / "result.json").write_text(json.dumps({
                "name": "orphan-result", "status": "pass", "dut": "rocket-clean",
            }), encoding="ascii")
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "orphan result not in timeline must be invalid")


class TestMetadataIdentityMismatch(unittest.TestCase):

    def test_metadata_campaign_id_mismatch_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002"]
            _write_timeline(campaign, "correct-campaign-id", case_ids=case_ids)
            _write_metadata(campaign, "wrong-campaign-id", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "metadata campaign_id mismatch must be invalid")

    def test_metadata_dut_mismatch_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root, dut="boom-clean")
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", dut="rocket-clean", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot",
                            dut="boom-clean")
            _write_cases_and_results(campaign, case_ids)
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "metadata DUT mismatch must be invalid")

    def test_metadata_seed_mismatch_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", seed=101, case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot", seed=202)
            _write_cases_and_results(campaign, case_ids)
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "metadata seed mismatch must be invalid")


class TestStrictEnvironmentManifest(unittest.TestCase):

    def test_strict_missing_environment_json_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)

            artifact_root = _artifact_root_from_campaign(campaign)
            _write_manifests(artifact_root, include_environment=False)
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "strict missing environment.json must be invalid")


class TestStrictGitShasManifest(unittest.TestCase):

    def test_strict_missing_git_shas_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)
            _write_manifests(artifact_root, include_git_shas=False)
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "strict missing git-shas.txt must be invalid")


class TestStrictMissingDutSha(unittest.TestCase):

    def test_strict_missing_source_sha_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot",
                            source_sha="", dut_sha="b" * 40,
                            dut_binary_sha256="c" * 64, capability_fingerprint="d" * 64)
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)
            _write_manifests(artifact_root)
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "strict missing source_sha must be invalid")

    def test_strict_missing_dut_binary_sha_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot",
                            source_sha="a" * 40, dut_sha="b" * 40,
                            dut_binary_sha256="", capability_fingerprint="d" * 64)
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)
            _write_manifests(artifact_root)
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "strict missing DUT binary SHA must be invalid")

    def test_strict_missing_capability_fingerprint_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot",
                            source_sha="a" * 40, dut_sha="b" * 40,
                            dut_binary_sha256="c" * 64, capability_fingerprint="")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)
            _write_manifests(artifact_root)
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "strict missing capability_fingerprint must be invalid")

    def test_strict_unknown_run_class_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="fomral")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)
            _write_manifests(artifact_root)
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "unknown non-empty run_class must be invalid")
            self.assertTrue(any(check["name"] == "run_class_known" and not check["passed"]
                                for check in report["checks"]))

    def test_strict_dut_binary_hash_must_match_file(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)
            _write_manifests(artifact_root)
            meta_path = campaign / "metrics" / "campaign_metadata.json"
            meta = json.loads(meta_path.read_text(encoding="ascii"))
            Path(meta["dut_binary_path"]).write_bytes(b"tampered-dut\n")
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "strict DUT binary hash mismatch must be invalid")
            self.assertTrue(any(check["name"] == "dut_binary_sha256_matches_file" and not check["passed"]
                                for check in report["checks"]))


class TestStrictMissingArtifactShaManifest(unittest.TestCase):

    def test_strict_missing_artifact_sha_manifest_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)
            _write_manifests(artifact_root, include_artifact_sha=False)
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "strict missing artifact-sha256.txt must be invalid")


class TestArtifactHashManifestIntegrity(unittest.TestCase):

    def test_artifact_sha_missing_file_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)

            tl_rel = ("campaigns/E1-COVERAGE-FEEDBACK/rocket-clean/random/semantic/"
                      "seed-0101/metrics/coverage_timeline.jsonl")
            tl_content = (campaign / "metrics" / "coverage_timeline.jsonl").read_text(encoding="ascii")
            _write_manifests(artifact_root, include_artifact_sha=True,
                             artifact_sha_files=[
                                 (tl_rel, tl_content),
                                 ("path/to/nonexistent/file.txt", "ghost content"),
                             ])
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "artifact SHA manifest with missing file must be invalid")

    def test_artifact_sha_mismatch_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)

            tl_rel = ("campaigns/E1-COVERAGE-FEEDBACK/rocket-clean/random/semantic/"
                      "seed-0101/metrics/coverage_timeline.jsonl")
            wrong_hash = "0" * 64
            manifests_dir = artifact_root / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            (manifests_dir / "environment.json").write_text('{"test": true}', encoding="ascii")
            (manifests_dir / "git-shas.txt").write_text("abc  repo\n", encoding="ascii")
            (manifests_dir / "artifact-sha256.txt").write_text(
                f"{wrong_hash}  {tl_rel}\n", encoding="ascii")
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "artifact SHA mismatch must be invalid")


class TestDevelopmentSmokeRules(unittest.TestCase):

    def test_dev_smoke_without_provenance_is_valid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="development-smoke")
            _write_cases_and_results(campaign, case_ids)

            report = validate_timeline(campaign)
            self.assertTrue(report["valid"],
                            f"dev-smoke without manifests should be valid, got: {report['checks']}")

    def test_dev_smoke_missing_raw_case_still_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="development-smoke")

            _write_case(campaign, "case-0001")
            _write_result(campaign, "case-0001")
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "dev-smoke missing raw case must still be invalid")

    def test_dev_smoke_missing_timeline_still_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            _write_metadata(campaign, "test-campaign", run_class="development-smoke")

            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "dev-smoke missing timeline must still be invalid")


class TestCLIExitCodes(unittest.TestCase):

    def test_cli_valid_returns_zero(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_strict_fixture(root)
            rc = main(["--campaign", str(campaign)])
            self.assertEqual(rc, 0, "CLI must return 0 for valid campaign")

    def test_cli_invalid_returns_nonzero(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)

            _write_metadata(campaign, "test-campaign", run_class="pilot")
            rc = main(["--campaign", str(campaign)])
            self.assertNotEqual(rc, 0, "CLI must return non-zero for invalid campaign")




class TestArtifactManifestNonempty(unittest.TestCase):

    def test_empty_manifest_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)

            _write_manifests(artifact_root, include_artifact_sha=True,
                             artifact_sha_files=[])
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "empty artifact-sha256.txt must be invalid "
                             "for strict campaign")
            nonempty = [c for c in report["checks"]
                        if c["name"] == "artifact_sha_manifest_nonempty"]
            self.assertTrue(len(nonempty) > 0,
                            "must have artifact_sha_manifest_nonempty check")
            self.assertFalse(nonempty[0]["passed"],
                             "nonempty check must fail for empty manifest")
            self.assertEqual(nonempty[0]["severity"], "error")

    def test_blank_only_manifest_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001", "case-0002"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)
            _write_manifests(artifact_root, include_artifact_sha=True,
                             artifact_sha_files=[])

            mf = artifact_root / "manifests" / "artifact-sha256.txt"
            mf.write_text("\n   \n\t\t\n\n", encoding="ascii")
            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "blank-only manifest must be invalid")
            nonempty = [c for c in report["checks"]
                        if c["name"] == "artifact_sha_manifest_nonempty"]
            self.assertTrue(len(nonempty) > 0)
            self.assertFalse(nonempty[0]["passed"])
            self.assertEqual(nonempty[0]["severity"], "error")


class TestArtifactManifestPathEscape(unittest.TestCase):

    def test_relative_path_escape_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)



            artifact_root = root / "campaigns" / "E1-COVERAGE-FEEDBACK"
            mdir = artifact_root / "manifests"
            mdir.mkdir(parents=True, exist_ok=True)
            (mdir / "environment.json").write_text(
                '{"test": true}', encoding="ascii")
            (mdir / "git-shas.txt").write_text(
                "abc  repo\n", encoding="ascii")


            escape_file = root / "outside.txt"
            content = "escaped-via-dotdot"
            escape_file.write_text(content, encoding="ascii")
            h = hashlib.sha256(content.encode("ascii")).hexdigest()

            rel = "../../../outside.txt"
            (mdir / "artifact-sha256.txt").write_text(
                f"{h}  {rel}\n", encoding="ascii")

            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "path escape via ../ must be invalid "
                             "even with correct hash")
            esc = [c for c in report["checks"]
                   if c["name"] == "artifact_sha_manifest_entry_escape"]
            self.assertTrue(len(esc) > 0,
                            "must have artifact_sha_manifest_entry_escape check")
            self.assertFalse(esc[0]["passed"])
            self.assertEqual(esc[0]["severity"], "error")


class TestArtifactManifestMultiLevelEscape(unittest.TestCase):

    def test_multilevel_path_escape_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)

            artifact_root = root / "campaigns" / "E1-COVERAGE-FEEDBACK"
            mdir = artifact_root / "manifests"
            mdir.mkdir(parents=True, exist_ok=True)
            (mdir / "environment.json").write_text(
                '{"test": true}', encoding="ascii")
            (mdir / "git-shas.txt").write_text(
                "abc  repo\n", encoding="ascii")


            escape_file = root / "campaigns" / "outside.txt"
            escape_file.parent.mkdir(parents=True, exist_ok=True)
            content = "escaped-via-multilevel"
            escape_file.write_text(content, encoding="ascii")
            h = hashlib.sha256(content.encode("ascii")).hexdigest()




            rel = "campaigns/E1-COVERAGE-FEEDBACK/../../../outside.txt"
            (mdir / "artifact-sha256.txt").write_text(
                f"{h}  {rel}\n", encoding="ascii")

            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "multi-level path escape must be invalid")
            esc = [c for c in report["checks"]
                   if c["name"] == "artifact_sha_manifest_entry_escape"]
            self.assertTrue(len(esc) > 0,
                            "must have artifact_sha_manifest_entry_escape check")
            self.assertFalse(esc[0]["passed"])
            self.assertEqual(esc[0]["severity"], "error")


class TestArtifactManifestAbsolutePath(unittest.TestCase):

    def test_absolute_path_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)
            _write_manifests(artifact_root, include_artifact_sha=False)

            abs_file = root / "outside_abs.txt"
            content = "absolute-path-escape"
            abs_file.write_text(content, encoding="ascii")
            h = hashlib.sha256(content.encode("ascii")).hexdigest()


            abs_path_str = str(abs_file.resolve())
            mdir = artifact_root / "manifests"
            (mdir / "artifact-sha256.txt").write_text(
                f"{h}  {abs_path_str}\n", encoding="ascii")

            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "absolute path entry must be invalid "
                             "even with correct hash")
            chk = [c for c in report["checks"]
                   if c["name"] == "artifact_sha_manifest_entry_absolute"]
            self.assertTrue(len(chk) > 0,
                            "must have artifact_sha_manifest_entry_absolute check")
            self.assertFalse(chk[0]["passed"])
            self.assertEqual(chk[0]["severity"], "error")


class TestArtifactManifestSelfReference(unittest.TestCase):

    def test_self_reference_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)
            _write_manifests(artifact_root, include_artifact_sha=False)

            mdir = artifact_root / "manifests"
            (mdir / "artifact-sha256.txt").write_text(
                f"{'a' * 64}  manifests/artifact-sha256.txt\n",
                encoding="ascii")

            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "manifest self-reference must be invalid")
            chk = [c for c in report["checks"]
                   if c["name"] == "artifact_sha_manifest_entry_self_ref"]
            self.assertTrue(len(chk) > 0,
                            "must have artifact_sha_manifest_entry_self_ref check")
            self.assertFalse(chk[0]["passed"])
            self.assertEqual(chk[0]["severity"], "error")


class TestArtifactManifestDirectoryTarget(unittest.TestCase):

    def test_directory_target_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)
            _write_manifests(artifact_root, include_artifact_sha=False)


            (artifact_root / "some_directory").mkdir(parents=True, exist_ok=True)
            mdir = artifact_root / "manifests"
            (mdir / "artifact-sha256.txt").write_text(
                f"{'b' * 64}  some_directory\n", encoding="ascii")

            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "directory target must be invalid")
            chk = [c for c in report["checks"]
                   if c["name"] == "artifact_sha_manifest_entry_not_file"]
            self.assertTrue(len(chk) > 0,
                            "must have artifact_sha_manifest_entry_not_file check")
            self.assertFalse(chk[0]["passed"])
            self.assertEqual(chk[0]["severity"], "error")


class TestArtifactManifestDuplicateEntry(unittest.TestCase):

    def test_duplicate_entry_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)
            _write_manifests(artifact_root, include_artifact_sha=False)


            dup_file = artifact_root / "dup_target.txt"
            content = "duplicate entry test"
            dup_file.write_text(content, encoding="ascii")
            h = hashlib.sha256(content.encode("ascii")).hexdigest()

            mdir = artifact_root / "manifests"
            (mdir / "artifact-sha256.txt").write_text(
                f"{h}  dup_target.txt\n"
                f"{h}  dup_target.txt\n",
                encoding="ascii")

            report = validate_timeline(campaign)
            self.assertFalse(report["valid"],
                             "duplicate manifest entry must be invalid "
                             "even when hash is correct")
            chk = [c for c in report["checks"]
                   if c["name"] == "artifact_sha_manifest_entry_duplicate"]
            self.assertTrue(len(chk) > 0,
                            "must have artifact_sha_manifest_entry_duplicate check")
            self.assertFalse(chk[0]["passed"])
            self.assertEqual(chk[0]["severity"], "error")


class TestArtifactManifestValidEntry(unittest.TestCase):

    def test_valid_entry_passes(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)



            tl_path = campaign / "metrics" / "coverage_timeline.jsonl"
            tl_bytes = tl_path.read_bytes()
            tl_hash = hashlib.sha256(tl_bytes).hexdigest()
            tl_rel = ("campaigns/E1-COVERAGE-FEEDBACK/rocket-clean/random/"
                      "semantic/seed-0101/metrics/coverage_timeline.jsonl")
            _write_manifests(artifact_root, include_artifact_sha=False)
            mdir = artifact_root / "manifests"
            (mdir / "artifact-sha256.txt").write_text(
                f"{tl_hash}  {tl_rel}\n", encoding="ascii")
            report = validate_timeline(campaign)
            self.assertTrue(report["valid"],
                            f"valid manifest entry must pass, got: "
                            f"{[c['name'] for c in report['checks'] if not c['passed']]}")
            integrity = [c for c in report["checks"]
                         if c["name"] == "artifact_sha_manifest_integrity"]
            self.assertTrue(len(integrity) > 0,
                            "must have integrity success check")
            self.assertTrue(integrity[0]["passed"])


class TestArtifactManifestMutableAggregateEntries(unittest.TestCase):

    def test_mutable_normalized_hash_drift_is_tolerated(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)

            normalized_dir = artifact_root / "normalized"
            normalized_dir.mkdir(parents=True, exist_ok=True)
            campaigns_csv = normalized_dir / "campaigns.csv"
            coverage_csv = normalized_dir / "coverage_timeseries.csv"
            campaigns_csv.write_text("campaign_id\nfinished-campaign\n", encoding="ascii")
            coverage_csv.write_text(
                "campaign_id,completion_seq\nfinished-campaign,1\n",
                encoding="ascii",
            )

            tl_path = campaign / "metrics" / "coverage_timeline.jsonl"
            tl_hash = hashlib.sha256(tl_path.read_bytes()).hexdigest()
            tl_rel = ("campaigns/E1-COVERAGE-FEEDBACK/rocket-clean/random/"
                      "semantic/seed-0101/metrics/coverage_timeline.jsonl")
            _write_manifests(artifact_root, include_artifact_sha=False)
            mdir = artifact_root / "manifests"
            (mdir / "artifact-sha256.txt").write_text(
                "\n".join(
                    [
                        f"{tl_hash}  {tl_rel}",
                        f"{'0' * 64}  normalized/campaigns.csv",
                        f"{'f' * 64}  normalized/coverage_timeseries.csv",
                    ]
                ) + "\n",
                encoding="ascii",
            )

            report = validate_timeline(campaign)
            self.assertTrue(report["valid"], report)
            integrity = [
                c for c in report["checks"]
                if c["name"] == "artifact_sha_manifest_integrity"
            ]
            self.assertTrue(len(integrity) > 0, report["checks"])
            self.assertTrue(integrity[0]["passed"])
            self.assertIn("mutable aggregate hash drift", integrity[0]["detail"])
            hash_match = [
                c for c in report["checks"]
                if c["name"] == "artifact_sha_manifest_hash_match"
            ]
            self.assertEqual(hash_match, [], report["checks"])


class TestArtifactManifestRegeneratedValidationEntries(unittest.TestCase):

    def test_regenerated_validation_hash_drift_is_tolerated(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            artifact_root = _artifact_root_from_campaign(campaign)

            validation_path = campaign / "validation.json"
            validation_path.write_text(
                json.dumps({"valid": True, "checks": []}, indent=2) + "\n",
                encoding="utf-8",
            )
            validation_rel = ("campaigns/E1-COVERAGE-FEEDBACK/rocket-clean/random/"
                              "semantic/seed-0101/validation.json")
            tl_path = campaign / "metrics" / "coverage_timeline.jsonl"
            tl_hash = hashlib.sha256(tl_path.read_bytes()).hexdigest()
            tl_rel = ("campaigns/E1-COVERAGE-FEEDBACK/rocket-clean/random/"
                      "semantic/seed-0101/metrics/coverage_timeline.jsonl")
            _write_manifests(artifact_root, include_artifact_sha=False)
            mdir = artifact_root / "manifests"
            (mdir / "artifact-sha256.txt").write_text(
                "\n".join(
                    [
                        f"{tl_hash}  {tl_rel}",
                        f"{'a' * 64}  {validation_rel}",
                    ]
                ) + "\n",
                encoding="ascii",
            )

            report = validate_timeline(campaign)
            self.assertTrue(report["valid"], report)
            integrity = [
                c for c in report["checks"]
                if c["name"] == "artifact_sha_manifest_integrity"
            ]
            self.assertTrue(len(integrity) > 0, report["checks"])
            self.assertTrue(integrity[0]["passed"])
            self.assertIn(
                "regenerated validation report hash drift",
                integrity[0]["detail"],
            )
            hash_match = [
                c for c in report["checks"]
                if c["name"] == "artifact_sha_manifest_hash_match"
            ]
            self.assertEqual(hash_match, [], report["checks"])


class TestCoverageJsonContract(unittest.TestCase):
    def test_campaign_schema6_coverage_mismatch_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            coverage_dir = campaign / "coverage"
            coverage_dir.mkdir(parents=True, exist_ok=True)
            (coverage_dir / "coverage.json").write_text(
                json.dumps(
                    {
                        "schema_version": 6,
                        "driver_mode": "campaign",
                        "run_dir": str(campaign),
                        "target": "core-stateful",
                        "target_bins": 10,
                        "covered_target_bins": 999,
                        "coverage_rate": 99.9,
                        "target_combo_bins": 5,
                        "covered_target_combo_bins": 0,
                        "combo_coverage_rate": 0.0,
                        "target_triples": 3,
                        "covered_target_triples": 0,
                        "triples_coverage_rate": 0.0,
                        "target_predicates": 2,
                        "covered_target_predicates": 0,
                        "predicate_coverage_rate": 0.0,
                        "semantic_bins": [],
                        "pairwise_bins": [],
                        "security_triples_bins": [],
                        "predicate_bins": [],
                    },
                    ensure_ascii=True,
                ),
                encoding="ascii",
            )

            report = validate_timeline(campaign)

        self.assertFalse(report["valid"])
        mismatch = [c for c in report["checks"] if c["name"] == "final_semantic_matches_coverage"]
        self.assertTrue(mismatch)
        self.assertFalse(mismatch[0]["passed"])


class TestContinuousCoverageAndScheduleContract(unittest.TestCase):
    def test_continuous_corrupt_coverage_json_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            _write_continuous_schedule(campaign, semantic_bins=["sem:0", "sem:1"])
            _mark_metadata_continuous(campaign)
            _write_manifests(_artifact_root_from_campaign(campaign))
            coverage_dir = campaign / "coverage"
            coverage_dir.mkdir(parents=True, exist_ok=True)
            (coverage_dir / "coverage.json").write_text("{not-json", encoding="ascii")

            report = validate_timeline(campaign)

        self.assertFalse(report["valid"])
        checks = [c for c in report["checks"] if c["name"] == "coverage_json_readable"]
        self.assertTrue(checks)
        self.assertFalse(checks[0]["passed"])
        self.assertEqual(checks[0]["severity"], "error")

    def test_continuous_missing_coverage_mode_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            _write_continuous_schedule(campaign, semantic_bins=["sem:0", "sem:1"])
            _mark_metadata_continuous(campaign)
            _write_manifests(_artifact_root_from_campaign(campaign))
            coverage_dir = campaign / "coverage"
            coverage_dir.mkdir(parents=True, exist_ok=True)
            (coverage_dir / "coverage.json").write_text(
                json.dumps(
                    {
                        "schema_version": 6,
                        "driver_mode": "campaign",
                        "run_dir": str(campaign),
                        "target": "core-stateful",
                        "target_bins": 10,
                        "covered_target_bins": 2,
                        "coverage_rate": 0.2,
                        "target_combo_bins": 5,
                        "covered_target_combo_bins": 0,
                        "combo_coverage_rate": 0.0,
                        "target_triples": 3,
                        "covered_target_triples": 0,
                        "triples_coverage_rate": 0.0,
                        "target_predicates": 2,
                        "covered_target_predicates": 0,
                        "predicate_coverage_rate": 0.0,
                        "semantic_bins": ["sem:0", "sem:1"],
                        "pairwise_bins": [],
                        "security_triples_bins": [],
                        "predicate_bins": [],
                        "execution_coverage": {
                            "by_dut": {
                                "rocket-clean": {
                                    "semantic": {
                                        "covered_target_bins": 2,
                                        "total_target_bins": 10,
                                        "covered_bins": ["sem:0", "sem:1"],
                                        "target": "core-stateful",
                                        "universe_sha256": "1" * 64,
                                    },
                                    "pairwise": {
                                        "covered_target_bins": 0,
                                        "total_target_bins": 5,
                                        "covered_bins": [],
                                        "target": "core-stateful",
                                        "universe_sha256": "2" * 64,
                                    },
                                    "security_triples": {
                                        "covered_target_bins": 0,
                                        "total_target_bins": 3,
                                        "covered_bins": [],
                                        "target": "core-stateful",
                                        "universe_sha256": "3" * 64,
                                    },
                                }
                            }
                        },
                    },
                    ensure_ascii=True,
                ),
                encoding="ascii",
            )

            report = validate_timeline(campaign)

        self.assertFalse(report["valid"])
        checks = [c for c in report["checks"] if c["name"] == "coverage_modes_complete"]
        self.assertTrue(checks)
        self.assertFalse(checks[0]["passed"])

    def test_continuous_schedule_v4_mismatch_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            _write_continuous_schedule(campaign, semantic_bins=["sem:0"])
            _mark_metadata_continuous(campaign)
            _write_manifests(_artifact_root_from_campaign(campaign))
            coverage_dir = campaign / "coverage"
            coverage_dir.mkdir(parents=True, exist_ok=True)
            (coverage_dir / "coverage.json").write_text(
                json.dumps(
                    {
                        "schema_version": 6,
                        "driver_mode": "campaign",
                        "run_dir": str(campaign),
                        "target": "core-stateful",
                        "target_bins": 10,
                        "covered_target_bins": 2,
                        "coverage_rate": 0.2,
                        "target_combo_bins": 5,
                        "covered_target_combo_bins": 0,
                        "combo_coverage_rate": 0.0,
                        "target_triples": 3,
                        "covered_target_triples": 0,
                        "triples_coverage_rate": 0.0,
                        "target_predicates": 2,
                        "covered_target_predicates": 0,
                        "predicate_coverage_rate": 0.0,
                        "semantic_bins": ["sem:0", "sem:1"],
                        "pairwise_bins": [],
                        "security_triples_bins": [],
                        "predicate_bins": [],
                        "execution_coverage": {
                            "by_dut": {
                                "rocket-clean": {
                                    "semantic": {
                                        "covered_target_bins": 2,
                                        "total_target_bins": 10,
                                        "covered_bins": ["sem:0", "sem:1"],
                                        "target": "core-stateful",
                                        "universe_sha256": "1" * 64,
                                    },
                                    "pairwise": {
                                        "covered_target_bins": 0,
                                        "total_target_bins": 5,
                                        "covered_bins": [],
                                        "target": "core-stateful",
                                        "universe_sha256": "2" * 64,
                                    },
                                    "security_triples": {
                                        "covered_target_bins": 0,
                                        "total_target_bins": 3,
                                        "covered_bins": [],
                                        "target": "core-stateful",
                                        "universe_sha256": "3" * 64,
                                    },
                                    "predicates": {
                                        "covered_target_bins": 0,
                                        "total_target_bins": 2,
                                        "covered_bins": [],
                                        "target": "core-stateful",
                                        "universe_sha256": "4" * 64,
                                    },
                                }
                            }
                        },
                    },
                    ensure_ascii=True,
                ),
                encoding="ascii",
            )

            report = validate_timeline(campaign)

        self.assertFalse(report["valid"])
        checks = [c for c in report["checks"] if c["name"] == "schedule_v4_semantic_matches_timeline"]
        self.assertTrue(checks)
        self.assertFalse(checks[0]["passed"])

    def test_continuous_missing_coverage_universe_hash_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            _write_continuous_schedule(campaign, semantic_bins=["sem:0", "sem:1"])
            _mark_metadata_continuous(campaign)
            universes = _write_continuous_universe_files(campaign)
            _write_manifests(_artifact_root_from_campaign(campaign))
            _write_continuous_coverage_json(
                campaign,
                semantic_hash="",
                pairwise_hash=str(universes["pairwise"]["sha256"]),
                triples_hash=str(universes["security_triples"]["sha256"]),
                predicates_hash=str(universes["predicates"]["sha256"]),
                semantic_target=10,
            )

            report = validate_timeline(campaign)

        self.assertFalse(report["valid"])
        checks = [c for c in report["checks"] if c["name"] == "coverage_universe_sha_semantic"]
        self.assertTrue(checks)
        self.assertFalse(checks[0]["passed"])

    def test_continuous_target_must_match_universe_bin_count(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            _write_continuous_schedule(campaign, semantic_bins=["sem:0", "sem:1"])
            _mark_metadata_continuous(campaign)
            universes = _write_continuous_universe_files(campaign)
            _write_manifests(_artifact_root_from_campaign(campaign))
            _write_continuous_coverage_json(
                campaign,
                semantic_hash=str(universes["semantic"]["sha256"]),
                pairwise_hash=str(universes["pairwise"]["sha256"]),
                triples_hash=str(universes["security_triples"]["sha256"]),
                predicates_hash=str(universes["predicates"]["sha256"]),
                semantic_target=11,
            )

            report = validate_timeline(campaign)

        self.assertFalse(report["valid"])
        checks = [c for c in report["checks"] if c["name"] == "coverage_universe_target_semantic"]
        self.assertTrue(checks)
        self.assertFalse(checks[0]["passed"])

    def test_continuous_bapc_target_must_match_v2_denominator(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root, coverage_mode="bapc")
            _write_bapc_timeline(campaign, "test-bapc-campaign", bapc_target=220)
            _write_metadata(campaign, "test-bapc-campaign", run_class="pilot", coverage_mode="bapc")
            _write_case(campaign, "case-0001")
            _write_result(campaign, "case-0001", status="observed")
            universe = _write_continuous_bapc_universe_file(campaign)
            bapc_bins = [str(universe["bin_ids"][0])]
            _write_continuous_bapc_schedule(campaign, bapc_bins=bapc_bins)
            _write_manifests(_artifact_root_from_campaign(campaign))
            _write_continuous_bapc_coverage_json(
                campaign,
                bapc_bins=bapc_bins,
                bapc_hash=str(universe["sha256"]),
                bapc_target=220,
            )

            report = validate_timeline(campaign)

        self.assertFalse(report["valid"])
        checks = [c for c in report["checks"] if c["name"] == "coverage_universe_target_bapc"]
        self.assertTrue(checks)
        self.assertFalse(checks[0]["passed"])

    def test_continuous_schedule_bins_must_belong_to_universe(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            _write_continuous_schedule(campaign, semantic_bins=["sem:0", "sem:999"])
            _mark_metadata_continuous(campaign)
            universes = _write_continuous_universe_files(campaign)
            _write_manifests(_artifact_root_from_campaign(campaign))
            _write_continuous_coverage_json(
                campaign,
                semantic_bins=["sem:0", "sem:999"],
                semantic_hash=str(universes["semantic"]["sha256"]),
                pairwise_hash=str(universes["pairwise"]["sha256"]),
                triples_hash=str(universes["security_triples"]["sha256"]),
                predicates_hash=str(universes["predicates"]["sha256"]),
                semantic_target=10,
            )

            report = validate_timeline(campaign)

        self.assertFalse(report["valid"])
        checks = [c for c in report["checks"] if c["name"] == "coverage_universe_membership_semantic"]
        self.assertTrue(checks)
        self.assertFalse(checks[0]["passed"])

    def test_continuous_by_dut_must_match_metadata_dut(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(campaign, "test-campaign", case_ids=case_ids)
            _write_metadata(campaign, "test-campaign", run_class="pilot")
            _write_cases_and_results(campaign, case_ids)
            _write_continuous_schedule(campaign, semantic_bins=["sem:0", "sem:1"])
            _mark_metadata_continuous(campaign)
            universes = _write_continuous_universe_files(campaign)
            _write_manifests(_artifact_root_from_campaign(campaign))
            _write_continuous_coverage_json(
                campaign,
                dut_name="boom-clean",
                semantic_hash=str(universes["semantic"]["sha256"]),
                pairwise_hash=str(universes["pairwise"]["sha256"]),
                triples_hash=str(universes["security_triples"]["sha256"]),
                predicates_hash=str(universes["predicates"]["sha256"]),
                semantic_target=10,
            )

            report = validate_timeline(campaign)

        self.assertFalse(report["valid"])
        checks = [c for c in report["checks"] if c["name"] == "coverage_by_dut_matches_metadata"]
        self.assertTrue(checks)
        self.assertFalse(checks[0]["passed"])


class TestStopReasonValidationContract(unittest.TestCase):
    def test_validation_report_records_stop_reason(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_strict_fixture(root)
            metadata_path = campaign / "metrics" / "campaign_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
            metadata["stop_reason"] = "coverage_converged"
            metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="ascii")

            report = validate_timeline(campaign)

        self.assertTrue(report["valid"], report)
        self.assertEqual(report.get("stop_reason"), "coverage_converged")

    def test_formal_legacy_hard_cap_stop_reason_is_invalid(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root)
            case_ids = ["case-0001"]
            _write_timeline(
                campaign,
                "test-campaign",
                case_ids=case_ids,
                variant="random-fresh",
            )
            _write_metadata(
                campaign,
                "test-campaign",
                variant="random-fresh",
                run_class="formal",
            )
            _write_cases_and_results(campaign, case_ids)
            _write_continuous_schedule(campaign, semantic_bins=["sem:0", "sem:1"])
            _mark_metadata_continuous(campaign)
            universes = _write_continuous_universe_files(campaign)
            _write_continuous_coverage_json(
                campaign,
                semantic_bins=["sem:0", "sem:1"],
                semantic_hash=str(universes["semantic"]["sha256"]),
                pairwise_hash=str(universes["pairwise"]["sha256"]),
                triples_hash=str(universes["security_triples"]["sha256"]),
                predicates_hash=str(universes["predicates"]["sha256"]),
                semantic_target=10,
            )
            writer = ScheduleV4Writer(campaign / "metrics" / "schedule_v4.jsonl")
            for event_name in ("stop_latched", "checkpoint", "campaign_closed"):
                writer.append(
                    event_name,
                    round_idx=0,
                    pending_count=0,
                    corpus_count=0,
                    completed_cases=1,
                    eligible_cases=1,
                    stop_reason="right_censored_not_converged",
                )
            metadata_path = campaign / "metrics" / "campaign_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
            metadata["stop_reason"] = "right_censored_not_converged"
            metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="ascii")
            timeline_path = campaign / "metrics" / "coverage_timeline.jsonl"
            timeline_text = timeline_path.read_bytes().decode("ascii")
            timeline_rel = str(timeline_path.relative_to(_artifact_root_from_campaign(campaign))).replace("\\", "/")
            _write_manifests(
                _artifact_root_from_campaign(campaign),
                artifact_sha_files=[
                    (
                        timeline_rel,
                        timeline_text,
                    )
                ],
            )

            report = validate_timeline(campaign)

        self.assertFalse(report["valid"])
        checks = [c for c in report["checks"] if c["name"] == "formal_stop_reason_legacy_name_rejected"]
        self.assertTrue(checks, report)
        self.assertFalse(checks[0]["passed"], report)

    def test_formal_bapc_contract_requires_protocol_id(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root, coverage_mode="bapc")
            _write_bapc_timeline(campaign, "formal-bapc", dut="boom-clean")
            _write_metadata(campaign, "formal-bapc", run_class="formal", coverage_mode="bapc", variant="random-mutation")
            _write_cases_and_results(campaign, ["case-0001"])
            universe = _write_continuous_bapc_universe_file(campaign)
            bapc_bins = [str(universe["bin_ids"][0])]
            _write_continuous_bapc_schedule(campaign, bapc_bins=bapc_bins)
            _write_continuous_bapc_coverage_json(
                campaign,
                dut_name="boom-clean",
                bapc_bins=bapc_bins,
                bapc_hash=str(universe["sha256"]),
            )
            metadata_path = campaign / "metrics" / "campaign_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
            metadata.update(
                {
                    "method": "pmpfuzz",
                    "dut": "boom-clean",
                    "coverage_mode": "bapc",
                    "source_sha": "a" * 40,
                    "source_tree_sha256": "b" * 64,
                    "source_dirty": False,
                    "dut_sha": "c" * 40,
                    "dut_binary_path": str((campaign / "fixtures" / "dut.bin").resolve()),
                    "dut_binary_sha256": hashlib.sha256((campaign / "fixtures" / "dut.bin").read_bytes()).hexdigest(),
                    "capability_fingerprint": str(universe["capability_fingerprint"]),
                    "budget_class": "primary-wall-clock",
                    "wall_clock_horizon_seconds": 7200,
                    "time_budget_seconds": 7200,
                    "convergence_enabled": True,
                    "convergence_min_runtime_seconds": 0,
                    "convergence_confirmation_seconds": 600,
                    "convergence_confirmation_eligible_cases": 300,
                    "max_wall_time_seconds": 7200,
                    "stop_reason": "coverage_converged",
                }
            )
            metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="ascii")
            _write_bapc_formal_contract(root, dut="boom-clean", bin_set_sha256=str(universe["bin_set_sha256"]))
            timeline_path = campaign / "metrics" / "coverage_timeline.jsonl"
            _write_manifests(
                root,
                artifact_sha_files=[
                    (
                        str(timeline_path.relative_to(root)).replace("\\", "/"),
                        timeline_path.read_text(encoding="ascii"),
                    )
                ],
                experiment_contract=json.loads((root / "manifests" / "experiment-contract.json").read_text(encoding="ascii")),
            )

            report = validate_timeline(campaign)

        self.assertFalse(report["valid"], report)
        checks = [c for c in report["checks"] if c["name"] == "formal_bapc_experiment_protocol_id_exact"]
        self.assertTrue(checks, report)
        self.assertFalse(checks[0]["passed"], report)

    def test_formal_bapc_without_protocol_or_contract_still_uses_formal_context(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root, coverage_mode="bapc")
            _write_bapc_timeline(campaign, "formal-bapc", dut="boom-clean")
            _write_metadata(
                campaign,
                "formal-bapc",
                run_class="formal",
                coverage_mode="bapc",
                variant="random-mutation",
            )
            _write_cases_and_results(campaign, ["case-0001"])
            universe = _write_continuous_bapc_universe_file(campaign)
            bapc_bins = [str(universe["bin_ids"][0])]
            _write_continuous_bapc_schedule(campaign, bapc_bins=bapc_bins)
            _write_continuous_bapc_coverage_json(
                campaign,
                dut_name="boom-clean",
                bapc_bins=bapc_bins,
                bapc_hash=str(universe["sha256"]),
            )
            metadata_path = campaign / "metrics" / "campaign_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
            metadata.update(
                {
                    "method": "pmpfuzz",
                    "dut": "boom-clean",
                    "coverage_mode": "bapc",
                    "source_sha": "a" * 40,
                    "source_tree_sha256": "b" * 64,
                    "source_dirty": False,
                    "dut_sha": "c" * 40,
                    "dut_binary_path": str((campaign / "fixtures" / "dut.bin").resolve()),
                    "dut_binary_sha256": hashlib.sha256((campaign / "fixtures" / "dut.bin").read_bytes()).hexdigest(),
                    "capability_fingerprint": str(universe["capability_fingerprint"]),
                    "budget_class": "primary-wall-clock",
                    "wall_clock_horizon_seconds": 7200,
                    "time_budget_seconds": 7200,
                    "convergence_enabled": True,
                    "convergence_min_runtime_seconds": 0,
                    "convergence_confirmation_seconds": 600,
                    "convergence_confirmation_eligible_cases": 300,
                    "max_wall_time_seconds": 7200,
                    "stop_reason": "coverage_converged",
                }
            )
            metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="ascii")
            timeline_path = campaign / "metrics" / "coverage_timeline.jsonl"
            _write_manifests(
                root,
                artifact_sha_files=[
                    (
                        str(timeline_path.relative_to(root)).replace("\\", "/"),
                        timeline_path.read_text(encoding="ascii"),
                    )
                ],
            )

            report = validate_timeline(campaign)

        self.assertFalse(report["valid"], report)
        checks = {c["name"]: c for c in report["checks"]}
        self.assertIn("formal_bapc_contract_manifest_exists", checks, report)
        self.assertFalse(checks["formal_bapc_contract_manifest_exists"]["passed"], report)
        self.assertIn("formal_bapc_experiment_protocol_id_exact", checks, report)
        self.assertFalse(checks["formal_bapc_experiment_protocol_id_exact"]["passed"], report)

    def test_formal_bapc_missing_run_class_does_not_fall_back_to_legacy(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root, coverage_mode="bapc")
            _write_bapc_timeline(campaign, "formal-bapc", dut="boom-clean")
            _write_metadata(campaign, "formal-bapc", run_class=None, coverage_mode="bapc", variant="random-mutation")
            _write_cases_and_results(campaign, ["case-0001"])
            universe = _write_continuous_bapc_universe_file(campaign)
            bapc_bins = [str(universe["bin_ids"][0])]
            _write_continuous_bapc_schedule(campaign, bapc_bins=bapc_bins)
            _write_continuous_bapc_coverage_json(
                campaign,
                dut_name="boom-clean",
                bapc_bins=bapc_bins,
                bapc_hash=str(universe["sha256"]),
            )
            metadata_path = campaign / "metrics" / "campaign_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
            metadata.update(
                {
                    "method": "pmpfuzz",
                    "dut": "boom-clean",
                    "coverage_mode": "bapc",
                    "experiment_protocol_id": BAPC_CONVERGENCE_PROTOCOL_ID,
                    "source_sha": "",
                    "source_tree_sha256": "",
                    "source_dirty": False,
                    "dut_sha": "c" * 40,
                    "dut_binary_path": str((campaign / "fixtures" / "dut.bin").resolve()),
                    "dut_binary_sha256": hashlib.sha256((campaign / "fixtures" / "dut.bin").read_bytes()).hexdigest(),
                    "capability_fingerprint": str(universe["capability_fingerprint"]),
                    "budget_class": "primary-wall-clock",
                    "wall_clock_horizon_seconds": 7200,
                    "time_budget_seconds": 7200,
                    "convergence_enabled": True,
                    "convergence_min_runtime_seconds": 0,
                    "convergence_confirmation_seconds": 600,
                    "convergence_confirmation_eligible_cases": 300,
                    "max_wall_time_seconds": 7200,
                    "stop_reason": "coverage_converged",
                }
            )
            metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="ascii")
            _write_bapc_formal_contract(root, dut="boom-clean", bin_set_sha256=str(universe["bin_set_sha256"]))
            timeline_path = campaign / "metrics" / "coverage_timeline.jsonl"
            _write_manifests(
                root,
                artifact_sha_files=[
                    (
                        str(timeline_path.relative_to(root)).replace("\\", "/"),
                        timeline_path.read_text(encoding="ascii"),
                    )
                ],
                experiment_contract=json.loads((root / "manifests" / "experiment-contract.json").read_text(encoding="ascii")),
            )

            report = validate_timeline(campaign)

        self.assertFalse(report["valid"], report)
        checks = {c["name"]: c for c in report["checks"]}
        self.assertIn("formal_bapc_method_run_class_coupled", checks, report)
        self.assertFalse(checks["formal_bapc_method_run_class_coupled"]["passed"], report)
        self.assertIn("source_sha_present", checks, report)
        self.assertEqual(checks["source_sha_present"]["severity"], "error", report)

    def test_formal_bapc_wrong_protocol_parameter_values_are_invalid(self):
        cases = {
            "convergence_min_runtime_seconds": 1,
            "convergence_confirmation_seconds": "600",
            "convergence_confirmation_eligible_cases": True,
            "max_wall_time_seconds": float("nan"),
            "time_budget_seconds": float("inf"),
            "wall_clock_horizon_seconds": 0,
            "budget_class": "secondary",
        }
        for field, bad_value in cases.items():
            with self.subTest(field=field, bad_value=bad_value):
                with TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    campaign = _build_minimal_campaign(root, coverage_mode="bapc")
                    _write_bapc_timeline(campaign, "formal-bapc", dut="boom-clean")
                    _write_metadata(campaign, "formal-bapc", run_class="formal", coverage_mode="bapc", variant="random-mutation")
                    _write_cases_and_results(campaign, ["case-0001"])
                    universe = _write_continuous_bapc_universe_file(campaign)
                    bapc_bins = [str(universe["bin_ids"][0])]
                    _write_continuous_bapc_schedule(campaign, bapc_bins=bapc_bins)
                    _write_continuous_bapc_coverage_json(
                        campaign,
                        dut_name="boom-clean",
                        bapc_bins=bapc_bins,
                        bapc_hash=str(universe["sha256"]),
                    )
                    metadata_path = campaign / "metrics" / "campaign_metadata.json"
                    metadata = json.loads(metadata_path.read_text(encoding="ascii"))
                    metadata.update(
                        {
                            "method": "pmpfuzz",
                            "dut": "boom-clean",
                            "coverage_mode": "bapc",
                            "experiment_protocol_id": BAPC_CONVERGENCE_PROTOCOL_ID,
                            "source_sha": "a" * 40,
                            "source_tree_sha256": "b" * 64,
                            "source_dirty": False,
                            "dut_sha": "c" * 40,
                            "dut_binary_path": str((campaign / "fixtures" / "dut.bin").resolve()),
                            "dut_binary_sha256": hashlib.sha256((campaign / "fixtures" / "dut.bin").read_bytes()).hexdigest(),
                            "capability_fingerprint": str(universe["capability_fingerprint"]),
                            "convergence_enabled": True,
                            "convergence_min_runtime_seconds": 0,
                            "convergence_confirmation_seconds": 600,
                            "convergence_confirmation_eligible_cases": 300,
                            "max_wall_time_seconds": 7200,
                            "time_budget_seconds": 7200,
                            "wall_clock_horizon_seconds": 7200,
                            "budget_class": "primary-wall-clock",
                            "stop_reason": "coverage_converged",
                        }
                    )
                    metadata[field] = bad_value
                    metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="ascii")
                    _write_bapc_formal_contract(root, dut="boom-clean", bin_set_sha256=str(universe["bin_set_sha256"]))
                    timeline_path = campaign / "metrics" / "coverage_timeline.jsonl"
                    _write_manifests(
                        root,
                        artifact_sha_files=[
                            (
                                str(timeline_path.relative_to(root)).replace("\\", "/"),
                                timeline_path.read_text(encoding="ascii"),
                            )
                        ],
                        experiment_contract=json.loads((root / "manifests" / "experiment-contract.json").read_text(encoding="ascii")),
                    )

                    report = validate_timeline(campaign)

                self.assertFalse(report["valid"], report)
                checks = {
                    c["name"]: c
                    for c in report["checks"]
                    if c["name"].startswith("formal_bapc_")
                }
                self.assertTrue(any(not c["passed"] for c in checks.values()), report)

    def test_formal_bapc_accepts_allowed_legacy_source_provenance(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root, coverage_mode="bapc")
            _write_bapc_timeline(campaign, "formal-bapc", dut="boom-clean")
            _write_metadata(
                campaign,
                "formal-bapc",
                run_class="formal",
                coverage_mode="bapc",
                variant="random-mutation",
                dut="boom-clean",
                method="pmpfuzz",
                source_sha="1" * 40,
                source_tree_sha256="2" * 64,
                source_dirty=False,
            )
            _write_cases_and_results(campaign, ["case-0001"])
            universe = _write_continuous_bapc_universe_file(campaign)
            bapc_bins = [str(universe["bin_ids"][0])]
            _write_continuous_bapc_schedule(campaign, bapc_bins=bapc_bins)
            _write_continuous_bapc_coverage_json(
                campaign,
                dut_name="boom-clean",
                bapc_bins=bapc_bins,
                bapc_hash=str(universe["sha256"]),
            )
            metadata_path = campaign / "metrics" / "campaign_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
            metadata.update(
                {
                    "method": "pmpfuzz",
                    "dut": "boom-clean",
                    "coverage_mode": "bapc",
                    "experiment_protocol_id": BAPC_CONVERGENCE_PROTOCOL_ID,
                    "dut_sha": "c" * 40,
                    "dut_binary_path": str((campaign / "fixtures" / "dut.bin").resolve()),
                    "dut_binary_sha256": hashlib.sha256((campaign / "fixtures" / "dut.bin").read_bytes()).hexdigest(),
                    "capability_fingerprint": str(universe["capability_fingerprint"]),
                    "convergence_enabled": True,
                    "convergence_min_runtime_seconds": 0,
                    "convergence_confirmation_seconds": 600,
                    "convergence_confirmation_eligible_cases": 300,
                    "max_wall_time_seconds": 7200,
                    "time_budget_seconds": 7200,
                    "wall_clock_horizon_seconds": 7200,
                    "budget_class": "primary-wall-clock",
                    "stop_reason": "coverage_converged",
                }
            )
            metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="ascii")
            contract = _write_bapc_formal_contract(root, dut="boom-clean", bin_set_sha256=str(universe["bin_set_sha256"]))
            contract_path = root / "manifests" / "experiment-contract.json"
            contract["source_sha"] = "a" * 40
            contract["allowed_source_shas"] = ["a" * 40, "1" * 40]
            contract["source_tree_sha256"] = "b" * 64
            contract["allowed_source_tree_sha256s"] = ["b" * 64, "2" * 64]
            contract["dut_sha"] = "c" * 40
            contract["dut_binary_sha256"] = hashlib.sha256((campaign / "fixtures" / "dut.bin").read_bytes()).hexdigest()
            contract_path.write_text(json.dumps(contract, indent=2, ensure_ascii=True), encoding="ascii")
            timeline_path = campaign / "metrics" / "coverage_timeline.jsonl"
            _write_manifests(
                root,
                artifact_sha_files=[
                    (
                        str(timeline_path.relative_to(root)).replace("\\", "/"),
                        timeline_path.read_text(encoding="ascii"),
                    )
                ],
                experiment_contract=json.loads(contract_path.read_text(encoding="ascii")),
            )

            report = validate_timeline(campaign)

        self.assertTrue(report["valid"], report)
        checks = {c["name"]: c for c in report["checks"]}
        self.assertTrue(checks["formal_bapc_metadata_source_sha_matches_contract"]["passed"], report)
        self.assertTrue(checks["formal_bapc_metadata_source_tree_sha256_matches_contract"]["passed"], report)

    def test_formal_bapc_requires_source_dirty_false(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = _build_minimal_campaign(root, coverage_mode="bapc")
            _write_bapc_timeline(campaign, "formal-bapc", dut="boom-clean")
            _write_metadata(
                campaign,
                "formal-bapc",
                run_class="formal",
                coverage_mode="bapc",
                variant="random-mutation",
            )
            _write_cases_and_results(campaign, ["case-0001"])
            universe = _write_continuous_bapc_universe_file(campaign)
            bapc_bins = [str(universe["bin_ids"][0])]
            _write_continuous_bapc_schedule(campaign, bapc_bins=bapc_bins)
            _write_continuous_bapc_coverage_json(
                campaign,
                dut_name="boom-clean",
                bapc_bins=bapc_bins,
                bapc_hash=str(universe["sha256"]),
            )
            metadata_path = campaign / "metrics" / "campaign_metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="ascii"))
            metadata.update(
                {
                    "method": "pmpfuzz",
                    "dut": "boom-clean",
                    "coverage_mode": "bapc",
                    "experiment_protocol_id": BAPC_CONVERGENCE_PROTOCOL_ID,
                    "source_sha": "a" * 40,
                    "source_tree_sha256": "b" * 64,
                    "source_dirty": True,
                    "dut_sha": "c" * 40,
                    "dut_binary_path": str((campaign / "fixtures" / "dut.bin").resolve()),
                    "dut_binary_sha256": hashlib.sha256((campaign / "fixtures" / "dut.bin").read_bytes()).hexdigest(),
                    "capability_fingerprint": str(universe["capability_fingerprint"]),
                    "budget_class": "primary-wall-clock",
                    "wall_clock_horizon_seconds": 7200,
                    "time_budget_seconds": 7200,
                    "convergence_enabled": True,
                    "convergence_min_runtime_seconds": 0,
                    "convergence_confirmation_seconds": 600,
                    "convergence_confirmation_eligible_cases": 300,
                    "max_wall_time_seconds": 7200,
                    "stop_reason": "coverage_converged",
                }
            )
            metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="ascii")
            _write_bapc_formal_contract(root, dut="boom-clean", bin_set_sha256=str(universe["bin_set_sha256"]))
            timeline_path = campaign / "metrics" / "coverage_timeline.jsonl"
            _write_manifests(
                root,
                artifact_sha_files=[
                    (
                        str(timeline_path.relative_to(root)).replace("\\", "/"),
                        timeline_path.read_text(encoding="ascii"),
                    )
                ],
                experiment_contract=json.loads((root / "manifests" / "experiment-contract.json").read_text(encoding="ascii")),
            )

            report = validate_timeline(campaign)

        self.assertFalse(report["valid"], report)
        checks = {c["name"]: c for c in report["checks"]}
        self.assertIn("source_dirty_false", checks, report)
        self.assertFalse(checks["source_dirty_false"]["passed"], report)

    def test_formal_bapc_method_and_stop_reason_constraints(self):
        scenarios = [
            ("cascade", "formal", "coverage_converged", False),
            ("pmpfuzz", "formal", "completed_requested_cases", False),
            ("pmpfuzz", "formal", "coverage_converged", True),
            ("cascade", "baseline-formal", "hard_cap_censored", True),
        ]
        for method, run_class, stop_reason, expected_valid in scenarios:
            with self.subTest(method=method, run_class=run_class, stop_reason=stop_reason):
                with TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    campaign = _build_minimal_campaign(root, coverage_mode="bapc")
                    _write_bapc_timeline(campaign, "formal-bapc", dut="boom-clean")
                    _write_metadata(
                        campaign,
                        "formal-bapc",
                        run_class=run_class,
                        coverage_mode="bapc",
                        variant="random-mutation",
                        method=method,
                    )
                    _write_cases_and_results(campaign, ["case-0001"])
                    universe = _write_continuous_bapc_universe_file(campaign)
                    bapc_bins = [str(universe["bin_ids"][0])]
                    _write_continuous_bapc_schedule(campaign, bapc_bins=bapc_bins)
                    _write_continuous_bapc_coverage_json(
                        campaign,
                        dut_name="boom-clean",
                        bapc_bins=bapc_bins,
                        bapc_hash=str(universe["sha256"]),
                    )
                    metadata_path = campaign / "metrics" / "campaign_metadata.json"
                    metadata = json.loads(metadata_path.read_text(encoding="ascii"))
                    metadata.update(
                        {
                            "method": method,
                            "dut": "boom-clean",
                            "coverage_mode": "bapc",
                            "experiment_protocol_id": BAPC_CONVERGENCE_PROTOCOL_ID,
                            "source_sha": "a" * 40,
                            "source_tree_sha256": "b" * 64,
                            "source_dirty": False,
                            "dut_sha": "c" * 40,
                            "dut_binary_path": str((campaign / "fixtures" / "dut.bin").resolve()),
                            "dut_binary_sha256": hashlib.sha256((campaign / "fixtures" / "dut.bin").read_bytes()).hexdigest(),
                            "capability_fingerprint": str(universe["capability_fingerprint"]),
                            "budget_class": "primary-wall-clock",
                            "wall_clock_horizon_seconds": 7200,
                            "time_budget_seconds": 7200,
                            "convergence_enabled": True,
                            "convergence_min_runtime_seconds": 0,
                            "convergence_confirmation_seconds": 600,
                            "convergence_confirmation_eligible_cases": 300,
                            "max_wall_time_seconds": 7200,
                            "stop_reason": stop_reason,
                        }
                    )
                    metadata_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=True), encoding="ascii")
                    _write_bapc_formal_contract(root, dut="boom-clean", bin_set_sha256=str(universe["bin_set_sha256"]))
                    timeline_path = campaign / "metrics" / "coverage_timeline.jsonl"
                    _write_manifests(
                        root,
                        artifact_sha_files=[
                            (
                                str(timeline_path.relative_to(root)).replace("\\", "/"),
                                timeline_path.read_text(encoding="ascii"),
                            )
                        ],
                        experiment_contract=json.loads((root / "manifests" / "experiment-contract.json").read_text(encoding="ascii")),
                    )

                    report = validate_timeline(campaign)

                self.assertEqual(report["valid"], expected_valid, report)


if __name__ == "__main__":
    unittest.main()
