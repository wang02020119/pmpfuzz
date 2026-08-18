from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from pmpfuzz.bapc import (
    BAPC_GENERATION_RULE_VERSION,
    BAPC_SCHEMA_VERSION,
    BAPC_TARGET,
    build_bapc_coverage_universe,
    validate_bapc_coverage_universe,
)
from pmpfuzz.capabilities import (
    capability_coverage_projection,
    capability_for_dut,
    oracle_applicability_for_case,
)
from pmpfuzz.coverage_universe import (
    freeze_coverage_universes,
    make_coverage_universe,
    write_coverage_universes,
)

from .generate_reference_cases import DEFAULT_FAMILY_PLAN, PRIMARY_SPEC_REVISION, write_reference_corpus
from .mutant_catalog import build_mutants_manifest


SCHEMA_VERSION = 1
EXPERIMENT_PROTOCOL_ID = "oracle-validation-v1"
REFERENCE_GENERATOR_SEED = 7601
COVERAGE_GENERATOR_SEED = 20260628
PRIMARY_DUTS = ("rocket-clean", "boom-clean", "cva6-clean")
ORDER_SEEDS = (4, 5, 6)
ONLINE_SEEDS = (4, 5, 6)
ONLINE_CANDIDATE_BUDGET = 2048
WALL_CLOCK_HORIZON_SECONDS = 7200
REPLAY_COUNT = 10
COUNTERFACTUAL_MUTATION_IDS = (
    "O1",
    "O2",
    "O3",
    "O4",
    "O5",
    "O6",
    "O7",
    "O8",
    "O9",
    "O10",
    "O11",
    "O12",
)
EXCLUDED_DUTS = (
    {
        "dut": "xiangshan-clean",
        "reason": "excluded before results because simulation cost is disproportionately high",
        "recorded_before_results": True,
    },
)
EXCLUSION_RULES = (
    "unsupported",
    "capability_dependent",
    "experimental",
    "infra_unadapted",
    "compile_fail",
    "timeout",
    "sim_crash",
    "invalid_observation",
    "incomplete_observation",
    "equivalent_mutant",
)
CRITICAL_MUTATION_FAMILIES = (
    "permission_bypass",
    "ptw_bypass",
    "stale_permission",
    "wrong_trap_cause",
    "forbidden_store_side_effect",
)


def freeze_formal_artifact(
    *,
    artifact_root: Path,
    source_root: Path,
    primary_duts: Iterable[str] = PRIMARY_DUTS,
    order_seeds: Iterable[int] = ORDER_SEEDS,
    online_seeds: Iterable[int] = ONLINE_SEEDS,
    reference_generator_seed: int = REFERENCE_GENERATOR_SEED,
    coverage_generator_seed: int = COVERAGE_GENERATOR_SEED,
    online_candidate_budget: int = ONLINE_CANDIDATE_BUDGET,
    wall_clock_horizon_seconds: int = WALL_CLOCK_HORIZON_SECONDS,
    replay_count: int = REPLAY_COUNT,
    spec_revision: str = PRIMARY_SPEC_REVISION,
    reference_family_plan: Iterable[Mapping[str, Any]] | None = None,
    reference_case_id_offsets: Mapping[str, int] | None = None,
    dut_binary_paths: Mapping[str, Path | str | None] | None = None,
    dut_source_roots: Mapping[str, Path | str | None] | None = None,
    capabilities_by_dut: Mapping[str, Mapping[str, Any]] | None = None,
    source_provenance: Mapping[str, Any] | None = None,
    allow_dirty_source: bool = False,
) -> dict[str, Any]:
    artifact_root = Path(artifact_root)
    source_root = Path(source_root).resolve()
    if artifact_root.exists() and any(artifact_root.iterdir()):
        raise ValueError(f"artifact_root must be empty or absent: {artifact_root}")
    artifact_root.mkdir(parents=True, exist_ok=True)

    primary_dut_list = [str(item) for item in primary_duts]
    order_seed_list = [int(item) for item in order_seeds]
    online_seed_list = [int(item) for item in online_seeds]

    manifests_dir = artifact_root / "manifests"
    universe_root = manifests_dir / "coverage-universes"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    universe_root.mkdir(parents=True, exist_ok=True)

    reference_summary = write_reference_corpus(
        artifact_root=artifact_root,
        generator_seed=reference_generator_seed,
        spec_revision=spec_revision,
        family_plan=reference_family_plan if reference_family_plan is not None else DEFAULT_FAMILY_PLAN,
        case_id_offsets=reference_case_id_offsets,
    )
    cases = _load_jsonl(artifact_root / "reference" / "cases.jsonl")
    labels_by_case = {
        str(item["case_id"]): item
        for item in _load_jsonl(artifact_root / "reference" / "labels.jsonl")
    }

    resolved_source = dict(source_provenance or _collect_source_provenance(source_root))
    if resolved_source.get("source_dirty") and not allow_dirty_source:
        raise ValueError("formal freeze requires source_dirty=False")

    capabilities_payload: dict[str, Any] = {}
    per_dut_universes: dict[str, dict[str, dict[str, Any]]] = {}
    dut_binary_payload: dict[str, Any] = {}
    applicability_matrix: dict[str, dict[str, str]] = {}

    for dut in primary_dut_list:
        binary_path = _maybe_path((dut_binary_paths or {}).get(dut))
        source_dir = _maybe_path((dut_source_roots or {}).get(dut))
        capability = dict(
            capabilities_by_dut.get(dut)
            if capabilities_by_dut and dut in capabilities_by_dut
            else capability_for_dut(
                dut,
                path=binary_path,
                available=None if binary_path is None else bool(binary_path.exists()),
            )
        )
        universes = freeze_coverage_universes(
            target="core-stateful",
            capability=capability,
            include_experimental=False,
            seed=coverage_generator_seed,
        )
        per_dut_universes[dut] = universes
        write_coverage_universes(universe_root / dut, universes)

        applicability_by_case = {}
        for case in cases:
            case_id = str(case["case_id"])
            enriched_case = dict(case)
            enriched_case.update(labels_by_case.get(case_id) or {})
            applicability_by_case[case_id] = oracle_applicability_for_case(enriched_case, capability)
        applicability_matrix[dut] = applicability_by_case
        applicability_counts = _count_values(applicability_by_case.values())

        capabilities_payload[dut] = {
            "capability": capability,
            "coverage_projection": capability_coverage_projection(capability),
            "coverage_capability_fingerprint": str(universes["semantic"]["capability_fingerprint"]),
            "applicability_counts": applicability_counts,
            "applicability_by_case": applicability_by_case,
        }
        dut_binary_payload[dut] = _collect_dut_binary_record(
            dut=dut,
            binary_path=binary_path,
            source_root=source_dir,
        )

    bapc_universe = build_section76_bapc_universe(generator_seed=coverage_generator_seed)
    _write_json(universe_root / "bapc_v2.json", bapc_universe)

    coverage_contract = build_coverage_contract(
        artifact_root=artifact_root,
        bapc_universe=bapc_universe,
        per_dut_universes=per_dut_universes,
    )
    _write_json(manifests_dir / "coverage-contract.json", coverage_contract)

    capabilities_manifest = {
        "schema_version": SCHEMA_VERSION,
        "reference_case_count": len(cases),
        "target": "core-stateful",
        "include_experimental": False,
        "duts": capabilities_payload,
        "excluded_duts": list(EXCLUDED_DUTS),
    }
    _write_json(manifests_dir / "capabilities.json", capabilities_manifest)

    dut_binaries_manifest = {
        "schema_version": SCHEMA_VERSION,
        "duts": dut_binary_payload,
    }
    _write_json(manifests_dir / "dut-binaries.json", dut_binaries_manifest)

    environment_manifest = _build_environment_manifest(artifact_root)
    _write_json(manifests_dir / "environment.json", environment_manifest)
    _write_git_shas(
        manifests_dir / "git-shas.txt",
        source_sha=str(resolved_source.get("source_sha") or ""),
        dut_records=dut_binary_payload,
    )
    mutants_manifest = build_mutants_manifest(
        artifact_root=artifact_root,
        order_seeds=order_seed_list,
        online_seeds=online_seed_list,
        replay_count=int(replay_count),
        online_candidate_budget=int(online_candidate_budget),
        wall_clock_horizon_seconds=int(wall_clock_horizon_seconds),
    )
    _write_json(manifests_dir / "mutants.json", mutants_manifest)

    experiment_contract = build_experiment_contract(
        artifact_root=artifact_root,
        source_root=source_root,
        source_provenance=resolved_source,
        primary_duts=primary_dut_list,
        order_seeds=order_seed_list,
        online_seeds=online_seed_list,
        spec_revision=spec_revision,
        coverage_generator_seed=coverage_generator_seed,
        online_candidate_budget=int(online_candidate_budget),
        wall_clock_horizon_seconds=int(wall_clock_horizon_seconds),
        replay_count=int(replay_count),
        reference_summary=reference_summary,
        applicability_matrix=applicability_matrix,
        mutants_manifest=mutants_manifest,
    )
    _write_json(manifests_dir / "experiment-contract.json", experiment_contract)

    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_root": str(artifact_root),
        "source_sha": str(resolved_source.get("source_sha") or ""),
        "source_tree_sha256": str(resolved_source.get("source_tree_sha256") or ""),
        "primary_duts": primary_dut_list,
        "cases_sha256": str(reference_summary["cases_sha256"]),
        "labels_sha256": str(reference_summary["labels_sha256"]),
        "bapc_bin_count": int(bapc_universe["bin_count"]),
        "bapc_bin_set_sha256": str(bapc_universe["bin_set_sha256"]),
    }


def build_section76_bapc_universe(*, generator_seed: int) -> dict[str, Any]:
    template = build_bapc_coverage_universe(
        dut="section76-primary-clean-duts",
        generator_seed=generator_seed,
        supports_fault_stage=True,
        supports_smepmp=False,
    )
    universe = make_coverage_universe(
        coverage_mode="bapc",
        bin_ids=template["bin_ids"],
        capability_fingerprint="bapc:section76-primary-clean-duts:fault-stage=1:smepmp=0",
        target=BAPC_TARGET,
        include_experimental=False,
        generator_seed=generator_seed,
        generation_rule_version=BAPC_GENERATION_RULE_VERSION,
        extra_fields={
            "bapc_schema_version": BAPC_SCHEMA_VERSION,
            "dut": "section76-primary-clean-duts",
            "capabilities": {
                "fault_stage": True,
                "smepmp": False,
            },
            "bin_families": list(template.get("bin_families") or []),
            "supplemental_bin_families": [],
        },
    )
    return validate_bapc_coverage_universe(universe)


def build_coverage_contract(
    *,
    artifact_root: Path,
    bapc_universe: Mapping[str, Any],
    per_dut_universes: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> dict[str, Any]:
    coverage_duts: dict[str, Any] = {}
    for dut, universes in sorted(per_dut_universes.items()):
        mode_payload: dict[str, Any] = {}
        for mode, universe in sorted(universes.items()):
            mode_payload[mode] = {
                "path": _relpath(artifact_root, artifact_root / "manifests" / "coverage-universes" / dut / _coverage_filename(mode)),
                "sha256": str(universe.get("sha256") or ""),
                "bin_count": int(universe.get("bin_count") or 0),
                "bin_set_sha256": str(universe.get("bin_set_sha256") or ""),
                "generation_rule_version": str(universe.get("generation_rule_version") or ""),
                "capability_fingerprint": str(universe.get("capability_fingerprint") or ""),
                "target": str(universe.get("target") or ""),
            }
        semantic = universes["semantic"]
        coverage_duts[dut] = {
            "target": str(semantic.get("target") or ""),
            "generator_seed": int(semantic.get("generator_seed") or 0),
            "include_experimental": bool(semantic.get("include_experimental", False)),
            "capability_fingerprint": str(semantic.get("capability_fingerprint") or ""),
            "modes": mode_payload,
        }

    return {
        "schema_version": SCHEMA_VERSION,
        "bapc_v2": {
            "path": _relpath(artifact_root, artifact_root / "manifests" / "coverage-universes" / "bapc_v2.json"),
            "schema_version": int(bapc_universe.get("schema_version") or 0),
            "bapc_schema_version": int(bapc_universe.get("bapc_schema_version") or 0),
            "generation_rule_version": str(bapc_universe.get("generation_rule_version") or ""),
            "generator_seed": int(bapc_universe.get("generator_seed") or 0),
            "target": str(bapc_universe.get("target") or ""),
            "bin_count": int(bapc_universe.get("bin_count") or 0),
            "sha256": str(bapc_universe.get("sha256") or ""),
            "bin_set_sha256": str(bapc_universe.get("bin_set_sha256") or ""),
        },
        "secondary_pmpfuzz_coverage": {
            "target": "core-stateful",
            "include_experimental": False,
            "duts": coverage_duts,
        },
    }


def build_experiment_contract(
    *,
    artifact_root: Path,
    source_root: Path,
    source_provenance: Mapping[str, Any],
    primary_duts: list[str],
    order_seeds: list[int],
    online_seeds: list[int],
    spec_revision: str,
    coverage_generator_seed: int,
    online_candidate_budget: int,
    wall_clock_horizon_seconds: int,
    replay_count: int,
    reference_summary: Mapping[str, Any],
    applicability_matrix: Mapping[str, Mapping[str, str]],
    mutants_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    cases_per_order = int(reference_summary.get("case_count") or 0)
    mutant_entries = [
        item
        for item in (mutants_manifest.get("entries") or [])
        if isinstance(item, dict)
    ]
    planned_online_campaigns = len(mutant_entries) * len(online_seeds)
    negative_control_campaigns = len(primary_duts) * len(online_seeds)
    applicability_counts = {
        dut: _count_values(case_status.values())
        for dut, case_status in sorted(applicability_matrix.items())
    }
    acceptance_thresholds = {
        "clean_allow_deny_accuracy": 1.0,
        "clean_trap_cause_accuracy": 1.0,
        "clean_trap_stage_accuracy": 1.0,
        "clean_side_effect_accuracy": 1.0,
        "unexplained_clean_false_violations": 0,
        "counterfactual_pass_on_contradiction": 0,
        "counterfactual_pass_on_malformed": 0,
        "counterfactual_failure_family_accuracy_min": 0.95,
        "mutation_score_min": 0.90,
        "critical_family_mutation_score_min": 1.0,
        "failure_family_localization_accuracy_min": 0.90,
        "clean_control_false_alarms": 0,
    }
    if replay_count > 0:
        acceptance_thresholds["replay_success_fraction"] = f"{replay_count}/{replay_count}"
    return {
        "schema_version": SCHEMA_VERSION,
        "experiment_protocol_id": EXPERIMENT_PROTOCOL_ID,
        "paper_section": "7.6",
        "status": "frozen",
        "frozen_at_utc": _utc_now_iso(),
        "artifact_root": str(artifact_root),
        "source_root": str(source_root),
        "source_sha": str(source_provenance.get("source_sha") or ""),
        "source_tree_sha256": str(source_provenance.get("source_tree_sha256") or ""),
        "source_dirty": bool(source_provenance.get("source_dirty", False)),
        "spec_revision": spec_revision,
        "reference_generator_seed": int(reference_summary.get("generator_seed") or 0),
        "coverage_generator_seed": int(coverage_generator_seed),
        "reference_hashes": {
            "cases_sha256": str(reference_summary.get("cases_sha256") or ""),
            "labels_sha256": str(reference_summary.get("labels_sha256") or ""),
        },
        "primary_duts": primary_duts,
        "excluded_duts": list(EXCLUDED_DUTS),
        "order_seeds": order_seeds,
        "online_seeds": online_seeds,
        "coverage_contract_path": "manifests/coverage-contract.json",
        "mutants_manifest_path": "manifests/mutants.json",
        "append_only_required": True,
        "clean_suite": {
            "cases_per_order_seed": cases_per_order,
            "order_seed_count": len(order_seeds),
            "dut_count": len(primary_duts),
            "max_clean_executions": cases_per_order * len(order_seeds) * len(primary_duts),
            "spike_secondary_sanity_only": True,
        },
        "counterfactual_suite": {
            "single_field_only": True,
            "mutation_ids": list(COUNTERFACTUAL_MUTATION_IDS),
            "must_fail_closed_without_evidence": True,
        },
        "mutation_suite": {
            "rocket_planned_mutants": 18,
            "boom_planned_mutants": 6,
            "cva6_planned_mutants": 6,
            "total_planned_mutants": 30,
            "online_candidate_budget": int(online_candidate_budget),
            "wall_clock_horizon_seconds": int(wall_clock_horizon_seconds),
            "replay_count": int(replay_count),
            "negative_control_campaigns": negative_control_campaigns,
            "planned_online_campaigns": planned_online_campaigns + negative_control_campaigns,
        },
        "acceptance_thresholds": acceptance_thresholds,
        "critical_mutation_families": list(CRITICAL_MUTATION_FAMILIES),
        "exclusion_rules": list(EXCLUSION_RULES),
        "applicability_counts": applicability_counts,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze a formal Section 7.6 oracle-validation artifact root")
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--spec-revision", default=PRIMARY_SPEC_REVISION)
    parser.add_argument("--reference-generator-seed", type=int, default=REFERENCE_GENERATOR_SEED)
    parser.add_argument("--coverage-generator-seed", type=int, default=COVERAGE_GENERATOR_SEED)
    parser.add_argument("--online-candidate-budget", type=int, default=ONLINE_CANDIDATE_BUDGET)
    parser.add_argument("--wall-clock-horizon-seconds", type=int, default=WALL_CLOCK_HORIZON_SECONDS)
    parser.add_argument("--replay-count", type=int, default=REPLAY_COUNT)
    parser.add_argument("--reference-family-plan-json", type=Path)
    parser.add_argument("--reference-case-id-offsets-json", type=Path)
    parser.add_argument("--primary-dut", action="append", default=None)
    parser.add_argument("--order-seed", action="append", type=int, default=None)
    parser.add_argument("--online-seed", action="append", type=int, default=None)
    parser.add_argument("--dut-binary", action="append", default=[])
    parser.add_argument("--dut-source-root", action="append", default=[])
    parser.add_argument("--allow-dirty-source", action="store_true")
    args = parser.parse_args(argv)

    reference_family_plan = None
    if args.reference_family_plan_json:
        payload = json.loads(args.reference_family_plan_json.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("reference family plan JSON must be a list")
        reference_family_plan = payload
    reference_case_id_offsets = None
    if args.reference_case_id_offsets_json:
        payload = json.loads(args.reference_case_id_offsets_json.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("reference case-id offsets JSON must be an object")
        reference_case_id_offsets = {str(key): int(value) for key, value in payload.items()}
    primary_duts = args.primary_dut or list(PRIMARY_DUTS)
    order_seeds = args.order_seed or list(ORDER_SEEDS)
    online_seeds = args.online_seed or list(ONLINE_SEEDS)

    summary = freeze_formal_artifact(
        artifact_root=args.artifact_root,
        source_root=args.source_root,
        primary_duts=primary_duts,
        order_seeds=order_seeds,
        online_seeds=online_seeds,
        reference_generator_seed=args.reference_generator_seed,
        coverage_generator_seed=args.coverage_generator_seed,
        online_candidate_budget=args.online_candidate_budget,
        wall_clock_horizon_seconds=args.wall_clock_horizon_seconds,
        replay_count=args.replay_count,
        spec_revision=args.spec_revision,
        reference_family_plan=reference_family_plan,
        reference_case_id_offsets=reference_case_id_offsets,
        dut_binary_paths=_parse_dut_mapping(args.dut_binary),
        dut_source_roots=_parse_dut_mapping(args.dut_source_root),
        allow_dirty_source=args.allow_dirty_source,
    )
    print(
        f"formal-freeze artifact_root={summary['artifact_root']} "
        f"source_sha={summary['source_sha']} cases_sha256={summary['cases_sha256']} "
        f"labels_sha256={summary['labels_sha256']} bapc_bin_count={summary['bapc_bin_count']}"
    )
    return 0


def _build_environment_manifest(artifact_root: Path) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_root": str(artifact_root),
        "cwd": str(Path.cwd()),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python_executable": sys.executable,
        "python_version": platform.python_version(),
        "git_version": _capture_version("git", "--version"),
        "gcc_version": _capture_version("riscv64-unknown-elf-gcc", "--version"),
        "verilator_version": _capture_version("verilator", "--version"),
    }


def _collect_source_provenance(source_root: Path) -> dict[str, Any]:
    return {
        "source_sha": str(_git_head_sha(source_root) or ""),
        "source_tree_sha256": str(_source_tree_sha256(source_root) or ""),
        "source_dirty": _git_is_dirty(source_root),
    }


def _collect_dut_binary_record(
    *,
    dut: str,
    binary_path: Path | None,
    source_root: Path | None,
) -> dict[str, Any]:
    return {
        "path": str(binary_path) if binary_path is not None else "",
        "sha256": str(_file_sha256(binary_path) or ""),
        "exists": bool(binary_path and binary_path.is_file()),
        "dut_sha": str(_git_head_sha(source_root) or "") if source_root is not None else "",
        "dut_source_root": str(source_root) if source_root is not None else "",
        "dut_source_tree_sha256": str(_source_tree_sha256(source_root) or "") if source_root is not None else "",
        "dut_source_dirty": _git_is_dirty(source_root) if source_root is not None else None,
        "dut": dut,
    }


def _write_git_shas(path: Path, *, source_sha: str, dut_records: Mapping[str, Mapping[str, Any]]) -> None:
    lines: list[str] = []
    if source_sha:
        lines.append(f"{source_sha}  pmpfuzz")
    for dut, record in sorted(dut_records.items()):
        sha = str(record.get("dut_sha") or "")
        if sha:
            lines.append(f"{sha}  {dut}")
    if not lines:
        lines.append(f"{'0' * 40}  unavailable")
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError(f"expected object row in {path}")
        rows.append(payload)
    return rows


def _count_values(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def _parse_dut_mapping(items: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items:
        text = str(item)
        if "=" not in text:
            raise ValueError(f"expected DUT=PATH mapping, got {text!r}")
        dut, value = text.split("=", 1)
        result[str(dut).strip()] = str(value).strip()
    return result


def _coverage_filename(mode: str) -> str:
    return f"{mode}_v1.json"


def _relpath(root: Path, path: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")


def _maybe_path(value: Path | str | None) -> Path | None:
    if value in {None, ""}:
        return None
    return Path(value).expanduser().resolve()


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(dict(payload), indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _git_head_sha(cwd: Path | None) -> str | None:
    if cwd is None:
        return None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(cwd),
        )
    except Exception:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _git_text(cwd: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(cwd),
        )
    except Exception:
        return None
    return result.stdout if result.returncode == 0 else None


def _source_tree_sha256(root: Path | None) -> str | None:
    if root is None:
        return None
    raw = _git_text(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    paths: list[str] = []
    if raw is not None:
        paths = [item for item in raw.split("\0") if item]
    else:
        for path in sorted(root.rglob("*")):
            if ".git" in path.parts or not path.is_file():
                continue
            paths.append(str(path.relative_to(root)).replace("\\", "/"))
    hasher = hashlib.sha256()
    for rel in paths:
        path = root / rel
        if not path.is_file():
            continue
        hasher.update(rel.replace("\\", "/").encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    if not paths:
        return None
    return hasher.hexdigest()


def _git_is_dirty(root: Path | None) -> bool:
    if root is None:
        return False
    status = _git_text(root, "status", "--porcelain=v1", "--untracked-files=all")
    return bool(status and status.strip())


def _file_sha256(path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _capture_version(*cmd: str) -> str:
    try:
        result = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return ""
    text = (result.stdout or result.stderr or "").strip()
    if not text:
        return ""
    return text.splitlines()[0].strip()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    raise SystemExit(main())
