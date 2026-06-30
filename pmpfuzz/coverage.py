from __future__ import annotations

from pathlib import Path
from typing import Any

from .semantic_coverage import (
    CORE_STATEFUL_TARGET,
    OOO_MICROARCH_TARGET,
    OOO_MICROARCH_PROFILES,
    XIANGSHAN_TARGETED_PROFILES,
    XIANGSHAN_TARGETED_TARGET,
    combo_bins_for_case,
    combination_gap_from_runs,
    coverage_gap_from_runs,
    semantic_bins_for_case,
)
from .schema import read_json, write_json


def _bump(bucket: dict[str, int], key: object) -> None:
    if key is None:
        return
    text = str(key)
    if not text:
        return
    bucket[text] = bucket.get(text, 0) + 1


def coverage_from_run(run_dir: Path) -> dict[str, Any]:
    cases = []
    for case_path in sorted((run_dir / "cases").glob("*/case.json")):
        cases.append(read_json(case_path))

    results = []
    for result_path in sorted((run_dir / "results").glob("*/result.json")):
        results.append(read_json(result_path))

    coverage: dict[str, Any] = {
        "schema_version": 3,
        "run_dir": str(run_dir),
        "total_cases": len(cases),
        "total_results": len(results),
        "profiles": {},
        "privileges": {},
        "accesses": {},
        "translations": {},
        "coverage_tags": {},
        "pmp_match_modes": {},
        "ptw_fault_levels": {},
        "preload_modes": {},
        "pte_permissions": {},
        "security_focus": {},
        "stateful_sequences": {},
        "stateful_mutations": {},
        "stateful_fences": {},
        "statuses": {},
        "failure_classes": {},
        "smepmp_mml": {},
        "smepmp_mmwp": {},
        "smepmp_rlb": {},
        "smepmp_rules": {},
        "effective_privileges": {},
        "pmp_match_results": {},
        "semantic_bins": {},
        "combo_bins": {},
    }

    for case in cases:
        _bump(coverage["profiles"], case.get("profile"))
        _bump(coverage["privileges"], case.get("privilege"))
        _bump(coverage["accesses"], case.get("access"))
        _bump(coverage["translations"], case.get("translation"))
        _bump(coverage["pmp_match_modes"], case.get("pmp_match_mode"))
        _bump(coverage["ptw_fault_levels"], case.get("ptw_fault_level"))
        _bump(coverage["preload_modes"], case.get("preload_mode"))
        _bump(coverage["security_focus"], case.get("security_focus"))
        for tag in case.get("coverage_tags") or []:
            _bump(coverage["coverage_tags"], tag)
        for semantic_bin in semantic_bins_for_case(case):
            _bump(coverage["semantic_bins"], semantic_bin)
        for combo_bin in combo_bins_for_case(case):
            _bump(coverage["combo_bins"], combo_bin)
        mseccfg = case.get("mseccfg") or {}
        _bump(coverage["smepmp_mml"], int(bool(mseccfg.get("mml"))))
        _bump(coverage["smepmp_mmwp"], int(bool(mseccfg.get("mmwp"))))
        _bump(coverage["smepmp_rlb"], int(bool(mseccfg.get("rlb"))))
        _bump(coverage["smepmp_rules"], case.get("smepmp_rule"))
        _bump(coverage["effective_privileges"], case.get("effective_privilege"))
        _bump(coverage["pmp_match_results"], case.get("pmp_match_result"))
        pte_permissions = case.get("pte_permissions") or {}
        _bump(coverage["pte_permissions"], pte_permissions.get("rwx"))
        sequence = case.get("stateful_sequence") or {}
        _bump(coverage["stateful_sequences"], sequence.get("kind"))
        _bump(coverage["stateful_mutations"], sequence.get("mutation"))
        _bump(coverage["stateful_fences"], sequence.get("fence"))

    for result in results:
        _bump(coverage["statuses"], result.get("status"))
        _bump(coverage["failure_classes"], result.get("failure_class"))

    target = _target_for_cases(cases)
    gap = coverage_gap_from_runs([run_dir], target=target)
    combo_gap = combination_gap_from_runs([run_dir], target=target, coverage_mode="pairwise")
    coverage.update(
        {
            "target": gap["target"],
            "target_bins": gap["total_target_bins"],
            "covered_bins": gap["covered_bins"],
            "covered_target_bins": gap["covered_target_bins"],
            "missing_bins": gap["missing_bins"],
            "missing_target_bins": gap["missing_target_bins"],
            "coverage_rate": gap["coverage_rate"],
            "top_gaps": gap["top_gaps"],
            "target_combo_bins": combo_gap["total_target_combo_bins"],
            "covered_combo_bins": combo_gap["covered_combo_bins"],
            "covered_target_combo_bins": combo_gap["covered_target_combo_bins"],
            "missing_combo_bins": combo_gap["missing_combo_bins"],
            "missing_target_combo_bins": combo_gap["missing_target_combo_bins"],
            "combo_coverage_rate": combo_gap["combo_coverage_rate"],
            "top_combo_gaps": combo_gap["top_combo_gaps"],
        }
    )
    return coverage


def _target_for_cases(cases: list[dict[str, Any]]) -> str:
    profiles = {str(case.get("profile") or "") for case in cases if case.get("profile")}
    if profiles and profiles <= set(XIANGSHAN_TARGETED_PROFILES):
        return XIANGSHAN_TARGETED_TARGET
    if profiles and profiles <= set(OOO_MICROARCH_PROFILES):
        return OOO_MICROARCH_TARGET
    return CORE_STATEFUL_TARGET


def write_coverage(run_dir: Path) -> Path:
    out = run_dir / "coverage" / "coverage.json"
    write_json(out, coverage_from_run(run_dir))
    return out
