from __future__ import annotations

from pathlib import Path
from typing import Any

from .capabilities import oracle_applicability_for_case
from .coverage_qualification import (
    collect_execution_evidence,
    load_capability_map,
    load_case_map,
    load_results,
)
from .dut_coverage import dut_coverage_from_run
from .schema import read_json, write_json
from .semantic_coverage import (
    CORE_STATEFUL_TARGET,
    OOO_MICROARCH_PROFILES,
    OOO_MICROARCH_TARGET,
    XIANGSHAN_TARGETED_PROFILES,
    XIANGSHAN_TARGETED_TARGET,
    _capability_case_for_scenario,
    _capability_fingerprint,
    _target_candidates,
    combo_bins_for_case,
    contract_predicates_for_case,
    semantic_bins_for_case,
    target_contract_predicates,
    target_semantic_bins,
    target_combo_bins,
)
from .scenario import ScenarioGenerator


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

    # ---- manifest coverage (unchanged logic, preserved) --------------------
    coverage: dict[str, Any] = {
        "schema_version": 5,
        "legacy_top_level_basis": "generated_manifest",
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
        "contract_predicates": {},
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
        for predicate in contract_predicates_for_case(case):
            _bump(coverage["contract_predicates"], predicate)
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

    # ---- manifest coverage gap (unchanged) ----------------------------------
    target = _target_for_cases(cases)
    gap = _manifest_gap(run_dir, cases, target)
    combo_gap = _manifest_combo_gap(run_dir, cases, target)
    predicate_gap = _manifest_predicate_gap(run_dir, cases, target)
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
            "target_predicates": predicate_gap["total_target_predicates"],
            "covered_predicates": predicate_gap["covered_predicates"],
            "covered_target_predicates": predicate_gap["covered_target_predicates"],
            "missing_predicates": predicate_gap["missing_predicates"],
            "missing_target_predicates": predicate_gap["missing_target_predicates"],
            "predicate_coverage_rate": predicate_gap["predicate_coverage_rate"],
            "top_predicate_gaps": predicate_gap["top_predicate_gaps"],
            "dut_whitebox": dut_coverage_from_run(run_dir),
        }
    )

    # ---- execution-qualified coverage ---------------------------------------
    exec_coverage = _build_execution_coverage(run_dir, cases)
    coverage["execution_coverage"] = exec_coverage

    return coverage


def _target_for_cases(cases: list[dict[str, Any]]) -> str:
    profiles = {str(case.get("profile") or "") for case in cases if case.get("profile")}
    if profiles and profiles <= set(XIANGSHAN_TARGETED_PROFILES):
        return XIANGSHAN_TARGETED_TARGET
    if profiles and profiles <= set(OOO_MICROARCH_PROFILES):
        return OOO_MICROARCH_TARGET
    return CORE_STATEFUL_TARGET


def _manifest_gap(run_dir: Path, cases: list[dict[str, Any]], target: str) -> dict[str, Any]:
    target_bins = set(target_semantic_bins(target=target))
    observed: set[str] = set()
    for case in cases:
        observed.update(semantic_bins_for_case(case))
    covered = observed & target_bins
    missing = target_bins - covered
    rate = round(len(covered) / len(target_bins), 6) if target_bins else 1.0
    return {
        "target": target,
        "total_target_bins": len(target_bins),
        "observed_bins": sorted(observed),
        "covered_bins": sorted(covered),
        "covered_target_bins": len(covered),
        "missing_bins": sorted(missing),
        "missing_target_bins": len(missing),
        "coverage_rate": rate,
        "top_gaps": sorted(missing)[:25],
    }


def _manifest_combo_gap(run_dir: Path, cases: list[dict[str, Any]], target: str) -> dict[str, Any]:
    target_bins = set(target_combo_bins(target=target, coverage_mode="pairwise"))
    observed: set[str] = set()
    for case in cases:
        observed.update(combo_bins_for_case(case, coverage_mode="pairwise"))
    covered = observed & target_bins
    missing = target_bins - covered
    rate = round(len(covered) / len(target_bins), 6) if target_bins else 1.0
    return {
        "total_target_combo_bins": len(target_bins),
        "observed_combo_bins": sorted(observed),
        "covered_combo_bins": sorted(covered),
        "covered_target_combo_bins": len(covered),
        "missing_combo_bins": sorted(missing),
        "missing_target_combo_bins": len(missing),
        "combo_coverage_rate": rate,
        "top_combo_gaps": sorted(missing)[:25],
    }


def _manifest_predicate_gap(run_dir: Path, cases: list[dict[str, Any]], target: str) -> dict[str, Any]:
    target_preds = set(target_contract_predicates(target=target))
    observed: set[str] = set()
    for case in cases:
        observed.update(contract_predicates_for_case(case))
    covered = observed & target_preds
    missing = target_preds - covered
    rate = round(len(covered) / len(target_preds), 6) if target_preds else 1.0
    return {
        "total_target_predicates": len(target_preds),
        "observed_predicates": sorted(observed),
        "covered_predicates": sorted(covered),
        "covered_target_predicates": len(covered),
        "missing_predicates": sorted(missing),
        "missing_target_predicates": len(missing),
        "predicate_coverage_rate": rate,
        "top_predicate_gaps": sorted(missing)[:25],
    }


# ---------------------------------------------------------------------------
# execution-qualified coverage
# ---------------------------------------------------------------------------


def _build_execution_coverage(run_dir: Path, cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the execution_coverage block (schema v5)."""
    capability_map = load_capability_map(run_dir)
    target = _target_for_cases(cases)

    if capability_map is None:
        # No capability file → all DUTs unavailable
        return {
            "schema_version": 1,
            "coverage_model": "execution-qualified-capability-scoped-v1",
            "by_dut": {
                "unknown": _unavailable_entry("missing_dut_capabilities"),
            },
        }

    by_dut: dict[str, Any] = {}
    for dut_name, capability in capability_map.items():
        if not capability.get("available"):
            by_dut[dut_name] = _unavailable_entry("dut_unavailable")
            continue

        # Enumerate capability-scoped target candidates once (shared logic)
        targets = compute_coverage_targets(
            target=target, capability=capability,
            include_experimental=False, seed=20260628,
        )
        target_sem = targets["semantic"]["target_bins"]
        target_pair = targets["pairwise"]["target_bins"]
        target_trip = targets["security_triples"]["target_bins"]
        target_pred = targets["predicates"]["target_bins"]

        # Use unified evidence collector (single source of truth)
        evidence = collect_execution_evidence([run_dir], dut=dut_name)
        summary = evidence.summary
        eligible_cases = evidence.eligible_cases

        qualification = {
            "total_results": summary.total_results,
            "eligible_results": summary.eligible_results,
            "valid_mismatches": summary.valid_mismatches,
            "excluded_results": summary.excluded_results,
            "missing_results": summary.missing_results,
            "orphan_results": summary.orphan_results,
            "excluded_by_reason": dict(summary.excluded_by_reason),
        }

        obs_sem: set[str] = set()
        obs_pair: set[str] = set()
        obs_trip: set[str] = set()
        obs_pred: set[str] = set()
        for case in eligible_cases:
            obs_sem.update(semantic_bins_for_case(case))
            obs_pair.update(b for b in combo_bins_for_case(case) if b.startswith("combo2:"))
            obs_trip.update(b for b in combo_bins_for_case(case) if b.startswith("combo3:"))
            obs_pred.update(contract_predicates_for_case(case))

        by_dut[dut_name] = {
            "available": True,
            "capability_fingerprint": _capability_fingerprint(capability),
            "qualification": qualification,
            "semantic": _make_coverage_section(target_sem, obs_sem),
            "pairwise": _make_coverage_section(target_pair, obs_pair),
            "security_triples": _make_coverage_section(target_trip, obs_trip),
            "predicates": _make_coverage_section(target_pred, obs_pred),
        }

    return {
        "schema_version": 1,
        "coverage_model": "execution-qualified-capability-scoped-v1",
        "by_dut": by_dut,
    }


def _make_coverage_section(target_bins: set[str], observed_bins: set[str]) -> dict[str, Any]:
    covered = observed_bins & target_bins
    missing = target_bins - covered
    total = len(target_bins)
    if total == 0:
        return {
            "total_target_bins": 0,
            "covered_target_bins": 0,
            "missing_target_bins": 0,
            "coverage_rate": None,
            "covered_bins": [],
            "missing_bins": [],
        }
    rate = round(len(covered) / total, 6)
    return {
        "total_target_bins": total,
        "covered_target_bins": len(covered),
        "missing_target_bins": len(missing),
        "coverage_rate": rate,
        "covered_bins": sorted(covered),
        "missing_bins": sorted(missing),
    }


def _empty_coverage_section() -> dict[str, Any]:
    return {
        "total_target_bins": 0,
        "covered_target_bins": 0,
        "missing_target_bins": 0,
        "coverage_rate": None,
        "covered_bins": [],
        "missing_bins": [],
    }


def _unavailable_entry(reason: str) -> dict[str, Any]:
    return {
        "available": False,
        "unavailable_reason": reason,
        "qualification": {
            "total_results": 0,
            "eligible_results": 0,
            "valid_mismatches": 0,
            "excluded_results": 0,
            "excluded_by_reason": {},
        },
    }


def write_coverage(run_dir: Path) -> Path:
    out = run_dir / "coverage" / "coverage.json"
    write_json(out, coverage_from_run(run_dir))
    return out


# ---------------------------------------------------------------------------
# Shared coverage target construction — single source of truth for
# denominator logic used by both execution-coverage and timeline.
# ---------------------------------------------------------------------------


def _capability_fingerprint_from_map(capability: dict[str, Any]) -> str:
    """Return a stable fingerprint string for a capability dict."""
    from .semantic_coverage import _capability_fingerprint
    return _capability_fingerprint(capability)


def compute_coverage_targets(
    *,
    target: str = CORE_STATEFUL_TARGET,
    capability: dict[str, Any],
    include_experimental: bool = False,
    seed: int = 20260628,
) -> dict[str, Any]:
    """Compute the four coverage target bin sets for a given DUT capability.

    Returns a dict with keys ``semantic``, ``pairwise``, ``security_triples``,
    ``predicates``, each containing the bin-set metadata as returned by
    :func:`_make_coverage_section`.
    """
    candidates = _target_candidates(
        target=target,
        include_experimental=include_experimental,
        seed=seed,
        capability=capability,
    )
    target_sem = {b for c in candidates for b in c["semantic_bins"]}
    target_pair = {b for c in candidates for b in c["combo_bins"] if b.startswith("combo2:")}
    target_trip = {b for c in candidates for b in c["combo_bins"] if b.startswith("combo3:")}
    target_pred = {b for c in candidates for b in c["contract_predicates"]}

    return {
        "capability_fingerprint": _capability_fingerprint_from_map(capability),
        "target": target,
        "include_experimental": include_experimental,
        "seed": seed,
        "total_candidates": len(candidates),
        "semantic": {"target_bins": target_sem, "total": len(target_sem)},
        "pairwise": {"target_bins": target_pair, "total": len(target_pair)},
        "security_triples": {"target_bins": target_trip, "total": len(target_trip)},
        "predicates": {"target_bins": target_pred, "total": len(target_pred)},
    }
