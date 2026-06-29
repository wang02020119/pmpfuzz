from __future__ import annotations

from pathlib import Path
from typing import Any

from .schema import read_json


def verdict_for_run(run_dir: Path) -> dict[str, Any]:
    cases = _cases_by_name(run_dir)
    results_by_case = _results_by_case(run_dir)
    evidence = []
    related = []

    for name, results in sorted(results_by_case.items()):
        case = cases.get(name, {})
        by_dut = {result.get("dut"): result for result in results}
        boom = by_dut.get("boom-clean")
        spike = by_dut.get("spike")
        rocket = by_dut.get("rocket-clean")
        stateful = _stateful_verdict_evidence(name, case, results)
        if stateful:
            if stateful["kind"] == "experimental_no_fence_observation":
                related.append(stateful)
            else:
                evidence.append(stateful)
        smepmp = _smepmp_verdict_evidence(name, case, results)
        if smepmp:
            evidence.append(smepmp)
        if _is_confirmed_boom_ptw_hang(case, spike, rocket, boom):
            evidence.append(
                {
                    "case": name,
                    "profile": case.get("profile"),
                    "boom_failure_class": boom.get("failure_class"),
                    "expected": "load access fault",
                    "reason": "Spike and Rocket pass while BOOM hangs on PTW PMP-denied U-mode Sv39 load",
                }
            )
        if _is_confirmed_boom_pmp_fetch_boundary_failure(case, spike, rocket, boom):
            evidence.append(
                {
                    "kind": "confirmed_pmp_fetch_boundary_failure",
                    "case": name,
                    "profile": case.get("profile"),
                    "boom_failure_class": boom.get("failure_class"),
                    "observed_tohost": boom.get("observed_tohost"),
                    "expected": "successful fetch and ecall completion",
                    "reason": "Spike and Rocket pass while BOOM fails an allowed PMP NA4 fetch boundary probe",
                }
            )
        if _is_related_wrong_mcause(case, boom):
            related.append(
                {
                    "case": name,
                    "profile": case.get("profile"),
                    "observed_mcause": boom.get("observed_mcause"),
                    "reason": "related S/U wrong exception evidence, not counted as the hang verdict",
                }
            )

    side_effect = [item for item in evidence if item.get("kind") == "confirmed_side_effect_failure"]
    stale = [item for item in evidence if item.get("kind") == "confirmed_stale_permission_failure"]
    smepmp = [item for item in evidence if item.get("kind") == "confirmed_smepmp_permission_failure"]
    experimental = [item for item in related if item.get("kind") == "experimental_no_fence_observation"]
    if side_effect:
        return {
            "verdict": "confirmed_side_effect_failure",
            "has_vulnerability": True,
            "impact": "forbidden_memory_side_effect",
            "expected": "trap without memory side effect",
            "evidence": side_effect,
            "related_evidence": related,
        }
    if stale:
        return {
            "verdict": "confirmed_stale_permission_failure",
            "has_vulnerability": True,
            "impact": "stale_permission_reuse",
            "expected": "post-mutation access must trap after required fence",
            "evidence": stale,
            "related_evidence": related,
        }
    if smepmp:
        return {
            "verdict": "confirmed_smepmp_permission_failure",
            "has_vulnerability": True,
            "impact": "wrong_smepmp_permission",
            "expected": "Smepmp permission behavior must match the reference oracle",
            "evidence": smepmp,
            "related_evidence": related,
        }
    fetch_boundary = [item for item in evidence if item.get("kind") == "confirmed_pmp_fetch_boundary_failure"]
    if fetch_boundary:
        return {
            "verdict": "confirmed_pmp_fetch_boundary_failure",
            "has_vulnerability": True,
            "impact": "denial_of_service / incorrect_execute_permission_handling",
            "expected": "successful fetch and ecall completion",
            "evidence": fetch_boundary,
            "related_evidence": related,
        }
    if evidence:
        return {
            "verdict": "confirmed_new_failure_mode",
            "has_vulnerability": True,
            "impact": "denial_of_service / missing_precise_trap",
            "expected": "load access fault",
            "evidence": evidence,
            "related_evidence": related,
        }
    if experimental:
        return {
            "verdict": "experimental_no_fence_observation",
            "has_vulnerability": False,
            "impact": None,
            "expected": "no-fence behavior is recorded but not treated as confirmed vulnerability",
            "evidence": [],
            "related_evidence": experimental,
        }
    if related:
        return {
            "verdict": "related_wrong_exception_evidence",
            "has_vulnerability": True,
            "impact": "wrong_exception_cause",
            "expected": "load access fault",
            "evidence": [],
            "related_evidence": related,
        }
    return {
        "verdict": "no_confirmed_vulnerability",
        "has_vulnerability": False,
        "impact": None,
        "expected": None,
        "evidence": [],
        "related_evidence": [],
    }


def _stateful_verdict_evidence(
    name: str,
    case: dict[str, Any],
    results: list[dict[str, Any]],
) -> dict[str, Any] | None:
    sequence = case.get("stateful_sequence")
    if not sequence:
        return None
    all_failing = [
        result
        for result in results
        if result.get("failure_class") in _STATEFUL_FAILURE_CLASSES
        and (result.get("oracle_applicability") or "valid") not in {"unsupported", "infra_unadapted"}
    ]
    if not all_failing:
        return None
    if sequence.get("fence") == "no-fence-experimental":
        return {
            "kind": "experimental_no_fence_observation",
            "case": name,
            "profile": case.get("profile"),
            "failure_classes": sorted({result.get("failure_class") for result in all_failing}),
            "reason": "no-fence stateful stale result is recorded as experimental observation",
        }
    failing = [result for result in all_failing if _is_valid_oracle_result(result)]
    if not failing:
        return None
    spike_passed = any(
        result.get("dut") == "spike" and result.get("status") == "pass" and _is_valid_oracle_result(result)
        for result in results
    )
    non_spike_failures = [result for result in failing if result.get("dut") != "spike"]
    if not spike_passed or not non_spike_failures:
        return None
    side_effect_classes = {"forbidden_side_effect", "missing_expected_side_effect"}
    if any(result.get("failure_class") in side_effect_classes for result in non_spike_failures):
        return {
            "kind": "confirmed_side_effect_failure",
            "case": name,
            "profile": case.get("profile"),
            "failure_classes": sorted({result.get("failure_class") for result in non_spike_failures}),
            "reason": "reference passed while DUT reported forbidden or missing memory side effect",
        }
    return {
        "kind": "confirmed_stale_permission_failure",
        "case": name,
        "profile": case.get("profile"),
        "failure_classes": sorted({result.get("failure_class") for result in non_spike_failures}),
        "reason": "reference passed while DUT reused stale permission after mutation/fence",
    }


_STATEFUL_FAILURE_CLASSES = {
    "forbidden_side_effect",
    "missing_expected_side_effect",
    "stale_pmp_permission",
    "stale_tlb_permission",
    "stale_ptw_permission",
}


def _smepmp_verdict_evidence(
    name: str,
    case: dict[str, Any],
    results: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not _is_smepmp_case(case):
        return None
    spike_passed = any(
        result.get("dut") == "spike" and result.get("status") == "pass" and _is_valid_oracle_result(result)
        for result in results
    )
    if not spike_passed:
        return None
    failures = [
        result
        for result in results
        if result.get("dut") != "spike"
        and _is_valid_oracle_result(result)
        and result.get("status") not in {"pass", "setup_unsupported"}
        and result.get("failure_class") not in {"setup_unsupported", "unsupported", "infra_unadapted"}
    ]
    if not failures:
        return None
    return {
        "kind": "confirmed_smepmp_permission_failure",
        "case": name,
        "profile": case.get("profile"),
        "smepmp_rule": case.get("smepmp_rule"),
        "failure_classes": sorted({str(result.get("failure_class") or result.get("status")) for result in failures}),
        "failing_duts": sorted({str(result.get("dut")) for result in failures}),
        "expected": "Smepmp permission behavior must match the reference oracle",
        "reason": "Spike passes while a capability-valid DUT reports a Smepmp permission mismatch",
    }


def _is_smepmp_case(case: dict[str, Any]) -> bool:
    if case.get("smepmp_rule"):
        return True
    if str(case.get("profile") or "").startswith("smepmp"):
        return True
    mseccfg = case.get("mseccfg") or {}
    return any(bool(mseccfg.get(bit)) for bit in ("mml", "mmwp", "rlb"))


def _cases_by_name(run_dir: Path) -> dict[str, dict[str, Any]]:
    cases = {}
    for case_path in sorted((run_dir / "cases").glob("*/case.json")):
        case = read_json(case_path)
        cases[case["name"]] = case
    return cases


def _results_by_case(run_dir: Path) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for result_path in sorted((run_dir / "results").glob("*/result.json")):
        result = read_json(result_path)
        grouped.setdefault(result["name"], []).append(result)
    return grouped


def _is_confirmed_boom_ptw_hang(
    case: dict[str, Any],
    spike: dict[str, Any] | None,
    rocket: dict[str, Any] | None,
    boom: dict[str, Any] | None,
) -> bool:
    if not spike or not rocket or not boom:
        return False
    return (
        _is_valid_oracle_result(spike)
        and _is_valid_oracle_result(rocket)
        and _is_valid_oracle_result(boom)
        and spike.get("status") == "pass"
        and rocket.get("status") == "pass"
        and boom.get("failure_class") == "pipeline_hung"
        and case.get("access") == "load"
        and case.get("privilege") == "U"
        and case.get("translation") == "sv39"
        and case.get("ptw_fault_level") == "L1"
        and case.get("preload_mode") == "cold"
        and bool(case.get("mxr"))
    )


def _is_confirmed_boom_pmp_fetch_boundary_failure(
    case: dict[str, Any],
    spike: dict[str, Any] | None,
    rocket: dict[str, Any] | None,
    boom: dict[str, Any] | None,
) -> bool:
    if not spike or not rocket or not boom:
        return False
    return (
        _is_valid_oracle_result(spike)
        and _is_valid_oracle_result(rocket)
        and _is_valid_oracle_result(boom)
        and spike.get("status") == "pass"
        and rocket.get("status") == "pass"
        and boom.get("status") not in {"pass", "setup_unsupported"}
        and boom.get("failure_class") in {"sim_assert", "tohost_fail", "infra_failure"}
        and case.get("profile") == "pmp-boundary"
        and case.get("translation") == "bare"
        and case.get("access") == "fetch"
        and case.get("pmp_match_mode") == "na4"
        and bool(case.get("expected_allowed"))
    )


def _is_related_wrong_mcause(case: dict[str, Any], boom: dict[str, Any] | None) -> bool:
    if not boom:
        return False
    return (
        _is_valid_oracle_result(boom)
        and case.get("translation") == "sv39"
        and case.get("ptw_fault_level") is not None
        and boom.get("failure_class") == "wrong_mcause"
        and boom.get("observed_mcause") == 13
    )


def _is_valid_oracle_result(result: dict[str, Any]) -> bool:
    return (result.get("oracle_applicability") or "valid") == "valid"
