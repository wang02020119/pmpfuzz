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
        if _is_related_wrong_mcause(case, boom):
            related.append(
                {
                    "case": name,
                    "profile": case.get("profile"),
                    "observed_mcause": boom.get("observed_mcause"),
                    "reason": "related S/U wrong exception evidence, not counted as the hang verdict",
                }
            )

    if evidence:
        return {
            "verdict": "confirmed_new_failure_mode",
            "has_vulnerability": True,
            "impact": "denial_of_service / missing_precise_trap",
            "expected": "load access fault",
            "evidence": evidence,
            "related_evidence": related,
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
        spike.get("status") == "pass"
        and rocket.get("status") == "pass"
        and boom.get("failure_class") == "pipeline_hung"
        and case.get("access") == "load"
        and case.get("privilege") == "U"
        and case.get("translation") == "sv39"
        and case.get("ptw_fault_level") == "L1"
        and case.get("preload_mode") == "cold"
        and bool(case.get("mxr"))
    )


def _is_related_wrong_mcause(case: dict[str, Any], boom: dict[str, Any] | None) -> bool:
    if not boom:
        return False
    return (
        case.get("translation") == "sv39"
        and case.get("ptw_fault_level") is not None
        and boom.get("failure_class") == "wrong_mcause"
        and boom.get("observed_mcause") == 13
    )
