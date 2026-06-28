from __future__ import annotations

from pathlib import Path
from typing import Any

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
        "schema_version": 1,
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
        "statuses": {},
        "failure_classes": {},
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
        pte_permissions = case.get("pte_permissions") or {}
        _bump(coverage["pte_permissions"], pte_permissions.get("rwx"))

    for result in results:
        _bump(coverage["statuses"], result.get("status"))
        _bump(coverage["failure_classes"], result.get("failure_class"))

    return coverage


def write_coverage(run_dir: Path) -> Path:
    out = run_dir / "coverage" / "coverage.json"
    write_json(out, coverage_from_run(run_dir))
    return out
