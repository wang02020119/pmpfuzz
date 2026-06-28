from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .oracle import evaluate_scenario
from .pmp import PmpEntry
from .scenario import PmpScenario


SCHEMA_VERSION = 2


def write_json(path: Path, data: dict[str, Any] | list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="ascii")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="ascii"))


def pmp_entry_to_dict(entry: PmpEntry) -> dict[str, Any]:
    return {
        "index": entry.index,
        "address_mode": entry.address_mode.name.lower(),
        "pmpaddr": f"0x{entry.pmpaddr:x}",
        "read": entry.read,
        "write": entry.write,
        "execute": entry.execute,
        "locked": entry.locked,
    }


def scenario_to_case_dict(scenario: PmpScenario, *, seed: int, index: int) -> dict[str, Any]:
    outcome = evaluate_scenario(scenario)
    data: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "name": scenario.name,
        "seed": seed,
        "index": index,
        "profile": scenario.profile,
        "privilege": scenario.privilege.value,
        "access": scenario.probe.access.value,
        "address": f"0x{scenario.probe.effective_address():x}",
        "physical_address": f"0x{scenario.probe.physical_address:x}",
        "virtual_address": f"0x{scenario.probe.virtual_address:x}" if scenario.probe.virtual_address is not None else None,
        "translation": scenario.translation.value,
        "mprv": scenario.mprv,
        "mpp": scenario.mpp.value,
        "sum_enabled": scenario.sum_enabled,
        "mxr": scenario.mxr,
        "sfence_vma": scenario.sfence_vma,
        "mseccfg": asdict(scenario.mseccfg),
        "pmp_entries": [pmp_entry_to_dict(entry) for entry in scenario.entries],
        "coverage_tags": list(scenario.coverage_tags),
        "ptw_fault_level": scenario.ptw_fault_level,
        "preload_mode": scenario.preload_mode,
        "pmp_match_mode": scenario.pmp_match_mode,
        "pte_permissions": scenario.pte_permissions,
        "security_focus": scenario.security_focus,
        "expected": {
            "allowed": outcome.allowed,
            "trap_cause": int(outcome.trap_cause) if outcome.trap_cause is not None else None,
            "stage": outcome.stage,
            "reason": outcome.reason,
            "physical_address": f"0x{outcome.physical_address:x}" if outcome.physical_address is not None else None,
        },
    }
    if scenario.sv39 is not None:
        data["sv39"] = {
            "virtual_page": f"0x{scenario.sv39.virtual_page:x}",
            "physical_page": f"0x{scenario.sv39.physical_page:x}",
            "root_table": f"0x{scenario.sv39.root_table:x}",
            "walk_addresses": [f"0x{address:x}" for address in scenario.sv39.walk_addresses],
            "pte": asdict(scenario.sv39.pte),
        }
    return data


def result_to_dict(
    *,
    case: dict[str, Any],
    dut: str,
    status: str,
    elapsed_seconds: float,
    returncode: int | None,
    log: Path,
    reason: str | None,
    observed_tohost: int | None = None,
    observed_mcause: int | None = None,
    observed_mtval: int | None = None,
    failure_class: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "name": case["name"],
        "profile": case["profile"],
        "dut": dut,
        "status": status,
        "failure_class": failure_class,
        "expected_allowed": case["expected"]["allowed"],
        "expected_cause": case["expected"]["trap_cause"],
        "expected_stage": case["expected"]["stage"],
        "elapsed_seconds": elapsed_seconds,
        "returncode": returncode,
        "observed_tohost": observed_tohost,
        "observed_mcause": observed_mcause,
        "observed_mtval": observed_mtval,
        "log": str(log),
        "reason": reason,
    }


def aggregate_results(run_dir: Path) -> dict[str, Any]:
    results = []
    for result_path in sorted((run_dir / "results").glob("*/result.json")):
        results.append(read_json(result_path))

    statuses: dict[str, int] = {}
    profiles: dict[str, int] = {}
    failure_classes: dict[str, int] = {}
    for result in results:
        statuses[result["status"]] = statuses.get(result["status"], 0) + 1
        profiles[result["profile"]] = profiles.get(result["profile"], 0) + 1
        failure_class = result.get("failure_class") or ""
        if failure_class:
            failure_classes[failure_class] = failure_classes.get(failure_class, 0) + 1

    total = len(results)
    nonpass = sum(1 for result in results if result["status"] not in {"pass", "setup_unsupported"})
    elapsed = sum(float(result.get("elapsed_seconds") or 0.0) for result in results)
    return {
        "schema_version": SCHEMA_VERSION,
        "total": total,
        "passed": statuses.get("pass", 0),
        "nonpass": nonpass,
        "statuses": statuses,
        "profiles": profiles,
        "failure_classes": failure_classes,
        "avg_elapsed_seconds": round(elapsed / total, 4) if total else None,
        "results": results,
    }


def write_aggregate(run_dir: Path) -> dict[str, Any]:
    aggregate = aggregate_results(run_dir)
    write_json(run_dir / "aggregate.json", aggregate)
    return aggregate
