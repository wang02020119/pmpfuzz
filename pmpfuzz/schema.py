from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .oracle import evaluate_scenario
from .pmp import Access, PmpEntry, PmpModel
from .scenario import M_DATA_BASE, M_DATA_SIZE, M_TEXT_BASE, M_TEXT_SIZE, SU_CODE_BASE, SU_CODE_SIZE, PmpScenario
from .semantic_coverage import combo_bins_for_case, semantic_bins_for_case
from .capabilities import oracle_applicability_for_case, required_capabilities_for_case


SCHEMA_VERSION = 2
STATEFUL_SCHEMA_VERSION = 3


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
    pmp_decision = PmpModel(scenario.entries, scenario.mseccfg).check(
        privilege=scenario.privilege,
        access=scenario.probe.access,
        physical_address=scenario.probe.physical_address,
        size=scenario.probe.size,
        mprv=scenario.mprv,
        mpp=scenario.mpp,
    )
    expected_allowed = outcome.allowed
    expected_cause = int(outcome.trap_cause) if outcome.trap_cause is not None else None
    expected_stage = outcome.stage
    expected_reason = outcome.reason
    expected_pa = f"0x{outcome.physical_address:x}" if outcome.physical_address is not None else None
    if scenario.stateful_sequence is not None:
        final = scenario.stateful_sequence.get("expected_final")
        final_cause = scenario.stateful_sequence.get("expected_cause")
        expected_allowed = final == "store_side_effect"
        expected_cause = int(final_cause) if final_cause is not None else None
        expected_stage = "stateful_final"
        expected_reason = f"stateful final outcome: {final}"
        expected_pa = f"0x{scenario.probe.physical_address:x}"
    pmp_locked, pmp_allow = _pmp_metadata_for_scenario(scenario)
    data: dict[str, Any] = {
        "schema_version": STATEFUL_SCHEMA_VERSION if scenario.stateful_sequence else SCHEMA_VERSION,
        "name": scenario.name,
        "seed": seed,
        "index": index,
        "profile": scenario.profile,
        "privilege": scenario.privilege.value,
        "access": scenario.probe.access.value,
        "address": f"0x{scenario.probe.effective_address():x}",
        "physical_address": f"0x{scenario.probe.physical_address:x}",
        "virtual_address": f"0x{scenario.probe.virtual_address:x}" if scenario.probe.virtual_address is not None else None,
        "probe_offset": scenario.probe.offset_name,
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
        "pmp_match_result": "matched" if pmp_decision.match_index is not None else "unmatched",
        "pmp_locked": pmp_locked,
        "pmp_allow": pmp_allow,
        "effective_privilege": pmp_decision.effective_privilege.value,
        "expected_allowed": expected_allowed,
        "pte_permissions": scenario.pte_permissions,
        "security_focus": scenario.security_focus,
        "smepmp_rule": scenario.smepmp_rule,
        "required_capabilities": [],
        "oracle_applicability": "valid",
        "expected": {
            "allowed": expected_allowed,
            "trap_cause": expected_cause,
            "stage": expected_stage,
            "reason": expected_reason,
            "physical_address": expected_pa,
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
    if scenario.stateful_sequence is not None:
        data["stateful_sequence"] = scenario.stateful_sequence
    data["required_capabilities"] = required_capabilities_for_case(data)
    data["oracle_applicability"] = oracle_applicability_for_case(data)
    data["semantic_bins"] = semantic_bins_for_case(data)
    data["combo_bins"] = combo_bins_for_case(data)
    return data


def _pmp_metadata_for_scenario(scenario: PmpScenario) -> tuple[bool, bool]:
    relevant = [
        entry
        for entry in scenario.entries
        if entry.address_mode.name.lower() != "off"
        and not _is_harness_entry(entry)
    ]
    locked = any(entry.locked for entry in relevant)
    decision = PmpModel(scenario.entries, scenario.mseccfg).check(
        privilege=scenario.privilege,
        access=scenario.probe.access,
        physical_address=scenario.probe.physical_address,
        size=scenario.probe.size,
        mprv=scenario.mprv,
        mpp=scenario.mpp,
    )
    matched = next((entry for entry in scenario.entries if entry.index == decision.match_index), None)
    if matched is None:
        return locked, False
    return locked, _entry_allows_access(matched, scenario.probe.access)


def _is_harness_entry(entry: PmpEntry) -> bool:
    if entry.address_mode.name.lower() != "napot":
        return False
    harness_regions = {
        PmpEntry.encode_napot(base=0x80000000, size=0x4000),
        PmpEntry.encode_napot(base=M_TEXT_BASE, size=M_TEXT_SIZE),
        PmpEntry.encode_napot(base=M_DATA_BASE, size=M_DATA_SIZE),
        PmpEntry.encode_napot(base=SU_CODE_BASE, size=SU_CODE_SIZE),
    }
    return entry.pmpaddr in harness_regions


def _entry_allows_access(entry: PmpEntry, access: Access) -> bool:
    if access == Access.LOAD:
        return entry.read
    if access == Access.STORE:
        return entry.write
    if access == Access.FETCH:
        return entry.execute
    raise ValueError(f"unsupported access: {access}")


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
    oracle_applicability: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "name": case["name"],
        "profile": case["profile"],
        "dut": dut,
        "status": status,
        "failure_class": failure_class,
        "required_capabilities": list(case.get("required_capabilities") or required_capabilities_for_case(case)),
        "oracle_applicability": oracle_applicability or case.get("oracle_applicability") or "valid",
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
    oracle_applicability: dict[str, int] = {}
    for result in results:
        statuses[result["status"]] = statuses.get(result["status"], 0) + 1
        profiles[result["profile"]] = profiles.get(result["profile"], 0) + 1
        applicability = result.get("oracle_applicability") or "unknown"
        oracle_applicability[applicability] = oracle_applicability.get(applicability, 0) + 1
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
        "oracle_applicability": oracle_applicability,
        "avg_elapsed_seconds": round(elapsed / total, 4) if total else None,
        "results": results,
    }


def write_aggregate(run_dir: Path) -> dict[str, Any]:
    aggregate = aggregate_results(run_dir)
    write_json(run_dir / "aggregate.json", aggregate)
    return aggregate
