from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .oracle import contract_trace_for_scenario, evaluate_scenario, final_stateful_scenario, normalized_stateful_sequence
from .pmp import Access, PmpEntry, PmpModel
from .scenario import M_DATA_BASE, M_DATA_SIZE, M_TEXT_BASE, M_TEXT_SIZE, SU_CODE_BASE, SU_CODE_SIZE, PmpScenario
from .scenario_codec import scenario_hash, scenario_to_spec
from .semantic_coverage import (
    combo_bins_for_case,
    contract_predicates_for_case,
    derived_pmp_match_mode_for_case,
    semantic_bins_for_case,
)
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


def scenario_to_case_dict(
    scenario: PmpScenario,
    *,
    seed: int,
    index: int,
    generator_variant: str = "full",
    generation_seed: int | None = None,
    scenario_index: int | None = None,
    mutation_operator: str = "root",
    continuous_sequence: int | None = None,
) -> dict[str, Any]:
    spec = scenario_to_spec(scenario)
    spec_hash = scenario_hash(spec)
    outcome = evaluate_scenario(scenario)
    normalized_sequence = normalized_stateful_sequence(scenario)
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
    if normalized_sequence is not None:
        final_scenario = final_stateful_scenario(scenario)
        final_outcome = evaluate_scenario(final_scenario)
        expected_allowed = final_outcome.allowed
        expected_cause = int(final_outcome.trap_cause) if final_outcome.trap_cause is not None else None
        expected_stage = "stateful_final"
        expected_reason = f"stateful final outcome: {normalized_sequence.get('expected_final')}"
        expected_pa = (
            f"0x{final_outcome.physical_address:x}" if final_outcome.physical_address is not None else None
        )
    pmp_locked, pmp_allow = _pmp_metadata_for_scenario(scenario)
    pte_permissions = scenario.pte_permissions
    if scenario.sv39 is not None:
        pte = scenario.sv39.pte
        pte_permissions = {
            "rwx": ("r" if pte.read else "-") + ("w" if pte.write else "-") + ("x" if pte.execute else "-"),
            "user": pte.user,
            "accessed": pte.accessed,
            "dirty": pte.dirty,
            "valid": pte.valid,
        }
    data: dict[str, Any] = {
        "schema_version": STATEFUL_SCHEMA_VERSION if normalized_sequence else SCHEMA_VERSION,
        "name": scenario.name,
        "seed": seed,
        "index": index,
        "generator_variant": str(generator_variant),
        "generation_seed": int(seed if generation_seed is None else generation_seed),
        "scenario_index": int(index if scenario_index is None else scenario_index),
        "continuous_sequence": continuous_sequence,
        "mutation_operator": str(mutation_operator),
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
        "ad_update_mode": scenario.ad_update_mode.value,
        "mseccfg": asdict(scenario.mseccfg),
        "pmp_entries": [pmp_entry_to_dict(entry) for entry in scenario.entries],
        "coverage_tags": list(scenario.coverage_tags),
        "ptw_fault_level": scenario.ptw_fault_level,
        "preload_mode": scenario.preload_mode,
        "pmp_match_mode": None,
        "pmp_match_result": "matched" if pmp_decision.match_index is not None else "unmatched",
        "pmp_locked": pmp_locked,
        "pmp_allow": pmp_allow,
        "effective_privilege": pmp_decision.effective_privilege.value,
        "expected_allowed": expected_allowed,
        "pte_permissions": pte_permissions,
        "security_focus": scenario.security_focus,
        "smepmp_rule": scenario.smepmp_rule,
        "required_capabilities": [],
        "oracle_applicability": "valid",
        "scenario_spec": spec,
        "scenario_hash": spec_hash,
        "expected": {
            "allowed": expected_allowed,
            "trap_cause": expected_cause,
            "stage": expected_stage,
            "reason": expected_reason,
            "physical_address": expected_pa,
        },
        "contract_trace": contract_trace_for_scenario(scenario),
    }
    data["pmp_match_mode"] = derived_pmp_match_mode_for_case(data)
    if scenario.sv39 is not None:
        data["sv39"] = {
            "virtual_page": f"0x{scenario.sv39.virtual_page:x}",
            "physical_page": f"0x{scenario.sv39.physical_page:x}",
            "root_table": f"0x{scenario.sv39.root_table:x}",
            "walk_addresses": [f"0x{address:x}" for address in scenario.sv39.walk_addresses],
            "pte": asdict(scenario.sv39.pte),
        }
    if normalized_sequence is not None:
        data["stateful_sequence"] = normalized_sequence
    data["required_capabilities"] = required_capabilities_for_case(data)
    data["oracle_applicability"] = oracle_applicability_for_case(data)
    data["semantic_bins"] = semantic_bins_for_case(data)
    data["combo_bins"] = combo_bins_for_case(data)
    data["contract_predicates"] = contract_predicates_for_case(data)
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
    observed_mepc_tag: int | None = None,
    observed_mtval_fingerprint: int | None = None,
    observed_event: str | None = None,
    observed_phase: str | None = None,
    observed_stage: str | None = None,
    observed_ptw_level: str | None = None,
    observed_fault_address: int | None = None,
    observed_probe_vaddr: int | None = None,
    observation_valid: bool = False,
    stage_verified: bool = False,
    failure_class: str | None = None,
    oracle_applicability: str | None = None,
    hpm_manifest: dict[str, Any] | None = None,
    hpm_snapshot_before: dict[str, Any] | None = None,
    hpm_snapshot_after: dict[str, Any] | None = None,
    hpm_coverage: dict[str, Any] | None = None,
    bapc_coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": f"{case.get('seed', 'unknown')}:{case.get('index', 'unknown')}:{case['name']}",
        "result_id": f"{case.get('seed', 'unknown')}:{case.get('index', 'unknown')}:{case['name']}:{dut}",
        "name": case["name"],
        "profile": case["profile"],
        "generator_variant": case.get("generator_variant", "full"),
        "generation_seed": case.get("generation_seed", case.get("seed")),
        "scenario_index": case.get("scenario_index", case.get("index")),
        "continuous_sequence": case.get("continuous_sequence"),
        "mutation_operator": case.get("mutation_operator", "root"),
        "scenario_hash": case.get("scenario_hash"),
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
        "observed_mepc_tag": observed_mepc_tag,
        "observed_mtval_fingerprint": observed_mtval_fingerprint,
        "observed_event": observed_event,
        "observed_phase": observed_phase,
        "observed_stage": observed_stage,
        "observed_ptw_level": observed_ptw_level,
        "observed_fault_address": (
            f"0x{observed_fault_address:x}" if observed_fault_address is not None else None
        ),
        "observed_probe_vaddr": (
            f"0x{observed_probe_vaddr:x}" if observed_probe_vaddr is not None else None
        ),
        "observation_valid": observation_valid,
        "stage_verified": stage_verified,
        "log": str(log),
        "reason": reason,
        "hpm_manifest": hpm_manifest,
        "hpm_snapshot_before": hpm_snapshot_before,
        "hpm_snapshot_after": hpm_snapshot_after,
        "hpm_coverage": hpm_coverage,
        "bapc_coverage": bapc_coverage,
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
