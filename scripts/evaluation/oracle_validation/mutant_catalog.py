from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
CRITICAL_MUTANT_IDS = {"M01", "M02", "M03", "M08", "M12", "M15", "M16", "M17"}
BOOM_CVA6_SUBSET = ("M02", "M04", "M08", "M12", "M16", "M17")


@dataclass(frozen=True)
class MutantPlan:
    mutant_id: str
    short_name: str
    fault_family: str
    injected_semantic_deviation: str


ROCKET_PRIMARY_MUTANTS: tuple[MutantPlan, ...] = (
    MutantPlan("M01", "ignore_load_read_permission", "permission_bypass", "ignore load-read permission"),
    MutantPlan("M02", "ignore_store_write_permission", "permission_bypass", "ignore store-write permission"),
    MutantPlan("M03", "ignore_fetch_execute_permission", "permission_bypass", "ignore fetch-execute permission"),
    MutantPlan("M04", "use_later_matching_entry", "priority_error", "use a later matching entry instead of the first match"),
    MutantPlan("M05", "incorrect_range_boundary", "range_boundary", "make one range boundary incorrectly inclusive/exclusive"),
    MutantPlan("M06", "allow_unmatched_su_access", "default_permission", "incorrectly allow an unmatched S/U access"),
    MutantPlan("M07", "ignore_mprv_effective_privilege", "effective_privilege", "ignore MPRV-derived effective privilege"),
    MutantPlan("M08", "bypass_ptw_pmp", "ptw_bypass", "bypass PMP for page-table memory reads"),
    MutantPlan("M09", "bypass_final_access_pmp", "final_access_bypass", "bypass PMP after address translation"),
    MutantPlan("M10", "alter_pte_permission_handling", "pte_permission", "alter U/SUM/MXR permission handling"),
    MutantPlan("M11", "mishandle_pte_ad_update", "pte_ad", "mishandle A/D update or SVADE behavior"),
    MutantPlan("M12", "wrong_trap_cause", "wrong_trap_cause", "report page fault as access fault or vice versa"),
    MutantPlan("M13", "wrong_trap_stage", "wrong_trap_stage", "attribute a PTW fault to the final access stage"),
    MutantPlan("M14", "corrupt_trap_metadata", "trap_metadata", "corrupt the architectural fault address or probe PC"),
    MutantPlan("M15", "retain_stale_pmp_permission", "stale_permission", "retain old PMP permission after configuration change"),
    MutantPlan("M16", "retain_stale_translation_permission", "stale_permission", "retain old PTE/TLB permission after invalidation"),
    MutantPlan("M17", "commit_denied_store_side_effect", "forbidden_store_side_effect", "commit a denied store to the sentinel"),
    MutantPlan("M18", "suppress_allowed_store_side_effect", "missing_required_store_side_effect", "suppress the sentinel update for an allowed store"),
)


def build_mutants_manifest(
    *,
    artifact_root: Path,
    order_seeds: list[int],
    online_seeds: list[int],
    replay_count: int,
    online_candidate_budget: int,
    wall_clock_horizon_seconds: int,
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    entries.extend(_entries_for_dut(artifact_root=artifact_root, dut="rocket-clean", plans=ROCKET_PRIMARY_MUTANTS))
    subset_plans = tuple(plan for plan in ROCKET_PRIMARY_MUTANTS if plan.mutant_id in BOOM_CVA6_SUBSET)
    entries.extend(_entries_for_dut(artifact_root=artifact_root, dut="boom-clean", plans=subset_plans))
    entries.extend(_entries_for_dut(artifact_root=artifact_root, dut="cva6-clean", plans=subset_plans))

    counts = {
        "rocket-clean": sum(1 for item in entries if item["dut"] == "rocket-clean"),
        "boom-clean": sum(1 for item in entries if item["dut"] == "boom-clean"),
        "cva6-clean": sum(1 for item in entries if item["dut"] == "cva6-clean"),
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "directed_order_seeds": list(order_seeds),
        "online_seeds": list(online_seeds),
        "replay_count": int(replay_count),
        "online_candidate_budget": int(online_candidate_budget),
        "wall_clock_horizon_seconds": int(wall_clock_horizon_seconds),
        "rocket_planned_mutants": counts["rocket-clean"],
        "boom_planned_mutants": counts["boom-clean"],
        "cva6_planned_mutants": counts["cva6-clean"],
        "total_planned_mutants": len(entries),
        "entries": entries,
    }


def _entries_for_dut(*, artifact_root: Path, dut: str, plans: tuple[MutantPlan, ...]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for plan in plans:
        mutant_root = artifact_root / "mutants" / dut / plan.mutant_id
        entries.append(
            {
                "schema_version": SCHEMA_VERSION,
                "dut": dut,
                "mutant_id": plan.mutant_id,
                "short_name": plan.short_name,
                "fault_family": plan.fault_family,
                "critical_family": plan.mutant_id in CRITICAL_MUTANT_IDS,
                "injected_semantic_deviation": plan.injected_semantic_deviation,
                "status": "planned_unbuilt",
                "artifacts": {
                    "patch_diff": _relpath(artifact_root, mutant_root / "patch.diff"),
                    "build_manifest": _relpath(artifact_root, mutant_root / "build-manifest.json"),
                    "binary_sha256": _relpath(artifact_root, mutant_root / "binary.sha256"),
                    "directed_root": _relpath(artifact_root, mutant_root / "directed"),
                    "campaigns_root": _relpath(artifact_root, mutant_root / "campaigns"),
                    "replay_root": _relpath(artifact_root, mutant_root / "replay"),
                },
            }
        )
    return entries


def _relpath(root: Path, target: Path) -> str:
    return target.relative_to(root).as_posix()
