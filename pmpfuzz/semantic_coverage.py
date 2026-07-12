from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from itertools import combinations
from pathlib import Path
from typing import Any, Iterable

from .capabilities import (
    capability_coverage_projection,
    oracle_applicability_for_case,
)
from .coverage_qualification import (
    collect_execution_evidence,
    load_capability_map,
    load_case_map,
    load_results,
    qualify_all_results,
    qualify_result_for_coverage,
)
from .oracle import contract_trace_for_scenario, evaluate_scenario
from .pmp import Access, PmpEntry, PmpModel
from .scenario import PmpScenario, ScenarioGenerator


CORE_STATEFUL_TARGET = "core-stateful"
XIANGSHAN_TARGETED_TARGET = "xiangshan-targeted"
OOO_MICROARCH_TARGET = "ooo-microarchitecture"

CORE_STATEFUL_PROFILES = (
    "pmp-boundary",
    "sv39-perm-matrix",
    "sv39-ptw-pmp-matrix",
    "pmp-side-effect",
    "tlb-stale-pte",
    "tlb-stale-pmp",
    "ptw-stale-pmp",
    "boom-ptw-pmp-regression",
    "smepmp-mmwp-mmode-default-deny",
    "smepmp-mml-shared-code",
    "smepmp-mml-shared-data",
    "smepmp-locked-entry",
    "smepmp-rlb-setup",
)

EXPERIMENTAL_PROFILES = (
    "legacy-fetch-experimental",
    "smepmp-table",
    "mixed-smepmp-mmu",
)

XIANGSHAN_TARGETED_PROFILES = (
    "xiangshan-fetch-pmp-boundary",
    "xiangshan-itlb-stale-pmp",
    "xiangshan-ptw-pmp-depth",
    "xiangshan-side-effect",
)

OOO_MICROARCH_PROFILES = (
    "ooo-fetch-replay-pmp",
    "ooo-itlb-stale-after-pmp-update",
    "ooo-dtlb-stale-after-pmp-update",
    "ooo-ptw-replay-pmp-deny",
    "ooo-exception-priority",
    "ooo-misaligned-page-cross-pmp",
    "ooo-ad-bit-side-effect",
    "ooo-fence-race-matrix",
)

PROFILE_TARGET_COUNTS = {
    "pmp-boundary": 144,
    "sv39-perm-matrix": 168,
    "sv39-ptw-pmp-matrix": 288,
    "pmp-side-effect": 8,
    "tlb-stale-pte": 4,
    "tlb-stale-pmp": 4,
    "ptw-stale-pmp": 4,
    "boom-ptw-pmp-regression": 6,
    "legacy-fetch-experimental": 12,
    "smepmp-table": 48,
    "mixed-smepmp-mmu": 48,
    "smepmp-mmwp-mmode-default-deny": 8,
    "smepmp-mml-shared-code": 9,
    "smepmp-mml-shared-data": 12,
    "smepmp-locked-entry": 9,
    "smepmp-rlb-setup": 4,
    "xiangshan-fetch-pmp-boundary": 96,
    "xiangshan-itlb-stale-pmp": 8,
    "xiangshan-ptw-pmp-depth": 96,
    "xiangshan-side-effect": 8,
    "ooo-fetch-replay-pmp": 96,
    "ooo-itlb-stale-after-pmp-update": 8,
    "ooo-dtlb-stale-after-pmp-update": 8,
    "ooo-ptw-replay-pmp-deny": 96,
    "ooo-exception-priority": 24,
    "ooo-misaligned-page-cross-pmp": 12,
    "ooo-ad-bit-side-effect": 16,
    "ooo-fence-race-matrix": 18,
}

COVERAGE_MODES = ("semantic", "pairwise", "security-triples", "predicates")


def semantic_bins_for_case(case: dict[str, Any]) -> list[str]:
    explicit = case.get("semantic_bins")
    if explicit:
        return sorted({str(item) for item in explicit if str(item)})

    profile = str(case.get("profile") or "unknown")
    bins = {f"profile={profile}"}

    privilege = case.get("privilege")
    access = case.get("access")
    translation = case.get("translation")
    if privilege:
        bins.add(f"profile={profile}|priv={privilege}")
    if access:
        bins.add(f"profile={profile}|access={access}")
    if privilege and access:
        bins.add(f"profile={profile}|priv={privilege}|access={access}")
    if translation:
        bins.add(f"profile={profile}|translation={translation}")

    for tag in case.get("coverage_tags") or []:
        bins.add(f"profile={profile}|tag={tag}")

    _add_field_bin(bins, profile, "pmp", case.get("pmp_match_mode"))
    _add_field_bin(bins, profile, "ptw", case.get("ptw_fault_level"))
    _add_field_bin(bins, profile, "preload", case.get("preload_mode"))
    _add_field_bin(bins, profile, "security", case.get("security_focus"))
    _add_field_bin(bins, profile, "smepmp_rule", case.get("smepmp_rule"))
    _add_field_bin(bins, profile, "effective_priv", case.get("effective_privilege"))
    _add_field_bin(bins, profile, "match", case.get("pmp_match_result"))

    mseccfg = case.get("mseccfg") or {}
    if mseccfg:
        bins.add(
            "profile={profile}|mml={mml}|mmwp={mmwp}|rlb={rlb}".format(
                profile=profile,
                mml=_bool_digit(mseccfg.get("mml")),
                mmwp=_bool_digit(mseccfg.get("mmwp")),
                rlb=_bool_digit(mseccfg.get("rlb")),
            )
        )

    pte = case.get("pte_permissions") or {}
    if pte:
        rwx = pte.get("rwx")
        if rwx:
            bins.add(f"profile={profile}|pte_rwx={rwx}")
        bins.add(
            "profile={profile}|pte={rwx}|u={user}|a={accessed}|d={dirty}|v={valid}".format(
                profile=profile,
                rwx=rwx or "unknown",
                user=_bool_digit(pte.get("user")),
                accessed=_bool_digit(pte.get("accessed")),
                dirty=_bool_digit(pte.get("dirty")),
                valid=_bool_digit(pte.get("valid")),
            )
        )

    if translation and translation != "bare":
        bins.add(
            "profile={profile}|sum={sum_enabled}|mxr={mxr}".format(
                profile=profile,
                sum_enabled=_bool_digit(case.get("sum_enabled")),
                mxr=_bool_digit(case.get("mxr")),
            )
        )

    sequence = case.get("stateful_sequence") or {}
    _add_field_bin(bins, profile, "sequence", sequence.get("kind"))
    _add_field_bin(bins, profile, "mutation", sequence.get("mutation"))
    _add_field_bin(bins, profile, "fence", sequence.get("fence"))
    _add_field_bin(bins, profile, "final", sequence.get("expected_final"))
    cause = sequence.get("expected_cause")
    if cause is not None:
        bins.add(f"profile={profile}|expected_cause={cause}")

    return sorted(bins)


def combo_bins_for_case(case: dict[str, Any], *, coverage_mode: str = "all") -> list[str]:
    explicit = case.get("combo_bins")
    if explicit:
        bins = sorted({str(item) for item in explicit if str(item)})
    else:
        factors = _combo_factors(case)
        bins = _pairwise_combo_bins(factors)
        bins.update(_security_triple_bins(factors))
        bins = sorted(bins)

    if coverage_mode == "all":
        return bins
    if coverage_mode == "pairwise":
        return [item for item in bins if item.startswith("combo2:")]
    if coverage_mode == "security-triples":
        return [item for item in bins if item.startswith("combo3:")]
    raise ValueError(f"unsupported coverage mode for combo bins: {coverage_mode}")


def contract_predicates_for_case(case: dict[str, Any]) -> list[str]:
    explicit = case.get("contract_predicates")
    if explicit:
        return sorted({str(item) for item in explicit if str(item)})

    predicates: set[str] = set()
    trace = case.get("contract_trace") or {}
    mode = trace.get("translation_mode") or case.get("translation")
    if mode:
        predicates.add(f"contract.translation.{mode}")
    trap_priority = trace.get("trap_priority")
    if trap_priority and trap_priority != "none":
        predicates.add(f"trap.{trap_priority}")
    if trap_priority == "misaligned":
        predicates.add("trap.misaligned_priority_over_permission")

    privilege = str(case.get("privilege") or trace.get("privilege") or "")
    effective = str(trace.get("effective_privilege") or case.get("effective_privilege") or privilege)
    if privilege and effective and privilege != effective:
        predicates.add("pmp.mprv_changes_effective_privilege")

    pmp_checks = list(trace.get("pmp_checks") or [])
    mseccfg = case.get("mseccfg") or {}
    for check in pmp_checks:
        if not isinstance(check, dict):
            continue
        stage = str(check.get("stage") or "unknown")
        match_mode = str(check.get("match_mode") or "unknown")
        allowed = bool(check.get("allowed"))
        check_effective = str(check.get("effective_privilege") or effective)
        predicates.add(f"pmp.{stage}_{'allow' if allowed else 'deny'}")
        if match_mode != "unknown":
            predicates.add(f"pmp.{stage}_match_{match_mode}")
        if match_mode == "no-match":
            if check_effective in {"S", "U"} and not allowed:
                predicates.add("pmp.su_no_match_default_deny")
            if check_effective == "M" and allowed:
                predicates.add("pmp.m_no_match_default_allow")
            if check_effective == "M" and not allowed and bool(mseccfg.get("mmwp")):
                predicates.add("pmp.m_no_match_mmwp_deny")
        if stage == "ptw" and not allowed:
            predicates.add("sv39.ptw_pmp_deny_before_final")
        if stage == "final" and not allowed:
            predicates.add("sv39.final_pmp_deny_after_translation")

    pmp_match_mode = str(case.get("pmp_match_mode") or "")
    if pmp_match_mode == "first-match-overlap":
        predicates.add("pmp.first_match_overlap")
    if pmp_match_mode in {"tor", "na4", "napot"}:
        predicates.add(f"pmp.{pmp_match_mode}_boundary")
    if case.get("pmp_locked"):
        predicates.add("pmp.locked_entry_affects_access")

    pte = trace.get("pte_decision") or {}
    if isinstance(pte, dict):
        decision = str(pte.get("decision") or "")
        if decision == "ok":
            predicates.add("sv39.pte_permission_ok")
        elif decision == "invalid":
            predicates.add("sv39.pte_invalid_page_fault")
        elif decision == "reserved_write_without_read":
            predicates.add("sv39.pte_reserved_page_fault")
        elif decision == "permission":
            predicates.add("sv39.pte_permission_page_fault")
        elif decision == "user":
            predicates.add("sv39.pte_user_page_fault")
        elif decision == "accessed":
            predicates.add("sv39.pte_accessed_page_fault")
        elif decision == "dirty":
            predicates.add("sv39.pte_dirty_page_fault")
        elif decision == "sum":
            predicates.add("sv39.sum_changes_permission_decision")
        if pte.get("mxr"):
            predicates.add("sv39.mxr_permission_context")
        if pte.get("sum"):
            predicates.add("sv39.sum_permission_context")

    side_effect = trace.get("side_effect_policy")
    if side_effect == "forbidden":
        predicates.add("memory.denied_store_no_side_effect")

    stateful = trace.get("stateful") or case.get("stateful_sequence") or {}
    if isinstance(stateful, dict) and stateful:
        mutation = str(stateful.get("mutation") or "")
        fence = str(stateful.get("fence") or "")
        expected_final = str(stateful.get("expected_final") or "")
        stale_class = stateful.get("stale_failure_class")
        if expected_final == "trap_no_side_effect":
            predicates.add("stateful.denied_store_no_side_effect")
        if stale_class and fence in {"with-sfence", "with-sfence-fence-i"}:
            predicates.add("stateful.stale_permission_forbidden_after_fence")
        if fence == "no-fence-experimental":
            predicates.add("stateful.no_fence_experimental_observation")
        if mutation and mutation != "none":
            predicates.add(f"stateful.mutation.{mutation}")
        if fence:
            predicates.add(f"stateful.fence.{fence}")

    smepmp_rule = case.get("smepmp_rule")
    if smepmp_rule:
        predicates.add(f"smepmp.{smepmp_rule}")
    if bool(mseccfg.get("mml")):
        predicates.add("smepmp.mml_enabled")
    if bool(mseccfg.get("mmwp")):
        predicates.add("smepmp.mmwp_enabled")
    if bool(mseccfg.get("rlb")):
        predicates.add("smepmp.rlb_enabled")

    return sorted(predicates)


def semantic_bins_for_scenario(scenario: PmpScenario) -> list[str]:
    case: dict[str, Any] = {
        "profile": scenario.profile,
        "privilege": scenario.privilege.value,
        "access": scenario.probe.access.value,
        "translation": scenario.translation.value,
        "sum_enabled": scenario.sum_enabled,
        "mxr": scenario.mxr,
        "coverage_tags": list(scenario.coverage_tags),
        "ptw_fault_level": scenario.ptw_fault_level,
        "preload_mode": scenario.preload_mode,
        "pmp_match_mode": scenario.pmp_match_mode,
        "pte_permissions": scenario.pte_permissions,
        "security_focus": scenario.security_focus,
        "smepmp_rule": scenario.smepmp_rule,
        "mseccfg": {
            "mml": scenario.mseccfg.mml,
            "mmwp": scenario.mseccfg.mmwp,
            "rlb": scenario.mseccfg.rlb,
        },
        "effective_privilege": scenario.mpp.value if scenario.mprv else scenario.privilege.value,
        "pmp_match_result": _pmp_match_result_for_scenario(scenario),
        "stateful_sequence": scenario.stateful_sequence,
    }
    return semantic_bins_for_case(case)


def combo_bins_for_scenario(scenario: PmpScenario, *, coverage_mode: str = "all") -> list[str]:
    pmp_locked, pmp_allow = _pmp_metadata_for_scenario(scenario)
    expected_allowed = evaluate_scenario(scenario).allowed
    if scenario.stateful_sequence is not None:
        expected_allowed = scenario.stateful_sequence.get("expected_final") == "store_side_effect"
    case: dict[str, Any] = {
        "profile": scenario.profile,
        "privilege": scenario.privilege.value,
        "access": scenario.probe.access.value,
        "translation": scenario.translation.value,
        "probe_offset": scenario.probe.offset_name,
        "sum_enabled": scenario.sum_enabled,
        "mxr": scenario.mxr,
        "ptw_fault_level": scenario.ptw_fault_level,
        "preload_mode": scenario.preload_mode,
        "pmp_match_mode": scenario.pmp_match_mode,
        "pmp_locked": pmp_locked,
        "pmp_allow": pmp_allow,
        "expected_allowed": expected_allowed,
        "pte_permissions": scenario.pte_permissions,
        "security_focus": scenario.security_focus,
        "mseccfg": {
            "mml": scenario.mseccfg.mml,
            "mmwp": scenario.mseccfg.mmwp,
            "rlb": scenario.mseccfg.rlb,
        },
        "smepmp_rule": scenario.smepmp_rule,
        "effective_privilege": scenario.mpp.value if scenario.mprv else scenario.privilege.value,
        "pmp_match_result": _pmp_match_result_for_scenario(scenario),
        "stateful_sequence": scenario.stateful_sequence,
    }
    return combo_bins_for_case(case, coverage_mode=coverage_mode)


def contract_predicates_for_scenario(scenario: PmpScenario) -> list[str]:
    pmp_locked, pmp_allow = _pmp_metadata_for_scenario(scenario)
    outcome = evaluate_scenario(scenario)
    if scenario.stateful_sequence is not None:
        expected_allowed = scenario.stateful_sequence.get("expected_final") == "store_side_effect"
    else:
        expected_allowed = outcome.allowed
    case: dict[str, Any] = {
        "profile": scenario.profile,
        "privilege": scenario.privilege.value,
        "access": scenario.probe.access.value,
        "translation": scenario.translation.value,
        "mprv": scenario.mprv,
        "mpp": scenario.mpp.value,
        "sum_enabled": scenario.sum_enabled,
        "mxr": scenario.mxr,
        "mseccfg": {
            "mml": scenario.mseccfg.mml,
            "mmwp": scenario.mseccfg.mmwp,
            "rlb": scenario.mseccfg.rlb,
        },
        "pmp_match_mode": scenario.pmp_match_mode,
        "pmp_locked": pmp_locked,
        "pmp_allow": pmp_allow,
        "expected_allowed": expected_allowed,
        "smepmp_rule": scenario.smepmp_rule,
        "stateful_sequence": scenario.stateful_sequence,
        "contract_trace": contract_trace_for_scenario(scenario),
    }
    return contract_predicates_for_case(case)


def _capability_case_for_scenario(scenario: PmpScenario) -> dict[str, Any]:
    """Build a minimal case-like dict that oracle_applicability_for_case can read."""
    ad_mode = getattr(scenario, 'ad_update_mode', None)
    case: dict[str, Any] = {
        "profile": scenario.profile,
        "privilege": scenario.privilege.value,
        "access": scenario.probe.access.value,
        "translation": scenario.translation.value,
        "mseccfg": asdict(scenario.mseccfg),
        "ad_update_mode": ad_mode.value if ad_mode else "unknown",
        "stateful_sequence": scenario.stateful_sequence,
    }
    if scenario.sv39 is not None:
        case["sv39"] = {
            "pte": asdict(scenario.sv39.pte),
        }
    return case


# ---------------------------------------------------------------------------
# ExecutionCoverageContext — single source of truth for execution coverage
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExecutionCoverageContext:
    """Bundles DUT, capability, and run directories for execution coverage."""

    dut: str
    capability: dict[str, Any]
    capability_fingerprint: str
    run_dirs: tuple[Path, ...]


def _capability_fingerprint(capability: dict[str, Any] | None) -> str:
    """Stable fingerprint for a capability dict using coverage projection."""
    if capability is None:
        return "none"
    projection = capability_coverage_projection(capability)
    raw = json.dumps(projection, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def resolve_execution_coverage_context(
    run_dirs: Iterable[Path],
    *,
    dut: str | None,
) -> ExecutionCoverageContext:
    """Resolve and validate the execution coverage context across run_dirs.

    Rules:
    - Every run_dir must have a dut_capabilities.json.
    - When *dut* is explicit, every capability map must contain it.
    - When *dut* is None, auto-infer ONLY when every run has exactly one DUT
      with the same name.
    - All runs must share the same capability fingerprint for the selected DUT.
    """
    run_dirs = tuple(run_dirs)
    if not run_dirs:
        raise ValueError("at least one run_dir is required")

    requested_dut = dut  # preserve original: None means "auto-infer"
    resolved_dut: str | None = None
    fingerprints: dict[str, str] = {}  # dut_name -> fingerprint
    capability_by_run: dict[Path, dict[str, Any]] = {}

    for rd in run_dirs:
        cap_map = load_capability_map(rd)
        if cap_map is None:
            raise ValueError(
                f"run directory {rd} is missing dut_capabilities.json; "
                f"execution coverage requires a capability file"
            )
        capability_by_run[rd] = cap_map

        if requested_dut is not None:
            # Explicit DUT: every map must contain it
            if requested_dut not in cap_map:
                raise ValueError(
                    f"run directory {rd} has no capability entry for DUT "
                    f"'{requested_dut}'; available: {sorted(cap_map.keys())}"
                )
            fp = _capability_fingerprint(cap_map[requested_dut])
            fingerprints[requested_dut] = fp
        else:
            # Auto-infer: every run must have exactly one DUT with same name
            dut_names = sorted(cap_map.keys())
            if len(dut_names) == 0:
                raise ValueError(
                    f"run directory {rd} has an empty capability map"
                )
            if len(dut_names) > 1:
                raise ValueError(
                    f"run directory {rd} contains multiple DUTs "
                    f"({dut_names}); pass --dut to select one"
                )
            inferred = dut_names[0]
            if resolved_dut is None:
                resolved_dut = inferred
            elif resolved_dut != inferred:
                raise ValueError(
                    f"run directories have different single DUTs: "
                    f"'{resolved_dut}' vs '{inferred}' from {rd}"
                )
            fp = _capability_fingerprint(cap_map[inferred])
            fingerprints[inferred] = fp

    # --- finalize DUT name --------------------------------------------------
    if requested_dut is not None:
        resolved_dut = requested_dut
    assert resolved_dut is not None

    # --- validate fingerprint consistency across runs -----------------------
    first_fp = fingerprints[resolved_dut]
    for rd in run_dirs:
        cap_map = capability_by_run[rd]
        cap = cap_map[resolved_dut]
        rd_fp = _capability_fingerprint(cap)
        if rd_fp != first_fp:
            raise ValueError(
                f"capability fingerprint mismatch for DUT '{resolved_dut}': "
                f"run {rd} has fingerprint {rd_fp}, "
                f"expected {first_fp}. "
                f"ISA={cap.get('isa')}, "
                f"run_dir={rd}"
            )

    return ExecutionCoverageContext(
        dut=resolved_dut,
        capability=capability_by_run[run_dirs[0]][resolved_dut],
        capability_fingerprint=first_fp,
        run_dirs=run_dirs,
    )


def _semantic_bins_for_case(case: dict[str, Any]) -> set[str]:
    return set(semantic_bins_for_case(case))


def _combo_bins_for_case_pairwise(case: dict[str, Any]) -> set[str]:
    return set(combo_bins_for_case(case, coverage_mode="pairwise"))


def _combo_bins_for_case_triples(case: dict[str, Any]) -> set[str]:
    return set(combo_bins_for_case(case, coverage_mode="security-triples"))


def _predicates_for_case(case: dict[str, Any]) -> set[str]:
    return set(contract_predicates_for_case(case))


def _gap_coverage_rate(
    covered: int,
    total: int,
    *,
    coverage_basis: str,
) -> float | None:
    """Return coverage rate consistent with the coverage basis.

    Execution mode: zero denominator → None (no applicable targets).
    Manifest mode: zero denominator → 1.0 (legacy compatibility).
    """
    if total:
        return round(covered / total, 6)
    if coverage_basis == "execution":
        return None
    return 1.0


def _observed_execution_bins(
    run_dir: Path,
    dut: str | None,
    bin_fn,
) -> set[str]:
    """Return bins from execution-qualified results for *dut* (or all DUTs).

    Uses qualify_result_for_coverage as the single source of truth so that
    coverage gap, build_schedule, and coverage.py all share the same
    eligibility rules.
    """
    case_map = load_case_map(run_dir)
    results_by_case = load_results(run_dir)
    observed: set[str] = set()
    for case_name, result_list in results_by_case.items():
        case = case_map.get(case_name)
        if case is None:
            continue
        for result in result_list:
            result_dut = str(result.get("dut") or "")
            if dut is not None and result_dut != dut:
                continue
            qual = qualify_result_for_coverage(case, result)
            if qual.eligible:
                observed.update(bin_fn(case))
    return observed


def coverage_gap_from_runs(
    run_dirs: Iterable[Path],
    *,
    target: str = CORE_STATEFUL_TARGET,
    include_experimental: bool = False,
    seed: int = 20260628,
    coverage_basis: str = "manifest",
    dut: str | None = None,
    capability: dict[str, Any] | None = None,
) -> dict[str, Any]:
    run_dirs = tuple(Path(item) for item in run_dirs)
    # --- execution mode: resolve context (fail closed) ----------------------
    resolved_dut: str | None = dut
    resolved_capability: dict[str, Any] | None = capability
    if coverage_basis == "execution":
        ctx = resolve_execution_coverage_context(run_dirs, dut=dut)
        resolved_dut = ctx.dut
        resolved_capability = ctx.capability

    target_bins = set(target_semantic_bins(
        target=target, include_experimental=include_experimental, seed=seed,
        capability=resolved_capability,
    ))
    observed_bins: set[str] = set()
    run_dir_text: list[str] = []
    for run_dir in run_dirs:
        run_dir = Path(run_dir)
        run_dir_text.append(str(run_dir))
        if coverage_basis == "execution":
            observed_bins.update(_observed_execution_bins(
                run_dir, resolved_dut, _semantic_bins_for_case,
            ))
        else:
            for case_path in sorted((run_dir / "cases").glob("*/case.json")):
                observed_bins.update(semantic_bins_for_case(_read_json(case_path)))

    covered_target = observed_bins & target_bins
    missing = target_bins - covered_target
    coverage_rate = _gap_coverage_rate(
        len(covered_target), len(target_bins), coverage_basis=coverage_basis,
    )
    gap = {
        "schema_version": 1,
        "coverage_basis": coverage_basis,
        "target": target,
        "include_experimental": include_experimental,
        "run_dirs": run_dir_text,
        "total_target_bins": len(target_bins),
        "observed_bins": sorted(observed_bins),
        "covered_bins": sorted(covered_target),
        "covered_target_bins": len(covered_target),
        "missing_bins": sorted(missing),
        "missing_target_bins": len(missing),
        "coverage_rate": coverage_rate,
        "top_gaps": sorted(missing)[:25],
    }
    if coverage_basis == "execution":
        gap["dut"] = resolved_dut
        gap["capability_fingerprint"] = ctx.capability_fingerprint if ctx else None
    return gap


def combination_gap_from_runs(
    run_dirs: Iterable[Path],
    *,
    target: str = CORE_STATEFUL_TARGET,
    include_experimental: bool = False,
    seed: int = 20260628,
    coverage_mode: str = "pairwise",
    coverage_basis: str = "manifest",
    dut: str | None = None,
    capability: dict[str, Any] | None = None,
) -> dict[str, Any]:
    run_dirs = tuple(Path(item) for item in run_dirs)
    if coverage_mode not in {"pairwise", "security-triples"}:
        raise ValueError("combination coverage gap requires pairwise or security-triples mode")

    # --- execution mode: resolve context (fail closed) ----------------------
    resolved_dut: str | None = dut
    resolved_capability: dict[str, Any] | None = capability
    if coverage_basis == "execution":
        ctx = resolve_execution_coverage_context(run_dirs, dut=dut)
        resolved_dut = ctx.dut
        resolved_capability = ctx.capability

    target_bins = set(
        target_combo_bins(
            target=target,
            include_experimental=include_experimental,
            seed=seed,
            coverage_mode=coverage_mode,
            capability=resolved_capability,
        )
    )
    bin_fn = _combo_bins_for_case_pairwise if coverage_mode == "pairwise" else _combo_bins_for_case_triples
    observed_bins: set[str] = set()
    run_dir_text: list[str] = []
    for run_dir in run_dirs:
        run_dir = Path(run_dir)
        run_dir_text.append(str(run_dir))
        if coverage_basis == "execution":
            observed_bins.update(_observed_execution_bins(run_dir, resolved_dut, bin_fn))
        else:
            for case_path in sorted((run_dir / "cases").glob("*/case.json")):
                observed_bins.update(combo_bins_for_case(_read_json(case_path), coverage_mode=coverage_mode))

    covered_target = observed_bins & target_bins
    missing = target_bins - covered_target
    coverage_rate = _gap_coverage_rate(
        len(covered_target), len(target_bins), coverage_basis=coverage_basis,
    )
    gap = {
        "schema_version": 3,
        "coverage_basis": coverage_basis,
        "target": target,
        "coverage_mode": coverage_mode,
        "include_experimental": include_experimental,
        "run_dirs": run_dir_text,
        "total_target_combo_bins": len(target_bins),
        "observed_combo_bins": sorted(observed_bins),
        "covered_combo_bins": sorted(covered_target),
        "covered_target_combo_bins": len(covered_target),
        "missing_combo_bins": sorted(missing),
        "missing_target_combo_bins": len(missing),
        "combo_coverage_rate": coverage_rate,
        "top_combo_gaps": sorted(missing)[:25],
    }
    if coverage_basis == "execution":
        gap["dut"] = resolved_dut
        gap["capability_fingerprint"] = ctx.capability_fingerprint if ctx else None
    return gap


def predicate_gap_from_runs(
    run_dirs: Iterable[Path],
    *,
    target: str = CORE_STATEFUL_TARGET,
    include_experimental: bool = False,
    seed: int = 20260628,
    coverage_basis: str = "manifest",
    dut: str | None = None,
    capability: dict[str, Any] | None = None,
) -> dict[str, Any]:
    run_dirs = tuple(Path(item) for item in run_dirs)
    # --- execution mode: resolve context (fail closed) ----------------------
    resolved_dut: str | None = dut
    resolved_capability: dict[str, Any] | None = capability
    if coverage_basis == "execution":
        ctx = resolve_execution_coverage_context(run_dirs, dut=dut)
        resolved_dut = ctx.dut
        resolved_capability = ctx.capability

    target_predicates = set(
        target_contract_predicates(target=target, include_experimental=include_experimental, seed=seed,
                                   capability=resolved_capability)
    )
    observed: set[str] = set()
    run_dir_text: list[str] = []
    for run_dir in run_dirs:
        run_dir = Path(run_dir)
        run_dir_text.append(str(run_dir))
        if coverage_basis == "execution":
            observed.update(_observed_execution_bins(run_dir, resolved_dut, _predicates_for_case))
        else:
            for case_path in sorted((run_dir / "cases").glob("*/case.json")):
                observed.update(contract_predicates_for_case(_read_json(case_path)))

    covered = observed & target_predicates
    missing = target_predicates - covered
    coverage_rate = _gap_coverage_rate(
        len(covered), len(target_predicates), coverage_basis=coverage_basis,
    )
    gap = {
        "schema_version": 1,
        "coverage_basis": coverage_basis,
        "target": target,
        "include_experimental": include_experimental,
        "run_dirs": run_dir_text,
        "total_target_predicates": len(target_predicates),
        "observed_predicates": sorted(observed),
        "covered_predicates": sorted(covered),
        "covered_target_predicates": len(covered),
        "missing_predicates": sorted(missing),
        "missing_target_predicates": len(missing),
        "predicate_coverage_rate": coverage_rate,
        "top_predicate_gaps": sorted(missing)[:25],
    }
    if coverage_basis == "execution":
        gap["dut"] = resolved_dut
        gap["capability_fingerprint"] = ctx.capability_fingerprint if ctx else None
    return gap


def build_schedule(
    run_dirs: Iterable[Path],
    *,
    target: str = CORE_STATEFUL_TARGET,
    max_cases: int = 64,
    seed: int = 20260628,
    include_experimental: bool = False,
    coverage_mode: str = "semantic",
    coverage_basis: str = "execution",
    dut: str | None = None,
) -> dict[str, Any]:
    if coverage_mode not in COVERAGE_MODES:
        raise ValueError(f"unsupported coverage mode: {coverage_mode}")
    run_dirs = tuple(Path(item) for item in run_dirs)

    # -- resolve DUT and capability -------------------------------------------
    ctx: ExecutionCoverageContext | None = None
    if coverage_basis == "execution":
        ctx = resolve_execution_coverage_context(run_dirs, dut=dut)
        resolved_dut = ctx.dut
        capability = ctx.capability
    else:
        resolved_dut = dut
        capability = None

    semantic_gap = coverage_gap_from_runs(
        run_dirs, target=target, include_experimental=include_experimental, seed=seed,
        coverage_basis=coverage_basis, dut=resolved_dut, capability=capability,
    )
    combo_gap = None
    predicate_gap = None
    if coverage_mode == "semantic":
        missing = set(semantic_gap["missing_bins"])
    elif coverage_mode == "predicates":
        predicate_gap = predicate_gap_from_runs(
            run_dirs,
            target=target,
            include_experimental=include_experimental,
            seed=seed,
            coverage_basis=coverage_basis,
            dut=resolved_dut,
            capability=capability,
        )
        missing = set(predicate_gap["missing_predicates"])
    else:
        combo_gap = combination_gap_from_runs(
            run_dirs,
            target=target,
            include_experimental=include_experimental,
            seed=seed,
            coverage_mode=coverage_mode,
            coverage_basis=coverage_basis,
            dut=resolved_dut,
            capability=capability,
        )
        missing = set(combo_gap["missing_combo_bins"])
    selected: list[dict[str, Any]] = []
    candidates = _target_candidates(target=target, include_experimental=include_experimental, seed=seed,
                                    capability=capability)

    while missing and len(selected) < max_cases:
        best = None
        best_gain: set[str] = set()
        for candidate in candidates:
            if candidate.get("_selected"):
                continue
            candidate_bins = (
                set(candidate["semantic_bins"])
                if coverage_mode == "semantic"
                else set(candidate["contract_predicates"])
                if coverage_mode == "predicates"
                else set(combo_bins_for_case(candidate, coverage_mode=coverage_mode))
            )
            gain = candidate_bins & missing
            if len(gain) > len(best_gain):
                best = candidate
                best_gain = gain
            elif len(gain) == len(best_gain) and gain and best is not None:
                if (candidate["profile"], candidate["index"]) < (best["profile"], best["index"]):
                    best = candidate
                    best_gain = gain
        if best is None or not best_gain:
            break
        best["_selected"] = True
        missing -= best_gain
        selected.append(_schedule_entry(best, best_gain, seed, coverage_mode=coverage_mode))

    # -- qualification summary -----------------------------------------------
    qualification = {"eligible_results": 0, "excluded_results": 0,
                     "excluded_by_reason": {}}
    if coverage_basis == "execution" and resolved_dut:
        evidence = collect_execution_evidence(run_dirs, dut=resolved_dut)
        qs = evidence.summary
        qualification = {
            "eligible_results": qs.eligible_results,
            "excluded_results": qs.excluded_results,
            "excluded_by_reason": dict(qs.excluded_by_reason),
            "valid_mismatches": qs.valid_mismatches,
            "total_results": qs.total_results,
            "missing_results": evidence.missing_results,
            "orphan_results": evidence.orphan_results,
        }

    schedule = {
        "schema_version": 2,
        "target": target,
        "coverage_mode": coverage_mode,
        "coverage_basis": coverage_basis,
        "dut": resolved_dut,
        "capability_fingerprint": _capability_fingerprint(capability) if capability else "none",
        "seed": seed,
        "include_smepmp": any(str(entry.get("profile") or "").startswith("smepmp") for entry in selected),
        "include_experimental": include_experimental,
        "max_cases": max_cases,
        "from_runs": [str(item) for item in run_dirs],
        "total_target_bins": semantic_gap["total_target_bins"],
        "covered_target_bins_before": semantic_gap["covered_target_bins"],
        "missing_target_bins_before": semantic_gap["missing_target_bins"],
        "qualification": qualification,
        "entries": selected,
    }
    if combo_gap is not None:
        schedule.update(
            {
                "total_target_combo_bins": combo_gap["total_target_combo_bins"],
                "covered_target_combo_bins_before": combo_gap["covered_target_combo_bins"],
                "missing_target_combo_bins_before": combo_gap["missing_target_combo_bins"],
                "combo_coverage_rate_before": combo_gap["combo_coverage_rate"],
            }
        )
    if coverage_mode == "predicates" and predicate_gap is not None:
        schedule.update(
            {
                "total_target_predicates": predicate_gap["total_target_predicates"],
                "covered_target_predicates_before": predicate_gap["covered_target_predicates"],
                "missing_target_predicates_before": predicate_gap["missing_target_predicates"],
                "predicate_coverage_rate_before": predicate_gap["predicate_coverage_rate"],
            }
        )
    return schedule


def write_schedule(
    run_dirs: Iterable[Path],
    *,
    target: str,
    max_cases: int,
    seed: int,
    out_dir: Path,
    include_experimental: bool = False,
    coverage_mode: str = "semantic",
    coverage_basis: str = "execution",
    dut: str | None = None,
) -> Path:
    out_dir = Path(out_dir)
    run_dirs = tuple(Path(item) for item in run_dirs)
    # Resolve capability for gap computation
    ctx: ExecutionCoverageContext | None = None
    resolved_dut = dut
    capability = None
    if coverage_basis == "execution":
        ctx = resolve_execution_coverage_context(run_dirs, dut=dut)
        resolved_dut = ctx.dut
        capability = ctx.capability

    if coverage_mode == "semantic":
        gap = coverage_gap_from_runs(run_dirs, target=target, include_experimental=include_experimental,
                                     seed=seed, coverage_basis=coverage_basis,
                                     dut=resolved_dut, capability=capability)
    elif coverage_mode == "predicates":
        gap = predicate_gap_from_runs(run_dirs, target=target, include_experimental=include_experimental,
                                      seed=seed, coverage_basis=coverage_basis,
                                      dut=resolved_dut, capability=capability)
    else:
        gap = combination_gap_from_runs(
            run_dirs,
            target=target,
            include_experimental=include_experimental,
            seed=seed,
            coverage_mode=coverage_mode,
            coverage_basis=coverage_basis,
            dut=resolved_dut,
            capability=capability,
        )
    schedule = build_schedule(
        run_dirs,
        target=target,
        max_cases=max_cases,
        seed=seed,
        include_experimental=include_experimental,
        coverage_mode=coverage_mode,
        coverage_basis=coverage_basis,
        dut=dut,
    )
    _write_json(out_dir / "coverage_gap.json", gap)
    schedule_path = out_dir / "schedule.json"
    _write_json(schedule_path, schedule)
    return schedule_path


def _resolve_dut(
    dut: str | None,
    capability_map: dict[str, Any],
    run_dirs: list[Path],
) -> str:
    """Resolve DUT name: explicit > auto-infer from single-DUT > error."""
    if dut is not None:
        return dut
    dut_names = list(capability_map.keys())
    if len(dut_names) == 1:
        return dut_names[0]
    if not dut_names:
        raise ValueError("no DUTs found in capability map; cannot auto-infer DUT")
    raise ValueError(
        f"multiple DUTs present ({', '.join(sorted(dut_names))}); "
        f"pass --dut to select one"
    )


def _resolve_capability_map(run_dirs: list[Path]) -> dict[str, Any] | None:
    """Load capability map from the first run_dir that has one."""
    for run_dir in run_dirs:
        cap_map = load_capability_map(run_dir)
        if cap_map:
            return cap_map
    return None


def load_schedule(path: Path) -> dict[str, Any]:
    schedule = _read_json(path)
    if not isinstance(schedule.get("entries"), list):
        raise ValueError("schedule.json must contain an entries list")
    return schedule


def scenarios_from_schedule(path: Path) -> list[tuple[int, PmpScenario]]:
    schedule = load_schedule(path)
    output: list[tuple[int, PmpScenario]] = []
    default_seed = int(schedule.get("seed", 20260628))
    default_include_smepmp = bool(schedule.get("include_smepmp", False))
    for entry in schedule["entries"]:
        profile = str(entry["profile"])
        index = int(entry["index"])
        entry_seed = int(entry.get("seed", default_seed))
        include_smepmp = bool(entry.get("include_smepmp", default_include_smepmp))
        generator = ScenarioGenerator(seed=entry_seed, include_smepmp=include_smepmp, profile=profile)
        scenario = generator.generate_batch(index + 1)[index]
        scenario = replace(scenario, name=str(entry.get("name") or f"{profile}__{scenario.name}"))
        output.append((index, scenario))
    return output


def target_semantic_bins(
    *,
    target: str = CORE_STATEFUL_TARGET,
    include_experimental: bool = False,
    seed: int = 20260628,
    capability: dict[str, Any] | None = None,
) -> list[str]:
    bins: set[str] = set()
    for candidate in _target_candidates(target=target, include_experimental=include_experimental, seed=seed,
                                        capability=capability):
        bins.update(candidate["semantic_bins"])
    return sorted(bins)


def target_combo_bins(
    *,
    target: str = CORE_STATEFUL_TARGET,
    include_experimental: bool = False,
    seed: int = 20260628,
    coverage_mode: str = "pairwise",
    capability: dict[str, Any] | None = None,
) -> list[str]:
    bins: set[str] = set()
    for candidate in _target_candidates(target=target, include_experimental=include_experimental, seed=seed,
                                        capability=capability):
        bins.update(combo_bins_for_case(candidate, coverage_mode=coverage_mode))
    return sorted(bins)


def target_contract_predicates(
    *,
    target: str = CORE_STATEFUL_TARGET,
    include_experimental: bool = False,
    seed: int = 20260628,
    capability: dict[str, Any] | None = None,
) -> list[str]:
    predicates: set[str] = set()
    for candidate in _target_candidates(target=target, include_experimental=include_experimental, seed=seed,
                                        capability=capability):
        predicates.update(candidate["contract_predicates"])
    return sorted(predicates)


def target_profiles(target: str, include_experimental: bool = False) -> tuple[str, ...]:
    if target == XIANGSHAN_TARGETED_TARGET:
        return XIANGSHAN_TARGETED_PROFILES
    if target == OOO_MICROARCH_TARGET:
        return OOO_MICROARCH_PROFILES
    if target != CORE_STATEFUL_TARGET:
        raise ValueError(f"unsupported semantic coverage target: {target}")
    profiles = list(CORE_STATEFUL_PROFILES)
    if include_experimental:
        profiles.extend(EXPERIMENTAL_PROFILES)
        profiles.extend(XIANGSHAN_TARGETED_PROFILES)
        profiles.extend(OOO_MICROARCH_PROFILES)
    return tuple(profiles)


def _target_candidates(*, target: str, include_experimental: bool, seed: int,
                       capability: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for profile in target_profiles(target, include_experimental):
        count = PROFILE_TARGET_COUNTS[profile]
        generator = ScenarioGenerator(seed=seed, include_smepmp=profile.startswith("smepmp"), profile=profile)
        for index, scenario in enumerate(generator.generate_batch(count)):
            capability_case = _capability_case_for_scenario(scenario)
            # Filter by capability if provided
            if capability is not None:
                if oracle_applicability_for_case(capability_case, capability) != "valid":
                    continue
            candidates.append(
                {
                    "profile": profile,
                    "index": index,
                    "name": f"{profile}__{scenario.name}",
                    "semantic_bins": semantic_bins_for_scenario(scenario),
                    "combo_bins": combo_bins_for_scenario(scenario),
                    "contract_predicates": contract_predicates_for_scenario(scenario),
                    "capability_case": capability_case,
                }
            )
    return candidates


def _schedule_entry(candidate: dict[str, Any], gain: set[str], seed: int, *, coverage_mode: str) -> dict[str, Any]:
    entry = {
        "profile": candidate["profile"],
        "index": candidate["index"],
        "name": candidate["name"],
        "seed": seed,
        "include_smepmp": str(candidate.get("profile") or "").startswith("smepmp"),
        "semantic_bins": candidate["semantic_bins"],
        "combo_bins": candidate["combo_bins"],
        "contract_predicates": candidate.get("contract_predicates") or [],
        "coverage_mode": coverage_mode,
    }
    if coverage_mode == "semantic":
        entry["covers_missing_bins"] = sorted(gain)
        entry["covers_missing_combo_bins"] = []
        entry["covers_missing_predicates"] = []
        entry["reason"] = f"covers {len(gain)} missing semantic bins"
    elif coverage_mode == "predicates":
        entry["covers_missing_bins"] = []
        entry["covers_missing_combo_bins"] = []
        entry["covers_missing_predicates"] = sorted(gain)
        entry["reason"] = f"covers {len(gain)} missing contract predicates"
    else:
        entry["covers_missing_bins"] = []
        entry["covers_missing_combo_bins"] = sorted(gain)
        entry["covers_missing_predicates"] = []
        entry["reason"] = f"covers {len(gain)} missing {coverage_mode} combo bins"
    return entry


def _combo_factors(case: dict[str, Any]) -> dict[str, str]:
    profile = str(case.get("profile") or "unknown")
    factors: dict[str, str] = {"profile": profile}
    _add_factor(factors, "priv", case.get("privilege"))
    _add_factor(factors, "access", case.get("access"))
    _add_factor(factors, "translation", case.get("translation"))
    _add_factor(factors, "pmp", case.get("pmp_match_mode"))
    _add_factor(factors, "pmp_allow", _bool_text(case.get("pmp_allow")) if case.get("pmp_allow") is not None else None)
    _add_factor(factors, "pmp_locked", _bool_text(case.get("pmp_locked")) if case.get("pmp_locked") is not None else None)
    _add_factor(factors, "expected_allowed", _bool_text(case.get("expected_allowed")) if case.get("expected_allowed") is not None else None)
    _add_factor(factors, "probe", case.get("probe_offset"))
    _add_factor(factors, "ptw", case.get("ptw_fault_level"))
    _add_factor(factors, "preload", case.get("preload_mode"))
    _add_factor(factors, "sum", _bool_text(case.get("sum_enabled")))
    _add_factor(factors, "mxr", _bool_text(case.get("mxr")))
    _add_factor(factors, "security", case.get("security_focus"))
    _add_factor(factors, "smepmp_rule", case.get("smepmp_rule"))
    _add_factor(factors, "effective_priv", case.get("effective_privilege"))
    _add_factor(factors, "match", case.get("pmp_match_result"))

    mseccfg = case.get("mseccfg") or {}
    _add_factor(factors, "mml", _bool_text(mseccfg.get("mml")) if mseccfg else None)
    _add_factor(factors, "mmwp", _bool_text(mseccfg.get("mmwp")) if mseccfg else None)
    _add_factor(factors, "rlb", _bool_text(mseccfg.get("rlb")) if mseccfg else None)

    pte = case.get("pte_permissions") or {}
    _add_factor(factors, "pte_rwx", pte.get("rwx"))
    _add_factor(factors, "pte_user", _bool_text(pte.get("user")) if "user" in pte else None)
    _add_factor(factors, "pte_a", _bool_text(pte.get("accessed")) if "accessed" in pte else None)
    _add_factor(factors, "pte_d", _bool_text(pte.get("dirty")) if "dirty" in pte else None)

    sequence = case.get("stateful_sequence") or {}
    _add_factor(factors, "sequence", sequence.get("kind"))
    _add_factor(factors, "mutation", sequence.get("mutation"))
    _add_factor(factors, "fence", sequence.get("fence"))
    _add_factor(factors, "expected_cause", sequence.get("expected_cause"))
    return factors


def _pairwise_combo_bins(factors: dict[str, str]) -> set[str]:
    profile = factors["profile"]
    names = [
        "priv",
        "access",
        "translation",
        "pmp",
        "pmp_allow",
        "pmp_locked",
        "expected_allowed",
        "probe",
        "ptw",
        "preload",
        "sum",
        "mxr",
        "pte_rwx",
        "pte_user",
        "pte_a",
        "pte_d",
        "security",
        "sequence",
        "mutation",
        "fence",
        "expected_cause",
        "mml",
        "mmwp",
        "rlb",
        "smepmp_rule",
        "effective_priv",
        "match",
    ]
    present = [(name, factors[name]) for name in names if name in factors]
    return {
        f"combo2:profile={profile}|{left}={left_value}|{right}={right_value}"
        for (left, left_value), (right, right_value) in combinations(present, 2)
    }


def _security_triple_bins(factors: dict[str, str]) -> set[str]:
    profile = factors["profile"]
    triples = (
        ("priv", "access", "pmp"),
        ("mxr", "preload", "ptw"),
        ("mutation", "fence", "priv"),
        ("priv", "access", "pte_rwx"),
        ("pmp_locked", "pmp_allow", "probe"),
        ("expected_allowed", "access", "priv"),
        ("mml", "mmwp", "rlb"),
        ("smepmp_rule", "effective_priv", "access"),
        ("smepmp_rule", "pmp_locked", "match"),
    )
    bins: set[str] = set()
    for names in triples:
        if all(name in factors for name in names):
            bins.add(
                "combo3:profile={profile}|{items}".format(
                    profile=profile,
                    items="|".join(f"{name}={factors[name]}" for name in names),
                )
            )
    return bins


def _add_factor(factors: dict[str, str], name: str, value: object) -> None:
    if value is None:
        return
    text = str(value)
    if text:
        factors[name] = text


def _bool_text(value: object) -> str:
    return "1" if bool(value) else "0"


def _pmp_metadata_for_scenario(scenario: PmpScenario) -> tuple[bool, bool]:
    harness_indices = {6, 7}
    if scenario.translation.value != "bare" or scenario.profile == "pmp-side-effect":
        harness_indices.update({0, 1, 2})
    relevant = [entry for entry in scenario.entries if entry.address_mode.name.lower() != "off" and entry.index not in harness_indices]
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


def _pmp_match_result_for_scenario(scenario: PmpScenario) -> str:
    decision = PmpModel(scenario.entries, scenario.mseccfg).check(
        privilege=scenario.privilege,
        access=scenario.probe.access,
        physical_address=scenario.probe.physical_address,
        size=scenario.probe.size,
        mprv=scenario.mprv,
        mpp=scenario.mpp,
    )
    return "matched" if decision.match_index is not None else "unmatched"


def _entry_allows_access(entry: PmpEntry, access: Access) -> bool:
    if access == Access.LOAD:
        return entry.read
    if access == Access.STORE:
        return entry.write
    if access == Access.FETCH:
        return entry.execute
    raise ValueError(f"unsupported access: {access}")


def _add_field_bin(bins: set[str], profile: str, name: str, value: object) -> None:
    if value is None:
        return
    text = str(value)
    if text:
        bins.add(f"profile={profile}|{name}={text}")


def _bool_digit(value: object) -> int:
    return 1 if bool(value) else 0


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="ascii"))


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="ascii")
