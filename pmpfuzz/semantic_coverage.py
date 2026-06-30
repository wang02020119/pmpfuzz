from __future__ import annotations

import json
from itertools import combinations
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable

from .oracle import evaluate_scenario
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

COVERAGE_MODES = ("semantic", "pairwise", "security-triples")


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


def coverage_gap_from_runs(
    run_dirs: Iterable[Path],
    *,
    target: str = CORE_STATEFUL_TARGET,
    include_experimental: bool = False,
    seed: int = 20260628,
) -> dict[str, Any]:
    target_bins = set(target_semantic_bins(target=target, include_experimental=include_experimental, seed=seed))
    observed_bins: set[str] = set()
    run_dir_text: list[str] = []
    for run_dir in run_dirs:
        run_dir = Path(run_dir)
        run_dir_text.append(str(run_dir))
        for case_path in sorted((run_dir / "cases").glob("*/case.json")):
            observed_bins.update(semantic_bins_for_case(_read_json(case_path)))

    covered_target = observed_bins & target_bins
    missing = target_bins - covered_target
    coverage_rate = round(len(covered_target) / len(target_bins), 6) if target_bins else 1.0
    return {
        "schema_version": 1,
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


def combination_gap_from_runs(
    run_dirs: Iterable[Path],
    *,
    target: str = CORE_STATEFUL_TARGET,
    include_experimental: bool = False,
    seed: int = 20260628,
    coverage_mode: str = "pairwise",
) -> dict[str, Any]:
    if coverage_mode not in {"pairwise", "security-triples"}:
        raise ValueError("combination coverage gap requires pairwise or security-triples mode")
    target_bins = set(
        target_combo_bins(
            target=target,
            include_experimental=include_experimental,
            seed=seed,
            coverage_mode=coverage_mode,
        )
    )
    observed_bins: set[str] = set()
    run_dir_text: list[str] = []
    for run_dir in run_dirs:
        run_dir = Path(run_dir)
        run_dir_text.append(str(run_dir))
        for case_path in sorted((run_dir / "cases").glob("*/case.json")):
            observed_bins.update(combo_bins_for_case(_read_json(case_path), coverage_mode=coverage_mode))

    covered_target = observed_bins & target_bins
    missing = target_bins - covered_target
    coverage_rate = round(len(covered_target) / len(target_bins), 6) if target_bins else 1.0
    return {
        "schema_version": 3,
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


def build_schedule(
    run_dirs: Iterable[Path],
    *,
    target: str = CORE_STATEFUL_TARGET,
    max_cases: int = 64,
    seed: int = 20260628,
    include_experimental: bool = False,
    coverage_mode: str = "semantic",
) -> dict[str, Any]:
    if coverage_mode not in COVERAGE_MODES:
        raise ValueError(f"unsupported coverage mode: {coverage_mode}")
    run_dirs = [Path(item) for item in run_dirs]
    semantic_gap = coverage_gap_from_runs(run_dirs, target=target, include_experimental=include_experimental, seed=seed)
    combo_gap = None
    if coverage_mode == "semantic":
        missing = set(semantic_gap["missing_bins"])
    else:
        combo_gap = combination_gap_from_runs(
            run_dirs,
            target=target,
            include_experimental=include_experimental,
            seed=seed,
            coverage_mode=coverage_mode,
        )
        missing = set(combo_gap["missing_combo_bins"])
    selected: list[dict[str, Any]] = []
    candidates = _target_candidates(target=target, include_experimental=include_experimental, seed=seed)

    while missing and len(selected) < max_cases:
        best = None
        best_gain: set[str] = set()
        for candidate in candidates:
            if candidate.get("_selected"):
                continue
            candidate_bins = (
                set(candidate["semantic_bins"])
                if coverage_mode == "semantic"
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

    schedule = {
        "schema_version": 2,
        "target": target,
        "coverage_mode": coverage_mode,
        "seed": seed,
        "include_smepmp": any(str(entry.get("profile") or "").startswith("smepmp") for entry in selected),
        "include_experimental": include_experimental,
        "max_cases": max_cases,
        "from_runs": [str(item) for item in run_dirs],
        "total_target_bins": semantic_gap["total_target_bins"],
        "covered_target_bins_before": semantic_gap["covered_target_bins"],
        "missing_target_bins_before": semantic_gap["missing_target_bins"],
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
) -> Path:
    out_dir = Path(out_dir)
    if coverage_mode == "semantic":
        gap = coverage_gap_from_runs(run_dirs, target=target, include_experimental=include_experimental, seed=seed)
    else:
        gap = combination_gap_from_runs(
            run_dirs,
            target=target,
            include_experimental=include_experimental,
            seed=seed,
            coverage_mode=coverage_mode,
        )
    schedule = build_schedule(
        run_dirs,
        target=target,
        max_cases=max_cases,
        seed=seed,
        include_experimental=include_experimental,
        coverage_mode=coverage_mode,
    )
    _write_json(out_dir / "coverage_gap.json", gap)
    schedule_path = out_dir / "schedule.json"
    _write_json(schedule_path, schedule)
    return schedule_path


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
) -> list[str]:
    bins: set[str] = set()
    for candidate in _target_candidates(target=target, include_experimental=include_experimental, seed=seed):
        bins.update(candidate["semantic_bins"])
    return sorted(bins)


def target_combo_bins(
    *,
    target: str = CORE_STATEFUL_TARGET,
    include_experimental: bool = False,
    seed: int = 20260628,
    coverage_mode: str = "pairwise",
) -> list[str]:
    bins: set[str] = set()
    for candidate in _target_candidates(target=target, include_experimental=include_experimental, seed=seed):
        bins.update(combo_bins_for_case(candidate, coverage_mode=coverage_mode))
    return sorted(bins)


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


def _target_candidates(*, target: str, include_experimental: bool, seed: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for profile in target_profiles(target, include_experimental):
        count = PROFILE_TARGET_COUNTS[profile]
        generator = ScenarioGenerator(seed=seed, include_smepmp=profile.startswith("smepmp"), profile=profile)
        for index, scenario in enumerate(generator.generate_batch(count)):
            candidates.append(
                {
                    "profile": profile,
                    "index": index,
                    "name": f"{profile}__{scenario.name}",
                    "semantic_bins": semantic_bins_for_scenario(scenario),
                    "combo_bins": combo_bins_for_scenario(scenario),
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
        "coverage_mode": coverage_mode,
    }
    if coverage_mode == "semantic":
        entry["covers_missing_bins"] = sorted(gain)
        entry["covers_missing_combo_bins"] = []
        entry["reason"] = f"covers {len(gain)} missing semantic bins"
    else:
        entry["covers_missing_bins"] = []
        entry["covers_missing_combo_bins"] = sorted(gain)
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
