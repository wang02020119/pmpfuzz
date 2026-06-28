from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable

from .scenario import PmpScenario, ScenarioGenerator


CORE_STATEFUL_TARGET = "core-stateful"

CORE_STATEFUL_PROFILES = (
    "pmp-boundary",
    "sv39-perm-matrix",
    "sv39-ptw-pmp-matrix",
    "pmp-side-effect",
    "tlb-stale-pte",
    "tlb-stale-pmp",
    "ptw-stale-pmp",
    "boom-ptw-pmp-regression",
)

EXPERIMENTAL_PROFILES = (
    "legacy-fetch-experimental",
    "smepmp-table",
    "mixed-smepmp-mmu",
)

PROFILE_TARGET_COUNTS = {
    "pmp-boundary": 72,
    "sv39-perm-matrix": 210,
    "sv39-ptw-pmp-matrix": 72,
    "pmp-side-effect": 4,
    "tlb-stale-pte": 4,
    "tlb-stale-pmp": 4,
    "ptw-stale-pmp": 4,
    "boom-ptw-pmp-regression": 6,
    "legacy-fetch-experimental": 12,
    "smepmp-table": 48,
    "mixed-smepmp-mmu": 48,
}


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
        "stateful_sequence": scenario.stateful_sequence,
    }
    return semantic_bins_for_case(case)


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


def build_schedule(
    run_dirs: Iterable[Path],
    *,
    target: str = CORE_STATEFUL_TARGET,
    max_cases: int = 64,
    seed: int = 20260628,
    include_experimental: bool = False,
) -> dict[str, Any]:
    run_dirs = [Path(item) for item in run_dirs]
    gap = coverage_gap_from_runs(run_dirs, target=target, include_experimental=include_experimental, seed=seed)
    missing = set(gap["missing_bins"])
    selected: list[dict[str, Any]] = []
    candidates = _target_candidates(target=target, include_experimental=include_experimental, seed=seed)

    while missing and len(selected) < max_cases:
        best = None
        best_gain: set[str] = set()
        for candidate in candidates:
            if candidate.get("_selected"):
                continue
            gain = set(candidate["semantic_bins"]) & missing
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
        selected.append(_schedule_entry(best, best_gain, seed))

    return {
        "schema_version": 1,
        "target": target,
        "seed": seed,
        "include_smepmp": False,
        "include_experimental": include_experimental,
        "max_cases": max_cases,
        "from_runs": [str(item) for item in run_dirs],
        "total_target_bins": gap["total_target_bins"],
        "covered_target_bins_before": gap["covered_target_bins"],
        "missing_target_bins_before": gap["missing_target_bins"],
        "entries": selected,
    }


def write_schedule(
    run_dirs: Iterable[Path],
    *,
    target: str,
    max_cases: int,
    seed: int,
    out_dir: Path,
    include_experimental: bool = False,
) -> Path:
    out_dir = Path(out_dir)
    gap = coverage_gap_from_runs(run_dirs, target=target, include_experimental=include_experimental, seed=seed)
    schedule = build_schedule(
        run_dirs,
        target=target,
        max_cases=max_cases,
        seed=seed,
        include_experimental=include_experimental,
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


def target_profiles(target: str, include_experimental: bool = False) -> tuple[str, ...]:
    if target != CORE_STATEFUL_TARGET:
        raise ValueError(f"unsupported semantic coverage target: {target}")
    profiles = list(CORE_STATEFUL_PROFILES)
    if include_experimental:
        profiles.extend(EXPERIMENTAL_PROFILES)
    return tuple(profiles)


def _target_candidates(*, target: str, include_experimental: bool, seed: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for profile in target_profiles(target, include_experimental):
        count = PROFILE_TARGET_COUNTS[profile]
        generator = ScenarioGenerator(seed=seed, include_smepmp=False, profile=profile)
        for index, scenario in enumerate(generator.generate_batch(count)):
            candidates.append(
                {
                    "profile": profile,
                    "index": index,
                    "name": f"{profile}__{scenario.name}",
                    "semantic_bins": semantic_bins_for_scenario(scenario),
                }
            )
    return candidates


def _schedule_entry(candidate: dict[str, Any], gain: set[str], seed: int) -> dict[str, Any]:
    return {
        "profile": candidate["profile"],
        "index": candidate["index"],
        "name": candidate["name"],
        "seed": seed,
        "include_smepmp": False,
        "semantic_bins": candidate["semantic_bins"],
        "covers_missing_bins": sorted(gain),
        "reason": f"covers {len(gain)} missing semantic bins",
    }


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
