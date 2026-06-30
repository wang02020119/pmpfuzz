from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable

from .scenario import ScenarioGenerator
from .schema import read_json, scenario_to_case_dict, write_json
from .semantic_coverage import CORE_STATEFUL_TARGET, PROFILE_TARGET_COUNTS, target_profiles


HIGH_VALUE_FAILURES = {
    "pipeline_hung": 35,
    "wrong_mcause": 25,
    "unexpected_no_trap": 25,
    "unexpected_trap": 20,
    "FORBIDDEN_SIDE_EFFECT": 30,
    "MISSING_EXPECTED_SIDE_EFFECT": 20,
    "STALE_PMP_PERMISSION": 30,
    "STALE_TLB_PERMISSION": 30,
    "STALE_PTW_PERMISSION": 30,
    "forbidden_side_effect": 30,
    "missing_expected_side_effect": 20,
    "stale_pmp_permission": 30,
    "stale_tlb_permission": 30,
    "stale_ptw_permission": 30,
    "timeout": 8,
}


def extract_behavior_signals(run_dirs: Iterable[Path]) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for run_dir in [Path(item) for item in run_dirs]:
        cases = _case_map(run_dir)
        results_by_case: dict[str, list[dict[str, Any]]] = {}
        for result_path in sorted((run_dir / "results").glob("*/result.json")):
            result = read_json(result_path)
            results_by_case.setdefault(str(result.get("name")), []).append(result)

        for case_name, results in sorted(results_by_case.items()):
            case = cases.get(case_name)
            if not case:
                continue
            pass_duts = {
                str(result.get("dut"))
                for result in results
                if result.get("status") == "pass" and _valid_oracle_result(result)
            }
            for result in sorted(results, key=lambda item: (str(item.get("dut")), str(item.get("failure_class")))):
                if _result_is_pass_or_unsupported(result):
                    continue
                if not _valid_oracle_result(result):
                    continue
                failure_class = str(result.get("failure_class") or result.get("status") or "nonpass")
                if {"spike", "rocket-clean"}.issubset(pass_duts):
                    kind = "differential_failure"
                    weight = 100 + HIGH_VALUE_FAILURES.get(failure_class, 10)
                else:
                    kind = failure_class
                    weight = 40 + HIGH_VALUE_FAILURES.get(failure_class, 5)
                signals.append(
                    _signal_from_result(
                        run_dir=run_dir,
                        case=case,
                        result=result,
                        results=results,
                        kind=kind,
                        weight=weight,
                    )
                )
    return _sorted_signals(signals)


def load_external_signals(signal_files: Iterable[Path] | None) -> list[dict[str, Any]]:
    if not signal_files:
        return []
    signals: list[dict[str, Any]] = []
    for signal_file in signal_files:
        payload = read_json(Path(signal_file))
        raw_signals = payload.get("signals") if isinstance(payload, dict) else payload
        if not isinstance(raw_signals, list):
            continue
        for raw in raw_signals:
            if not isinstance(raw, dict):
                continue
            provider = str(raw.get("provider") or "whitebox")
            signals.append(
                {
                    "provider": provider,
                    "kind": str(raw.get("kind") or "unknown"),
                    "case": str(raw.get("case") or ""),
                    "dut": str(raw.get("dut") or ""),
                    "weight": int(raw.get("weight") or 1),
                    "features": dict(raw.get("features") or {}),
                    "evidence": dict(raw.get("evidence") or {}),
                }
            )
    return _sorted_signals(signals)


def build_feedback_schedule(
    run_dirs: Iterable[Path],
    *,
    max_cases: int = 64,
    seed: int = 20260629,
    target: str = CORE_STATEFUL_TARGET,
    include_experimental: bool = False,
    signal_files: Iterable[Path] | None = None,
) -> dict[str, Any]:
    run_dirs = [Path(item) for item in run_dirs]
    signals = extract_behavior_signals(run_dirs)
    signals.extend(load_external_signals(signal_files))
    signals = _sorted_signals(signals)
    candidates = _candidate_cases(target=target, include_experimental=include_experimental, seed=seed)

    entries: list[dict[str, Any]] = []
    selected: set[tuple[str, int]] = set()
    for signal in signals:
        if len(entries) >= max_cases:
            break
        ranked = _rank_candidates_for_signal(signal, candidates)
        for scored in ranked:
            if len(entries) >= max_cases:
                break
            candidate = scored["candidate"]
            key = (str(candidate["profile"]), int(candidate["index"]))
            if key in selected:
                continue
            selected.add(key)
            entries.append(_feedback_entry(candidate, signal, scored, seed))

    return {
        "schema_version": 3,
        "guidance_mode": "behavior",
        "target": target,
        "seed": seed,
        "include_smepmp": include_experimental,
        "include_experimental": include_experimental,
        "max_cases": max_cases,
        "from_runs": [str(item) for item in run_dirs],
        "signal_count": len(signals),
        "signals": signals[:50],
        "entries": entries,
    }


def write_feedback(
    run_dirs: Iterable[Path],
    *,
    max_cases: int,
    seed: int,
    out_dir: Path,
    target: str = CORE_STATEFUL_TARGET,
    include_experimental: bool = False,
    signal_files: Iterable[Path] | None = None,
) -> Path:
    out_dir = Path(out_dir)
    schedule = build_feedback_schedule(
        run_dirs,
        max_cases=max_cases,
        seed=seed,
        target=target,
        include_experimental=include_experimental,
        signal_files=signal_files,
    )
    feedback = {
        "schema_version": 1,
        "guidance_mode": "behavior",
        "target": target,
        "seed": seed,
        "from_runs": schedule["from_runs"],
        "signals": schedule["signals"],
        "selected_entries": schedule["entries"],
    }
    write_json(out_dir / "feedback.json", feedback)
    schedule_path = out_dir / "schedule.json"
    write_json(schedule_path, schedule)
    return schedule_path


def behavior_guidance_summary(run_dir: Path, *, max_cases: int = 8, seed: int = 20260629) -> dict[str, Any]:
    schedule = build_feedback_schedule([run_dir], max_cases=max_cases, seed=seed)
    top_signals = [
        {
            "kind": signal.get("kind"),
            "case": signal.get("case"),
            "dut": signal.get("dut"),
            "failure_class": (signal.get("features") or {}).get("failure_class"),
            "weight": signal.get("weight"),
        }
        for signal in schedule.get("signals", [])[:5]
    ]
    top_entries = [
        {
            "name": entry.get("name"),
            "profile": entry.get("profile"),
            "mutation_strategy": entry.get("mutation_strategy"),
            "mutation_ops": entry.get("mutation_ops"),
            "score": entry.get("score"),
        }
        for entry in schedule.get("entries", [])[:5]
    ]
    return {
        "signal_count": schedule.get("signal_count", 0),
        "top_signals": top_signals,
        "top_entries": top_entries,
    }


def _case_map(run_dir: Path) -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    for case_path in sorted((run_dir / "cases").glob("*/case.json")):
        case = read_json(case_path)
        cases[str(case.get("name"))] = case
    return cases


def _result_is_pass_or_unsupported(result: dict[str, Any]) -> bool:
    return str(result.get("status")) in {"pass", "setup_unsupported"} or str(result.get("oracle_applicability")) in {
        "unsupported",
        "infra_unadapted",
    }


def _valid_oracle_result(result: dict[str, Any]) -> bool:
    return str(result.get("oracle_applicability") or "valid") == "valid"


def _signal_from_result(
    *,
    run_dir: Path,
    case: dict[str, Any],
    result: dict[str, Any],
    results: list[dict[str, Any]],
    kind: str,
    weight: int,
) -> dict[str, Any]:
    failure_class = result.get("failure_class") or result.get("status")
    return {
        "provider": "behavior",
        "kind": kind,
        "case": case["name"],
        "dut": result.get("dut"),
        "weight": weight,
        "features": _features_for_case_result(case, result),
        "evidence": {
            "run_dir": str(run_dir),
            "result_status_by_dut": {
                str(item.get("dut")): {
                    "status": item.get("status"),
                    "failure_class": item.get("failure_class"),
                    "observed_mcause": item.get("observed_mcause"),
                    "oracle_applicability": item.get("oracle_applicability"),
                }
                for item in sorted(results, key=lambda value: str(value.get("dut")))
            },
            "failure_class": failure_class,
        },
    }


def _features_for_case_result(case: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    pte = case.get("pte_permissions") or {}
    sequence = case.get("stateful_sequence") or {}
    return {
        "profile": case.get("profile"),
        "privilege": case.get("privilege"),
        "access": case.get("access"),
        "translation": case.get("translation"),
        "failure_class": result.get("failure_class") or result.get("status"),
        "status": result.get("status"),
        "expected_cause": result.get("expected_cause"),
        "expected_stage": result.get("expected_stage"),
        "observed_mcause": result.get("observed_mcause"),
        "observed_mtval": result.get("observed_mtval"),
        "oracle_applicability": result.get("oracle_applicability"),
        "ptw_fault_level": case.get("ptw_fault_level"),
        "preload_mode": case.get("preload_mode"),
        "pmp_match_mode": case.get("pmp_match_mode"),
        "pmp_locked": case.get("pmp_locked"),
        "pmp_allow": case.get("pmp_allow"),
        "pmp_match_result": case.get("pmp_match_result"),
        "mxr": case.get("mxr"),
        "sum_enabled": case.get("sum_enabled"),
        "smepmp_rule": case.get("smepmp_rule"),
        "effective_privilege": case.get("effective_privilege"),
        "mseccfg_mml": (case.get("mseccfg") or {}).get("mml"),
        "mseccfg_mmwp": (case.get("mseccfg") or {}).get("mmwp"),
        "mseccfg_rlb": (case.get("mseccfg") or {}).get("rlb"),
        "security_focus": case.get("security_focus"),
        "pte_rwx": pte.get("rwx"),
        "pte_user": pte.get("user"),
        "pte_accessed": pte.get("accessed"),
        "pte_dirty": pte.get("dirty"),
        "stateful_kind": sequence.get("kind"),
        "stateful_mutation": sequence.get("mutation"),
        "stateful_fence": sequence.get("fence"),
        "stateful_expected_final": sequence.get("expected_final"),
    }


def _candidate_cases(*, target: str, include_experimental: bool, seed: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for profile in target_profiles(target, include_experimental):
        include_smepmp = include_experimental or profile.startswith("smepmp")
        generator = ScenarioGenerator(seed=seed, include_smepmp=include_smepmp, profile=profile)
        for index, scenario in enumerate(generator.generate_batch(PROFILE_TARGET_COUNTS[profile])):
            scenario = replace(scenario, name=f"{profile}__{scenario.name}")
            case = scenario_to_case_dict(scenario, seed=seed, index=index)
            candidates.append(case)
    return candidates


def _rank_candidates_for_signal(signal: dict[str, Any], candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    strategy = _strategy_for_signal(signal)
    ranked: list[dict[str, Any]] = []
    for candidate in candidates:
        if candidate.get("name") == signal.get("case"):
            continue
        score = _score_candidate(signal, candidate, strategy)
        if score <= 0:
            continue
        ops = _mutation_ops(signal.get("features") or {}, candidate)
        ranked.append(
            {
                "candidate": candidate,
                "score": score,
                "strategy": strategy,
                "mutation_ops": ops,
                "feedback_tags": _feedback_tags(signal, strategy),
            }
        )
    ranked.sort(
        key=lambda item: (
            -int(item["score"]),
            str(item["candidate"].get("profile")),
            int(item["candidate"].get("index") or 0),
        )
    )
    return ranked


def _strategy_for_signal(signal: dict[str, Any]) -> str:
    if signal.get("provider") == "whitebox":
        return _strategy_for_whitebox_signal(signal)
    features = signal.get("features") or {}
    failure_class = str(features.get("failure_class") or signal.get("kind") or "")
    profile = str(features.get("profile") or "")
    sequence_kind = str(features.get("stateful_kind") or "")
    if profile.startswith("smepmp") or features.get("smepmp_rule"):
        return "smepmp-permission-neighborhood"
    if _is_ptw_pmp_signal(features, failure_class, profile):
        return "ptw-pmp-neighborhood"
    if failure_class == "wrong_mcause":
        return "wrong-mcause-neighborhood"
    if sequence_kind or failure_class in {
        "FORBIDDEN_SIDE_EFFECT",
        "MISSING_EXPECTED_SIDE_EFFECT",
        "STALE_PMP_PERMISSION",
        "STALE_TLB_PERMISSION",
        "STALE_PTW_PERMISSION",
    }:
        return "stateful-permission-neighborhood"
    if failure_class == "timeout":
        return "timeout-control"
    return "semantic-neighborhood"


def _strategy_for_whitebox_signal(signal: dict[str, Any]) -> str:
    features = signal.get("features") or {}
    kind = str(signal.get("kind") or "")
    security_chain = str(features.get("security_chain") or "")
    perf_counter = str(features.get("perf_counter") or "").lower()
    profile = str(features.get("profile") or "")
    if "smepmp" in security_chain or profile.startswith("smepmp") or features.get("smepmp_rule"):
        return "smepmp-permission-neighborhood"
    if (
        "ptw" in security_chain
        or str(features.get("pmp_stage")) == "ptw"
        or kind.startswith("ptw_")
        or any(item in perf_counter for item in ("ptw", "tlb", "itlb", "dtlb"))
    ):
        return "ptw-pmp-neighborhood"
    if "side-effect" in security_chain or kind == "forbidden_side_effect_footprint" or "store" in perf_counter:
        return "stateful-permission-neighborhood"
    if "trap" in security_chain or kind == "trap_commit_trace" or any(item in perf_counter for item in ("exception", "trap")):
        return "wrong-mcause-neighborhood"
    return "semantic-neighborhood"


def _is_ptw_pmp_signal(features: dict[str, Any], failure_class: str, profile: str) -> bool:
    return (
        failure_class == "pipeline_hung"
        and str(features.get("translation")) == "sv39"
        and (features.get("ptw_fault_level") is not None or "ptw-pmp" in profile)
    )


def _score_candidate(signal: dict[str, Any], candidate: dict[str, Any], strategy: str) -> int:
    features = signal.get("features") or {}
    if strategy == "ptw-pmp-neighborhood":
        return _score_ptw_pmp_candidate(features, candidate)
    if strategy == "wrong-mcause-neighborhood":
        return _score_wrong_mcause_candidate(features, candidate)
    if strategy == "stateful-permission-neighborhood":
        return _score_stateful_candidate(features, candidate)
    if strategy == "smepmp-permission-neighborhood":
        return _score_smepmp_candidate(features, candidate)
    if strategy == "timeout-control":
        return _score_timeout_candidate(features, candidate)
    return _score_semantic_candidate(features, candidate)


def _score_ptw_pmp_candidate(features: dict[str, Any], candidate: dict[str, Any]) -> int:
    profile = str(candidate.get("profile"))
    score = 0
    if profile == "boom-ptw-pmp-regression":
        score += 170
    elif profile == "sv39-ptw-pmp-matrix":
        score += 90
    elif profile == "ptw-stale-pmp":
        score += 55
    else:
        return 0
    if candidate.get("translation") == features.get("translation"):
        score += 8
    if candidate.get("profile") == features.get("profile"):
        score += 35
    if candidate.get("access") == features.get("access"):
        score += 8
    if candidate.get("privilege") == features.get("privilege"):
        score += 6
    if candidate.get("ptw_fault_level") == features.get("ptw_fault_level"):
        score += 8
    if candidate.get("preload_mode") != features.get("preload_mode"):
        score += 18
    if candidate.get("mxr") != features.get("mxr"):
        score += 18
    if candidate.get("privilege") != features.get("privilege"):
        score += 10
    if candidate.get("access") != features.get("access"):
        score += 10
    if candidate.get("ptw_fault_level") != features.get("ptw_fault_level"):
        score += 12
    if candidate.get("pmp_locked") != features.get("pmp_locked"):
        score += 8
    if (candidate.get("pte_permissions") or {}).get("rwx") != features.get("pte_rwx"):
        score += 6
    if str(candidate.get("security_focus") or "").endswith("control"):
        score += 4
    return score


def _score_wrong_mcause_candidate(features: dict[str, Any], candidate: dict[str, Any]) -> int:
    profile = str(candidate.get("profile"))
    if profile not in {"sv39-ptw-pmp-matrix", "sv39-perm-matrix", "boom-ptw-pmp-regression"}:
        return 0
    score = 60
    if candidate.get("privilege") != features.get("privilege"):
        score += 12
    if candidate.get("ptw_fault_level") != features.get("ptw_fault_level"):
        score += 10
    if (candidate.get("pte_permissions") or {}).get("rwx") != features.get("pte_rwx"):
        score += 8
    return score


def _score_stateful_candidate(features: dict[str, Any], candidate: dict[str, Any]) -> int:
    profile = str(candidate.get("profile"))
    if profile not in {"pmp-side-effect", "tlb-stale-pte", "tlb-stale-pmp", "ptw-stale-pmp"}:
        return 0
    sequence = candidate.get("stateful_sequence") or {}
    score = 65
    if sequence.get("mutation") != features.get("stateful_mutation"):
        score += 12
    if sequence.get("fence") != features.get("stateful_fence"):
        score += 10
    if candidate.get("privilege") != features.get("privilege"):
        score += 8
    return score


def _score_smepmp_candidate(features: dict[str, Any], candidate: dict[str, Any]) -> int:
    profile = str(candidate.get("profile") or "")
    if not profile.startswith("smepmp"):
        return 0
    score = 100
    if candidate.get("smepmp_rule") != features.get("smepmp_rule"):
        score += 45
    else:
        score += 10
    mseccfg = candidate.get("mseccfg") or {}
    for bit in ("mml", "mmwp", "rlb"):
        if bool(mseccfg.get(bit)) != bool(features.get(f"mseccfg_{bit}")):
            score += 20
        else:
            score += 2
    if candidate.get("privilege") != features.get("privilege"):
        score += 10
    if candidate.get("access") != features.get("access"):
        score += 8
    if candidate.get("pmp_match_result") != features.get("pmp_match_result"):
        score += 6
    return score


def _score_timeout_candidate(features: dict[str, Any], candidate: dict[str, Any]) -> int:
    if candidate.get("profile") != features.get("profile"):
        return 0
    score = 25
    if candidate.get("access") == features.get("access"):
        score += 4
    if candidate.get("privilege") == features.get("privilege"):
        score += 4
    return score


def _score_semantic_candidate(features: dict[str, Any], candidate: dict[str, Any]) -> int:
    score = 0
    if candidate.get("profile") == features.get("profile"):
        score += 35
    if candidate.get("access") == features.get("access"):
        score += 6
    if candidate.get("privilege") != features.get("privilege"):
        score += 6
    return score


def _mutation_ops(features: dict[str, Any], candidate: dict[str, Any]) -> list[str]:
    ops: list[str] = []
    _append_flip(ops, "privilege", features.get("privilege"), candidate.get("privilege"), prefix="set-privilege")
    _append_flip(ops, "access", features.get("access"), candidate.get("access"), prefix="set-access")
    _append_flip(ops, "mxr", _bool_digit(features.get("mxr")), _bool_digit(candidate.get("mxr")), prefix="set-mxr")
    _append_flip(ops, "preload", features.get("preload_mode"), candidate.get("preload_mode"), prefix="set-preload")
    _append_flip(ops, "ptw", features.get("ptw_fault_level"), candidate.get("ptw_fault_level"), prefix="set-ptw-level")
    _append_flip(ops, "pmp-locked", _bool_digit(features.get("pmp_locked")), _bool_digit(candidate.get("pmp_locked")), prefix="set-pmp-locked")
    _append_flip(ops, "pmp-match", features.get("pmp_match_result"), candidate.get("pmp_match_result"), prefix="set-pmp-match")
    _append_flip(ops, "pte-rwx", features.get("pte_rwx"), (candidate.get("pte_permissions") or {}).get("rwx"), prefix="set-pte-rwx")
    mseccfg = candidate.get("mseccfg") or {}
    _append_flip(ops, "mseccfg-mml", _bool_digit(features.get("mseccfg_mml")), _bool_digit(mseccfg.get("mml")), prefix="set-mseccfg-mml")
    _append_flip(ops, "mseccfg-mmwp", _bool_digit(features.get("mseccfg_mmwp")), _bool_digit(mseccfg.get("mmwp")), prefix="set-mseccfg-mmwp")
    _append_flip(ops, "mseccfg-rlb", _bool_digit(features.get("mseccfg_rlb")), _bool_digit(mseccfg.get("rlb")), prefix="set-mseccfg-rlb")
    _append_flip(ops, "smepmp-rule", features.get("smepmp_rule"), candidate.get("smepmp_rule"), prefix="set-smepmp-rule")
    sequence = candidate.get("stateful_sequence") or {}
    _append_flip(ops, "mutation", features.get("stateful_mutation"), sequence.get("mutation"), prefix="set-stateful-mutation")
    _append_flip(ops, "fence", features.get("stateful_fence"), sequence.get("fence"), prefix="set-fence")
    return ops or ["nearby-control"]


def _append_flip(ops: list[str], name: str, source: object, target: object, *, prefix: str) -> None:
    if target is None or source == target:
        return
    ops.append(f"{prefix}={target}")


def _bool_digit(value: object) -> int | None:
    if value is None:
        return None
    return 1 if bool(value) else 0


def _feedback_tags(signal: dict[str, Any], strategy: str) -> list[str]:
    features = signal.get("features") or {}
    tags = ["behavior", strategy, str(signal.get("kind") or "unknown")]
    failure_class = features.get("failure_class")
    if failure_class:
        tags.append(str(failure_class))
    provider = signal.get("provider")
    if provider:
        tags.append(str(provider))
    return sorted(set(tags))


def _feedback_entry(candidate: dict[str, Any], signal: dict[str, Any], scored: dict[str, Any], seed: int) -> dict[str, Any]:
    return {
        "profile": candidate["profile"],
        "index": candidate["index"],
        "name": candidate["name"],
        "seed": seed,
        "include_smepmp": str(candidate.get("profile") or "").startswith("smepmp") or bool(candidate.get("smepmp_rule")),
        "semantic_bins": list(candidate.get("semantic_bins") or []),
        "combo_bins": list(candidate.get("combo_bins") or []),
        "coverage_mode": "behavior",
        "guidance_mode": "behavior",
        "source_case": signal.get("case"),
        "source_signal": _compact_signal(signal),
        "mutation_strategy": scored["strategy"],
        "mutation_ops": scored["mutation_ops"],
        "score": int(scored["score"]),
        "feedback_tags": scored["feedback_tags"],
        "covers_missing_bins": [],
        "covers_missing_combo_bins": [],
        "reason": "behavior feedback from {kind} on {case}".format(
            kind=signal.get("kind"),
            case=signal.get("case"),
        ),
    }


def _compact_signal(signal: dict[str, Any]) -> dict[str, Any]:
    features = signal.get("features") or {}
    return {
        "provider": signal.get("provider"),
        "kind": signal.get("kind"),
        "dut": signal.get("dut"),
        "case": signal.get("case"),
        "failure_class": features.get("failure_class"),
        "weight": signal.get("weight"),
    }


def _sorted_signals(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        signals,
        key=lambda item: (
            -int(item.get("weight") or 0),
            str(item.get("provider")),
            str(item.get("kind")),
            str(item.get("case")),
            str(item.get("dut")),
            json.dumps(item.get("features") or {}, sort_keys=True),
        ),
    )
