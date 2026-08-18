#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pmpfuzz.continuous import ScenarioStream
from pmpfuzz.scenario_codec import scenario_from_spec, scenario_hash, scenario_to_spec

import u74_cl144_common as C


def _collect_candidate(
    *,
    scenario,
    profile: str,
    generator_index: int,
    seed: int,
    case_index: int,
    mutation: str,
    source: str,
    reachable_set: set[str],
) -> dict[str, Any] | None:
    scenario_hash_value = scenario_hash(scenario_to_spec(scenario))
    if not C.is_supported_scenario(scenario):
        return None
    case_name = f"u74-cl144-cand-{case_index:06d}"
    try:
        case, lowering = C.build_case_and_lowering(
            scenario, seed=seed, index=case_index, case_name=case_name
        )
    except (ValueError, AssertionError):
        return None
    expected = case["expected"]
    predicted = C.predict_case_bins(
        case,
        expected_allowed=bool(expected["allowed"]),
        expected_cause=expected["trap_cause"],
    )
    if not predicted.get("eligible"):
        return None
    predicted_bins = sorted(set(str(b) for b in (predicted.get("observed_bins") or [])))
    predicted_reachable = sorted(set(predicted_bins) & reachable_set)
    config_classes = C.config_classes_for_scenario(scenario)
    firmware_ready = C.firmware_ready_for_scenario(scenario)
    locked_tor = C.scenario_locked_tor_flags(scenario)
    translation = "sv39" if scenario.sv39 is not None else "bare"
    access = str(scenario.probe.access.value)




    board_unstable = bool(translation == "sv39" and access == "fetch")
    return {
        "name": case_name,
        "candidate_id": C.make_candidate_id(
            seed=seed,
            profile=profile,
            generator_index=generator_index,
            scenario_hash=scenario_hash_value,
            mutation=mutation,
        ),
        "scenario_hash": scenario_hash_value,
        "scenario_fingerprint": scenario_hash_value,
        "profile": profile,
        "generator_profile": profile,
        "generator_index": generator_index,
        "seed": seed,
        "case_index": case_index,
        "mutation_operator": mutation,
        "source": source,
        "firmware_ready": firmware_ready,
        "board_unstable": board_unstable,
        "translation": translation,
        "access": access,
        "has_tor": locked_tor["has_tor"],
        "has_locked": locked_tor["has_locked"],
        "config_classes": config_classes,
        "predicted_bins": predicted_bins,
        "predicted_reachable_bins": predicted_reachable,
        "scenario_spec": case["scenario_spec"],
        "lowering": lowering,
        "expected": expected,
    }


def _reachable_config_classes(reachable_set: set[str]) -> set[tuple[str, str, str]]:
    classes = set()
    for bin_id in reachable_set:
        if not str(bin_id).startswith("family=config"):
            continue
        fields = dict(part.split("=", 1) for part in str(bin_id).split("|")[1:])
        if fields.get("pmp_mode") == "off":
            continue
        classes.add((fields.get("pmp_mode"), fields.get("permission_rwx"), fields.get("locked")))
    return classes


def _enrich_missing_config_classes(
    *,
    candidates: list[dict[str, Any]],
    seen_hashes: set[str],
    reachable_set: set[str],
    seed: int,
    target_classes: set[tuple[str, str, str]],
    time_budget: float,
    stats: dict[str, Any],
) -> list[dict[str, Any]]:
    from pmpfuzz.scenario_codec import scenario_from_spec

    started = time.time()
    covered = set()
    for cand in candidates:
        for cls in cand.get("config_classes") or []:
            covered.add(tuple(cls))
    missing = sorted(target_classes - covered)
    stats["missing_config_classes_before"] = missing
    if not missing:
        return candidates

    parents = [c for c in candidates if c.get("scenario_spec")]
    if not parents:
        stats["enrichment_attempts"] = 0
        stats["missing_config_classes_after"] = missing
        return candidates
    parent_sample = (parents * ((300 + len(parents) - 1) // len(parents)))[:300]
    plans = _mutation_plans()
    attempts = 0
    for target_class in missing:
        if time.time() - started > time_budget:
            break
        found = False
        for parent in parent_sample:
            if found:
                break
            try:
                parent_scenario = scenario_from_spec(parent["scenario_spec"])
            except Exception:
                continue
            base_spec = scenario_to_spec(parent_scenario)
            for plan in plans:
                if time.time() - started > time_budget:
                    break
                for attempt in range(4):
                    attempts += 1
                    try:
                        mutated = _mutate_chain(base_spec, plan=plan, attempt=attempt, seed=seed)
                    except ValueError:
                        continue
                    mut_hash = scenario_hash(scenario_to_spec(mutated))
                    if mut_hash in seen_hashes:
                        continue
                    cls_set = set(tuple(c) for c in C.config_classes_for_scenario(mutated))
                    if target_class not in cls_set:
                        continue
                    cand = _collect_candidate(
                        scenario=mutated,
                        profile=parent.get("generator_profile") or "pmp-boundary",
                        generator_index=int(parent.get("generator_index") or 0),
                        seed=seed,
                        case_index=len(candidates) + attempts,
                        mutation="+".join(plan) or "enrichment",
                        source="enrichment",
                        reachable_set=reachable_set,
                    )
                    if cand is None:
                        continue
                    seen_hashes.add(mut_hash)
                    candidates.append(cand)
                    covered.update(tuple(c) for c in cand["config_classes"])
                    found = True
                    break
                if found:
                    break
    stats["enrichment_attempts"] = attempts
    still_missing = sorted(target_classes - {tuple(c) for cand in candidates for c in (cand.get("config_classes") or [])})
    stats["missing_config_classes_after"] = still_missing
    return candidates


def _mutation_plans() -> list[list[str]]:
    plans: list[list[str]] = []
    for locked_op in ("set-pmp-locked=1", "set-pmp-locked=0"):
        for mode_depth in (0, 1, 2):
            for perm_depth in (1, 2, 3):
                plan = []
                if mode_depth:
                    plan += ["toggle-pmp-address-mode"] * mode_depth
                plan.append(locked_op)
                plan += ["toggle-pmp-permissions"] * perm_depth
                plans.append(plan)
    for perm_depth in (1, 2, 3):
        plans.append(["toggle-pmp-permissions"] * perm_depth)
    return plans


def _mutate_chain(base_spec: dict[str, Any], *, plan: list[str], attempt: int, seed: int):
    from pmpfuzz.continuous import ScenarioStream

    stream = ScenarioStream(root_seed=seed, include_experimental=False)
    spec = dict(base_spec)
    for op in plan:
        spec = scenario_to_spec(stream.mutate(spec, op, attempt))
    return scenario_from_spec(spec)


def generate_corpus(*, universe: dict[str, Any], seed: int, target: int, time_budget: float) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    reachable_set = set(C.reachable_bins(universe))
    profiles = C.ROUND_GENERATOR_PROFILES
    stream = ScenarioStream(
        root_seed=seed,
        include_experimental=False,
        profiles=profiles,
    )
    candidates: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()
    case_index = 0
    root_seq = 0
    started = time.time()
    stats = {"roots_seen": 0, "mutations_tried": 0, "mutations_accepted": 0}
    max_roots = 12000
    while len(candidates) < target and root_seq < max_roots:
        if time.time() - started > time_budget:
            stats["stopped"] = "time_budget"
            break
        root_meta = stream.generate_root_with_metadata(root_seq)
        root = root_meta.scenario
        profile = root_meta.profile
        generator_index = root_meta.scenario_index
        stats["roots_seen"] += 1

        def _try_add(scenario, profile, generator_index, mutation, source):
            nonlocal case_index
            scenario_hash_value = scenario_hash(scenario_to_spec(scenario))
            if scenario_hash_value in seen_hashes:
                return
            cand = _collect_candidate(
                scenario=scenario,
                profile=profile,
                generator_index=generator_index,
                seed=seed,
                case_index=case_index,
                mutation=mutation,
                source=source,
                reachable_set=reachable_set,
            )
            if cand is None:
                return
            seen_hashes.add(scenario_hash_value)
            candidates.append(cand)
            case_index += 1

        _try_add(root, profile, generator_index, "root", "scenario-generator")



        if root_seq % 4 == 0:
            parent_spec = scenario_to_spec(root)
            for op in C.CORPUS_MUTATION_OPERATORS:
                for attempt in range(4):
                    stats["mutations_tried"] += 1
                    try:
                        mutated = stream.mutate(parent_spec, op, attempt)
                    except ValueError:
                        continue
                    mut_hash = scenario_hash(scenario_to_spec(mutated))
                    if mut_hash in seen_hashes:
                        continue
                    stats["mutations_accepted"] += 1
                    _try_add(mutated, profile, generator_index, op, "mutation")
        root_seq += 1





    candidates = _enrich_missing_config_classes(
        candidates=candidates,
        seen_hashes=seen_hashes,
        reachable_set=reachable_set,
        seed=seed,
        target_classes=_reachable_config_classes(reachable_set),
        time_budget=max(60.0, time_budget - (time.time() - started)),
        stats=stats,
    )

    stats["candidates"] = len(candidates)
    stats["unique_scenarios"] = len(seen_hashes)
    stats["roots_generated"] = root_seq
    return candidates, stats


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build U74 closedloop-144 candidate corpus")
    parser.add_argument("--universe", type=Path, required=True,
                        help="fixed 144-bin universe file (sha 3aa0ee...73cd0)")
    parser.add_argument("--out-dir", type=Path, required=True,
                        help="corpus output dir (writes corpus.json + corpus-hash.json)")
    parser.add_argument("--seed", type=int, default=4)
    parser.add_argument("--target", type=int, default=1200,
                        help="minimum number of unique lowering-valid candidates")
    parser.add_argument("--time-budget", type=float, default=3600.0,
                        help="wall-clock cap in seconds for generation")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    universe = C.load_universe(args.universe)
    candidates, stats = generate_corpus(
        universe=universe,
        seed=args.seed,
        target=args.target,
        time_budget=args.time_budget,
    )
    if len(candidates) < args.target:
        raise SystemExit(
            f"corpus build produced only {len(candidates)} candidates "
            f"(target {args.target}); increase time budget or reduce target"
        )

    firmware_ready = [c for c in candidates if c["firmware_ready"]]
    unsupported_bins = C.compute_unsupported_bins(universe)
    reachable = C.reachable_bins(universe)

    payload = {
        "schema_version": 1,
        "kind": "u74-cl144-candidate-corpus",
        "universe_sha256": C.CONTRACT_UNIVERSE_SHA256,
        "capability_fingerprint": C.CONTRACT_CAPABILITY_FINGERPRINT,
        "seed": args.seed,
        "generator_profiles": list(C.ROUND_GENERATOR_PROFILES),
        "target": args.target,
        "count": len(candidates),
        "firmware_ready_count": len(firmware_ready),
        "not_firmware_ready_count": len(candidates) - len(firmware_ready),
        "universe_bin_count": int(universe["bin_count"]),
        "reachable_bin_count": len(reachable),
        "unsupported_bin_count": len(unsupported_bins),
        "unsupported_bins": unsupported_bins,
        "generation_stats": stats,
        "candidates": candidates,
    }
    C.write_json(args.out_dir / "corpus.json", payload)

    fingerprint = C.sha256_payload(
        {
            "kind": "u74-cl144-candidate-corpus-v1",
            "universe_sha256": C.CONTRACT_UNIVERSE_SHA256,
            "seed": args.seed,
            "profiles": list(C.ROUND_GENERATOR_PROFILES),
            "candidates": [
                (c["candidate_id"], c["scenario_hash"], c["firmware_ready"])
                for c in candidates
            ],
        }
    )
    hash_payload = {
        "schema_version": 1,
        "corpus_path": str(args.out_dir / "corpus.json"),
        "corpus_sha256": C.sha256_file(args.out_dir / "corpus.json"),
        "corpus_fingerprint": fingerprint,
        "count": len(candidates),
        "reachable_bin_count": len(reachable),
        "unsupported_bin_count": len(unsupported_bins),
        "universe_sha256": C.CONTRACT_UNIVERSE_SHA256,
        "generated_utc": None,
    }
    C.write_json(args.out_dir / "corpus-hash.json", hash_payload)

    firmware_ready = [c for c in candidates if c["firmware_ready"]]
    print(f"corpus: {len(candidates)} candidates "
          f"({len(firmware_ready)} firmware-ready, {len(candidates)-len(firmware_ready)} TOR/locked) "
          f"reachable {len(reachable)}/144 unsupported {len(unsupported_bins)}")
    print(f"fingerprint: {fingerprint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
