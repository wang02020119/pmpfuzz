#!/usr/bin/env python3
"""Coverage-guided GENERATION for the C910 closedloop-56 campaign (protocol v2).

Round 0: breadth seed -- greedy predicted-coverage over the seed pool plus a
directed construction for every reachable bin.

Rounds r >= 1: for each real-missing reachable bin, construct a params tuple
whose predicted bins contain it; fill the remaining budget with deterministic
parent mutations (coverage-weighted).  Each generated case is a new
scenario_hash executed by the probe's parameterized case-runner (manifest v3).

Usage:
    PYTHONPATH=. python scripts/evaluation/hardware/c910/c910_guided_generate.py \
        --seed-pool .../aggregation/seed-pool.json \
        --round-index 1 --budget 16 --seed 4 \
        --prior-summary .../aggregation/round-0000-summary.json \
        --out-dir .../rounds/round-0001
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from random import Random
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from pmpfuzz.c910_nonpmp_dynamic import build_dynamic_manifest, generated_manifest_source
from pmpfuzz.c910_m2_scheduling import predict_shared56_bins

from c910_cl56_common import (
    FILL_OPS,
    REACHABLE_BINS,
    assemble_generated,
    board_mappable,
    construct_params_for_bin,
    load_seed_pool,
    mutate_parent_params,
    sha256_text,
)

CAMPAIGN_ID = "hw-v2-m4-c910-closedloop-56"


# ---------------------------------------------------------------------------
# round-0 breadth
# ---------------------------------------------------------------------------

def _catalog_mapped_cases() -> list[dict[str, Any]]:
    from pmpfuzz.c910_nonpmp_dynamic import catalog_cases

    out: list[dict[str, Any]] = []
    for case in catalog_cases():
        if not board_mappable(case):
            continue
        predicted = predict_shared56_bins(case)
        if predicted.get("status") != "mapped":
            continue
        case = dict(case)
        case["predicted_bins"] = list(predicted.get("bins") or [])
        case["_meta"] = {"target_bin": "", "operator": "catalog", "parent_id": ""}
        out.append(case)
    return out


def _constructed_breadth_pool(seed: int) -> list[dict[str, Any]]:
    pool: list[dict[str, Any]] = []
    for index, bin_id in enumerate(REACHABLE_BINS):
        params = construct_params_for_bin(bin_id, index, seed)
        if params is None:
            continue
        case = assemble_generated(
            params, index=index, target_bin=bin_id,
            operator="construct:breadth", parent_id="", seed=seed,
            record_name=f"gen-breadth-{index:04d}",
        )
        if case is not None:
            pool.append(case)
    return pool


def _select_greedy(
    pool: list[dict[str, Any]],
    *,
    budget: int,
    seed: int,
    used_hashes: set[str],
) -> list[dict[str, Any]]:
    """Deterministic greedy: maximize new predicted bins, unique records."""
    rng = Random(seed)
    candidates = [c for c in pool if c["scenario_hash"] not in used_hashes]
    rng.shuffle(candidates)
    selected: list[dict[str, Any]] = []
    used_records: set[str] = set()
    covered: set[str] = set()
    for _ in range(budget):
        best: dict[str, Any] | None = None
        best_key: tuple[int, int] | None = None
        for index, cand in enumerate(candidates):
            record = str(cand["uart_record"])
            if record in used_records:
                continue
            gain = len(set(cand.get("predicted_bins") or []) - covered)
            key = (gain, -index)
            if best_key is None or key > best_key:
                best = cand
                best_key = key
        if best is None:
            break
        selected.append(best)
        covered.update(best.get("predicted_bins") or [])
        used_records.add(str(best["uart_record"]))
        candidates.remove(best)
    return selected


def breadth_round(*, pool: list[dict[str, Any]], budget: int, seed: int,
                  used_hashes: set[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    selected = _select_greedy(pool, budget=budget, seed=seed, used_hashes=used_hashes)
    stats = {
        "mode": "breadth",
        "budget": budget,
        "selected_count": len(selected),
        "covered_bins_estimate": len(
            set().union(*(set(c.get("predicted_bins") or []) for c in selected))
        ),
    }
    return selected, {"stats": stats, "log": {}}


# ---------------------------------------------------------------------------
# guided generation rounds (r >= 1)
# ---------------------------------------------------------------------------

def guided_round(
    *,
    seed_pool: list[dict[str, Any]],
    missing: list[str],
    budget: int,
    seed: int,
    used_hashes: set[str],
    max_tries_per_mutation: int = 6,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Guided round: (catalog_selected, generated, result).

    For each missing reachable bin: directed construction first; if the bin is
    outside the parameterized-runner vocabulary (e.g. fetch), fall back to a
    catalog case that predicts it.  Remaining budget is filled by coverage-
    weighted parent mutations.
    """
    rng = Random(seed)
    generated: list[dict[str, Any]] = []
    catalog_selected: list[dict[str, Any]] = []
    seen = set(used_hashes)
    used_records: set[str] = set()
    index = 0
    log: dict[str, Any] = {"missing_bins": list(missing), "targeted": [], "skipped_targets": [], "fill_ops": {}}

    def _try_add(case: dict[str, Any] | None, *, target: str, operator: str, parent_id: str, generated_case: bool = True) -> bool:
        nonlocal index
        if case is None:
            return False
        if case["scenario_hash"] in seen:
            return False
        if str(case["uart_record"]) in used_records:
            return False
        seen.add(case["scenario_hash"])
        used_records.add(str(case["uart_record"]))
        case = dict(case)
        case["_meta"] = {
            "target_bin": target,
            "operator": operator,
            "parent_id": parent_id,
            "generation_seed": seed,
        }
        if generated_case:
            generated.append(case)
        else:
            catalog_selected.append(case)
        index += 1
        return True

    catalog_candidates = [c for c in seed_pool if c.get("source") == "catalog"]

    # 1. directed construction (with catalog fallback) for each missing bin.
    for target in missing:
        if len(generated) + len(catalog_selected) >= budget:
            break
        params = construct_params_for_bin(target, index, seed)
        case = None
        operator = ""
        if params is not None:
            case = assemble_generated(
                params, index=index, target_bin=target,
                operator=f"construct:{target.split('|')[0]}", parent_id="", seed=seed,
                record_name=f"gen-r{index:04d}",
            )
            operator = f"construct:{target.split('|')[0]}"
        if case is None:
            # bin not in the parameterized vocabulary -> catalog fallback,
            # skipping candidates whose hash/record is already executed.
            fallback = _pick_catalog_for_bin(catalog_candidates, target, seen, used_records)
            if fallback is not None:
                case = fallback
                operator = "select:catalog"
        is_fallback = operator == "select:catalog"
        if case is not None and _try_add(
            case, target=target, operator=operator, parent_id="",
            generated_case=not is_fallback,
        ):
            log["targeted"].append(target)
        else:
            log["skipped_targets"].append({"bin": target, "reason": "no-construction-and-no-catalog-fallback"})

    # 2. parent-mutation fill (coverage-weighted by predicted new bins).
    def _parent_weight(p: dict[str, Any]) -> int:
        return len(set(p.get("predicted_bins") or []) & set(missing))

    ranked = sorted(seed_pool, key=_parent_weight, reverse=True)
    while len(generated) + len(catalog_selected) < budget:
        progress = False
        for parent in ranked:
            if len(generated) + len(catalog_selected) >= budget:
                break
            for op in FILL_OPS:
                if len(generated) + len(catalog_selected) >= budget:
                    break
                for attempt in range(max_tries_per_mutation):
                    params = mutate_parent_params(parent, op, attempt, seed=seed)
                    if params is None:
                        continue
                    case = assemble_generated(
                        params, index=index, target_bin="",
                        operator=f"fill:{op}", parent_id=str(parent.get("name") or ""),
                        seed=seed, record_name=f"gen-fill-{index:04d}",
                    )
                    if case is not None:
                        if _try_add(case, target="", operator=f"fill:{op}", parent_id=str(parent.get("name") or "")):
                            progress = True
                            log["fill_ops"][op] = log["fill_ops"].get(op, 0) + 1
                            break
        if not progress and len(generated) + len(catalog_selected) < budget:
            break

    stats = {
        "mode": "guided-generate",
        "budget": budget,
        "generated_count": len(generated),
        "catalog_count": len(catalog_selected),
        "missing_count": len(missing),
        "targeted_bin_count": len(log["targeted"]),
        "skipped_target_count": len(log["skipped_targets"]),
        "fill_ops": log["fill_ops"],
    }
    return catalog_selected, generated, {"stats": stats, "log": log}


def _pick_catalog_for_bin(
    catalog_candidates: list[dict[str, Any]], target: str,
    used_hashes: set[str] | None = None, used_records: set[str] | None = None,
) -> dict[str, Any] | None:
    """Pick a catalog case whose predicted bins contain ``target``.

    Used as the fallback when a missing bin is outside the parameterized-runner
    vocabulary (e.g. fetch stimulus).  Deterministic: first candidate in pool
    order whose hash has not been executed and whose base record is not already
    selected in this round (slot variants share the base record).
    """
    used_h = set(used_hashes or ())
    used_r = set(used_records or ())
    for cand in catalog_candidates:
        if cand.get("scenario_hash") in used_h:
            continue
        if str(cand.get("uart_record") or "") in used_r:
            continue
        if target in set(cand.get("predicted_bins") or []):
            return cand
    return None


# ---------------------------------------------------------------------------
# emission
# ---------------------------------------------------------------------------

def emit_round(
    *,
    selected_catalog: list[dict[str, Any]],
    generated: list[dict[str, Any]],
    round_index: int,
    seed: int,
    selection_source: str,
    out_dir: Path,
    stats: dict[str, Any],
    log: dict[str, Any],
    prior_covered: list[str],
    seed_pool_hash: str,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    estimated = {
        c["name"]: max(0, len(set(c.get("predicted_bins") or [])))
        for c in (selected_catalog + generated)
    }
    manifest = build_dynamic_manifest(
        case_names=[c["name"] for c in selected_catalog],
        generated_cases=generated,
        campaign_id=CAMPAIGN_ID,
        round_id=f"round-{round_index:04d}",
        selection_source=selection_source,
        estimated_new_bins_by_case=estimated,
    )
    (out_dir / f"manifest-v3.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (out_dir / f"c910_nonpmp_generated_manifest.c").write_text(
        generated_manifest_source(manifest), encoding="ascii"
    )

    schedule = {
        "schema_version": 3,
        "round_id": f"round-{round_index:04d}",
        "campaign_id": CAMPAIGN_ID,
        "seed": seed,
        "selection_source": selection_source,
        "selection_summary": stats,
        "entries": [
            {
                "case_id": c["name"],
                "record": c["uart_record"],
                "scenario_hash": c["scenario_hash"],
                "predicted_bins": list(c.get("predicted_bins") or []),
                "operator": c.get("_meta", {}).get("operator"),
                "parent_case_id": c.get("_meta", {}).get("parent_id"),
                "target_bin": c.get("_meta", {}).get("target_bin"),
                "params": dict(c.get("generated_params") or {}),
            }
            for c in (selected_catalog + generated)
        ],
    }
    (out_dir / f"schedule_round_{round_index:04d}.json").write_text(
        json.dumps(schedule, indent=2), encoding="utf-8"
    )

    generation_log = {
        "schema_version": 1,
        "round_id": f"round-{round_index:04d}",
        "mode": stats.get("mode"),
        "seed": seed,
        "selection_source": selection_source,
        "seed_pool_hash": seed_pool_hash,
        "prior_covered_bins": sorted(prior_covered),
        "missing_bins": list(log.get("missing_bins") or []),
        "targeted_bins": list(log.get("targeted") or []),
        "skipped_targets": list(log.get("skipped_targets") or []),
        "fill_ops": dict(log.get("fill_ops") or {}),
        "generated": [
            {
                "name": c["name"],
                "scenario_hash": c["scenario_hash"],
                "operator": c.get("_meta", {}).get("operator"),
                "parent_case_id": c.get("_meta", {}).get("parent_id"),
                "target_bin": c.get("_meta", {}).get("target_bin"),
                "predicted_bins": list(c.get("predicted_bins") or []),
            }
            for c in generated
        ],
        "unsupported_bins": sorted(
            set(
                (
                    __import__("pmpfuzz.v4_nonpmp_projection", fromlist=["build_v4_nonpmp_bin_ids"]).build_v4_nonpmp_bin_ids()
                )
            )
            - set(REACHABLE_BINS)
        ),
        "unsupported_bin_count": 56 - len(REACHABLE_BINS),
    }
    (out_dir / "generation-log.json").write_text(json.dumps(generation_log, indent=2), encoding="utf-8")
    print(f"{selection_source} round-{round_index:04d}: {stats}")


def _load_prior_summary(path: Path | None) -> dict[str, Any] | None:
    if path is None or not Path(path).exists():
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="C910 closedloop-56 coverage-guided generation")
    parser.add_argument("--seed-pool", type=Path, required=True)
    parser.add_argument("--round-index", type=int, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--budget", type=int, default=16)
    parser.add_argument("--seed", type=int, default=4)
    parser.add_argument("--prior-summary", type=Path, default=None)
    args = parser.parse_args(argv)

    seed_pool = load_seed_pool(args.seed_pool)
    prior = _load_prior_summary(args.prior_summary)
    prior_covered = list((prior or {}).get("cumulative_covered_bins") or [])
    used_hashes = set(str(h) for h in ((prior or {}).get("executed_scenario_hashes") or []))
    seed_pool_hash = sha256_text(json.dumps([c.get("scenario_hash") for c in seed_pool], sort_keys=True))

    rng = Random((args.seed + args.round_index * 7919) & 0x7FFFFFFF)
    selection_source = f"c910-guided-generate-v1-r{args.round_index:04d}"

    if args.round_index == 0:
        pool = _catalog_mapped_cases() + _constructed_breadth_pool(args.seed)
        selected, result = breadth_round(
            pool=pool, budget=args.budget, seed=args.seed, used_hashes=used_hashes,
        )
        selected_catalog = [c for c in selected if c.get("_meta", {}).get("operator") == "catalog"]
        generated = [c for c in selected if c.get("_meta", {}).get("operator") != "catalog"]
    else:
        missing = [b for b in REACHABLE_BINS if b not in set(prior_covered)]
        selected_catalog, generated, result = guided_round(
            seed_pool=seed_pool, missing=missing, budget=args.budget,
            seed=args.seed, used_hashes=used_hashes,
        )

    if len(selected_catalog) + len(generated) == 0:
        raise SystemExit("generation produced no cases")

    emit_round(
        selected_catalog=selected_catalog,
        generated=generated,
        round_index=args.round_index,
        seed=args.seed,
        selection_source=selection_source,
        out_dir=args.out_dir,
        stats=result["stats"],
        log=result["log"],
        prior_covered=prior_covered,
        seed_pool_hash=seed_pool_hash,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
