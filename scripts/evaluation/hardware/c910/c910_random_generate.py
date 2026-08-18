#!/usr/bin/env python3
"""Unguided random generation for the C910 closedloop-56 campaign.

Same machinery as the guided generator but without guidance: no directed
construction, parents chosen uniformly (not by coverage value), mutation
operators chosen uniformly.  Round 0 (breadth seed) is shared with guided so
the two conditions start from the same base.

Usage mirrors ``c910_guided_generate.py``.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from random import Random
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from c910_cl56_common import (
    FILL_OPS,
    REACHABLE_BINS,
    assemble_generated,
    mutate_parent_params,
    sha256_text,
)
from c910_guided_generate import (
    _catalog_mapped_cases,
    _constructed_breadth_pool,
    breadth_round,
    emit_round,
)


def random_round(
    *,
    seed_pool: list[dict[str, Any]],
    budget: int,
    seed: int,
    used_hashes: set[str],
    max_tries_per_mutation: int = 6,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rng = Random(seed)
    generated: list[dict[str, Any]] = []
    seen = set(used_hashes)
    index = 0
    log: dict[str, Any] = {"fill_ops": {}}

    parents = [p for p in seed_pool if not p.get("board_unstable")]
    while len(generated) < budget:
        progress = False
        order = list(parents)
        rng.shuffle(order)
        for parent in order:
            if len(generated) >= budget:
                break
            op = FILL_OPS[rng.randrange(len(FILL_OPS))]
            for attempt in range(max_tries_per_mutation):
                params = mutate_parent_params(parent, op, attempt, seed=seed + index * 31)
                if params is None:
                    continue
                case = assemble_generated(
                    params, index=index, target_bin="",
                    operator=f"random:{op}", parent_id=str(parent.get("name") or ""),
                    seed=seed, record_name=f"rnd-{index:04d}",
                )
                if case is not None and case["scenario_hash"] not in seen:
                    seen.add(case["scenario_hash"])
                    case["_meta"]["operator"] = f"random:{op}"
                    generated.append(case)
                    index += 1
                    log["fill_ops"][op] = log["fill_ops"].get(op, 0) + 1
                    progress = True
                    break
        if not progress and len(generated) < budget:
            break

    stats = {
        "mode": "random-generate",
        "budget": budget,
        "generated_count": len(generated),
        "fill_ops": log["fill_ops"],
    }
    return generated, {"stats": stats, "log": log}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="C910 closedloop-56 unguided random generation")
    parser.add_argument("--seed-pool", type=Path, required=True)
    parser.add_argument("--round-index", type=int, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--budget", type=int, default=16)
    parser.add_argument("--seed", type=int, default=101)
    parser.add_argument("--prior-summary", type=Path, default=None)
    args = parser.parse_args(argv)

    seed_pool = json.loads(Path(args.seed_pool).read_text(encoding="utf-8")).get("candidates") or []
    prior = json.loads(Path(args.prior_summary).read_text(encoding="utf-8")) if args.prior_summary and Path(args.prior_summary).exists() else None
    prior_covered = list((prior or {}).get("cumulative_covered_bins") or [])
    used_hashes = set(str(h) for h in ((prior or {}).get("executed_scenario_hashes") or []))
    seed_pool_hash = sha256_text(json.dumps([c.get("scenario_hash") for c in seed_pool], sort_keys=True))
    selection_source = f"c910-random-generate-v1-r{args.round_index:04d}"

    if args.round_index == 0:
        pool = _catalog_mapped_cases() + _constructed_breadth_pool(args.seed)
        selected, result = breadth_round(
            pool=pool, budget=args.budget, seed=args.seed, used_hashes=used_hashes,
        )
        selected_catalog = [c for c in selected if c.get("_meta", {}).get("operator") == "catalog"]
        generated = [c for c in selected if c.get("_meta", {}).get("operator") != "catalog"]
    else:
        selected_catalog: list[dict[str, Any]] = []
        generated, result = random_round(
            seed_pool=seed_pool, budget=args.budget,
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
