#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from random import Random
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pmpfuzz.scenario import TARGET_BASE, PmpScenario
from pmpfuzz.scenario_codec import scenario_from_spec

import u74_cl144_common as C
from u74_guided_generate import (
    _fill_mutate,
    _assemble,
)
from u74_guided_select import build_catalog_entries, build_schedule_entries


_OPS = ("toggle-pmp-permissions", "toggle-access", "toggle-privilege",
        "toggle-mprv-mpp", "toggle-pmp-address-mode")


def random_generate_round(
    *,
    seed_pool: list[dict[str, Any]],
    universe: dict[str, Any],
    prior_summary: dict[str, Any] | None,
    round_index: int,
    budget: int,
    seed: int,
    executed_hashes: set[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    import u74_guided_generate as G

    G._REACHABLE = C.reachable_bins(universe)
    parents = [p for p in seed_pool if not p.get("board_unstable") and p.get("scenario_spec")]
    rng = Random((int(seed) + int(round_index) * 104729) & 0x7FFFFFFF)

    generated: list[dict[str, Any]] = []
    seen_hashes = set(executed_hashes)
    index = 0
    op_counts: dict[str, int] = {}
    attempts = 0

    while len(generated) < budget:
        parent = parents[rng.randrange(len(parents))]
        op = _OPS[rng.randrange(len(_OPS))]
        attempt = rng.randrange(8)
        attempts += 1
        try:
            parent_scenario = scenario_from_spec(parent["scenario_spec"])
        except Exception:
            continue
        mutated = _fill_mutate(parent_scenario, op, attempt, seed=seed)
        if mutated is None:
            continue
        name = f"u74-cl144-r{round_index}-case-{index:04d}"
        cand = _assemble(
            mutated, seed=seed, index=index, name=name,
            target="", operator=f"random:{op}",
            parent_id=str(parent.get("candidate_id") or parent.get("name") or ""),
        )
        if cand is None:
            continue
        if cand["scenario_hash"] in seen_hashes:
            continue
        seen_hashes.add(cand["scenario_hash"])
        generated.append(cand)
        op_counts[op] = op_counts.get(op, 0) + 1
        index += 1
        if attempts > 200000:
            break

    if len(generated) < budget:
        raise RuntimeError(
            f"random generation produced only {len(generated)}/{budget} candidates"
        )
    stats = {"budget": budget, "generated_count": len(generated), "attempts": attempts, "op_counts": op_counts}
    return generated, stats


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="U74 closedloop-144 unguided random generation")
    parser.add_argument("--seed-pool", type=Path, required=True)
    parser.add_argument("--universe", type=Path, required=True)
    parser.add_argument("--round-index", type=int, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--budget", type=int, default=96)
    parser.add_argument("--seed", type=int, default=101)
    parser.add_argument("--prior-summary", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    universe = C.load_universe(args.universe)
    seed_pool = C.load_json(args.seed_pool).get("candidates") or []
    prior = C.load_json(args.prior_summary) if Path(args.prior_summary).exists() else None
    executed_hashes = set(str(h) for h in ((prior or {}).get("executed_scenario_hashes") or []))

    generated, stats = random_generate_round(
        seed_pool=seed_pool, universe=universe, prior_summary=prior,
        round_index=args.round_index, budget=args.budget, seed=args.seed,
        executed_hashes=executed_hashes,
    )
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    schedule_entries = build_schedule_entries(
        [(c, {"marginal_gain": 0, "predicted_bins": c.get("predicted_bins") or [],
              "predicted_new_bins": [], "config_classes": c.get("config_classes") or []}) for c in generated],
        round_index=args.round_index, selection_source="u74-random-generate-v1",
    )
    for entry, cand in zip(schedule_entries, generated):
        entry["operator"] = cand.get("operator")
        entry["parent_case_id"] = cand.get("parent_case_id") or ""
    schedule = {
        "schema_version": 1,
        "round_id": f"round-{args.round_index:04d}",
        "campaign_id": f"{C.CAMPAIGN_ID}-random-{args.seed:04d}",
        "seed": args.seed,
        "selection_source": "u74-random-generate-v1",
        "selection_summary": {"mode": "random-generate", "budget": len(generated), "count": len(generated)},
        "entries": schedule_entries,
    }
    C.write_json(out / f"schedule_round_{args.round_index:04d}.json", schedule)
    C.write_json(out / "catalog.json", {"schema_version": 1, "cases": build_catalog_entries(schedule_entries)})
    C.write_json(out / "generation-log.json", {
        "schema_version": 1,
        "round_id": f"round-{args.round_index:04d}",
        "mode": "random-generate",
        "seed": args.seed,
        "budget": len(generated),
        "selection_source": "u74-random-generate-v1",
        "tie_break_rule": "uniform parent + uniform operator; no coverage input",
        "seed_pool_path": str(args.seed_pool),
        "op_counts": stats["op_counts"],
        "generated": [
            {"name": c["name"], "candidate_id": c["candidate_id"], "scenario_hash": c["scenario_hash"],
             "operator": c.get("operator"), "parent_case_id": c.get("parent_case_id")}
            for c in generated
        ],
        "unsupported_bins": C.compute_unsupported_bins(universe),
        "unsupported_bin_count": len(C.compute_unsupported_bins(universe)),
    })

    print(f"random-generate round-{args.round_index:04d} seed={args.seed}: "
          f"generated {stats['generated_count']}/{stats['budget']} (attempts {stats['attempts']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
