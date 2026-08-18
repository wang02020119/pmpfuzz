#!/usr/bin/env python3
"""Random-control selection for the U74 closedloop-144 experiment.

PROTOCOL §6: the same frozen candidate corpus, same round size, and same
board/validation/aggregation rules as the guided campaign, but the schedule is
sampled *uniformly without replacement* instead of by coverage marginal gain.
Each random campaign uses a distinct seed; at least three seeds are planned
(two minimum pilot).

Writes the same artifacts as ``u74_guided_select.py`` so the rest of the
pipeline (board runner, aggregation, convergence) is bit-for-bit shared.

Usage:

    PYTHONPATH=. python scripts/evaluation/hardware/u74/u74_random_select.py \
        --corpus <...>/corpus/corpus.json \
        --universe <...>/u74-supported-v4-144.json \
        --round-index 0 --budget 96 --seed 101 \
        --campaign-id closedloop-144-random-0101 \
        --out-dir <...>/random/run-seed-0101/rounds/round-0000
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from random import Random
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import u74_cl144_common as C
from u74_guided_select import build_catalog_entries, build_schedule_entries


def select_random(
    corpus: list[dict[str, Any]],
    *,
    budget: int,
    seed: int,
    round_index: int,
    executed_hashes: set[str],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], dict[str, Any]]:
    rng = Random((int(seed) + int(round_index) * 104729) & 0x7FFFFFFF)
    pool = [
        cand for cand in corpus
        if cand.get("firmware_ready")
        and not cand.get("board_unstable")
        and not (cand.get("has_tor") and cand.get("has_locked"))
        and str(cand.get("scenario_hash") or "") not in executed_hashes
    ]
    rng.shuffle(pool)
    selected = [
        (
            cand,
            {
                "marginal_gain": None,  # random sampling does not score coverage
                "predicted_bins": sorted(cand.get("predicted_reachable_bins") or []),
                "predicted_new_bins": [],
                "config_classes": [list(c) for c in cand.get("config_classes") or []],
            },
        )
        for cand in pool[:budget]
    ]
    if len(selected) < budget:
        raise RuntimeError(
            f"random selection could not fill budget: {len(selected)}/{budget}"
        )
    selected_ids = {str(c["candidate_id"]) for c, _ in selected}
    rejected_ids = [str(c["candidate_id"]) for c in pool if str(c["candidate_id"]) not in selected_ids]
    stats = {
        "mode": "random",
        "seed": seed,
        "budget": budget,
        "pool_size": len(pool),
        "selected_count": len(selected),
        "rejected_count": len(rejected_ids),
    }
    return selected, stats


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="U74 closedloop-144 random-control selection")
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--universe", type=Path, required=True)
    parser.add_argument("--round-index", type=int, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--budget", type=int, default=96)
    parser.add_argument("--seed", type=int, default=101)
    parser.add_argument("--campaign-id", default=C.CAMPAIGN_ID)
    parser.add_argument("--prior-summary", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    universe = C.load_universe(args.universe)
    corpus = C.load_json(args.corpus).get("candidates") or []
    reachable = set(C.reachable_bins(universe))
    unsupported_bins = C.compute_unsupported_bins(universe)

    executed_hashes: set[str] = set()
    if args.prior_summary is not None and Path(args.prior_summary).exists():
        prior = C.load_json(args.prior_summary)
        executed_hashes = set(str(h) for h in (prior.get("executed_scenario_hashes") or []))

    selected, stats = select_random(
        corpus,
        budget=args.budget,
        seed=args.seed,
        round_index=args.round_index,
        executed_hashes=executed_hashes,
    )

    selection_source = "u74-random-v1"
    entries = build_schedule_entries(selected, round_index=args.round_index, selection_source=selection_source)
    schedule = {
        "schema_version": 1,
        "round_id": f"round-{args.round_index:04d}",
        "campaign_id": args.campaign_id,
        "seed": args.seed,
        "selection_source": selection_source,
        "selection_summary": {
            "mode": "random",
            "budget": args.budget,
            "count": len(entries),
            "prior_covered_count": 0,
            "missing_reachable_count": len(reachable),
        },
        "entries": entries,
    }
    out = Path(args.out_dir)
    C.write_json(out / f"schedule_round_{args.round_index:04d}.json", schedule)
    C.write_json(out / "catalog.json", {"schema_version": 1, "cases": build_catalog_entries(entries)})

    corpus_meta = C.load_json(args.corpus)
    selection_log = {
        "schema_version": 1,
        "round_id": f"round-{args.round_index:04d}",
        "mode": "random",
        "seed": args.seed,
        "budget": args.budget,
        "selection_source": selection_source,
        "tie_break_rule": "uniform without replacement; seeded shuffle only",
        "corpus_fingerprint": str((corpus_meta.get("corpus") and corpus_meta["corpus"].get("corpus_fingerprint")) or corpus_meta.get("corpus_fingerprint") or ""),
        "corpus_path": str(args.corpus),
        "corpus_count": len(corpus),
        "universe_sha256": C.CONTRACT_UNIVERSE_SHA256,
        "reachable_bin_count": len(reachable),
        "selected_candidate_ids": [str(c["candidate_id"]) for c, _ in selected],
        "selected_scenario_hashes": [str(c["scenario_hash"]) for c, _ in selected],
        "rejected_candidate_ids": _rejected_ids(selected, corpus, executed_hashes),
        "selection_details": {str(c["candidate_id"]): d for c, d in selected},
        "unsupported_bins": unsupported_bins,
        "unsupported_bin_count": len(unsupported_bins),
    }
    C.write_json(out / "selection-log.json", selection_log)

    print(f"random round-{args.round_index:04d} seed={args.seed}: selected {len(selected)} from {stats['pool_size']}")
    return 0


def _rejected_ids(selected: list[tuple[dict[str, Any], dict[str, Any]]], corpus: list[dict[str, Any]], executed_hashes: set[str]) -> list[str]:
    selected_ids = {str(c["candidate_id"]) for c, _ in selected}
    return sorted(
        str(c["candidate_id"])
        for c in corpus
        if str(c["candidate_id"]) not in selected_ids
        and str(c.get("scenario_hash") or "") not in executed_hashes
        and c.get("firmware_ready")
        and not c.get("board_unstable")
    )


if __name__ == "__main__":
    raise SystemExit(main())
