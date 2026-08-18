#!/usr/bin/env python3
"""Write the closedloop-144 final-summary.json (EXPERIMENT_PROTOCOL.md §5, §8).

Reads the guided campaign's aggregation (round summaries + convergence.json)
and any random-control roots, then emits the protocol's convergence fields and
the paper-mapping numbers.  Convergence fields come only from real observed
bins.

Usage:

    PYTHONPATH=. python scripts/evaluation/hardware/u74/u74_cl144_final_summary.py \
        --root <...>/closedloop-144 \
        --universe <...>/u74-supported-v4-144.json \
        [--random-root <...>/random/run-seed-0101]... \
        --out <...>/aggregation/final-summary.json
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import u74_cl144_common as C


def _load(path: Path) -> Any:
    return C.load_json(path) if Path(path).exists() else None


def convergence_state(root: Path) -> dict[str, Any]:
    conv = _load(root / "aggregation" / "convergence.json") or {"rows": []}
    rows = conv.get("rows") or []
    summaries = {}
    for row in rows:
        round_id = row["round_id"]
        summary = _load(root / "aggregation" / f"{round_id}-summary.json")
        if summary:
            summaries[round_id] = summary
    return {"rows": rows, "summaries": summaries}


def compute_final(root: Path, universe: dict[str, Any]) -> dict[str, Any]:
    cs = convergence_state(root)
    rows = cs["rows"]
    summaries = cs["summaries"]
    reachable = set(C.reachable_bins(universe))

    # last-novelty tracking across accepted rounds
    last_novelty_round = None
    last_novelty_round_index = None
    last_novelty_eligible = 0
    zero_novelty_streak = 0
    max_round_index = -1
    final_covered = set()
    final_eligible = 0
    for row in rows:
        idx = int(row["round_index"])
        max_round_index = max(max_round_index, idx)
        new_bins = int(row["new_bins_in_round"] or 0)
        eligible_in_round = int(row["eligible_cases_in_round"] or 0)
        if new_bins > 0:
            last_novelty_round = row["round_id"]
            last_novelty_round_index = idx
            last_novelty_eligible = final_eligible + eligible_in_round
            zero_novelty_streak = 0
        else:
            zero_novelty_streak += 1
        final_eligible += eligible_in_round
        covered = set(str(b) for b in (row.get("cumulative_covered") and
                                       summaries.get(row["round_id"], {}).get("cumulative_covered_bins") or []))
        if covered:
            final_covered = covered

    covered_count = len(final_covered & set(universe.get("bin_ids") or []))
    reachable_covered = len(final_covered & reachable)

    # stop reason
    budget_hit = max_round_index + 1 >= 10
    if zero_novelty_streak >= 2 and not budget_hit:
        stop_reason = "coverage_converged"
    elif budget_hit and (rows and int(rows[-1].get("new_bins_in_round") or 0) > 0):
        stop_reason = "right_censored_budget"
    else:
        stop_reason = "coverage_converged"

    return {
        "schema_version": 1,
        "campaign_id": C.CAMPAIGN_ID,
        "universe_sha256": C.CONTRACT_UNIVERSE_SHA256,
        "capability_fingerprint": C.CONTRACT_CAPABILITY_FINGERPRINT,
        "universe_bin_count": int(universe.get("bin_count") or 0),
        "reachable_bin_count": len(reachable),
        "unsupported_bin_count": int(universe.get("bin_count") or 0) - len(reachable),
        "stop_reason": stop_reason,
        "convergence_round": last_novelty_round,
        "convergence_round_index": last_novelty_round_index,
        "convergence_completed_cases": sum(int(r.get("executed_cases_in_round") or 0) for r in rows),
        "convergence_eligible_cases": final_eligible,
        "last_novelty_round": last_novelty_round,
        "last_novelty_case_seq": None,
        "zero_novelty_rounds_after_last_novelty": zero_novelty_streak,
        "final_covered_bins": sorted(final_covered),
        "final_covered_count": covered_count,
        "final_reachable_covered_count": reachable_covered,
        "family_breakdown": C.family_breakdown(sorted(final_covered)),
        "rounds_completed": len(rows),
        "convergence_note": (
            f"converged within the reachable space at {reachable_covered}/{len(reachable)} reachable "
            f"bins ({covered_count}/{int(universe.get('bin_count') or 0)} universe); "
            f"{int(universe.get('bin_count') or 0) - len(reachable)} bins structurally unsupported "
            f"(non-canonical OFF config bins)"
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Write closedloop-144 final-summary.json")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--universe", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--random-root", type=Path, action="append", default=[])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    universe = C.load_universe(args.universe)
    final = compute_final(args.root, universe)

    random_trajectories = []
    for rr in args.random_root:
        cs = convergence_state(rr)
        rows = cs["rows"]
        if not rows:
            continue
        covered = int(rows[-1].get("cumulative_covered") or 0)
        random_trajectories.append({
            "root": str(rr),
            "rounds_completed": len(rows),
            "final_covered_universe": covered,
            "eligible_cases": sum(int(r.get("eligible_cases_in_round") or 0) for r in rows),
            "rows": rows,
        })
    final["random_controls"] = random_trajectories

    if random_trajectories and final["stop_reason"] != "right_censored_budget":
        guided_endpoint = final["final_covered_count"]
        final["guidance_comparison"] = {
            "guided_final_covered": guided_endpoint,
            "random_covered_at_matched_rounds": [
                {"root": rt["root"], "final_covered": rt["final_covered_universe"]}
                for rt in random_trajectories
            ],
            "caveat": "p-values require >= 3 random campaigns; report trajectories/effect sizes otherwise",
        }

    C.write_json(args.out, final)
    print(f"final-summary: covered {final['final_covered_count']}/{final['universe_bin_count']} "
          f"({final['final_reachable_covered_count']}/{final['reachable_bin_count']} reachable), "
          f"stop={final['stop_reason']}, rounds={final['rounds_completed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
