#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from c910_cl56_common import REACHABLE_BINS


def _read(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def process_round(*, root: Path, round_index: int) -> dict:
    aggregation = root / "aggregation"
    round_id = f"round-{round_index:04d}"
    shared56_path = root / "rounds" / round_id / "run" / "coverage" / "shared56.json"
    if not shared56_path.exists():
        raise FileNotFoundError(f"missing round coverage: {shared56_path}")
    shared56 = _read(shared56_path)

    prior_path = aggregation / f"round-{round_index - 1:04d}-summary.json"
    prior = _read(prior_path) if prior_path.exists() else None
    prior_cumulative = set((prior or {}).get("cumulative_covered_bins") or [])
    prior_hashes = set((prior or {}).get("executed_scenario_hashes") or [])

    round_covered = set(shared56.get("covered_bins") or [])
    new_bins = sorted(round_covered - prior_cumulative)
    cumulative = sorted(prior_cumulative | round_covered)

    manifest_path = root / "rounds" / round_id / "manifest-v3.json"
    hashes = set(prior_hashes)
    if manifest_path.exists():
        manifest = _read(manifest_path)
        hashes.update(str(e["scenario_hash"]) for e in manifest.get("entries") or [])

    reachable_set = set(REACHABLE_BINS)
    summary = {
        "round_id": round_id,
        "round_covered_bins": sorted(round_covered),
        "round_covered_count": len(round_covered),
        "cumulative_covered_bins": cumulative,
        "cumulative_covered_count": len(cumulative),
        "cumulative_covered_reachable": len(set(cumulative) & reachable_set),
        "round_new_bins": new_bins,
        "round_new_bin_count": len(new_bins),
        "executed_scenario_hashes": sorted(hashes),
        "eligible_count": len(hashes),
        "mapped": shared56.get("mapped", 0),
        "unsupported": shared56.get("unsupported", 0),
        "observation_unqualified": shared56.get("observation_unqualified", 0),
        "known_violations": shared56.get("known_violations", []),
    }
    _write(aggregation / f"{round_id}-summary.json", summary)
    return summary


def _convergence_state(root: Path) -> dict:
    path = root / "aggregation" / "convergence.json"
    if path.exists():
        return _read(path)
    return {"rounds": [], "stop_reason": None}


def update_convergence(*, root: Path, summary: dict) -> dict:
    conv = _convergence_state(root)
    prev_rounds = list(conv.get("rounds") or [])

    prev_rounds = [r for r in prev_rounds if r.get("round_id") != summary["round_id"]]
    rows = prev_rounds + [summary]

    last_novelty = None
    zero_streak = 0
    for row in rows:
        if row["round_new_bin_count"] > 0:
            last_novelty = row["round_id"]
            zero_streak = 0
        else:
            zero_streak += 1

    stop_reason = None
    if last_novelty is not None and zero_streak >= 2:
        stop_reason = "coverage_converged"
    final_covered_reachable = rows[-1]["cumulative_covered_reachable"] if rows else 0
    conv = {
        "rounds": rows,
        "stop_reason": stop_reason,
        "convergence_round": rows[-1]["round_id"] if rows else None,
        "convergence_completed_cases": sum(r["eligible_count"] for r in rows),
        "last_novelty_round": last_novelty,
        "zero_novelty_rounds_after_last_novelty": zero_streak,
        "final_covered_reachable": final_covered_reachable,
        "final_covered_count": rows[-1]["cumulative_covered_count"] if rows else 0,
        "final_covered_bins": rows[-1]["cumulative_covered_bins"] if rows else [],
        "reachable_count": len(REACHABLE_BINS),
        "universe_count": 56,
    }
    _write(root / "aggregation" / "convergence.json", conv)
    return conv


def write_final_summary(*, root: Path, conv: dict) -> dict:
    final = {
        "universe": "v4-nonpmp-56",
        "reachable_count": len(REACHABLE_BINS),
        "structurally_unreachable_count": 56 - len(REACHABLE_BINS),
        "stop_reason": conv.get("stop_reason"),
        "convergence_round": conv.get("convergence_round"),
        "final_covered_reachable": conv.get("final_covered_reachable", 0),
        "final_covered_universe": conv.get("final_covered_count", 0),
        "final_covered_bins": conv.get("final_covered_bins", []),
        "rounds": conv.get("rounds", []),
    }
    _write(root / "aggregation" / "final-summary.json", final)
    return final


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--round-index", type=int, required=True)
    args = parser.parse_args(argv)

    summary = process_round(root=args.root, round_index=args.round_index)
    conv = update_convergence(root=args.root, summary=summary)
    print(
        f"{summary['round_id']}: +{summary['round_new_bin_count']} new, "
        f"cumulative {summary['cumulative_covered_count']}/{len(REACHABLE_BINS)} "
        f"reachable ({summary['cumulative_covered_count']}/56 universe)"
    )
    if conv["stop_reason"]:
        final = write_final_summary(root=args.root, conv=conv)
        print(
            f"CONVERGED ({conv['stop_reason']}) at {final['final_covered_reachable']}"
            f"/{len(REACHABLE_BINS)} reachable in {len(final['rounds'])} rounds"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
