#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from pmpfuzz.c910_m2_scheduling import predict_shared56_bins
from pmpfuzz.c910_nonpmp_dynamic import catalog_cases
from pmpfuzz.v4_nonpmp_projection import build_v4_nonpmp_bin_ids

from c910_cl56_common import REACHABLE_BINS, board_mappable, construct_params_for_bin, sha256_text


def build_seed_pool() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    reachable_set = set(REACHABLE_BINS)
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()

    for case in catalog_cases():
        if not board_mappable(case):
            continue
        predicted = predict_shared56_bins(case)
        if predicted.get("status") != "mapped":
            continue
        bins = list(predicted.get("bins") or [])
        entry = {
            "name": case["name"],
            "scenario_hash": case["scenario_hash"],
            "scenario_spec": case.get("scenario_spec"),
            "profile": case.get("profile"),
            "uart_record": case.get("uart_record"),
            "predicted_bins": bins,
            "predicted_reachable_bins": sorted(set(bins) & reachable_set),
            "board_unstable": False,
            "source": "catalog",
        }
        if entry["scenario_hash"] not in seen:
            seen.add(entry["scenario_hash"])
            candidates.append(entry)



    for index, bin_id in enumerate(REACHABLE_BINS):
        params = construct_params_for_bin(bin_id, index, seed=20260812)
        if params is None:
            continue
        from c910_cl56_common import assemble_generated

        case = assemble_generated(
            params, index=index, target_bin=bin_id,
            operator="construct:seed", parent_id="", seed=20260812,
            record_name=f"gen-seed-{index:04d}",
        )
        if case is None:
            continue
        bins = list(case.get("predicted_bins") or [])
        entry = {
            "name": case["name"],
            "scenario_hash": case["scenario_hash"],
            "scenario_spec": case.get("scenario_spec"),
            "profile": case.get("profile"),
            "uart_record": case.get("uart_record"),
            "predicted_bins": bins,
            "predicted_reachable_bins": sorted(set(bins) & reachable_set),
            "board_unstable": False,
            "generated_params": case.get("generated_params"),
            "source": "constructed",
        }
        if entry["scenario_hash"] not in seen:
            seen.add(entry["scenario_hash"])
            candidates.append(entry)

    summary = {
        "candidate_count": len(candidates),
        "catalog_count": sum(1 for c in candidates if c["source"] == "catalog"),
        "constructed_count": sum(1 for c in candidates if c["source"] == "constructed"),
        "reachable_bin_count": len(REACHABLE_BINS),
        "universe": "v4-nonpmp-56",
        "universe_bin_count": len(build_v4_nonpmp_bin_ids()),
        "structurally_unreachable_bin_count": 56 - len(REACHABLE_BINS),
    }
    return candidates, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path("aggregation/seed-pool.json"))
    args = parser.parse_args(argv)

    candidates, summary = build_seed_pool()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fingerprint = sha256_text(json.dumps([c["scenario_hash"] for c in candidates], sort_keys=True))
    args.out.write_text(
        json.dumps(
            {"corpus_fingerprint": fingerprint, "candidates": candidates, "summary": summary},
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"seed pool: {summary}")
    print("wrote", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
