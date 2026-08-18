#!/usr/bin/env python3
"""Aggregate a U74 physical round's real observations into the 144-bin summary.

PROTOCOL §3 / §4.8: only ``results/*/result.json`` board observations are used
-- never predicted bins.  The convergence curve is built exclusively from these
real observed bins.

Reads:

- ``--round-dir`` ``results/*/result.json`` (per-case real observations) and
  ``validator/report.json`` (executed/eligible/error counts),
- the fixed 144-bin universe,
- the prior round summary (for cumulative coverage / executed set).

Writes ``aggregation/round-000N-summary.json`` with scheduled/executed/eligible,
pass/fail/skip and failure-class counts, round-new bins, cumulative bins,
family breakdown, missing-reachable summary and the executed scenario-hash set
(which the next guided round uses to avoid re-running executed candidates).

Usage:

    PYTHONPATH=. python scripts/evaluation/hardware/u74/aggregate_u74_bapc.py \
        --round-dir <...>/rounds/round-0001 \
        --universe <...>/u74-supported-v4-144.json \
        --prior-summary <...>/aggregation/round-0000-summary.json \
        --out <...>/aggregation/round-0001-summary.json
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import u74_cl144_common as C


def _load_result(path: Path) -> dict[str, Any]:
    return C.load_json(path)


def aggregate_round(
    round_dir: Path,
    universe: dict[str, Any],
    prior: dict[str, Any] | None,
) -> dict[str, Any]:
    round_dir = Path(round_dir)
    universe_ids = set(str(b) for b in (universe.get("bin_ids") or []))
    reachable_ids = set(C.reachable_bins(universe))
    unsupported_ids = set(C.compute_unsupported_bins(universe))

    prior_cumulative = set(str(b) for b in ((prior or {}).get("cumulative_covered_bins") or []))
    prior_eligible = int((prior or {}).get("eligible_cumulative") or 0)
    prior_hashes = set(str(h) for h in ((prior or {}).get("executed_scenario_hashes") or []))
    prior_candidate_ids = set(str(c) for c in ((prior or {}).get("executed_candidate_ids") or []))

    # schedule entry lookup (name -> entry) for candidate_id / scenario_hash mapping
    schedule_path = round_dir / f"schedule_round_{round_dir.name.replace('round-', '')}.json"
    schedule_entries: list[dict[str, Any]] = []
    if schedule_path.exists():
        schedule_entries = C.load_json(schedule_path).get("entries") or []
    elif (round_dir / "schedule.json").exists():
        schedule_entries = C.load_json(round_dir / "schedule.json").get("entries") or []
    entry_by_name = {str(e.get("name") or ""): e for e in schedule_entries}

    status_counts: Counter = Counter()
    failure_class_counts: Counter = Counter()
    coverage_eligible = 0
    observation_valid = 0
    round_observed: set[str] = set()
    out_of_universe: list[str] = []
    results_seen = 0
    executed_hashes: set[str] = set(prior_hashes)
    executed_candidate_ids: set[str] = set(prior_candidate_ids)

    results_dir = round_dir / "results"
    for result_path in sorted(results_dir.glob("*/result.json")) if results_dir.exists() else []:
        results_seen += 1
        result = _load_result(result_path)
        name = str(result.get("name") or "")
        status = str(result.get("status") or "unknown")
        status_counts[status] += 1
        failure_class = str(result.get("failure_class") or "")
        if failure_class:
            failure_class_counts[failure_class] += 1
        bapc = result.get("bapc_coverage") or {}
        eligible = bool(bapc.get("eligible"))
        if eligible:
            coverage_eligible += 1
            observed = set(str(b) for b in (bapc.get("observed_bins") or []))
            outside = sorted(observed - universe_ids)
            out_of_universe.extend(outside)
            round_observed.update(observed & universe_ids)
        if bool(result.get("observation_valid")):
            observation_valid += 1
        entry = entry_by_name.get(name)
        if entry is not None:
            executed_hashes.add(str(entry.get("scenario_hash") or ""))
            executed_candidate_ids.add(str(entry.get("candidate_id") or ""))
        else:
            executed_hashes.add(str(result.get("scenario_hash") or ""))

    cumulative = prior_cumulative | round_observed
    new_bins = sorted(round_observed - prior_cumulative)

    validator: dict[str, Any] = {}
    validator_path = round_dir / "validator" / "report.json"
    if validator_path.exists():
        validator = C.load_json(validator_path)

    round_id = str(round_dir.name)
    if not round_id.startswith("round-"):
        digits = "".join(ch for ch in round_id if ch.isdigit())
        round_id = f"round-{int(digits or 0):04d}"
    scheduled_count = int(validator.get("scheduled_case_count") or len(schedule_entries) or results_seen)
    executed_count = int(validator.get("executed_case_count") or results_seen)
    eligible_count = int(validator.get("coverage_eligible_case_count") or coverage_eligible)

    return {
        "schema_version": 1,
        "round_id": round_id,
        "campaign_id": str(validator.get("campaign_id") or C.CAMPAIGN_ID),
        "universe_sha256": C.CONTRACT_UNIVERSE_SHA256,
        "validator": {
            "error_count": int(validator.get("error_count") or 0),
            "runner_begin_count": int(validator.get("runner_begin_count") or 0),
            "runner_end_count": int(validator.get("runner_end_count") or 0),
            "validator_profile": str(validator.get("validator_profile") or ""),
            "generated_manifest_path": str(validator.get("generated_manifest_path") or ""),
            "fit_sha256": str(validator.get("fit_sha256") or ""),
        },
        "scheduled_count": scheduled_count,
        "executed_count": executed_count,
        "coverage_eligible_count": coverage_eligible,
        "eligible_count": eligible_count,
        "observation_valid_count": observation_valid,
        "results_seen": results_seen,
        "pass_count": int(status_counts.get("pass", 0)),
        "fail_count": int(status_counts.get("fail", 0)),
        "skip_count": int(status_counts.get("skip", 0)),
        "status_counts": dict(status_counts),
        "failure_class_counts": dict(failure_class_counts),
        "universe_bin_count": len(universe_ids),
        "round_observed_bins": sorted(round_observed),
        "round_observed_count": len(round_observed),
        "round_new_bins": new_bins,
        "round_new_count": len(new_bins),
        "cumulative_covered_bins": sorted(cumulative),
        "cumulative_covered_count": len(cumulative),
        "eligible_cumulative": prior_eligible + coverage_eligible,
        "coverage_hash": C.coverage_hash_of_bins(sorted(cumulative)),
        "reachable_bin_count": len(reachable_ids),
        "reachable_covered_count": len(cumulative & reachable_ids),
        "unsupported_bin_count": len(unsupported_ids),
        "unsupported_bins": sorted(unsupported_ids),
        "missing_reachable_bins": sorted(reachable_ids - cumulative),
        "missing_reachable_count": len(reachable_ids - cumulative),
        "family_breakdown": C.family_breakdown(sorted(cumulative)),
        "out_of_universe_observed_bins": sorted(set(out_of_universe)),
        "executed_candidate_ids": sorted(executed_candidate_ids),
        "executed_scenario_hashes": sorted(executed_hashes),
        "prior_coverage_hash": C.coverage_hash_of_bins(sorted(prior_cumulative)),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Aggregate U74 closedloop-144 round observations")
    parser.add_argument("--round-dir", type=Path, required=True)
    parser.add_argument("--universe", type=Path, required=True)
    parser.add_argument("--prior-summary", type=Path, default=None)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    universe = C.load_universe(args.universe)
    prior = C.load_json(args.prior_summary) if args.prior_summary and Path(args.prior_summary).exists() else None
    summary = aggregate_round(args.round_dir, universe, prior)
    C.write_json(args.out, summary)
    print(
        f"{summary['round_id']}: executed {summary['executed_count']} eligible {summary['eligible_count']} "
        f"| cumulative {summary['cumulative_covered_count']}/{summary['universe_bin_count']} "
        f"(reachable {summary['reachable_covered_count']}/{summary['reachable_bin_count']}) "
        f"| new {summary['round_new_count']} | missing reachable {summary['missing_reachable_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
