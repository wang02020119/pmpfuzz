#!/usr/bin/env python3
"""Guided selection for the U74 closedloop-144 experiment.

Round 0 (EXPERIMENT_PROTOCOL.md §3): stratified-breadth seed over coverage
families and PMP modes -- no prior observations are used, so round 0 is not
evidence of feedback guidance.

Rounds >= 1 (PROTOCOL §4): marginal-gain selection over the frozen candidate
corpus using the *cumulative real observed coverage* from all previous physical
rounds:

- primary score  : predicted reachable bins in the missing set (reachable - covered);
- secondary score: coverage-family priority (config / stimulus gaps win ties);
- tertiary score : scheduler seed for deterministic tie-breaking.

Selection is pre-registered: the full selection log (prior coverage hash,
corpus hash, selected/rejected candidate ids, predicted bins, marginal gain,
seed and tie-break rule) is written before any board execution.

Writes into ``--out-dir``:

- ``schedule_round_000N.json``  (scenario-native entries with lowering);
- ``selection-log.json``        (pre-registration provenance);
- ``catalog.json``              (runner ``--u74-catalog`` input).

Usage:

    PYTHONPATH=. python scripts/evaluation/hardware/u74/u74_guided_select.py \
        --corpus <closedloop-144>/corpus/corpus.json \
        --universe <...>/u74-supported-v4-144.json \
        --round-index 1 --budget 96 --seed 4 \
        --prior-summary <closedloop-144>/aggregation/round-0000-summary.json \
        --out-dir <closedloop-144>/rounds/round-0001
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from random import Random
from typing import Any, Callable

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import u74_cl144_common as C


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------

def _score_round0(cand: dict[str, Any], *, covered_config: set, covered_families: set, covered_bins: set, missing_bins: set, rng_index: int) -> tuple:
    config_classes = {tuple(cls) for cls in cand.get("config_classes") or []}
    new_config = len(config_classes - covered_config)
    predicted = set(cand.get("predicted_reachable_bins") or [])
    new_bins = predicted - covered_bins
    new_families = {C.family_of_bin(b) for b in new_bins} - covered_families
    return (new_config, len(new_families), len(new_bins), -rng_index)


def _score_guided(cand: dict[str, Any], *, covered_config: set, covered_families: set, covered_bins: set, missing_bins: set, rng_index: int) -> tuple:
    predicted = set(cand.get("predicted_reachable_bins") or [])
    new_bins = predicted & missing_bins
    config_new = sum(1 for b in new_bins if C.family_of_bin(b) == "family=config")
    stimulus_new = sum(1 for b in new_bins if C.family_of_bin(b) == "family=stimulus")
    return (len(new_bins), config_new, stimulus_new, -rng_index)


def _score_noop_key(key: tuple) -> tuple:
    """Demote a candidate's key to fill-level (only the tie-break survives)."""
    if not key:
        return key
    return tuple([0] * (len(key) - 1)) + (key[-1],)


# ---------------------------------------------------------------------------
# greedy selection
# ---------------------------------------------------------------------------

def _is_locked_candidate(cand: dict[str, Any]) -> bool:
    return bool(cand.get("has_locked"))


def select(
    corpus: list[dict[str, Any]],
    *,
    budget: int,
    seed: int,
    prior_covered_bins: set[str],
    missing_bins: set[str],
    executed_hashes: set[str],
    round_index: int,
    mode: str,
    max_locked: int = 20,
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], dict[str, Any]]:
    """Return (selected, stats) where each selection is (candidate, detail).

    ``max_locked`` caps the number of locked cases per round: locked cases
    mostly *skip* on the U74 board (PMP entry exhaustion under the locked-last
    protocol), so letting the greedy chase the locked config bins wastes the
    budget; the cap keeps the round focused on reachable gaps.
    """
    rng = Random((int(seed) + int(round_index) * 7919) & 0x7FFFFFFF)
    pool = [
        cand for cand in corpus
        if cand.get("firmware_ready")
        and not cand.get("board_unstable")
        and not (cand.get("has_tor") and cand.get("has_locked"))
        and str(cand.get("scenario_hash") or "") not in executed_hashes
    ]
    rng.shuffle(pool)
    shuffled = list(pool)

    if mode == "round0":
        scorer: Callable[..., tuple] = _score_round0
    elif mode == "guided":
        scorer = _score_guided
    else:
        raise ValueError(f"unsupported guided-select mode: {mode}")

    covered_bins = set(prior_covered_bins)
    covered_config: set = set()
    covered_families: set = set()

    selected: list[tuple[dict[str, Any], dict[str, Any]]] = []
    remaining = list(pool)
    selected_ids: set[str] = set()
    locked_picked = 0
    while len(selected) < budget and remaining:
        best = None
        best_key: tuple | None = None
        best_idx = -1
        for index, cand in enumerate(remaining):
            if _is_locked_candidate(cand) and locked_picked >= max_locked:
                # hard cap: skip locked candidates once the per-round budget is
                # used up (locked cases mostly skip on the board).
                continue
            rng_index = shuffled.index(cand)
            key = scorer(
                cand,
                covered_config=covered_config,
                covered_families=covered_families,
                covered_bins=covered_bins,
                missing_bins=missing_bins,
                rng_index=rng_index,
            )
            if best_key is None or key > best_key:
                best = cand
                best_key = key
                best_idx = index
        if best is None:
            break
        predicted = set(best.get("predicted_reachable_bins") or [])
        gain_bins = predicted & missing_bins if mode == "guided" else (predicted - covered_bins)
        marginal_gain = len(gain_bins)
        if marginal_gain == 0 and len(selected) >= budget:
            break
        detail = {
            "marginal_gain": marginal_gain,
            "predicted_bins": sorted(predicted),
            "predicted_new_bins": sorted(gain_bins),
            "config_classes": [list(c) for c in best.get("config_classes") or []],
        }
        selected.append((best, detail))
        selected_ids.add(str(best["candidate_id"]))
        if _is_locked_candidate(best):
            locked_picked += 1
        covered_bins.update(predicted)
        covered_config.update(tuple(cls) for cls in (best.get("config_classes") or []))
        covered_families.update(C.family_of_bin(b) for b in predicted)
        remaining.pop(best_idx)

    # Fill remaining budget (no candidate predicts a new bin) in seeded order.
    for cand in shuffled:
        if len(selected) >= budget:
            break
        if str(cand["candidate_id"]) in selected_ids:
            continue
        if _is_locked_candidate(cand) and locked_picked >= max_locked:
            continue
        selected.append((cand, {"marginal_gain": 0, "predicted_bins": sorted(cand.get("predicted_reachable_bins") or []), "predicted_new_bins": [], "config_classes": [list(c) for c in cand.get("config_classes") or []], "fill": True}))
        selected_ids.add(str(cand["candidate_id"]))
        if _is_locked_candidate(cand):
            locked_picked += 1

    rejected_ids = [str(c["candidate_id"]) for c in pool if str(c["candidate_id"]) not in selected_ids]
    stats = {
        "mode": mode,
        "seed": seed,
        "budget": budget,
        "pool_size": len(pool),
        "selected_count": len(selected),
        "rejected_count": len(rejected_ids),
        "executed_hash_excluded": len(corpus) - len(pool) - sum(
            1 for c in corpus if str(c.get("scenario_hash") or "") in executed_hashes
        ),
        "estimated_new_bins_total": sum(int(d.get("marginal_gain") or 0) for _, d in selected),
    }
    return selected, stats


# ---------------------------------------------------------------------------
# schedule / selection-log / catalog emission
# ---------------------------------------------------------------------------

def build_schedule_entries(selected: list[tuple[dict[str, Any], dict[str, Any]]], *, round_index: int, selection_source: str) -> list[dict[str, Any]]:
    entries = []
    for slot, (cand, detail) in enumerate(selected):
        name = f"u74-cl144-r{round_index}-case-{slot:04d}"
        lowering = dict(cand["lowering"])
        # The firmware prints case={lowering.name}; it must equal the schedule
        # entry name or the validator's scheduled-vs-UART reconciliation fails.
        lowering["name"] = name
        entry = {
            "schema_version": 1,
            "round_id": f"round-{round_index:04d}",
            "round_index": round_index,
            "index": slot,
            "name": name,
            "case_id": name,
            "candidate_id": cand["candidate_id"],
            "seed": cand["seed"],
            "generator_profile": cand["generator_profile"],
            "generator_index": cand["generator_index"],
            "case_index": cand["case_index"],
            "profile": cand["profile"],
            "scenario_hash": cand["scenario_hash"],
            "scenario_fingerprint": cand["scenario_fingerprint"],
            "scenario_spec": cand["scenario_spec"],
            "lowering": lowering,
            "config_classes": cand["config_classes"],
            "selection_source": selection_source,
            "estimated_new_bins": detail.get("marginal_gain") or 0,
        }
        entries.append(entry)
    return entries


def build_catalog_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Catalog entries for the board runner (fake UART synthesis needs these)."""
    rows = []
    trap_name_by_cause = {
        1: "instruction_access_fault",
        5: "load_access_fault",
        7: "store_access_fault",
        12: "instruction_page_fault",
        13: "load_page_fault",
        15: "store_page_fault",
    }
    for entry in entries:
        lowering = entry["lowering"]
        expected_allowed = bool(lowering.get("expected_allowed"))
        expected_cause = int(lowering.get("expected_cause") or 0)
        access = str(lowering.get("access") or "")
        status = "pass" if expected_allowed else "fail"
        rows.append({
            "case": entry["name"],
            "profile": entry["profile"],
            "status": status,
            "op": access,
            "addr": f"0x{int(lowering.get('probe_pa') or 0):x}",
            "mpp": int(lowering.get("mpp") or 0),
            "satp": int(lowering.get("satp") or 0),
            "result": "allow" if expected_allowed else "trap",
            "cause": f"0x{expected_cause:x}",
            "trap_name": trap_name_by_cause.get(expected_cause, "none"),
            "tval": "0x0",
            "expected": "allow" if expected_allowed else "trap",
            "expected_cause": f"0x{expected_cause:x}",
            "scenario_hash": entry["scenario_hash"],
        })
    return rows


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="U74 closedloop-144 guided / breadth selection")
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--universe", type=Path, required=True)
    parser.add_argument("--round-index", type=int, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--budget", type=int, default=96)
    parser.add_argument("--seed", type=int, default=4)
    parser.add_argument("--campaign-id", default=C.CAMPAIGN_ID)
    parser.add_argument("--prior-summary", type=Path, default=None,
                        help="aggregation/round-(r-1)-summary.json (required for round_index >= 1)")
    parser.add_argument("--mode", choices=("guided", "round0"), default=None,
                        help="round0 breadth (no prior) or guided marginal gain; default: round0 when index==0")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    mode = args.mode or ("round0" if args.round_index == 0 else "guided")
    if args.round_index > 0 and args.prior_summary is None:
        raise SystemExit("--prior-summary is required for round_index >= 1")

    universe = C.load_universe(args.universe)
    corpus = C.load_json(args.corpus).get("candidates") or []
    reachable = set(C.reachable_bins(universe))
    unsupported_bins = C.compute_unsupported_bins(universe)

    prior_covered: set[str] = set()
    executed_hashes: set[str] = set()
    prior_summary = None
    if args.prior_summary is not None and Path(args.prior_summary).exists():
        prior_summary = C.load_json(args.prior_summary)
        prior_covered = set(str(b) for b in (prior_summary.get("cumulative_covered_bins") or []))
        executed_hashes = set(str(h) for h in (prior_summary.get("executed_scenario_hashes") or []))
    prior_covered = prior_covered & reachable
    missing = reachable - prior_covered

    selected, stats = select(
        corpus,
        budget=args.budget,
        seed=args.seed,
        prior_covered_bins=prior_covered,
        missing_bins=missing,
        executed_hashes=executed_hashes,
        round_index=args.round_index,
        mode=mode,
    )
    if len(selected) < args.budget:
        raise SystemExit(
            f"could not fill budget: selected {len(selected)}/{args.budget} from "
            f"{len(corpus)} corpus candidates"
        )

    selection_source = "u74-breadth-v1" if mode == "round0" else "u74-guided-v1"
    entries = build_schedule_entries(selected, round_index=args.round_index, selection_source=selection_source)

    schedule = {
        "schema_version": 1,
        "round_id": f"round-{args.round_index:04d}",
        "campaign_id": args.campaign_id,
        "seed": args.seed,
        "selection_source": selection_source,
        "selection_summary": {
            "mode": mode,
            "budget": args.budget,
            "count": len(entries),
            "estimated_new_bins_total": stats["estimated_new_bins_total"],
            "prior_covered_count": len(prior_covered),
            "missing_reachable_count": len(missing),
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
        "mode": mode,
        "seed": args.seed,
        "budget": args.budget,
        "selection_source": selection_source,
        "tie_break_rule": "marginal-gain primary, config/stimulus family priority secondary, seeded shuffle index tertiary",
        "prior_covered_bins": sorted(prior_covered),
        "prior_covered_set_hash": C.coverage_hash_of_bins(sorted(prior_covered)),
        "corpus_fingerprint": str((corpus_meta.get("corpus") and corpus_meta["corpus"].get("corpus_fingerprint")) or corpus_meta.get("corpus_fingerprint") or ""),
        "corpus_path": str(args.corpus),
        "corpus_count": len(corpus),
        "universe_sha256": C.CONTRACT_UNIVERSE_SHA256,
        "reachable_bin_count": len(reachable),
        "missing_reachable_bins": sorted(missing),
        "selected_candidate_ids": [str(c["candidate_id"]) for c, _ in selected],
        "selected_scenario_hashes": [str(c["scenario_hash"]) for c, _ in selected],
        "rejected_candidate_ids": stats["rejected_count"] and _rejected_ids(selected, corpus, executed_hashes),
        "selection_details": {
            str(c["candidate_id"]): d for c, d in selected
        },
        "estimated_new_bins_total": stats["estimated_new_bins_total"],
        "unsupported_bins": unsupported_bins,
        "unsupported_bin_count": len(unsupported_bins),
    }
    C.write_json(out / "selection-log.json", selection_log)

    print(f"{mode} round-{args.round_index:04d}: selected {len(selected)} "
          f"(prior {len(prior_covered)}/{len(reachable)} reachable covered, missing {len(missing)}), "
          f"estimated new bins {stats['estimated_new_bins_total']}")
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
