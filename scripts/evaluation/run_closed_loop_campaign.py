#!/usr/bin/env python3
"""Closed-loop fuzzing campaign driver — fixed multi-round accumulation.

Architecture (Phase B4):
  Single driver process maintains CampaignState across all rounds.
  Each round calls pmpfuzz run via subprocess with --schedule.
  Driver accumulates coverage, completion_seq, and timeline in-process.
  Wall-clock includes scheduling and coverage computation time.

Variants (Phase B3):
  random    — seeded shuffle of full candidate pool, without replacement
  guided    — coverage-gap schedule from execution-qualified coverage
  bb        — blackbox coverage feedback (no whitebox events for scheduling)
  bb-wb     — up to 16 whitebox + blackbox to fill round_size (16+16 rule)

Candidate pool (Phase B2):
  Built once at campaign start, saved as metrics/candidate_pool.json.
  executed_candidates.jsonl tracks which candidates have been run.
"""

from __future__ import annotations

import sys
from pathlib import Path as _Path
# Ensure pmpfuzz package is importable when script is run directly
_script_dir = _Path(__file__).resolve().parents[2]
if str(_script_dir) not in sys.path:
    sys.path.insert(0, str(_script_dir))

import argparse
import hashlib
import json
import os
import random as rng_mod
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# CampaignState — single source of truth across all rounds
# ---------------------------------------------------------------------------


class CampaignState:
    """In-memory campaign state that survives across rounds (Phase B4)."""

    VALID_VARIANTS = frozenset({"random", "guided", "bb", "bb-wb"})

    def __init__(
        self,
        campaign_id: str,
        variant: str,
        dut: str,
        seed: int,
        coverage_mode: str,
        candidate_pool: list[dict[str, Any]],
        start_time: float,
    ):
        if variant not in self.VALID_VARIANTS:
            raise ValueError(f"invalid variant: {variant}")
        self.campaign_id = campaign_id
        self.variant = variant
        self.dut = dut
        self.seed = seed
        self.coverage_mode = coverage_mode
        self.start_time = start_time

        # Candidate pool
        self._candidate_pool: list[dict[str, Any]] = list(candidate_pool)
        self._executed_ids: set[str] = set()

        # Accumulated state
        self._completion_seq: int = 0
        self._completed_cases: int = 0
        self._eligible_cases: int = 0
        self._round_idx: int = 0

        # Coverage sets (accumulated across all rounds)
        self._covered_semantic: set[str] = set()
        self._covered_pairwise: set[str] = set()
        self._covered_triples: set[str] = set()
        self._covered_predicates: set[str] = set()

        # Target bin counts (Fix 1) — computed once from candidate pool
        self._target_semantic: int = len(set().union(*(c.get("semantic_bins", []) for c in candidate_pool)))
        self._target_pairwise: int = len(set().union(*(c.get("pairwise_bins", []) for c in candidate_pool)))
        self._target_triples: int = len(set().union(*(c.get("security_triple_bins", []) for c in candidate_pool)))
        self._target_predicates: int = len(set().union(*(c.get("predicate_bins", []) for c in candidate_pool)))

        # Whitebox events
        self._whitebox_event_ids: set[str] = set()

        # Timeline lines + persistence (Fix 8)
        self._timeline_lines: list[dict] = []
        self._timeline_path: Path | None = None

        # Round failure tracking
        self._round_results: list[dict] = []
        self._any_round_failed: bool = False

    # -- properties ----------------------------------------------------------

    @property
    def completion_seq(self) -> int:
        return self._completion_seq

    @property
    def completed_cases(self) -> int:
        return self._completed_cases

    @property
    def eligible_cases(self) -> int:
        return self._eligible_cases

    @property
    def round_idx(self) -> int:
        return self._round_idx

    @property
    def executed_ids(self) -> frozenset[str]:
        return frozenset(self._executed_ids)

    @property
    def any_round_failed(self) -> bool:
        return self._any_round_failed

    # -- candidate pool -----------------------------------------------------

    def unexecuted_candidates(self) -> list[dict[str, Any]]:
        return [c for c in self._candidate_pool if c["candidate_id"] not in self._executed_ids]

    def mark_executed(self, candidate_id: str) -> None:
        if candidate_id in self._executed_ids:
            raise ValueError(f"duplicate execution: {candidate_id}")
        self._executed_ids.add(candidate_id)

    # -- round tracking ------------------------------------------------------

    def advance_round(self) -> None:
        self._round_idx += 1

    def record_round_result(self, success: bool, info: dict[str, Any]) -> None:
        self._round_results.append({"round": self._round_idx, "success": success, **info})
        if not success:
            self._any_round_failed = True

    # -- case completion ----------------------------------------------------

    def record_case(self, candidate_id, case_id, profile, status, failure_class,
                    eligible, qualification_reason, elapsed_wall, case_elapsed,
                    new_semantic, new_pairwise, new_triples, new_predicates, new_whitebox,
                    case_semantic=None, case_pairwise=None, case_triples=None, case_predicates=None):
        """Fix 2+8: Update coverage from bin sets, write line, persist incrementally.

        If case_* bin sets are provided, they are accumulated before writing
        the timeline line (only if eligible).
        """
        self.mark_executed(candidate_id)
        self._completion_seq += 1
        self._completed_cases += 1
        if eligible:
            self._eligible_cases += 1
            # Actually apply coverage changes to covered sets
            if case_semantic is not None:
                self._covered_semantic.update(case_semantic)
            if case_pairwise is not None:
                self._covered_pairwise.update(case_pairwise)
            if case_triples is not None:
                self._covered_triples.update(case_triples)
            if case_predicates is not None:
                self._covered_predicates.update(case_predicates)

        line = self._make_timeline_line(
            case_id=case_id, profile=profile, status=status,
            failure_class=failure_class, eligible=eligible,
            qualification_reason=qualification_reason,
            elapsed_wall=elapsed_wall, case_elapsed=case_elapsed,
            new_semantic=new_semantic, new_pairwise=new_pairwise,
            new_triples=new_triples, new_predicates=new_predicates,
            new_whitebox=new_whitebox,
        )
        self._timeline_lines.append(line)
        self._persist_line(line)
        return line

    def _make_timeline_line(self, **kwargs) -> dict[str, Any]:
        """Fix 1: Include real cumulative covered/target/rate values."""
        sem_cov = len(self._covered_semantic)
        pair_cov = len(self._covered_pairwise)
        trip_cov = len(self._covered_triples)
        pred_cov = len(self._covered_predicates)
        return {
            "schema_version": 1,
            "campaign_id": self.campaign_id,
            "variant": self.variant,
            "dut": self.dut,
            "seed": self.seed,
            "completion_seq": self._completion_seq,
            "case_id": kwargs.get("case_id"),
            "profile": kwargs.get("profile"),
            "elapsed_wall_seconds": kwargs.get("elapsed_wall", 0),
            "case_elapsed_seconds": kwargs.get("case_elapsed", 0),
            "completed_cases": self._completed_cases,
            "eligible_cases": self._eligible_cases,
            "status": kwargs.get("status"),
            "failure_class": kwargs.get("failure_class"),
            "coverage_eligible": kwargs.get("eligible", False),
            "qualification_reason": kwargs.get("qualification_reason"),
            "semantic_covered": sem_cov,
            "semantic_target": self._target_semantic,
            "semantic_rate": sem_cov / self._target_semantic if self._target_semantic > 0 else None,
            "pairwise_covered": pair_cov,
            "pairwise_target": self._target_pairwise,
            "pairwise_rate": pair_cov / self._target_pairwise if self._target_pairwise > 0 else None,
            "security_triples_covered": trip_cov,
            "security_triples_target": self._target_triples,
            "security_triples_rate": trip_cov / self._target_triples if self._target_triples > 0 else None,
            "predicates_covered": pred_cov,
            "predicates_target": self._target_predicates,
            "predicates_rate": pred_cov / self._target_predicates if self._target_predicates > 0 else None,
            "new_semantic_bins": kwargs.get("new_semantic", 0),
            "new_pairwise_bins": kwargs.get("new_pairwise", 0),
            "new_security_triple_bins": kwargs.get("new_triples", 0),
            "new_predicate_bins": kwargs.get("new_predicates", 0),
            "whitebox_distinct_events": len(self._whitebox_event_ids),
            "new_whitebox_events": kwargs.get("new_whitebox", 0),
        }

    # -- coverage accumulation (Fix 2: only update for eligible) ------------

    def update_coverage_sets(
        self,
        semantic: set[str],
        pairwise: set[str],
        triples: set[str],
        predicates: set[str],
        eligible: bool,
    ) -> tuple[int, int, int, int]:
        """Fix 2: Only update coverage if eligible. Returns new bin counts."""
        if not eligible:
            return 0, 0, 0, 0
        ns = len(semantic - self._covered_semantic)
        np = len(pairwise - self._covered_pairwise)
        nt = len(triples - self._covered_triples)
        npr = len(predicates - self._covered_predicates)
        self._covered_semantic.update(semantic)
        self._covered_pairwise.update(pairwise)
        self._covered_triples.update(triples)
        self._covered_predicates.update(predicates)
        return ns, np, nt, npr

    def record_whitebox_events(self, event_ids: set[str]) -> int:
        new = event_ids - self._whitebox_event_ids
        self._whitebox_event_ids.update(new)
        return len(new)

    @property
    def whitebox_distinct_events(self) -> int:
        return len(self._whitebox_event_ids)

    # -- timeline persistence (Fix 8: incremental) ---------------------------

    def set_timeline_path(self, path: Path) -> None:
        """Set the output path and write the baseline (idempotent)."""
        self._timeline_path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.stat().st_size == 0:
            path.write_text(
                json.dumps(self._make_baseline_line(), ensure_ascii=True, sort_keys=True) + "\n",
                encoding="ascii",
            )

    def _persist_line(self, line: dict) -> None:
        """Fix 8: Append one line and flush immediately."""
        if self._timeline_path is None:
            return
        with open(self._timeline_path, "a", encoding="ascii") as fh:
            fh.write(json.dumps(line, ensure_ascii=True, sort_keys=True) + "\n")
            fh.flush()

    def write_timeline(self, path: Path) -> None:
        """Write accumulated timeline to JSONL file (full rewrite)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="ascii") as fh:
            fh.write(json.dumps(self._make_baseline_line(), ensure_ascii=True, sort_keys=True) + "\n")
            for line in self._timeline_lines:
                fh.write(json.dumps(line, ensure_ascii=True, sort_keys=True) + "\n")
            fh.flush()

    def _make_baseline_line(self) -> dict:
        """Baseline with real target counts (Fix: denominator constant)."""
        return {
            "schema_version": 1,
            "campaign_id": self.campaign_id,
            "variant": self.variant,
            "dut": self.dut,
            "seed": self.seed,
            "completion_seq": 0,
            "case_id": None,
            "profile": None,
            "elapsed_wall_seconds": 0.0,
            "case_elapsed_seconds": 0.0,
            "completed_cases": 0,
            "eligible_cases": 0,
            "status": None,
            "failure_class": None,
            "coverage_eligible": False,
            "qualification_reason": None,
            "semantic_covered": 0,
            "semantic_target": self._target_semantic,
            "semantic_rate": 0.0,
            "pairwise_covered": 0,
            "pairwise_target": self._target_pairwise,
            "pairwise_rate": 0.0,
            "security_triples_covered": 0,
            "security_triples_target": self._target_triples,
            "security_triples_rate": 0.0,
            "predicates_covered": 0,
            "predicates_target": self._target_predicates,
            "predicates_rate": 0.0,
            "new_semantic_bins": 0,
            "new_pairwise_bins": 0,
            "new_security_triple_bins": 0,
            "new_predicate_bins": 0,
            "whitebox_distinct_events": 0,
            "new_whitebox_events": 0,
        }


# ---------------------------------------------------------------------------
# Candidate pool builder (Phase B2)
# ---------------------------------------------------------------------------


def build_candidate_pool(
    target: str = "core-stateful",
    include_experimental: bool = False,
    seed: int = 20260628,
    capability: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build the fixed candidate pool for a campaign.

    Each candidate has a stable candidate_id (sha256 of profile+seed+index).
    """
    from pmpfuzz.capabilities import oracle_applicability_for_case
    from pmpfuzz.semantic_coverage import (
        PROFILE_TARGET_COUNTS,
        _capability_case_for_scenario,
        _target_candidates,
        combo_bins_for_case,
        contract_predicates_for_case,
        semantic_bins_for_case,
        target_profiles,
    )

    candidates: list[dict[str, Any]] = []
    raw = _target_candidates(
        target=target,
        include_experimental=include_experimental,
        seed=seed,
        capability=capability,
    )
    for c in raw:
        candidate_id = _make_candidate_id(c["profile"], c["index"], seed)
        candidates.append({
            "candidate_id": candidate_id,
            "profile": c["profile"],
            "generation_seed": seed,
            "scenario_index": c["index"],
            "name": c["name"],
            "semantic_bins": c.get("semantic_bins", []),
            "pairwise_bins": [b for b in c.get("combo_bins", []) if b.startswith("combo2:")],
            "security_triple_bins": [b for b in c.get("combo_bins", []) if b.startswith("combo3:")],
            "predicate_bins": c.get("contract_predicates", []),
            "capability_case": c.get("capability_case"),
        })
    return candidates


def _make_candidate_id(profile: str, index: int, seed: int) -> str:
    """Stable candidate ID from profile, index, and seed."""
    return hashlib.sha256(
        f"{profile}:{seed}:{index}".encode("ascii")
    ).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Variant selection (Phase B3)
# ---------------------------------------------------------------------------


def select_next_candidates(
    state: CampaignState,
    round_size: int,
    run_dirs: list[Path],
    seed: int,
) -> list[dict[str, Any]]:
    """Select the next batch of candidates based on variant.

    Returns a list of candidate dicts (from the pool) to execute.
    """
    unexec = state.unexecuted_candidates()
    if not unexec:
        return []

    if state.variant == "random":
        return [
            _selection_record(candidate, "random", 0)
            for candidate in _select_random(
                unexec, round_size, state.seed + state.round_idx * 1000
            )
        ]
    elif state.variant == "guided":
        return _select_guided(state, unexec, round_size, run_dirs, seed)
    elif state.variant == "bb":
        return _select_guided(state, unexec, round_size, run_dirs, seed)  # BB = coverage-guided only
    elif state.variant == "bb-wb":
        return _select_bb_wb(state, unexec, round_size, run_dirs, seed)
    return []


def _select_random(
    unexec: list[dict[str, Any]], count: int, shuffle_seed: int
) -> list[dict[str, Any]]:
    """Seeded shuffle without replacement (Phase B3 random)."""
    shuffled = list(unexec)
    rng = rng_mod.Random(shuffle_seed)
    rng.shuffle(shuffled)
    return shuffled[:count]


def _selection_record(
    candidate: dict[str, Any], source: str, estimated_new_bins: int
) -> dict[str, Any]:
    """Return a schedule-local copy with an auditable selection reason."""
    return {
        **candidate,
        "selection_source": source,
        "estimated_new_bins": int(estimated_new_bins),
    }


def _schedule_entry(candidate: dict[str, Any], seed: int) -> dict[str, Any]:
    """Serialize a candidate without losing its selection provenance."""
    return {
        "candidate_id": candidate["candidate_id"],
        "profile": candidate["profile"],
        "index": candidate["scenario_index"],
        "name": candidate.get(
            "name", f"{candidate['profile']}__case_{candidate['scenario_index']}"
        ),
        "seed": seed,
        "include_smepmp": candidate["profile"].startswith("smepmp"),
        "selection_source": candidate.get("selection_source", "bootstrap"),
        "estimated_new_bins": int(candidate.get("estimated_new_bins", 0)),
    }


def _selection_summary(candidates: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for candidate in candidates:
        source = str(candidate.get("selection_source") or "bootstrap")
        summary[source] = summary.get(source, 0) + 1
    summary["final_selected_count"] = len(candidates)
    return summary


def _select_guided(
    state: CampaignState,
    unexec: list[dict[str, Any]],
    count: int,
    run_dirs: list[Path],
    seed: int,
) -> list[dict[str, Any]]:
    """P0-1 FIX: DUT-qualified coverage-gap greedy + seeded fallback."""
    dut = state.dut
    missing: set[str] = set()
    bin_key = "semantic_bins"
    if run_dirs:
        if state.coverage_mode == "semantic":
            missing = _coverage_gap_semantic(run_dirs, dut)
            bin_key = "semantic_bins"
        elif state.coverage_mode == "predicates":
            missing = _coverage_gap_predicates(run_dirs, dut)
            bin_key = "predicate_bins"
        else:
            missing = _coverage_gap_combo(run_dirs, state.coverage_mode, dut)
            bin_key = "pairwise_bins" if state.coverage_mode == "pairwise" else "security_triple_bins"

    # Greedy phase
    selected: list[dict[str, Any]] = []
    available = list(unexec)

    while missing and len(selected) < count and available:
        best = None
        best_gain: set[str] = set()
        for c in available:
            cbins = set(c.get(bin_key, []))
            gain = cbins & missing
            if len(gain) > len(best_gain):
                best = c
                best_gain = gain
            elif len(gain) == len(best_gain) and gain and best is not None:
                # Stable tie-breaking: lower candidate_id wins
                if c["candidate_id"] < best["candidate_id"]:
                    best = c
                    best_gain = gain
        if best is None or not best_gain:
            break
        missing -= best_gain
        available.remove(best)
        selected.append(_selection_record(best, "blackbox", len(best_gain)))

    # P0-1 FIX: Fill remaining slots with seeded fallback
    if len(selected) < count:
        fallback_ids = {c["candidate_id"] for c in selected}
        fallback_pool = [c for c in unexec if c["candidate_id"] not in fallback_ids]
        remainder = _select_random(fallback_pool, count - len(selected), seed)
        selected.extend(_selection_record(c, "fallback", 0) for c in remainder)

    return selected[:count]


def _select_bb_wb(
    state: CampaignState,
    unexec: list[dict[str, Any]],
    round_size: int,
    run_dirs: list[Path],
    seed: int,
) -> list[dict[str, Any]]:
    """P0-4 FIX: 16+16 rule with DUT-qualified whitebox + blackbox + fallback.

    Tracks per-round metadata: whitebox_count, blackbox_count, fallback_count,
    deduplicated_count, already_executed_excluded_count, final_selected_count.
    """
    whitebox_selected, wb_profile_counts, wb_warnings = _whitebox_schedule(
        unexec, run_dirs, max_wb=16
    )
    whitebox_selected = [
        _selection_record(candidate, "whitebox", 1)
        for candidate in whitebox_selected
    ]
    wb_ids = {c["candidate_id"] for c in whitebox_selected}

    remaining = [c for c in unexec if c["candidate_id"] not in wb_ids]
    bb_count = round_size - len(whitebox_selected)
    blackbox_selected = _select_guided(state, remaining, bb_count, run_dirs, seed)

    result = whitebox_selected + blackbox_selected
    seen: set[str] = set()
    deduped: list[dict] = []
    for c in result:
        if c["candidate_id"] not in seen:
            seen.add(c["candidate_id"])
            deduped.append(c)

    fallback_count = 0
    if len(deduped) < round_size:
        deduped_ids = {c["candidate_id"] for c in deduped}
        extra = _select_random(
            [c for c in unexec if c["candidate_id"] not in deduped_ids],
            round_size - len(deduped), seed)
        fallback_count = len(extra)
        deduped.extend(_selection_record(c, "fallback", 0) for c in extra)

    # P0-4: Log round metadata
    print(f"  [bb-wb] wb={len(whitebox_selected)} bb={len(blackbox_selected)} "
          f"fallback={fallback_count} final={len(deduped)}")

    if wb_warnings:
        print(f"  [bb-wb] whitebox_warnings={len(wb_warnings)}")

    return deduped[:round_size]


def _whitebox_schedule(
    unexec: list[dict[str, Any]], run_dirs: list[Path], max_wb: int
) -> tuple[list[dict[str, Any]], dict[str, int], list[str]]:
    """P0-4 FIX: Select up to max_wb candidates from profiles with eligible whitebox events.

    Only qual.eligible results contribute to feedback. Returns:
      (selected_candidates, profile_event_counts, warning_messages)
    """
    from pmpfuzz.whitebox import extract_whitebox_signals_for_result
    from pmpfuzz.coverage_qualification import load_case_map, load_results, qualify_result_for_coverage

    wb_profiles: dict[str, int] = {}
    warnings: list[str] = []
    skipped_ineligible: int = 0

    for d in run_dirs:
        try:
            case_map = load_case_map(d)
            results_by_case = load_results(d)
        except Exception as e:
            warnings.append(f"load failed for {d}: {e}")
            continue

        for case_name, result_list in results_by_case.items():
            case = case_map.get(case_name)
            if case is None:
                continue
            for result in result_list:
                # P0-4: Only eligible results contribute
                qual = qualify_result_for_coverage(case, result)
                if not qual.eligible:
                    skipped_ineligible += 1
                    continue
                try:
                    signals = extract_whitebox_signals_for_result(case, result, d)
                    if signals:
                        profile = case.get("profile", "")
                        wb_profiles[profile] = wb_profiles.get(profile, 0) + len(signals)
                except Exception as e:
                    warnings.append(f"extraction failed for {case_name}: {e}")

    if skipped_ineligible > 0:
        print(f"  [whitebox] skipped {skipped_ineligible} ineligible results")

    if not wb_profiles:
        return [], dict(wb_profiles), warnings

    ranked = sorted(wb_profiles.items(), key=lambda x: -x[1])
    selected: list[dict] = []
    seen: set[str] = set()
    for profile, count in ranked:
        for c in unexec:
            if len(selected) >= max_wb:
                break
            if c.get("profile") == profile and c["candidate_id"] not in seen:
                seen.add(c["candidate_id"])
                selected.append(c)
        if len(selected) >= max_wb:
            break
    return selected, dict(wb_profiles), warnings


def _coverage_gap_semantic(run_dirs: list[Path], dut: str) -> set[str]:
    """P0-1 FIX: Compute missing semantic bins using real DUT name."""
    from pmpfuzz.semantic_coverage import target_semantic_bins, semantic_bins_for_case
    from pmpfuzz.coverage_qualification import collect_execution_evidence

    target = set(target_semantic_bins(target="core-stateful"))
    observed: set[str] = set()
    for d in run_dirs:
        evidence = collect_execution_evidence([d], dut=dut)
        for case in evidence.eligible_cases:
            observed.update(semantic_bins_for_case(case))
    return target - observed


def _coverage_gap_predicates(run_dirs: list[Path], dut: str) -> set[str]:
    """P0-1 FIX: Compute missing predicate bins using real DUT name."""
    from pmpfuzz.semantic_coverage import target_contract_predicates, contract_predicates_for_case
    from pmpfuzz.coverage_qualification import collect_execution_evidence

    target = set(target_contract_predicates(target="core-stateful"))
    observed: set[str] = set()
    for d in run_dirs:
        evidence = collect_execution_evidence([d], dut=dut)
        for case in evidence.eligible_cases:
            observed.update(contract_predicates_for_case(case))
    return target - observed


def _coverage_gap_combo(run_dirs: list[Path], mode: str, dut: str) -> set[str]:
    """P0-1 FIX: Compute missing combo bins using real DUT name."""
    from pmpfuzz.semantic_coverage import target_combo_bins, combo_bins_for_case
    from pmpfuzz.coverage_qualification import collect_execution_evidence

    target = set(target_combo_bins(target="core-stateful", coverage_mode=mode))
    observed: set[str] = set()
    for d in run_dirs:
        evidence = collect_execution_evidence([d], dut=dut)
        for case in evidence.eligible_cases:
            observed.update(combo_bins_for_case(case, coverage_mode=mode))
    return target - observed


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------


def run_closed_loop(args: argparse.Namespace) -> int:
    """Execute a closed-loop campaign with single CampaignState (Phase B4)."""
    artifact_root = Path(args.artifact_root).resolve()
    campaign_dir = _campaign_output_dir(args, artifact_root)

    if campaign_dir.exists():
        print(f"ERROR: campaign output directory already exists: {campaign_dir}", file=sys.stderr)
        return 1

    campaign_dir.mkdir(parents=True)
    rounds_dir = campaign_dir / "rounds"
    rounds_dir.mkdir()
    metrics_dir = campaign_dir / "metrics"
    metrics_dir.mkdir()

    # Record start
    start_utc = datetime.now(timezone.utc).isoformat()
    start_wall = time.monotonic()

    # Build candidate pool (Phase B2)
    print(f"[{datetime.now(timezone.utc).isoformat()}] Building candidate pool...")
    from pmpfuzz.capabilities import capability_for_dut
    capability = capability_for_dut(args.dut)
    pool = build_candidate_pool(seed=args.seed, capability=capability)
    pool_path = metrics_dir / "candidate_pool.json"
    pool_path.write_text(json.dumps(pool, indent=2, ensure_ascii=True), encoding="ascii")
    print(f"  Pool: {len(pool)} candidates")

    # Create campaign state (Phase B4)
    campaign_id = args.campaign_id or f"{args.experiment_id}__{args.dut}__{args.variant}__{args.coverage_mode}__seed-{args.seed:04d}"
    state = CampaignState(
        campaign_id=campaign_id,
        variant=args.variant,
        dut=args.dut,
        seed=args.seed,
        coverage_mode=args.coverage_mode,
        candidate_pool=pool,
        start_time=start_wall,
    )

    # Write metadata
    meta = {
        "schema_version": "1.0",
        "experiment_id": args.experiment_id,
        "campaign_id": campaign_id,
        "variant": args.variant,
        "coverage_mode": args.coverage_mode,
        "dut": args.dut,
        "seed": args.seed,
        "round_size": args.round_size,
        "time_budget_seconds": args.time_budget,
        "per_case_timeout_seconds": args.per_case_timeout,
        "bootstrap_size": args.bootstrap_size,
        "candidate_pool_size": len(pool),
        "start_utc": start_utc,
        "hostname": os.uname().nodename if hasattr(os, "uname") else "unknown",
        "command_line": " ".join(sys.argv),
    }
    (metrics_dir / "campaign_metadata.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )

    # Build base command and environment
    base_cmd, base_env = _build_base_cmd(args)

    # Fix 8: Set timeline path for incremental persistence
    state.set_timeline_path(metrics_dir / "coverage_timeline.jsonl")

    # --- Bootstrap (Fix 3: map to candidate pool) ---
    print(f"[{datetime.now(timezone.utc).isoformat()}] Bootstrap (size={args.bootstrap_size})")
    bootstrap_dir = rounds_dir / "round_0000"
    bootstrap_candidates = _select_bootstrap_candidates(state, args)
    round_start_offset = time.monotonic() - start_wall
    success = _run_round(base_cmd, bootstrap_dir, args, state,
                         bootstrap_candidates=bootstrap_candidates,
                         enable_whitebox=getattr(args, "whitebox", False),
                         env=base_env,
                         round_start_offset=round_start_offset)
    if not success:
        print("ERROR: bootstrap failed — terminating campaign")
        _finalize(state, campaign_dir, metrics_dir, meta, start_wall)
        return 1
    state.advance_round()

    completed_round_dirs = [bootstrap_dir]

    # --- Main loop ---
    max_rounds = getattr(args, "max_rounds", None)
    while True:
        elapsed = time.monotonic() - start_wall
        if elapsed >= args.time_budget:
            print(f"Time budget exhausted after {state.round_idx} rounds")
            break
        if max_rounds is not None and state.round_idx >= max_rounds:
            print(f"Max rounds reached: {max_rounds}")
            break

        unexec = state.unexecuted_candidates()
        if not unexec:
            print(f"Candidate pool exhausted after {state.round_idx} rounds")
            break

        print(f"\n[{datetime.now(timezone.utc).isoformat()}] Round {state.round_idx} (elapsed={elapsed:.0f}s)")

        round_dir = rounds_dir / f"round_{state.round_idx:04d}"

        # Select candidates
        schedule_start = time.monotonic()
        candidates = select_next_candidates(state, args.round_size, completed_round_dirs, args.seed)
        schedule_time = time.monotonic() - schedule_start
        print(f"  Schedule: {len(candidates)} candidates in {schedule_time:.1f}s")

        if not candidates:
            print("  No candidates to execute (pool exhausted)")
            break

        # Fix 4: schedule seed = args.seed (same as candidate pool generation seed)
        schedule_path = metrics_dir / f"schedule_round_{state.round_idx:04d}.json"
        schedule_data = {
            "schema_version": 1,
            "seed": args.seed,  # Fix 4: consistent with candidate pool
            "selection_summary": _selection_summary(candidates),
            "entries": [_schedule_entry(c, args.seed) for c in candidates],
        }
        schedule_path.write_text(json.dumps(schedule_data, indent=2, ensure_ascii=True), encoding="ascii")

        # Execute round with whitebox enabled
        round_start_offset = time.monotonic() - start_wall
        success = _run_round(base_cmd, round_dir, args, state,
                             schedule_path=schedule_path, expected_candidates=candidates,
                             enable_whitebox=getattr(args, "whitebox", False),
                             env=base_env,
                             round_start_offset=round_start_offset)
        if not success:
            print(f"WARNING: round {state.round_idx} had failures")

        completed_round_dirs.append(round_dir)
        state.advance_round()

    # --- Finalize ---
    _finalize(state, campaign_dir, metrics_dir, meta, start_wall)
    return 0 if not state.any_round_failed else 1


def _select_bootstrap_candidates(state: CampaignState, args: argparse.Namespace) -> list[dict]:
    """Fix 3: Select bootstrap cases from the candidate pool."""
    unexec = state.unexecuted_candidates()
    # Bootstrap uses the first N unexecuted from the pool (in pool order)
    return unexec[:args.bootstrap_size]


def _run_round(
    base_cmd: list[str],
    round_dir: Path,
    args: argparse.Namespace,
    state: CampaignState,
    bootstrap_candidates: list[dict] | None = None,
    schedule_path: Path | None = None,
    expected_candidates: list[dict] | None = None,
    enable_whitebox: bool = False,
    env: dict | None = None,
    round_start_offset: float = 0.0,
) -> bool:
    """Execute one round via subprocess, then ingest results.

    Fix 9: Check subprocess return code and round result integrity.
    """
    is_bootstrap = bootstrap_candidates is not None
    candidates = bootstrap_candidates or expected_candidates or []

    # Fix 3: Write schedule that maps to candidate pool
    if is_bootstrap:
        schedule_path = round_dir.parent / "schedule_bootstrap.json"
        schedule_path.parent.mkdir(parents=True, exist_ok=True)
        schedule_data = {
            "schema_version": 1,
            "seed": args.seed,
            "selection_summary": _selection_summary(candidates),
            "entries": [_schedule_entry(c, args.seed) for c in candidates],
        }
        schedule_path.write_text(json.dumps(schedule_data, indent=2, ensure_ascii=True), encoding="ascii")

    round_cmd = list(base_cmd) + ["--out", str(round_dir)]
    round_cmd += ["--record-timeline",
                   "--campaign-id", f"{state.campaign_id}__round-{state.round_idx:04d}",
                   "--variant", state.variant]
    round_cmd += ["--schedule", str(schedule_path), "--seed", str(args.seed)]

    # P0-3: Separate process_success from ingest_success
    proc = subprocess.run(round_cmd, check=False, env=env)
    # The PMPFuzz CLI uses exit status 1 when one or more cases produce the
    # opaque ``nonpass`` outcome.  That is a completed engineering run, not a
    # launcher/infrastructure failure.  Artifact reconciliation below remains
    # authoritative for deciding whether the round is usable.
    process_success = proc.returncode in (0, 1)
    ingest_success = _ingest_round_results(state, round_dir, candidates,
                                            enable_whitebox=enable_whitebox,
                                            round_start_offset=round_start_offset)
    round_success = process_success and ingest_success

    if not process_success:
        print(f"  WARNING: round subprocess exited with {proc.returncode}")
    if not ingest_success:
        print(f"  WARNING: round ingestion incomplete (missing results)")

    state.record_round_result(round_success, {
        "process_success": process_success,
        "ingest_success": ingest_success,
        "returncode": proc.returncode,
    })
    return round_success


def _ingest_round_results(
    state: CampaignState,
    round_dir: Path,
    expected_candidates: list[dict[str, Any]],
    enable_whitebox: bool = False,
    round_start_offset: float = 0.0,
) -> bool:
    """P0-2 FIX: Read round timeline for real completion order and wall time.

    Each case's global wall time = round_start_offset + round_timeline_wall.
    This preserves real completion order and avoids batch-jump artifacts.
    """
    from pmpfuzz.coverage_qualification import load_case_map, load_results, qualify_result_for_coverage
    from pmpfuzz.semantic_coverage import (
        combo_bins_for_case, contract_predicates_for_case, semantic_bins_for_case,
    )

    case_map = load_case_map(round_dir)
    results_by_case = load_results(round_dir)
    cand_by_name: dict[str, str] = {c.get("name", ""): c["candidate_id"] for c in expected_candidates}

    # The child timeline is the only authoritative source for completion order.
    round_tl_path = round_dir / "metrics" / "coverage_timeline.jsonl"
    tl_order: list[dict] = []
    if not round_tl_path.exists():
        print(f"  WARNING: missing authoritative round timeline: {round_tl_path}")
        return False
    try:
        for line in round_tl_path.read_text(encoding="ascii").splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            if obj.get("completion_seq", 0) > 0:
                tl_order.append(obj)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"  WARNING: invalid authoritative round timeline: {exc}")
        return False

    if not tl_order:
        print("  WARNING: round timeline has no completed cases")
        return False

    round_sequences = [entry.get("completion_seq") for entry in tl_order]
    if round_sequences != list(range(1, len(round_sequences) + 1)):
        print("  WARNING: round completion_seq is not continuous")
        return False

    executed_names: set[str] = set()
    missing: list[str] = []
    integrity_errors: list[str] = []
    expected_names = {c.get("name", "") for c in expected_candidates if c.get("name")}
    timeline_names = [str(entry.get("case_id") or "") for entry in tl_order]
    timeline_name_set = {name for name in timeline_names if name}
    missing_from_timeline = sorted(expected_names - timeline_name_set)
    unexpected_in_timeline = sorted(timeline_name_set - expected_names)
    if missing_from_timeline:
        integrity_errors.append(
            f"{len(missing_from_timeline)} expected candidates missing from timeline"
        )
    if unexpected_in_timeline:
        integrity_errors.append(
            f"{len(unexpected_in_timeline)} unexpected candidates in timeline"
        )
    if len(timeline_names) != len(timeline_name_set):
        integrity_errors.append("duplicate case_id in round timeline")

    orphan_results = sorted(set(results_by_case) - expected_names)
    if orphan_results:
        integrity_errors.append(f"{len(orphan_results)} orphan result groups")

    # P0-2: Process in timeline order (real completion order)
    for tl_entry in tl_order:
        case_name = tl_entry.get("case_id", "")
        if not case_name:
            continue

        case = case_map.get(case_name)
        result_list = results_by_case.get(case_name, [])
        if case is None or not result_list:
            missing.append(case_name)
            continue
        executed_names.add(case_name)

        if len(result_list) != 1:
            integrity_errors.append(
                f"case {case_name} has {len(result_list)} results; expected exactly one"
            )
            continue

        result = result_list[0]
        qual = qualify_result_for_coverage(case, result)
        status = result.get("status", "unknown")

        # P0-2: Global wall time = round offset + round-relative completion time
        case_elapsed = result.get("elapsed_seconds", 0)
        completion_monotonic = tl_entry.get("completion_monotonic_seconds")
        if completion_monotonic is not None:
            elapsed_wall = float(completion_monotonic) - state.start_time
        else:
            round_wall = tl_entry.get("elapsed_wall_seconds", 0) or 0
            elapsed_wall = round_start_offset + float(round_wall)

        # Compute coverage contribution
        case_sem = set(semantic_bins_for_case(case))
        case_pair = {b for b in combo_bins_for_case(case) if b.startswith("combo2:")}
        case_trip = {b for b in combo_bins_for_case(case) if b.startswith("combo3:")}
        case_pred = set(contract_predicates_for_case(case))
        ns, np, nt, npr = state.update_coverage_sets(
            case_sem, case_pair, case_trip, case_pred, eligible=qual.eligible,
        )

        # Extract whitebox events
        new_wb = 0
        if enable_whitebox and qual.eligible and str(result.get("dut") or "") == state.dut:
            try:
                from pmpfuzz.whitebox import whitebox_event_ids_for_result
                wb_ids = whitebox_event_ids_for_result(case, result, round_dir)
                new_wb = state.record_whitebox_events(wb_ids)
            except Exception as e:
                print(f"  WARNING: whitebox extraction failed for {case_name}: {e}")

        candidate_id = cand_by_name.get(case_name)
        if candidate_id is None:
            integrity_errors.append(f"timeline case {case_name} has no scheduled candidate_id")
            continue
        state.record_case(
            candidate_id=candidate_id, case_id=case_name,
            profile=case.get("profile", ""), status=status,
            failure_class=result.get("failure_class"),
            eligible=qual.eligible, qualification_reason=qual.reason,
            elapsed_wall=elapsed_wall, case_elapsed=case_elapsed,
            new_semantic=ns, new_pairwise=np, new_triples=nt, new_predicates=npr,
            new_whitebox=new_wb,
            case_semantic=case_sem, case_pairwise=case_pair,
            case_triples=case_trip, case_predicates=case_pred,
        )

    if missing:
        print(f"  WARNING: {len(missing)} expected cases missing results")

    for error in integrity_errors:
        print(f"  WARNING: {error}")

    return len(missing) == 0 and not integrity_errors


def _finalize(
    state: CampaignState,
    campaign_dir: Path,
    metrics_dir: Path,
    meta: dict,
    start_wall: float,
) -> None:
    """Write final campaign outputs."""
    end_utc = datetime.now(timezone.utc).isoformat()
    meta["end_utc"] = end_utc
    meta["completed_rounds"] = state.round_idx
    meta["completed_cases"] = state.completed_cases
    meta["eligible_cases"] = state.eligible_cases
    meta["any_round_failed"] = state.any_round_failed
    (metrics_dir / "campaign_metadata.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )

    # Write campaign-level timeline
    tl_path = metrics_dir / "coverage_timeline.jsonl"
    state.write_timeline(tl_path)

    # Write executed_candidates.jsonl
    exec_path = metrics_dir / "executed_candidates.jsonl"
    with exec_path.open("w", encoding="ascii") as fh:
        for cid in sorted(state.executed_ids):
            fh.write(json.dumps({"candidate_id": cid}, ensure_ascii=True) + "\n")

    # Run coverage
    subprocess.run(
        [sys.executable, "-m", "pmpfuzz", "coverage", "--run-dir", str(campaign_dir)],
        check=False,
    )

    _write_commands_log(metrics_dir)

    print(f"\nCampaign complete: {campaign_dir}")
    print(f"  Rounds: {state.round_idx}")
    print(f"  Total cases: {state.completed_cases}")
    print(f"  Eligible cases: {state.eligible_cases}")
    print(f"  Wall time: {time.monotonic() - start_wall:.0f}s")
    print(f"  Any round failed: {state.any_round_failed}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_base_cmd(args: argparse.Namespace) -> tuple[list[str], dict]:
    """Return (command_list, env_dict) with PYTHONPATH set."""
    env = os.environ.copy()
    project_root = str(Path(__file__).resolve().parents[2])
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{project_root}:{existing}" if existing else project_root

    cmd = [
        sys.executable, "-m", "pmpfuzz", "run",
        "--dut", args.dut,
        "--time-budget", _format_budget(args.round_size * args.per_case_timeout * 2),
        "--per-case-timeout", str(args.per_case_timeout),
        "--jobs", str(args.jobs),
    ]
    if getattr(args, "whitebox", False):
        cmd.append("--whitebox-artifacts")
    if getattr(args, "spike", None):
        cmd.extend(["--spike", args.spike])
    if getattr(args, "isa", None):
        cmd.extend(["--isa", args.isa])
    if getattr(args, "chipyard_dir", None):
        cmd.extend(["--chipyard-dir", args.chipyard_dir])
    if getattr(args, "dut_bin", None):
        cmd.extend(["--dut-bin", args.dut_bin])
    if getattr(args, "no_smepmp", False):
        cmd.append("--no-smepmp")
    return cmd, env


def _campaign_output_dir(args: argparse.Namespace, artifact_root: Path) -> Path:
    return (
        artifact_root / "campaigns" / args.experiment_id / args.dut /
        args.variant / args.coverage_mode / f"seed-{args.seed:04d}"
    )


def _write_commands_log(metrics_dir: Path) -> None:
    log_path = metrics_dir / "commands.log"
    if not log_path.exists():
        log_path.write_text(
            f"# PMPFuzz closed-loop campaign commands\n"
            f"# Recorded at {datetime.now(timezone.utc).isoformat()}\n"
            f"command: {' '.join(sys.argv)}\n",
            encoding="ascii",
        )


def _format_budget(seconds: int) -> str:
    if seconds >= 3600:
        return f"{seconds // 3600}h"
    if seconds >= 60:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Closed-loop fuzzing campaign driver")
    parser.add_argument("--experiment-id", default="eval-v1")
    parser.add_argument("--variant", choices=["random", "guided", "bb", "bb-wb"], default="guided")
    parser.add_argument("--coverage-mode", choices=["semantic", "pairwise", "security-triples", "predicates"], default="semantic")
    parser.add_argument("--dut", default="spike")
    parser.add_argument("--profile", default="pmp-boundary")
    parser.add_argument("--bootstrap-profile", default=None)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--round-size", type=int, default=32)
    parser.add_argument("--bootstrap-size", type=int, default=32)
    parser.add_argument("--time-budget", type=int, default=3600)
    parser.add_argument("--per-case-timeout", type=int, default=10)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--campaign-id", default=None)
    parser.add_argument("--spike", default=None)
    parser.add_argument("--isa", default=None)
    parser.add_argument("--chipyard-dir", default=None)
    parser.add_argument("--dut-bin", default=None)
    parser.add_argument("--no-smepmp", action="store_true")
    parser.add_argument("--whitebox", action="store_true", dest="whitebox")
    parser.add_argument("--max-rounds", type=int, default=None,
                        help="Maximum number of rounds (for testing/smoke only)")

    return run_closed_loop(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
