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
_script_dir = _Path(__file__).resolve().parents[3]
if str(_script_dir) not in sys.path:
    sys.path.insert(0, str(_script_dir))

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
import platform
import random as rng_mod
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pmpfuzz.experiment_protocols import (
    BAPC_CONVERGENCE_FORMAL,
    BAPC_FORMAL_SEEDS,
    BAPC_FORMAL_VARIANTS,
    bapc_formal_contract_matches,
    build_bapc_convergence_contract,
    expected_bapc_formal_run_class,
    is_bapc_formal_campaign,
    is_bapc_formal_request,
    is_bapc_formal_run_class,
    typed_int_matches,
    typed_numeric_matches,
)
from pmpfuzz.stop_reasons import (
    STOP_COVERAGE_CONVERGED,
    STOP_HARD_CAP_CENSORED,
    is_convergence_terminal_stop_reason,
    normalize_stop_reason,
)

FIXED_VARIANTS = frozenset({"random", "guided", "bb", "bb-wb"})
CONTINUOUS_VARIANTS = frozenset({"random-fresh", "random-mutation", "bb-guided"})
ALL_VARIANTS = FIXED_VARIANTS | CONTINUOUS_VARIANTS
STRICT_RUN_CLASSES = frozenset({"readiness", "pilot", "formal", "baseline-pilot", "baseline-formal"})
KNOWN_RUN_CLASSES = STRICT_RUN_CLASSES | frozenset({"development-smoke"})
PMPFUZZ_ANALYSIS_COVERAGE_MODES = frozenset({"semantic", "pairwise", "security-triples", "predicates"})
PMPFUZZ_SINGLE_MODE_COVERAGE_MODES = frozenset({"hpm", "bapc"})
CONVERGENCE_TRACKED_MODES = ("semantic", "pairwise", "security_triples", "predicates")
RESUMABLE_CONTINUOUS_STOP_REASONS = frozenset({"max_rounds_reached"})
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _provided_flag_name(dest: str) -> str:
    return f"_{dest}_provided"


class _StoreValueWithProvidedFlag(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        setattr(namespace, _provided_flag_name(self.dest), True)


class _StoreTrueWithProvidedFlag(argparse.Action):
    def __init__(self, option_strings, dest, default=False, required=False, help=None):
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=0,
            const=True,
            default=default,
            required=required,
            help=help,
        )

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, True)
        setattr(namespace, _provided_flag_name(self.dest), True)


def _arg_was_provided(args: argparse.Namespace, dest: str) -> bool:
    marker = _provided_flag_name(dest)
    if hasattr(args, marker):
        return bool(getattr(args, marker))
    return getattr(args, dest, None) is not None


def _string_matches_canonical(value: object, expected: str) -> bool:
    return str(value or "") == str(expected)


def _enforce_or_fill_protocol_value(
    args: argparse.Namespace,
    *,
    field: str,
    expected: int | float | str,
    matches,
) -> None:
    current = getattr(args, field, None)
    if _arg_was_provided(args, field):
        if not matches(current, expected):
            raise ValueError(
                f"formal BAPC protocol requires {field}={expected!r}, got {current!r}"
            )
    else:
        setattr(args, field, expected)


def _empty_convergence_mode_positions(tracked_modes: tuple[str, ...] = CONVERGENCE_TRACKED_MODES) -> dict[str, dict[str, Any]]:
    return {
        mode: {
            "elapsed_wall_seconds": 0.0,
            "completed_cases": 0,
            "eligible_cases": 0,
            "completion_seq": 0,
        }
        for mode in tracked_modes
    }


def _analysis_scope_modes_for_campaign(variant: str, coverage_mode: str) -> set[str]:
    if str(variant) in CONTINUOUS_VARIANTS and str(coverage_mode) not in PMPFUZZ_SINGLE_MODE_COVERAGE_MODES:
        return set(PMPFUZZ_ANALYSIS_COVERAGE_MODES)
    return {str(coverage_mode)}


@dataclass
class ContinuousConvergenceTracker:
    enabled: bool = False
    min_runtime_seconds: float = 0.0
    confirmation_seconds: float = 0.0
    confirmation_eligible_cases: int = 0
    max_wall_time_seconds: float | None = None
    tracked_modes: tuple[str, ...] = CONVERGENCE_TRACKED_MODES
    convergence_confirmed: bool = False
    convergence_time_seconds: float | None = None
    convergence_completed_cases: int | None = None
    convergence_eligible_cases: int | None = None
    last_novelty_time: float = 0.0
    last_novelty_eligible_seq: int = 0
    last_novelty_completed_cases: int = 0
    last_novelty_unique_scenario_count: int = 0
    last_mode_novelty: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.tracked_modes = tuple(str(mode) for mode in (self.tracked_modes or CONVERGENCE_TRACKED_MODES))
        if not self.last_mode_novelty:
            self.last_mode_novelty = _empty_convergence_mode_positions(self.tracked_modes)

    def note_execution(
        self,
        *,
        elapsed_wall_seconds: float,
        completed_cases: int,
        eligible_cases: int,
        completion_seq: int,
        unique_scenario_count: int,
        eligible: bool,
        new_bins: dict[str, list[str] | set[str]],
    ) -> None:
        if not self.enabled or not eligible:
            return
        saw_novelty = False
        for mode in self.tracked_modes:
            values = new_bins.get(mode) or []
            if not values:
                continue
            saw_novelty = True
            self.last_mode_novelty[mode] = {
                "elapsed_wall_seconds": float(elapsed_wall_seconds),
                "completed_cases": int(completed_cases),
                "eligible_cases": int(eligible_cases),
                "completion_seq": int(completion_seq),
            }
        if not saw_novelty:
            return
        self.last_novelty_time = float(elapsed_wall_seconds)
        self.last_novelty_eligible_seq = int(eligible_cases)
        self.last_novelty_completed_cases = int(completed_cases)
        self.last_novelty_unique_scenario_count = int(unique_scenario_count)

    def evaluate(
        self,
        *,
        elapsed_wall_seconds: float,
        completed_cases: int,
        eligible_cases: int,
        unique_scenario_count: int,
        pending_count: int,
        any_round_failed: bool,
    ) -> dict[str, Any]:
        elapsed_wall_seconds = float(elapsed_wall_seconds)
        completed_cases = int(completed_cases)
        eligible_cases = int(eligible_cases)
        unique_scenario_count = int(unique_scenario_count)
        pending_count = int(pending_count)
        confirmation_window_seconds = max(0.0, elapsed_wall_seconds - self.last_novelty_time)
        confirmation_window_eligible_cases = max(0, eligible_cases - self.last_novelty_eligible_seq)
        unique_scenarios_since_last_novelty = max(
            0,
            unique_scenario_count - self.last_novelty_unique_scenario_count,
        )
        executions_since_last_novelty = max(
            0,
            completed_cases - self.last_novelty_completed_cases,
        )
        stable_all_modes = all(
            float(position.get("elapsed_wall_seconds") or 0.0) <= self.last_novelty_time + 1e-9
            for position in self.last_mode_novelty.values()
        )
        runtime_requirement_met = elapsed_wall_seconds >= self.min_runtime_seconds
        quiet_time_requirement_met = confirmation_window_seconds >= self.confirmation_seconds
        eligible_requirement_met = confirmation_window_eligible_cases >= self.confirmation_eligible_cases
        unique_progress_met = unique_scenarios_since_last_novelty > 0
        execution_progress_met = executions_since_last_novelty > 0
        pending_queue_nonempty = pending_count > 0
        convergence_candidate = (
            self.enabled
            and runtime_requirement_met
            and quiet_time_requirement_met
            and eligible_requirement_met
            and stable_all_modes
            and unique_progress_met
            and execution_progress_met
            and not any_round_failed
        )
        suggested_stop_reason = None
        if convergence_candidate and not self.convergence_confirmed:
            self.convergence_confirmed = True
            self.convergence_time_seconds = elapsed_wall_seconds
            self.convergence_completed_cases = completed_cases
            self.convergence_eligible_cases = eligible_cases
            suggested_stop_reason = STOP_COVERAGE_CONVERGED
        elif (
            self.enabled
            and not self.convergence_confirmed
            and self.max_wall_time_seconds is not None
            and elapsed_wall_seconds >= self.max_wall_time_seconds
        ):
            suggested_stop_reason = STOP_HARD_CAP_CENSORED
        return {
            "convergence_enabled": self.enabled,
            "convergence_min_runtime_seconds": self.min_runtime_seconds,
            "convergence_confirmation_seconds": self.confirmation_seconds,
            "convergence_confirmation_eligible_cases": self.confirmation_eligible_cases,
            "max_wall_time_seconds": self.max_wall_time_seconds,
            "tracked_modes": list(self.tracked_modes),
            "convergence_confirmed": self.convergence_confirmed,
            "convergence_time_seconds": self.convergence_time_seconds,
            "convergence_completed_cases": self.convergence_completed_cases,
            "convergence_eligible_cases": self.convergence_eligible_cases,
            "last_novelty_time": self.last_novelty_time,
            "last_novelty_eligible_seq": self.last_novelty_eligible_seq,
            "last_novelty_completed_cases": self.last_novelty_completed_cases,
            "last_novelty_unique_scenario_count": self.last_novelty_unique_scenario_count,
            "confirmation_window_seconds": confirmation_window_seconds,
            "confirmation_window_eligible_cases": confirmation_window_eligible_cases,
            "convergence_unique_scenarios_since_last_novelty": unique_scenarios_since_last_novelty,
            "convergence_executions_since_last_novelty": executions_since_last_novelty,
            "convergence_pending_queue_nonempty": pending_queue_nonempty,
            "convergence_stable_all_modes": stable_all_modes,
            "convergence_last_mode_novelty": self._mode_snapshot(),
            "suggested_stop_reason": suggested_stop_reason,
        }

    def restore(self, payload: dict[str, Any] | None) -> None:
        if not payload:
            return
        self.enabled = bool(payload.get("convergence_enabled", self.enabled))
        self.min_runtime_seconds = float(
            payload.get("convergence_min_runtime_seconds", self.min_runtime_seconds) or 0.0
        )
        self.confirmation_seconds = float(
            payload.get("convergence_confirmation_seconds", self.confirmation_seconds) or 0.0
        )
        self.confirmation_eligible_cases = int(
            payload.get("convergence_confirmation_eligible_cases", self.confirmation_eligible_cases) or 0
        )
        max_wall = payload.get("max_wall_time_seconds", self.max_wall_time_seconds)
        self.max_wall_time_seconds = None if max_wall in {None, ""} else float(max_wall)
        self.convergence_confirmed = bool(payload.get("convergence_confirmed", self.convergence_confirmed))
        self.convergence_time_seconds = _optional_float(
            payload.get("convergence_time_seconds", self.convergence_time_seconds)
        )
        self.convergence_completed_cases = _optional_int(
            payload.get("convergence_completed_cases", self.convergence_completed_cases)
        )
        self.convergence_eligible_cases = _optional_int(
            payload.get("convergence_eligible_cases", self.convergence_eligible_cases)
        )
        self.last_novelty_time = float(payload.get("last_novelty_time", self.last_novelty_time) or 0.0)
        self.last_novelty_eligible_seq = int(
            payload.get("last_novelty_eligible_seq", self.last_novelty_eligible_seq) or 0
        )
        self.last_novelty_completed_cases = int(
            payload.get("last_novelty_completed_cases", self.last_novelty_completed_cases) or 0
        )
        self.last_novelty_unique_scenario_count = int(
            payload.get("last_novelty_unique_scenario_count", self.last_novelty_unique_scenario_count) or 0
        )
        raw_modes = payload.get("convergence_last_mode_novelty") or {}
        tracked_modes = tuple(
            str(mode)
            for mode in (payload.get("tracked_modes") or self.tracked_modes or CONVERGENCE_TRACKED_MODES)
        )
        self.tracked_modes = tracked_modes
        restored = _empty_convergence_mode_positions(self.tracked_modes)
        for mode in self.tracked_modes:
            item = raw_modes.get(mode) or {}
            restored[mode] = {
                "elapsed_wall_seconds": float(item.get("elapsed_wall_seconds") or 0.0),
                "completed_cases": int(item.get("completed_cases") or 0),
                "eligible_cases": int(item.get("eligible_cases") or 0),
                "completion_seq": int(item.get("completion_seq") or 0),
            }
        self.last_mode_novelty = restored

    def _mode_snapshot(self) -> dict[str, dict[str, Any]]:
        return {
            mode: {
                "elapsed_wall_seconds": float(position.get("elapsed_wall_seconds") or 0.0),
                "completed_cases": int(position.get("completed_cases") or 0),
                "eligible_cases": int(position.get("eligible_cases") or 0),
                "completion_seq": int(position.get("completion_seq") or 0),
            }
            for mode, position in self.last_mode_novelty.items()
        }

    def mode_snapshot(self) -> dict[str, dict[str, Any]]:
        return self._mode_snapshot()


def _project_root() -> Path:
    source_root = os.environ.get("PMPFUZZ_SOURCE_ROOT")
    if source_root:
        return Path(source_root).expanduser().resolve()
    return Path(__file__).resolve().parents[3]


def _git_head_sha(cwd: Path | None = None) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(cwd or _project_root()),
        )
    except Exception:
        return None
    if result.returncode == 0:
        return result.stdout.strip()
    return None


def _git_text(cwd: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(cwd),
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def _stable_hex_digest(*parts: object) -> str:
    raw = "\0".join(str(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _resolve_existing_path(raw: str | None) -> Path | None:
    if not raw:
        return None
    path = Path(raw)
    return path if path.exists() else None


def _file_sha256(path: Path | None) -> str | None:
    if path is None or not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_hex_digest(value: object, length: int) -> bool:
    if not isinstance(value, str):
        return False
    pattern = _HEX40_RE if length == 40 else _HEX64_RE
    return pattern.fullmatch(value) is not None


def _optional_float(value: object) -> float | None:
    if value in {None, ""}:
        return None
    return float(value)


def _optional_int(value: object) -> int | None:
    if value in {None, ""}:
        return None
    return int(value)


def _classify_run_class(value: object) -> tuple[str, bool, bool]:
    run_class = str(value or "")
    if not run_class:
        return "", False, True
    return run_class, run_class in STRICT_RUN_CLASSES, run_class in KNOWN_RUN_CLASSES


def _whitebox_signal_event_id(signal: dict[str, Any]) -> str:
    features = signal.get("features") or {}
    key = "|".join(
        [
            str(signal.get("kind") or ""),
            str(features.get("security_chain") or ""),
            str(features.get("probe") or ""),
            str(features.get("coverage_point") or ""),
            str(features.get("perf_counter") or ""),
        ]
    )
    return hashlib.sha256(key.encode("ascii")).hexdigest()[:16]


def _security_events_from_whitebox_signals(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for signal in signals:
        if not isinstance(signal, dict):
            continue
        features = signal.get("features") or {}
        event_id = _whitebox_signal_event_id(signal)
        if event_id in seen_ids:
            continue
        seen_ids.add(event_id)
        kind = str(signal.get("kind") or "")
        chain = str(features.get("security_chain") or kind or "whitebox")
        namespace = "source_probe" if kind == "source_probe" else "whitebox"
        events.append(
            {
                "event_id": event_id,
                "event_namespace": namespace,
                "event_category": chain,
                "kind": kind,
                "security_chain": chain,
            }
        )
    return events


def _build_security_event_timeseries(
    lines: list[dict[str, Any]],
    *,
    experiment_id: str,
    campaign_id: str,
    method: str,
    variant: str,
    dut: str,
    seed: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    distinct_event_ids: set[str] = set()
    for entry in lines:
        completion_seq = int(entry.get("completion_seq") or 0)
        if completion_seq <= 0:
            continue
        event_index = 0
        case_seen: set[str] = set()
        for event in entry.get("security_events") or []:
            if not isinstance(event, dict):
                continue
            event_id = str(event.get("event_id") or "")
            if not event_id or event_id in case_seen:
                continue
            case_seen.add(event_id)
            event_index += 1
            is_new_event = event_id not in distinct_event_ids
            if is_new_event:
                distinct_event_ids.add(event_id)
            rows.append(
                {
                    "schema_version": "1.0",
                    "experiment_id": experiment_id,
                    "campaign_id": campaign_id,
                    "method": method,
                    "variant": variant,
                    "dut": dut,
                    "seed": seed,
                    "completion_seq": completion_seq,
                    "event_index": event_index,
                    "elapsed_wall_seconds": entry.get("elapsed_wall_seconds", 0),
                    "event_namespace": str(event.get("event_namespace") or "whitebox"),
                    "event_category": str(event.get("event_category") or ""),
                    "event_id": event_id,
                    "is_new_event": is_new_event,
                    "total_distinct_events": len(distinct_event_ids),
                    "case_id": entry.get("case_id"),
                }
            )
    return rows


def _write_security_event_timeseries(metrics_dir: Path, state: "CampaignState", meta: dict[str, Any]) -> None:
    rows = _build_security_event_timeseries(
        state._timeline_lines,
        experiment_id=str(meta.get("experiment_id") or ""),
        campaign_id=str(meta.get("campaign_id") or state.campaign_id),
        method=str(meta.get("method") or "pmpfuzz"),
        variant=str(meta.get("variant") or state.variant),
        dut=str(meta.get("dut") or state.dut),
        seed=int(meta.get("seed") or state.seed),
    )
    text = "".join(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n" for row in rows)
    _atomic_write_text(metrics_dir / "security_event_timeseries.jsonl", text, encoding="ascii")


def _source_tree_sha256(root: Path) -> str | None:
    raw = _git_text(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    paths: list[str] = []
    if raw is not None:
        paths = [item for item in raw.split("\0") if item]
    else:
        for path in sorted(root.rglob("*")):
            if ".git" in path.parts or not path.is_file():
                continue
            paths.append(str(path.relative_to(root)).replace("\\", "/"))
    hasher = hashlib.sha256()
    for rel in paths:
        path = root / rel
        if not path.is_file():
            continue
        hasher.update(rel.replace("\\", "/").encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    if not paths:
        return None
    return hasher.hexdigest()


def _git_is_dirty(root: Path) -> bool:
    status = _git_text(root, "status", "--porcelain=v1", "--untracked-files=all")
    return bool(status and status.strip())


def _expected_campaign_id(args: argparse.Namespace) -> str:
    return args.campaign_id or (
        f"{args.experiment_id}__{args.dut}__{_variant_path_segment(args)}__{args.coverage_mode}__seed-{args.seed:04d}"
    )


def _generator_variant(args: argparse.Namespace) -> str:
    return str(getattr(args, "generator_variant", "full") or "full")


def _variant_path_segment(args: argparse.Namespace) -> str:
    generator_variant = _generator_variant(args)
    scheduler = str(getattr(args, "variant", "") or "")
    if generator_variant == "full":
        return scheduler
    return f"{scheduler}__{generator_variant}"


def _continuous_profiles_from_args(args: argparse.Namespace) -> tuple[str, ...]:
    from pmpfuzz.semantic_coverage import CORE_STATEFUL_TARGET, target_profiles

    raw_profiles = [item.strip() for item in str(getattr(args, "profile", "") or "").split(",") if item.strip()]
    if not raw_profiles:
        raw_profiles = ["pmp-boundary"]
    profiles: list[str] = []
    for profile in raw_profiles:
        if profile == CORE_STATEFUL_TARGET:
            profiles.extend(target_profiles(CORE_STATEFUL_TARGET, include_experimental=False))
        else:
            profiles.append(profile)
    return tuple(profiles)


def _profile_distribution(profiles: tuple[str, ...]) -> dict[str, float]:
    if not profiles:
        return {}
    counts: dict[str, int] = {}
    for profile in profiles:
        counts[profile] = counts.get(profile, 0) + 1
    total = float(len(profiles))
    return {profile: count / total for profile, count in sorted(counts.items())}


def _apply_experiment_protocol_defaults(args: argparse.Namespace) -> None:
    coverage_mode = getattr(args, "coverage_mode", None)
    run_class = getattr(args, "run_class", None)
    protocol_id = getattr(args, "experiment_protocol_id", None)
    if not is_bapc_formal_request(
        coverage_mode=coverage_mode,
        run_class=run_class,
        experiment_protocol_id=protocol_id,
    ):
        return
    if not is_bapc_formal_campaign(
        coverage_mode=coverage_mode,
        experiment_protocol_id=protocol_id,
    ):
        raise ValueError(
            "formal BAPC run requires experiment_protocol_id='bapc-convergence-v1'"
        )
    expected_run_class = expected_bapc_formal_run_class("pmpfuzz")
    if str(run_class or "") != expected_run_class:
        raise ValueError(
            f"bapc convergence protocol requires PMPFuzz run_class={expected_run_class!r}, "
            f"got {run_class!r}"
        )
    args.convergence_stop = True
    _enforce_or_fill_protocol_value(
        args,
        field="convergence_min_runtime_seconds",
        expected=BAPC_CONVERGENCE_FORMAL["convergence_min_runtime_seconds"],
        matches=typed_numeric_matches,
    )
    _enforce_or_fill_protocol_value(
        args,
        field="convergence_confirmation_seconds",
        expected=BAPC_CONVERGENCE_FORMAL["convergence_confirmation_seconds"],
        matches=typed_numeric_matches,
    )
    _enforce_or_fill_protocol_value(
        args,
        field="convergence_confirmation_eligible_cases",
        expected=BAPC_CONVERGENCE_FORMAL["convergence_confirmation_eligible_cases"],
        matches=typed_int_matches,
    )
    _enforce_or_fill_protocol_value(
        args,
        field="max_wall_time_seconds",
        expected=BAPC_CONVERGENCE_FORMAL["max_wall_time_seconds"],
        matches=typed_numeric_matches,
    )
    _enforce_or_fill_protocol_value(
        args,
        field="time_budget",
        expected=BAPC_CONVERGENCE_FORMAL["time_budget_seconds"],
        matches=typed_int_matches,
    )
    _enforce_or_fill_protocol_value(
        args,
        field="budget_class",
        expected=BAPC_CONVERGENCE_FORMAL["budget_class"],
        matches=_string_matches_canonical,
    )


def _write_expected_bapc_contract(contract_path: Path, expected: dict[str, Any]) -> None:
    if contract_path.exists():
        try:
            existing = json.loads(contract_path.read_text(encoding="ascii"))
        except Exception as exc:
            raise ValueError(f"experiment-contract.json unreadable: {exc}") from exc
        if not bapc_formal_contract_matches(existing, expected):
            raise ValueError("experiment-contract.json does not match formal BAPC protocol contract")
        return
    _atomic_write_text(
        contract_path,
        json.dumps(expected, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )


def _write_experiment_contract_manifest(
    args: argparse.Namespace,
    artifact_root: Path,
    coverage_universes: dict[str, dict[str, Any]],
) -> None:
    if not is_bapc_formal_request(
        coverage_mode=getattr(args, "coverage_mode", None),
        run_class=getattr(args, "run_class", None),
        experiment_protocol_id=getattr(args, "experiment_protocol_id", None),
    ):
        return
    if not is_bapc_formal_campaign(
        coverage_mode=getattr(args, "coverage_mode", None),
        experiment_protocol_id=getattr(args, "experiment_protocol_id", None),
    ):
        raise ValueError("formal BAPC run requires experiment_protocol_id before contract creation")
    universe = coverage_universes.get("bapc")
    if not isinstance(universe, dict):
        return
    manifests_dir = artifact_root / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    contract_path = manifests_dir / "experiment-contract.json"
    provenance = _continuous_provenance(args, coverage_universes)
    contract = build_bapc_convergence_contract(
        dut=str(getattr(args, "dut")),
        bin_count=int(universe.get("bin_count") or 0),
        bin_set_sha256=str(universe.get("bin_set_sha256") or ""),
        variants=BAPC_FORMAL_VARIANTS,
        seeds=BAPC_FORMAL_SEEDS,
        source_sha=str(provenance.get("source_sha") or ""),
        source_tree_sha256=str(provenance.get("source_tree_sha256") or ""),
        dut_sha=str(provenance.get("dut_sha") or ""),
        dut_binary_sha256=str(provenance.get("dut_binary_sha256") or ""),
    )
    _write_expected_bapc_contract(contract_path, contract)


def _resolve_dut_binary_path(args: argparse.Namespace) -> Path | None:
    for attr in ("dut_bin", "spike"):
        path = _resolve_existing_path(getattr(args, attr, None))
        if path is not None:
            return path
    return None


def _continuous_convergence_config(args: argparse.Namespace) -> dict[str, Any]:
    if not bool(getattr(args, "convergence_stop", False)):
        return {}
    max_wall = getattr(args, "max_wall_time_seconds", None)
    if max_wall in {None, ""}:
        max_wall = getattr(args, "time_budget")
    return {
        "convergence_enabled": True,
        "convergence_min_runtime_seconds": float(getattr(args, "convergence_min_runtime_seconds", 0) or 0.0),
        "convergence_confirmation_seconds": float(getattr(args, "convergence_confirmation_seconds", 0) or 0.0),
        "convergence_confirmation_eligible_cases": int(
            getattr(args, "convergence_confirmation_eligible_cases", 0) or 0
        ),
        "max_wall_time_seconds": float(max_wall),
    }


def _continuous_provenance(args: argparse.Namespace, coverage_universes: dict[str, dict[str, Any]]) -> dict[str, Any]:
    project_root = _project_root()
    source_sha = str(getattr(args, "source_sha", None) or _git_head_sha(project_root) or "")
    source_sha_status = "explicit" if getattr(args, "source_sha", None) else "git-head"
    source_tree_sha256 = str(_source_tree_sha256(project_root) or "")
    source_dirty = _git_is_dirty(project_root)
    chipyard_dir = _resolve_existing_path(getattr(args, "chipyard_dir", None))
    dut_sha = str(getattr(args, "dut_sha", None) or "")
    dut_sha_status = "explicit" if dut_sha else ""
    dut_sha_reason = ""
    if not dut_sha and chipyard_dir is not None:
        dut_sha = str(_git_head_sha(chipyard_dir) or "")
        if dut_sha:
            dut_sha_status = "git-head"
    if not dut_sha:
        dut_sha_status = "not-applicable"
        dut_sha_reason = "dut source repository unavailable"
    dut_binary_path = _resolve_dut_binary_path(args)
    dut_binary_sha256 = str(_file_sha256(dut_binary_path) or "")
    capability_fingerprint = str(
        getattr(args, "capability_fingerprint", None)
        or coverage_universes.get(str(getattr(args, "coverage_mode", "")), {}).get("capability_fingerprint")
        or coverage_universes.get("semantic", {}).get("capability_fingerprint")
        or _stable_hex_digest(
            "capability",
            getattr(args, "dut", ""),
            getattr(args, "coverage_mode", ""),
        )
    )
    return {
        "method": "pmpfuzz",
        "experiment_protocol_id": str(getattr(args, "experiment_protocol_id", "") or ""),
        "run_class": str(getattr(args, "run_class", "pilot") or "pilot"),
        "budget_class": str(getattr(args, "budget_class", "primary-wall-clock") or "primary-wall-clock"),
        "wall_clock_horizon_seconds": int(
            getattr(args, "max_wall_time_seconds", None) or getattr(args, "time_budget")
        ),
        "source_sha": source_sha,
        "source_sha_status": source_sha_status,
        "source_tree_sha256": source_tree_sha256,
        "source_dirty": source_dirty,
        "dut_sha": dut_sha,
        "dut_sha_status": dut_sha_status,
        "dut_sha_reason": dut_sha_reason,
        "dut_binary_sha256": dut_binary_sha256,
        "dut_binary_path": str(dut_binary_path) if dut_binary_path is not None else "",
        "capability_fingerprint": capability_fingerprint,
        "coverage_schema": (
            "pmpfuzz-v1-single-mode"
            if str(getattr(args, "coverage_mode", "")) in PMPFUZZ_SINGLE_MODE_COVERAGE_MODES
            else "pmpfuzz-v1-four-mode"
        ),
    }


def _current_elapsed_wall_seconds(state: "CampaignState", start_wall: float) -> float:
    elapsed = state._elapsed_wall_offset + (time.monotonic() - start_wall)
    if state._timeline_lines:
        elapsed = max(elapsed, float(state._timeline_lines[-1].get("elapsed_wall_seconds") or 0.0))
    return float(elapsed)


def _validate_continuous_provenance(meta: dict[str, Any]) -> None:
    run_class, is_strict, is_known = _classify_run_class(meta.get("run_class"))
    if run_class and not is_known:
        raise ValueError(f"unknown run_class: {run_class}")
    if not is_strict:
        return
    errors: list[str] = []
    if not _is_hex_digest(meta.get("source_sha"), 40):
        errors.append("source_sha must be a 40-hex git commit")
    if not _is_hex_digest(meta.get("source_tree_sha256"), 64):
        errors.append("source_tree_sha256 must be a 64-hex tree digest")
    if not isinstance(meta.get("source_dirty"), bool):
        errors.append("source_dirty must be a bool")
    elif is_bapc_formal_request(
        coverage_mode=meta.get("coverage_mode"),
        run_class=run_class,
        experiment_protocol_id=meta.get("experiment_protocol_id"),
    ) and meta.get("source_dirty") is not False:
        errors.append("formal BAPC requires source_dirty=False")
    dut_sha_status = str(meta.get("dut_sha_status") or "")
    if dut_sha_status == "not-applicable":
        if not str(meta.get("dut_sha_reason") or ""):
            errors.append("dut_sha_reason required when dut_sha_status=not-applicable")
    elif not _is_hex_digest(meta.get("dut_sha"), 40):
        errors.append("dut_sha must be 40-hex or typed not-applicable")
    if not _is_hex_digest(meta.get("dut_binary_sha256"), 64):
        errors.append("dut_binary_sha256 must be a 64-hex file digest")
    binary_path = _resolve_existing_path(str(meta.get("dut_binary_path") or ""))
    if binary_path is None or not binary_path.is_file():
        errors.append("dut_binary_path must point to an existing file")
    elif _file_sha256(binary_path) != meta.get("dut_binary_sha256"):
        errors.append("dut_binary_sha256 does not match dut_binary_path")
    if not str(meta.get("capability_fingerprint") or ""):
        errors.append("capability_fingerprint required")
    if errors:
        raise ValueError("strict provenance invalid: " + "; ".join(errors))


def _prepare_artifact_root(args: argparse.Namespace, artifact_root: Path) -> None:
    if bool(getattr(args, "skip_artifact_root_prep", False)):
        return
    artifact_root.mkdir(parents=True, exist_ok=True)
    manifests_dir = artifact_root / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    run_class, is_strict, is_known = _classify_run_class(getattr(args, "run_class", None))
    if run_class and not is_known:
        raise ValueError(f"unknown run_class: {run_class}")
    if not is_strict:
        return
    _write_global_manifests(args, artifact_root, manifests_dir)


def _write_global_manifests(args: argparse.Namespace, artifact_root: Path, manifests_dir: Path) -> None:
    environment = {
        "artifact_root": str(artifact_root),
        "cwd": str(Path.cwd()),
        "hostname": os.uname().nodename if hasattr(os, "uname") else platform.node(),
        "platform": platform.platform(),
        "python_executable": sys.executable,
        "python_version": platform.python_version(),
    }
    _atomic_write_text(
        manifests_dir / "environment.json",
        json.dumps(environment, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )

    project_root = _project_root()
    chipyard_dir = _resolve_existing_path(getattr(args, "chipyard_dir", None))
    lines: list[str] = []
    source_sha = str(getattr(args, "source_sha", None) or _git_head_sha(project_root) or "")
    if source_sha:
        lines.append(f"{source_sha}  pmpfuzz")
    dut_sha = str(getattr(args, "dut_sha", None) or "")
    if not dut_sha and chipyard_dir is not None:
        dut_sha = str(_git_head_sha(chipyard_dir) or "")
    if dut_sha:
        lines.append(f"{dut_sha}  chipyard")
    if not lines:
        lines.append(f"{'0' * 40}  unavailable")
    _atomic_write_text(
        manifests_dir / "git-shas.txt",
        "\n".join(lines) + "\n",
        encoding="ascii",
    )

    scope_path = manifests_dir / "analysis-scope.json"
    existing: dict[str, Any] = {}
    if scope_path.exists():
        try:
            existing = json.loads(scope_path.read_text(encoding="ascii"))
        except Exception:
            existing = {}
    variants = {str(item) for item in existing.get("primary_variants") or [] if str(item)}
    variants.add(str(args.variant))
    seeds = {int(item) for item in existing.get("primary_seeds") or []}
    seeds.add(int(args.seed))
    coverage_modes = {str(item) for item in existing.get("coverage_modes") or [] if str(item)}
    coverage_modes |= _analysis_scope_modes_for_campaign(str(args.variant), str(args.coverage_mode))
    guidance_mode = str(existing.get("guidance_mode") or getattr(args, "coverage_mode", "") or "")
    primary_metric = str(existing.get("primary_metric") or getattr(args, "coverage_mode", "") or "")
    scope = {
        "schema_version": 1,
        "artifact_root": str(artifact_root),
        "experiment_id": str(args.experiment_id),
        "dut": str(args.dut),
        "run_class": str(getattr(args, "run_class", "") or ""),
        "guidance_mode": guidance_mode,
        "primary_metric": primary_metric,
        "primary_variants": sorted(variants),
        "primary_seeds": sorted(seeds),
        "coverage_modes": sorted(coverage_modes),
        "updated_utc": datetime.now(timezone.utc).isoformat(),
    }
    _atomic_write_text(
        scope_path,
        json.dumps(scope, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )


def _write_artifact_sha_manifest(artifact_root: Path) -> None:
    from scripts.evaluation.analysis.aggregate_results import _write_artifact_hashes

    hash_path = artifact_root / "manifests" / "artifact-sha256.txt"
    paths = [
        path
        for path in sorted(artifact_root.rglob("*"))
        if path.is_file() and path.resolve() != hash_path.resolve()
    ]
    hash_path.parent.mkdir(parents=True, exist_ok=True)
    _write_artifact_hashes(artifact_root, paths, hash_path)


def _finalize_artifact_root(args: argparse.Namespace, artifact_root: Path) -> None:
    run_class, is_strict, is_known = _classify_run_class(getattr(args, "run_class", None))
    if run_class and not is_known:
        raise ValueError(f"unknown run_class: {run_class}")
    if not is_strict:
        return
    if bool(getattr(args, "skip_artifact_root_finalize", False)):
        _write_artifact_sha_manifest(artifact_root)
        return
    from scripts.evaluation.analysis.aggregate_results import aggregate

    aggregate(artifact_root, str(args.experiment_id))


def _atomic_write_text(path: Path, text: str, *, encoding: str = "ascii") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding=encoding,
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            handle.write(text)
            tmp_name = handle.name
        os.replace(tmp_name, path)
    except Exception:
        if tmp_name:
            try:
                Path(tmp_name).unlink(missing_ok=True)
            except Exception:
                pass
        raise

# ---------------------------------------------------------------------------
# CampaignState — single source of truth across all rounds
# ---------------------------------------------------------------------------


class CampaignState:
    """In-memory campaign state that survives across rounds (Phase B4)."""

    VALID_VARIANTS = ALL_VARIANTS

    def __init__(
        self,
        campaign_id: str,
        variant: str,
        dut: str,
        seed: int,
        coverage_mode: str,
        candidate_pool: list[dict[str, Any]],
        start_time: float,
        coverage_universes: dict[str, dict[str, Any]] | None = None,
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
        self._elapsed_wall_offset: float = 0.0

        # Coverage sets (accumulated across all rounds)
        self._covered_semantic: set[str] = set()
        self._covered_pairwise: set[str] = set()
        self._covered_triples: set[str] = set()
        self._covered_predicates: set[str] = set()
        self._covered_hpm: set[str] = set()
        self._eligible_hpm_cases: int = 0
        self._covered_bapc: set[str] = set()
        self._eligible_bapc_cases: int = 0

        # Target bin counts (Fix 1) — computed once from candidate pool
        if coverage_universes is not None:
            from pmpfuzz.bapc import infer_bapc_core_version
            from pmpfuzz.coverage_universe import validate_coverage_universe

            semantic_universe = validate_coverage_universe(coverage_universes["semantic"])
            pairwise_universe = validate_coverage_universe(coverage_universes["pairwise"])
            triples_universe = validate_coverage_universe(coverage_universes["security_triples"])
            predicates_universe = validate_coverage_universe(coverage_universes["predicates"])
            hpm_universe = validate_coverage_universe(coverage_universes["hpm"]) if "hpm" in coverage_universes else None
            bapc_universe = validate_coverage_universe(coverage_universes["bapc"]) if "bapc" in coverage_universes else None
            self._target_semantic_bins = set(semantic_universe["bin_ids"])
            self._target_pairwise_bins = set(pairwise_universe["bin_ids"])
            self._target_triples_bins = set(triples_universe["bin_ids"])
            self._target_predicates_bins = set(predicates_universe["bin_ids"])
            self._target_hpm_bins = set(hpm_universe["bin_ids"]) if hpm_universe is not None else set()
            self._target_bapc_bins = set(bapc_universe["bin_ids"]) if bapc_universe is not None else set()
            self.coverage_universe_hashes = {
                "semantic": semantic_universe["sha256"],
                "pairwise": pairwise_universe["sha256"],
                "security_triples": triples_universe["sha256"],
                "predicates": predicates_universe["sha256"],
            }
            if hpm_universe is not None:
                self.coverage_universe_hashes["hpm"] = hpm_universe["sha256"]
            if bapc_universe is not None:
                self.coverage_universe_hashes["bapc"] = bapc_universe["sha256"]
            self.coverage_target = str(semantic_universe.get("target") or "core-stateful")
            self.bapc_core_version = infer_bapc_core_version(bapc_universe) if bapc_universe is not None else None
        else:
            self._target_semantic_bins = set().union(*(c.get("semantic_bins", []) for c in candidate_pool))
            self._target_pairwise_bins = set().union(*(c.get("pairwise_bins", []) for c in candidate_pool))
            self._target_triples_bins = set().union(*(c.get("security_triple_bins", []) for c in candidate_pool))
            self._target_predicates_bins = set().union(*(c.get("predicate_bins", []) for c in candidate_pool))
            self._target_hpm_bins = set().union(*(c.get("hpm_bins", []) for c in candidate_pool))
            self._target_bapc_bins = set().union(*(c.get("bapc_bins", []) for c in candidate_pool))
            self.coverage_universe_hashes = {}
            self.coverage_target = "core-stateful"
            self.bapc_core_version = None
        self._target_semantic: int = len(self._target_semantic_bins)
        self._target_pairwise: int = len(self._target_pairwise_bins)
        self._target_triples: int = len(self._target_triples_bins)
        self._target_predicates: int = len(self._target_predicates_bins)
        self._target_hpm: int = len(self._target_hpm_bins)
        self._target_bapc: int = len(self._target_bapc_bins)

        # Whitebox events
        self._whitebox_event_ids: set[str] = set()

        # Timeline lines + persistence (Fix 8)
        self._timeline_lines: list[dict] = []
        self._timeline_path: Path | None = None

        # Round failure tracking
        self._round_results: list[dict] = []
        self._any_round_failed: bool = False
        self._stop_reason: str | None = None
        self._convergence = ContinuousConvergenceTracker()
        self._unique_scenario_count: int = 0
        self._pending_count: int = 0

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

    @property
    def stop_reason(self) -> str | None:
        return self._stop_reason

    @property
    def unique_scenario_count(self) -> int:
        return self._unique_scenario_count

    @property
    def pending_count(self) -> int:
        return self._pending_count

    @property
    def convergence_confirmed(self) -> bool:
        return bool(self._convergence.convergence_confirmed)

    @property
    def target_semantic_bins(self) -> frozenset[str]:
        return frozenset(self._target_semantic_bins)

    @property
    def target_pairwise_bins(self) -> frozenset[str]:
        return frozenset(self._target_pairwise_bins)

    @property
    def target_triples_bins(self) -> frozenset[str]:
        return frozenset(self._target_triples_bins)

    @property
    def target_predicates_bins(self) -> frozenset[str]:
        return frozenset(self._target_predicates_bins)

    @property
    def target_hpm_bins(self) -> frozenset[str]:
        return frozenset(self._target_hpm_bins)

    @property
    def target_bapc_bins(self) -> frozenset[str]:
        return frozenset(self._target_bapc_bins)

    def set_stop_reason(self, reason: str | None) -> None:
        new_reason = normalize_stop_reason(reason)
        if new_reason is None:
            if self._stop_reason is None:
                return
            raise ValueError(f"cannot clear latched stop_reason {self._stop_reason!r}")
        if self._stop_reason is None:
            self._stop_reason = new_reason
            return
        if self._stop_reason != new_reason:
            raise ValueError(
                f"stop_reason already latched as {self._stop_reason!r}; cannot replace with {new_reason!r}"
            )

    def clear_stop_reason(self) -> None:
        if self._stop_reason is not None:
            raise ValueError(f"cannot clear latched stop_reason {self._stop_reason!r}")

    def set_unique_scenario_count(self, value: int) -> None:
        self._unique_scenario_count = max(0, int(value))

    def set_pending_count(self, value: int) -> None:
        self._pending_count = max(0, int(value))

    def configure_convergence(
        self,
        *,
        enabled: bool,
        min_runtime_seconds: float = 0.0,
        confirmation_seconds: float = 0.0,
        confirmation_eligible_cases: int = 0,
        max_wall_time_seconds: float | None = None,
        tracked_modes: tuple[str, ...] = CONVERGENCE_TRACKED_MODES,
    ) -> None:
        self._convergence = ContinuousConvergenceTracker(
            enabled=bool(enabled),
            min_runtime_seconds=float(min_runtime_seconds or 0.0),
            confirmation_seconds=float(confirmation_seconds or 0.0),
            confirmation_eligible_cases=int(confirmation_eligible_cases or 0),
            max_wall_time_seconds=None if max_wall_time_seconds in {None, ""} else float(max_wall_time_seconds),
            tracked_modes=tracked_modes,
        )

    def restore_convergence_state(self, payload: dict[str, Any] | None) -> None:
        self._convergence.restore(payload)

    def _current_convergence_eligible_cases(self) -> int:
        if self.coverage_mode == "bapc":
            return self._eligible_bapc_cases
        if self.coverage_mode == "hpm":
            return self._eligible_hpm_cases
        return self._eligible_cases

    def _projected_convergence_eligible_cases(
        self,
        *,
        executed: bool,
        eligible: bool,
        hpm_eligible: bool = False,
        bapc_eligible: bool = False,
    ) -> int:
        eligible_cases = self._current_convergence_eligible_cases()
        if executed:
            return eligible_cases
        if self.coverage_mode == "bapc":
            return eligible_cases + int(bool(bapc_eligible))
        if self.coverage_mode == "hpm":
            return eligible_cases + int(bool(hpm_eligible))
        return eligible_cases + int(bool(eligible))

    def _convergence_eligible(
        self,
        *,
        eligible: bool,
        hpm_eligible: bool | None = None,
        bapc_eligible: bool | None = None,
    ) -> bool:
        if self.coverage_mode == "bapc" and bapc_eligible is not None:
            return bool(bapc_eligible)
        if self.coverage_mode == "hpm" and hpm_eligible is not None:
            return bool(hpm_eligible)
        return bool(eligible)

    def note_convergence_execution(
        self,
        *,
        elapsed_wall_seconds: float,
        eligible: bool,
        hpm_eligible: bool | None = None,
        bapc_eligible: bool | None = None,
        new_bins: dict[str, list[str] | set[str]],
        unique_scenario_count: int,
        completed_cases: int,
        eligible_cases: int | None = None,
    ) -> None:
        convergence_eligible = self._convergence_eligible(
            eligible=eligible,
            hpm_eligible=hpm_eligible,
            bapc_eligible=bapc_eligible,
        )
        if (
            (self.coverage_mode == "bapc" and bapc_eligible is None)
            or (self.coverage_mode == "hpm" and hpm_eligible is None)
            or eligible_cases is None
        ):
            eligible_cases = self._current_convergence_eligible_cases()
        self._convergence.note_execution(
            elapsed_wall_seconds=float(elapsed_wall_seconds),
            completed_cases=int(completed_cases),
            eligible_cases=int(eligible_cases),
            completion_seq=int(completed_cases),
            unique_scenario_count=int(unique_scenario_count),
            eligible=convergence_eligible,
            new_bins=new_bins,
        )

    def convergence_snapshot(self, *, elapsed_wall_seconds: float, unique_scenario_count: int, pending_count: int) -> dict[str, Any]:
        snapshot = self._convergence.evaluate(
            elapsed_wall_seconds=float(elapsed_wall_seconds),
            completed_cases=self.completed_cases,
            eligible_cases=self._current_convergence_eligible_cases(),
            unique_scenario_count=int(unique_scenario_count),
            pending_count=int(pending_count),
            any_round_failed=self.any_round_failed,
        )
        snapshot["stop_reason"] = self.stop_reason
        return snapshot

    def convergence_mode_snapshot(self) -> dict[str, dict[str, Any]]:
        return self._convergence.mode_snapshot()

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
                    new_hpm=0, hpm_eligible=False, case_hpm=None, hpm_snapshot=None,
                    new_bapc=0, bapc_eligible=False, case_bapc=None, bapc_snapshot=None,
                    case_semantic=None, case_pairwise=None, case_triples=None, case_predicates=None,
                    security_events=None):
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
        if hpm_eligible:
            self._eligible_hpm_cases += 1
            if case_hpm is not None:
                self._covered_hpm.update(case_hpm)
        if bapc_eligible:
            self._eligible_bapc_cases += 1
            if case_bapc is not None:
                self._covered_bapc.update(case_bapc)

        line = self._make_timeline_line(
            case_id=case_id, profile=profile, status=status,
            failure_class=failure_class, eligible=eligible,
            qualification_reason=qualification_reason,
            elapsed_wall=elapsed_wall, case_elapsed=case_elapsed,
            new_semantic=new_semantic, new_pairwise=new_pairwise,
            new_triples=new_triples, new_predicates=new_predicates,
            new_whitebox=new_whitebox,
            new_hpm=new_hpm,
            hpm_eligible=hpm_eligible,
            hpm_snapshot=hpm_snapshot or {},
            new_bapc=new_bapc,
            bapc_eligible=bapc_eligible,
            bapc_snapshot=bapc_snapshot or {},
            security_events=security_events or [],
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
        hpm_cov = len(self._covered_hpm)
        hpm_target = self._target_hpm
        bapc_cov = len(self._covered_bapc)
        bapc_target = self._target_bapc
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
            "eligible_hpm_cases": self._eligible_hpm_cases,
            "eligible_bapc_cases": self._eligible_bapc_cases,
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
            "hpm_covered": hpm_cov,
            "hpm_target": hpm_target,
            "hpm_rate": hpm_cov / hpm_target if hpm_target > 0 else None,
            "bapc_covered": bapc_cov,
            "bapc_target": bapc_target,
            "bapc_rate": bapc_cov / bapc_target if bapc_target > 0 else None,
            "new_semantic_bins": kwargs.get("new_semantic", 0),
            "new_pairwise_bins": kwargs.get("new_pairwise", 0),
            "new_security_triple_bins": kwargs.get("new_triples", 0),
            "new_predicate_bins": kwargs.get("new_predicates", 0),
            "new_hpm_bins": kwargs.get("new_hpm", 0),
            "hpm_eligible": bool(kwargs.get("hpm_eligible", False)),
            "last_hpm_novelty_time": kwargs.get("hpm_snapshot", {}).get("last_hpm_novelty_time"),
            "new_bapc_bins": kwargs.get("new_bapc", 0),
            "bapc_eligible": bool(kwargs.get("bapc_eligible", False)),
            "last_bapc_novelty_time": kwargs.get("bapc_snapshot", {}).get("last_bapc_novelty_time"),
            "whitebox_distinct_events": len(self._whitebox_event_ids),
            "new_whitebox_events": kwargs.get("new_whitebox", 0),
            "security_events": kwargs.get("security_events") or [],
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
        semantic = semantic & self._target_semantic_bins
        pairwise = pairwise & self._target_pairwise_bins
        triples = triples & self._target_triples_bins
        predicates = predicates & self._target_predicates_bins
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

    def record_whitebox_event_count(self, new_count: int) -> int:
        start = len(self._whitebox_event_ids)
        for index in range(max(0, int(new_count))):
            self._whitebox_event_ids.add(f"schedule:{start + index}")
        return max(0, int(new_count))

    @property
    def whitebox_distinct_events(self) -> int:
        return len(self._whitebox_event_ids)

    def replay_execution_commit(self, record: dict[str, Any]) -> None:
        candidate_id = str(record.get("candidate_id") or "")
        if candidate_id:
            self.mark_executed(candidate_id)
        self._completion_seq += 1
        self._completed_cases += 1
        eligible = bool(record.get("eligible"))
        if eligible:
            self._eligible_cases += 1
        new_bins = record.get("new_bins") or {}
        if eligible:
            self._covered_semantic.update(str(item) for item in (new_bins.get("semantic") or []))
            self._covered_pairwise.update(str(item) for item in (new_bins.get("pairwise") or []))
            self._covered_triples.update(str(item) for item in (new_bins.get("security_triples") or []))
            self._covered_predicates.update(str(item) for item in (new_bins.get("predicates") or []))
            self._covered_hpm.update(str(item) for item in (new_bins.get("hpm") or []))
            self._covered_bapc.update(str(item) for item in (new_bins.get("bapc") or []))
        if bool(record.get("hpm_eligible")):
            self._eligible_hpm_cases += 1
        if bool(record.get("bapc_eligible")):
            self._eligible_bapc_cases += 1
        self.record_whitebox_event_count(int(record.get("new_whitebox_events") or 0))
        line = self._make_timeline_line(
            case_id=record.get("case_id"),
            profile=record.get("profile"),
            status=record.get("status"),
            failure_class=record.get("failure_class"),
            eligible=eligible,
            qualification_reason=record.get("qualification_reason"),
            elapsed_wall=float(record.get("elapsed_wall_seconds") or 0.0),
            case_elapsed=float(record.get("case_elapsed_seconds") or 0.0),
            new_semantic=len(new_bins.get("semantic") or []),
            new_pairwise=len(new_bins.get("pairwise") or []),
            new_triples=len(new_bins.get("security_triples") or []),
            new_predicates=len(new_bins.get("predicates") or []),
            new_hpm=len(new_bins.get("hpm") or []),
            hpm_eligible=bool(record.get("hpm_eligible")),
            hpm_snapshot={
                "last_hpm_novelty_time": record.get("last_hpm_novelty_time"),
            },
            new_bapc=len(new_bins.get("bapc") or []),
            bapc_eligible=bool(record.get("bapc_eligible")),
            bapc_snapshot={
                "last_bapc_novelty_time": record.get("last_bapc_novelty_time"),
            },
            new_whitebox=int(record.get("new_whitebox_events") or 0),
            security_events=record.get("security_events") or [],
        )
        self._timeline_lines.append(line)

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
            "eligible_hpm_cases": 0,
            "eligible_bapc_cases": 0,
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
            "hpm_covered": 0,
            "hpm_target": self._target_hpm,
            "hpm_rate": 0.0 if self._target_hpm > 0 else None,
            "bapc_covered": 0,
            "bapc_target": self._target_bapc,
            "bapc_rate": 0.0 if self._target_bapc > 0 else None,
            "new_semantic_bins": 0,
            "new_pairwise_bins": 0,
            "new_security_triple_bins": 0,
            "new_predicate_bins": 0,
            "new_hpm_bins": 0,
            "hpm_eligible": False,
            "last_hpm_novelty_time": 0.0,
            "new_bapc_bins": 0,
            "bapc_eligible": False,
            "last_bapc_novelty_time": 0.0,
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
    from pmpfuzz.scenario import ScenarioGenerator
    from pmpfuzz.scenario_codec import scenario_hash, scenario_to_spec
    from pmpfuzz.semantic_coverage import _target_candidates

    candidates: list[dict[str, Any]] = []
    raw = _target_candidates(
        target=target,
        include_experimental=include_experimental,
        seed=seed,
        capability=capability,
    )
    for c in raw:
        candidate_id = _make_candidate_id(c["profile"], c["index"], seed)
        generator = ScenarioGenerator(
            seed=seed,
            include_smepmp=str(c["profile"]).startswith("smepmp"),
            profile=str(c["profile"]),
        )
        scenario = generator.generate_one(int(c["index"]))
        spec = scenario_to_spec(scenario)
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
            "scenario_spec": spec,
            "scenario_hash": scenario_hash(spec),
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
    entry = {
        "candidate_id": candidate["candidate_id"],
        "profile": candidate["profile"],
        "index": candidate["scenario_index"],
        "name": candidate.get(
            "name", f"{candidate['profile']}__case_{candidate['scenario_index']}"
        ),
        "seed": seed,
        "include_smepmp": candidate["profile"].startswith("smepmp"),
        "generator_variant": str(candidate.get("generator_variant") or "full"),
        "generation_seed": int(candidate.get("generation_seed") or seed),
        "scenario_index": int(
            candidate.get("scenario_index")
            if candidate.get("scenario_index") is not None
            else candidate.get("index", 0)
        ),
        "continuous_sequence": candidate.get("continuous_sequence"),
        "mutation_operator": str(candidate.get("mutation_operator") or "root"),
        "selection_source": candidate.get("selection_source", "bootstrap"),
        "estimated_new_bins": int(candidate.get("estimated_new_bins", 0)),
    }
    if "scenario_spec" in candidate:
        entry["scenario_spec"] = candidate["scenario_spec"]
    if "scenario_hash" in candidate:
        entry["scenario_hash"] = candidate["scenario_hash"]
    return entry


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
            missing = _coverage_gap_semantic(run_dirs, dut, state.target_semantic_bins)
            bin_key = "semantic_bins"
        elif state.coverage_mode == "predicates":
            missing = _coverage_gap_predicates(run_dirs, dut, state.target_predicates_bins)
            bin_key = "predicate_bins"
        else:
            target_bins = (
                state.target_pairwise_bins
                if state.coverage_mode == "pairwise"
                else state.target_triples_bins
            )
            missing = _coverage_gap_combo(run_dirs, state.coverage_mode, dut, target_bins)
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


def _coverage_gap_semantic(
    run_dirs: list[Path],
    dut: str,
    target_bins: set[str] | frozenset[str] | None = None,
) -> set[str]:
    """P0-1 FIX: Compute missing semantic bins using real DUT name."""
    from pmpfuzz.semantic_coverage import semantic_bins_for_case, target_semantic_bins
    from pmpfuzz.coverage_qualification import collect_execution_evidence

    if target_bins is None:
        target_bins = set(target_semantic_bins(target="core-stateful"))
    observed: set[str] = set()
    for d in run_dirs:
        evidence = collect_execution_evidence([d], dut=dut)
        for case in evidence.eligible_cases:
            observed.update(semantic_bins_for_case(case))
    return set(target_bins) - observed


def _coverage_gap_predicates(
    run_dirs: list[Path],
    dut: str,
    target_bins: set[str] | frozenset[str] | None = None,
) -> set[str]:
    """P0-1 FIX: Compute missing predicate bins using real DUT name."""
    from pmpfuzz.semantic_coverage import contract_predicates_for_case, target_contract_predicates
    from pmpfuzz.coverage_qualification import collect_execution_evidence

    if target_bins is None:
        target_bins = set(target_contract_predicates(target="core-stateful"))
    observed: set[str] = set()
    for d in run_dirs:
        evidence = collect_execution_evidence([d], dut=dut)
        for case in evidence.eligible_cases:
            observed.update(contract_predicates_for_case(case))
    return set(target_bins) - observed


def _coverage_gap_combo(
    run_dirs: list[Path],
    mode: str,
    dut: str,
    target_bins: set[str] | frozenset[str] | None = None,
) -> set[str]:
    """P0-1 FIX: Compute missing combo bins using real DUT name."""
    from pmpfuzz.semantic_coverage import combo_bins_for_case, target_combo_bins
    from pmpfuzz.coverage_qualification import collect_execution_evidence

    if target_bins is None:
        target_bins = set(target_combo_bins(target="core-stateful", coverage_mode=mode))
    observed: set[str] = set()
    for d in run_dirs:
        evidence = collect_execution_evidence([d], dut=dut)
        for case in evidence.eligible_cases:
            observed.update(combo_bins_for_case(case, coverage_mode=mode))
    return set(target_bins) - observed


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------


def run_closed_loop(args: argparse.Namespace) -> int:
    """Execute a closed-loop campaign with single CampaignState (Phase B4)."""
    _resolve_requested_bapc_core_version(args)
    _apply_experiment_protocol_defaults(args)
    if args.variant in CONTINUOUS_VARIANTS:
        return run_continuous_closed_loop(args)
    _validate_fixed_pool_bapc_variant(args)

    artifact_root = Path(args.artifact_root).resolve()
    _prepare_artifact_root(args, artifact_root)
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
    from pmpfuzz.bapc import BAPC_SCHEMA_VERSION
    from pmpfuzz.coverage_universe import write_coverage_universes

    capability = capability_for_dut(args.dut)
    coverage_universes, bapc_core_version = _resolve_coverage_universes(args=args, capability=capability)
    universe_paths = write_coverage_universes(metrics_dir / "coverage_universe", coverage_universes)
    _write_experiment_contract_manifest(args, artifact_root, coverage_universes)
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
        coverage_universes=coverage_universes,
    )
    if args.coverage_mode == "bapc" and not state.target_bapc_bins:
        raise ValueError("BAPC coverage mode resolved to an empty target universe")

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
        "fault_family": str(getattr(args, "fault_family", "") or ""),
        "critical_family": bool(getattr(args, "critical_family", False)),
        "candidate_pool_size": len(pool),
        "coverage_universe_hashes": {
            mode: universe["sha256"] for mode, universe in coverage_universes.items()
        },
        "coverage_universe_files": {
            mode: str(path.relative_to(campaign_dir)) for mode, path in universe_paths.items()
        },
        "start_utc": start_utc,
        "hostname": os.uname().nodename if hasattr(os, "uname") else "unknown",
        "command_line": " ".join(sys.argv),
    }
    if args.coverage_mode == "bapc":
        meta.update(
            {
                "bapc_schema_version": BAPC_SCHEMA_VERSION,
                "bapc_core_version": str(bapc_core_version),
                "bapc_measurement_mode": "target-operation",
                "probe_required": False,
                "instrumented_supplemental_enabled": bool(getattr(args, "whitebox", False)),
                "bapc_target": int(coverage_universes["bapc"]["bin_count"]),
            }
        )
    meta.update(_continuous_provenance(args, coverage_universes))
    _validate_continuous_provenance(meta)
    max_completed_cases = getattr(args, "max_completed_cases", None)
    if max_completed_cases not in {None, ""}:
        meta["max_completed_cases"] = int(max_completed_cases)
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
    bootstrap_limit = None
    if max_completed_cases not in {None, ""}:
        bootstrap_limit = max(0, int(max_completed_cases) - state.completed_cases)
    bootstrap_candidates = _select_bootstrap_candidates(state, args, limit=bootstrap_limit)
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
        if max_completed_cases not in {None, ""} and state.completed_cases >= int(max_completed_cases):
            state.set_stop_reason("input_budget_exhausted")
            print(f"Completed-case budget exhausted after {state.completed_cases} cases")
            break
        elapsed = time.monotonic() - start_wall
        if elapsed >= args.time_budget:
            state.set_stop_reason(STOP_HARD_CAP_CENSORED)
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
        requested_round_size = int(args.round_size)
        if max_completed_cases not in {None, ""}:
            remaining_budget = int(max_completed_cases) - state.completed_cases
            requested_round_size = min(requested_round_size, max(0, remaining_budget))
        if requested_round_size <= 0:
            state.set_stop_reason("input_budget_exhausted")
            print(f"Completed-case budget exhausted after {state.completed_cases} cases")
            break
        candidates = select_next_candidates(state, requested_round_size, completed_round_dirs, args.seed)
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
    _finalize_artifact_root(args, artifact_root)
    return 0 if not state.any_round_failed else 1


def run_continuous_closed_loop(args: argparse.Namespace) -> int:
    """Execute a continuous closed-loop campaign with mutation/corpus state."""
    from pmpfuzz.capabilities import capability_for_dut
    from pmpfuzz.continuous import ScenarioStream
    from pmpfuzz.continuous_campaign import ContinuousQueueManager, candidate_record_from_dict
    from pmpfuzz.coverage_universe import (
        coverage_universe_filename,
        freeze_coverage_universes,
        load_coverage_universe,
        write_coverage_universes,
    )
    from pmpfuzz.bapc import (
        BAPC_SCHEMA_VERSION,
        load_bapc_coverage_universe,
    )
    from pmpfuzz.hpm import build_hpm_coverage_universe, manifest_for_dut
    from pmpfuzz.schedule_v4 import recover_schedule_v4, ScheduleV4Writer

    requested_bapc_core_version = _resolve_requested_bapc_core_version(args)
    artifact_root = Path(args.artifact_root).resolve()
    _prepare_artifact_root(args, artifact_root)
    campaign_dir = _campaign_output_dir(args, artifact_root)
    rounds_dir = campaign_dir / "rounds"
    metrics_dir = campaign_dir / "metrics"
    coverage_dir = metrics_dir / "coverage_universe"
    timeline_path = metrics_dir / "coverage_timeline.jsonl"
    schedule_v4_path = metrics_dir / "schedule_v4.jsonl"
    metadata_path = metrics_dir / "campaign_metadata.json"
    hpm_manifest_path = coverage_dir / "hpm_manifest_v1.json"
    bapc_universe_filename = coverage_universe_filename(
        "bapc",
        {"bapc_schema_version": BAPC_SCHEMA_VERSION, "bapc_core_version": requested_bapc_core_version},
    )

    if campaign_dir.exists() and not getattr(args, "resume", False):
        print(f"ERROR: campaign output directory already exists: {campaign_dir}", file=sys.stderr)
        return 1
    if getattr(args, "resume", False) and not campaign_dir.exists():
        print(f"ERROR: resume requested but campaign directory does not exist: {campaign_dir}", file=sys.stderr)
        return 1

    campaign_dir.mkdir(parents=True, exist_ok=True)
    rounds_dir.mkdir(exist_ok=True)
    metrics_dir.mkdir(exist_ok=True)

    start_utc = datetime.now(timezone.utc).isoformat()
    start_wall = time.monotonic()
    max_completed_cases = getattr(args, "max_completed_cases", None)
    capability = capability_for_dut(args.dut)
    continuous_profiles = _continuous_profiles_from_args(args)
    if getattr(args, "resume", False) and (coverage_dir / "semantic_v1.json").exists():
        coverage_universes = {
            "semantic": load_coverage_universe(coverage_dir / "semantic_v1.json"),
            "pairwise": load_coverage_universe(coverage_dir / "pairwise_v1.json"),
            "security_triples": load_coverage_universe(coverage_dir / "security_triples_v1.json"),
            "predicates": load_coverage_universe(coverage_dir / "predicates_v1.json"),
        }
        if args.coverage_mode == "hpm" and (coverage_dir / "hpm_v1.json").exists():
            coverage_universes["hpm"] = load_coverage_universe(coverage_dir / "hpm_v1.json")
        if args.coverage_mode == "bapc" and (coverage_dir / bapc_universe_filename).exists():
            coverage_universes["bapc"] = load_bapc_coverage_universe(
                coverage_dir / bapc_universe_filename,
                expected_bapc_core_version=requested_bapc_core_version,
            )
        universe_paths = {
            "semantic": coverage_dir / "semantic_v1.json",
            "pairwise": coverage_dir / "pairwise_v1.json",
            "security_triples": coverage_dir / "security_triples_v1.json",
            "predicates": coverage_dir / "predicates_v1.json",
            "contract": coverage_dir / "coverage_contract_v1.json",
        }
        if args.coverage_mode == "hpm" and hpm_manifest_path.exists():
            universe_paths["hpm"] = coverage_dir / "hpm_v1.json"
            universe_paths["hpm_manifest"] = hpm_manifest_path
        if args.coverage_mode == "bapc" and (coverage_dir / bapc_universe_filename).exists():
            universe_paths["bapc"] = coverage_dir / bapc_universe_filename
    else:
        coverage_universes, requested_bapc_core_version = _resolve_coverage_universes(
            args=args,
            capability=capability,
        )
        universe_paths = write_coverage_universes(coverage_dir, coverage_universes)
        if args.coverage_mode == "hpm":
            hpm_manifest_payload = manifest_for_dut(args.dut)
            hpm_manifest_path.write_text(
                json.dumps(hpm_manifest_payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
                encoding="ascii",
            )
            universe_paths["hpm_manifest"] = hpm_manifest_path
        _write_experiment_contract_manifest(args, artifact_root, coverage_universes)

    if args.coverage_mode == "hpm":
        setattr(args, "hpm_manifest", str(hpm_manifest_path))

    if metadata_path.exists() and getattr(args, "resume", False):
        meta = json.loads(metadata_path.read_text(encoding="ascii"))
        _validate_continuous_resume_args(
            args,
            meta,
            coverage_universes,
            campaign_dir,
            schedule_v4_path,
            universe_paths,
        )
        campaign_id = str(meta.get("campaign_id"))
        elapsed_wall_offset = float(meta.get("elapsed_wall_seconds") or 0.0)
    else:
        campaign_id = _expected_campaign_id(args)
        elapsed_wall_offset = 0.0
        meta = {
            "schema_version": "1.0",
            "experiment_id": args.experiment_id,
            "campaign_id": campaign_id,
            "variant": args.variant,
            "scheduler_variant": args.variant,
            "generator_variant": _generator_variant(args),
            "coverage_mode": args.coverage_mode,
            "dut": args.dut,
            "seed": args.seed,
            "round_size": args.round_size,
            "profile_distribution": _profile_distribution(continuous_profiles),
            "time_budget_seconds": args.time_budget,
            "per_case_timeout_seconds": args.per_case_timeout,
            "jobs": args.jobs,
            "driver_mode": "continuous",
            "fault_family": str(getattr(args, "fault_family", "") or ""),
            "critical_family": bool(getattr(args, "critical_family", False)),
            "schedule_v4": str(schedule_v4_path.relative_to(campaign_dir)),
            "pending_limit": args.pending_limit,
            "corpus_limit": args.corpus_limit,
            "low_watermark": args.low_watermark,
            "coverage_universe_hashes": {
                mode: universe["sha256"] for mode, universe in coverage_universes.items()
            },
            "coverage_universe_files": {
                mode: str(path.relative_to(campaign_dir)) for mode, path in universe_paths.items()
            },
            "start_utc": start_utc,
            "hostname": os.uname().nodename if hasattr(os, "uname") else "unknown",
            "command_line": " ".join(sys.argv),
        }
        if args.coverage_mode == "bapc":
            meta.update(
                {
                    "bapc_schema_version": BAPC_SCHEMA_VERSION,
                    "bapc_core_version": requested_bapc_core_version,
                    "bapc_measurement_mode": "target-operation",
                    "probe_required": False,
                    "instrumented_supplemental_enabled": bool(getattr(args, "whitebox", False)),
                    "bapc_target": int(coverage_universes["bapc"]["bin_count"]),
                }
            )
        meta.update(_continuous_provenance(args, coverage_universes))
        meta.update(_continuous_convergence_config(args))
        _validate_continuous_provenance(meta)

    state = CampaignState(
        campaign_id=campaign_id,
        variant=args.variant,
        dut=args.dut,
        seed=args.seed,
        coverage_mode=args.coverage_mode,
        candidate_pool=[],
        start_time=start_wall,
        coverage_universes=coverage_universes,
    )
    if args.coverage_mode == "bapc" and not state.target_bapc_bins:
        raise ValueError("BAPC coverage mode resolved to an empty target universe")
    state._elapsed_wall_offset = elapsed_wall_offset
    state.set_timeline_path(timeline_path)
    convergence_config = _continuous_convergence_config(args)
    state.configure_convergence(
        enabled=bool(convergence_config.get("convergence_enabled")),
        min_runtime_seconds=float(convergence_config.get("convergence_min_runtime_seconds") or 0.0),
        confirmation_seconds=float(convergence_config.get("convergence_confirmation_seconds") or 0.0),
        confirmation_eligible_cases=int(convergence_config.get("convergence_confirmation_eligible_cases") or 0),
        max_wall_time_seconds=convergence_config.get("max_wall_time_seconds"),
        tracked_modes=(
            (str(args.coverage_mode),)
            if str(args.coverage_mode) in PMPFUZZ_SINGLE_MODE_COVERAGE_MODES
            else CONVERGENCE_TRACKED_MODES
        ),
    )

    if schedule_v4_path.exists() and schedule_v4_path.stat().st_size > 0:
        recovered = recover_schedule_v4(schedule_v4_path)
        _restore_continuous_campaign_state(state, timeline_path, rounds_dir, recovered)
        recovered_stop_reason = getattr(recovered, "stop_reason", None)
        if recovered_stop_reason and str(recovered_stop_reason) not in RESUMABLE_CONTINUOUS_STOP_REASONS:
            state.set_stop_reason(recovered_stop_reason)
    else:
        recovered = None

    writer = ScheduleV4Writer(schedule_v4_path)
    stream = ScenarioStream(
        root_seed=args.seed,
        profiles=continuous_profiles,
        generator_variant=_generator_variant(args),
    )
    queue = ContinuousQueueManager(
        variant=args.variant,
        stream=stream,
        coverage_universes=coverage_universes,
        scheduler_seed=args.seed,
        pending_limit=args.pending_limit,
        corpus_limit=args.corpus_limit,
        coverage_mode=args.coverage_mode,
    )
    if recovered is not None:
        next_root_sequence = getattr(recovered, "next_root_sequence", 0)
        if next_root_sequence <= 0 and getattr(recovered, "seen_hashes", None):
            next_root_sequence = len(recovered.seen_hashes)
        queue.restore_runtime_state(
            seen_hashes=recovered.seen_hashes,
            coverage_state=recovered.coverage_state,
            next_generation_seq=getattr(recovered, "next_generation_seq", 0),
            next_mutation_attempt=getattr(recovered, "next_mutation_attempt", 0),
            next_root_sequence=next_root_sequence,
        )
        restored_pending = [
            candidate_record_from_dict(recovered.candidate_records[scenario_hash_value])
            for scenario_hash_value in recovered.pending_hashes
            if scenario_hash_value in recovered.candidate_records
        ]
        restored_corpus = [
            (
                candidate_record_from_dict(recovered.candidate_records[scenario_hash_value]),
                dict(recovered.candidate_discovered_bins.get(scenario_hash_value) or {}),
                float(recovered.candidate_execution_costs.get(scenario_hash_value) or 0.0),
                int(recovered.parent_selection_counts.get(scenario_hash_value, 0)),
                bool(recovered.candidate_retained_without_novelty.get(scenario_hash_value, False)),
            )
            for scenario_hash_value in recovered.active_corpus_hashes
            if scenario_hash_value in recovered.candidate_records
        ]
        queue.restore_records(
            pending_records=restored_pending,
            corpus_records=restored_corpus,
        )
        _rebuild_convergence_state_from_recovery(state, timeline_path, recovered)
        state.set_unique_scenario_count(len(recovered.seen_hashes))
        state.set_pending_count(len(recovered.pending_hashes))

    base_cmd, base_env = _build_base_cmd(args)
    max_rounds = getattr(args, "max_rounds", None)
    _current_convergence_snapshot(
        state,
        elapsed_wall_seconds=_current_elapsed_wall_seconds(state, start_wall),
        unique_scenario_count=state.unique_scenario_count,
        pending_count=state.pending_count,
    )
    if (
        recovered is not None
        and getattr(recovered, "closed", False)
        and str(getattr(recovered, "stop_reason", "") or "") not in RESUMABLE_CONTINUOUS_STOP_REASONS
    ):
        return 0 if not state.any_round_failed else 1
    if is_convergence_terminal_stop_reason(state.stop_reason):
        return _finish_continuous_campaign_after_stop(
            args=args,
            state=state,
            queue=queue,
            writer=writer,
            metadata_path=metadata_path,
            meta=meta,
            start_wall=start_wall,
            campaign_dir=campaign_dir,
            metrics_dir=metrics_dir,
            artifact_root=artifact_root,
            checkpoint_round_idx=max(state.round_idx - 1, 0),
            emit_stop_latched=not bool(getattr(recovered, "stop_latched", False)),
        )
    _write_continuous_metadata_checkpoint(metadata_path, meta, state, start_wall)

    while True:
        if max_completed_cases not in {None, ""} and state.completed_cases >= int(max_completed_cases):
            state.set_stop_reason("input_budget_exhausted")
            print(f"Completed-case budget exhausted after {state.completed_cases} cases")
            break
        elapsed = _current_elapsed_wall_seconds(state, start_wall)
        if not convergence_config and elapsed >= args.time_budget:
            state.set_stop_reason("time_budget_exhausted")
            print(f"Time budget exhausted after {state.round_idx} rounds")
            break
        if convergence_config and elapsed >= float(convergence_config.get("max_wall_time_seconds") or args.time_budget):
            state.set_stop_reason(STOP_HARD_CAP_CENSORED)
            print(f"Reached max wall time after {state.round_idx} rounds")
            break
        if max_rounds is not None and state.round_idx >= max_rounds:
            state.set_stop_reason("max_rounds_reached")
            print(f"Max rounds reached: {max_rounds}")
            break

        queue.fill_pending(args.low_watermark)
        state.set_unique_scenario_count(len(queue.seen_hashes))
        state.set_pending_count(len(queue.pending))
        for attempt in queue.consume_generation_attempts():
            record = attempt.record
            event = "candidate_admitted"
            if attempt.rejected_reason is not None:
                event = "candidate_rejected"
            elif attempt.duplicate:
                event = "candidate_duplicate"
            writer.append(
                event,
                scenario_hash=record.scenario_hash,
                scenario_spec=record.scenario_spec,
                profile=str(record.scenario_spec.get("profile") or ""),
                name=str(record.scenario_spec.get("name") or record.scenario_hash),
                parent_hash=record.parent_hash,
                mutation_operator=record.mutation_operator,
                mutation_seed=record.mutation_seed,
                generation_seed=record.generation_seed,
                scenario_index=record.scenario_index,
                generation_seq=record.generation_seq,
                mutation_depth=record.mutation_depth,
                generator_variant=record.generator_variant,
                root_sequence=record.root_sequence,
                rejection_reason=attempt.rejected_reason,
            )

        requested_round_size = min(int(args.round_size), len(queue.pending))
        if max_completed_cases not in {None, ""}:
            remaining_budget = int(max_completed_cases) - state.completed_cases
            requested_round_size = min(requested_round_size, max(0, remaining_budget))
        if requested_round_size <= 0:
            state.set_stop_reason("input_budget_exhausted")
            print(f"Completed-case budget exhausted after {state.completed_cases} cases")
            break

        batch = queue.pop_batch(requested_round_size)
        state.set_pending_count(len(queue.pending))
        if not batch:
            state.set_stop_reason("no_pending_candidates_available")
            print("No pending candidates available for continuous driver")
            break

        expected_candidates = [_continuous_candidate_dict(record, args.seed) for record in batch]
        state.set_unique_scenario_count(len(queue.seen_hashes))
        for candidate in expected_candidates:
            writer.append(
                "execution_started",
                scenario_hash=candidate["scenario_hash"],
                candidate_id=candidate["candidate_id"],
                round_idx=state.round_idx,
            )

        round_dir = rounds_dir / f"round_{state.round_idx:04d}"
        schedule_path = metrics_dir / f"schedule_round_{state.round_idx:04d}.json"
        schedule_data = {
            "schema_version": 1,
            "seed": args.seed,
            "selection_summary": {
                "continuous_variant": args.variant,
                "round_idx": state.round_idx,
                "final_selected_count": len(expected_candidates),
            },
            "entries": [_schedule_entry(candidate, args.seed) for candidate in expected_candidates],
        }
        schedule_path.write_text(json.dumps(schedule_data, indent=2, ensure_ascii=True), encoding="ascii")

        def _on_case_ingested(
            candidate,
            case,
            result,
            eligible,
            qualification_reason,
            elapsed_wall,
            discovered_bins,
            execution_cost,
            security_events,
            new_whitebox_events,
            hpm_eligible=False,
            bapc_eligible=False,
        ):
            completed_cases = state.completed_cases
            candidate_id = str(candidate.get("candidate_id") or candidate.get("scenario_hash") or "")
            already_executed = candidate_id in state.executed_ids
            if not already_executed:
                completed_cases += 1
            eligible_cases = state._projected_convergence_eligible_cases(
                executed=already_executed,
                eligible=bool(eligible),
                hpm_eligible=bool(hpm_eligible),
                bapc_eligible=bool(bapc_eligible),
            )
            summary = queue.prepare_execution(
                candidate["record"],
                eligible=eligible,
                observed_bins=discovered_bins,
                execution_cost=execution_cost,
            )
            state.note_convergence_execution(
                elapsed_wall_seconds=float(elapsed_wall),
                eligible=bool(eligible),
                hpm_eligible=bool(hpm_eligible),
                bapc_eligible=bool(bapc_eligible),
                new_bins=summary["discovered_bins"],
                unique_scenario_count=state.unique_scenario_count,
                completed_cases=completed_cases,
                eligible_cases=eligible_cases,
            )
            writer.append(
                "execution_committed",
                scenario_hash=candidate["scenario_hash"],
                candidate_id=candidate["candidate_id"],
                case_id=case.get("name"),
                profile=case.get("profile"),
                status=result.get("status"),
                failure_class=result.get("failure_class"),
                eligible=eligible,
                hpm_eligible=bool(hpm_eligible),
                bapc_eligible=bool(bapc_eligible),
                qualification_reason=qualification_reason,
                elapsed_wall_seconds=float(elapsed_wall),
                case_elapsed_seconds=float(execution_cost),
                execution_cost=execution_cost,
                new_bins=summary["discovered_bins"],
                promoted=summary["promoted"],
                evicted_hashes=summary["evicted_hashes"],
                retained_without_novelty=summary["retained_without_novelty"],
                security_events=security_events,
                new_whitebox_events=int(new_whitebox_events),
            )
            queue.commit_execution(candidate["record"], summary)
            return summary

        success = _run_round(
            base_cmd,
            round_dir,
            args,
            state,
            schedule_path=schedule_path,
            expected_candidates=expected_candidates,
            enable_whitebox=getattr(args, "whitebox", False),
            env=base_env,
            round_start_offset=state._elapsed_wall_offset + (time.monotonic() - start_wall),
            on_case_ingested=_on_case_ingested,
        )
        if not success:
            print(f"WARNING: continuous round {state.round_idx} had failures")
        elapsed_after_round = _current_elapsed_wall_seconds(state, start_wall)
        convergence_snapshot = _current_convergence_snapshot(
            state,
            elapsed_wall_seconds=elapsed_after_round,
            unique_scenario_count=state.unique_scenario_count,
            pending_count=state.pending_count,
        )
        convergence_snapshot.pop("suggested_stop_reason", None)
        state.advance_round()
        if is_convergence_terminal_stop_reason(state.stop_reason):
            if state.stop_reason == STOP_COVERAGE_CONVERGED:
                print(f"Coverage converged after {state.round_idx} rounds")
            else:
                print(f"Reached max wall time after {state.round_idx} rounds")
            return _finish_continuous_campaign_after_stop(
                args=args,
                state=state,
                queue=queue,
                writer=writer,
                metadata_path=metadata_path,
                meta=meta,
                start_wall=start_wall,
                campaign_dir=campaign_dir,
                metrics_dir=metrics_dir,
                artifact_root=artifact_root,
                checkpoint_round_idx=state.round_idx - 1,
                emit_stop_latched=True,
            )
        writer.append(
            "checkpoint",
            round_idx=state.round_idx - 1,
            pending_count=state.pending_count,
            corpus_count=len(queue.corpus_entries),
            completed_cases=state.completed_cases,
            eligible_cases=state.eligible_cases,
            **convergence_snapshot,
        )
        _write_continuous_metadata_checkpoint(metadata_path, meta, state, start_wall)
    final_snapshot = _current_convergence_snapshot(
        state,
        elapsed_wall_seconds=_current_elapsed_wall_seconds(state, start_wall),
        unique_scenario_count=state.unique_scenario_count,
        pending_count=state.pending_count,
    )
    final_snapshot.pop("suggested_stop_reason", None)
    writer.append(
        "campaign_closed",
        round_idx=state.round_idx,
        completed_cases=state.completed_cases,
        eligible_cases=state.eligible_cases,
        **final_snapshot,
    )
    _finalize(state, campaign_dir, metrics_dir, meta, start_wall)
    _finalize_artifact_root(args, artifact_root)
    return 0 if not state.any_round_failed else 1


def _continuous_candidate_dict(record: Any, seed: int) -> dict[str, Any]:
    from pmpfuzz.scenario_codec import scenario_from_spec
    from pmpfuzz.schema import scenario_to_case_dict

    scenario = scenario_from_spec(record.scenario_spec)
    scenario_index = record.scenario_index if record.scenario_index is not None else record.generation_seq
    case = scenario_to_case_dict(
        scenario,
        seed=seed,
        index=record.generation_seq,
        generator_variant=record.generator_variant,
        generation_seed=record.generation_seed,
        scenario_index=scenario_index,
        mutation_operator=record.mutation_operator,
        continuous_sequence=record.generation_seq,
    )
    return {
        "candidate_id": record.scenario_hash,
        "profile": case["profile"],
        "generator_variant": record.generator_variant,
        "generation_seed": record.generation_seed,
        "scenario_index": scenario_index,
        "continuous_sequence": record.generation_seq,
        "name": case["name"],
        "semantic_bins": list(case.get("semantic_bins") or []),
        "pairwise_bins": [item for item in case.get("combo_bins") or [] if str(item).startswith("combo2:")],
        "security_triple_bins": [item for item in case.get("combo_bins") or [] if str(item).startswith("combo3:")],
        "predicate_bins": list(case.get("contract_predicates") or []),
        "scenario_spec": record.scenario_spec,
        "scenario_hash": record.scenario_hash,
        "parent_hash": record.parent_hash,
        "mutation_operator": record.mutation_operator,
        "mutation_seed": record.mutation_seed,
        "generation_seq": record.generation_seq,
        "mutation_depth": record.mutation_depth,
        "record": record,
    }


def _restore_continuous_campaign_state(
    state: CampaignState,
    timeline_path: Path,
    rounds_dir: Path,
    recovered: Any,
) -> None:
    state._executed_ids = set()
    state._round_idx = max(
        int(getattr(recovered, "last_round_idx", 0)),
        len(sorted(rounds_dir.glob("round_*"))),
    )
    state._covered_semantic = set()
    state._covered_pairwise = set()
    state._covered_triples = set()
    state._covered_predicates = set()
    state._completion_seq = 0
    state._completed_cases = 0
    state._eligible_cases = 0
    state._timeline_lines = []
    state._whitebox_event_ids = set()
    execution_commits = list(getattr(recovered, "execution_commits", []) or [])
    if execution_commits:
        for record in execution_commits:
            state.replay_execution_commit(record)
        if state._timeline_lines:
            state._elapsed_wall_offset = max(
                state._elapsed_wall_offset,
                float(state._timeline_lines[-1].get("elapsed_wall_seconds") or 0.0),
            )
            state.write_timeline(timeline_path)
        return
    state._executed_ids = set(getattr(recovered, "completed_hashes", set()))
    state._covered_semantic = set(getattr(recovered, "coverage_state", {}).get("semantic", set()))
    state._covered_pairwise = set(getattr(recovered, "coverage_state", {}).get("pairwise", set()))
    state._covered_triples = set(getattr(recovered, "coverage_state", {}).get("security_triples", set()))
    state._covered_predicates = set(getattr(recovered, "coverage_state", {}).get("predicates", set()))
    state._completion_seq = int(getattr(recovered, "completed_cases", 0))
    state._completed_cases = int(getattr(recovered, "completed_cases", 0))
    state._eligible_cases = int(getattr(recovered, "eligible_cases", 0))
    if not timeline_path.exists() or timeline_path.stat().st_size == 0:
        return
    lines = [
        json.loads(line)
        for line in timeline_path.read_text(encoding="ascii").splitlines()
        if line.strip()
    ]
    state._timeline_lines = [line for line in lines if int(line.get("completion_seq") or 0) > 0]
    if not state._timeline_lines:
        return
    last = state._timeline_lines[-1]
    state._completion_seq = max(state._completion_seq, int(last.get("completion_seq") or 0))
    state._completed_cases = max(state._completed_cases, int(last.get("completed_cases") or 0))
    state._eligible_cases = max(state._eligible_cases, int(last.get("eligible_cases") or 0))
    state._elapsed_wall_offset = max(state._elapsed_wall_offset, float(last.get("elapsed_wall_seconds") or 0.0))
    whitebox_count = int(last.get("whitebox_distinct_events") or 0)
    state._whitebox_event_ids = {f"resume:{index}" for index in range(whitebox_count)}


def _rebuild_convergence_state_from_recovery(
    state: CampaignState,
    timeline_path: Path,
    recovered: Any,
) -> None:
    tracker = getattr(state, "_convergence", None)
    if tracker is None:
        return
    state.configure_convergence(
        enabled=bool(tracker.enabled),
        min_runtime_seconds=float(tracker.min_runtime_seconds),
        confirmation_seconds=float(tracker.confirmation_seconds),
        confirmation_eligible_cases=int(tracker.confirmation_eligible_cases),
        max_wall_time_seconds=tracker.max_wall_time_seconds,
        tracked_modes=tuple(tracker.tracked_modes),
    )
    execution_commits = list(getattr(recovered, "execution_commits", []) or [])
    if execution_commits:
        convergence_eligible_cases = 0
        for index, record in enumerate(execution_commits, start=1):
            completed_cases = int(record.get("_recovered_completed_cases") or index)
            unique_scenario_count = int(record.get("_recovered_unique_scenario_count") or 0)
            if unique_scenario_count <= 0:
                unique_scenario_count = completed_cases
            eligible = bool(record.get("eligible"))
            hpm_eligible = bool(record.get("hpm_eligible"))
            bapc_eligible = bool(record.get("bapc_eligible"))
            if state.coverage_mode == "bapc":
                convergence_eligible_cases += int(bapc_eligible)
            elif state.coverage_mode == "hpm":
                convergence_eligible_cases += int(hpm_eligible)
            else:
                recovered_eligible_cases = record.get("_recovered_eligible_cases")
                if recovered_eligible_cases is not None:
                    convergence_eligible_cases = int(recovered_eligible_cases or 0)
                else:
                    convergence_eligible_cases += int(eligible)
            state.note_convergence_execution(
                elapsed_wall_seconds=float(record.get("elapsed_wall_seconds") or 0.0),
                eligible=eligible,
                hpm_eligible=hpm_eligible,
                bapc_eligible=bapc_eligible,
                new_bins=record.get("new_bins") or {},
                unique_scenario_count=unique_scenario_count,
                completed_cases=completed_cases,
                eligible_cases=convergence_eligible_cases,
            )
        return
    if not timeline_path.exists() or timeline_path.stat().st_size == 0:
        return
    for line in state._timeline_lines:
        completion_seq = int(line.get("completion_seq") or 0)
        if completion_seq <= 0:
            continue
        eligible = bool(line.get("coverage_eligible"))
        hpm_eligible = bool(line.get("hpm_eligible"))
        bapc_eligible = bool(line.get("bapc_eligible"))
        if state.coverage_mode == "bapc":
            eligible_cases = int(line.get("eligible_bapc_cases") or 0)
        elif state.coverage_mode == "hpm":
            eligible_cases = int(line.get("eligible_hpm_cases") or 0)
        else:
            eligible_cases = int(line.get("eligible_cases") or 0)
        state.note_convergence_execution(
            elapsed_wall_seconds=float(line.get("elapsed_wall_seconds") or 0.0),
            eligible=eligible,
            hpm_eligible=hpm_eligible,
            bapc_eligible=bapc_eligible,
            new_bins={
                "semantic": [
                    f"timeline-semantic-{completion_seq}-{index}"
                    for index in range(int(line.get("new_semantic_bins") or 0))
                ],
                "pairwise": [
                    f"timeline-pairwise-{completion_seq}-{index}"
                    for index in range(int(line.get("new_pairwise_bins") or 0))
                ],
                "security_triples": [
                    f"timeline-triples-{completion_seq}-{index}"
                    for index in range(int(line.get("new_security_triple_bins") or 0))
                ],
                "predicates": [
                    f"timeline-predicates-{completion_seq}-{index}"
                    for index in range(int(line.get("new_predicate_bins") or 0))
                ],
                "hpm": [
                    f"timeline-hpm-{completion_seq}-{index}"
                    for index in range(int(line.get("new_hpm_bins") or 0))
                ],
                "bapc": [
                    f"timeline-bapc-{completion_seq}-{index}"
                    for index in range(int(line.get("new_bapc_bins") or 0))
                ],
            },
            unique_scenario_count=int(line.get("completed_cases") or completion_seq),
            completed_cases=int(line.get("completed_cases") or completion_seq),
            eligible_cases=eligible_cases,
        )


def _write_continuous_metadata_checkpoint(
    metadata_path: Path,
    meta: dict[str, Any],
    state: CampaignState,
    start_wall: float,
) -> None:
    snapshot = dict(meta)
    snapshot["completed_rounds"] = state.round_idx
    snapshot["completed_cases"] = state.completed_cases
    snapshot["eligible_cases"] = state.eligible_cases
    snapshot["any_round_failed"] = state.any_round_failed
    snapshot["elapsed_wall_seconds"] = _current_elapsed_wall_seconds(state, start_wall)
    snapshot.update(
        _current_convergence_snapshot(
            state,
            elapsed_wall_seconds=float(snapshot["elapsed_wall_seconds"]),
            unique_scenario_count=state.unique_scenario_count,
            pending_count=state.pending_count,
        )
    )
    snapshot.pop("suggested_stop_reason", None)
    _atomic_write_text(
        metadata_path,
        json.dumps(snapshot, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )


def _current_convergence_snapshot(
    state: CampaignState,
    *,
    elapsed_wall_seconds: float,
    unique_scenario_count: int,
    pending_count: int,
) -> dict[str, Any]:
    snapshot = state.convergence_snapshot(
        elapsed_wall_seconds=float(elapsed_wall_seconds),
        unique_scenario_count=int(unique_scenario_count),
        pending_count=int(pending_count),
    )
    suggested_stop_reason = snapshot.get("suggested_stop_reason")
    if suggested_stop_reason and state.stop_reason is None:
        state.set_stop_reason(suggested_stop_reason)
    if state.stop_reason is None and bool(snapshot.get("convergence_confirmed")):
        state.set_stop_reason(STOP_COVERAGE_CONVERGED)
    snapshot["stop_reason"] = state.stop_reason
    return snapshot


def _discard_pending_candidates(
    queue: Any,
    writer: Any,
    *,
    round_idx: int,
    discard_reason: str,
) -> list[Any]:
    discarded = list(getattr(queue, "pending", []))
    if not discarded:
        return []
    for record in discarded:
        writer.append(
            "candidate_discarded",
            scenario_hash=record.scenario_hash,
            discard_reason=discard_reason,
            round_idx=int(round_idx),
        )
    queue.pending = []
    return discarded


def _finish_continuous_campaign_after_stop(
    *,
    args: argparse.Namespace,
    state: CampaignState,
    queue: Any,
    writer: Any,
    metadata_path: Path,
    meta: dict[str, Any],
    start_wall: float,
    campaign_dir: Path,
    metrics_dir: Path,
    artifact_root: Path,
    checkpoint_round_idx: int,
    emit_stop_latched: bool,
) -> int:
    stop_snapshot = _current_convergence_snapshot(
        state,
        elapsed_wall_seconds=_current_elapsed_wall_seconds(state, start_wall),
        unique_scenario_count=state.unique_scenario_count,
        pending_count=state.pending_count,
    )
    stop_snapshot.pop("suggested_stop_reason", None)
    discarded = []
    if emit_stop_latched:
        writer.append(
            "stop_latched",
            round_idx=int(checkpoint_round_idx),
            pending_count=state.pending_count,
            corpus_count=len(queue.corpus_entries),
            completed_cases=state.completed_cases,
            eligible_cases=state.eligible_cases,
            discarded_pending_count=len(getattr(queue, "pending", [])),
            **stop_snapshot,
        )
    if state.stop_reason == STOP_COVERAGE_CONVERGED:
        discarded = _discard_pending_candidates(
            queue,
            writer,
            round_idx=checkpoint_round_idx,
            discard_reason="discarded_due_to_convergence",
        )
    state.set_pending_count(len(queue.pending))
    checkpoint_snapshot = _current_convergence_snapshot(
        state,
        elapsed_wall_seconds=_current_elapsed_wall_seconds(state, start_wall),
        unique_scenario_count=state.unique_scenario_count,
        pending_count=state.pending_count,
    )
    checkpoint_snapshot.pop("suggested_stop_reason", None)
    writer.append(
        "checkpoint",
        round_idx=int(checkpoint_round_idx),
        pending_count=state.pending_count,
        corpus_count=len(queue.corpus_entries),
        completed_cases=state.completed_cases,
        eligible_cases=state.eligible_cases,
        **checkpoint_snapshot,
    )
    _write_continuous_metadata_checkpoint(metadata_path, meta, state, start_wall)
    final_snapshot = _current_convergence_snapshot(
        state,
        elapsed_wall_seconds=_current_elapsed_wall_seconds(state, start_wall),
        unique_scenario_count=state.unique_scenario_count,
        pending_count=state.pending_count,
    )
    final_snapshot.pop("suggested_stop_reason", None)
    writer.append(
        "campaign_closed",
        round_idx=state.round_idx,
        completed_cases=state.completed_cases,
        eligible_cases=state.eligible_cases,
        **final_snapshot,
    )
    _finalize(state, campaign_dir, metrics_dir, meta, start_wall)
    _finalize_artifact_root(args, artifact_root)
    return 0 if not state.any_round_failed else 1


def _validate_continuous_resume_args(
    args: argparse.Namespace,
    meta: dict[str, Any],
    coverage_universes: dict[str, dict[str, Any]],
    campaign_dir: Path,
    schedule_v4_path: Path,
    universe_paths: dict[str, Path],
) -> None:
    expected = {
        "experiment_id": args.experiment_id,
        "campaign_id": _expected_campaign_id(args),
        "variant": args.variant,
        "scheduler_variant": args.variant,
        "generator_variant": _generator_variant(args),
        "coverage_mode": args.coverage_mode,
        "dut": args.dut,
        "seed": args.seed,
        "round_size": args.round_size,
        "profile_distribution": _profile_distribution(_continuous_profiles_from_args(args)),
        "time_budget_seconds": args.time_budget,
        "per_case_timeout_seconds": args.per_case_timeout,
        "jobs": args.jobs,
        "pending_limit": args.pending_limit,
        "corpus_limit": args.corpus_limit,
        "low_watermark": args.low_watermark,
        "driver_mode": "continuous",
        "schedule_v4": str(schedule_v4_path.relative_to(campaign_dir)),
        "coverage_universe_hashes": {
            mode: universe["sha256"] for mode, universe in coverage_universes.items()
        },
        "coverage_universe_files": {
            mode: str(path.relative_to(campaign_dir)) for mode, path in universe_paths.items()
        },
    }
    expected.update(_continuous_provenance(args, coverage_universes))
    expected.update(_continuous_convergence_config(args))
    _validate_continuous_provenance(meta)
    mismatches = [
        f"{key}: expected {value!r}, got {meta.get(key)!r}"
        for key, value in expected.items()
        if meta.get(key) != value
    ]
    if mismatches:
        raise ValueError("resume configuration mismatch: " + "; ".join(mismatches))


def _select_bootstrap_candidates(
    state: CampaignState,
    args: argparse.Namespace,
    *,
    limit: int | None = None,
) -> list[dict]:
    """Fix 3: Select bootstrap cases from the candidate pool."""
    unexec = state.unexecuted_candidates()
    bootstrap_size = int(args.bootstrap_size)
    if limit is not None:
        bootstrap_size = min(bootstrap_size, max(0, int(limit)))
    # Bootstrap uses the first N unexecuted from the pool (in pool order)
    return unexec[:bootstrap_size]


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
    on_case_ingested: Any | None = None,
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
                                            round_start_offset=round_start_offset,
                                            on_case_ingested=on_case_ingested)
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
    on_case_ingested: Any | None = None,
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
    candidate_by_name: dict[str, dict[str, Any]] = {c.get("name", ""): c for c in expected_candidates}

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

    validated_records: list[dict[str, Any]] = []

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

        candidate = candidate_by_name.get(case_name)
        if candidate is None:
            integrity_errors.append(f"timeline case {case_name} has no scheduled candidate_id")
            continue

        expected_hash = candidate.get("scenario_hash")
        actual_hash = case.get("scenario_hash")
        if expected_hash is not None:
            if actual_hash is None:
                integrity_errors.append(f"case {case_name} is missing scenario_hash")
                continue
            if str(actual_hash) != str(expected_hash):
                integrity_errors.append(
                    f"case {case_name} scenario_hash mismatch: expected {expected_hash}, got {actual_hash}"
                )
                continue

        result = result_list[0]
        qual = qualify_result_for_coverage(case, result)
        status = result.get("status", "unknown")

        # P0-2: Global wall time = round offset + round-relative completion time
        case_elapsed = result.get("elapsed_seconds", 0)
        completion_monotonic = tl_entry.get("completion_monotonic_seconds")
        if completion_monotonic is not None:
            elapsed_wall = state._elapsed_wall_offset + (float(completion_monotonic) - state.start_time)
        else:
            round_wall = tl_entry.get("elapsed_wall_seconds", 0) or 0
            elapsed_wall = round_start_offset + float(round_wall)

        # Compute coverage contribution
        case_sem = set(semantic_bins_for_case(case)) & state.target_semantic_bins
        case_pair = {b for b in combo_bins_for_case(case) if b.startswith("combo2:")} & state.target_pairwise_bins
        case_trip = {b for b in combo_bins_for_case(case) if b.startswith("combo3:")} & state.target_triples_bins
        case_pred = set(contract_predicates_for_case(case)) & state.target_predicates_bins
        hpm_payload = result.get("hpm_coverage") or {}
        hpm_eligible = bool(qual.eligible and hpm_payload.get("eligible"))
        case_hpm = (
            {str(item) for item in (hpm_payload.get("observed_bins") or [])} & state.target_hpm_bins
            if hpm_eligible
            else set()
        )
        bapc_payload = result.get("bapc_coverage") or {}
        bapc_eligible = bool(qual.eligible and bapc_payload.get("eligible"))
        case_bapc, bapc_errors = _validate_bapc_payload_contract(
            state=state,
            case_name=str(case_name),
            payload=bapc_payload,
            eligible=bapc_eligible,
        )
        integrity_errors.extend(bapc_errors)
        candidate_id = cand_by_name.get(case_name)
        if candidate_id is None:
            integrity_errors.append(f"timeline case {case_name} has no scheduled candidate_id")
            continue
        validated_records.append(
            {
                "candidate": candidate,
                "candidate_id": candidate_id,
                "case_name": case_name,
                "case": case,
                "result": result,
                "eligible": qual.eligible,
                "qualification_reason": qual.reason,
                "status": status,
                "elapsed_wall": elapsed_wall,
                "case_elapsed": case_elapsed,
                "case_sem": case_sem,
                "case_pair": case_pair,
                "case_trip": case_trip,
                "case_pred": case_pred,
                "case_hpm": case_hpm,
                "hpm_eligible": hpm_eligible,
                "hpm_snapshot": {
                    "last_hpm_novelty_time": None,
                    "before": result.get("hpm_snapshot_before"),
                    "after": result.get("hpm_snapshot_after"),
                    "coverage": hpm_payload,
                },
                "case_bapc": case_bapc,
                "bapc_eligible": bapc_eligible,
                "bapc_snapshot": {
                    "last_bapc_novelty_time": None,
                    "coverage": bapc_payload,
                },
            }
        )

    if missing:
        print(f"  WARNING: {len(missing)} expected cases missing results")

    for error in integrity_errors:
        print(f"  WARNING: {error}")

    if missing or integrity_errors:
        return False

    for item in validated_records:
        wb_ids: set[str] = set()
        security_events: list[dict[str, Any]] = []
        if enable_whitebox and item["eligible"] and str(item["result"].get("dut") or "") == state.dut:
            try:
                from pmpfuzz.whitebox import extract_whitebox_signals_for_result

                signals = extract_whitebox_signals_for_result(item["case"], item["result"], round_dir)
                security_events = _security_events_from_whitebox_signals(signals)
                wb_ids = {str(event.get("event_id") or "") for event in security_events if event.get("event_id")}
            except Exception as e:
                print(f"  WARNING: whitebox extraction failed for {item['case_name']}: {e}")

        if on_case_ingested is not None:
            on_case_ingested(
                item["candidate"],
                item["case"],
                item["result"],
                item["eligible"],
                item["qualification_reason"],
                item["elapsed_wall"],
                {
                    "semantic": sorted(item["case_sem"]),
                    "pairwise": sorted(item["case_pair"]),
                    "security_triples": sorted(item["case_trip"]),
                    "predicates": sorted(item["case_pred"]),
                    "hpm": sorted(item["case_hpm"]),
                    "bapc": sorted(item["case_bapc"]),
                },
                float(item["case_elapsed"]),
                security_events,
                len(wb_ids - state._whitebox_event_ids),
                item["hpm_eligible"],
                item["bapc_eligible"],
            )
        new_hpm = 0
        if item["hpm_eligible"]:
            new_hpm = len(item["case_hpm"] - state._covered_hpm)
        new_bapc = 0
        if item["bapc_eligible"]:
            new_bapc = len(item["case_bapc"] - state._covered_bapc)
        convergence_last_hpm = None
        if item["hpm_eligible"]:
            convergence_last_hpm = (
                state.convergence_mode_snapshot()
                .get("hpm", {})
                .get("elapsed_wall_seconds")
            )
        convergence_last_bapc = None
        if item["bapc_eligible"]:
            convergence_last_bapc = (
                state.convergence_mode_snapshot()
                .get("bapc", {})
                .get("elapsed_wall_seconds")
            )
        ns, np, nt, npr = state.update_coverage_sets(
            item["case_sem"],
            item["case_pair"],
            item["case_trip"],
            item["case_pred"],
            eligible=item["eligible"],
        )
        new_wb = state.record_whitebox_events(wb_ids)
        state.record_case(
            candidate_id=item["candidate_id"],
            case_id=item["case_name"],
            profile=item["case"].get("profile", ""),
            status=item["status"],
            failure_class=item["result"].get("failure_class"),
            eligible=item["eligible"],
            qualification_reason=item["qualification_reason"],
            elapsed_wall=item["elapsed_wall"],
            case_elapsed=item["case_elapsed"],
            new_semantic=ns,
            new_pairwise=np,
            new_triples=nt,
            new_predicates=npr,
            new_whitebox=new_wb,
            new_hpm=new_hpm,
            hpm_eligible=item["hpm_eligible"],
            case_hpm=item["case_hpm"],
            hpm_snapshot={
                **item["hpm_snapshot"],
                "last_hpm_novelty_time": convergence_last_hpm,
            },
            new_bapc=new_bapc,
            bapc_eligible=item["bapc_eligible"],
            case_bapc=item["case_bapc"],
            bapc_snapshot={
                **item["bapc_snapshot"],
                "last_bapc_novelty_time": convergence_last_bapc,
            },
            case_semantic=item["case_sem"],
            case_pairwise=item["case_pair"],
            case_triples=item["case_trip"],
            case_predicates=item["case_pred"],
            security_events=security_events,
        )

    return True


def _finalize(
    state: CampaignState,
    campaign_dir: Path,
    metrics_dir: Path,
    meta: dict,
    start_wall: float,
) -> None:
    """Write final campaign outputs."""
    end_utc = datetime.now(timezone.utc).isoformat()
    elapsed_wall_seconds = _current_elapsed_wall_seconds(state, start_wall)
    meta["end_utc"] = end_utc
    meta["completed_rounds"] = state.round_idx
    meta["completed_cases"] = state.completed_cases
    meta["eligible_cases"] = state.eligible_cases
    meta["eligible_hpm_cases"] = state._eligible_hpm_cases
    meta["eligible_bapc_cases"] = state._eligible_bapc_cases
    meta["any_round_failed"] = state.any_round_failed
    meta["elapsed_wall_seconds"] = elapsed_wall_seconds
    meta["stop_reason"] = state.stop_reason
    meta.update(
        state.convergence_snapshot(
            elapsed_wall_seconds=float(elapsed_wall_seconds),
            unique_scenario_count=state.unique_scenario_count,
            pending_count=state.pending_count,
        )
    )
    meta.pop("suggested_stop_reason", None)
    _atomic_write_text(
        metrics_dir / "campaign_metadata.json",
        json.dumps(meta, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )

    # Write campaign-level timeline
    tl_path = metrics_dir / "coverage_timeline.jsonl"
    state.write_timeline(tl_path)

    _write_security_event_timeseries(metrics_dir, state, meta)

    # Write executed_candidates.jsonl
    exec_path = metrics_dir / "executed_candidates.jsonl"
    with exec_path.open("w", encoding="ascii") as fh:
        for cid in sorted(state.executed_ids):
            fh.write(json.dumps({"candidate_id": cid}, ensure_ascii=True) + "\n")

    _write_campaign_coverage(campaign_dir, state)

    _write_commands_log(metrics_dir)

    print(f"\nCampaign complete: {campaign_dir}")
    print(f"  Rounds: {state.round_idx}")
    print(f"  Total cases: {state.completed_cases}")
    print(f"  Eligible cases: {state.eligible_cases}")
    print(f"  Wall time: {elapsed_wall_seconds:.0f}s")
    print(f"  Any round failed: {state.any_round_failed}")
    print(f"  Stop reason: {state.stop_reason}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_campaign_coverage(campaign_dir: Path, state: CampaignState) -> None:
    coverage_dir = campaign_dir / "coverage"
    coverage_dir.mkdir(parents=True, exist_ok=True)
    total_cases = len(list((campaign_dir / "rounds").glob("round_*/cases/*/case.json")))
    total_results = len(list((campaign_dir / "rounds").glob("round_*/results/*/result.json")))
    semantic_covered = len(state._covered_semantic)
    pairwise_covered = len(state._covered_pairwise)
    triples_covered = len(state._covered_triples)
    predicates_covered = len(state._covered_predicates)
    hpm_covered = len(state._covered_hpm)
    bapc_covered = len(state._covered_bapc)
    coverage = {
        "schema_version": 6,
        "run_dir": str(campaign_dir),
        "driver_mode": "campaign",
        "total_cases": total_cases,
        "total_results": total_results,
        "target": state.coverage_target,
        "target_bins": state._target_semantic,
        "covered_target_bins": semantic_covered,
        "coverage_rate": semantic_covered / state._target_semantic if state._target_semantic else 1.0,
        "target_combo_bins": state._target_pairwise,
        "covered_target_combo_bins": pairwise_covered,
        "combo_coverage_rate": pairwise_covered / state._target_pairwise if state._target_pairwise else 1.0,
        "target_triples": state._target_triples,
        "covered_target_triples": triples_covered,
        "triples_coverage_rate": triples_covered / state._target_triples if state._target_triples else 1.0,
        "target_predicates": state._target_predicates,
        "covered_target_predicates": predicates_covered,
        "predicate_coverage_rate": predicates_covered / state._target_predicates if state._target_predicates else 1.0,
        "target_hpm_bins": state._target_hpm,
        "covered_target_hpm_bins": hpm_covered,
        "hpm_coverage_rate": hpm_covered / state._target_hpm if state._target_hpm else 1.0,
        "target_bapc_bins": state._target_bapc,
        "covered_target_bapc_bins": bapc_covered,
        "bapc_coverage_rate": bapc_covered / state._target_bapc if state._target_bapc else 1.0,
        "semantic_bins": sorted(state._covered_semantic),
        "pairwise_bins": sorted(state._covered_pairwise),
        "security_triples_bins": sorted(state._covered_triples),
        "predicate_bins": sorted(state._covered_predicates),
        "hpm_bins": sorted(state._covered_hpm),
        "bapc_bins": sorted(state._covered_bapc),
        "coverage_universe_hashes": dict(state.coverage_universe_hashes),
        "execution_coverage": {
            "by_dut": {
                state.dut: {
                    "semantic": {
                        "covered_target_bins": semantic_covered,
                        "total_target_bins": state._target_semantic,
                        "covered_bins": sorted(state._covered_semantic),
                        "target": state.coverage_target,
                        "universe_sha256": state.coverage_universe_hashes.get("semantic"),
                    },
                    "pairwise": {
                        "covered_target_bins": pairwise_covered,
                        "total_target_bins": state._target_pairwise,
                        "covered_bins": sorted(state._covered_pairwise),
                        "target": state.coverage_target,
                        "universe_sha256": state.coverage_universe_hashes.get("pairwise"),
                    },
                    "security_triples": {
                        "covered_target_bins": triples_covered,
                        "total_target_bins": state._target_triples,
                        "covered_bins": sorted(state._covered_triples),
                        "target": state.coverage_target,
                        "universe_sha256": state.coverage_universe_hashes.get("security_triples"),
                    },
                    "predicates": {
                        "covered_target_bins": predicates_covered,
                        "total_target_bins": state._target_predicates,
                        "covered_bins": sorted(state._covered_predicates),
                        "target": state.coverage_target,
                        "universe_sha256": state.coverage_universe_hashes.get("predicates"),
                    },
                    "hpm": {
                        "covered_target_bins": hpm_covered,
                        "total_target_bins": state._target_hpm,
                        "covered_bins": sorted(state._covered_hpm),
                        "target": "pmp-relevant-hpm",
                        "universe_sha256": state.coverage_universe_hashes.get("hpm"),
                    },
                    "bapc": {
                        "covered_target_bins": bapc_covered,
                        "total_target_bins": state._target_bapc,
                        "covered_bins": sorted(state._covered_bapc),
                        "target": "black-box-architectural-pmp-target-operation",
                        "universe_sha256": state.coverage_universe_hashes.get("bapc"),
                    },
                }
            }
        },
    }
    (coverage_dir / "coverage.json").write_text(
        json.dumps(coverage, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )


def _build_base_cmd(args: argparse.Namespace) -> tuple[list[str], dict]:
    """Return (command_list, env_dict) with PYTHONPATH set."""
    env = os.environ.copy()
    project_root = str(Path(__file__).resolve().parents[3])
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{project_root}:{existing}" if existing else project_root

    cmd = [
        sys.executable, "-m", "pmpfuzz", "run",
        "--dut", args.dut,
        "--time-budget", _format_budget(args.round_size * args.per_case_timeout * 2),
        "--per-case-timeout", str(args.per_case_timeout),
        "--jobs", str(args.jobs),
        "--generator-variant", _generator_variant(args),
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
    if getattr(args, "hpm_manifest", None):
        cmd.extend(["--hpm-manifest", str(args.hpm_manifest)])
    if getattr(args, "bapc_core_version", None):
        cmd.extend(["--bapc-core-version", str(args.bapc_core_version)])
    return cmd, env


def _validate_fixed_pool_bapc_variant(args: argparse.Namespace) -> None:
    if str(getattr(args, "coverage_mode", "") or "") != "bapc":
        return
    if str(getattr(args, "variant", "") or "") not in {"guided", "bb", "bb-wb"}:
        return
    raise ValueError(
        f"variant {args.variant!r} does not support fixed-pool BAPC guidance; "
        "use variant 'random' or a continuous BAPC workflow"
    )


def _validate_bapc_payload_contract(
    *,
    state: CampaignState,
    case_name: str,
    payload: dict[str, Any],
    eligible: bool,
) -> tuple[set[str], list[str]]:
    from pmpfuzz.bapc import BAPC_SCHEMA_VERSION

    if str(getattr(state, "coverage_mode", "") or "") != "bapc":
        return set(), []
    if not isinstance(payload, dict) or not payload:
        return set(), [f"case {case_name} missing BAPC payload"]
    raw_schema_version = payload.get("bapc_schema_version")
    try:
        actual_schema_version = int(raw_schema_version)
    except (TypeError, ValueError):
        actual_schema_version = None
    if actual_schema_version != BAPC_SCHEMA_VERSION:
        return set(), [
            "case "
            f"{case_name} BAPC schema version mismatch: expected {BAPC_SCHEMA_VERSION}, "
            f"got {raw_schema_version if raw_schema_version is not None else 'missing'}"
        ]
    expected_version = getattr(state, "bapc_core_version", None)
    actual_version = str(payload.get("bapc_core_version") or "").strip().lower()
    if expected_version is not None and actual_version != expected_version:
        return set(), [
            f"case {case_name} BAPC core version mismatch: expected {expected_version}, got {actual_version or 'missing'}"
        ]
    if not eligible:
        return set(), []
    observed = {str(item) for item in (payload.get("observed_bins") or [])}
    unexpected = sorted(observed - state.target_bapc_bins)
    if unexpected:
        return set(), [
            f"case {case_name} reported {len(unexpected)} out-of-contract BAPC bins"
        ]
    return observed, []


def _campaign_output_dir(args: argparse.Namespace, artifact_root: Path) -> Path:
    override = getattr(args, "campaign_dir", None)
    if override not in {None, ""}:
        return Path(override).resolve()
    return (
        artifact_root / "campaigns" / args.experiment_id / args.dut /
        _variant_path_segment(args) / args.coverage_mode / f"seed-{args.seed:04d}"
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


def _resolve_requested_bapc_core_version(args: argparse.Namespace) -> str | None:
    from pmpfuzz.bapc import normalize_bapc_core_version

    raw_value = getattr(args, "bapc_core_version", None)
    if str(getattr(args, "coverage_mode", "") or "") != "bapc":
        if raw_value in {None, ""}:
            return None
        return normalize_bapc_core_version(raw_value)
    if raw_value in {None, ""}:
        raise ValueError("coverage mode 'bapc' requires explicit --bapc-core-version {v2,v3,v4}")
    return normalize_bapc_core_version(raw_value)


def _resolve_coverage_universes(
    *,
    args: argparse.Namespace,
    capability: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], str | None]:
    from pmpfuzz.bapc import build_bapc_coverage_universe
    from pmpfuzz.coverage_universe import freeze_coverage_universes
    from pmpfuzz.hpm import build_hpm_coverage_universe

    coverage_universes = freeze_coverage_universes(
        target="core-stateful",
        capability=capability,
        include_experimental=False,
        seed=args.seed,
    )
    bapc_core_version = _resolve_requested_bapc_core_version(args)
    if args.coverage_mode == "hpm":
        coverage_universes["hpm"] = build_hpm_coverage_universe(dut=args.dut, generator_seed=args.seed)
    if args.coverage_mode == "bapc":
        supported = capability.get("supported_capabilities") or {}
        coverage_universes["bapc"] = build_bapc_coverage_universe(
            dut=args.dut,
            generator_seed=args.seed,
            supports_fault_stage=bool(supported.get("sv39", False)),
            supports_smepmp=bool(supported.get("smepmp", False)),
            bapc_core_version=str(bapc_core_version),
        )
    return coverage_universes, bapc_core_version


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Closed-loop fuzzing campaign driver")
    parser.set_defaults(
        **{
            _provided_flag_name("time_budget"): False,
            _provided_flag_name("budget_class"): False,
            _provided_flag_name("convergence_min_runtime_seconds"): False,
            _provided_flag_name("convergence_confirmation_seconds"): False,
            _provided_flag_name("convergence_confirmation_eligible_cases"): False,
            _provided_flag_name("max_wall_time_seconds"): False,
        }
    )
    parser.add_argument("--experiment-id", default="eval-v1")
    parser.add_argument("--variant", choices=sorted(ALL_VARIANTS), default="guided")
    parser.add_argument("--generator-variant", choices=["full", "syntax"], default="full")
    parser.add_argument(
        "--coverage-mode",
        choices=["semantic", "pairwise", "security-triples", "predicates", "hpm", "bapc"],
        default="semantic",
    )
    parser.add_argument("--bapc-core-version", choices=["v2", "v3", "v4"], default=None)
    parser.add_argument("--dut", default="spike")
    parser.add_argument("--profile", default="pmp-boundary")
    parser.add_argument("--bootstrap-profile", default=None)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--round-size", type=int, default=32)
    parser.add_argument("--bootstrap-size", type=int, default=32)
    parser.add_argument("--time-budget", action=_StoreValueWithProvidedFlag, type=int, default=3600)
    parser.add_argument("--per-case-timeout", type=int, default=10)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--experiment-protocol-id", default="")
    parser.add_argument("--run-class", choices=sorted(KNOWN_RUN_CLASSES), default="pilot")
    parser.add_argument("--budget-class", action=_StoreValueWithProvidedFlag, default="primary-wall-clock")
    parser.add_argument("--source-sha", default=None)
    parser.add_argument("--dut-sha", default=None)
    parser.add_argument("--dut-binary-sha256", default=None)
    parser.add_argument("--capability-fingerprint", default=None)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--campaign-dir", type=Path, default=None)
    parser.add_argument("--campaign-id", default=None)
    parser.add_argument("--spike", default=None)
    parser.add_argument("--isa", default=None)
    parser.add_argument("--chipyard-dir", default=None)
    parser.add_argument("--dut-bin", default=None)
    parser.add_argument("--no-smepmp", action="store_true")
    parser.add_argument("--whitebox", action="store_true", dest="whitebox")
    parser.add_argument("--max-rounds", type=int, default=None,
                        help="Maximum number of rounds (for testing/smoke only)")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--max-completed-cases", type=int, default=None)
    parser.add_argument("--pending-limit", type=int, default=1000)
    parser.add_argument("--corpus-limit", type=int, default=10000)
    parser.add_argument("--low-watermark", type=int, default=32)
    parser.add_argument("--fault-family", default="")
    parser.add_argument("--critical-family", action="store_true")
    parser.add_argument("--skip-artifact-root-prep", action="store_true")
    parser.add_argument("--skip-artifact-root-finalize", action="store_true")
    parser.add_argument("--convergence-stop", action="store_true")
    parser.add_argument(
        "--convergence-min-runtime-seconds",
        action=_StoreValueWithProvidedFlag,
        type=int,
        default=3600,
    )
    parser.add_argument(
        "--convergence-confirmation-seconds",
        action=_StoreValueWithProvidedFlag,
        type=int,
        default=1800,
    )
    parser.add_argument(
        "--convergence-confirmation-eligible-cases",
        action=_StoreValueWithProvidedFlag,
        type=int,
        default=2000,
    )
    parser.add_argument(
        "--max-wall-time-seconds",
        action=_StoreValueWithProvidedFlag,
        type=int,
        default=None,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    return run_closed_loop(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
