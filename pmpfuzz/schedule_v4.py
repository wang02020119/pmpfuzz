from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .scenario_codec import scenario_hash
from .stop_reasons import normalize_stop_reason


SCHEMA_VERSION = 4
TRACKED_COVERAGE_MODES = ("semantic", "pairwise", "security_triples", "predicates", "hpm", "bapc")
VALID_EVENTS = frozenset(
    {
        "candidate_admitted",
        "candidate_generated",
        "candidate_duplicate",
        "candidate_rejected",
        "candidate_discarded",
        "candidate_queued",
        "execution_started",
        "execution_committed",
        "execution_completed",
        "coverage_recorded",
        "corpus_promoted",
        "corpus_evicted",
        "stop_latched",
        "checkpoint",
        "campaign_closed",
    }
)
CONVERGENCE_STATE_FIELDS = frozenset(
    {
        "convergence_enabled",
        "convergence_min_runtime_seconds",
        "convergence_confirmation_seconds",
        "convergence_confirmation_eligible_cases",
        "max_wall_time_seconds",
        "convergence_confirmed",
        "convergence_time_seconds",
        "convergence_completed_cases",
        "convergence_eligible_cases",
        "last_novelty_time",
        "last_novelty_eligible_seq",
        "last_novelty_completed_cases",
        "last_novelty_unique_scenario_count",
        "confirmation_window_seconds",
        "confirmation_window_eligible_cases",
        "convergence_unique_scenarios_since_last_novelty",
        "convergence_executions_since_last_novelty",
        "convergence_pending_queue_nonempty",
        "convergence_stable_all_modes",
        "convergence_last_mode_novelty",
    }
)


@dataclass
class RecoveredScheduleState:
    seen_hashes: set[str] = field(default_factory=set)
    pending_hashes: list[str] = field(default_factory=list)
    completed_hashes: set[str] = field(default_factory=set)
    active_corpus_hashes: list[str] = field(default_factory=list)
    candidate_records: dict[str, dict[str, Any]] = field(default_factory=dict)
    candidate_discovered_bins: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    candidate_execution_costs: dict[str, float] = field(default_factory=dict)
    candidate_retained_without_novelty: dict[str, bool] = field(default_factory=dict)
    coverage_state: dict[str, set[str]] = field(
        default_factory=lambda: {
            "semantic": set(),
            "pairwise": set(),
            "security_triples": set(),
            "predicates": set(),
            "hpm": set(),
            "bapc": set(),
        }
    )
    completed_cases: int = 0
    eligible_cases: int = 0
    next_generation_seq: int = 0
    next_mutation_attempt: int = 0
    next_root_sequence: int = 0
    parent_selection_counts: dict[str, int] = field(default_factory=dict)
    last_round_idx: int = 0
    valid_bytes: int = 0
    needs_trailing_newline: bool = False
    execution_commits: list[dict[str, Any]] = field(default_factory=list)
    next_event_seq: int = 1
    closed: bool = False
    stop_latched: bool = False
    stop_reason: str | None = None
    convergence_state: dict[str, Any] = field(default_factory=dict)


class ScheduleV4Writer:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and self.path.stat().st_size > 0:
            self._state = recover_schedule_v4(self.path)
            current_size = self.path.stat().st_size
            if self._state.valid_bytes < current_size:
                with self.path.open("r+b") as fh:
                    fh.truncate(self._state.valid_bytes)
                    fh.flush()
                    os.fsync(fh.fileno())
            if self._state.needs_trailing_newline:
                with self.path.open("ab") as fh:
                    fh.write(b"\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                self._state.valid_bytes += 1
                self._state.needs_trailing_newline = False
        else:
            self._state = RecoveredScheduleState()

    @property
    def next_event_seq(self) -> int:
        return self._state.next_event_seq

    def append(self, event: str, **payload: Any) -> dict[str, Any]:
        if event in {"stop_latched", "checkpoint", "campaign_closed"} and "stop_reason" in payload:
            payload["stop_reason"] = normalize_stop_reason(payload.get("stop_reason"))
        record = {
            "schema_version": SCHEMA_VERSION,
            "event_seq": self._state.next_event_seq,
            "event": event,
            **payload,
        }
        _validate_event_record(record)
        next_state = copy.deepcopy(self._state)
        _apply_event(next_state, record)
        encoded = (json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n").encode("ascii")
        with self.path.open("ab") as fh:
            fh.write(encoded)
            fh.flush()
            os.fsync(fh.fileno())
        self._state = next_state
        return record


def recover_schedule_v4(path: Path) -> RecoveredScheduleState:
    state = RecoveredScheduleState()
    raw = Path(path).read_bytes()
    lines = raw.splitlines(keepends=True)
    cursor = 0
    for index, raw_line in enumerate(lines):
        has_newline = raw_line.endswith(b"\n") or raw_line.endswith(b"\r")
        next_cursor = cursor + len(raw_line)
        try:
            line = raw_line.decode("ascii")
        except UnicodeDecodeError as exc:
            if index == len(lines) - 1 and not has_newline:
                break
            raise ValueError(f"schedule_v4 contains non-ascii data on line {index + 1}") from exc
        text = line.strip()
        if not text:
            cursor = next_cursor
            state.valid_bytes = cursor
            continue
        try:
            record = json.loads(text)
        except json.JSONDecodeError as exc:
            if index == len(lines) - 1 and not has_newline:
                break
            raise ValueError(f"invalid JSON on schedule_v4 line {index + 1}") from exc
        _validate_event_record(record)
        expected_seq = state.next_event_seq
        if int(record["event_seq"]) != expected_seq:
            raise ValueError(
                f"non-contiguous schedule_v4 event_seq: expected {expected_seq}, got {record['event_seq']}"
            )
        _apply_event(state, record)
        cursor = next_cursor
        state.valid_bytes = cursor
    state.needs_trailing_newline = (
        state.valid_bytes > 0
        and state.valid_bytes == len(raw)
        and raw[state.valid_bytes - 1 : state.valid_bytes] not in {b"\n", b"\r"}
    )
    return state


def _validate_event_record(record: dict[str, Any]) -> None:
    if not isinstance(record, dict):
        raise ValueError("schedule_v4 event record must be an object")
    if record.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported schedule_v4 schema_version {record.get('schema_version')!r}; expected {SCHEMA_VERSION}"
        )
    event = record.get("event")
    if event not in VALID_EVENTS:
        raise ValueError(f"unsupported schedule_v4 event {event!r}")
    event_seq = record.get("event_seq")
    if type(event_seq) is not int or event_seq <= 0:
        raise ValueError("schedule_v4 event_seq must be a positive integer")
    if event in {"candidate_admitted", "candidate_generated", "candidate_duplicate", "candidate_rejected"}:
        spec = record.get("scenario_spec")
        if not isinstance(spec, dict):
            raise ValueError(f"{event} requires scenario_spec")
        expected_hash = record.get("scenario_hash")
        actual_hash = scenario_hash(spec)
        if expected_hash != actual_hash:
            raise ValueError(
                f"{event} scenario_hash mismatch: expected {expected_hash}, got {actual_hash}"
            )
    if event == "candidate_rejected" and not str(record.get("rejection_reason") or ""):
        raise ValueError("candidate_rejected requires rejection_reason")
    if event == "candidate_discarded":
        if not str(record.get("scenario_hash") or ""):
            raise ValueError("candidate_discarded requires scenario_hash")
        if not str(record.get("discard_reason") or ""):
            raise ValueError("candidate_discarded requires discard_reason")
    if event == "stop_latched" and not str(record.get("stop_reason") or ""):
        raise ValueError("stop_latched requires stop_reason")
    if event == "execution_committed":
        new_bins = record.get("new_bins") or {}
        if not isinstance(new_bins, dict):
            raise ValueError("execution_committed new_bins must be an object")
        evicted_hashes = record.get("evicted_hashes") or []
        if not isinstance(evicted_hashes, list):
            raise ValueError("execution_committed evicted_hashes must be a list")


def _apply_event(state: RecoveredScheduleState, record: dict[str, Any]) -> None:
    event = str(record["event"])
    scenario_hash_value = record.get("scenario_hash")
    state.closed = event == "campaign_closed"
    if event in {"candidate_admitted", "candidate_generated", "candidate_duplicate", "candidate_rejected"}:
        text = str(scenario_hash_value)
        if event in {"candidate_generated", "candidate_admitted"}:
            state.seen_hashes.add(text)
            state.candidate_records[text] = {
                "scenario_hash": text,
                "scenario_spec": dict(record["scenario_spec"]),
                "parent_hash": record.get("parent_hash"),
                "mutation_operator": str(record.get("mutation_operator") or ""),
                "mutation_seed": int(record.get("mutation_seed") or 0),
                "generation_seed": int(record.get("generation_seed") or record.get("mutation_seed") or 0),
                "scenario_index": record.get("scenario_index"),
                "generation_seq": int(record.get("generation_seq") or 0),
                "mutation_depth": int(record.get("mutation_depth") or 0),
                "generator_variant": str(record.get("generator_variant") or "full"),
                "root_sequence": record.get("root_sequence"),
            }
            if text not in state.completed_hashes and text not in state.pending_hashes and event == "candidate_admitted":
                state.pending_hashes.append(text)
        state.next_generation_seq = max(
            state.next_generation_seq,
            int(record.get("generation_seq") or 0),
        )
        root_sequence = record.get("root_sequence")
        if type(root_sequence) is int:
            state.next_root_sequence = max(state.next_root_sequence, root_sequence + 1)
        elif record.get("parent_hash") is None and str(record.get("mutation_operator") or "") == "root":
            state.next_root_sequence += 1
        else:
            state.next_mutation_attempt = max(
                state.next_mutation_attempt,
                int(record.get("mutation_seed") or 0) + 1,
            )
        parent_hash = record.get("parent_hash")
        if parent_hash is not None:
            parent_text = str(parent_hash)
            state.parent_selection_counts[parent_text] = state.parent_selection_counts.get(parent_text, 0) + 1
    elif event == "candidate_discarded":
        text = str(scenario_hash_value)
        if text not in state.seen_hashes:
            raise ValueError(f"candidate_discarded references unknown scenario_hash {text}")
        state.pending_hashes = [item for item in state.pending_hashes if item != text]
    elif event == "candidate_queued":
        text = str(scenario_hash_value)
        if text not in state.seen_hashes:
            raise ValueError(f"candidate_queued references unknown scenario_hash {text}")
        if text not in state.completed_hashes and text not in state.pending_hashes:
            state.pending_hashes.append(text)
    elif event == "execution_committed":
        _apply_execution_commit(state, record)
    elif event == "execution_completed":
        text = str(scenario_hash_value)
        if text not in state.seen_hashes:
            raise ValueError(f"execution_completed references unknown scenario_hash {text}")
        if text in state.pending_hashes:
            state.pending_hashes = [item for item in state.pending_hashes if item != text]
        state.completed_hashes.add(text)
        state.completed_cases += 1
        if bool(record.get("eligible")):
            state.eligible_cases += 1
        if "execution_cost" in record:
            state.candidate_execution_costs[text] = float(record.get("execution_cost") or 0.0)
    elif event == "coverage_recorded":
        text = str(scenario_hash_value)
        new_bins = record.get("new_bins") or {}
        if not isinstance(new_bins, dict):
            raise ValueError("coverage_recorded new_bins must be an object")
        snapshot = {mode: [] for mode in TRACKED_COVERAGE_MODES}
        for mode in TRACKED_COVERAGE_MODES:
            values = new_bins.get(mode) or []
            if not isinstance(values, list):
                raise ValueError(f"coverage_recorded new_bins.{mode} must be a list")
            normalized = [str(item) for item in values]
            state.coverage_state[mode].update(normalized)
            snapshot[mode] = normalized
        state.candidate_discovered_bins[text] = snapshot
    elif event == "corpus_promoted":
        text = str(scenario_hash_value)
        if text not in state.seen_hashes:
            raise ValueError(f"corpus_promoted references unknown scenario_hash {text}")
        if text not in state.active_corpus_hashes:
            state.active_corpus_hashes.append(text)
    elif event == "corpus_evicted":
        text = str(scenario_hash_value)
        state.active_corpus_hashes = [item for item in state.active_corpus_hashes if item != text]
    elif event in {"stop_latched", "checkpoint", "campaign_closed"}:
        state.last_round_idx = max(state.last_round_idx, int(record.get("round_idx") or 0))
        if event == "stop_latched":
            state.stop_latched = True
        state.stop_reason = normalize_stop_reason(record.get("stop_reason"))
        state.convergence_state = {
            key: copy.deepcopy(record[key])
            for key in CONVERGENCE_STATE_FIELDS
            if key in record
        }
    state.next_event_seq = int(record["event_seq"]) + 1


def _apply_execution_commit(state: RecoveredScheduleState, record: dict[str, Any]) -> None:
    text = str(record.get("scenario_hash"))
    if text not in state.seen_hashes:
        raise ValueError(f"execution_committed references unknown scenario_hash {text}")
    if text in state.pending_hashes:
        state.pending_hashes = [item for item in state.pending_hashes if item != text]
    state.completed_hashes.add(text)
    state.completed_cases += 1
    eligible = bool(record.get("eligible"))
    if eligible:
        state.eligible_cases += 1
    if "execution_cost" in record:
        state.candidate_execution_costs[text] = float(record.get("execution_cost") or 0.0)
    new_bins = record.get("new_bins") or {}
    snapshot = {mode: [] for mode in TRACKED_COVERAGE_MODES}
    for mode in TRACKED_COVERAGE_MODES:
        values = new_bins.get(mode) or []
        if not isinstance(values, list):
            raise ValueError(f"execution_committed new_bins.{mode} must be a list")
        normalized = [str(item) for item in values]
        state.coverage_state[mode].update(normalized)
        snapshot[mode] = normalized
    state.candidate_discovered_bins[text] = snapshot
    state.candidate_retained_without_novelty[text] = bool(record.get("retained_without_novelty"))
    if bool(record.get("promoted")) and text not in state.active_corpus_hashes:
        state.active_corpus_hashes.append(text)
    for evicted_hash in record.get("evicted_hashes") or []:
        evicted_text = str(evicted_hash)
        state.active_corpus_hashes = [item for item in state.active_corpus_hashes if item != evicted_text]
    commit_record = dict(record)
    commit_record["_recovered_completed_cases"] = state.completed_cases
    commit_record["_recovered_eligible_cases"] = state.eligible_cases
    commit_record["_recovered_unique_scenario_count"] = len(state.seen_hashes)
    state.execution_commits.append(commit_record)
