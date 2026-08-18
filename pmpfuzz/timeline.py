
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Set

from .coverage_qualification import qualify_result_for_coverage
from .semantic_coverage import (
    CORE_STATEFUL_TARGET,
    combo_bins_for_case,
    contract_predicates_for_case,
    semantic_bins_for_case,
)


SCHEMA_VERSION = 1


@dataclass
class TimelineRecorder:

    run_dir: Path
    campaign_id: str
    variant: str
    dut: str
    seed: int


    target_semantic: Set[str] = field(default_factory=set)
    target_pairwise: Set[str] = field(default_factory=set)
    target_security_triples: Set[str] = field(default_factory=set)
    target_predicates: Set[str] = field(default_factory=set)


    _completion_seq: int = 0
    _completed_cases: int = 0
    _eligible_cases: int = 0
    _covered_semantic: Set[str] = field(default_factory=set)
    _covered_pairwise: Set[str] = field(default_factory=set)
    _covered_security_triples: Set[str] = field(default_factory=set)
    _covered_predicates: Set[str] = field(default_factory=set)
    _whitebox_distinct_events: int = 0
    _whitebox_event_ids: Set[str] = field(default_factory=set)


    _output_path: Path | None = None
    _metadata_path: Path | None = None
    _baseline_written: bool = False

    def __post_init__(self) -> None:
        metrics_dir = self.run_dir / "metrics"
        metrics_dir.mkdir(parents=True, exist_ok=True)
        self._output_path = metrics_dir / "coverage_timeline.jsonl"
        self._metadata_path = metrics_dir / "campaign_metadata.json"
        self._baseline_written = (
            self._output_path.exists() and self._output_path.stat().st_size > 0
        )

    @property
    def output_path(self) -> Path:
        assert self._output_path is not None
        return self._output_path

    def _write_baseline(self) -> None:
        self._append_line(self._make_line(
            completion_seq=0,
            case_id=None,
            profile=None,
            elapsed_wall_seconds=0.0,
            completion_monotonic_seconds=None,
            case_elapsed_seconds=0.0,
            status=None,
            failure_class=None,
            qualification_reason=None,
            new_semantic=0,
            new_pairwise=0,
            new_triple=0,
            new_predicate=0,
            new_whitebox=0,
        ))

    def record(
        self,
        case: dict[str, Any],
        result: dict[str, Any],
        elapsed_wall_seconds: float,
        case_elapsed_seconds: float,
        whitebox_new_events: int = 0,
        completion_monotonic_seconds: float | None = None,
    ) -> None:
        if not self._baseline_written:
            self._write_baseline()
            self._baseline_written = True

        self._completion_seq += 1
        self._completed_cases += 1

        status = str(result.get("status") or "")
        failure_class = result.get("failure_class")

        qual = qualify_result_for_coverage(case, result)
        coverage_eligible = qual.eligible
        qualification_reason = qual.reason

        new_semantic = 0
        new_pairwise = 0
        new_triple = 0
        new_predicate = 0

        if coverage_eligible:
            self._eligible_cases += 1

            case_sem = set(semantic_bins_for_case(case)) & self.target_semantic
            case_pair = {b for b in combo_bins_for_case(case, coverage_mode="pairwise")
                         if b.startswith("combo2:")} & self.target_pairwise
            case_trip = {b for b in combo_bins_for_case(case, coverage_mode="security-triples")
                         if b.startswith("combo3:")} & self.target_security_triples
            case_pred = set(contract_predicates_for_case(case)) & self.target_predicates

            new_semantic = len(case_sem - self._covered_semantic)
            new_pairwise = len(case_pair - self._covered_pairwise)
            new_triple = len(case_trip - self._covered_security_triples)
            new_predicate = len(case_pred - self._covered_predicates)

            self._covered_semantic.update(case_sem)
            self._covered_pairwise.update(case_pair)
            self._covered_security_triples.update(case_trip)
            self._covered_predicates.update(case_pred)

        self._whitebox_distinct_events += whitebox_new_events

        self._append_line(self._make_line(
            completion_seq=self._completion_seq,
            case_id=case.get("name") or result.get("name") or "",
            profile=case.get("profile") or result.get("profile") or "",
            elapsed_wall_seconds=elapsed_wall_seconds,
            completion_monotonic_seconds=completion_monotonic_seconds,
            case_elapsed_seconds=case_elapsed_seconds,
            status=status,
            failure_class=failure_class,
            qualification_reason=qualification_reason,
            new_semantic=new_semantic,
            new_pairwise=new_pairwise,
            new_triple=new_triple,
            new_predicate=new_predicate,
            new_whitebox=whitebox_new_events,
        ))

    def _make_line(
        self,
        *,
        completion_seq: int,
        case_id: str | None,
        profile: str | None,
        elapsed_wall_seconds: float,
        completion_monotonic_seconds: float | None,
        case_elapsed_seconds: float,
        status: str | None,
        failure_class: str | None,
        qualification_reason: str | None,
        new_semantic: int,
        new_pairwise: int,
        new_triple: int,
        new_predicate: int,
        new_whitebox: int,
    ) -> dict[str, Any]:
        sem_total = len(self.target_semantic)
        pair_total = len(self.target_pairwise)
        trip_total = len(self.target_security_triples)
        pred_total = len(self.target_predicates)

        sem_rate = len(self._covered_semantic) / sem_total if sem_total > 0 else None
        pair_rate = len(self._covered_pairwise) / pair_total if pair_total > 0 else None
        trip_rate = len(self._covered_security_triples) / trip_total if trip_total > 0 else None
        pred_rate = len(self._covered_predicates) / pred_total if pred_total > 0 else None

        return {
            "schema_version": SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "variant": self.variant,
            "dut": self.dut,
            "seed": self.seed,
            "completion_seq": completion_seq,
            "case_id": case_id,
            "profile": profile,
            "elapsed_wall_seconds": elapsed_wall_seconds,
            "completion_monotonic_seconds": completion_monotonic_seconds,
            "case_elapsed_seconds": case_elapsed_seconds,
            "completed_cases": self._completed_cases,
            "eligible_cases": self._eligible_cases,
            "status": status,
            "failure_class": failure_class,
            "coverage_eligible": completion_seq > 0 and qualification_reason == "eligible",
            "qualification_reason": qualification_reason,
            "semantic_covered": len(self._covered_semantic),
            "semantic_target": sem_total,
            "semantic_rate": sem_rate,
            "pairwise_covered": len(self._covered_pairwise),
            "pairwise_target": pair_total,
            "pairwise_rate": pair_rate,
            "security_triples_covered": len(self._covered_security_triples),
            "security_triples_target": trip_total,
            "security_triples_rate": trip_rate,
            "predicates_covered": len(self._covered_predicates),
            "predicates_target": pred_total,
            "predicates_rate": pred_rate,
            "new_semantic_bins": new_semantic,
            "new_pairwise_bins": new_pairwise,
            "new_security_triple_bins": new_triple,
            "new_predicate_bins": new_predicate,
            "whitebox_distinct_events": self._whitebox_distinct_events,
            "new_whitebox_events": new_whitebox,
        }

    def _append_line(self, obj: dict[str, Any]) -> None:
        assert self._output_path is not None
        line = json.dumps(obj, ensure_ascii=True, sort_keys=True) + "\n"
        with open(self._output_path, "a", encoding="ascii") as fh:
            fh.write(line)
            fh.flush()

    def write_metadata(
        self,
        *,
        source_sha: str | None = None,
        dut_sha: str | None = None,
        dut_binary_sha256: str | None = None,
        start_utc: str | None = None,
        end_utc: str | None = None,
        time_budget_seconds: int | None = None,
        round_size: int | None = None,
        jobs: int | None = None,
        per_case_timeout_seconds: int | None = None,
        hostname: str | None = None,
        command_line: str | None = None,
        coverage_mode: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        assert self._metadata_path is not None
        meta: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "variant": self.variant,
            "dut": self.dut,
            "seed": self.seed,
            "source_sha": source_sha,
            "dut_sha": dut_sha,
            "dut_binary_sha256": dut_binary_sha256,
            "start_utc": start_utc,
            "end_utc": end_utc,
            "time_budget_seconds": time_budget_seconds,
            "round_size": round_size,
            "jobs": jobs,
            "per_case_timeout_seconds": per_case_timeout_seconds,
            "hostname": hostname,
            "command_line": command_line,
            "coverage_mode": coverage_mode,
        }
        if extra:
            meta.update(extra)
        self._metadata_path.write_text(
            json.dumps(meta, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
            encoding="ascii",
        )

    def record_whitebox_events(self, event_ids: set[str]) -> int:
        new = event_ids - self._whitebox_event_ids
        self._whitebox_event_ids.update(event_ids)
        self._whitebox_distinct_events = len(self._whitebox_event_ids)
        return len(new)

    def coverage_state(self) -> dict[str, Any]:
        sem_total = len(self.target_semantic)
        pair_total = len(self.target_pairwise)
        trip_total = len(self.target_security_triples)
        pred_total = len(self.target_predicates)

        return {
            "semantic": {
                "total_target_bins": sem_total,
                "covered_target_bins": len(self._covered_semantic),
                "coverage_rate": len(self._covered_semantic) / sem_total if sem_total > 0 else None,
            },
            "pairwise": {
                "total_target_bins": pair_total,
                "covered_target_bins": len(self._covered_pairwise),
                "coverage_rate": len(self._covered_pairwise) / pair_total if pair_total > 0 else None,
            },
            "security_triples": {
                "total_target_bins": trip_total,
                "covered_target_bins": len(self._covered_security_triples),
                "coverage_rate": len(self._covered_security_triples) / trip_total if trip_total > 0 else None,
            },
            "predicates": {
                "total_target_bins": pred_total,
                "covered_target_bins": len(self._covered_predicates),
                "coverage_rate": len(self._covered_predicates) / pred_total if pred_total > 0 else None,
            },
        }


def timeline_on_complete_factory(
    recorder: TimelineRecorder,
    *,
    enable_whitebox: bool = False,
) -> Any:
    def _on_complete(index, scenario, result, completion_seq, campaign_elapsed):
        out_dir = recorder.run_dir
        case_path = out_dir / "cases" / result.name / "case.json"
        result_path = out_dir / "results" / result.name / "result.json"

        if case_path.exists():
            case = json.loads(case_path.read_text(encoding="ascii"))
        else:
            case = {"name": result.name, "profile": result.profile}

        if result_path.exists():
            result_dict = json.loads(result_path.read_text(encoding="ascii"))
        else:

            result_dict = {
                "name": result.name,
                "status": result.status,
                "failure_class": result.failure_class,
                "observation_valid": result.observation_valid,
                "stage_verified": result.stage_verified,
                "observed_event": result.observed_event,
                "observed_phase": result.observed_phase,
                "observed_stage": result.observed_stage,
                "observed_ptw_level": result.observed_ptw_level,
                "oracle_applicability": "valid",
                "dut": recorder.dut,
            }

        new_whitebox = 0
        if enable_whitebox:
            try:
                from .whitebox import whitebox_event_ids_for_result
                event_ids = whitebox_event_ids_for_result(case, result_dict, out_dir)
                new_whitebox = recorder.record_whitebox_events(event_ids)
            except Exception:
                pass

        recorder.record(
            case=case,
            result=result_dict,
            elapsed_wall_seconds=campaign_elapsed,
            case_elapsed_seconds=result.elapsed_seconds,
            whitebox_new_events=new_whitebox,
            completion_monotonic_seconds=time.monotonic(),
        )

    return _on_complete
