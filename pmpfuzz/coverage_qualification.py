
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable




@dataclass(frozen=True)
class CoverageQualification:

    eligible: bool
    reason: str
    status: str | None = None
    oracle_applicability: str | None = None
    observation_valid: bool | None = None
    target_phase: str | None = None
    reached_phase: str | None = None
    semantic_mismatch: bool = False




def read_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="ascii"))


def load_case_map(run_dir: Path) -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    cases_dir = run_dir / "cases"
    if not cases_dir.is_dir():
        return cases
    for case_path in sorted(cases_dir.glob("*/case.json")):
        case = read_json_file(case_path)
        cases[case["name"]] = case
    return cases


def load_results(run_dir: Path) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    results_dir = run_dir / "results"
    if not results_dir.is_dir():
        return grouped
    for result_path in sorted(results_dir.glob("*/result.json")):
        result = read_json_file(result_path)
        name = result.get("name") or result.get("case_id", "unknown")
        grouped.setdefault(name, []).append(result)
    return grouped


def load_capability_map(run_dir: Path) -> dict[str, dict[str, Any]] | None:
    path = run_dir / "dut_capabilities.json"
    if not path.exists():
        return None
    data = read_json_file(path)
    return data.get("duts") or {}


def result_reached_target_phase(case: dict[str, Any], result: dict[str, Any]) -> bool:
    expected = case.get("expected") or {}
    expected_stage = str(expected.get("stage") or "none")

    observed_phase = str(result.get("observed_phase") or "").lower()

    if expected_stage == "stateful_final":
        return observed_phase in _FINAL_PHASES

    observed_event = str(result.get("observed_event") or "")

    if observed_event == "trap":
        return observed_phase == "probe"

    if observed_event == "completion":
        return observed_phase == "completed"

    return False


_FINAL_PHASES = frozenset({
    "final",
    "final_sentinel_initial",
    "final_sentinel_modified",
    "final_sentinel_other",
})


def _target_phase_label(case: dict[str, Any], result: dict[str, Any]) -> str | None:
    expected = case.get("expected") or {}
    expected_stage = str(expected.get("stage") or "none")

    if expected_stage == "stateful_final":
        return "final"

    observed_event = str(result.get("observed_event") or "")
    if observed_event == "trap":
        return "probe"
    if observed_event == "completion":
        return "completed"

    return None




def qualify_result_for_coverage(
    case: dict[str, Any],
    result: dict[str, Any],
) -> CoverageQualification:
    status = str(result.get("status") or "")
    oracle_applicability = str(result.get("oracle_applicability") or "")
    observation_valid = bool(result.get("observation_valid"))
    observed_phase = str(result.get("observed_phase") or "").lower()

    if oracle_applicability != "valid":
        return CoverageQualification(
            eligible=False,
            reason=f"oracle_{oracle_applicability}",
            status=status,
            oracle_applicability=oracle_applicability,
            observation_valid=observation_valid,
            target_phase=_target_phase_label(case, result),
            reached_phase=observed_phase or None,
        )

    if status not in {"pass", "fail"}:
        return CoverageQualification(
            eligible=False,
            reason=f"status_{status}",
            status=status,
            oracle_applicability=oracle_applicability,
            observation_valid=observation_valid,
            target_phase=_target_phase_label(case, result),
            reached_phase=observed_phase or None,
        )

    if not observation_valid:
        return CoverageQualification(
            eligible=False,
            reason="observation_invalid",
            status=status,
            oracle_applicability=oracle_applicability,
            observation_valid=False,
            target_phase=_target_phase_label(case, result),
            reached_phase=observed_phase or None,
        )


    if not _has_structured_observation(result):
        return CoverageQualification(
            eligible=False,
            reason="missing_structured_observation",
            status=status,
            oracle_applicability=oracle_applicability,
            observation_valid=True,
            target_phase=_target_phase_label(case, result),
            reached_phase=observed_phase or None,
        )

    if not result_reached_target_phase(case, result):
        return CoverageQualification(
            eligible=False,
            reason="wrong_phase",
            status=status,
            oracle_applicability=oracle_applicability,
            observation_valid=True,
            target_phase=_target_phase_label(case, result),
            reached_phase=observed_phase or None,
        )

    semantic_mismatch = _is_semantic_mismatch(case, result)
    return CoverageQualification(
        eligible=True,
        reason="eligible",
        status=status,
        oracle_applicability=oracle_applicability,
        observation_valid=True,
        target_phase=_target_phase_label(case, result),
        reached_phase=observed_phase or None,
        semantic_mismatch=semantic_mismatch,
    )




def _has_structured_observation(result: dict[str, Any]) -> bool:
    observed_event = str(result.get("observed_event") or "")
    if observed_event not in ("trap", "completion"):
        return False

    observed_phase = str(result.get("observed_phase") or "")
    if not observed_phase:
        return False


    for key in ("observed_tohost", "observed_mcause", "observed_mtval"):
        if key in result and result[key] is not None:
            return True
    return False


def _is_semantic_mismatch(case: dict[str, Any], result: dict[str, Any]) -> bool:
    if result.get("status") != "fail":
        return False
    if result.get("oracle_applicability") != "valid":
        return False
    failure_class = result.get("failure_class") or ""

    mismatch_classes = {
        "unexpected_trap",
        "unexpected_no_trap",
        "wrong_mcause",
        "wrong_mtval",
        "wrong_mepc",
        "wrong_trap_stage",
        "wrong_path",
        "invalid_completion",
        "missing_expected_side_effect",
        "forbidden_side_effect",
        "unexpected_side_effect_state",
    }
    return failure_class in mismatch_classes or bool(result.get("observation_valid"))




@dataclass
class QualificationSummary:

    total_results: int = 0
    eligible_results: int = 0
    valid_mismatches: int = 0
    excluded_results: int = 0
    missing_results: int = 0
    orphan_results: int = 0
    excluded_by_reason: Counter = field(default_factory=Counter)


def qualify_all_results(
    run_dir: Path,
    capability: dict[str, Any] | None = None,
) -> dict[str, QualificationSummary]:
    case_map = load_case_map(run_dir)
    results_by_case = load_results(run_dir)

    summaries: dict[str, QualificationSummary] = {}

    for case_name, result_list in results_by_case.items():
        case = case_map.get(case_name)
        if case is None:
            continue
        for result in result_list:
            dut = str(result.get("dut") or "unknown")
            summary = summaries.setdefault(dut, QualificationSummary())
            summary.total_results += 1
            qual = qualify_result_for_coverage(case, result)
            if qual.eligible:
                summary.eligible_results += 1
                if qual.semantic_mismatch:
                    summary.valid_mismatches += 1
            else:
                summary.excluded_results += 1
                summary.excluded_by_reason[qual.reason] += 1

    return summaries


@dataclass
class ExecutionEvidence:

    dut: str
    eligible_cases: list[dict[str, Any]]
    summary: QualificationSummary
    missing_results: int = 0
    orphan_results: int = 0


def collect_execution_evidence(
    run_dirs: Iterable[Path],
    *,
    dut: str,
) -> ExecutionEvidence:
    all_eligible: list[dict[str, Any]] = []
    summary = QualificationSummary()
    missing = 0
    orphans = 0

    for run_dir in run_dirs:
        run_dir = Path(run_dir)
        case_map = load_case_map(run_dir)
        results_by_case = load_results(run_dir)

        cases_with_result: set[str] = set()

        for case_name, result_list in results_by_case.items():
            case = case_map.get(case_name)
            if case is None:
                for result in result_list:
                    result_dut = str(result.get("dut") or "")
                    if result_dut == dut:
                        orphans += 1
                        summary.total_results += 1
                        summary.excluded_results += 1
                        summary.excluded_by_reason["missing_case"] += 1
                continue


            matching_results = [
                result
                for result in result_list
                if str(result.get("dut") or "") == dut
            ]

            if matching_results:
                cases_with_result.add(case_name)

            for result in matching_results:
                summary.total_results += 1
                qual = qualify_result_for_coverage(case, result)
                if qual.eligible:
                    summary.eligible_results += 1
                    all_eligible.append(case)
                    if qual.semantic_mismatch:
                        summary.valid_mismatches += 1
                else:
                    summary.excluded_results += 1
                    summary.excluded_by_reason[qual.reason] += 1

        for case_name, case in case_map.items():
            if case_name not in cases_with_result:
                missing += 1

    summary.missing_results = missing
    summary.orphan_results = orphans

    return ExecutionEvidence(
        dut=dut,
        eligible_cases=all_eligible,
        summary=summary,
        missing_results=missing,
        orphan_results=orphans,
    )
