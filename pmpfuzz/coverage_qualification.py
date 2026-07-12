"""Execution-qualified coverage: decide whether a test result counts toward coverage.

This module does NOT import schema.py (to avoid circular dependencies).
It uses only stdlib json, pathlib, dataclasses, collections, and typing.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# data class
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CoverageQualification:
    """Whether a single result qualifies for execution-qualified coverage."""

    eligible: bool
    reason: str
    status: str | None = None
    oracle_applicability: str | None = None
    observation_valid: bool | None = None
    target_phase: str | None = None
    reached_phase: str | None = None
    semantic_mismatch: bool = False


# ---------------------------------------------------------------------------
# file I/O (stdlib only, no schema.py)
# ---------------------------------------------------------------------------


def read_json_file(path: Path) -> Any:
    """Read a JSON file.  Thin wrapper so callers don't need to import json."""
    return json.loads(path.read_text(encoding="ascii"))


def load_case_map(run_dir: Path) -> dict[str, dict[str, Any]]:
    """Return {case_name: case_dict} for every case.json under run_dir/cases/."""
    cases: dict[str, dict[str, Any]] = {}
    cases_dir = run_dir / "cases"
    if not cases_dir.is_dir():
        return cases
    for case_path in sorted(cases_dir.glob("*/case.json")):
        case = read_json_file(case_path)
        cases[case["name"]] = case
    return cases


def load_results(run_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """Return {case_name: [result_dict, ...]} for every result.json under run_dir/results/.

    Grouped by case name because repro runs may produce multiple DUT results
    for the same case (e.g. spike + rocket-clean).
    """
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
    """Return {dut_name: capability_dict} or None if the file is missing."""
    path = run_dir / "dut_capabilities.json"
    if not path.exists():
        return None
    data = read_json_file(path)
    return data.get("duts") or {}


# ---------------------------------------------------------------------------
# target-phase logic (single function — not duplicated elsewhere)
# ---------------------------------------------------------------------------


def result_reached_target_phase(case: dict[str, Any], result: dict[str, Any]) -> bool:
    """Return True when *result* reached the observation phase required by *case*.

    Rules (see docs, §3.1):

    * Stateful cases (expected.stage == "stateful_final"):
      must reach one of the ``final*`` phases.

    * Normal cases: target phase is determined by the *actual* observed_event,
      NOT by expected.allowed.

      - observed_event == "trap"       → must reach ``probe``
      - observed_event == "completion" → must reach ``completed``
      - anything else                  → False
    """
    expected = case.get("expected") or {}
    expected_stage = str(expected.get("stage") or "none")

    observed_phase = str(result.get("observed_phase") or "").lower()

    # -- stateful -----------------------------------------------------------
    if expected_stage == "stateful_final":
        return observed_phase in _FINAL_PHASES

    # -- normal: use actual observed_event ----------------------------------
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
    """Human-readable label for the expected target phase.

    For normal cases the target phase is determined by the *actual* observed_event
    (not by expected.allowed).  Returns None when the observed_event is unknown.
    """
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


# ---------------------------------------------------------------------------
# qualification
# ---------------------------------------------------------------------------


def qualify_result_for_coverage(
    case: dict[str, Any],
    result: dict[str, Any],
) -> CoverageQualification:
    """Decide whether a single (case, result) pair is execution-qualified.

    Conditions (all must be true):

    1. oracle_applicability == "valid"
    2. status in {"pass", "fail"}
    3. observation_valid is True
    4. structured observation data is present (known event type + concrete field)
    5. reached the target observation phase (actual event drives target)
    """
    status = str(result.get("status") or "")
    oracle_applicability = str(result.get("oracle_applicability") or "")
    observation_valid = bool(result.get("observation_valid"))
    observed_phase = str(result.get("observed_phase") or "").lower()

    # --- 1. oracle applicability -------------------------------------------
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

    # --- 2. status must be pass or fail ------------------------------------
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

    # --- 3. observation_valid -----------------------------------------------
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

    # --- 4. structured observation ------------------------------------------
    #     Must come before phase check because phase logic depends on
    #     observed_event being a known type (trap / completion).
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

    # --- 5. target phase ----------------------------------------------------
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

    # --- eligible -----------------------------------------------------------
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


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _has_structured_observation(result: dict[str, Any]) -> bool:
    """Return True when *result* contains parseable structured observation data.

    A structured result must have a known observed_event (trap or completion),
    a non-empty observed_phase, and at least one concrete observation field
    (observed_tohost, observed_mcause, or observed_mtval) whose value is not None.

    The integer 0 is a valid observation value — only None means "absent".
    """
    observed_event = str(result.get("observed_event") or "")
    if observed_event not in ("trap", "completion"):
        return False

    observed_phase = str(result.get("observed_phase") or "")
    if not observed_phase:
        return False

    # At least one concrete observation field must be present (0 is valid)
    for key in ("observed_tohost", "observed_mcause", "observed_mtval"):
        if key in result and result[key] is not None:
            return True
    return False


def _is_semantic_mismatch(case: dict[str, Any], result: dict[str, Any]) -> bool:
    """A fail result with valid oracle where DUT behaviour diverges from expected."""
    if result.get("status") != "fail":
        return False
    if result.get("oracle_applicability") != "valid":
        return False
    failure_class = result.get("failure_class") or ""
    # These failure classes indicate a real semantic mismatch (not infra).
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


# ---------------------------------------------------------------------------
# batch qualification (used by coverage.py and semantic_coverage.py)
# ---------------------------------------------------------------------------


@dataclass
class QualificationSummary:
    """Aggregated qualification counts for one DUT in one run directory."""

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
    """Qualify every result in *run_dir*, grouped by DUT.

    Returns {dut_name: QualificationSummary}.
    """
    case_map = load_case_map(run_dir)
    results_by_case = load_results(run_dir)

    summaries: dict[str, QualificationSummary] = {}

    for case_name, result_list in results_by_case.items():
        case = case_map.get(case_name)
        if case is None:
            # result without matching case — skip
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


# ---------------------------------------------------------------------------
# multi-run evidence collection (Fix 4 & 5)
# ---------------------------------------------------------------------------


@dataclass
class ExecutionEvidence:
    """Aggregated qualification evidence for one DUT across one or more runs."""

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
    """Collect execution evidence for *dut* across all *run_dirs*.

    - Iterates every run_dir.
    - Only reads results belonging to the specified DUT.
    - Qualifies every (case, result) pair via qualify_result_for_coverage.
    - Tracks missing results (case has no result for this DUT) and
      orphan results (result has no matching case).
    - Returns a single ExecutionEvidence aggregating all runs.
    """
    all_eligible: list[dict[str, Any]] = []
    summary = QualificationSummary()
    missing = 0
    orphans = 0

    for run_dir in run_dirs:
        run_dir = Path(run_dir)
        case_map = load_case_map(run_dir)
        results_by_case = load_results(run_dir)

        # --- track which cases have at least one result for this DUT ---------
        cases_with_result: set[str] = set()

        for case_name, result_list in results_by_case.items():
            case = case_map.get(case_name)
            if case is None:
                # result without matching case → orphan
                for result in result_list:
                    result_dut = str(result.get("dut") or "")
                    if result_dut == dut:
                        orphans += 1
                        summary.total_results += 1
                        summary.excluded_results += 1
                        summary.excluded_by_reason["missing_case"] += 1
                continue

            # Filter to results belonging to the target DUT FIRST,
            # then mark the case as "has result" only when at least one
            # matching result exists.  This prevents cross-DUT contamination
            # where a Rocket result would suppress a Spike missing count.
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

        # --- missing results: cases with no result for this DUT --------------
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
