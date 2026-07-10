from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .diagnostics import (
    ObservedEvent,
    ObservationKind,
    ObservationPhase,
    mepc_tag,
    mtval_fingerprint,
)


@dataclass(frozen=True)
class ObservationJudgment:
    status: str
    failure_class: str | None
    reason: str
    observation_valid: bool
    stage_verified: bool


def judge_observation(
    case: dict[str, Any],
    event: ObservedEvent,
    *,
    observed_stage: str | None = None,
    observed_ptw_level: str | None = None,
    observed_fault_address: int | None = None,
) -> ObservationJudgment:
    expected = case.get("expected") or {}
    expected_allowed = bool(expected.get("allowed"))
    expected_stage = str(expected.get("stage") or "none")
    expected_phase = ObservationPhase.FINAL if expected_stage == "stateful_final" else None
    final_phases = {
        ObservationPhase.FINAL,
        ObservationPhase.FINAL_SENTINEL_INITIAL,
        ObservationPhase.FINAL_SENTINEL_MODIFIED,
        ObservationPhase.FINAL_SENTINEL_OTHER,
    }

    if event.kind == ObservationKind.COMPLETION:
        valid_phases = {ObservationPhase.COMPLETED}
        if expected_phase is not None:
            valid_phases.update(final_phases)
        if event.phase not in valid_phases:
            return _failure("wrong_path", f"completion reported from phase {event.phase.name.lower()}")
        ecall_cause = _expected_ecall_cause(case)
        if ecall_cause is not None and event.mcause != ecall_cause:
            return _failure("invalid_completion", "completion event does not contain the expected ecall cause")
        if event.mtval_fingerprint != mtval_fingerprint(0):
            return _failure("invalid_completion", "completion ecall reported a non-zero mtval")
        if not _mepc_matches_probe_window(case, event):
            return _failure("wrong_mepc", "completion mepc is outside the active probe instruction window")
        if expected_allowed:
            side_effect = _stateful_side_effect_judgment(case, event)
            if side_effect is not None:
                return side_effect
            return ObservationJudgment("pass", None, "host oracle accepted completion", True, True)
        side_effect = _stateful_side_effect_judgment(case, event)
        if side_effect is not None:
            return side_effect
        return _failure(
            "unexpected_no_trap",
            "probe completed although the host oracle expected a trap",
            stage_verified=True,
        )

    if event.kind != ObservationKind.TRAP:
        return _failure("invalid_observation", "unknown DUT observation kind")

    valid_trap_phases = final_phases if expected_phase is not None else {ObservationPhase.PROBE}
    if event.phase not in valid_trap_phases:
        return _failure(
            "wrong_path",
            f"trap reported from unexpected phase {event.phase.name.lower()}",
        )
    if expected_allowed:
        return _failure("unexpected_trap", "DUT trapped although the host oracle expected completion")

    expected_cause = expected.get("trap_cause")
    if expected_cause is None or event.mcause != int(expected_cause):
        return _failure(
            "wrong_mcause",
            f"observed mcause={event.mcause}, expected={expected_cause}",
        )

    expected_address = _case_address(case)
    if expected_address is not None and event.mtval_fingerprint != mtval_fingerprint(expected_address):
        return _failure(
            "wrong_mtval",
            "observed mtval low bits do not match the expected fault address",
        )
    if not _mepc_matches_probe_window(case, event):
        return _failure("wrong_mepc", "trap mepc is outside the active probe instruction window")

    if expected_stage == "page_table_walk":
        expected_level, expected_address = _expected_denied_ptw(case)
        if observed_stage is None or observed_fault_address is None:
            return ObservationJudgment(
                "inconclusive",
                "unverified_trap_stage",
                "matching mcause lacks PTW stage/address evidence",
                True,
                False,
            )
        normalized_stage = observed_stage.lower().replace("-", "_")
        level_matches = observed_ptw_level is None or expected_level is None or observed_ptw_level == expected_level
        address_matches = expected_address is not None and observed_fault_address == expected_address
        if normalized_stage not in {"ptw", "page_table_walk"} or not level_matches or not address_matches:
            return _failure(
                "wrong_trap_stage",
                "matching mcause came from the wrong PTW stage, level, or address",
            )

    side_effect = _stateful_side_effect_judgment(case, event)
    if side_effect is not None:
        return side_effect

    return ObservationJudgment("pass", None, "host oracle accepted raw DUT trap", True, True)


def _expected_denied_ptw(case: dict[str, Any]) -> tuple[str | None, int | None]:
    trace = case.get("contract_trace") or {}
    for check in trace.get("pmp_checks") or []:
        if check.get("stage") not in {"ptw", "pte_ad_update"} or bool(check.get("allowed")):
            continue
        address = check.get("physical_address")
        parsed_address = int(address, 0) if isinstance(address, str) else int(address) if address is not None else None
        return check.get("ptw_level"), parsed_address
    return None, None


def _case_address(case: dict[str, Any]) -> int | None:
    address = case.get("address")
    if address is None:
        return None
    return int(address, 0) if isinstance(address, str) else int(address)


def _mepc_matches_probe_window(case: dict[str, Any], event: ObservedEvent) -> bool:
    if not all(key in case for key in ("access", "privilege", "translation")):
        return True
    address = _case_address(case)
    observed_page_tag = event.mepc_tag
    if case.get("access") == "fetch" and address is not None:
        return observed_page_tag == mepc_tag(address)
    if case.get("translation") == "sv39":
        return observed_page_tag == 0
    if str(case.get("profile") or "").startswith("legacy"):
        return observed_page_tag in {0, 1}
    if case.get("privilege") == "M":
        return observed_page_tag in {0, 1}
    return observed_page_tag == 4


def _expected_ecall_cause(case: dict[str, Any]) -> int | None:
    return {"U": 8, "S": 9, "M": 11}.get(case.get("privilege"))


def _failure(
    failure_class: str,
    reason: str,
    *,
    stage_verified: bool = False,
) -> ObservationJudgment:
    return ObservationJudgment("fail", failure_class, reason, True, stage_verified)


def _stateful_side_effect_judgment(
    case: dict[str, Any], event: ObservedEvent
) -> ObservationJudgment | None:
    sequence = case.get("stateful_sequence") or {}
    expected_final = sequence.get("expected_final")
    if expected_final == "store_side_effect":
        if event.phase != ObservationPhase.FINAL_SENTINEL_MODIFIED:
            return _failure(
                "missing_expected_side_effect",
                "final sentinel did not contain the probe store value",
                stage_verified=True,
            )
    elif expected_final == "trap_no_side_effect":
        if event.phase != ObservationPhase.FINAL_SENTINEL_INITIAL:
            return _failure(
                "forbidden_side_effect",
                "denied probe modified the final sentinel",
                stage_verified=True,
            )
    elif _expected_stage_is_stateful(case) and event.phase == ObservationPhase.FINAL_SENTINEL_OTHER:
        return _failure(
            "unexpected_side_effect_state",
            "final sentinel contained an unknown value",
            stage_verified=True,
        )
    return None


def _expected_stage_is_stateful(case: dict[str, Any]) -> bool:
    return str((case.get("expected") or {}).get("stage") or "") == "stateful_final"
