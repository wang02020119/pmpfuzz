from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from .mmu import PageFaultKind, Sv39Model, TranslationMode, TranslationStage
from .pmp import Access, PmpDecision, PmpEntry, PmpModel, Privilege
from .scenario import PmpScenario


class TrapCause(IntEnum):
    INSTRUCTION_ADDRESS_MISALIGNED = 0
    INSTRUCTION_ACCESS_FAULT = 1
    LOAD_ADDRESS_MISALIGNED = 4
    LOAD_ACCESS_FAULT = 5
    STORE_ADDRESS_MISALIGNED = 6
    STORE_ACCESS_FAULT = 7
    ECALL_FROM_U = 8
    ECALL_FROM_S = 9
    ECALL_FROM_M = 11
    INSTRUCTION_PAGE_FAULT = 12
    LOAD_PAGE_FAULT = 13
    STORE_PAGE_FAULT = 15


@dataclass(frozen=True)
class ExpectedOutcome:
    allowed: bool
    trap_cause: TrapCause | None
    stage: str
    reason: str
    physical_address: int | None = None


def evaluate_scenario(scenario: PmpScenario) -> ExpectedOutcome:
    pmp_model = PmpModel(scenario.entries, scenario.mseccfg)
    probe_address = scenario.probe.effective_address()
    if _is_misaligned(probe_address, scenario.probe.size):
        return ExpectedOutcome(
            allowed=False,
            trap_cause=_misaligned_cause(scenario.probe.access),
            stage="address_misaligned",
            reason="access address is not naturally aligned",
            physical_address=scenario.probe.physical_address,
        )

    if scenario.translation == TranslationMode.SV39:
        if scenario.sv39 is None:
            raise ValueError("Sv39 scenario requires sv39 mapping metadata")
        address = scenario.probe.virtual_address
        if address is None:
            raise ValueError("Sv39 scenario requires a virtual probe address")
        result = Sv39Model(mappings=[scenario.sv39], pmp_model=pmp_model).check(
            privilege=scenario.privilege,
            access=scenario.probe.access,
            virtual_address=address,
            size=scenario.probe.size,
            sum_enabled=scenario.sum_enabled,
            mxr=scenario.mxr,
        )
        if result.allowed:
            return ExpectedOutcome(
                allowed=True,
                trap_cause=None,
                stage="none",
                reason=result.reason,
                physical_address=result.physical_address,
            )
        if result.kind == PageFaultKind.PAGE_FAULT:
            return ExpectedOutcome(
                allowed=False,
                trap_cause=_page_fault_cause(scenario.probe.access),
                stage=result.stage.value,
                reason=result.reason,
                physical_address=result.physical_address,
            )
        return ExpectedOutcome(
            allowed=False,
            trap_cause=_access_fault_cause(scenario.probe.access),
            stage=result.stage.value,
            reason=result.reason,
            physical_address=result.physical_address,
        )

    decision = pmp_model.check(
        privilege=scenario.privilege,
        access=scenario.probe.access,
        physical_address=scenario.probe.physical_address,
        size=scenario.probe.size,
        mprv=scenario.mprv,
        mpp=scenario.mpp,
    )
    if decision.allowed:
        return ExpectedOutcome(
            allowed=True,
            trap_cause=None,
            stage="none",
            reason=decision.reason,
            physical_address=scenario.probe.physical_address,
        )
    return ExpectedOutcome(
        allowed=False,
        trap_cause=_access_fault_cause(scenario.probe.access),
        stage="pmp",
        reason=decision.reason,
        physical_address=scenario.probe.physical_address,
    )


def contract_trace_for_scenario(scenario: PmpScenario) -> dict[str, object]:
    outcome = evaluate_scenario(scenario)
    trace: dict[str, object] = {
        "schema_version": 1,
        "privilege": scenario.privilege.value,
        "access": scenario.probe.access.value,
        "translation_mode": scenario.translation.value,
        "translation_stage": _trace_translation_stage(scenario, outcome),
        "trap_priority": _trace_trap_priority(outcome),
        "effective_privilege": scenario.privilege.value,
        "pmp_checks": [],
        "pte_decision": {"decision": "not_applicable"},
        "side_effect_policy": _side_effect_policy(scenario, outcome),
        "stateful": _stateful_trace(scenario),
    }
    if outcome.trap_cause is not None:
        trace["expected_trap_cause"] = int(outcome.trap_cause)

    pmp_model = PmpModel(scenario.entries, scenario.mseccfg)
    probe_address = scenario.probe.effective_address()
    if _is_misaligned(probe_address, scenario.probe.size):
        return trace

    if scenario.translation == TranslationMode.BARE:
        decision = pmp_model.check(
            privilege=scenario.privilege,
            access=scenario.probe.access,
            physical_address=scenario.probe.physical_address,
            size=scenario.probe.size,
            mprv=scenario.mprv,
            mpp=scenario.mpp,
        )
        trace["effective_privilege"] = decision.effective_privilege.value
        trace["pmp_checks"] = [
            _pmp_check_trace(
                stage="bare",
                decision=decision,
                entries=scenario.entries,
                access=scenario.probe.access,
                physical_address=scenario.probe.physical_address,
                size=scenario.probe.size,
            )
        ]
        return trace

    if scenario.sv39 is None or scenario.probe.virtual_address is None:
        return trace

    pmp_checks: list[dict[str, object]] = []
    for level, walk_address in zip(("L2", "L1", "L0"), scenario.sv39.walk_addresses):
        decision = pmp_model.check(
            privilege=Privilege.S,
            access=Access.LOAD,
            physical_address=walk_address,
            size=8,
        )
        pmp_checks.append(
            _pmp_check_trace(
                stage="ptw",
                decision=decision,
                entries=scenario.entries,
                access=Access.LOAD,
                physical_address=walk_address,
                size=8,
                ptw_level=level,
            )
        )
        if not decision.allowed:
            trace["effective_privilege"] = decision.effective_privilege.value
            trace["pmp_checks"] = pmp_checks
            trace["pte_decision"] = {"decision": "not_evaluated"}
            return trace

    pte_decision = _pte_decision_trace(scenario)
    trace["pte_decision"] = pte_decision
    if pte_decision["decision"] != "ok":
        trace["effective_privilege"] = scenario.privilege.value
        trace["pmp_checks"] = pmp_checks
        return trace

    physical_address = scenario.sv39.physical_address_for(scenario.probe.virtual_address)
    final_decision = pmp_model.check(
        privilege=scenario.privilege,
        access=scenario.probe.access,
        physical_address=physical_address,
        size=scenario.probe.size,
    )
    pmp_checks.append(
        _pmp_check_trace(
            stage="final",
            decision=final_decision,
            entries=scenario.entries,
            access=scenario.probe.access,
            physical_address=physical_address,
            size=scenario.probe.size,
        )
    )
    trace["effective_privilege"] = final_decision.effective_privilege.value
    trace["pmp_checks"] = pmp_checks
    return trace


def _access_fault_cause(access: Access) -> TrapCause:
    if access == Access.LOAD:
        return TrapCause.LOAD_ACCESS_FAULT
    if access == Access.STORE:
        return TrapCause.STORE_ACCESS_FAULT
    if access == Access.FETCH:
        return TrapCause.INSTRUCTION_ACCESS_FAULT
    raise ValueError(f"unsupported access type: {access}")


def _misaligned_cause(access: Access) -> TrapCause:
    if access == Access.LOAD:
        return TrapCause.LOAD_ADDRESS_MISALIGNED
    if access == Access.STORE:
        return TrapCause.STORE_ADDRESS_MISALIGNED
    if access == Access.FETCH:
        return TrapCause.INSTRUCTION_ADDRESS_MISALIGNED
    raise ValueError(f"unsupported access type: {access}")


def _is_misaligned(address: int, size: int) -> bool:
    if size <= 1:
        return False
    return address % size != 0


def _page_fault_cause(access: Access) -> TrapCause:
    if access == Access.LOAD:
        return TrapCause.LOAD_PAGE_FAULT
    if access == Access.STORE:
        return TrapCause.STORE_PAGE_FAULT
    if access == Access.FETCH:
        return TrapCause.INSTRUCTION_PAGE_FAULT
    raise ValueError(f"unsupported access type: {access}")


def _trace_translation_stage(scenario: PmpScenario, outcome: ExpectedOutcome) -> str:
    if scenario.translation == TranslationMode.BARE:
        return "none"
    if outcome.stage == "none":
        return "final_access"
    return outcome.stage


def _trace_trap_priority(outcome: ExpectedOutcome) -> str:
    if outcome.allowed:
        return "none"
    if outcome.stage == "address_misaligned":
        return "misaligned"
    if outcome.stage == TranslationStage.PTE_PERMISSION.value:
        return "page_fault"
    return "access_fault"


def _pmp_check_trace(
    *,
    stage: str,
    decision: PmpDecision,
    entries: list[PmpEntry],
    access: Access,
    physical_address: int,
    size: int,
    ptw_level: str | None = None,
) -> dict[str, object]:
    entry = _entry_by_index(entries, decision.match_index)
    trace: dict[str, object] = {
        "stage": stage,
        "access": access.value,
        "physical_address": f"0x{physical_address:x}",
        "size": size,
        "effective_privilege": decision.effective_privilege.value,
        "match_index": decision.match_index,
        "match_mode": entry.address_mode.name.lower() if entry else "no-match",
        "allowed": decision.allowed,
        "reason": decision.reason,
    }
    if ptw_level is not None:
        trace["ptw_level"] = ptw_level
    return trace


def _entry_by_index(entries: list[PmpEntry], index: int | None) -> PmpEntry | None:
    if index is None:
        return None
    for entry in entries:
        if entry.index == index:
            return entry
    return None


def _pte_decision_trace(scenario: PmpScenario) -> dict[str, object]:
    if scenario.sv39 is None:
        return {"decision": "not_applicable"}
    pte = scenario.sv39.pte
    base = {
        "rwx": ("r" if pte.read else "-") + ("w" if pte.write else "-") + ("x" if pte.execute else "-"),
        "user": pte.user,
        "accessed": pte.accessed,
        "dirty": pte.dirty,
        "valid": pte.valid,
        "sum": scenario.sum_enabled,
        "mxr": scenario.mxr,
    }
    if not pte.valid:
        return {"decision": "invalid", **base}
    if pte.write and not pte.read:
        return {"decision": "reserved_write_without_read", **base}
    if not pte.accessed:
        return {"decision": "accessed", **base}
    if scenario.probe.access == Access.STORE and not pte.write:
        return {"decision": "permission", **base}
    if scenario.probe.access == Access.STORE and not pte.dirty:
        return {"decision": "dirty", **base}
    if scenario.privilege == Privilege.U and not pte.user:
        return {"decision": "user", **base}
    if scenario.privilege == Privilege.S and pte.user and scenario.probe.access == Access.FETCH:
        return {"decision": "user", **base}
    if scenario.privilege == Privilege.S and pte.user and not scenario.sum_enabled:
        return {"decision": "sum", **base}
    if scenario.probe.access == Access.LOAD and not (pte.read or (scenario.mxr and pte.execute)):
        return {"decision": "permission", **base}
    if scenario.probe.access == Access.FETCH and not pte.execute:
        return {"decision": "permission", **base}
    return {"decision": "ok", **base}


def _side_effect_policy(scenario: PmpScenario, outcome: ExpectedOutcome) -> str:
    if scenario.probe.access != Access.STORE:
        return "not_applicable"
    sequence = scenario.stateful_sequence or {}
    if sequence:
        return "allowed" if sequence.get("expected_final") == "store_side_effect" else "forbidden"
    return "allowed" if outcome.allowed else "forbidden"


def _stateful_trace(scenario: PmpScenario) -> dict[str, object] | None:
    sequence = scenario.stateful_sequence
    if not sequence:
        return None
    return {
        "kind": sequence.get("kind"),
        "warmup": sequence.get("warmup"),
        "mutation": sequence.get("mutation"),
        "fence": sequence.get("fence"),
        "final_probe": sequence.get("final_probe"),
        "expected_final": sequence.get("expected_final"),
        "expected_cause": sequence.get("expected_cause"),
        "stale_failure_class": sequence.get("stale_failure_class"),
    }
