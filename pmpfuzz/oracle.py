from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from .mmu import PageFaultKind, Sv39Model, TranslationMode, TranslationStage
from .pmp import Access, PmpModel
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
