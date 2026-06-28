from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .pmp import Access, PmpModel, Privilege


PAGE_SIZE = 4096
SV39_MODE_VALUE = 8


class TranslationMode(Enum):
    BARE = "bare"
    SV39 = "sv39"


class PageFaultKind(Enum):
    NONE = "none"
    PAGE_FAULT = "page_fault"
    ACCESS_FAULT = "access_fault"


class TranslationStage(Enum):
    NONE = "none"
    PAGE_TABLE_WALK = "page_table_walk"
    PTE_PERMISSION = "pte_permission"
    FINAL_ACCESS = "final_access"


@dataclass(frozen=True)
class PageTableEntry:
    read: bool
    write: bool
    execute: bool
    user: bool
    accessed: bool
    dirty: bool
    valid: bool = True
    global_mapping: bool = False

    def flags(self) -> int:
        value = 0
        value |= 0x001 if self.valid else 0
        value |= 0x002 if self.read else 0
        value |= 0x004 if self.write else 0
        value |= 0x008 if self.execute else 0
        value |= 0x010 if self.user else 0
        value |= 0x020 if self.global_mapping else 0
        value |= 0x040 if self.accessed else 0
        value |= 0x080 if self.dirty else 0
        return value


@dataclass(frozen=True)
class Sv39Mapping:
    virtual_page: int
    physical_page: int
    root_table: int
    walk_addresses: tuple[int, ...]
    pte: PageTableEntry
    page_size: int = PAGE_SIZE

    def contains(self, virtual_address: int, size: int) -> bool:
        offset = virtual_address - self.virtual_page
        return offset >= 0 and offset + size <= self.page_size

    def physical_address_for(self, virtual_address: int) -> int:
        return self.physical_page + (virtual_address - self.virtual_page)


@dataclass(frozen=True)
class TranslationResult:
    allowed: bool
    kind: PageFaultKind
    stage: TranslationStage
    reason: str
    physical_address: int | None = None
    fault_address: int | None = None
    pmp_match_index: int | None = None


class Sv39Model:
    def __init__(self, *, mappings: list[Sv39Mapping], pmp_model: PmpModel) -> None:
        self.mappings = mappings
        self.pmp_model = pmp_model

    def check(
        self,
        *,
        privilege: Privilege,
        access: Access,
        virtual_address: int,
        size: int,
        sum_enabled: bool = False,
        mxr: bool = False,
    ) -> TranslationResult:
        mapping = self._mapping_for(virtual_address, size)
        if mapping is None:
            return TranslationResult(
                allowed=False,
                kind=PageFaultKind.PAGE_FAULT,
                stage=TranslationStage.PTE_PERMISSION,
                reason="no Sv39 mapping for virtual address",
                fault_address=virtual_address,
            )

        for walk_address in mapping.walk_addresses:
            pmp = self.pmp_model.check(
                privilege=Privilege.S,
                access=Access.LOAD,
                physical_address=walk_address,
                size=8,
            )
            if not pmp.allowed:
                return TranslationResult(
                    allowed=False,
                    kind=PageFaultKind.ACCESS_FAULT,
                    stage=TranslationStage.PAGE_TABLE_WALK,
                    reason=f"page-table walk blocked by PMP: {pmp.reason}",
                    fault_address=walk_address,
                    pmp_match_index=pmp.match_index,
                )

        if not self._pte_allows(mapping.pte, privilege, access, sum_enabled, mxr):
            return TranslationResult(
                allowed=False,
                kind=PageFaultKind.PAGE_FAULT,
                stage=TranslationStage.PTE_PERMISSION,
                reason="Sv39 PTE permissions deny access",
                fault_address=virtual_address,
            )

        physical_address = mapping.physical_address_for(virtual_address)
        pmp = self.pmp_model.check(
            privilege=privilege,
            access=access,
            physical_address=physical_address,
            size=size,
        )
        if not pmp.allowed:
            return TranslationResult(
                allowed=False,
                kind=PageFaultKind.ACCESS_FAULT,
                stage=TranslationStage.FINAL_ACCESS,
                reason=f"final physical access blocked by PMP: {pmp.reason}",
                physical_address=physical_address,
                fault_address=physical_address,
                pmp_match_index=pmp.match_index,
            )

        return TranslationResult(
            allowed=True,
            kind=PageFaultKind.NONE,
            stage=TranslationStage.NONE,
            reason="Sv39 translation and PMP checks permit access",
            physical_address=physical_address,
            pmp_match_index=pmp.match_index,
        )

    def _mapping_for(self, virtual_address: int, size: int) -> Sv39Mapping | None:
        for mapping in self.mappings:
            if mapping.contains(virtual_address, size):
                return mapping
        return None

    def _pte_allows(
        self,
        pte: PageTableEntry,
        privilege: Privilege,
        access: Access,
        sum_enabled: bool,
        mxr: bool,
    ) -> bool:
        if not pte.valid or (pte.write and not pte.read) or not pte.accessed:
            return False
        if access == Access.STORE and (not pte.write or not pte.dirty):
            return False

        if privilege == Privilege.U and not pte.user:
            return False
        if privilege == Privilege.S and pte.user:
            if access == Access.FETCH:
                return False
            if not sum_enabled:
                return False

        if access == Access.LOAD:
            return pte.read or (mxr and pte.execute)
        if access == Access.STORE:
            return pte.write
        if access == Access.FETCH:
            return pte.execute
        raise ValueError(f"unsupported access type: {access}")


def sv39_indices(virtual_address: int) -> tuple[int, int, int]:
    return (
        (virtual_address >> 30) & 0x1FF,
        (virtual_address >> 21) & 0x1FF,
        (virtual_address >> 12) & 0x1FF,
    )


def pte_value(physical_page: int, pte: PageTableEntry) -> int:
    return ((physical_page >> 12) << 10) | pte.flags()


def pointer_pte_value(physical_page: int) -> int:
    return ((physical_page >> 12) << 10) | 0x1
