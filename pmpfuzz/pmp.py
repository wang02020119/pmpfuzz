from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Access(Enum):
    LOAD = "load"
    STORE = "store"
    FETCH = "fetch"


class AddressMode(Enum):
    OFF = 0
    TOR = 1
    NA4 = 2
    NAPOT = 3


class Privilege(Enum):
    U = "U"
    S = "S"
    M = "M"


@dataclass(frozen=True)
class Mseccfg:
    rlb: bool = False
    mmwp: bool = False
    mml: bool = False


@dataclass(frozen=True)
class PmpEntry:
    index: int
    address_mode: AddressMode
    pmpaddr: int
    read: bool
    write: bool
    execute: bool
    locked: bool

    @staticmethod
    def encode_napot(base: int, size: int) -> int:
        if size < 8 or size & (size - 1):
            raise ValueError("NAPOT size must be a power of two and at least 8 bytes")
        if base % size:
            raise ValueError("NAPOT base must be naturally aligned to size")
        return (base >> 2) | ((size - 1) >> 3)

    def cfg_byte(self) -> int:
        value = 0
        value |= 0x01 if self.read else 0
        value |= 0x02 if self.write else 0
        value |= 0x04 if self.execute else 0
        value |= self.address_mode.value << 3
        value |= 0x80 if self.locked else 0
        return value


@dataclass(frozen=True)
class PmpDecision:
    allowed: bool
    reason: str
    effective_privilege: Privilege
    match_index: int | None


class PmpModel:
    def __init__(
        self,
        entries: list[PmpEntry] | None = None,
        mseccfg: Mseccfg | None = None,
    ) -> None:
        self.entries = sorted(entries or [], key=lambda entry: entry.index)
        self.mseccfg = mseccfg or Mseccfg()

    def check(
        self,
        *,
        privilege: Privilege,
        access: Access,
        physical_address: int,
        size: int,
        mprv: bool = False,
        mpp: Privilege = Privilege.M,
    ) -> PmpDecision:
        if size <= 0:
            raise ValueError("access size must be positive")
        effective = self._effective_privilege(privilege, access, mprv, mpp)
        match = self._first_matching_entry(physical_address, size)

        if match is None:
            return self._unmatched_decision(effective)

        if not self._entry_contains(match, physical_address, size):
            return PmpDecision(
                False,
                "lowest-numbered matching entry only partially covers access",
                effective,
                match.index,
            )

        allowed = self._entry_allows(match, effective, access)
        if allowed:
            return PmpDecision(True, "matching entry permits access", effective, match.index)
        return PmpDecision(False, "matching entry denies access by permission", effective, match.index)

    def _effective_privilege(
        self,
        privilege: Privilege,
        access: Access,
        mprv: bool,
        mpp: Privilege,
    ) -> Privilege:
        if mprv and access in {Access.LOAD, Access.STORE} and privilege == Privilege.M:
            return mpp
        return privilege

    def _first_matching_entry(self, physical_address: int, size: int) -> PmpEntry | None:
        for entry in self.entries:
            if self._entry_matches(entry, physical_address, size):
                return entry
        return None

    def _entry_matches(self, entry: PmpEntry, physical_address: int, size: int) -> bool:
        if entry.address_mode == AddressMode.OFF:
            return False

        bounds = self._entry_bounds(entry)
        if bounds is None:
            return False

        lower, upper = bounds
        access_upper = physical_address + size
        return lower < access_upper and physical_address < upper

    def _entry_contains(self, entry: PmpEntry, physical_address: int, size: int) -> bool:
        bounds = self._entry_bounds(entry)
        if bounds is None:
            return False
        lower, upper = bounds
        return lower <= physical_address and physical_address + size <= upper

    def _entry_bounds(self, entry: PmpEntry) -> tuple[int, int] | None:
        if entry.address_mode == AddressMode.TOR:
            previous_addr = 0
            if entry.index > 0:
                previous = self._entry_by_index(entry.index - 1)
                previous_addr = previous.pmpaddr if previous else 0
            lower = previous_addr << 2
            upper = entry.pmpaddr << 2
            if upper <= lower:
                return None
            return lower, upper

        if entry.address_mode == AddressMode.NA4:
            lower = entry.pmpaddr << 2
            return lower, lower + 4

        if entry.address_mode == AddressMode.NAPOT:
            ones = _trailing_ones(entry.pmpaddr)
            size = 1 << (ones + 3)
            lower = (entry.pmpaddr & ~((1 << ones) - 1)) << 2
            return lower, lower + size

        return None

    def _entry_by_index(self, index: int) -> PmpEntry | None:
        for entry in self.entries:
            if entry.index == index:
                return entry
        return None

    def _unmatched_decision(self, effective: Privilege) -> PmpDecision:
        if effective == Privilege.M and not self.mseccfg.mmwp:
            return PmpDecision(True, "unmatched M-mode access is allowed", effective, None)
        if effective == Privilege.M and self.mseccfg.mmwp:
            return PmpDecision(False, "unmatched M-mode access denied by Smepmp MMWP", effective, None)
        return PmpDecision(False, "unmatched S/U access denied by default", effective, None)

    def _entry_allows(self, entry: PmpEntry, effective: Privilege, access: Access) -> bool:
        if self.mseccfg.mml:
            return self._entry_allows_mml(entry, effective, access)

        if entry.write and not entry.read:
            return False

        if effective == Privilege.M and not entry.locked:
            return True
        return self._permission_bit(entry, access)

    def _entry_allows_mml(self, entry: PmpEntry, effective: Privilege, access: Access) -> bool:
        l, r, w, x = entry.locked, entry.read, entry.write, entry.execute

        if not l:
            if not r and w:
                if x:
                    return access in {Access.LOAD, Access.STORE}
                if effective == Privilege.M:
                    return access in {Access.LOAD, Access.STORE}
                return access == Access.LOAD
            if effective == Privilege.M:
                return False
            return self._permission_bit(entry, access)

        if not r and w:
            if not x:
                return access == Access.FETCH
            if effective == Privilege.M:
                return access in {Access.LOAD, Access.FETCH}
            return access == Access.FETCH

        if r and w and x:
            return access == Access.LOAD

        if effective != Privilege.M:
            return False
        return self._permission_bit(entry, access)

    def _permission_bit(self, entry: PmpEntry, access: Access) -> bool:
        if access == Access.LOAD:
            return entry.read
        if access == Access.STORE:
            return entry.write
        if access == Access.FETCH:
            return entry.execute
        raise ValueError(f"unsupported access type: {access}")


def _trailing_ones(value: int) -> int:
    count = 0
    while value & (1 << count):
        count += 1
    return count
