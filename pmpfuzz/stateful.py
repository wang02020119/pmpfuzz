from __future__ import annotations

from dataclasses import replace

from .mmu import TranslationMode
from .pmp import Access, AddressMode, PmpEntry
from .scenario import PAGE_TABLE_BASE, PmpScenario


_SEQUENCE_BASE_KEYS = frozenset(
    {
        "kind",
        "warmup",
        "warmup_access",
        "mutation",
        "fence",
        "final_probe",
        "sentinel",
        "expected_final",
        "expected_cause",
        "stale_failure_class",
    }
)


def canonical_stateful_sequence(scenario: PmpScenario) -> dict[str, object] | None:
    sequence = scenario.stateful_sequence
    if not sequence:
        return None
    normalized = {
        key: value
        for key, value in dict(sequence).items()
        if key in _SEQUENCE_BASE_KEYS
    }
    mutation = str(normalized.get("mutation") or "none")
    normalized["mutation"] = mutation
    normalized["warmup"] = bool(normalized.get("warmup"))
    warmup_access = normalized.get("warmup_access")
    normalized["warmup_access"] = str(warmup_access or "").lower() or None
    normalized["fence"] = str(normalized.get("fence") or "none")
    if not normalized["warmup"]:
        normalized["fence"] = "none"

    if mutation == "pmpcfg-deny-target":
        normalized.update(_pmp_mutation_payload(scenario, deny_target=True, deny_ptw=False))
    elif mutation == "pmpcfg-deny-ptw":
        normalized.update(_pmp_mutation_payload(scenario, deny_target=False, deny_ptw=True))
    elif mutation == "pte-deny-leaf" and scenario.sv39 is not None:
        normalized["pte_after"] = "0x0"
    return normalized


def apply_canonical_stateful_transition(scenario: PmpScenario) -> PmpScenario:
    sequence = canonical_stateful_sequence(scenario)
    if not sequence:
        return scenario
    mutation = str(sequence.get("mutation") or "none")
    if mutation == "none":
        return replace(scenario, stateful_sequence=sequence)

    if mutation == "pte-deny-leaf":
        if scenario.sv39 is None:
            return replace(scenario, stateful_sequence=sequence)
        pte = replace(
            scenario.sv39.pte,
            read=False,
            write=False,
            execute=False,
            user=False,
            accessed=False,
            dirty=False,
            valid=False,
            global_mapping=False,
        )
        return replace(
            scenario,
            sv39=replace(scenario.sv39, pte=pte),
            stateful_sequence=sequence,
        )

    pmpaddr_by_index: dict[int, int] = {}
    for write in sequence.get("pmpaddr_writes") or []:
        if not isinstance(write, dict):
            continue
        index = write.get("index")
        value = write.get("pmpaddr")
        if type(index) is not int:
            continue
        if isinstance(value, str):
            pmpaddr_by_index[index] = int(value, 16)
        elif type(value) is int:
            pmpaddr_by_index[index] = value

    cfg_after_raw = sequence.get("pmpcfg0_after")
    cfg_after = None
    if isinstance(cfg_after_raw, str):
        cfg_after = int(cfg_after_raw, 16)
    elif type(cfg_after_raw) is int:
        cfg_after = cfg_after_raw

    updated_entries: list[PmpEntry] = []
    for entry in scenario.entries:
        cfg_byte = entry.cfg_byte() if cfg_after is None else (cfg_after >> (entry.index * 8)) & 0xFF
        updated_entries.append(
            PmpEntry(
                index=entry.index,
                address_mode=AddressMode((cfg_byte >> 3) & 0x3),
                pmpaddr=pmpaddr_by_index.get(entry.index, entry.pmpaddr),
                read=bool(cfg_byte & 0x01),
                write=bool(cfg_byte & 0x02),
                execute=bool(cfg_byte & 0x04),
                locked=bool(cfg_byte & 0x80),
            )
        )
    return replace(
        scenario,
        entries=updated_entries,
        stateful_sequence=sequence,
    )


def validate_stateful_contract(scenario: PmpScenario) -> tuple[bool, str]:
    sequence = canonical_stateful_sequence(scenario)
    if not sequence:
        return True, ""

    mutation = str(sequence.get("mutation") or "none")
    warmup = bool(sequence.get("warmup"))
    if mutation == "pte-deny-leaf" and scenario.translation != TranslationMode.SV39:
        return False, "pte-deny-leaf requires Sv39 translation"
    if scenario.probe.access == Access.STORE:
        store_valid, store_reason = _validate_stateful_store_probe(scenario, sequence)
        if not store_valid:
            return False, store_reason
    if not warmup:
        return True, ""
    warmup_access_raw = sequence.get("warmup_access")
    warmup_access = scenario.probe.access if warmup_access_raw is None else Access(str(warmup_access_raw))
    if scenario.probe.access == Access.STORE and warmup_access == Access.STORE:
        return False, "store warmup would clobber the sentinel before mutation"

    from .oracle import evaluate_scenario

    initial = evaluate_scenario(replace(scenario, probe=replace(scenario.probe, access=warmup_access)))
    if not initial.allowed:
        return False, "warmup requires an initially allowed probe before mutation"
    return True, ""


def _validate_stateful_store_probe(
    scenario: PmpScenario,
    sequence: dict[str, object],
) -> tuple[bool, str]:
    if scenario.probe.size != 4:
        return False, "stateful store probe must be a naturally aligned 4-byte single memory operation"
    if scenario.probe.physical_address % scenario.probe.size != 0:
        return False, "stateful store probe must be naturally aligned in physical address"
    if scenario.probe.virtual_address is not None and scenario.probe.virtual_address % scenario.probe.size != 0:
        return False, "stateful store probe must be naturally aligned in virtual address"

    sentinel = sequence.get("sentinel") or {}
    sentinel_physical = _parse_address((sentinel.get("physical_address") if isinstance(sentinel, dict) else None))
    if sentinel_physical is None:
        return False, "stateful store probe requires sentinel physical address metadata"
    if scenario.probe.physical_address != sentinel_physical:
        return False, "stateful store probe must target the sentinel physical address"
    return True, ""


def _parse_address(value: object) -> int | None:
    if isinstance(value, str):
        return int(value, 16)
    if type(value) is int:
        return value
    return None


def _pmp_mutation_payload(
    scenario: PmpScenario,
    *,
    deny_target: bool,
    deny_ptw: bool,
) -> dict[str, object]:
    after = list(scenario.entries)
    writes: list[dict[str, object]] = []
    if deny_target:
        target_entry = _find_entry_for_access(
            scenario.entries,
            physical_address=scenario.probe.physical_address,
            size=scenario.probe.size,
        )
        if target_entry is not None:
            after = [
                _deny_entry(entry) if entry.index == target_entry.index else entry
                for entry in after
            ]
    if deny_ptw:
        walk_address, walk_size = _ptw_deny_region(scenario)
        deny_entry = _precise_ptw_deny_entry(after, walk_address=walk_address, walk_size=walk_size)
        if deny_entry is not None:
            after = [deny_entry if entry.index == deny_entry.index else entry for entry in after]
            writes.append({"index": deny_entry.index, "pmpaddr": f"0x{deny_entry.pmpaddr:x}"})
        else:
            ptw_entry = _find_entry_for_access(
                scenario.entries,
                physical_address=walk_address,
                size=walk_size,
            )
            if ptw_entry is not None:
                after = [
                    _deny_entry(entry) if entry.index == ptw_entry.index else entry
                    for entry in after
                ]
    return {
        "pmpaddr_writes": writes,
        "pmpcfg0_after": f"0x{_pmpcfg0(after):x}",
    }


def _ptw_deny_region(scenario: PmpScenario) -> tuple[int, int]:
    if scenario.sv39 is None:
        return PAGE_TABLE_BASE + 0x3000, 0x1000
    level = str(scenario.ptw_fault_level or "L1").upper()
    if level == "L2":
        return scenario.sv39.walk_addresses[0], 8
    if level == "L0":
        return scenario.sv39.walk_addresses[2], 0x1000
    return scenario.sv39.walk_addresses[1], 0x1000


def _precise_ptw_deny_entry(
    entries: list[PmpEntry],
    *,
    walk_address: int,
    walk_size: int,
) -> PmpEntry | None:
    off_entry = next(
        (
            candidate
            for candidate in sorted(entries, key=lambda candidate: candidate.index)
            if candidate.address_mode == AddressMode.OFF
        ),
        None,
    )
    if off_entry is None:
        return None
    deny_base = walk_address if walk_size == 8 else walk_address & ~0xFFF
    return PmpEntry(
        index=off_entry.index,
        address_mode=AddressMode.NAPOT,
        pmpaddr=PmpEntry.encode_napot(base=deny_base, size=walk_size),
        read=False,
        write=False,
        execute=False,
        locked=False,
    )


def _pmpcfg0(entries: list[PmpEntry]) -> int:
    cfg0 = 0
    for entry in entries:
        cfg0 |= entry.cfg_byte() << (entry.index * 8)
    return cfg0


def _deny_entry(entry: PmpEntry) -> PmpEntry:
    return PmpEntry(
        index=entry.index,
        address_mode=entry.address_mode,
        pmpaddr=entry.pmpaddr,
        read=False,
        write=False,
        execute=False,
        locked=entry.locked,
    )


def _find_entry_for_access(
    entries: list[PmpEntry],
    *,
    physical_address: int,
    size: int,
) -> PmpEntry | None:
    sorted_entries = sorted(entries, key=lambda entry: entry.index)
    access_upper = physical_address + size
    by_index = {entry.index: entry for entry in sorted_entries}
    for entry in sorted_entries:
        bounds = _entry_bounds(by_index, entry)
        if bounds is None:
            continue
        lower, upper = bounds
        if lower < access_upper and physical_address < upper:
            return entry
    return None


def _entry_bounds(entries_by_index: dict[int, PmpEntry], entry: PmpEntry) -> tuple[int, int] | None:
    if entry.address_mode == AddressMode.OFF:
        return None
    if entry.address_mode == AddressMode.TOR:
        previous_addr = 0
        if entry.index > 0:
            previous = entries_by_index.get(entry.index - 1)
            previous_addr = previous.pmpaddr if previous is not None else 0
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


def _trailing_ones(value: int) -> int:
    count = 0
    while value & (1 << count):
        count += 1
    return count
