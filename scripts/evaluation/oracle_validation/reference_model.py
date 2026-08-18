from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from pmpfuzz.mmu import AdUpdateMode, PageTableEntry, Sv39Mapping, TranslationMode
from pmpfuzz.pmp import Access, AddressMode, Mseccfg, PmpEntry, Privilege
from pmpfuzz.scenario import PmpScenario
from pmpfuzz.scenario_codec import scenario_from_spec, scenario_hash


PRIMARY_SPEC_REVISION = "RISC-V Privileged Architecture Manual (pinned by experiment contract)"


@dataclass(frozen=True)
class ReferenceOutcome:
    allowed: bool
    trap_cause: int | None
    stage: str
    ptw_level: str | None
    fault_address: int | None
    physical_address: int | None
    side_effect: str
    spec_clause: str
    rationale: str


def build_reference_label(
    case_record: Mapping[str, Any],
    *,
    spec_revision: str = PRIMARY_SPEC_REVISION,
) -> dict[str, Any]:
    scenario_spec = case_record.get("scenario_spec")
    if not isinstance(scenario_spec, Mapping):
        raise ValueError("case_record missing scenario_spec")
    scenario = scenario_from_spec(dict(scenario_spec))
    if not isinstance(scenario, PmpScenario):
        raise TypeError(f"expected PmpScenario, got {type(scenario).__name__}")

    outcome = evaluate_reference_scenario(scenario)
    case_id = str(case_record.get("case_id") or "")
    family = str(case_record.get("family") or "")
    return {
        "schema_version": 1,
        "case_id": case_id,
        "family": family,
        "profile": scenario.profile,
        "scenario_hash": scenario_hash(dict(scenario_spec)),
        "access_type": scenario.probe.access.value,
        "privilege": scenario.privilege.value,
        "translation_mode": scenario.translation.value,
        "applicability": _reference_applicability(case_record, scenario),
        "expected_allowed": outcome.allowed,
        "expected_trap_cause": outcome.trap_cause,
        "expected_stage": outcome.stage,
        "expected_ptw_level": outcome.ptw_level,
        "expected_fault_address": _format_optional_hex(outcome.fault_address),
        "expected_physical_address": _format_optional_hex(outcome.physical_address),
        "expected_side_effect": outcome.side_effect,
        "expected_failure_if_violated": _expected_failure_if_violated(outcome),
        "spec_revision": spec_revision,
        "spec_clause": outcome.spec_clause,
        "rationale": outcome.rationale,
    }


def _reference_applicability(case_record: Mapping[str, Any], scenario: PmpScenario) -> str:
    if scenario.profile == "legacy-fetch-experimental":
        return "experimental"
    sequence = scenario.stateful_sequence or {}
    if str(sequence.get("fence") or "") == "no-fence-experimental":
        return "experimental"
    tags = {str(item) for item in (case_record.get("coverage_tags") or ())}
    if "no-fence-experimental" in tags:
        return "experimental"
    return "applicable"


def evaluate_reference_scenario(scenario: PmpScenario) -> ReferenceOutcome:
    if scenario.stateful_sequence:
        transitioned = _apply_stateful_transition(scenario)
        final = _evaluate_transient_scenario(transitioned)
        side_effect = _expected_side_effect(transitioned, final)
        return replace(
            final,
            stage="stateful_final" if final.stage == "none" else final.stage,
            side_effect=side_effect,
            spec_clause=_join_clauses(
                final.spec_clause,
                "state-transition and memory-side-effect contract",
            ),
            rationale=f"stateful final probe after frozen transition: {final.rationale}",
        )
    final = _evaluate_transient_scenario(scenario)
    return replace(final, side_effect=_expected_side_effect(scenario, final))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        import json

        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError(f"expected object JSONL row in {path}")
        records.append(payload)
    return records


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _evaluate_transient_scenario(scenario: PmpScenario) -> ReferenceOutcome:
    if _is_misaligned(scenario.probe.effective_address(), scenario.probe.size):
        return ReferenceOutcome(
            allowed=False,
            trap_cause=_misaligned_trap_cause(scenario.probe.access),
            stage="address_misaligned",
            ptw_level=None,
            fault_address=scenario.probe.effective_address(),
            physical_address=scenario.probe.physical_address,
            side_effect="not_applicable",
            spec_clause="misaligned-address exception priority and fault reporting",
            rationale="access address is not naturally aligned for the probe size",
        )

    if scenario.translation == TranslationMode.BARE:
        decision = _check_pmp(
            entries=scenario.entries,
            mseccfg=scenario.mseccfg,
            privilege=scenario.privilege,
            access=scenario.probe.access,
            physical_address=scenario.probe.physical_address,
            size=scenario.probe.size,
            mprv=scenario.mprv,
            mpp=scenario.mpp,
        )
        if decision.allowed:
            return ReferenceOutcome(
                allowed=True,
                trap_cause=None,
                stage="none",
                ptw_level=None,
                fault_address=None,
                physical_address=scenario.probe.physical_address,
                side_effect="not_applicable",
                spec_clause="PMP address matching and permission check",
                rationale=decision.rationale,
            )
        return ReferenceOutcome(
            allowed=False,
            trap_cause=_access_fault_cause(scenario.probe.access),
            stage="pmp",
            ptw_level=None,
            fault_address=scenario.probe.physical_address,
            physical_address=scenario.probe.physical_address,
            side_effect="not_applicable",
            spec_clause="PMP address matching and permission check",
            rationale=decision.rationale,
        )

    if scenario.sv39 is None or scenario.probe.virtual_address is None:
        raise ValueError("Sv39 scenario requires mapping metadata and virtual probe address")
    return _check_sv39(scenario)


@dataclass(frozen=True)
class _Decision:
    allowed: bool
    effective_privilege: Privilege
    match_index: int | None
    rationale: str


def _check_pmp(
    *,
    entries: list[PmpEntry],
    mseccfg: Mseccfg,
    privilege: Privilege,
    access: Access,
    physical_address: int,
    size: int,
    mprv: bool,
    mpp: Privilege,
) -> _Decision:
    if size <= 0:
        raise ValueError("access size must be positive")
    effective = _effective_privilege(privilege, access, mprv, mpp)
    ordered_entries = sorted(entries, key=lambda item: item.index)
    match = _first_matching_entry(ordered_entries, physical_address, size)

    if match is None:
        if effective == Privilege.M and not mseccfg.mmwp:
            return _Decision(True, effective, None, "unmatched M-mode access is allowed")
        if effective == Privilege.M and mseccfg.mmwp:
            return _Decision(False, effective, None, "unmatched M-mode access denied by Smepmp MMWP")
        return _Decision(False, effective, None, "unmatched S/U access denied by default")

    if not _entry_contains(ordered_entries, match, physical_address, size):
        return _Decision(
            False,
            effective,
            match.index,
            "lowest-numbered matching entry only partially covers the access",
        )

    if _entry_allows(match, effective, access, mseccfg):
        return _Decision(True, effective, match.index, "matching PMP entry permits access")
    return _Decision(False, effective, match.index, "matching PMP entry denies access")


def _check_sv39(scenario: PmpScenario) -> ReferenceOutcome:
    assert scenario.sv39 is not None
    mapping = scenario.sv39
    if not mapping.contains(scenario.probe.virtual_address, scenario.probe.size):
        return ReferenceOutcome(
            allowed=False,
            trap_cause=_page_fault_cause(scenario.probe.access),
            stage="pte_permission",
            ptw_level=None,
            fault_address=scenario.probe.virtual_address,
            physical_address=None,
            side_effect="not_applicable",
            spec_clause="Sv39 address translation and leaf-PTE lookup",
            rationale="no frozen Sv39 mapping covers the probe virtual address",
        )

    for level_name, walk_address in zip(("L2", "L1", "L0"), mapping.walk_addresses):
        decision = _check_pmp(
            entries=scenario.entries,
            mseccfg=scenario.mseccfg,
            privilege=Privilege.S,
            access=Access.LOAD,
            physical_address=walk_address,
            size=8,
            mprv=False,
            mpp=Privilege.M,
        )
        if not decision.allowed:
            return ReferenceOutcome(
                allowed=False,
                trap_cause=_access_fault_cause(scenario.probe.access),
                stage="page_table_walk",
                ptw_level=level_name,
                fault_address=walk_address,
                physical_address=None,
                side_effect="not_applicable",
                spec_clause="Sv39 page-table walk under PMP protection",
                rationale=f"page-table walk blocked at {level_name}: {decision.rationale}",
            )

    pte_decision = _check_pte_permissions(
        pte=mapping.pte,
        privilege=scenario.privilege,
        access=scenario.probe.access,
        sum_enabled=scenario.sum_enabled,
        mxr=scenario.mxr,
    )
    if pte_decision is not None:
        return ReferenceOutcome(
            allowed=False,
            trap_cause=_page_fault_cause(scenario.probe.access),
            stage="pte_permission",
            ptw_level=None,
            fault_address=scenario.probe.virtual_address,
            physical_address=None,
            side_effect="not_applicable",
            spec_clause="Sv39 leaf-PTE permission and attribute checks",
            rationale=pte_decision,
        )

    ad_update_required = _ad_update_required(mapping.pte, scenario.probe.access)
    if ad_update_required and scenario.ad_update_mode == AdUpdateMode.SVADE:
        return ReferenceOutcome(
            allowed=False,
            trap_cause=_page_fault_cause(scenario.probe.access),
            stage="pte_permission",
            ptw_level=None,
            fault_address=scenario.probe.virtual_address,
            physical_address=None,
            side_effect="not_applicable",
            spec_clause="Sv39 A/D-bit update and Svade fault rule",
            rationale="A/D update is required and Svade mandates a page fault",
        )

    if ad_update_required:
        leaf_address = mapping.walk_addresses[-1]
        ad_decision = _check_pmp(
            entries=scenario.entries,
            mseccfg=scenario.mseccfg,
            privilege=Privilege.S,
            access=Access.STORE,
            physical_address=leaf_address,
            size=8,
            mprv=False,
            mpp=Privilege.M,
        )
        if not ad_decision.allowed:
            return ReferenceOutcome(
                allowed=False,
                trap_cause=_access_fault_cause(scenario.probe.access),
                stage="page_table_walk",
                ptw_level="L0",
                fault_address=leaf_address,
                physical_address=None,
                side_effect="not_applicable",
                spec_clause="Sv39 hardware A/D-bit update under PMP protection",
                rationale=f"hardware A/D update blocked by PMP: {ad_decision.rationale}",
            )

    physical_address = mapping.physical_address_for(scenario.probe.virtual_address)
    final_decision = _check_pmp(
        entries=scenario.entries,
        mseccfg=scenario.mseccfg,
        privilege=scenario.privilege,
        access=scenario.probe.access,
        physical_address=physical_address,
        size=scenario.probe.size,
        mprv=scenario.mprv,
        mpp=scenario.mpp,
    )
    if not final_decision.allowed:
        return ReferenceOutcome(
            allowed=False,
            trap_cause=_access_fault_cause(scenario.probe.access),
            stage="final_access",
            ptw_level=None,
            fault_address=physical_address,
            physical_address=physical_address,
            side_effect="not_applicable",
            spec_clause="final translated access under PMP protection",
            rationale=f"translated access denied by PMP: {final_decision.rationale}",
        )

    return ReferenceOutcome(
        allowed=True,
        trap_cause=None,
        stage="none",
        ptw_level=None,
        fault_address=None,
        physical_address=physical_address,
        side_effect="not_applicable",
        spec_clause=_join_clauses(
            "Sv39 page-table walk, PTE permission, and final PMP enforcement",
            "A/D update rule" if ad_update_required else None,
        ),
        rationale="page-table walk, PTE checks, and final translated access all permit the probe",
    )


def _check_pte_permissions(
    *,
    pte: PageTableEntry,
    privilege: Privilege,
    access: Access,
    sum_enabled: bool,
    mxr: bool,
) -> str | None:
    if not pte.valid:
        return "leaf PTE is invalid"
    if pte.write and not pte.read:
        return "leaf PTE uses the reserved W=1,R=0 encoding"
    if privilege == Privilege.U and not pte.user:
        return "U-mode access is blocked by the PTE U bit"
    if privilege == Privilege.S and pte.user:
        if access == Access.FETCH:
            return "S-mode instruction fetch from a user page is forbidden"
        if not sum_enabled:
            return "S-mode load/store to a user page requires SUM=1"
    if access == Access.LOAD and not (pte.read or (mxr and pte.execute)):
        return "load permission is absent after MXR is applied"
    if access == Access.STORE and not pte.write:
        return "store permission is absent in the leaf PTE"
    if access == Access.FETCH and not pte.execute:
        return "execute permission is absent in the leaf PTE"
    return None


def _ad_update_required(pte: PageTableEntry, access: Access) -> bool:
    return (not pte.accessed) or (access == Access.STORE and not pte.dirty)


def _effective_privilege(
    privilege: Privilege,
    access: Access,
    mprv: bool,
    mpp: Privilege,
) -> Privilege:
    if privilege == Privilege.M and mprv and access in {Access.LOAD, Access.STORE}:
        return mpp
    return privilege


def _first_matching_entry(
    ordered_entries: list[PmpEntry],
    physical_address: int,
    size: int,
) -> PmpEntry | None:
    access_upper = physical_address + size
    for entry in ordered_entries:
        bounds = _entry_bounds(ordered_entries, entry)
        if bounds is None:
            continue
        lower, upper = bounds
        if lower < access_upper and physical_address < upper:
            return entry
    return None


def _entry_contains(
    ordered_entries: list[PmpEntry],
    entry: PmpEntry,
    physical_address: int,
    size: int,
) -> bool:
    bounds = _entry_bounds(ordered_entries, entry)
    if bounds is None:
        return False
    lower, upper = bounds
    return lower <= physical_address and physical_address + size <= upper


def _entry_bounds(
    ordered_entries: list[PmpEntry],
    entry: PmpEntry,
) -> tuple[int, int] | None:
    if entry.address_mode == AddressMode.OFF:
        return None
    if entry.address_mode == AddressMode.TOR:
        previous_addr = 0
        if entry.index > 0:
            previous = next((item for item in ordered_entries if item.index == entry.index - 1), None)
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
        trailing = _trailing_ones(entry.pmpaddr)
        size = 1 << (trailing + 3)
        lower = (entry.pmpaddr & ~((1 << trailing) - 1)) << 2
        return lower, lower + size
    return None


def _entry_allows(
    entry: PmpEntry,
    effective: Privilege,
    access: Access,
    mseccfg: Mseccfg,
) -> bool:
    if mseccfg.mml:
        return _entry_allows_mml(entry, effective, access)
    if entry.write and not entry.read:
        return False
    if effective == Privilege.M and not entry.locked:
        return True
    return _permission_bit(entry, access)


def _entry_allows_mml(entry: PmpEntry, effective: Privilege, access: Access) -> bool:
    locked = entry.locked
    read = entry.read
    write = entry.write
    execute = entry.execute

    if not locked:
        if write and not read:
            if execute:
                return access in {Access.LOAD, Access.STORE}
            if effective == Privilege.M:
                return access in {Access.LOAD, Access.STORE}
            return access == Access.LOAD
        if effective == Privilege.M:
            return False
        return _permission_bit(entry, access)

    if write and not read:
        if not execute:
            return access == Access.FETCH
        if effective == Privilege.M:
            return access in {Access.LOAD, Access.FETCH}
        return access == Access.FETCH

    if read and write and execute:
        return access == Access.LOAD

    if effective != Privilege.M:
        return False
    return _permission_bit(entry, access)


def _permission_bit(entry: PmpEntry, access: Access) -> bool:
    if access == Access.LOAD:
        return entry.read
    if access == Access.STORE:
        return entry.write
    if access == Access.FETCH:
        return entry.execute
    raise ValueError(f"unsupported access {access}")


def _apply_stateful_transition(scenario: PmpScenario) -> PmpScenario:
    sequence = scenario.stateful_sequence or {}
    mutation = str(sequence.get("mutation") or "none")
    if mutation == "none":
        return scenario
    if mutation == "pte-deny-leaf":
        if scenario.sv39 is None:
            return scenario
        denied_pte = PageTableEntry(
            read=False,
            write=False,
            execute=False,
            user=False,
            accessed=False,
            dirty=False,
            valid=False,
            global_mapping=False,
        )
        return replace(scenario, sv39=replace(scenario.sv39, pte=denied_pte))

    pmpaddr_overrides: dict[int, int] = {}
    for write in sequence.get("pmpaddr_writes") or []:
        if not isinstance(write, Mapping):
            continue
        raw_index = write.get("index")
        raw_value = write.get("pmpaddr")
        if type(raw_index) is not int:
            continue
        if isinstance(raw_value, str):
            pmpaddr_overrides[int(raw_index)] = int(raw_value, 0)
        elif type(raw_value) is int:
            pmpaddr_overrides[int(raw_index)] = raw_value

    cfg_after = sequence.get("pmpcfg0_after")
    decoded_cfg = int(cfg_after, 0) if isinstance(cfg_after, str) else int(cfg_after) if type(cfg_after) is int else None
    if decoded_cfg is None and not pmpaddr_overrides:
        return scenario

    updated_entries: list[PmpEntry] = []
    for entry in scenario.entries:
        cfg_byte = entry.cfg_byte() if decoded_cfg is None else ((decoded_cfg >> (entry.index * 8)) & 0xFF)
        updated_entries.append(
            PmpEntry(
                index=entry.index,
                address_mode=AddressMode((cfg_byte >> 3) & 0x3),
                pmpaddr=pmpaddr_overrides.get(entry.index, entry.pmpaddr),
                read=bool(cfg_byte & 0x01),
                write=bool(cfg_byte & 0x02),
                execute=bool(cfg_byte & 0x04),
                locked=bool(cfg_byte & 0x80),
            )
        )
    return replace(scenario, entries=updated_entries)


def _expected_side_effect(scenario: PmpScenario, outcome: ReferenceOutcome) -> str:
    if scenario.probe.access != Access.STORE:
        return "not_applicable"
    return "required_store_side_effect" if outcome.allowed else "forbidden_store_side_effect"


def _expected_failure_if_violated(outcome: ReferenceOutcome) -> str:
    if outcome.allowed:
        return "unexpected_trap"
    if outcome.stage == "page_table_walk":
        return "wrong_trap_stage_or_unexpected_no_trap"
    if outcome.side_effect == "forbidden_store_side_effect":
        return "unexpected_no_trap_or_forbidden_store_side_effect"
    return "unexpected_no_trap"


def _access_fault_cause(access: Access) -> int:
    return {
        Access.FETCH: 1,
        Access.LOAD: 5,
        Access.STORE: 7,
    }[access]


def _page_fault_cause(access: Access) -> int:
    return {
        Access.FETCH: 12,
        Access.LOAD: 13,
        Access.STORE: 15,
    }[access]


def _misaligned_trap_cause(access: Access) -> int:
    return {
        Access.FETCH: 0,
        Access.LOAD: 4,
        Access.STORE: 6,
    }[access]


def _is_misaligned(address: int, size: int) -> bool:
    if size <= 1:
        return False
    return (address % size) != 0


def _trailing_ones(value: int) -> int:
    count = 0
    while value & (1 << count):
        count += 1
    return count


def _format_optional_hex(value: int | None) -> str | None:
    return None if value is None else f"0x{value:x}"


def _join_clauses(*parts: str | None) -> str:
    return "; ".join(part for part in parts if part)
