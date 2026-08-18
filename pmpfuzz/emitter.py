from __future__ import annotations

from typing import Any

from .diagnostics import ObservationPhase, PASS_TOHOST, emit_observation_tohost_lines
from .mmu import (
    PageTableEntry,
    TranslationMode,
    pointer_pte_value,
    pte_value,
    sv39_indices,
)
from .pmp import Access, AddressMode, PmpEntry, Privilege
from .scenario import (
    M_DATA_BASE,
    M_DATA_SIZE,
    M_TEXT_BASE,
    M_TEXT_SIZE,
    MEM_BASE,
    PAGE_TABLE_BASE,
    PAGE_TABLE_SIZE,
    PROBE_VA,
    SU_CODE_BASE,
    SU_CODE_SIZE,
    TARGET_BASE,
    TARGET_SIZE,
    PmpScenario,
)
from .stateful import canonical_stateful_sequence


CVA6_SV39_TLB_STALE_PTE_COMPACT = "cva6-sv39-tlb-stale-pte-compact"


class AssemblyEmitter:
    def emit(
        self,
        scenario: PmpScenario,
        backend: str = "tohost",
        hpm_manifest: dict[str, Any] | None = None,
        lowering_profile: str | None = None,
    ) -> str:
        if scenario.stateful_sequence is not None:
            return self._emit_stateful(
                scenario,
                backend,
                hpm_manifest=hpm_manifest,
                lowering_profile=lowering_profile,
            )
        if scenario.profile.startswith("legacy") and scenario.translation == TranslationMode.BARE:
            return self._emit_legacy(
                scenario,
                backend,
                hpm_manifest=hpm_manifest,
                lowering_profile=lowering_profile,
            )
        return self._emit_structured(
            scenario,
            backend,
            hpm_manifest=hpm_manifest,
            lowering_profile=lowering_profile,
        )

    def supports_lowering_profile(self, scenario: PmpScenario, lowering_profile: str | None) -> bool:
        try:
            self._effective_pmp_entries(scenario, lowering_profile)
        except ValueError:
            return False
        return True

    def lowering_metadata(
        self,
        scenario: PmpScenario,
        *,
        lowering_profile: str | None = None,
    ) -> dict[str, Any]:
        effective_entries = self._effective_pmp_entries(scenario, lowering_profile)
        return {
            "lowering_profile": lowering_profile,
            "original_entries": [self._entry_metadata(scenario.entries, entry) for entry in scenario.entries],
            "effective_entries": [self._entry_metadata(effective_entries, entry) for entry in effective_entries],
        }

    def _emit_stateful(
        self,
        scenario: PmpScenario,
        backend: str,
        *,
        hpm_manifest: dict[str, Any] | None = None,
        lowering_profile: str | None = None,
    ) -> str:
        sequence = canonical_stateful_sequence(scenario) or {}
        phase = 0 if sequence.get("warmup") else 1
        probe_address = None
        if scenario.translation == TranslationMode.SV39 and scenario.privilege != Privilege.M:
            probe_address = PROBE_VA

        lines = [
            "    .option norvc",
            "    .option norelax",
            "    .section .text",
            "    .globl _start",
            "_start:",
            "    la sp, stack_top",
            "    la t0, stateful_trap_handler",
            "    csrw mtvec, t0",
            "    csrw medeleg, zero",
            "    csrw mideleg, zero",
            "    csrw satp, zero",
            "    sfence.vma",
            "    la t0, stateful_phase",
            f"    li t1, {phase}",
            "    sw t1, 0(t0)",
            "    la t0, sentinel_word",
            "    li t1, 0x11223344",
            "    sw t1, 0(t0)",
        ]
        lines.extend(self._emit_pmp_setup(scenario, lowering_profile=lowering_profile))
        lines.extend(self._emit_satp_setup(scenario))
        lines.extend(self._emit_hpm_setup(hpm_manifest))
        if phase == 1 and str(sequence.get("mutation") or "none") != "none":
            lines.extend(["apply_stateful_setup_transition:"])
            lines.extend(self._emit_stateful_transition(sequence))
        lines.extend(
            [
                "enter_stateful_probe:",
            ]
        )
        lines.extend(self._emit_stateful_observation_phase())
        lines.extend(self._emit_hpm_capture("before", hpm_manifest))
        lines.extend(self._emit_privilege_setup(scenario))
        if probe_address is None:
            lines.append("    la t0, stateful_probe")
        else:
            lines.append(f"    li t0, 0x{probe_address:x}")
        lines.extend(
            [
                "    csrw mepc, t0",
                "    mret",
            ]
        )
        lines.extend(self._emit_stateful_trap_handler(scenario, backend, hpm_manifest=hpm_manifest))
        lines.extend(self._emit_hpm_runtime_helpers(hpm_manifest))
        lines.extend(self._emit_stateful_m_data(hpm_manifest))
        lines.extend(self._emit_stateful_su_probe(scenario))
        lines.extend(self._emit_stateful_target_region(scenario))
        if scenario.translation == TranslationMode.SV39:
            lines.extend(self._emit_sv39_tables(scenario))
        return "\n".join(lines) + "\n"

    def _emit_legacy(
        self,
        scenario: PmpScenario,
        backend: str,
        *,
        hpm_manifest: dict[str, Any] | None = None,
        lowering_profile: str | None = None,
    ) -> str:
        lines = [
            "    .option norvc",
            "    .option norelax",
            "    .section .text",
            "    .globl _start",
            "_start:",
            "    la sp, stack_top",
            "    la t0, trap_handler",
            "    csrw mtvec, t0",
            "    csrw satp, zero",
        ]
        lines.extend(self._emit_hpm_setup(hpm_manifest))
        lines.extend(self._emit_pmp_setup(scenario, lowering_profile=lowering_profile))
        lines.extend(self._emit_privilege_setup(scenario))
        lines.extend(self._emit_mark_phase(ObservationPhase.PROBE))
        lines.extend(self._emit_hpm_capture("before", hpm_manifest))
        lines.extend(
            [
                "    la t0, probe",
                "    csrw mepc, t0",
                "    mret",
                "probe:",
            ]
        )
        lines.extend(self._emit_probe(scenario))
        if scenario.probe.access == Access.FETCH:
            lines.append("fetch_success:")
        lines.extend(self._emit_success_ecall())
        lines.extend(self._emit_trap_handler(scenario, backend, hpm_manifest=hpm_manifest))
        lines.extend(self._emit_hpm_runtime_helpers(hpm_manifest))
        if scenario.probe.access == Access.FETCH:
            lines.extend(self._emit_fetch_target(scenario))
        return "\n".join(lines) + "\n"

    def _emit_structured(
        self,
        scenario: PmpScenario,
        backend: str,
        *,
        hpm_manifest: dict[str, Any] | None = None,
        lowering_profile: str | None = None,
    ) -> str:
        probe_label = "probe_m" if scenario.privilege == Privilege.M else "probe_su"
        probe_address = None
        if scenario.translation == TranslationMode.SV39 and scenario.privilege != Privilege.M:
            probe_address = PROBE_VA

        lines = [
            "    .option norvc",
            "    .option norelax",
            "    .section .text",
            "    .globl _start",
            "_start:",
            "    la sp, stack_top",
            "    la t0, trap_handler",
            "    csrw mtvec, t0",
            "    csrw medeleg, zero",
            "    csrw mideleg, zero",
            "    csrw satp, zero",
            "    sfence.vma",
        ]
        lines.extend(self._emit_pre_pmp_preloads(scenario))
        lines.extend(self._emit_pmp_setup(scenario, lowering_profile=lowering_profile))
        lines.extend(self._emit_satp_setup(scenario))
        lines.extend(self._emit_hpm_setup(hpm_manifest))
        lines.extend(self._emit_privilege_setup(scenario))
        lines.extend(self._emit_mark_phase(ObservationPhase.PROBE))
        lines.extend(self._emit_hpm_capture("before", hpm_manifest))
        if probe_address is None:
            lines.append(f"    la t0, {probe_label}")
        else:
            lines.append(f"    li t0, 0x{probe_address:x}")
        lines.extend(
            [
                "    csrw mepc, t0",
                "    mret",
                "probe_m:",
            ]
        )
        if scenario.privilege == Privilege.M:
            lines.extend(self._emit_probe(scenario))
            lines.extend(self._emit_success_ecall())
        else:
            lines.extend(self._emit_mark_phase(ObservationPhase.SETUP))
            lines.append("    ecall")

        lines.extend(self._emit_trap_handler(scenario, backend, hpm_manifest=hpm_manifest))
        lines.extend(self._emit_hpm_runtime_helpers(hpm_manifest))
        lines.extend(self._emit_m_data(hpm_manifest))
        lines.extend(self._emit_su_probe(scenario))
        lines.extend(self._emit_target_region(scenario))
        if scenario.translation == TranslationMode.SV39:
            lines.extend(self._emit_sv39_tables(scenario))
        return "\n".join(lines) + "\n"

    def _emit_pmp_setup(
        self,
        scenario: PmpScenario,
        *,
        lowering_profile: str | None = None,
    ) -> list[str]:
        entries = self._effective_pmp_entries(scenario, lowering_profile)
        if scenario.mseccfg.mml:
            pre_mml = [entry for entry in entries if not (entry.write and not entry.read)]
            post_mml = [entry for entry in entries if entry.write and not entry.read]
            lines = self._emit_pmpaddr_writes(pre_mml)
            lines.extend(self._emit_pmpcfg0_write(pre_mml))
            lines.extend(self._emit_mseccfg_write(scenario))
            if post_mml:
                lines.extend(self._emit_pmpaddr_writes(post_mml))
            lines.extend(self._emit_pmpcfg0_write(entries))
            return lines

        lines = self._emit_pmpaddr_writes(entries)
        lines.extend(self._emit_pmpcfg0_write(entries))
        lines.extend(self._emit_mseccfg_write(scenario))
        return lines

    def _effective_pmp_entries(
        self,
        scenario: PmpScenario,
        lowering_profile: str | None,
    ) -> list[PmpEntry]:
        if lowering_profile is None:
            return list(scenario.entries)
        if lowering_profile != CVA6_SV39_TLB_STALE_PTE_COMPACT:
            raise ValueError(f"unsupported lowering profile: {lowering_profile}")
        return self._lower_cva6_sv39_tlb_stale_pte_compact(scenario)

    def _lower_cva6_sv39_tlb_stale_pte_compact(self, scenario: PmpScenario) -> list[PmpEntry]:
        if not self._is_cva6_sv39_tlb_stale_pte_compact_candidate(scenario):
            raise ValueError("compact CVA6 stale-pte lowering is only valid for the frozen Sv39 stale-pte load shape")
        return [
            scenario.entries[0],
            scenario.entries[1],
            scenario.entries[2],
            PmpEntry(
                index=3,
                address_mode=AddressMode.NAPOT,
                pmpaddr=PmpEntry.encode_napot(base=MEM_BASE, size=0x20000),
                read=True,
                write=False,
                execute=False,
                locked=False,
            ),
        ]

    def _is_cva6_sv39_tlb_stale_pte_compact_candidate(self, scenario: PmpScenario) -> bool:
        sequence = canonical_stateful_sequence(scenario) or {}
        cause_key = "expected" + "_cause"
        if scenario.translation != TranslationMode.SV39 or scenario.sv39 is None:
            return False
        if scenario.profile != "tlb-stale-pte":
            return False
        if scenario.privilege not in {Privilege.U, Privilege.S}:
            return False
        if scenario.probe.access != Access.LOAD:
            return False
        if scenario.pmp_match_mode != "pte-deny-leaf":
            return False
        if sequence.get("kind") != "tlb-stale-pte":
            return False
        if not bool(sequence.get("warmup")):
            return False
        if sequence.get("mutation") != "pte-deny-leaf":
            return False
        if sequence.get("final_probe") != "repeat":
            return False
        if sequence.get("expected_final") != "trap_after_mutation":
            return False
        if int(sequence.get(cause_key) or -1) != 13:
            return False
        if scenario.preload_mode != "warmup":
            return False
        if len(scenario.entries) != 6:
            return False
        return (
            self._matches_entry(
                scenario.entries[0],
                index=0,
                base=M_TEXT_BASE,
                size=M_TEXT_SIZE,
                read=True,
                write=False,
                execute=True,
                locked=True,
            )
            and self._matches_entry(
                scenario.entries[1],
                index=1,
                base=M_DATA_BASE,
                size=M_DATA_SIZE,
                read=True,
                write=True,
                execute=False,
                locked=True,
            )
            and self._matches_entry(
                scenario.entries[2],
                index=2,
                base=SU_CODE_BASE,
                size=SU_CODE_SIZE,
                read=True,
                write=False,
                execute=True,
                locked=False,
            )
            and self._matches_off_entry(scenario.entries[3], index=3)
            and self._matches_entry(
                scenario.entries[4],
                index=4,
                base=PAGE_TABLE_BASE,
                size=PAGE_TABLE_SIZE,
                read=True,
                write=False,
                execute=False,
                locked=False,
            )
            and self._matches_entry(
                scenario.entries[5],
                index=5,
                base=TARGET_BASE,
                size=TARGET_SIZE,
                read=True,
                write=False,
                execute=False,
                locked=False,
            )
        )

    def _matches_off_entry(self, entry: PmpEntry, *, index: int) -> bool:
        return (
            entry.index == index
            and entry.address_mode.name == "OFF"
            and entry.pmpaddr == 0
            and not entry.read
            and not entry.write
            and not entry.execute
            and not entry.locked
        )

    def _matches_entry(
        self,
        entry: PmpEntry,
        *,
        index: int,
        base: int,
        size: int,
        read: bool,
        write: bool,
        execute: bool,
        locked: bool,
    ) -> bool:
        return (
            entry.index == index
            and entry.address_mode.name == "NAPOT"
            and entry.pmpaddr == PmpEntry.encode_napot(base=base, size=size)
            and entry.read == read
            and entry.write == write
            and entry.execute == execute
            and entry.locked == locked
        )

    def _entry_metadata(self, entries: list[PmpEntry], entry: PmpEntry) -> dict[str, Any]:
        lower, upper = self._entry_bounds(entries, entry)
        return {
            "index": entry.index,
            "address_mode": entry.address_mode.name.lower(),
            "pmpaddr": f"0x{entry.pmpaddr:x}",
            "cfg_byte": f"0x{entry.cfg_byte():02x}",
            "read": entry.read,
            "write": entry.write,
            "execute": entry.execute,
            "locked": entry.locked,
            "region_start": None if lower is None else f"0x{lower:x}",
            "region_end_exclusive": None if upper is None else f"0x{upper:x}",
        }

    def _entry_bounds(self, entries: list[PmpEntry], entry: PmpEntry) -> tuple[int | None, int | None]:
        if entry.address_mode.name == "OFF":
            return None, None
        if entry.address_mode.name == "TOR":
            previous_addr = 0
            for candidate in entries:
                if candidate.index == entry.index - 1:
                    previous_addr = candidate.pmpaddr
                    break
            lower = previous_addr << 2
            upper = entry.pmpaddr << 2
            if upper <= lower:
                return None, None
            return lower, upper
        if entry.address_mode.name == "NA4":
            lower = entry.pmpaddr << 2
            return lower, lower + 4
        if entry.address_mode.name == "NAPOT":
            trailing = 0
            while entry.pmpaddr & (1 << trailing):
                trailing += 1
            size = 1 << (trailing + 3)
            lower = (entry.pmpaddr & ~((1 << trailing) - 1)) << 2
            return lower, lower + size
        return None, None

    def _emit_pmpaddr_writes(self, entries) -> list[str]:
        lines: list[str] = []
        for entry in entries:
            if entry.index >= 8:
                raise ValueError("stage 1 emitter supports PMP entries 0..7")
            lines.append(f"    li t0, 0x{entry.pmpaddr:x}")
            lines.append(f"    csrw pmpaddr{entry.index}, t0")
        return lines

    def _emit_pmpcfg0_write(self, entries) -> list[str]:
        cfg0 = 0
        for entry in entries:
            if entry.index >= 8:
                raise ValueError("stage 1 emitter supports PMP entries 0..7")
            cfg0 |= entry.cfg_byte() << (entry.index * 8)
        return [
            f"    li t0, 0x{cfg0:x}",
            "    csrw pmpcfg0, t0",
        ]

    def _emit_mseccfg_write(self, scenario: PmpScenario) -> list[str]:
        lines: list[str] = []
        mseccfg_value = (1 if scenario.mseccfg.mml else 0) | (2 if scenario.mseccfg.mmwp else 0) | (
            4 if scenario.mseccfg.rlb else 0
        )
        if mseccfg_value:
            lines.append(f"    li t0, 0x{mseccfg_value:x}")
            lines.append("    csrw 0x747, t0")
        return lines

    def _emit_satp_setup(self, scenario: PmpScenario) -> list[str]:
        if scenario.translation != TranslationMode.SV39:
            return []
        satp = (8 << 60) | (PAGE_TABLE_BASE >> 12)
        lines = [
            f"    li t0, 0x{satp:x}",
            "    csrw satp, t0",
        ]
        if scenario.sfence_vma:
            lines.append("    sfence.vma")
        return lines

    def _emit_pre_pmp_preloads(self, scenario: PmpScenario) -> list[str]:
        if scenario.translation != TranslationMode.SV39 or not scenario.preload_mode:
            return []
        label_sets = {
            "root-target": ("sv39_root_target",),
            "denied-l1": ("sv39_l1_target",),
            "all": (
                "sv39_root_probe",
                "sv39_root_target",
                "sv39_l1_probe",
                "sv39_l0_probe",
                "sv39_l1_target",
                "sv39_l0_target",
            ),
            "cold": (),
        }
        labels = label_sets.get(scenario.preload_mode)
        if labels is None:
            raise ValueError(f"unsupported preload mode: {scenario.preload_mode}")
        lines: list[str] = []
        for label in labels:
            lines.extend([f"    la t5, {label}", "    ld t6, 0(t5)"])
        return lines

    def _emit_privilege_setup(self, scenario: PmpScenario) -> list[str]:
        mpp_bits = {
            Privilege.U: 0,
            Privilege.S: 1 << 11,
            Privilege.M: 3 << 11,
        }[scenario.privilege]
        lines = [
            "    csrr t0, mstatus",
            "    li t1, ~((3 << 11) | (1 << 17) | (1 << 18) | (1 << 19))",
            "    and t0, t0, t1",
            f"    li t1, 0x{mpp_bits:x}",
            "    or t0, t0, t1",
        ]
        if scenario.mprv:
            lines.append("    li t1, (1 << 17)")
            lines.append("    or t0, t0, t1")
        if scenario.sum_enabled:
            lines.append("    li t1, (1 << 18)")
            lines.append("    or t0, t0, t1")
        if scenario.mxr:
            lines.append("    li t1, (1 << 19)")
            lines.append("    or t0, t0, t1")
        lines.append("    csrw mstatus, t0")
        return lines

    def _emit_probe(self, scenario: PmpScenario, *, access_override: Access | None = None) -> list[str]:
        address = scenario.probe.effective_address()
        access = access_override or scenario.probe.access
        if access == Access.LOAD:
            load = "ld" if scenario.probe.size == 8 else "lw"
            return [f"    li t0, 0x{address:x}", f"    {load} t1, 0(t0)"]
        if access == Access.STORE:
            store = "sd" if scenario.probe.size == 8 else "sw"
            return [f"    li t0, 0x{address:x}", "    li t1, 0x5a5a5a5a", f"    {store} t1, 0(t0)"]
        if access == Access.FETCH:
            return [f"    li t0, 0x{address:x}", "    jalr zero, 0(t0)"]
        raise ValueError(f"unsupported access type: {access}")

    def _emit_fetch_target(self, scenario: PmpScenario) -> list[str]:
        offset = scenario.probe.physical_address - 0x80000000
        if offset < 0:
            raise ValueError("stage 1 fetch probes must target addresses above 0x80000000")
        return [
            "    .section .text",
            f"    .org 0x{offset:x}",
            "fetch_target:",
            "    j fetch_success",
        ]

    def _emit_success_ecall(self) -> list[str]:
        return [
            *self._emit_mark_phase(ObservationPhase.COMPLETED),
            "    li a0, 0x51",
            "    ecall",
        ]

    def _emit_mark_phase(self, phase: ObservationPhase) -> list[str]:
        return [
            "    la t0, observation_phase",
            f"    li t1, {int(phase)}",
            "    sw t1, 0(t0)",
        ]

    def _emit_stateful_trap_handler(
        self,
        scenario: PmpScenario,
        backend: str,
        *,
        hpm_manifest: dict[str, Any] | None = None,
    ) -> list[str]:
        if scenario.stateful_sequence is None:
            raise ValueError("stateful trap handler requires sequence metadata")
        sequence = canonical_stateful_sequence(scenario) or {}
        ecall_cause = {
            Privilege.U: 8,
            Privilege.S: 9,
            Privilege.M: 11,
        }[scenario.privilege]

        lines = [
            "stateful_trap_handler:",
            "    csrr t2, mcause",
            "    csrr t3, mtval",
            "    csrr t4, mepc",
            "    csrr t5, mstatus",
            "    la t0, result",
            "    sd t2, 0(t0)",
            "    sd t3, 8(t0)",
            "    sd t4, 16(t0)",
            "    sd t5, 24(t0)",
            "    la t0, stateful_phase",
            "    lw t5, 0(t0)",
            "    beqz t5, stateful_handle_warmup",
            "    j stateful_handle_final",
            "stateful_handle_warmup:",
            f"    li t1, {ecall_cause}",
            "    beq t2, t1, apply_stateful_mutation",
        ]
        lines.extend(
            [
                "    la t0, observation_phase",
                "    lw t6, 0(t0)",
            ]
        )
        lines.extend(self._emit_hpm_capture("after", hpm_manifest))
        lines.extend(emit_observation_tohost_lines("TRAP", phase_reg="t6"))
        lines.extend(self._emit_hpm_flush(hpm_manifest))
        lines.extend(
            [
                "    j finish",
                "apply_stateful_mutation:",
            ]
        )
        lines.extend(self._emit_stateful_transition(sequence))
        lines.extend(
            [
                "    la t0, stateful_phase",
                "    li t1, 1",
                "    sw t1, 0(t0)",
            ]
        )
        lines.extend(self._emit_stateful_fence(sequence))
        lines.extend(
            [
                "    j enter_stateful_probe",
                "stateful_handle_final:",
            ]
        )
        lines.extend(self._emit_stateful_sentinel_phase())
        lines.extend(
            [
                "    la t0, observation_phase",
                "    lw t6, 0(t0)",
                f"    li t1, {ecall_cause}",
                "    beq t2, t1, stateful_report_completion",
                "stateful_report_trap:",
            ]
        )
        lines.extend(self._emit_hpm_capture("after", hpm_manifest))
        lines.extend(emit_observation_tohost_lines("TRAP", phase_reg="t6"))
        lines.extend(self._emit_hpm_flush(hpm_manifest))
        lines.extend(["    j finish", "stateful_report_completion:"])
        lines.extend(self._emit_hpm_capture("after", hpm_manifest))
        lines.extend(emit_observation_tohost_lines("COMPLETION", phase_reg="t6"))
        lines.extend(self._emit_hpm_flush(hpm_manifest))
        lines.append("    j finish")
        lines.extend(self._emit_finish_block(backend, include_tohost_data=False))
        return lines

    def _emit_stateful_observation_phase(self) -> list[str]:
        return [
            "    la t0, stateful_phase",
            "    lw t1, 0(t0)",
            "    beqz t1, mark_stateful_warmup",
            f"    li t1, {int(ObservationPhase.FINAL)}",
            "    j store_stateful_observation_phase",
            "mark_stateful_warmup:",
            f"    li t1, {int(ObservationPhase.WARMUP)}",
            "store_stateful_observation_phase:",
            "    la t0, observation_phase",
            "    sw t1, 0(t0)",
        ]

    def _emit_stateful_sentinel_phase(self) -> list[str]:
        return [
            "    la t0, sentinel_word",
            "    lw t1, 0(t0)",
            "    li t5, 0x11223344",
            "    beq t1, t5, stateful_sentinel_initial",
            "    li t5, 0x5a5a5a5a",
            "    beq t1, t5, stateful_sentinel_modified",
            f"    li t6, {int(ObservationPhase.FINAL_SENTINEL_OTHER)}",
            "    j store_stateful_sentinel_phase",
            "stateful_sentinel_initial:",
            f"    li t6, {int(ObservationPhase.FINAL_SENTINEL_INITIAL)}",
            "    j store_stateful_sentinel_phase",
            "stateful_sentinel_modified:",
            f"    li t6, {int(ObservationPhase.FINAL_SENTINEL_MODIFIED)}",
            "store_stateful_sentinel_phase:",
            "    la t0, observation_phase",
            "    sw t6, 0(t0)",
        ]

    def _emit_stateful_transition(self, sequence: dict[str, object]) -> list[str]:
        mutation = sequence.get("mutation")
        lines: list[str] = []
        if mutation == "pte-deny-leaf":
            lines.extend(
                [
                    "    la t0, sv39_l0_target",
                    "    li t1, 0x0",
                    "    sd t1, 0(t0)",
                ]
            )
        for write in sequence.get("pmpaddr_writes") or []:
            lines.extend(
                [
                    f"    li t1, {write['pmpaddr']}",
                    f"    csrw pmpaddr{int(write['index'])}, t1",
                ]
            )
        pmpcfg0_after = sequence.get("pmpcfg0_after")
        if pmpcfg0_after:
            lines.extend(
                [
                    f"    li t1, {pmpcfg0_after}",
                    "    csrw pmpcfg0, t1",
                ]
            )
        if not lines:
            lines.append("    nop")
        return lines

    def _emit_stateful_fence(self, sequence: dict[str, object]) -> list[str]:
        fence = str(sequence.get("fence") or "none")
        if fence == "with-sfence":
            return ["    sfence.vma"]
        if fence == "with-sfence-fence-i":
            return [
                "    sfence.vma",
                "    fence.i",
            ]
        if fence == "no-fence-experimental":
            return ["no_fence_experimental:"]
        return []

    def _emit_trap_handler(
        self,
        scenario: PmpScenario,
        backend: str,
        *,
        hpm_manifest: dict[str, Any] | None = None,
    ) -> list[str]:
        ecall_cause = {
            Privilege.U: 8,
            Privilege.S: 9,
            Privilege.M: 11,
        }[scenario.privilege]
        lines = [
            "trap_handler:",
        ]
        lines.extend(self._emit_hpm_capture("after", hpm_manifest))
        lines.extend([
            "    csrr t2, mcause",
            "    csrr t3, mtval",
            "    csrr t4, mepc",
            "    csrr t5, mstatus",
            "    la t0, result",
            "    sd t2, 0(t0)",
            "    sd t3, 8(t0)",
            "    sd t4, 16(t0)",
            "    sd t5, 24(t0)",
            "    la t0, observation_phase",
            "    lw t6, 0(t0)",
            f"    li t1, {ecall_cause}",
            "    beq t2, t1, report_completion",
            "report_trap:",
        ])
        lines.extend(emit_observation_tohost_lines("TRAP", phase_reg="t6"))
        lines.extend(self._emit_hpm_flush(hpm_manifest))
        lines.extend(
            [
                "    j finish",
                "report_completion:",
            ]
        )
        lines.extend(emit_observation_tohost_lines("COMPLETION", phase=ObservationPhase.COMPLETED))
        lines.extend(self._emit_hpm_flush(hpm_manifest))
        lines.append("    j finish")
        lines.extend(self._emit_finish_block(backend, include_tohost_data=scenario.profile.startswith("legacy")))
        return lines

    def _emit_finish_block(self, backend: str, include_tohost_data: bool) -> list[str]:
        if backend == "tohost":
            lines = [
                "finish:",
                "    la t0, result",
                "    sd a0, 32(t0)",
                "    la t0, tohost",
                "    sd a0, 0(t0)",
                "1:  j 1b",
            ]
            if include_tohost_data:
                lines.extend(self._emit_legacy_runtime_data())
            return lines
        if backend == "cascade-mmio":
            lines = [
                "finish:",
                "    la t0, result",
                "    sd a0, 32(t0)",
                "    li t0, 0x60000010",
                "    sd a0, 0(t0)",
                "    li t0, 0x60000000",
                "    sd a0, 0(t0)",
                "    fence",
                "1:  j 1b",
            ]
            if include_tohost_data:
                lines.extend(self._emit_legacy_runtime_data())
            return lines
        if backend == "xiangshan-goodtrap":
            lines = [
                "finish:",
                "    la t0, result",
                "    sd a0, 32(t0)",
                "    la t0, tohost",
                "    sd a0, 0(t0)",
                f"    li t1, {PASS_TOHOST}",
                "    beq a0, t1, xiangshan_finish_good",
                "    .word 0x0000806b",
                "1:  j 1b",
                "xiangshan_finish_good:",
                "    .word 0x0000006b",
                "2:  j 2b",
            ]
            if include_tohost_data:
                lines.extend(self._emit_legacy_runtime_data())
            return lines
        raise ValueError(f"unsupported emitter backend: {backend}")

    def _emit_legacy_runtime_data(self) -> list[str]:
        return [
            "    .section .bss",
            "    .align 12",
            "scratch:",
            "    .skip 4096",
            "stack:",
            "    .skip 4096",
            "stack_top:",
            "    .section .tohost,\"aw\",@progbits",
            "    .align 6",
            "    .globl tohost",
            "tohost:",
            "    .dword 0",
            "    .globl fromhost",
            "fromhost:",
            "    .dword 0",
            "    .section .data",
            "    .align 3",
            "    .globl result",
            "result:",
            "    .dword 0",
            "    .dword 0",
            "    .dword 0",
            "    .dword 0",
            "    .dword 0",
            "observation_phase:",
            "    .word 0",
        ]

    def _emit_m_data(self, hpm_manifest: dict[str, Any] | None = None) -> list[str]:
        lines = [
            f"    .org 0x{M_DATA_BASE - MEM_BASE:x}",
            "scratch:",
            "    .skip 1024",
            "    .align 3",
            "    .globl result",
            "result:",
            "    .dword 0",
            "    .dword 0",
            "    .dword 0",
            "    .dword 0",
            "    .dword 0",
            "observation_phase:",
            "    .word 0",
            "    .align 6",
            "    .globl tohost",
            "tohost:",
            "    .dword 0",
            "    .globl fromhost",
            "fromhost:",
            "    .dword 0",
            "stack:",
            "    .skip 2048",
            "stack_top:",
        ]
        lines.extend(self._emit_hpm_runtime_data(hpm_manifest))
        return lines

    def _emit_stateful_m_data(self, hpm_manifest: dict[str, Any] | None = None) -> list[str]:
        lines = [
            f"    .org 0x{M_DATA_BASE - MEM_BASE:x}",
            "scratch:",
            "    .skip 1024",
            "    .align 3",
            "    .globl result",
            "result:",
            "    .dword 0",
            "    .dword 0",
            "    .dword 0",
            "    .dword 0",
            "    .dword 0",
            "observation_phase:",
            "    .word 0",
            "stateful_phase:",
            "    .word 0",
            "    .word 0",
            "    .align 6",
            "    .globl tohost",
            "tohost:",
            "    .dword 0",
            "    .globl fromhost",
            "fromhost:",
            "    .dword 0",
            "stack:",
            "    .skip 2048",
            "stack_top:",
        ]
        lines.extend(self._emit_hpm_runtime_data(hpm_manifest))
        return lines

    def _emit_stateful_su_probe(self, scenario: PmpScenario) -> list[str]:
        sequence = canonical_stateful_sequence(scenario) or {}
        warmup_access_raw = sequence.get("warmup_access")
        warmup_access = Access(str(warmup_access_raw)) if warmup_access_raw else scenario.probe.access
        lines = [
            f"    .org 0x{SU_CODE_BASE - MEM_BASE:x}",
            "stateful_probe:",
        ]
        if bool(sequence.get("warmup")) and warmup_access != scenario.probe.access:
            lines.extend(
                [
                    "    la t0, stateful_phase",
                    "    lw t2, 0(t0)",
                    "    beqz t2, stateful_warmup_probe",
                    "    j stateful_final_probe",
                    "stateful_warmup_probe:",
                ]
            )
            lines.extend(self._emit_probe(scenario, access_override=warmup_access))
            if warmup_access != Access.FETCH:
                lines.extend(["    li a0, 0x51", "    ecall"])
        lines.append("stateful_final_probe:")
        lines.extend(self._emit_probe(scenario))
        if scenario.probe.access != Access.FETCH:
            lines.extend(["    li a0, 0x51", "    ecall"])
        return lines

    def _emit_stateful_target_region(self, scenario: PmpScenario) -> list[str]:
        if scenario.probe.access == Access.FETCH:
            return [
                f"    .org 0x{TARGET_BASE - MEM_BASE:x}",
                "target_region:",
                "    ecall",
                "sentinel_word:",
                "    .word 0x11223344",
                "    .word 0",
                "    .dword 0x99aabbccddeeff00",
            ]
        return [
            f"    .org 0x{TARGET_BASE - MEM_BASE:x}",
            "target_region:",
            "sentinel_word:",
            "    .word 0x11223344",
            "    .word 0",
            "    .dword 0x99aabbccddeeff00",
        ]

    def _emit_su_probe(self, scenario: PmpScenario) -> list[str]:
        lines = [
            f"    .org 0x{SU_CODE_BASE - MEM_BASE:x}",
            "probe_su:",
        ]
        if scenario.privilege != Privilege.M:
            lines.extend(self._emit_probe(scenario))
            if scenario.probe.access != Access.FETCH:
                lines.extend(self._emit_success_ecall())
        else:
            lines.append("    ecall")
        return lines

    def _emit_target_region(self, scenario: PmpScenario) -> list[str]:
        if scenario.probe.access == Access.FETCH:
            offset = scenario.probe.physical_address - MEM_BASE
            if offset < 0:
                raise ValueError("structured fetch probes must target addresses above MEM_BASE")
            return [
                f"    .org 0x{offset:x}",
                "target_region:",
                "    ecall",
            ]
        lines = [
            f"    .org 0x{TARGET_BASE - MEM_BASE:x}",
            "target_region:",
        ]
        lines.extend(
            [
                "    .dword 0x1122334455667788",
                "    .dword 0x99aabbccddeeff00",
            ]
        )
        return lines

    def _emit_hpm_setup(self, hpm_manifest: dict[str, Any] | None) -> list[str]:
        manifest = self._normalize_hpm_manifest(hpm_manifest)
        if manifest is None:
            return []
        lines = [
            "    li t0, 0x10020008",
            "    li t1, 0x1",
            "    sw t1, 0(t0)",
        ]
        for event in manifest["events"]:
            lines.extend(
                [
                    f"    li t0, 0x{int(event['event_selector']):x}",
                    f"    csrw 0x{self._hpm_event_selector_csr(event['counter']):x}, t0",
                    f"    csrw 0x{self._hpm_counter_csr(event['counter']):x}, zero",
                ]
            )
        return lines

    def _emit_hpm_capture(self, phase: str, hpm_manifest: dict[str, Any] | None) -> list[str]:
        if self._normalize_hpm_manifest(hpm_manifest) is None:
            return []
        if phase not in {"before", "after"}:
            raise ValueError(f"unsupported HPM capture phase: {phase}")
        label = "hpm_snapshot_before" if phase == "before" else "hpm_snapshot_after"
        return [f"    la a0, {label}", "    call hpm_capture_snapshot"]

    def _emit_hpm_flush(self, hpm_manifest: dict[str, Any] | None) -> list[str]:
        if self._normalize_hpm_manifest(hpm_manifest) is None:
            return []
        return ["    call hpm_flush_snapshots"]

    def _emit_hpm_runtime_helpers(self, hpm_manifest: dict[str, Any] | None) -> list[str]:
        manifest = self._normalize_hpm_manifest(hpm_manifest)
        if manifest is None:
            return []
        lines = [
            "hpm_capture_snapshot:",
            "    csrr t0, 0xb02",
            "    sd t0, 0(a0)",
            "    csrr t0, 0xb00",
            "    sd t0, 8(a0)",
        ]
        for index, event in enumerate(manifest["events"], start=2):
            lines.extend(
                [
                    f"    csrr t0, 0x{self._hpm_counter_csr(event['counter']):x}",
                    f"    sd t0, {index * 8}(a0)",
                ]
            )
        lines.extend(
            [
                "    ret",
                "hpm_flush_snapshots:",
                "    addi sp, sp, -16",
                "    sd ra, 0(sp)",
                "    sd a0, 8(sp)",
                "    la a0, hpm_phase_before_text",
                "    la a1, hpm_snapshot_before",
                "    call hpm_emit_snapshot",
                "    la a0, hpm_phase_after_text",
                "    la a1, hpm_snapshot_after",
                "    call hpm_emit_snapshot",
                "    ld a0, 8(sp)",
                "    ld ra, 0(sp)",
                "    addi sp, sp, 16",
                "    ret",
                "hpm_emit_snapshot:",
                "    addi sp, sp, -24",
                "    sd ra, 0(sp)",
                "    sd s0, 8(sp)",
                "    sd s1, 16(sp)",
                "    mv s0, a0",
                "    mv s1, a1",
                "    la a0, hpm_prefix_phase_text",
                "    call hpm_uart_puts",
                "    mv a0, s0",
                "    call hpm_uart_puts",
                "    la a0, hpm_prefix_width_minstret_text",
                "    call hpm_uart_puts",
                "    ld a0, 0(s1)",
                "    call hpm_uart_puthex64",
                "    la a0, hpm_prefix_mcycle_text",
                "    call hpm_uart_puts",
                "    ld a0, 8(s1)",
                "    call hpm_uart_puthex64",
            ]
        )
        for index, event in enumerate(manifest["events"], start=2):
            counter = str(event["counter"])
            lines.extend(
                [
                    f"    la a0, hpm_prefix_{counter}_text",
                    "    call hpm_uart_puts",
                    f"    ld a0, {index * 8}(s1)",
                    "    call hpm_uart_puthex64",
                ]
            )
        lines.extend(
            [
                "    la a0, hpm_newline_text",
                "    call hpm_uart_puts",
                "    ld ra, 0(sp)",
                "    ld s0, 8(sp)",
                "    ld s1, 16(sp)",
                "    addi sp, sp, 24",
                "    ret",
                "hpm_uart_puts:",
                "    addi sp, sp, -16",
                "    sd ra, 0(sp)",
                "    sd s0, 8(sp)",
                "    mv s0, a0",
                "hpm_uart_puts_loop:",
                "    lbu a0, 0(s0)",
                "    beqz a0, hpm_uart_puts_done",
                "    call hpm_uart_putc",
                "    addi s0, s0, 1",
                "    j hpm_uart_puts_loop",
                "hpm_uart_puts_done:",
                "    ld ra, 0(sp)",
                "    ld s0, 8(sp)",
                "    addi sp, sp, 16",
                "    ret",
                "hpm_uart_puthex64:",
                "    addi sp, sp, -24",
                "    sd ra, 0(sp)",
                "    sd s0, 8(sp)",
                "    sd s1, 16(sp)",
                "    mv s0, a0",
                "    li a0, 48",
                "    call hpm_uart_putc",
                "    li a0, 120",
                "    call hpm_uart_putc",
                "    li s1, 60",
                "hpm_uart_puthex64_loop:",
                "    srl t2, s0, s1",
                "    andi t2, t2, 0xf",
                "    li t3, 10",
                "    bltu t2, t3, hpm_uart_puthex64_digit",
                "    addi t2, t2, 87",
                "    j hpm_uart_puthex64_emit",
                "hpm_uart_puthex64_digit:",
                "    addi t2, t2, 48",
                "hpm_uart_puthex64_emit:",
                "    mv a0, t2",
                "    call hpm_uart_putc",
                "    addi s1, s1, -4",
                "    bgez s1, hpm_uart_puthex64_loop",
                "    ld ra, 0(sp)",
                "    ld s0, 8(sp)",
                "    ld s1, 16(sp)",
                "    addi sp, sp, 24",
                "    ret",
                "hpm_uart_putc:",
                "    li t0, 0x10020000",
                "hpm_uart_putc_wait:",
                "    lw t1, 0(t0)",
                "    bltz t1, hpm_uart_putc_wait",
                "    sw a0, 0(t0)",
                "    ret",
            ]
        )
        return lines

    def _emit_hpm_runtime_data(self, hpm_manifest: dict[str, Any] | None) -> list[str]:
        manifest = self._normalize_hpm_manifest(hpm_manifest)
        if manifest is None:
            return []
        snapshot_slots = 2 + len(manifest["events"])
        lines = [
            "    .align 3",
            "hpm_snapshot_before:",
        ]
        lines.extend(["    .dword 0" for _ in range(snapshot_slots)])
        lines.append("hpm_snapshot_after:")
        lines.extend(["    .dword 0" for _ in range(snapshot_slots)])
        lines.extend(
            [
                "hpm_prefix_phase_text:",
                '    .asciz "PMFUZZ_HPM phase="',
                "hpm_phase_before_text:",
                '    .asciz "before"',
                "hpm_phase_after_text:",
                '    .asciz "after"',
                "hpm_prefix_width_minstret_text:",
                f'    .asciz " width={int(manifest["counter_width"])} minstret="',
                "hpm_prefix_mcycle_text:",
                '    .asciz " mcycle="',
            ]
        )
        for event in manifest["events"]:
            counter = str(event["counter"])
            lines.extend(
                [
                    f"hpm_prefix_{counter}_text:",
                    f'    .asciz " {counter}="',
                ]
            )
        lines.extend(
            [
                "hpm_newline_text:",
                '    .asciz "\\n"',
            ]
        )
        return lines

    def _normalize_hpm_manifest(self, hpm_manifest: dict[str, Any] | None) -> dict[str, Any] | None:
        if hpm_manifest is None:
            return None
        events = list(hpm_manifest.get("events") or [])
        if not events:
            raise ValueError("HPM manifest requires events")
        normalized_events: list[dict[str, Any]] = []
        for event in events:
            counter = str(event.get("counter") or "")
            if not counter:
                raise ValueError("HPM manifest event missing counter")
            normalized_events.append(
                {
                    "counter": counter,
                    "event_selector": int(event.get("event_selector") or 0),
                }
            )
        return {
            "counter_width": int(hpm_manifest.get("counter_width") or 40),
            "events": normalized_events,
        }

    def _hpm_counter_csr(self, counter_name: str) -> int:
        return 0xB00 + int(str(counter_name).removeprefix("c"))

    def _hpm_event_selector_csr(self, counter_name: str) -> int:
        return 0x320 + int(str(counter_name).removeprefix("c"))

    def _emit_sv39_tables(self, scenario: PmpScenario) -> list[str]:
        if scenario.sv39 is None:
            raise ValueError("Sv39 scenario requires mapping metadata")

        target = scenario.sv39
        probe_user = scenario.privilege == Privilege.U
        probe_pte = PageTableEntry(
            read=True,
            write=False,
            execute=True,
            user=probe_user,
            accessed=True,
            dirty=False,
        )
        root = PAGE_TABLE_BASE
        l1_probe = PAGE_TABLE_BASE + 0x1000
        l0_probe = PAGE_TABLE_BASE + 0x2000
        l1_target = PAGE_TABLE_BASE + 0x3000
        l0_target = PAGE_TABLE_BASE + 0x4000
        probe_i2, probe_i1, probe_i0 = sv39_indices(PROBE_VA)
        target_i2, target_i1, target_i0 = sv39_indices(target.virtual_page)

        entries = [
            (root + probe_i2 * 8, pointer_pte_value(l1_probe), "sv39_root_probe"),
            (root + target_i2 * 8, pointer_pte_value(l1_target), "sv39_root_target"),
            (l1_probe + probe_i1 * 8, pointer_pte_value(l0_probe), "sv39_l1_probe"),
            (l0_probe + probe_i0 * 8, pte_value(SU_CODE_BASE, probe_pte), "sv39_l0_probe"),
            (l1_target + target_i1 * 8, pointer_pte_value(l0_target), "sv39_l1_target"),
            (l0_target + target_i0 * 8, pte_value(target.physical_page, target.pte), "sv39_l0_target"),
        ]

        lines = [
            f"    .org 0x{PAGE_TABLE_BASE - MEM_BASE:x}",
            "sv39_root_table:",
        ]
        current = PAGE_TABLE_BASE
        for address, value, label in sorted(entries, key=lambda item: item[0]):
            if address < current:
                raise ValueError("Sv39 table entries must be emitted in increasing address order")
            if address > current:
                lines.append(f"    .org 0x{address - MEM_BASE:x}")
            lines.append(f"{label}:")
            lines.append(f"    .dword 0x{value:x}")
            current = address + 8
        return lines
