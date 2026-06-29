from __future__ import annotations

from .diagnostics import PASS_TOHOST, emit_failure_tohost_lines, emit_static_failure_tohost_lines
from .mmu import (
    PageTableEntry,
    TranslationMode,
    pointer_pte_value,
    pte_value,
    sv39_indices,
)
from .oracle import TrapCause, evaluate_scenario
from .pmp import Access, PmpModel, Privilege
from .scenario import (
    M_DATA_BASE,
    M_TEXT_BASE,
    MEM_BASE,
    PAGE_TABLE_BASE,
    PROBE_VA,
    SU_CODE_BASE,
    TARGET_BASE,
    PmpScenario,
)


class AssemblyEmitter:
    def emit(self, scenario: PmpScenario, backend: str = "tohost") -> str:
        if scenario.stateful_sequence is not None:
            return self._emit_stateful(scenario, backend)
        if scenario.profile.startswith("legacy") and scenario.translation == TranslationMode.BARE:
            return self._emit_legacy(scenario, backend)
        return self._emit_structured(scenario, backend)

    def _emit_stateful(self, scenario: PmpScenario, backend: str) -> str:
        phase = 0 if scenario.stateful_sequence and scenario.stateful_sequence.get("warmup") else 1
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
        lines.extend(self._emit_pmp_setup(scenario))
        lines.extend(self._emit_satp_setup(scenario))
        lines.extend(
            [
                "enter_stateful_probe:",
            ]
        )
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
        lines.extend(self._emit_stateful_trap_handler(scenario, backend))
        lines.extend(self._emit_stateful_m_data())
        lines.extend(self._emit_stateful_su_probe(scenario))
        lines.extend(self._emit_stateful_target_region(scenario))
        if scenario.translation == TranslationMode.SV39:
            lines.extend(self._emit_sv39_tables(scenario))
        return "\n".join(lines) + "\n"

    def _emit_legacy(self, scenario: PmpScenario, backend: str) -> str:
        decision = PmpModel(scenario.entries, scenario.mseccfg).check(
            privilege=scenario.privilege,
            access=scenario.probe.access,
            physical_address=scenario.probe.physical_address,
            size=scenario.probe.size,
            mprv=scenario.mprv,
            mpp=scenario.mpp,
        )
        expected_cause = int(evaluate_scenario(scenario).trap_cause or 0)

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
        lines.extend(self._emit_pmp_setup(scenario))
        lines.extend(self._emit_privilege_setup(scenario))
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
        if decision.allowed:
            lines.extend([f"    li a0, {PASS_TOHOST}", "    j finish"])
        else:
            lines.extend(
                emit_static_failure_tohost_lines(
                    "UNEXPECTED_NO_TRAP",
                    mcause=0,
                    mtval=scenario.probe.effective_address(),
                )
            )
            lines.append("    j finish")
        lines.extend(
            [
                "trap_handler:",
                "    csrr t2, mcause",
                "    csrr t3, mtval",
                "    la t0, result",
                "    sd t2, 0(t0)",
                "    sd t3, 8(t0)",
            ]
        )
        if decision.allowed:
            lines.extend(emit_failure_tohost_lines("UNEXPECTED_TRAP"))
            lines.append("    j finish")
        else:
            lines.extend(
                [
                    f"    li t1, {expected_cause}",
                    "    beq t2, t1, pass",
                ]
            )
            lines.extend(emit_failure_tohost_lines("WRONG_MCAUSE"))
            lines.extend(
                [
                    "    j finish",
                    "pass:",
                    f"    li a0, {PASS_TOHOST}",
                    "    j finish",
                ]
            )
        lines.extend(self._emit_finish_block(backend, include_tohost_data=True))
        if scenario.probe.access == Access.FETCH:
            lines.extend(self._emit_fetch_target(scenario))
        return "\n".join(lines) + "\n"

    def _emit_structured(self, scenario: PmpScenario, backend: str) -> str:
        outcome = evaluate_scenario(scenario)
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
        lines.extend(self._emit_pmp_setup(scenario))
        lines.extend(self._emit_satp_setup(scenario))
        lines.extend(self._emit_privilege_setup(scenario))
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
            lines.append("    j fail_wrong_path")

        lines.extend(self._emit_trap_handler(scenario, outcome, backend))
        lines.extend(self._emit_m_data())
        lines.extend(self._emit_su_probe(scenario))
        lines.extend(self._emit_target_region(scenario))
        if scenario.translation == TranslationMode.SV39:
            lines.extend(self._emit_sv39_tables(scenario))
        return "\n".join(lines) + "\n"

    def _emit_pmp_setup(self, scenario: PmpScenario) -> list[str]:
        if scenario.mseccfg.mml:
            pre_mml = [entry for entry in scenario.entries if not (entry.write and not entry.read)]
            post_mml = [entry for entry in scenario.entries if entry.write and not entry.read]
            lines = self._emit_pmpaddr_writes(pre_mml)
            lines.extend(self._emit_pmpcfg0_write(pre_mml))
            lines.extend(self._emit_mseccfg_write(scenario))
            lines.extend(self._emit_pmpaddr_writes(post_mml))
            lines.extend(self._emit_pmpcfg0_write(scenario.entries))
            return lines

        lines = self._emit_pmpaddr_writes(scenario.entries)
        lines.extend(self._emit_pmpcfg0_write(scenario.entries))
        lines.extend(self._emit_mseccfg_write(scenario))
        return lines

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

    def _emit_probe(self, scenario: PmpScenario) -> list[str]:
        address = scenario.probe.effective_address()
        if scenario.probe.access == Access.LOAD:
            return [f"    li t0, 0x{address:x}", "    lw t1, 0(t0)"]
        if scenario.probe.access == Access.STORE:
            return [f"    li t0, 0x{address:x}", "    li t1, 0x5a5a5a5a", "    sw t1, 0(t0)"]
        if scenario.probe.access == Access.FETCH:
            return [f"    li t0, 0x{address:x}", "    jalr zero, 0(t0)"]
        raise ValueError(f"unsupported access type: {scenario.probe.access}")

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
            "    li a0, 0x51",
            "    ecall",
        ]

    def _emit_stateful_trap_handler(self, scenario: PmpScenario, backend: str) -> list[str]:
        if scenario.stateful_sequence is None:
            raise ValueError("stateful trap handler requires sequence metadata")
        expected_cause = scenario.stateful_sequence.get("expected_cause")
        expected_final = scenario.stateful_sequence.get("expected_final")
        stale_failure_class = scenario.stateful_sequence.get("stale_failure_class")
        ecall_cause = {
            Privilege.U: int(TrapCause.ECALL_FROM_U),
            Privilege.S: int(TrapCause.ECALL_FROM_S),
            Privilege.M: int(TrapCause.ECALL_FROM_M),
        }[scenario.privilege]

        lines = [
            "stateful_trap_handler:",
            "    csrr t2, mcause",
            "    csrr t3, mtval",
            "    la t0, result",
            "    sd t2, 0(t0)",
            "    sd t3, 8(t0)",
            "    la t0, stateful_phase",
            "    lw t5, 0(t0)",
            "    beqz t5, stateful_handle_warmup",
            "    j stateful_handle_final",
            "stateful_handle_warmup:",
            f"    li t1, {ecall_cause}",
            "    beq t2, t1, apply_stateful_mutation",
        ]
        lines.extend(emit_failure_tohost_lines("UNEXPECTED_TRAP"))
        lines.extend(
            [
                "    j finish",
                "apply_stateful_mutation:",
            ]
        )
        lines.extend(self._emit_stateful_mutation(scenario))
        lines.extend(
            [
                "    la t0, stateful_phase",
                "    li t1, 1",
                "    sw t1, 0(t0)",
            ]
        )
        if scenario.stateful_sequence.get("fence") == "with-sfence":
            lines.append("    sfence.vma")
        elif scenario.stateful_sequence.get("fence") == "with-sfence-fence-i":
            lines.extend(
                [
                    "    sfence.vma",
                    "    fence.i",
                ]
            )
        elif scenario.stateful_sequence.get("fence") == "no-fence-experimental":
            lines.append("no_fence_experimental:")
        lines.extend(
            [
                "    j enter_stateful_probe",
                "stateful_handle_final:",
            ]
        )

        if expected_final == "store_side_effect":
            lines.extend(
                [
                    f"    li t1, {ecall_cause}",
                    "    beq t2, t1, check_expected_side_effect",
                ]
            )
            lines.extend(emit_failure_tohost_lines("UNEXPECTED_TRAP"))
            lines.extend(["    j finish", "check_expected_side_effect:"])
            lines.extend(self._emit_check_sentinel_store())
        else:
            if expected_cause is None:
                raise ValueError("stateful expected trap requires expected_cause")
            lines.extend(
                [
                    f"    li t1, {int(expected_cause)}",
                    "    beq t2, t1, stateful_expected_trap",
                    f"    li t1, {ecall_cause}",
                    "    beq t2, t1, stateful_unexpected_no_trap",
                ]
            )
            lines.extend(emit_failure_tohost_lines("WRONG_MCAUSE"))
            lines.extend(["    j finish", "stateful_expected_trap:"])
            if expected_final == "trap_no_side_effect":
                lines.extend(self._emit_check_sentinel_initial())
            else:
                lines.extend([f"    li a0, {PASS_TOHOST}", "    j finish"])
            lines.append("stateful_unexpected_no_trap:")
            if expected_final == "trap_no_side_effect":
                lines.extend(
                    [
                        "    la t0, sentinel_word",
                        "    lw t1, 0(t0)",
                        "    li t4, 0x11223344",
                        "    bne t1, t4, fail_forbidden_side_effect",
                    ]
                )
                lines.extend(emit_failure_tohost_lines("UNEXPECTED_NO_TRAP"))
                lines.append("    j finish")
            else:
                lines.extend(emit_failure_tohost_lines(str(stale_failure_class)))
                lines.append("    j finish")

        lines.extend(
            [
                "pass_stateful:",
                f"    li a0, {PASS_TOHOST}",
                "    j finish",
                "fail_forbidden_side_effect:",
            ]
        )
        lines.extend(emit_failure_tohost_lines("FORBIDDEN_SIDE_EFFECT"))
        lines.extend(["    j finish", "fail_missing_expected_side_effect:"])
        lines.extend(emit_failure_tohost_lines("MISSING_EXPECTED_SIDE_EFFECT"))
        lines.extend(self._emit_finish_block(backend, include_tohost_data=False))
        return lines

    def _emit_stateful_mutation(self, scenario: PmpScenario) -> list[str]:
        sequence = scenario.stateful_sequence or {}
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

    def _emit_check_sentinel_initial(self) -> list[str]:
        return [
            "    la t0, sentinel_word",
            "    lw t1, 0(t0)",
            "    li t4, 0x11223344",
            "    bne t1, t4, fail_forbidden_side_effect",
            f"    li a0, {PASS_TOHOST}",
            "    j finish",
        ]

    def _emit_check_sentinel_store(self) -> list[str]:
        return [
            "    la t0, sentinel_word",
            "    lw t1, 0(t0)",
            "    li t4, 0x5a5a5a5a",
            "    bne t1, t4, fail_missing_expected_side_effect",
            f"    li a0, {PASS_TOHOST}",
            "    j finish",
        ]

    def _emit_trap_handler(self, scenario: PmpScenario, outcome, backend: str) -> list[str]:
        expected_cause = int(outcome.trap_cause) if outcome.trap_cause is not None else None
        ecall_cause = {
            Privilege.U: int(TrapCause.ECALL_FROM_U),
            Privilege.S: int(TrapCause.ECALL_FROM_S),
            Privilege.M: int(TrapCause.ECALL_FROM_M),
        }[scenario.privilege]
        lines = [
            "trap_handler:",
            "    csrr t2, mcause",
            "    csrr t3, mtval",
            "    la t0, result",
            "    sd t2, 0(t0)",
            "    sd t3, 8(t0)",
        ]
        if outcome.allowed:
            lines.extend(
                [
                    f"    li t1, {ecall_cause}",
                    "    beq t2, t1, pass",
                ]
            )
            lines.extend(emit_failure_tohost_lines("UNEXPECTED_TRAP"))
            lines.append("    j finish")
        else:
            lines.extend(
                [
                    f"    li t1, {expected_cause}",
                    "    beq t2, t1, pass",
                    f"    li t1, {ecall_cause}",
                    "    beq t2, t1, fail_unexpected_no_trap",
                ]
            )
            lines.extend(emit_failure_tohost_lines("WRONG_MCAUSE"))
            lines.extend(["    j finish", "fail_unexpected_no_trap:"])
            lines.extend(emit_failure_tohost_lines("UNEXPECTED_NO_TRAP"))
            lines.append("    j finish")
        lines.extend(
            [
                "pass:",
                f"    li a0, {PASS_TOHOST}",
                "    j finish",
                "fail_wrong_path:",
            ]
        )
        lines.extend(emit_static_failure_tohost_lines("WRONG_PATH"))
        lines.extend(self._emit_finish_block(backend, include_tohost_data=False))
        return lines

    def _emit_finish_block(self, backend: str, include_tohost_data: bool) -> list[str]:
        if backend == "tohost":
            lines = [
                "finish:",
                "    la t0, result",
                "    sd a0, 0(t0)" if include_tohost_data else "    sd a0, 16(t0)",
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
                "    sd a0, 0(t0)" if include_tohost_data else "    sd a0, 16(t0)",
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
                "    sd a0, 0(t0)" if include_tohost_data else "    sd a0, 16(t0)",
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
        ]

    def _emit_m_data(self) -> list[str]:
        return [
            f"    .org 0x{M_DATA_BASE - MEM_BASE:x}",
            "scratch:",
            "    .skip 1024",
            "    .align 3",
            "    .globl result",
            "result:",
            "    .dword 0",
            "    .dword 0",
            "    .dword 0",
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

    def _emit_stateful_m_data(self) -> list[str]:
        return [
            f"    .org 0x{M_DATA_BASE - MEM_BASE:x}",
            "scratch:",
            "    .skip 1024",
            "    .align 3",
            "    .globl result",
            "result:",
            "    .dword 0",
            "    .dword 0",
            "    .dword 0",
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

    def _emit_stateful_su_probe(self, scenario: PmpScenario) -> list[str]:
        lines = [
            f"    .org 0x{SU_CODE_BASE - MEM_BASE:x}",
            "stateful_probe:",
            "stateful_final_probe:",
        ]
        lines.extend(self._emit_probe(scenario))
        if scenario.probe.access != Access.FETCH:
            lines.extend(self._emit_success_ecall())
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
