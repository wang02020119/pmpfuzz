#!/usr/bin/env python3

import argparse
import json
import re
import sys



DUT_PARAMS = {
    "rocket-clean": {"pmpcfg_csrs": [0x3A0, 0x3A2], "pmpaddr_count": 16, "read_mseccfg": 0},
    "boom-clean": {"pmpcfg_csrs": [0x3A0, 0x3A2], "pmpaddr_count": 16, "read_mseccfg": 0},
    "cva6-clean": {"pmpcfg_csrs": [0x3A0, 0x3A2],
                   "pmpaddr_count": 16, "read_mseccfg": 0},
}

_INIT_LABEL_RE = re.compile(r"^init:\s*$")
_TERMINAL_LABEL_RE = re.compile(r"^(test_done|test_end):\s*$")
_ECALL_RE = re.compile(r"^\s*ecall\s*$")
_WRITE_TOHOST_RE = re.compile(r"^write_tohost:\s*$")
_SYMBOL_DEF_RE = re.compile(r"^([a-zA-Z_.$][a-zA-Z0-9_.$]*):\s*$")


PROBE_VARIANTS = {
    "epilogue-load": {
        "name": "epilogue-load",
        "access": "load",
        "size": 8,
        "privilege": "m",
        "scratch_registers": ["x27", "x28"],
        "asm": [
            "la x27, __RDV_PROBE_SYMBOL__",
            "ld x28, 0(x27)",
        ],
        "priority_symbols": ["user_stack_start", "kernel_stack_start", "region_0"],
        "fallback_slot": "rdv_probe_slot",
        "insertion": (
            "immediately before the terminal ecall after test_done/test_end; "
            "the COMPLETION observation follows via the trap handler"
        ),
        "provenance": (
            "wrapper-epilogue-probe: SV-generator (official eUVM D port) "
            "programs carry no designated target operation; same convention "
            "as R4 (mirrors Cascade's single-target-op convention); no "
            "protection semantics injected"
        ),
    },
}


GRAFT_VARIANTS = {
    "upstream-enable-all": {
        "name": "upstream-enable-all",
        "source": (
            "riscv-dv src/riscv_pmp_cfg.sv gen_pmp_enable_all() "
            "(pin b7a0b4b0b51346a3c64f159f81ea262d867c14a9)"
        ),
        "source_lines": "src/riscv_pmp_cfg.sv:379-385",
        "insertion": (
            "after rdv runtime prologue (mtvec/medeleg/mideleg setup), "
            "before riscv-dv test_start"
        ),
        "scratch_register": "x27",
        "asm": [
            "li x27, 0x1fffffff",
            "csrw 0x3b0, x27",
            "csrw 0x3a0, 0x1f",
        ],
        "expected_pmp_state": {
            "programmed_entries": [
                {
                    "index": 0,
                    "address_mode": "napot",
                    "pmpaddr": "0x1fffffff",
                    "read": True,
                    "write": True,
                    "execute": True,
                    "locked": False,
                }
            ],
            "other_entries": (
                "OFF with pmpcfg bytes 0 (pmpcfg0 fully overwritten by the "
                "graft; pmpcfg2 untouched)"
            ),
            "note": (
                "region 0 = NAPOT covering the whole 32-bit address space, "
                "RWX, unlocked (upstream gen_pmp_enable_all semantics)"
            ),
        },
    },
}

OFF_SLOT0_MCAUSE = 0x010
OFF_SLOT0_MTVAL = 0x018
OFF_SLOT0_MEPC = 0x020
OFF_SLOT0_MSTATUS = 0x028
OFF_SLOT0_SATP = 0x030
OFF_SLOT0_MSECCFG = 0x038
OFF_PMPCFG_BASE = 0x310
OFF_PMPADDR_BASE = 0x350
OFF_FINAL_SATP = 0x3D0
OFF_FINAL_MSECCFG = 0x3D8
OFF_FINAL_MSTATUS = 0x3E0


def _hex(value):
    return hex(value)


def _prologue():
    return [
        "    la x26, rdv_trap_handler",
        "    csrw 0x305, x26",
        "    csrw 0x302, zero",
        "    csrw 0x303, zero",
    ]



def _find_terminal_ecall(lines):
    for idx, line in enumerate(lines):
        if _TERMINAL_LABEL_RE.match(line):
            for j in range(idx + 1, min(idx + 40, len(lines))):
                if _ECALL_RE.match(lines[j]):
                    return j
            break
    for idx, line in enumerate(lines):
        if _WRITE_TOHOST_RE.match(line):
            for j in range(idx - 1, max(idx - 8, 0), -1):
                if _ECALL_RE.match(lines[j]):
                    return j
            break
    raise ValueError(
        "no terminal ecall found (test_done/test_end/write_tohost anchors missing)"
    )


def _resolve_probe_symbol(lines, priority_symbols):
    defined = set()
    for line in lines:
        m = _SYMBOL_DEF_RE.match(line.strip())
        if m:
            defined.add(m.group(1))
    for sym in priority_symbols:
        if sym in defined:
            return sym, False
    return "rdv_probe_slot", True


def _probe_block(name, symbol):
    spec = PROBE_VARIANTS[name]
    asm = [line.replace("__RDV_PROBE_SYMBOL__", symbol) for line in spec["asm"]]
    lines = [
        "    .globl rdv_probe_start",
        "rdv_probe_start:",
    ]
    for line in asm:
        lines.append("    " + line)
    lines.append("    .globl rdv_probe_end")
    lines.append("rdv_probe_end:")
    return lines


def _write_probe_sidecar(name, symbol, fallback, dut, in_path, out_path, probe_json_path):
    spec = PROBE_VARIANTS[name]
    sidecar = {
        "schema_version": 1,
        "probe": spec["name"],
        "access": spec["access"],
        "size": spec["size"],
        "privilege": spec["privilege"],
        "probe_symbol": symbol,
        "fallback_slot": bool(fallback),
        "scratch_registers": list(spec["scratch_registers"]),
        "injected_instructions": [
            line.replace("__RDV_PROBE_SYMBOL__", symbol) for line in spec["asm"]
        ],
        "insertion": spec["insertion"],
        "provenance": spec["provenance"],
        "input": str(in_path),
        "spliced_output": str(out_path),
        "dut": dut,
    }
    sidecar_path = probe_json_path or (out_path + ".probe.json")
    with open(sidecar_path, "w", encoding="utf-8") as handle:
        json.dump(sidecar, handle, indent=2, ensure_ascii=True)
        handle.write("\n")
    return sidecar_path

def _graft_block(name):
    spec = GRAFT_VARIANTS[name]
    lines = [
        "    .globl rdv_graft_start",
        "rdv_graft_start:",
    ]
    for asm in spec["asm"]:
        lines.append("    " + asm)
    lines.append("    .globl rdv_graft_end")
    lines.append("rdv_graft_end:")
    return lines


def _write_graft_sidecar(name, dut, in_path, out_path, graft_json_path):
    spec = GRAFT_VARIANTS[name]
    sidecar = {
        "schema_version": 1,
        "graft": spec["name"],
        "source": spec["source"],
        "source_lines": spec["source_lines"],
        "insertion": spec["insertion"],
        "scratch_register": spec["scratch_register"],
        "injected_instructions": list(spec["asm"]),
        "expected_pmp_state": spec["expected_pmp_state"],
        "input": str(in_path),
        "spliced_output": str(out_path),
        "dut": dut,
    }
    sidecar_path = graft_json_path or (out_path + ".graft.json")
    with open(sidecar_path, "w", encoding="utf-8") as handle:
        json.dump(sidecar, handle, indent=2, ensure_ascii=True)
        handle.write("\n")
    return sidecar_path


def _handler(dut, pmpcfg_csrs, pmpaddr_count, read_mseccfg):
    lines = []
    lines.append("    .section .text")
    lines.append("    .align 2")
    lines.append("rdv_trap_handler:")
    lines.append("    csrr t2, 0x342")
    lines.append("    csrr t3, 0x343")
    lines.append("    la t0, rdv_result")
    lines.append("    lw t1, 0x8(t0)")
    lines.append("    bnez t1, rdv_handler_infra")
    lines.append("    li t1, 1")
    lines.append("    sw t1, 0x8(t0)")
    lines.append("    csrr t4, 0x341")
    lines.append("    sd t4, 0x20(t0)")
    lines.append("    csrr t5, 0x300")
    lines.append("    sd t5, 0x28(t0)")
    lines.append("    csrr t6, 0x180")
    lines.append("    sd t6, 0x30(t0)")
    if read_mseccfg:
        lines.append("    csrr t5, 0x747")
        lines.append("    sd t5, 0x38(t0)")
    for csr in pmpcfg_csrs:
        slot = (csr - 0x3A0) // 2
        lines.append("    csrr t1, " + _hex(csr))
        lines.append("    sd t1, " + _hex(OFF_PMPCFG_BASE + 8 * slot) + "(t0)")
    for i in range(pmpaddr_count):
        csr = 0x3B0 + i
        lines.append("    csrr t1, " + _hex(csr))
        lines.append("    sd t1, " + _hex(OFF_PMPADDR_BASE + 8 * i) + "(t0)")
    lines.append("    csrr t6, 0x180")
    lines.append("    sd t6, " + _hex(OFF_FINAL_SATP) + "(t0)")
    if read_mseccfg:
        lines.append("    csrr t5, 0x747")
        lines.append("    sd t5, " + _hex(OFF_FINAL_MSECCFG) + "(t0)")
    lines.append("    csrr t5, 0x300")
    lines.append("    sd t5, " + _hex(OFF_FINAL_MSTATUS) + "(t0)")
    lines.append("    sd t2, 0x10(t0)")
    lines.append("    sd t3, 0x18(t0)")
    lines.append("    li t1, 11")
    lines.append("    beq t2, t1, rdv_obs_completion")
    lines.append("    li t5, 1")
    lines.append("    li t6, 0")
    lines.append("    j rdv_obs_build")
    lines.append("rdv_obs_completion:")
    lines.append("    li t5, 2")
    lines.append("    li t6, 1")
    lines.append("rdv_obs_build:")
    lines.append("    li a0, 0x20000000")
    lines.append("    slli t1, t6, 28")
    lines.append("    or a0, a0, t1")
    lines.append("    slli t1, t5, 25")
    lines.append("    or a0, a0, t1")
    lines.append("    andi t1, t2, 0xF")
    lines.append("    slli t1, t1, 21")
    lines.append("    or a0, a0, t1")
    lines.append("    srli t1, t4, 12")
    lines.append("    andi t1, t1, 0xF")
    lines.append("    slli t1, t1, 17")
    lines.append("    or a0, a0, t1")
    lines.append("    mv t1, t3")
    lines.append("    srli t5, t3, 17")
    lines.append("    xor t1, t1, t5")
    lines.append("    srli t5, t3, 34")
    lines.append("    xor t1, t1, t5")
    lines.append("    srli t5, t3, 51")
    lines.append("    xor t1, t1, t5")
    lines.append("    li t5, 0x1FFFF")
    lines.append("    and t1, t1, t5")
    lines.append("    or a0, a0, t1")
    lines.append("    slli a0, a0, 1")
    lines.append("    ori a0, a0, 1")
    lines.append("    la t0, tohost")
    lines.append("    sd a0, 0(t0)")

    lines.append("    la t0, rdv_result")
    lines.append("    sd a0, 32(t0)")
    lines.append("rdv_spin:")
    lines.append("    j rdv_spin")
    lines.append("")
    lines.append("rdv_handler_infra:")


    lines.append("    li a0, 0x80000000")
    lines.append("    li t1, 5")
    lines.append("    slli t1, t1, 16")
    lines.append("    or a0, a0, t1")
    lines.append("    andi t1, t2, 0xFF")
    lines.append("    slli t1, t1, 8")
    lines.append("    or a0, a0, t1")
    lines.append("    andi t1, t3, 0xFF")
    lines.append("    or a0, a0, t1")
    lines.append("    slli a0, a0, 1")
    lines.append("    ori a0, a0, 1")
    lines.append("    la t0, tohost")
    lines.append("    sd a0, 0(t0)")
    lines.append("    la t0, rdv_result")
    lines.append("    sd a0, 32(t0)")
    lines.append("    j rdv_spin")
    return lines


def _data_section(has_tohost, has_fromhost, with_probe_slot=False):
    lines = []
    lines.append("    .section .data")
    lines.append("    .align 3")
    if not has_tohost:
        lines.append("    .align 6")
        lines.append("    .global tohost")
        lines.append("tohost:")
        lines.append("    .dword 0")
    if not has_fromhost:
        lines.append("    .align 6")
        lines.append("    .global fromhost")
        lines.append("fromhost:")
        lines.append("    .dword 0")
    lines.append("    .align 3")
    lines.append("rdv_result:")
    lines.append("    .word 0x504D5246")
    lines.append("    .word 1")
    lines.append("    .word 0")
    lines.append("    .word 0")
    lines.append("    .skip 0x300")
    lines.append("    .skip 64")
    lines.append("    .skip 128")
    lines.append("    .skip 24")
    if with_probe_slot:
        lines.append("    .align 3")
        lines.append("rdv_probe_slot:")
        lines.append("    .dword 0")
    return lines


def splice(in_path, out_path, dut, pmpcfg_csrs, pmpaddr_count, read_mseccfg,
           pmp_graft=None, graft_json_path=None,
           designated_probe=None, probe_json_path=None):
    params = dict(DUT_PARAMS[dut])
    if pmpcfg_csrs is not None:
        params["pmpcfg_csrs"] = [int(x, 0) for x in pmpcfg_csrs.split(",")]
    if pmpaddr_count is not None:
        params["pmpaddr_count"] = int(pmpaddr_count)
    if read_mseccfg is not None:
        params["read_mseccfg"] = int(read_mseccfg)
    if not (0 <= params["pmpaddr_count"] <= 16):
        raise ValueError("pmpaddr_count must be within [0, 16]")

    with open(in_path, "r", encoding="utf-8") as handle:
        original = handle.read().splitlines()

    init_indexes = [idx for idx, line in enumerate(original)
                    if _INIT_LABEL_RE.match(line)]
    if len(init_indexes) != 1:
        raise ValueError("expected exactly one init: label, found %d" % len(init_indexes))
    init_index = init_indexes[0]

    graft_spec = None
    if pmp_graft is not None:
        if pmp_graft not in GRAFT_VARIANTS:
            raise ValueError("unknown pmp graft variant: %s" % pmp_graft)
        graft_spec = GRAFT_VARIANTS[pmp_graft]

    probe_spec = None
    probe_symbol = None
    probe_fallback = False
    if designated_probe is not None:
        if designated_probe not in PROBE_VARIANTS:
            raise ValueError("unknown designated probe variant: %s" % designated_probe)
        probe_spec = PROBE_VARIANTS[designated_probe]
        probe_symbol, probe_fallback = _resolve_probe_symbol(
            original, probe_spec["priority_symbols"]
        )
        ecall_index = _find_terminal_ecall(original)

    out_lines = []
    out_lines.extend(original[: init_index + 1])
    out_lines.extend(_prologue())
    if graft_spec is not None:
        out_lines.extend(_graft_block(pmp_graft))
    if probe_spec is not None:
        out_lines.extend(original[init_index + 1: ecall_index])
        out_lines.extend(_probe_block(designated_probe, probe_symbol))
        out_lines.extend(original[ecall_index:])
    else:
        out_lines.extend(original[init_index + 1:])
    out_lines.append("")
    out_lines.extend(_handler(dut, params["pmpcfg_csrs"],
                              params["pmpaddr_count"],
                              params["read_mseccfg"]))
    out_lines.append("")
    has_tohost = any("tohost:" in line for line in original)
    has_fromhost = any("fromhost:" in line for line in original)
    out_lines.extend(_data_section(has_tohost, has_fromhost,
                                   with_probe_slot=(probe_spec is not None)))
    out_lines.append("")

    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(out_lines))
    if graft_spec is not None:
        _write_graft_sidecar(pmp_graft, dut, in_path, out_path, graft_json_path)
    if probe_spec is not None:
        _write_probe_sidecar(designated_probe, probe_symbol, probe_fallback,
                             dut, in_path, out_path, probe_json_path)
    return len(out_lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="pygen .S input")
    parser.add_argument("output", help="spliced .S output")
    parser.add_argument("--dut", required=True, choices=sorted(DUT_PARAMS.keys()))
    parser.add_argument("--pmpcfg-csrs", default=None,
                        help="comma list overriding readable pmpcfg CSR addresses")
    parser.add_argument("--pmpaddr-count", type=int, default=None)
    parser.add_argument("--read-mseccfg", type=int, choices=[0, 1], default=None)
    parser.add_argument(
        "--pmp-graft",
        choices=sorted(GRAFT_VARIANTS.keys()),
        default=None,
        help="inject an upstream riscv-dv PMP init graft (R3; default: off)",
    )
    parser.add_argument(
        "--graft-json",
        default=None,
        help="path for the graft sidecar JSON (default: <output>.graft.json)",
    )
    parser.add_argument(
        "--designated-probe",
        choices=sorted(PROBE_VARIANTS.keys()),
        default=None,
        help="inject an R4 designated epilogue probe (default: off)",
    )
    parser.add_argument(
        "--probe-json",
        default=None,
        help="path for the probe sidecar JSON (default: <output>.probe.json)",
    )
    args = parser.parse_args()
    count = splice(args.input, args.output, args.dut,
                   args.pmpcfg_csrs, args.pmpaddr_count, args.read_mseccfg,
                   pmp_graft=args.pmp_graft, graft_json_path=args.graft_json,
                   designated_probe=args.designated_probe,
                   probe_json_path=args.probe_json)
    extra = []
    if args.pmp_graft:
        extra.append("graft=%s" % args.pmp_graft)
    if args.designated_probe:
        extra.append("probe=%s" % args.designated_probe)
    print("spliced %d lines -> %s (dut=%s%s)" % (
        count, args.output, args.dut,
        (" " + " ".join(extra)) if extra else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
