"""R6 static PMP-state deriver + trap-address fingerprint recovery (riscv-dv baseline).

Derives the deterministic post-setup PMP state (16 entries) of a riscv-dv
SV-generator program from its generated .S (all PMP CSR writes in the setup
block are immediate literals) and recovers the trap address (mtval) of
instruction-access-fault observations (mcause=1 => mtval == mepc) by inverting
the 17-bit tohost fingerprint over the program's code region, cross-checked
against the 4-bit mepc tag. Engineering instrumentation only: no DUT reruns,
no pmpfuzz/bapc.py changes, no safety analysis.
"""

import json
import re
import subprocess
from pathlib import Path

_LI_RE = re.compile(r"^\s*li\s+x(\d+),\s*0x([0-9a-fA-F]+)")
_LA_MAIN_RE = re.compile(r"^\s*la\s+x(\d+),\s*main\b")
_ADD_RE = re.compile(r"^\s*add\s+x(\d+),\s*x(\d+),\s*x(\d+)")
_SRLI_RE = re.compile(r"^\s*srli\s+x(\d+),\s*x(\d+),\s*(\d+)")
_CSRW_RE = re.compile(r"^\s*csrw\s+0x([0-9a-fA-F]+),\s*x(\d+)")
_CSRR_RE = re.compile(r"^\s*csrr\s+x(\d+),\s*0x([0-9a-fA-F]+)")


def _symbol_address(elf_path, symbol):
    try:
        out = subprocess.run(
            ["riscv64-unknown-elf-nm", str(elf_path)],
            capture_output=True, text=True, timeout=60, check=True,
        )
    except Exception:
        return None
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == symbol:
            try:
                return int(parts[0], 16)
            except ValueError:
                return None
    return None


def fold17(value):
    return (value ^ (value >> 17) ^ (value >> 34) ^ (value >> 51)) & 0x1FFFF


def derive_static_pmp(asm_path, elf_path):
    """Derive the deterministic post-setup PMP state from the generated .S.

    Returns a dict with per-entry mode/rwx/locked/pmpaddr plus the raw words
    and the parsed anchor instructions. Raises ValueError when the .S shape
    does not match the expected generator layout.
    """
    lines = Path(asm_path).read_text(encoding="utf-8", errors="replace").splitlines()
    in_setup = False
    regs = {}
    pmpaddr = [0] * 16
    pmpcfg_words = {}
    anchors = []
    for line in lines:
        stripped = line.strip()
        if stripped == "pmp_setup:":
            in_setup = True
            continue
        if in_setup and stripped.startswith(("mepc_setup:", "custom_csr_setup:", "init_machine_mode:")):
            break
        if not in_setup:
            continue
        m = _LA_MAIN_RE.match(line)
        if m:
            main_addr = _symbol_address(elf_path, "main")
            if main_addr is None:
                raise ValueError("main symbol not found in ELF")
            regs[int(m.group(1))] = main_addr
            anchors.append(("la-main", int(m.group(1)), main_addr))
            continue
        m = _LI_RE.match(line)
        if m:
            regs[int(m.group(1))] = int(m.group(2), 16)
            anchors.append(("li", int(m.group(1)), int(m.group(2), 16)))
            continue
        m = _ADD_RE.match(line)
        if m:
            dst, a, b = (int(g) for g in m.groups())
            regs[dst] = regs.get(a, 0) + regs.get(b, 0)
            anchors.append(("add", dst, regs[dst]))
            continue
        m = _SRLI_RE.match(line)
        if m:
            dst, src, sh = int(m.group(1)), int(m.group(2)), int(m.group(3))
            regs[dst] = (regs.get(src, 0) >> sh)
            anchors.append(("srli", dst, regs[dst]))
            continue
        m = _CSRW_RE.match(line)
        if m:
            csr, src = int(m.group(1), 16), int(m.group(2))
            if 0x3B0 <= csr <= 0x3BF:
                pmpaddr[csr - 0x3B0] = regs.get(src, 0) & 0x3FFFFFFFFFFFFF
                anchors.append(("csrw", csr, pmpaddr[csr - 0x3B0]))
            elif 0x3A0 <= csr <= 0x3AE:
                pmpcfg_words[csr] = regs.get(src, 0) & 0xFFFFFFFFFFFFFFFF
                anchors.append(("csrw", csr, pmpcfg_words[csr]))
            continue
    if not anchors or not pmpcfg_words:
        raise ValueError("pmp_setup block not found or empty")
    entries = []
    for i in range(16):
        word = pmpcfg_words.get(0x3A0 + (i // 8) * 2, 0)
        byte = (word >> (8 * (i % 8))) & 0xFF
        a_field = (byte >> 3) & 0x3
        entries.append({
            "index": i,
            "address_mode": {0: "off", 1: "tor", 2: "na4", 3: "napot"}.get(a_field, "off"),
            "pmpaddr": pmpaddr[i],
            "read": bool(byte & 1),
            "write": bool(byte & 2),
            "execute": bool(byte & 4),
            "locked": bool(byte & 0x80),
        })
    cfg_words = [
        pmpcfg_words.get(0x3A0, 0), 0, pmpcfg_words.get(0x3A2, 0), 0,
        pmpcfg_words.get(0x3A4, 0), 0, pmpcfg_words.get(0x3A6, 0), 0,
    ]
    return {
        "schema_version": 1,
        "pmpcfg": ["0x%x" % w for w in cfg_words],
        "pmpaddr": ["0x%x" % a for a in pmpaddr],
        "entries": entries,
        "anchors": anchors,
        "evidence": "deductive-from-generated-stream",
        "note": ("post-setup deterministic state; the generated random stream "
                 "contains no PMP CSR writes (enable_write_pmp_csr=false) and "
                 "the SV program's own trap handlers are unreachable (mtvec "
                 "replaced by the spliced runtime)"),
    }


def recover_trap_address(fp, tag, elf_path, main_addr=None):
    """Recover mtval for mcause=1 traps by inverting the 17-bit fingerprint
    over the code region, cross-checked with the 4-bit mepc tag.

    Returns (address, unique) where unique is False when the inversion is
    ambiguous (then the caller must not use the address for mode matching).
    """
    if main_addr is None:
        main_addr = _symbol_address(elf_path, "main")
    if main_addr is None:
        return None, False
    matches = []
    # step 2: instruction addresses may be 2-byte aligned (compressed ISA)
    for addr in range(main_addr, main_addr + 0x40000, 2):
        if ((addr >> 12) & 0xF) != (tag & 0xF):
            continue
        if fold17(addr) == (fp & 0x1FFFF):
            matches.append(addr)
    if len(matches) == 1:
        return matches[0], True
    return (matches[0] if matches else None), False


def write_pmp_static(path, state):
    Path(path).write_text(
        json.dumps(state, indent=2, ensure_ascii=True) + "\n", encoding="ascii"
    )
    return path
