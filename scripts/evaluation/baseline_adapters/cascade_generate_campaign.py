#!/usr/bin/env python3
"""Cascade campaign generator with optional HPM instrumentation.

Executed inside the official Cascade Python environment after sourcing
``/cascade-meta/env.sh``. The module stays import-safe outside the container:
all Cascade-specific imports remain deferred until ``generate_campaign``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Callable


ALLOWED_DESIGNS = frozenset({"rocket", "boom", "cva6", "xiangshan"})
_HPM_UART_DATA_ADDR = 0x10020000
_HPM_UART_READY_ADDR = 0x10020008
_U64_MASK = (1 << 64) - 1
_CSR_MSTATUS = 0x300
_CSR_SATP = 0x180
_CSR_PMPCFG0 = 0x3A0
_CSR_PMPADDR0 = 0x3B0
_CSR_MSECCFG = 0x747
_DEFAULT_TARGET_OPERATION_ATTEMPTS_PER_CASE = 200


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic Cascade ELF campaign",
    )
    parser.add_argument(
        "--design",
        required=True,
        choices=sorted(ALLOWED_DESIGNS),
        help="CPU design name",
    )
    parser.add_argument(
        "--seed",
        required=True,
        type=int,
        help="Campaign seed (nonnegative integer)",
    )
    parser.add_argument(
        "--count",
        required=True,
        type=int,
        help="Number of ELFs to generate (positive integer)",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=str,
        help="Output directory for ELFs and sidecars",
    )
    parser.add_argument(
        "--hpm-manifest",
        required=False,
        default=None,
        type=str,
        help="Optional HPM manifest JSON used for UART counter instrumentation",
    )
    parser.add_argument(
        "--start-index",
        required=False,
        default=0,
        type=int,
        help="Global case index offset for continuous multi-batch generation",
    )
    parser.add_argument(
        "--require-single-target-operation",
        action="store_true",
        help=(
            "Reject generated cases whose sidecar cannot bind BAPC coverage "
            "to exactly one target load/store operation"
        ),
    )
    parser.add_argument(
        "--require-target-operation-candidate",
        action="store_true",
        help=(
            "Reject generated cases whose sidecar has no target load/store "
            "operation candidates"
        ),
    )
    parser.add_argument(
        "--max-target-operation-attempts-per-case",
        required=False,
        default=_DEFAULT_TARGET_OPERATION_ATTEMPTS_PER_CASE,
        type=int,
        help="Maximum resampling attempts per output case when requiring one target operation",
    )
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if args.design not in ALLOWED_DESIGNS:
        raise ValueError(
            f"Invalid design: {args.design!r}. "
            f"Must be one of {sorted(ALLOWED_DESIGNS)}"
        )
    if args.seed < 0:
        raise ValueError(f"Seed must be nonnegative, got {args.seed}")
    if args.count <= 0:
        raise ValueError(f"Count must be positive, got {args.count}")
    if args.start_index < 0:
        raise ValueError(f"start_index must be nonnegative, got {args.start_index}")
    if args.max_target_operation_attempts_per_case <= 0:
        raise ValueError(
            "max_target_operation_attempts_per_case must be positive, got "
            f"{args.max_target_operation_attempts_per_case}"
        )

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    if args.hpm_manifest:
        manifest_path = Path(args.hpm_manifest)
        if not manifest_path.exists() or not manifest_path.is_file():
            raise ValueError(f"HPM manifest not found: {manifest_path}")


def _call_with_spikespeed_lock(calibrate_fn: Callable[[], object]) -> object:
    """Serialize Cascade Spike speed calibration across concurrent campaigns.

    Cascade's shared ``common.spike.calibrate_spikespeed()`` implementation
    uses fixed temporary paths under ``/cascade-data``. Parallel calibrations
    for different DUTs can race on those paths and fail with spurious
    ``FileNotFoundError`` during cleanup. Guard the calibration with a shared
    process lock so formal waves can launch multiple Cascade campaigns safely.
    """

    try:
        import fcntl
    except ImportError:
        return calibrate_fn()

    requested_lock_path = Path(
        os.environ.get(
            "PMPFUZZ_CASCADE_SPIKESPEED_LOCK",
            "/cascade-data/dbgcmds/spikespeedcalibration.lock",
        )
    )
    try:
        requested_lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = requested_lock_path
    except OSError:
        lock_path = Path(tempfile.gettempdir()) / "pmpfuzz-cascade-spikespeedcalibration.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            return calibrate_fn()
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _u64(value: int) -> int:
    return int(value) & _U64_MASK


def _signed(value: int) -> int:
    value = _u64(value)
    if value & (1 << 63):
        return value - (1 << 64)
    return value


def _apply_regimm(op: str, src: int, imm: int) -> int | None:
    if op == "addi":
        return _u64(src + imm)
    if op == "addiw":
        value = ((src & 0xFFFFFFFF) + (imm & 0xFFFFFFFF)) & 0xFFFFFFFF
        if value & (1 << 31):
            value -= 1 << 32
        return _u64(value)
    if op in {"slli", "slliw"}:
        return _u64(src << int(imm))
    if op in {"srli", "srliw"}:
        return _u64(src >> int(imm))
    if op in {"srai", "sraiw"}:
        return _u64(_signed(src) >> int(imm))
    if op == "ori":
        return _u64(src | imm)
    if op == "xori":
        return _u64(src ^ imm)
    if op == "andi":
        return _u64(src & imm)
    return None


def _apply_binary(op: str, lhs: int, rhs: int) -> int | None:
    if op in {"add", "addw"}:
        return _u64(lhs + rhs)
    if op in {"sub", "subw"}:
        return _u64(lhs - rhs)
    if op == "or":
        return _u64(lhs | rhs)
    if op == "and":
        return _u64(lhs & rhs)
    if op == "xor":
        return _u64(lhs ^ rhs)
    if op in {"sll", "sllw"}:
        return _u64(lhs << (rhs & 0x3F))
    if op in {"srl", "srlw"}:
        return _u64(lhs >> (rhs & 0x3F))
    if op in {"sra", "sraw"}:
        return _u64(_signed(lhs) >> (rhs & 0x3F))
    return None


def _set_reg(regs: dict[int, int], rd: int, value: int) -> None:
    if int(rd) == 0:
        return
    regs[int(rd)] = _u64(value)


def _flatten_instrs(fuzzerstate) -> list[object]:
    out: list[object] = []
    for block in getattr(fuzzerstate, "instr_objs_seq", []) or []:
        out.extend(list(block))
    return out


def _extract_actual_csr_state(fuzzerstate) -> dict[str, object]:
    regs: dict[int, int] = {0: 0}
    csrs: dict[int, int] = {}
    for instr in _flatten_instrs(fuzzerstate):
        instr_name = str(getattr(instr, "instr_str", "") or "").lower()
        if type(instr).__name__ == "ImmRdInstruction" and instr_name == "lui":
            _set_reg(regs, int(getattr(instr, "rd", 0) or 0), int(getattr(instr, "imm", 0) or 0) << 12)
            continue
        if type(instr).__name__ == "RegImmInstruction":
            rd = int(getattr(instr, "rd", 0) or 0)
            rs1 = int(getattr(instr, "rs1", 0) or 0)
            imm = int(getattr(instr, "imm", 0) or 0)
            value = _apply_regimm(instr_name, regs.get(rs1, 0), imm)
            if value is not None:
                _set_reg(regs, rd, value)
            continue
        if type(instr).__name__ == "R12DInstruction":
            rd = int(getattr(instr, "rd", 0) or 0)
            rs1 = int(getattr(instr, "rs1", 0) or 0)
            rs2 = int(getattr(instr, "rs2", 0) or 0)
            value = _apply_binary(instr_name, regs.get(rs1, 0), regs.get(rs2, 0))
            if value is not None:
                _set_reg(regs, rd, value)
            continue
        if type(instr).__name__ == "CSRImmInstruction":
            csr_id = int(getattr(instr, "csr_id", -1) or -1)
            rd = int(getattr(instr, "rd", 0) or 0)
            uimm = int(getattr(instr, "uimm", 0) or 0)
            old = csrs.get(csr_id, 0)
            if rd:
                _set_reg(regs, rd, old)
            if instr_name == "csrrwi":
                csrs[csr_id] = _u64(uimm)
            elif instr_name == "csrrsi":
                csrs[csr_id] = _u64(old | uimm)
            elif instr_name == "csrrci":
                csrs[csr_id] = _u64(old & ~uimm)
            continue
        if type(instr).__name__ == "CSRRegInstruction":
            csr_id = int(getattr(instr, "csr_id", -1) or -1)
            rd = int(getattr(instr, "rd", 0) or 0)
            rs1 = int(getattr(instr, "rs1", 0) or 0)
            src = regs.get(rs1, 0)
            old = csrs.get(csr_id, 0)
            if rd:
                _set_reg(regs, rd, old)
            if instr_name == "csrrw":
                csrs[csr_id] = _u64(src)
            elif instr_name == "csrrs":
                csrs[csr_id] = _u64(old | src)
            elif instr_name == "csrrc":
                csrs[csr_id] = _u64(old & ~src)
            continue
    return {
        "mstatus": csrs.get(_CSR_MSTATUS),
        "satp": csrs.get(_CSR_SATP),
        "satp_written": _CSR_SATP in csrs,
        "pmpcfg0": csrs.get(_CSR_PMPCFG0),
        "pmpaddr0": csrs.get(_CSR_PMPADDR0),
        "mseccfg": csrs.get(_CSR_MSECCFG),
    }


def _translation_from_csr_state(csr_state: dict[str, object]) -> str:
    if not bool(csr_state.get("satp_written")):
        return "bare"
    satp = int(csr_state.get("satp") or 0)
    return "sv39" if ((satp >> 60) & 0xF) == 8 else "bare"


def _mseccfg_from_csr_state(csr_state: dict[str, object]) -> dict[str, bool]:
    raw = int(csr_state.get("mseccfg") or 0)
    return {
        "mml": bool(raw & 0x1),
        "mmwp": bool(raw & 0x2),
        "rlb": bool(raw & 0x4),
    }


def _pmp_entries_from_csr_state(csr_state: dict[str, object]) -> list[dict[str, object]]:
    pmpcfg0 = csr_state.get("pmpcfg0")
    pmpaddr0 = csr_state.get("pmpaddr0")
    if pmpcfg0 is None or pmpaddr0 is None:
        return []
    cfg = int(pmpcfg0) & 0xFF
    mode_bits = (cfg >> 3) & 0x3
    address_mode = {
        0: "off",
        1: "tor",
        2: "na4",
        3: "napot",
    }[mode_bits]
    return [
        {
            "index": 0,
            "address_mode": address_mode,
            "pmpaddr": f"0x{int(pmpaddr0):x}",
            "read": bool(cfg & 0x1),
            "write": bool(cfg & 0x2),
            "execute": bool(cfg & 0x4),
            "locked": bool(cfg & 0x80),
        }
    ]


def _normalize_producer_id(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None


def _candidate_access(instr: object) -> str | None:
    name = type(instr).__name__
    mnemonic = str(getattr(instr, "instr_str", "") or "").strip().lower()
    if "LoadInstruction" in name:
        return "load"
    if "StoreInstruction" in name:
        return "store"
    if mnemonic in {"lb", "lbu", "lh", "lhu", "lw", "lwu", "ld", "lr.w", "lr.d", "flh", "flw", "fld"}:
        return "load"
    if mnemonic in {"sb", "sh", "sw", "sd", "sc.w", "sc.d", "fsh", "fsw", "fsd"}:
        return "store"
    return None


def _candidate_size(instr: object) -> int | None:
    mnemonic = str(getattr(instr, "instr_str", "") or "").strip().lower()
    return {
        "lb": 1,
        "lbu": 1,
        "sb": 1,
        "lh": 2,
        "lhu": 2,
        "sh": 2,
        "flh": 2,
        "fsh": 2,
        "lw": 4,
        "lwu": 4,
        "sw": 4,
        "lr.w": 4,
        "sc.w": 4,
        "flw": 4,
        "fsw": 4,
        "ld": 8,
        "sd": 8,
        "lr.d": 8,
        "sc.d": 8,
        "fld": 8,
        "fsd": 8,
    }.get(mnemonic)


def _extract_target_operation_candidates(fuzzerstate) -> list[dict[str, object]]:
    producer_map = {
        producer_id: int(address)
        for raw_producer_id, address in dict(getattr(fuzzerstate, "producer_id_to_tgtaddr", {}) or {}).items()
        if (producer_id := _normalize_producer_id(raw_producer_id)) is not None
    }
    bb_start_addrs = list(getattr(fuzzerstate, "bb_start_addr_seq", []) or [])
    design_base_addr = int(getattr(fuzzerstate, "design_base_addr", 0) or 0)
    candidates: list[dict[str, object]] = []
    for bb_id, bb_instrs in enumerate(getattr(fuzzerstate, "instr_objs_seq", []) or []):
        if bb_id == 0 or bb_id >= len(bb_start_addrs):
            continue
        for instr_id, instr in enumerate(bb_instrs):
            active_instr = getattr(instr, "meminstr", None) or instr
            access = _candidate_access(active_instr)
            size = _candidate_size(active_instr)
            if access is None or size is None:
                continue
            instruction_address = design_base_addr + int(bb_start_addrs[bb_id]) + (instr_id * 4)
            candidate = {
                "target_operation_id": f"bb{bb_id}-i{instr_id}",
                "privilege": "M",
                "access": access,
                "size": size,
                "instruction_address": f"0x{instruction_address:x}",
                "instruction_page_tag": (instruction_address >> 12) & 0xF,
            }
            producer_id = _normalize_producer_id(getattr(active_instr, "producer_id", None))
            if producer_id is not None and producer_id >= 0:
                base_addr = producer_map.get(producer_id)
                if base_addr is not None:
                    imm = int(getattr(active_instr, "imm", 0) or 0)
                    physical_address = _u64(base_addr + imm)
                    candidate["physical_address"] = f"0x{physical_address:x}"
            candidates.append(candidate)
    return candidates


def _select_target_operation_candidate(
    candidates: list[dict[str, object]],
) -> dict[str, object] | None:
    if not candidates:
        return None
    return dict(candidates[0])


class _EncodedInstruction:
    def __init__(self, word: int):
        self.word = int(word) & 0xFFFFFFFF

    def gen_bytecode_int(self, is_spike_resolution: bool):
        return self.word


def _instruction_word(instr: object) -> int | None:
    if instr is None or not hasattr(instr, "gen_bytecode_int"):
        return None
    try:
        return int(instr.gen_bytecode_int(False)) & 0xFFFFFFFF
    except TypeError:
        try:
            return int(instr.gen_bytecode_int(is_spike_resolution=False)) & 0xFFFFFFFF
        except Exception:
            return None
    except Exception:
        return None


def _canonicalize_reserved_special_word(instr_str: object, word: int) -> int | None:
    mnemonic = str(instr_str or "").strip().lower()
    word = int(word) & 0xFFFFFFFF
    if mnemonic == "fence.i":
        return 0x0000100F
    if mnemonic == "fence":
        if (word & 0x7F) != 0x0F or ((word >> 12) & 0x7) != 0:
            return None
        return (word & 0xFFF00000) | 0x0000000F
    return None


def _canonicalize_cva6_reserved_special_instructions(fuzzerstate) -> int:
    canonicalized = 0

    def rewrite_sequence(seq) -> None:
        nonlocal canonicalized
        if not isinstance(seq, list):
            return
        for index, instr in enumerate(list(seq)):
            word = _instruction_word(instr)
            if word is None:
                continue
            replacement = _canonicalize_reserved_special_word(
                getattr(instr, "instr_str", None),
                word,
            )
            if replacement is None or replacement == word:
                continue
            seq[index] = _EncodedInstruction(replacement)
            canonicalized += 1

    for block in list(getattr(fuzzerstate, "instr_objs_seq", []) or []):
        rewrite_sequence(block)
    for attr in ("final_bb", "ctxsv_bb", "ctxdmp_bb"):
        rewrite_sequence(getattr(fuzzerstate, attr, None) or [])
    return canonicalized


class _LabelAssembler:
    def __init__(self) -> None:
        self._items: list[tuple[str, object]] = []

    def label(self, name: str) -> None:
        self._items.append(("label", str(name)))

    def emit(self, encoder: Callable[[int, dict[str, int]], int]) -> None:
        self._items.append(("instr", encoder))

    def finalize(self, base_addr: int) -> list[_EncodedInstruction]:
        labels: dict[str, int] = {}
        cursor = int(base_addr)
        for kind, payload in self._items:
            if kind == "label":
                labels[str(payload)] = cursor
            else:
                cursor += 4
        out: list[_EncodedInstruction] = []
        cursor = int(base_addr)
        for kind, payload in self._items:
            if kind == "label":
                continue
            out.append(_EncodedInstruction(int(payload(cursor, labels))))
            cursor += 4
        return out


def _load_hpm_manifest(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(
            f"HPM manifest must be a JSON object, got {type(payload).__name__}"
        )
    events = payload.get("events")
    if not isinstance(events, list) or not events:
        raise ValueError("HPM manifest requires a non-empty events array")

    normalized_events = []
    seen_counters: set[str] = set()
    for raw_event in events:
        if not isinstance(raw_event, dict):
            raise ValueError("HPM manifest events must be objects")
        counter = str(raw_event.get("counter") or "")
        if not counter.startswith("c"):
            raise ValueError(f"unsupported HPM counter name: {counter!r}")
        counter_index = int(counter[1:])
        if counter_index <= 2:
            raise ValueError(f"HPM counter index must be >= 3, got {counter}")
        if counter in seen_counters:
            raise ValueError(f"duplicate HPM counter assignment: {counter}")
        seen_counters.add(counter)
        normalized_events.append(
            {
                "name": str(raw_event.get("name") or counter),
                "counter": counter,
                "counter_index": counter_index,
                "event_selector": int(raw_event.get("event_selector") or 0),
            }
        )

    return {
        "dut": str(payload.get("dut") or ""),
        "counter_width": int(payload.get("counter_width") or 40),
        "events": normalized_events,
    }


def _alloc_first_free(memview, *, size_bytes: int, alignment: int = 8) -> int:
    if size_bytes <= 0:
        raise ValueError(f"size_bytes must be positive, got {size_bytes}")
    for start, end in list(memview.freepairs):
        aligned = ((int(start) + alignment - 1) // alignment) * alignment
        if aligned + size_bytes <= int(end):
            memview.alloc_mem_range(aligned, aligned + size_bytes)
            return aligned
    raise ValueError(
        f"unable to allocate {size_bytes} bytes with alignment {alignment}"
    )


def _pack_words(raw: bytes) -> list[int]:
    data = bytearray(raw)
    while len(data) % 4:
        data.append(0)
    return [
        int.from_bytes(data[index:index + 4], "little")
        for index in range(0, len(data), 4)
    ]


def _build_hpm_data_layout(manifest: dict) -> tuple[dict[str, int], list[int], int]:
    layout: dict[str, int] = {}
    cursor = 0

    for name in ("save_x26", "save_x27", "save_x28", "save_x29", "save_x30", "save_x31"):
        layout[name] = cursor
        cursor += 8

    snapshot_slots = 2 + len(manifest["events"])
    layout["snapshot_before"] = cursor
    cursor += 8 * snapshot_slots
    layout["snapshot_after"] = cursor
    cursor += 8 * snapshot_slots

    strings: list[tuple[str, bytes]] = [
        ("prefix_phase", b"PMFUZZ_HPM phase=\x00"),
        ("phase_before", b"before\x00"),
        ("phase_after", b"after\x00"),
        (
            "prefix_width_minstret",
            f" width={manifest['counter_width']} minstret=".encode("ascii")
            + b"\x00",
        ),
        ("prefix_mcycle", b" mcycle=\x00"),
        ("newline", b"\n\x00"),
    ]
    for event in manifest["events"]:
        strings.append(
            (
                f"prefix_{event['counter']}",
                f" {event['counter']}=".encode("ascii") + b"\x00",
            )
        )

    blob = bytearray(cursor)
    for key, value in strings:
        layout[key] = len(blob)
        blob.extend(value)
    return layout, _pack_words(bytes(blob)), len(blob)


def _jal_encoder(target_label: str, *, rd: int = 0):
    from rv.rv32i import rv32i_jal

    def _encode(curr_addr: int, labels: dict[str, int]) -> int:
        return rv32i_jal(rd, labels[target_label] - curr_addr)

    return _encode


def _branch_encoder(kind: str, rs1: int, rs2: int, target_label: str):
    from rv.rv32i import rv32i_beq, rv32i_bge, rv32i_bltu

    def _encode(curr_addr: int, labels: dict[str, int]) -> int:
        imm = labels[target_label] - curr_addr
        if kind == "beq":
            return rv32i_beq(rs1, rs2, imm)
        if kind == "bge":
            return rv32i_bge(rs1, rs2, imm)
        if kind == "bltu":
            return rv32i_bltu(rs1, rs2, imm)
        raise ValueError(f"unsupported branch kind: {kind}")

    return _encode


def _build_hpm_capture_sequence(
    *,
    snapshot_addr: int,
    save_base_addr: int,
    manifest: dict,
    initialize_counters: bool,
) -> list[_EncodedInstruction]:
    from rv.asmutil import li_into_reg
    from rv.rv32i import rv32i_addi, rv32i_lui, rv32i_sw
    from rv.rv64i import rv64i_ld, rv64i_sd
    from rv.zicsr import zicsr_csrrs, zicsr_csrrw

    out: list[_EncodedInstruction] = []

    def emit_li(rd: int, value: int) -> None:
        lui_imm, addi_imm = li_into_reg(int(value), False)
        out.append(_EncodedInstruction(rv32i_lui(rd, lui_imm)))
        out.append(_EncodedInstruction(rv32i_addi(rd, rd, addi_imm)))

    emit_li(25, save_base_addr)
    for index, reg in enumerate((26, 27, 28, 29, 30, 31)):
        out.append(_EncodedInstruction(rv64i_sd(25, reg, index * 8)))

    if initialize_counters:
        emit_li(30, _HPM_UART_READY_ADDR)
        out.append(_EncodedInstruction(rv32i_addi(31, 0, 1)))
        out.append(_EncodedInstruction(rv32i_sw(30, 31, 0)))
        for event in manifest["events"]:
            emit_li(30, int(event["event_selector"]))
            out.append(
                _EncodedInstruction(
                    zicsr_csrrw(0, 30, 0x320 + int(event["counter_index"]))
                )
            )
            out.append(
                _EncodedInstruction(
                    zicsr_csrrw(0, 0, 0xB00 + int(event["counter_index"]))
                )
            )

    emit_li(30, snapshot_addr)
    out.append(_EncodedInstruction(zicsr_csrrs(31, 0, 0xB02)))
    out.append(_EncodedInstruction(rv64i_sd(30, 31, 0)))
    out.append(_EncodedInstruction(zicsr_csrrs(31, 0, 0xB00)))
    out.append(_EncodedInstruction(rv64i_sd(30, 31, 8)))
    for slot_index, event in enumerate(manifest["events"], start=2):
        out.append(
            _EncodedInstruction(
                zicsr_csrrs(31, 0, 0xB00 + int(event["counter_index"]))
            )
        )
        out.append(_EncodedInstruction(rv64i_sd(30, 31, slot_index * 8)))

    emit_li(25, save_base_addr)
    for index, reg in enumerate((26, 27, 28, 29, 30, 31)):
        out.append(_EncodedInstruction(rv64i_ld(reg, 25, index * 8)))
    return out


def _build_hpm_flush_sequence(
    *,
    base_addr: int,
    data_base_addr: int,
    layout: dict[str, int],
    manifest: dict,
) -> list[_EncodedInstruction]:
    from rv.asmutil import li_into_reg
    from rv.rv32i import (
        rv32i_addi,
        rv32i_andi,
        rv32i_jalr,
        rv32i_lbu,
        rv32i_lui,
        rv32i_lw,
        rv32i_srl,
        rv32i_sw,
    )
    from rv.rv64i import rv64i_ld

    asm = _LabelAssembler()

    def emit_li(rd: int, value: int) -> None:
        lui_imm, addi_imm = li_into_reg(int(value), False)
        asm.emit(lambda _addr, _labels, rd=rd, lui_imm=lui_imm: rv32i_lui(rd, lui_imm))
        asm.emit(lambda _addr, _labels, rd=rd, addi_imm=addi_imm: rv32i_addi(rd, rd, addi_imm))

    def emit_puts_call(text_addr: int) -> None:
        emit_li(27, text_addr)
        asm.emit(_jal_encoder("puts", rd=1))

    def emit_hex64_call(snapshot_offset: int) -> None:
        emit_li(28, data_base_addr + snapshot_offset)
        asm.emit(lambda _addr, _labels: rv64i_ld(27, 28, 0))
        asm.emit(_jal_encoder("puthex64", rd=1))

    emit_puts_call(data_base_addr + layout["prefix_phase"])
    emit_puts_call(data_base_addr + layout["phase_before"])
    emit_puts_call(data_base_addr + layout["prefix_width_minstret"])
    emit_hex64_call(layout["snapshot_before"] + 0)
    emit_puts_call(data_base_addr + layout["prefix_mcycle"])
    emit_hex64_call(layout["snapshot_before"] + 8)
    for index, event in enumerate(manifest["events"], start=2):
        emit_puts_call(data_base_addr + layout[f"prefix_{event['counter']}"])
        emit_hex64_call(layout["snapshot_before"] + (index * 8))
    emit_puts_call(data_base_addr + layout["newline"])

    emit_puts_call(data_base_addr + layout["prefix_phase"])
    emit_puts_call(data_base_addr + layout["phase_after"])
    emit_puts_call(data_base_addr + layout["prefix_width_minstret"])
    emit_hex64_call(layout["snapshot_after"] + 0)
    emit_puts_call(data_base_addr + layout["prefix_mcycle"])
    emit_hex64_call(layout["snapshot_after"] + 8)
    for index, event in enumerate(manifest["events"], start=2):
        emit_puts_call(data_base_addr + layout[f"prefix_{event['counter']}"])
        emit_hex64_call(layout["snapshot_after"] + (index * 8))
    emit_puts_call(data_base_addr + layout["newline"])
    asm.emit(_jal_encoder("flush_done", rd=0))

    asm.label("puts")
    asm.label("puts_loop")
    asm.emit(lambda _addr, _labels: rv32i_lbu(29, 27, 0))
    asm.emit(_branch_encoder("beq", 29, 0, "puts_done"))
    asm.emit(_jal_encoder("putc", rd=1))
    asm.emit(lambda _addr, _labels: rv32i_addi(27, 27, 1))
    asm.emit(_jal_encoder("puts_loop", rd=0))
    asm.label("puts_done")
    asm.emit(lambda _addr, _labels: rv32i_jalr(0, 1, 0))

    asm.label("puthex64")
    asm.emit(lambda _addr, _labels: rv32i_addi(29, 0, ord("0")))
    asm.emit(_jal_encoder("putc", rd=1))
    asm.emit(lambda _addr, _labels: rv32i_addi(29, 0, ord("x")))
    asm.emit(_jal_encoder("putc", rd=1))
    asm.emit(lambda _addr, _labels: rv32i_addi(28, 0, 60))
    asm.label("puthex64_loop")
    asm.emit(lambda _addr, _labels: rv32i_srl(30, 27, 28))
    asm.emit(lambda _addr, _labels: rv32i_andi(30, 30, 0xF))
    asm.emit(lambda _addr, _labels: rv32i_addi(31, 0, 10))
    asm.emit(_branch_encoder("bltu", 30, 31, "puthex64_digit"))
    asm.emit(lambda _addr, _labels: rv32i_addi(29, 30, 87))
    asm.emit(_jal_encoder("puthex64_emit", rd=0))
    asm.label("puthex64_digit")
    asm.emit(lambda _addr, _labels: rv32i_addi(29, 30, 48))
    asm.label("puthex64_emit")
    asm.emit(_jal_encoder("putc", rd=1))
    asm.emit(lambda _addr, _labels: rv32i_addi(28, 28, -4))
    asm.emit(_branch_encoder("bge", 28, 0, "puthex64_loop"))
    asm.emit(lambda _addr, _labels: rv32i_jalr(0, 1, 0))

    asm.label("putc")
    emit_li(30, _HPM_UART_DATA_ADDR)
    asm.label("putc_wait")
    asm.emit(lambda _addr, _labels: rv32i_lw(31, 30, 0))
    asm.emit(_branch_encoder("bge", 31, 0, "putc_ready"))
    asm.emit(_jal_encoder("putc_wait", rd=0))
    asm.label("putc_ready")
    asm.emit(lambda _addr, _labels: rv32i_sw(30, 29, 0))
    asm.emit(lambda _addr, _labels: rv32i_jalr(0, 1, 0))

    asm.label("flush_done")
    return asm.finalize(base_addr)


def _instrument_hpm_for_fuzzerstate(*, fuzzerstate, manifest: dict) -> None:
    from cascade.cfinstructionclasses import RawDataWord
    from cascade.finalblock import finalblock
    from rv.rv32i import rv32i_jal

    if len(fuzzerstate.bb_start_addr_seq) < 2:
        raise ValueError("expected initial block plus at least one generated block")

    layout, data_words, data_size = _build_hpm_data_layout(manifest)
    data_addr = _alloc_first_free(
        fuzzerstate.memview,
        size_bytes=data_size,
        alignment=8,
    )
    fuzzerstate.bb_start_addr_seq.append(data_addr)
    fuzzerstate.instr_objs_seq.append([RawDataWord(word) for word in data_words])

    capture_before = _build_hpm_capture_sequence(
        snapshot_addr=data_addr + layout["snapshot_before"],
        save_base_addr=data_addr,
        manifest=manifest,
        initialize_counters=True,
    )
    capture_before_size = (len(capture_before) + 1) * 4
    capture_before_addr = _alloc_first_free(
        fuzzerstate.memview,
        size_bytes=capture_before_size,
        alignment=4,
    )
    original_first_fuzz_addr = int(fuzzerstate.bb_start_addr_seq[1])
    capture_jump_addr = capture_before_addr + (len(capture_before) * 4)
    capture_before.append(
        _EncodedInstruction(rv32i_jal(0, original_first_fuzz_addr - capture_jump_addr))
    )
    fuzzerstate.bb_start_addr_seq.append(capture_before_addr)
    fuzzerstate.instr_objs_seq.append(capture_before)

    initial_block = fuzzerstate.instr_objs_seq[0]
    initial_jal_addr = int(fuzzerstate.bb_start_addr_seq[0]) + ((len(initial_block) - 1) * 4)
    initial_block[-1] = _EncodedInstruction(
        rv32i_jal(0, capture_before_addr - initial_jal_addr)
    )

    base_final = finalblock(fuzzerstate, fuzzerstate.design_name)
    if len(base_final) < 5:
        raise ValueError("unexpectedly short final block")
    dump_prefix = list(base_final[:-5])
    stop_tail = list(base_final[-5:])
    final_prefix = _build_hpm_capture_sequence(
        snapshot_addr=data_addr + layout["snapshot_after"],
        save_base_addr=data_addr,
        manifest=manifest,
        initialize_counters=False,
    )
    flush_base_addr = int(fuzzerstate.final_bb_base_addr) + ((len(final_prefix) + len(dump_prefix)) * 4)
    flush_seq = _build_hpm_flush_sequence(
        base_addr=flush_base_addr,
        data_base_addr=data_addr,
        layout=layout,
        manifest=manifest,
    )
    fuzzerstate.final_bb = final_prefix + dump_prefix + flush_seq + stop_tail


def generate_campaign(
    design: str,
    seed: int,
    count: int,
    output_dir: Path,
    hpm_manifest_path: Path | None = None,
    start_index: int = 0,
    require_single_target_operation: bool = False,
    require_target_operation_candidate: bool = False,
    max_target_operation_attempts_per_case: int = _DEFAULT_TARGET_OPERATION_ATTEMPTS_PER_CASE,
) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)

    from cascade.fuzzfromdescriptor import gen_fuzzerstate_elf_expectedvals
    from cascade.fuzzfromdescriptor import gen_new_test_instance
    from common.profiledesign import profile_get_medeleg_mask
    from common.spike import calibrate_spikespeed
    import random
    import shutil

    hpm_manifest = (
        _load_hpm_manifest(hpm_manifest_path)
        if hpm_manifest_path is not None
        else None
    )

    _call_with_spikespeed_lock(calibrate_spikespeed)
    profile_get_medeleg_mask(design)

    for case_index in range(count):
        global_case_index = int(start_index) + case_index
        elf_name = f"{design}_{global_case_index}.elf"
        dest_path = output_dir / elf_name
        sidecar_name = f"{design}_{global_case_index}.json"
        sidecar_path = output_dir / sidecar_name

        max_attempts = (
            max(1, int(max_target_operation_attempts_per_case))
            if (require_single_target_operation or require_target_operation_candidate)
            else 1
        )
        accepted = False
        last_reject_reason = None
        target_operation_filter = (
            "single"
            if require_single_target_operation
            else ("nonempty" if require_target_operation_candidate else "none")
        )
        for target_operation_attempt in range(max_attempts):
            base_instance_id = seed + global_case_index
            if require_single_target_operation:
                derived_instance_id = (
                    seed
                    + global_case_index * int(max_target_operation_attempts_per_case)
                    + target_operation_attempt
                )
            else:
                derived_instance_id = (
                    base_instance_id
                    if target_operation_attempt == 0
                    else base_instance_id
                    + target_operation_attempt * int(max_target_operation_attempts_per_case)
                )
            random.seed(derived_instance_id)

            try:
                descriptor = gen_new_test_instance(design, derived_instance_id, True)
                (
                    memsize,
                    design_name,
                    randseed,
                    nmax_bbs,
                    authorize_privileges,
                ) = descriptor

                (
                    fuzzerstate,
                    rtl_elfpath,
                    expected_regvals,
                    time_gen_bbs,
                    time_spike,
                    time_gen_elf,
                ) = gen_fuzzerstate_elf_expectedvals(
                    memsize,
                    design_name,
                    randseed,
                    nmax_bbs,
                    authorize_privileges,
                    False,
                )

                rtl_path = Path(rtl_elfpath)
                if not rtl_path.exists() or not rtl_path.is_file():
                    raise FileNotFoundError(
                        f"generated ELF not found at {rtl_elfpath!r}"
                    )

                target_candidates = _extract_target_operation_candidates(fuzzerstate)
                if design_name != "cva6":
                    target_candidates = [
                        dict(candidate)
                        for candidate in target_candidates
                        if candidate.get("physical_address") is not None
                    ]
                candidate_count = len(target_candidates)
                should_retry = (
                    candidate_count != 1
                    if require_single_target_operation
                    else (candidate_count == 0 if require_target_operation_candidate else False)
                )
                if should_retry:
                    last_reject_reason = (
                        "target-operation-candidate-count-"
                        f"{candidate_count}"
                    )
                    try:
                        os.unlink(rtl_path)
                    except OSError:
                        pass
                    continue

                cva6_canonicalized_instruction_count = 0
                if design_name == "cva6":
                    cva6_canonicalized_instruction_count = (
                        _canonicalize_cva6_reserved_special_instructions(fuzzerstate)
                    )

                if hpm_manifest is None and cva6_canonicalized_instruction_count == 0:
                    shutil.move(str(rtl_path), str(dest_path))
                else:
                    from cascade.genelf import gen_elf_from_bbs

                    if hpm_manifest is not None:
                        _instrument_hpm_for_fuzzerstate(
                            fuzzerstate=fuzzerstate,
                            manifest=hpm_manifest,
                        )
                    patched_suffix = "hpm" if hpm_manifest is not None else "cva6canon"
                    if hpm_manifest is not None and cva6_canonicalized_instruction_count:
                        patched_suffix = "cva6canon_hpm"
                    patched_elf = Path(
                        gen_elf_from_bbs(
                            fuzzerstate,
                            False,
                            "rtl",
                            f"{fuzzerstate.instance_to_str()}_{patched_suffix}",
                            fuzzerstate.design_base_addr,
                        )
                    )
                    if not patched_elf.exists() or not patched_elf.is_file():
                        raise FileNotFoundError(
                            f"patched ELF not found at {patched_elf!s}"
                        )
                    try:
                        os.unlink(rtl_path)
                    except OSError:
                        pass
                    shutil.move(str(patched_elf), str(dest_path))

                selected_target = _select_target_operation_candidate(target_candidates)
                sidecar = {
                    "campaign_seed": seed,
                    "case_index": global_case_index,
                    "derived_instance_id": derived_instance_id,
                    "target_operation_attempt": target_operation_attempt,
                    "target_operation_filter": target_operation_filter,
                    "memsize": memsize,
                    "design": design_name,
                    "randseed": randseed,
                    "nmax_bbs": nmax_bbs,
                    "authorize_privileges": authorize_privileges,
                    "runtime_attribution_contract": "cascade-target-operation-v1",
                    "target_operation_selection_rule": (
                        "deterministic-single-candidate"
                        if require_single_target_operation
                        else (
                            "deterministic-first-runtime-attributed-candidate"
                            if design_name == "cva6"
                            else "deterministic-first-natural-candidate"
                        )
                    ),
                }
                csr_state = _extract_actual_csr_state(fuzzerstate)
                sidecar["actual_csr_state"] = csr_state
                sidecar["translation"] = _translation_from_csr_state(csr_state)
                sidecar["mseccfg"] = _mseccfg_from_csr_state(csr_state)
                sidecar["pmp_entries"] = _pmp_entries_from_csr_state(csr_state)
                sidecar["target_operation_candidates"] = target_candidates
                if selected_target is not None:
                    sidecar["target_operation_id"] = str(selected_target["target_operation_id"])
                    sidecar["privilege"] = str(selected_target["privilege"])
                    sidecar["access"] = str(selected_target["access"])
                    sidecar["size"] = int(selected_target["size"])
                    if selected_target.get("physical_address") is not None:
                        sidecar["physical_address"] = str(selected_target["physical_address"])
                    sidecar["instruction_address"] = str(selected_target["instruction_address"])
                    sidecar["instruction_page_tag"] = int(selected_target["instruction_page_tag"])
                if cva6_canonicalized_instruction_count:
                    sidecar["emit_canonicalization"] = {
                        "kind": "cva6-reserved-fence-bits-v1",
                        "canonicalized_instruction_count": cva6_canonicalized_instruction_count,
                    }
                if hpm_manifest is not None:
                    sidecar["hpm_manifest"] = {
                        "dut": str(hpm_manifest.get("dut") or ""),
                        "counter_width": int(hpm_manifest.get("counter_width") or 0),
                        "events": [dict(event) for event in hpm_manifest["events"]],
                    }
                sidecar_path.write_text(
                    json.dumps(sidecar, indent=2, ensure_ascii=True) + "\n",
                    encoding="ascii",
                )
                accepted = True
                break
            except Exception as exc:
                print(f"Case {design}_{case_index}: {exc}", file=sys.stderr)
                for path in (dest_path, sidecar_path):
                    try:
                        path.unlink(missing_ok=True)
                    except Exception:
                        pass
                return 1

        if not accepted:
            print(
                f"Case {design}_{case_index}: unable to generate a {target_operation_filter} "
                f"target-operation case after {max_attempts} attempts"
                + (f" ({last_reject_reason})" if last_reject_reason else ""),
                file=sys.stderr,
            )
            for path in (dest_path, sidecar_path):
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass
            return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2

    try:
        validate_args(args)
    except ValueError as exc:
        print(f"Argument error: {exc}", file=sys.stderr)
        return 2

    output_dir = Path(args.output)
    return generate_campaign(
        args.design,
        args.seed,
        args.count,
        output_dir,
        Path(args.hpm_manifest) if args.hpm_manifest else None,
        args.start_index,
        args.require_single_target_operation,
        args.require_target_operation_candidate,
        args.max_target_operation_attempts_per_case,
    )


if __name__ == "__main__":
    raise SystemExit(main())
