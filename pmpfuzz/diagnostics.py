from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum


class FailureClass(IntEnum):
    WRONG_MCAUSE = 1
    UNEXPECTED_NO_TRAP = 2
    UNEXPECTED_TRAP = 3
    WRONG_PATH = 4
    INFRA_ERROR = 5
    FORBIDDEN_SIDE_EFFECT = 6
    MISSING_EXPECTED_SIDE_EFFECT = 7
    STALE_PMP_PERMISSION = 8
    STALE_TLB_PERMISSION = 9
    STALE_PTW_PERMISSION = 10


class ObservationKind(IntEnum):
    TRAP = 1
    COMPLETION = 2


class ObservationPhase(IntEnum):
    SETUP = 0
    PROBE = 1
    COMPLETED = 2
    WARMUP = 3
    FINAL = 4
    FINAL_SENTINEL_INITIAL = 5
    FINAL_SENTINEL_MODIFIED = 6
    FINAL_SENTINEL_OTHER = 7


PASS_TOHOST = 1
MCAUSE_MASK = 0xFF
MTVAL_MASK = 0xFFFFFFFF
FAILURE_CLASS_SHIFT = 40
MCAUSE_SHIFT = 32

OBSERVATION_SCHEMA_VERSION = 1
OBSERVATION_VERSION_SHIFT = 29
OBSERVATION_KIND_SHIFT = 28
OBSERVATION_PHASE_SHIFT = 25
OBSERVATION_MCAUSE_SHIFT = 21
OBSERVATION_MEPC_SHIFT = 17
OBSERVATION_VERSION_MASK = 0x1
OBSERVATION_KIND_MASK = 0x1
OBSERVATION_PHASE_MASK = 0x7
OBSERVATION_MCAUSE_MASK = 0xF
OBSERVATION_MEPC_MASK = 0xF
OBSERVATION_MTVAL_MASK = 0x1FFFF


@dataclass(frozen=True)
class DecodedTohost:
    observed_tohost: int
    failure_class: str | None
    observed_mcause: int | None
    observed_mtval: int | None


@dataclass(frozen=True)
class ObservedEvent:
    kind: ObservationKind
    mcause: int
    mtval_fingerprint: int
    mepc_tag: int
    phase: ObservationPhase


def encode_observation_payload(
    kind: ObservationKind,
    *,
    mcause: int,
    mtval: int,
    mepc: int,
    phase: ObservationPhase,
) -> int:
    return (
        (OBSERVATION_SCHEMA_VERSION << OBSERVATION_VERSION_SHIFT)
        | (((int(kind) - 1) & OBSERVATION_KIND_MASK) << OBSERVATION_KIND_SHIFT)
        | ((int(phase) & OBSERVATION_PHASE_MASK) << OBSERVATION_PHASE_SHIFT)
        | ((mcause & OBSERVATION_MCAUSE_MASK) << OBSERVATION_MCAUSE_SHIFT)
        | (mepc_tag(mepc) << OBSERVATION_MEPC_SHIFT)
        | mtval_fingerprint(mtval)
    )


def decode_observation_payload(payload: int | None) -> ObservedEvent | None:
    if payload is None:
        return None
    version = (payload >> OBSERVATION_VERSION_SHIFT) & OBSERVATION_VERSION_MASK
    if version != OBSERVATION_SCHEMA_VERSION:
        return None
    try:
        kind = ObservationKind(((payload >> OBSERVATION_KIND_SHIFT) & OBSERVATION_KIND_MASK) + 1)
        phase = ObservationPhase((payload >> OBSERVATION_PHASE_SHIFT) & OBSERVATION_PHASE_MASK)
    except ValueError:
        return None
    return ObservedEvent(
        kind=kind,
        mcause=(payload >> OBSERVATION_MCAUSE_SHIFT) & OBSERVATION_MCAUSE_MASK,
        mtval_fingerprint=payload & OBSERVATION_MTVAL_MASK,
        mepc_tag=(payload >> OBSERVATION_MEPC_SHIFT) & OBSERVATION_MEPC_MASK,
        phase=phase,
    )


def mtval_fingerprint(value: int) -> int:
    folded = value
    for shift in range(17, 64, 17):
        folded ^= value >> shift
    return folded & OBSERVATION_MTVAL_MASK


def mepc_tag(value: int) -> int:
    return (value >> 12) & OBSERVATION_MEPC_MASK


def encode_failure_payload(failure_class: FailureClass, mcause: int = 0, mtval: int = 0) -> int:
    return (
        (int(failure_class) << FAILURE_CLASS_SHIFT)
        | ((mcause & MCAUSE_MASK) << MCAUSE_SHIFT)
        | (mtval & MTVAL_MASK)
    )


def encode_tohost_failure(failure_class: FailureClass, mcause: int = 0, mtval: int = 0) -> int:
    return (encode_failure_payload(failure_class, mcause, mtval) << 1) | 1


def decode_tohost_payload(payload: int | None) -> DecodedTohost | None:
    if payload is None:
        return None
    class_id = (payload >> FAILURE_CLASS_SHIFT) & 0xFF
    mcause = (payload >> MCAUSE_SHIFT) & MCAUSE_MASK
    mtval = payload & MTVAL_MASK
    try:
        failure_class = FailureClass(class_id).name.lower()
    except ValueError:
        failure_class = None
    return DecodedTohost(
        observed_tohost=payload,
        failure_class=failure_class,
        observed_mcause=mcause if failure_class else None,
        observed_mtval=mtval if failure_class else None,
    )


def classify_log_failure(text: str, returncode: int, decoded: DecodedTohost | None = None) -> str:
    if "Pipeline has hung" in text:
        return "pipeline_hung"
    if decoded and decoded.failure_class:
        return decoded.failure_class
    if "Assertion failed" in text or "%Error:" in text:
        return "sim_assert" if returncode != 0 else "tohost_fail"
    if returncode != 0:
        return "infra_failure"
    return "unknown_failure"


def failed_tohost_from_log(text: str) -> int | None:
    failed = re.search(r"\*\*\* FAILED \*\*\*(?: \(tohost = (\d+)\))?", text)
    if not failed:
        return None
    return int(failed.group(1)) if failed.group(1) else None


def emit_failure_tohost_lines(class_name: str, mcause_reg: str = "t2", mtval_reg: str = "t3") -> list[str]:
    failure_class = FailureClass[class_name]
    return [
        f"    li a0, {int(failure_class)}",
        f"    slli a0, a0, {FAILURE_CLASS_SHIFT}",
        "    li t4, 0xff",
        f"    and t4, {mcause_reg}, t4",
        f"    slli t4, t4, {MCAUSE_SHIFT}",
        "    or a0, a0, t4",
        "    li t4, 0xffffffff",
        f"    and t4, {mtval_reg}, t4",
        "    or a0, a0, t4",
        "    slli a0, a0, 1",
        "    ori a0, a0, 1",
    ]


def emit_static_failure_tohost_lines(class_name: str, mcause: int = 0, mtval: int = 0) -> list[str]:
    return [f"    li a0, 0x{encode_tohost_failure(FailureClass[class_name], mcause, mtval):x}"]


def emit_observation_tohost_lines(
    kind_name: str,
    *,
    phase: ObservationPhase | None = None,
    phase_reg: str = "t6",
    mcause_reg: str = "t2",
    mtval_reg: str = "t3",
    mepc_reg: str = "t4",
) -> list[str]:
    kind = ObservationKind[kind_name]
    prefix = (OBSERVATION_SCHEMA_VERSION << OBSERVATION_VERSION_SHIFT) | (
        (int(kind) - 1) << OBSERVATION_KIND_SHIFT
    )
    if phase is not None:
        prefix |= int(phase) << OBSERVATION_PHASE_SHIFT
    lines = [
        f"    li a0, 0x{prefix:x}",
    ]
    if phase is None:
        lines.extend(
            [
                f"    li t5, 0x{OBSERVATION_PHASE_MASK:x}",
                f"    and t5, {phase_reg}, t5",
                f"    slli t5, t5, {OBSERVATION_PHASE_SHIFT}",
                "    or a0, a0, t5",
            ]
        )
    lines.extend(
        [
            f"    li t5, 0x{OBSERVATION_MCAUSE_MASK:x}",
            f"    and t5, {mcause_reg}, t5",
            f"    slli t5, t5, {OBSERVATION_MCAUSE_SHIFT}",
            "    or a0, a0, t5",
            f"    srli t5, {mepc_reg}, 12",
            "    andi t5, t5, 0xf",
            f"    slli t5, t5, {OBSERVATION_MEPC_SHIFT}",
            "    or a0, a0, t5",
            f"    mv t5, {mtval_reg}",
            f"    srli t1, {mtval_reg}, 17",
            "    xor t5, t5, t1",
            f"    srli t1, {mtval_reg}, 34",
            "    xor t5, t5, t1",
            f"    srli t1, {mtval_reg}, 51",
            "    xor t5, t5, t1",
            f"    li t1, 0x{OBSERVATION_MTVAL_MASK:x}",
            "    and t5, t5, t1",
            "    or a0, a0, t5",
            "    slli a0, a0, 1",
            "    ori a0, a0, 1",
        ]
    )
    return lines
