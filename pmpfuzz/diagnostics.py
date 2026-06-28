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


PASS_TOHOST = 1
MCAUSE_MASK = 0xFF
MTVAL_MASK = 0xFFFFFFFF
FAILURE_CLASS_SHIFT = 40
MCAUSE_SHIFT = 32


@dataclass(frozen=True)
class DecodedTohost:
    observed_tohost: int
    failure_class: str | None
    observed_mcause: int | None
    observed_mtval: int | None


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
