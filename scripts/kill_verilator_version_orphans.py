#!/usr/bin/env python3
from __future__ import annotations

import os
import signal
import time


PATTERNS = (
    "/home/dubhe/wjs/pmp-duts/chipyard-1.14.0/.conda-env/bin/verilator --version",
    "verilator --version | perl",
)


def matching_pids() -> list[int]:
    current = os.getpid()
    matches: list[int] = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        if pid == current:
            continue
        try:
            raw = open(f"/proc/{pid}/cmdline", "rb").read()
        except OSError:
            continue
        command = raw.replace(b"\0", b" ").decode("utf-8", errors="replace")
        if any(pattern in command for pattern in PATTERNS):
            matches.append(pid)
    return matches


def kill_all(sig: signal.Signals) -> list[int]:
    killed: list[int] = []
    for pid in matching_pids():
        try:
            os.kill(pid, sig)
            killed.append(pid)
        except ProcessLookupError:
            continue
    return killed


if __name__ == "__main__":
    term = kill_all(signal.SIGTERM)
    time.sleep(2)
    remaining = matching_pids()
    killed = []
    if remaining:
        killed = kill_all(signal.SIGKILL)
        time.sleep(1)
    print(f"sigterm={len(term)} sigkill={len(killed)} remaining={len(matching_pids())}")
