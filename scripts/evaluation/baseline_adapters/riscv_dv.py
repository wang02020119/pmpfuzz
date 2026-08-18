#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from pmpfuzz.bapc import (
    BAPC_CORE_VERSION_V4,
    BAPC_SCHEMA_VERSION,
    build_bapc_coverage_universe,
    summarize_bapc_target_operation,
)

try:
    from riscv_dv_static_pmp import derive_static_pmp, recover_trap_address
except ImportError:
    derive_static_pmp = None
    recover_trap_address = None
from pmpfuzz.coverage_universe import classify_observed_bins, coverage_universe_filename
from pmpfuzz.diagnostics import decode_observation_payload


SUPPORTED_DUTS = ("rocket-clean", "boom-clean", "cva6-clean")


DUT_PARAMS = {
    "rocket-clean": {"pmpcfg_csrs": [0x3A0, 0x3A2], "pmpaddr_count": 16, "read_mseccfg": 0},
    "boom-clean": {"pmpcfg_csrs": [0x3A0, 0x3A2], "pmpaddr_count": 16, "read_mseccfg": 0},
    "cva6-clean": {"pmpcfg_csrs": [0x3A0, 0x3A2],
                   "pmpaddr_count": 16, "read_mseccfg": 0},
}

_WORKSPACE_ROOT = Path(
    os.environ.get("PMPFUZZ_WORKSPACE", str(Path.home() / "pmpfuzz-workspace"))
).expanduser()
_CHIPYARD_ROOT = Path(
    os.environ.get("CHIPYARD_DIR", str(_WORKSPACE_ROOT / "chipyard"))
).expanduser()
RISCV_DV_ROOT = Path(
    os.environ.get("RISCV_DV_ROOT", str(_WORKSPACE_ROOT / "third_party" / "riscv-dv"))
).expanduser()
RISCV_DV_VENV = Path(
    os.environ.get("RISCV_DV_VENV", str(_WORKSPACE_ROOT / "third_party" / ".venv-rdv"))
).expanduser()
CHIPYARD_SIM_DIR = _CHIPYARD_ROOT / "sims" / "verilator"
DRAMSIM_INI_DIR = str(
    _CHIPYARD_ROOT / "generators" / "testchipip" / "src" / "main" / "resources" / "dramsim2_ini"
)
SIM_BINARIES = {
    "rocket-clean": CHIPYARD_SIM_DIR / "simulator-chipyard.harness-RocketConfig",
    "boom-clean": CHIPYARD_SIM_DIR / "simulator-chipyard.harness-SmallBoomV3Config",
    "cva6-clean": CHIPYARD_SIM_DIR / "simulator-chipyard.harness-CVA6Config",
}



_TRACE_RE = re.compile(
    r"C0:\s+\d+\s+\[[01]\]\s+pc=\[([0-9a-f]{16})\]\s+W\[r\s*(\d+)=([0-9a-f]{16})\]\[[01]\]"
)
_TRACE_INST_RE = re.compile(r"inst=\[([0-9a-f]+)\]")
_EXIT_RE = re.compile(r"exit code =\s*(\d+)")
_TOHOST_RE = re.compile(r"tohost =\s*(-?\d+)")
_TIMEOUT_RE = re.compile(r"\(timeout\)")

_DASM_RE = re.compile(
    r"^\s*\d+\s+0x([0-9a-f]+)\s+M\s+\(0x([0-9a-f]+)\)\s+DASM\([0-9a-f]+\)"
)
_GRAFT_WINDOW_START = "rdv_graft_start"
_GRAFT_WINDOW_END = "rdv_graft_end"


RESET_OFF_PATTERNS = {
    "rocket-clean": {
        "count": 8,
        "source": (
            "v1 formal rocket snapshots: pmpcfg0 reset readback "
            "0x0706010405060302, pmpcfg2 0x0"
        ),
    },
    "cva6-clean": {
        "count": 1,
        "source": (
            "cva6 RTL pmp_csr_state probe (pilot tools/cva6_probe5.log): "
            "all entries cfg=0x0 addr=0x0"
        ),
    },
    "boom-clean": {
        "count": None,
        "source": (
            "no PMP readback channel on the frozen boom DUT binary "
            "(v1 documented limitation)"
        ),
    },
}


_CSR_WORDS = {
    "mcause": 0x342023F3,
    "mtval": 0x34302E73,
    "mepc": 0x34102EF3,
    "mstatus": 0x30002F73,
    "satp": 0x18002FF3,
    "mseccfg": 0x74702FF3,
}


def _hex(v):
    return hex(int(v))


def _git_head(path):
    try:
        out = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return out.stdout.strip()
    except Exception:
        return ""


def _git_is_dirty(path):
    try:
        out = subprocess.run(
            ["git", "-C", str(path), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return bool(out.stdout.strip())
    except Exception:
        return True


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()



def _symbol_window(elf_path, start_sym, end_sym):
    try:
        out = subprocess.run(
            ["riscv64-unknown-elf-nm", "-a", str(elf_path)],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
    except Exception:
        return None
    start = end = None
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[-1] in (start_sym, end_sym):
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            if parts[-1] == start_sym:
                start = addr
            else:
                end = addr
    if start is None or end is None or end <= start:
        return None
    return (start, end)


def _window_inst_words(elf_path, window):
    if window is None:
        return None
    try:
        out = subprocess.run(
            ["riscv64-unknown-elf-objdump", "-d", str(elf_path)],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
    except Exception:
        return None
    start, end = window
    words = []
    in_window = False
    for line in out.stdout.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+([0-9a-f]{4,8})\s", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if addr == start:
            in_window = True
        if in_window:
            if addr >= end:
                break
            words.append((addr, int(m.group(2), 16)))
    return words or None


def _graft_window(elf_path):
    return _symbol_window(elf_path, _GRAFT_WINDOW_START, _GRAFT_WINDOW_END)


def _graft_inst_words(elf_path):
    return _window_inst_words(elf_path, _graft_window(elf_path))


def _probe_window(elf_path):
    return _symbol_window(elf_path, "rdv_probe_start", "rdv_probe_end")


def _symbol_address(elf_path, symbol):
    try:
        out = subprocess.run(
            ["riscv64-unknown-elf-nm", "-a", str(elf_path)],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
    except Exception:
        return None
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[-1] == symbol:
            try:
                return int(parts[0], 16)
            except ValueError:
                return None
    return None


def _c0_items(log_text):
    items = []
    for line in str(log_text or "").splitlines():
        m = _TRACE_RE.match(line)
        if not m:
            continue
        im = _TRACE_INST_RE.search(line)
        if not im:
            continue
        try:
            items.append((int(m.group(1), 16), int(im.group(1), 16)))
        except ValueError:
            continue
    return items


def _dasm_items(dasm_path):
    try:
        text = dasm_path.read_text(encoding="ascii", errors="replace")
    except OSError:
        return []
    items = []
    for line in text.splitlines():
        m = _DASM_RE.match(line)
        if m:
            items.append((int(m.group(1), 16), int(m.group(2), 16)))
    return items


def _match_words_in_trace(words, items):
    if not words:
        return None
    idx = 0
    matched = []
    for addr, inst in items:
        if inst == words[idx][1]:
            matched.append((addr, inst))
            idx += 1
            if idx == len(words):
                return matched
    return None


def extract_graft_evidence(log_text, elf_path, dut, graft_path, dasm_path=None):
    if graft_path is None or not Path(graft_path).exists():
        return None
    try:
        sidecar = json.loads(Path(graft_path).read_text(encoding="utf-8"))
    except Exception:
        sidecar = None
    words = _graft_inst_words(elf_path)
    channel = None
    matched = None
    if dut == "rocket-clean" and words:
        matched = _match_words_in_trace(words, _c0_items(log_text))
        if matched:
            channel = "commit-trace"
    elif dut == "cva6-clean" and words and dasm_path is not None and Path(dasm_path).exists():
        matched = _match_words_in_trace(words, _dasm_items(Path(dasm_path)))
        if matched:
            channel = "dasm-trace"
    return {
        "graft": (sidecar or {}).get("graft"),
        "sidecar_present": bool(sidecar),
        "graft_window_symbols_present": _graft_window(elf_path) is not None,
        "graft_inst_words": ["%x" % word for _, word in (words or [])],
        "evidence_channel": channel,
        "matched_inst_words": ["%x" % word for _, word in (matched or [])],
    }


def _off_patterns(snapshot):
    patterns = set()
    pmpcfg = [int(v, 16) for v in snapshot["final_snapshot"]["pmpcfg"]]
    for entry_index in range(16):
        byte = (pmpcfg[entry_index // 8] >> (8 * (entry_index % 8))) & 0xFF
        if ((byte >> 3) & 0x3) != 0:
            continue
        patterns.add((byte & 1, (byte >> 1) & 1, (byte >> 2) & 1, (byte >> 7) & 1))
    return patterns


def _programmed_patterns(snapshot):
    patterns = []
    pmpcfg = [int(v, 16) for v in snapshot["final_snapshot"]["pmpcfg"]]
    for entry_index in range(16):
        byte = (pmpcfg[entry_index // 8] >> (8 * (entry_index % 8))) & 0xFF
        a_field = (byte >> 3) & 0x3
        if a_field == 0:
            continue
        mode = {1: "tor", 2: "na4", 3: "napot"}.get(a_field, "off")
        patterns.append(
            (mode, byte & 1, (byte >> 1) & 1, (byte >> 2) & 1, (byte >> 7) & 1)
        )
    return patterns


def build_pmp_programming_stats(dut, case_rows):
    if not case_rows:
        return None
    grafted = any(r.get("graft_evidence") is not None for r in case_rows)
    completed = sum(1 for r in case_rows if r.get("completed"))
    readback = [r for r in case_rows if r.get("snapshot_present")]
    trace = [r for r in case_rows if r.get("graft_executed")]
    static = [
        r for r in case_rows
        if not r.get("snapshot_present")
        and not r.get("graft_executed")
        and r.get("completed")
        and (r.get("graft_evidence") or {}).get("sidecar_present")
    ]
    none = [
        r for r in case_rows
        if not r.get("snapshot_present")
        and not r.get("graft_executed")
        and not (r.get("completed") and (r.get("graft_evidence") or {}).get("sidecar_present"))
    ]
    programmed_counts = [r["programmed_entries"] for r in readback if r.get("programmed_entries") is not None]
    pattern_counts = {}
    for r in readback:
        for pat in r.get("programmed_patterns") or []:
            key = json.dumps(pat, sort_keys=True)
            pattern_counts[key] = pattern_counts.get(key, 0) + 1
    breakdown = []
    for key, count in sorted(pattern_counts.items()):
        mode, rw, w_, x_, l_ = json.loads(key)
        breakdown.append({"mode": mode, "r": int(rw), "w": int(w_), "x": int(x_), "l": int(l_), "count": count})
    final_off = set()
    for r in readback:
        final_off.update(r.get("off_patterns") or [])
    reset_info = RESET_OFF_PATTERNS.get(dut, {"count": None, "source": "unknown dut"})
    locked_total = sum(r.get("locked_entries") or 0 for r in readback)
    total_programmed = sum(programmed_counts)
    notes = [
        "supplementary stat; does not change the 144-bin BAPC scoring "
        "(completions remain ineligible, D4 unchanged)",
    ]
    if grafted:
        notes.append(
            "graft is deterministic: entry0 NAPOT full-address-space RWX unlocked"
        )
    else:
        notes.append(
            "R5 (SV-generator eUVM port): programs program PMP themselves; "
            "entry0 is the generator's forced code-entry region (TOR RWX); "
            "entries 1..N-1 are randomized"
        )
    stats = {
        "schema_version": 1,
        "graft": (
            "upstream-enable-all"
            if grafted
            else "none (SV-generator programs program PMP themselves)"
        ),
        "cases_with_snapshot": len(readback),
        "avg_programmed_entries": (
            float(sum(programmed_counts)) / len(programmed_counts)
            if programmed_counts
            else None
        ),
        "distinct_programmed_patterns": len(pattern_counts),
        "pattern_breakdown": breakdown,
        "locked_entries": locked_total,
        "locked_ratio": (
            float(locked_total) / total_programmed if total_programmed else None
        ),
        "reset_off_patterns": reset_info["count"],
        "reset_off_patterns_source": reset_info["source"],
        "final_off_patterns": len(final_off),
        "evidence_channels": {
            "readback_snapshot": len(readback),
            "graft_execution_trace": len(trace),
            "static_sidecar_deductive": len(static),
            "none": len(none),
        },
        "completed_cases": completed,
        "notes": notes,
    }
    return stats


def _handler_symbol(elf_path):
    try:
        out = subprocess.run(
            ["riscv64-unknown-elf-nm", str(elf_path)],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
    except Exception:
        return None
    for line in out.stdout.splitlines():
        if line.strip().endswith(" rdv_trap_handler"):
            try:
                return int(line.split()[0], 16)
            except ValueError:
                return None
    return None


def extract_snapshot(log_text, elf_path, dut):
    params = DUT_PARAMS[dut]
    handler_addr = _handler_symbol(elf_path)
    if handler_addr is None:
        return None
    handler_end = handler_addr + 0x800
    want = dict(_CSR_WORDS)
    for csr in params["pmpcfg_csrs"]:
        want["pmpcfg%d" % ((csr - 0x3A0) // 2)] = (csr << 20) | 0x2373
    for i in range(params["pmpaddr_count"]):
        csr = 0x3B0 + i
        want["pmpaddr%d" % i] = (csr << 20) | 0x2373
    found = {}
    for line in str(log_text or "").splitlines():
        m = _TRACE_RE.match(line)
        if not m:
            continue
        pc = int(m.group(1), 16)
        if not (handler_addr <= pc < handler_end):
            continue
        inst_m = _TRACE_INST_RE.search(line)
        if not inst_m:
            continue
        inst = int(inst_m.group(1), 16)
        value = int(m.group(3), 16)
        for name, word in want.items():
            if inst == word:
                if name not in found:
                    found[name] = value
                break
    if "mcause" not in found:
        return None
    pmpcfg = [found.get("pmpcfg%d" % i, 0) for i in range(8)]
    pmpaddr = [found.get("pmpaddr%d" % i, 0) for i in range(16)]
    trap = {
        "mcause": found.get("mcause", 0),
        "mtval": _hex(found.get("mtval", 0)),
        "mepc": _hex(found.get("mepc", 0)),
        "mstatus": _hex(found.get("mstatus", 0)),
        "satp": _hex(found.get("satp", 0)),
    }
    if params["read_mseccfg"]:
        trap["mseccfg"] = _hex(found.get("mseccfg", 0))
    else:
        trap["mseccfg"] = None
    final = {
        "pmpcfg": [_hex(v) for v in pmpcfg],
        "pmpaddr": [_hex(v) for v in pmpaddr],
        "satp": _hex(found.get("satp", 0)),
        "mseccfg": None,
        "mstatus": _hex(found.get("mstatus", 0)),
    }
    if params["read_mseccfg"]:
        final["mseccfg"] = _hex(found.get("mseccfg", 0))
    return {
        "schema_version": 1,
        "dut": dut,
        "handler_pc": _hex(handler_addr),
        "trap_records": [trap],
        "final_snapshot": final,
    }


def extract_channels(log_text):
    text = str(log_text or "")
    exit_m = _EXIT_RE.search(text)
    tohost_m = _TOHOST_RE.search(text)
    exit_val = int(exit_m.group(1)) if exit_m else None
    tohost_val = int(tohost_m.group(1)) if tohost_m else None
    return exit_val, tohost_val, bool(_TIMEOUT_RE.search(text))


def classify_case(log_text, returncode):
    exit_val, tohost_val, timed_out = extract_channels(log_text)
    infra = None
    obs = None
    if exit_val is not None:
        if exit_val & 0x80000000:
            infra = {
                "failure_class": "handler-self-fault",
                "mcause": (exit_val >> 8) & 0xFF,
                "mtval_low": exit_val & 0xFF,
            }
        elif exit_val & 0x40000000:
            infra = {"failure_class": "unexpected-record-shape", "raw": exit_val}
        else:
            obs = decode_observation_payload(exit_val)
    cross_check = None
    if tohost_val is not None and tohost_val >= 0 and tohost_val != exit_val:
        cross_check = tohost_val
    if infra is not None:
        return {
            "status": "infra_failure",
            "observation_valid": False,
            "observed_event": None,
            "failure_class": infra["failure_class"],
            "observed_mcause": infra.get("mcause"),
            "infra": infra,
            "exit_value": exit_val,
            "tohost_value": tohost_val,
            "cross_check": cross_check,
        }
    if obs is not None:
        return {
            "status": "observed",
            "observation_valid": True,
            "observed_event": obs.kind.name.lower(),
            "failure_class": None,
            "observed_mcause": obs.mcause,
            "observed_mepc_tag": obs.mepc_tag,
            "observed_mtval_fingerprint": obs.mtval_fingerprint,
            "observation_phase": int(obs.phase),
            "infra": None,
            "exit_value": exit_val,
            "tohost_value": tohost_val,
            "cross_check": cross_check,
        }
    if timed_out:
        return {
            "status": "timeout",
            "observation_valid": False,
            "observed_event": None,
            "failure_class": "timeout",
            "infra": None,
            "exit_value": exit_val,
            "tohost_value": tohost_val,
            "cross_check": cross_check,
        }
    if returncode not in (None, 0):
        return {
            "status": "infra_failure",
            "observation_valid": False,
            "observed_event": None,
            "failure_class": "sim-returncode",
            "infra": None,
            "exit_value": exit_val,
            "tohost_value": tohost_val,
            "cross_check": cross_check,
        }
    return {
        "status": "infra_failure",
        "observation_valid": False,
        "observed_event": None,
        "failure_class": "missing-completion-marker",
        "infra": None,
        "exit_value": exit_val,
        "tohost_value": tohost_val,
        "cross_check": cross_check,
    }
_MCAUSE_ACCESS = {1: "fetch", 5: "load", 7: "store", 12: "fetch", 13: "load", 15: "store"}
_PRIV_MAP = {0: "u", 1: "s", 3: "m"}


def build_context(snapshot):
    final = snapshot["final_snapshot"]
    trap = snapshot["trap_records"][0]
    satp = int(final["satp"], 16)
    mode = (satp >> 60) & 0xF
    translation = {0: "bare", 8: "sv39"}.get(mode, "other")
    mstatus = int(final["mstatus"], 16)
    mpp = (mstatus >> 11) & 0x3
    privilege = _PRIV_MAP.get(mpp, "m")
    mprv = (mstatus >> 17) & 0x1
    entries = []
    pmpcfg = [int(v, 16) for v in final["pmpcfg"]]
    pmpaddr = [int(v, 16) for v in final["pmpaddr"]]
    for entry_index in range(16):
        byte = (pmpcfg[entry_index // 8] >> (8 * (entry_index % 8))) & 0xFF
        a_field = (byte >> 3) & 0x3
        mode_name = {0: "off", 1: "tor", 2: "na4", 3: "napot"}.get(a_field, "off")
        entries.append(
            {
                "index": entry_index,
                "address_mode": mode_name,
                "pmpaddr": pmpaddr[entry_index] if entry_index < len(pmpaddr) else 0,
                "read": bool(byte & 0x1),
                "write": bool(byte & 0x2),
                "execute": bool(byte & 0x4),
                "locked": bool(byte & 0x80),
            }
        )
    context = {
        "translation": translation,
        "mseccfg": {},
        "pmp_entries": entries,
        "default_privilege": privilege,
        "default_access": _MCAUSE_ACCESS.get(trap.get("mcause")),
        "default_size": 4,
        "size_source": "default",
        "default_address": int(trap.get("mtval"), 16),
        "default_mprv": bool(mprv),
        "default_mpp": privilege,
    }
    if final.get("mseccfg"):
        context["mseccfg"] = {"raw": final["mseccfg"]}
    return context


def build_static_context(static_state, mcause, address, access, context_evidence):
    entries = static_state.get("entries") or []
    return {
        "translation": "bare",
        "mseccfg": {},
        "pmp_entries": entries,
        "default_privilege": "m",
        "default_access": access,
        "default_size": 4,
        "size_source": "default",
        "default_address": address if address is not None else 0,
        "default_mprv": False,
        "default_mpp": "m",
        "context_evidence": context_evidence or "deductive-from-generated-stream",
    }


def score_case(snapshot, classified, bapc_core_version=BAPC_CORE_VERSION_V4,
               static_state=None, static_address=None, static_evidence=None):
    if classified.get("infra") is not None or not classified.get("observation_valid"):
        reason = "infra-failure-%s" % (classified.get("failure_class") or "unknown")
        return (
            {
                "eligible": False,
                "qualification_reason": reason,
                "observed_bins": [],
                "event_records": [],
            },
            reason,
        )
    event = str(classified.get("observed_event") or "")
    if event == "completion":
        return (
            {
                "eligible": False,
                "qualification_reason": "completion-no-designated-target-op",
                "observed_bins": [],
                "event_records": [],
            },
            "completion-no-designated-target-op",
        )
    if snapshot is None:
        if static_state is None:
            return (
                {
                    "eligible": False,
                    "qualification_reason": "missing-runtime-snapshot",
                    "observed_bins": [],
                    "event_records": [],
                },
                "missing-runtime-snapshot",
            )
        mcause = classified.get("observed_mcause")
        access = _MCAUSE_ACCESS.get(mcause) if isinstance(mcause, int) else None
        if access is None:
            return (
                {
                    "eligible": False,
                    "qualification_reason": "missing-runtime-snapshot",
                    "observed_bins": [],
                    "event_records": [],
                },
                "missing-runtime-snapshot",
            )
        context = build_static_context(
            static_state, mcause, static_address, access, static_evidence
        )
        result = {
            "observation_valid": True,
            "observed_event": event,
            "observed_mcause": mcause,
            "observed_mepc_tag": classified.get("observed_mepc_tag"),
            "observed_mtval_fingerprint": classified.get("observed_mtval_fingerprint"),
        }
        bapc = summarize_bapc_target_operation(
            context, result, bapc_core_version=bapc_core_version
        )
        if static_address is None:
            bapc["observed_bins"] = [
                b for b in (bapc.get("observed_bins") or [])
                if not str(b).startswith("family=mode-decision")
            ]
            bapc["mode_decision_omitted_reason"] = (
                "trap-address-not-recoverable-from-tohost-record"
            )
        bapc["context_evidence"] = context["context_evidence"]
        bapc["context"] = context
        return bapc, str(bapc.get("qualification_reason") or "")
    context = build_context(snapshot)
    if context["translation"] == "sv39":
        return (
            {
                "eligible": False,
                "qualification_reason": "sv39-address-unresolved",
                "observed_bins": [],
                "event_records": [],
            },
            "sv39-address-unresolved",
        )
    result = {
        "observation_valid": True,
        "observed_event": event,
        "observed_mcause": classified.get("observed_mcause"),
        "observed_mepc_tag": classified.get("observed_mepc_tag"),
        "observed_mtval_fingerprint": classified.get("observed_mtval_fingerprint"),
    }
    bapc = summarize_bapc_target_operation(
        context,
        result,
        bapc_core_version=bapc_core_version,
    )
    return bapc, str(bapc.get("qualification_reason") or "")


def timeline_line(
    campaign_id,
    dut,
    seed,
    completion_seq,
    case_id,
    elapsed_wall_seconds,
    case_elapsed_seconds,
    completed_cases,
    eligible_cases,
    eligible_bapc_cases,
    status,
    failure_class,
    coverage_eligible,
    qualification_reason,
    bapc_covered,
    bapc_target,
    new_bapc_bins,
    last_bapc_novelty_time,
):
    return {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "variant": "riscv-dv",
        "dut": dut,
        "seed": seed,
        "completion_seq": completion_seq,
        "case_id": case_id,
        "profile": "riscv-dv-baseline",
        "elapsed_wall_seconds": float(elapsed_wall_seconds),
        "case_elapsed_seconds": float(case_elapsed_seconds),
        "completed_cases": completed_cases,
        "eligible_cases": eligible_cases,
        "eligible_bapc_cases": eligible_bapc_cases,
        "status": status,
        "failure_class": failure_class,
        "coverage_eligible": bool(coverage_eligible),
        "qualification_reason": qualification_reason,
        "semantic_covered": 0,
        "semantic_target": 0,
        "semantic_rate": None,
        "pairwise_covered": 0,
        "pairwise_target": 0,
        "pairwise_rate": None,
        "security_triples_covered": 0,
        "security_triples_target": 0,
        "security_triples_rate": None,
        "predicates_covered": 0,
        "predicates_target": 0,
        "predicates_rate": None,
        "bapc_covered": bapc_covered,
        "bapc_target": bapc_target,
        "bapc_rate": (bapc_covered / bapc_target) if bapc_target > 0 else None,
        "new_semantic_bins": 0,
        "new_pairwise_bins": 0,
        "new_security_triple_bins": 0,
        "new_predicate_bins": 0,
        "new_bapc_bins": new_bapc_bins,
        "bapc_eligible": bool(coverage_eligible),
        "last_bapc_novelty_time": float(last_bapc_novelty_time),
        "whitebox_distinct_events": 0,
        "new_whitebox_events": 0,
    }


def campaign_metadata(
    dut,
    seed,
    experiment_id,
    campaign_id,
    run_class,
    budget_class,
    generator_variant,
    start_utc,
    elapsed_wall_seconds,
    per_case_timeout_seconds,
    jobs,
    simlen,
    rdv_commit,
    pyvsc_version,
    universe,
    counts,
    stop_reason,
    dut_binary=None,
    mutant_id=None,
):
    dut_binary = str(dut_binary) if dut_binary else str(SIM_BINARIES.get(dut, ""))
    dut_binary_sha256 = ""
    if dut_binary and Path(dut_binary).exists():
        dut_binary_sha256 = _file_sha256(Path(dut_binary))
    dut_sha = ""
    dut_binary_is_override = not dut_binary.endswith(str(SIM_BINARIES.get(dut, "")))
    if dut in ("rocket-clean", "boom-clean", "cva6-clean") and not dut_binary_is_override:
        dut_sha = _git_head(_CHIPYARD_ROOT)
    repo_source_sha = _git_head(_REPO_ROOT)
    source_tree_sha256 = hashlib.sha256((rdv_commit or "").encode("ascii")).hexdigest()
    meta = {
        "schema_version": 1,
        "experiment_id": experiment_id,
        "campaign_id": campaign_id,
        "mutant_id": mutant_id,
        "dut_binary_is_override": dut_binary_is_override,
        "method": "riscv-dv",
        "variant": "riscv-dv",
        "generator_variant": generator_variant,
        "dut": dut,
        "seed": seed,
        "coverage_mode": "bapc",
        "source_sha": repo_source_sha,
        "dut_sha": dut_sha,
        "dut_binary_path": dut_binary,
        "dut_binary_sha256": dut_binary_sha256,
        "source_tree_sha256": source_tree_sha256,
        "source_dirty": _git_is_dirty(_REPO_ROOT),
        "capability_fingerprint": str(universe.get("capability_fingerprint") or ""),
        "experiment_protocol_id": "",
        "start_utc": start_utc,
        "end_utc": datetime.now(timezone.utc).isoformat(),
        "time_budget_seconds": float(elapsed_wall_seconds),
        "wall_clock_horizon_seconds": float(max(elapsed_wall_seconds, 1.0)),
        "budget_class": budget_class,
        "run_class": run_class,
        "stop_reason": stop_reason,
        "convergence_enabled": False,
        "convergence_min_runtime_seconds": 0.0,
        "convergence_confirmation_seconds": 0.0,
        "convergence_confirmation_eligible_cases": 0,
        "max_wall_time_seconds": float(max(elapsed_wall_seconds, 1.0)),
        "round_size": 1,
        "jobs": jobs,
        "per_case_timeout_seconds": per_case_timeout_seconds,
        "simlen": simlen,
        "completed_cases": counts["completed"],
        "eligible_cases": counts["eligible"],
        "eligible_hpm_cases": 0,
        "eligible_bapc_cases": counts["eligible_bapc"],
        "timeouts": counts["timeouts"],
        "inconclusive": counts["inconclusive"],
        "infra_failures": counts["infra_failures"],
        "status": "completed" if stop_reason != "infra_failure" else "infra_failure",
        "semantic_target": 0,
        "pairwise_target": 0,
        "triples_target": 0,
        "predicates_target": 0,
        "hpm_target": 0,
        "bapc_target": int(universe["bin_count"]),
        "semantic_covered": 0,
        "pairwise_covered": 0,
        "triples_covered": 0,
        "predicates_covered": 0,
        "hpm_covered": 0,
        "bapc_covered": counts["bapc_covered"],
        "semantic_final_rate": None,
        "pairwise_final_rate": None,
        "triples_final_rate": None,
        "predicates_final_rate": None,
        "hpm_final_rate": None,
        "bapc_final_rate": (
            counts["bapc_covered"] / int(universe["bin_count"])
            if int(universe["bin_count"]) > 0
            else None
        ),
        "artifact_path": ".",
        "riscv_dv_commit": rdv_commit,
        "pyvsc_version": pyvsc_version,
        "bapc_schema_version": BAPC_SCHEMA_VERSION,
        "bapc_core_version": BAPC_CORE_VERSION_V4,
        "bapc_measurement_mode": "target-operation",
        "probe_required": False,
        "instrumented_supplemental_enabled": False,
        "analysis_scope": {
            "guidance_mode": "bapc",
            "primary_metric": "bapc",
            "coverage_modes": ["bapc"],
        },
    }
    return meta




def extract_probe_operation(log_text, elf_path, dut, probe_path, dasm_path=None, snapshot=None):
    if probe_path is None or not Path(probe_path).exists():
        return None
    try:
        sidecar = json.loads(Path(probe_path).read_text(encoding="utf-8"))
    except Exception:
        sidecar = None
    window = _probe_window(elf_path)
    words = _window_inst_words(elf_path, window)
    channel = None
    matched = None
    if dut == "rocket-clean" and words:
        matched = _match_words_in_trace(words, _c0_items(log_text))
        if matched:
            channel = "commit-trace"
    elif dut == "cva6-clean" and words and dasm_path is not None and Path(dasm_path).exists():
        matched = _match_words_in_trace(words, _dasm_items(Path(dasm_path)))
        if matched:
            channel = "dasm-trace"
    symbol = (sidecar or {}).get("probe_symbol")
    phys = None
    if symbol:
        phys = _symbol_address(elf_path, symbol)
    if phys is None and window:
        phys = _symbol_address(elf_path, "rdv_probe_slot")
    adjacency = None
    if dut == "rocket-clean" and snapshot and snapshot.get("trap_records"):
        mepc_raw = snapshot["trap_records"][0].get("mepc")
        try:
            mepc_val = int(str(mepc_raw), 16)
        except (TypeError, ValueError):
            mepc_val = None
        if window and mepc_val == window[1]:
            adjacency = "mepc-readback"
    if dut == "rocket-clean":
        evidence = "readback" if (channel == "commit-trace" and adjacency) else "deductive"
    elif dut == "cva6-clean":
        evidence = "dasm+deductive" if channel == "dasm-trace" else "deductive"
    else:
        evidence = "deductive"
    return {
        "probe": (sidecar or {}).get("probe"),
        "sidecar_present": bool(sidecar),
        "probe_symbol": symbol,
        "physical_address": phys,
        "instruction_address": window[0] if window else None,
        "probe_end_address": window[1] if window else None,
        "window_symbols_present": window is not None,
        "inst_words": ["%x" % w for _, w in (words or [])],
        "evidence_channel": channel,
        "matched_inst_words": ["%x" % w for _, w in (matched or [])],
        "mepc_adjacency": adjacency,
        "context_evidence": evidence,
        "provenance": (sidecar or {}).get("provenance"),
        "probe_executed": bool(matched is not None or adjacency is not None or evidence == "deductive"),
    }


def build_probe_context(snapshot, probe_op, graft_path, dut, static_state=None):
    pmpcfg = [0] * 8
    pmpaddr = [0] * 16
    snap_final = None
    if snapshot and snapshot.get("final_snapshot"):
        snap_final = snapshot["final_snapshot"]
    if snap_final:
        pmpcfg = [int(v, 16) for v in snap_final["pmpcfg"]]
        pmpaddr = [int(v, 16) for v in snap_final["pmpaddr"]]
    elif static_state is not None:
        pmpcfg = [int(v, 16) for v in static_state["pmpcfg"]]
        pmpaddr = [int(v, 16) for v in static_state["pmpaddr"]]
    else:

        graft = None
        if graft_path is not None and Path(graft_path).exists():
            try:
                graft = json.loads(Path(graft_path).read_text(encoding="utf-8"))
            except Exception:
                graft = None
        expected = (graft or {}).get("expected_pmp_state") or {}
        for entry in expected.get("programmed_entries") or []:
            idx = int(entry.get("index", 0))
            if not 0 <= idx < 16:
                continue
            mode = str(entry.get("address_mode") or "off")
            byte = {"napot": 3, "tor": 1, "na4": 2}.get(mode, 0) << 3
            if entry.get("read"):
                byte |= 1
            if entry.get("write"):
                byte |= 2
            if entry.get("execute"):
                byte |= 4
            if entry.get("locked"):
                byte |= 0x80
            pmpcfg[idx // 8] |= byte << (8 * (idx % 8))
            try:
                pmpaddr[idx] = int(str(entry.get("pmpaddr")), 16)
            except (TypeError, ValueError):
                pmpaddr[idx] = 0
    entries = []
    for i in range(16):
        byte = (pmpcfg[i // 8] >> (8 * (i % 8))) & 0xFF
        a_field = (byte >> 3) & 0x3
        mode_name = {0: "off", 1: "tor", 2: "na4", 3: "napot"}.get(a_field, "off")
        entries.append(
            {
                "index": i,
                "address_mode": mode_name,
                "pmpaddr": pmpaddr[i],
                "read": bool(byte & 1),
                "write": bool(byte & 2),
                "execute": bool(byte & 4),
                "locked": bool(byte & 0x80),
            }
        )
    return {
        "translation": "bare",
        "mseccfg": {},
        "pmp_entries": entries,
        "default_privilege": "m",
        "default_access": "load",
        "default_size": 8,
        "size_source": "designated-probe",
        "default_address": probe_op.get("physical_address"),
        "default_mprv": False,
        "default_mpp": "m",
        "context_evidence": probe_op.get("context_evidence"),
    }


def score_probe_completion(snapshot, probe_op, graft_path, dut, static_state=None,
                          bapc_core_version=BAPC_CORE_VERSION_V4):
    if probe_op is None or probe_op.get("physical_address") is None:
        return (
            {
                "eligible": False,
                "qualification_reason": "probe-not-resolved",
                "observed_bins": [],
                "event_records": [],
            },
            "probe-not-resolved",
        )
    context = build_probe_context(snapshot, probe_op, graft_path, dut, static_state=static_state)
    if static_state is not None and not (snapshot and snapshot.get("final_snapshot")):
        context["context_evidence"] = "deductive-from-generated-stream"
    result = {
        "observation_valid": True,
        "observed_event": "completion",
        "observed_mcause": 11,
    }
    bapc = summarize_bapc_target_operation(
        context,
        result,
        bapc_core_version=bapc_core_version,
    )
    return bapc, str(bapc.get("qualification_reason") or "")


def score_case_with_probe(snapshot, classified, probe_op, graft_path, dut, probe_mode,
                          static_state=None, static_address=None, static_evidence=None,
                          bapc_core_version=BAPC_CORE_VERSION_V4):
    if (
        probe_mode
        and classified.get("status") == "observed"
        and classified.get("observed_event") == "completion"
    ):
        return score_probe_completion(
            snapshot, probe_op, graft_path, dut, static_state=static_state,
            bapc_core_version=bapc_core_version,
        )
    return score_case(
        snapshot, classified,
        static_state=static_state, static_address=static_address,
        static_evidence=static_evidence,
        bapc_core_version=bapc_core_version,
    )



def _campaign_manifest_relpaths(campaign_dir, artifact_root, graft_mode):
    camp_rel = campaign_dir.resolve().relative_to(artifact_root.resolve())
    rels = [
        str(camp_rel / "events.json"),
        str(camp_rel / "metrics" / "campaign_metadata.json"),
        str(camp_rel / "metrics" / "coverage_timeline.jsonl"),
        str(camp_rel / "coverage" / "coverage.json"),
    ]
    if graft_mode:
        rels.append(str(camp_rel / "metrics" / "pmp_programming_stats.json"))
    for universe_file in sorted((campaign_dir / "universe").glob("*.json")):
        rels.append(str(universe_file.relative_to(artifact_root)))
    return [rel for rel in rels if (Path(artifact_root) / rel).exists()]


def _run_one_sim(dut, elf, log_path, simlen, timeout_seconds, dut_binary=None):
    start = time.monotonic()
    run_dir = log_path.parent / (log_path.stem + ".d")
    run_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(dut_binary or SIM_BINARIES[dut]),
        "+permissive",
        "+verbose",
        "+dramsim",
        "+dramsim_ini_dir=%s" % DRAMSIM_INI_DIR,
        "+max-cycles=%d" % simlen,
        "+loadmem=%s" % elf,
        "+permissive-off",
        str(elf),
    ]
    cwd = str(run_dir)
    try:
        with open(log_path, "w", encoding="ascii", errors="replace") as handle:
            proc = subprocess.run(
                cmd,
                stdout=handle,
                stderr=subprocess.STDOUT,
                timeout=timeout_seconds,
                cwd=cwd,
                env=None,
            )
        returncode = proc.returncode
    except subprocess.TimeoutExpired:
        returncode = None
    elapsed = time.monotonic() - start
    dasm_src = run_dir / "trace_hart_00.dasm"
    if dasm_src.exists():
        try:
            (log_path.parent / (log_path.stem + ".dasm")).write_bytes(
                dasm_src.read_bytes()
            )
        except OSError:
            pass
    try:
        shutil.rmtree(run_dir, ignore_errors=True)
    except Exception:
        pass
    return returncode, elapsed


def score_campaign(
    campaign_dir,
    dut,
    seed,
    experiment_id="riscv-dv-baseline",
    run_class="baseline-pilot",
    budget_class="fixed-input-budget",
    generator_variant="pygen",
    bapc_core_version=BAPC_CORE_VERSION_V4,
    simlen=50000,
    per_case_timeout_seconds=60,
    static_pmp_src=None,
    dut_binary=None,
    mutant_id=None,
):
    campaign_dir = Path(campaign_dir)
    elfs_dir = campaign_dir / "elfs"
    logs_dir = campaign_dir / "logs"
    metrics_dir = campaign_dir / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=True)
    universe_dir = campaign_dir / "universe"
    universe_dir.mkdir(parents=True, exist_ok=True)
    coverage_dir = campaign_dir / "coverage"
    coverage_dir.mkdir(parents=True, exist_ok=True)

    universe = build_bapc_coverage_universe(
        dut=dut,
        generator_seed=seed,
        supports_fault_stage=False,
        supports_smepmp=False,
        bapc_core_version=bapc_core_version,
    )
    universe_name = coverage_universe_filename("bapc", universe)
    (universe_dir / universe_name).write_text(
        json.dumps(universe, indent=2, ensure_ascii=True) + "\n",
        encoding="ascii",
    )

    static_src_dir = Path(static_pmp_src) if static_pmp_src else None
    _static_cache = {}
    elfs = sorted(elfs_dir.glob("*.elf"))
    graft_sidecars = {p.stem: p for p in elfs_dir.glob("*.graft.json")}
    graft_mode = bool(graft_sidecars)
    probe_sidecars = {p.stem: p for p in elfs_dir.glob("*.probe.json")}
    probe_mode = bool(probe_sidecars)
    stats_rows = []
    probe_attributed = 0
    probe_evidence_channels = {}
    campaign_id = "riscv-dv__%s__seed-%04d" % (dut, int(seed))
    start_utc = datetime.now(timezone.utc).isoformat()
    start_wall = time.monotonic()
    covered = set()
    last_novelty = 0.0
    eligible_bapc = 0
    eligible_total = 0
    timeouts = 0
    inconclusive = 0
    infra_failures = 0
    timeline = []
    events = []
    timeline.append(
        {
            "schema_version": 1,
            "campaign_id": campaign_id,
            "variant": "riscv-dv",
            "dut": dut,
            "seed": seed,
            "completion_seq": 0,
            "case_id": None,
            "profile": "riscv-dv-baseline",
            "elapsed_wall_seconds": 0.0,
            "case_elapsed_seconds": 0.0,
            "completed_cases": 0,
            "eligible_cases": 0,
            "eligible_bapc_cases": 0,
            "status": None,
            "failure_class": None,
            "coverage_eligible": False,
            "qualification_reason": None,
            "semantic_covered": 0,
            "semantic_target": 0,
            "semantic_rate": None,
            "pairwise_covered": 0,
            "pairwise_target": 0,
            "pairwise_rate": None,
            "security_triples_covered": 0,
            "security_triples_target": 0,
            "security_triples_rate": None,
            "predicates_covered": 0,
            "predicates_target": 0,
            "predicates_rate": None,
            "bapc_covered": 0,
            "bapc_target": int(universe["bin_count"]),
            "bapc_rate": 0.0 if int(universe["bin_count"]) > 0 else None,
            "new_semantic_bins": 0,
            "new_pairwise_bins": 0,
            "new_security_triple_bins": 0,
            "new_predicate_bins": 0,
            "new_bapc_bins": 0,
            "bapc_eligible": False,
            "last_bapc_novelty_time": 0.0,
            "whitebox_distinct_events": 0,
            "new_whitebox_events": 0,
        }
    )
    for idx, elf in enumerate(elfs, start=1):
        stem = elf.stem
        log_path = logs_dir / (stem + ".log")
        if log_path.exists():
            log_text = log_path.read_text(encoding="ascii", errors="replace")
        else:
            log_text = ""
        classified = classify_case(log_text, None)
        snapshot = extract_snapshot(log_text, elf, dut)
        graft_evidence = None
        if graft_mode:
            graft_evidence = extract_graft_evidence(
                log_text,
                elf,
                dut,
                elfs_dir / (stem + ".graft.json"),
                logs_dir / (stem + ".dasm"),
            )
        probe_op = None
        if probe_mode:
            probe_op = extract_probe_operation(
                log_text,
                elf,
                dut,
                elfs_dir / (stem + ".probe.json"),
                logs_dir / (stem + ".dasm"),
                snapshot,
            )
        static_state = None
        static_address = None
        static_evidence = "deductive-from-generated-stream"
        if static_src_dir is not None and derive_static_pmp is not None:
            src_asm = static_src_dir / (stem + ".S")
            if src_asm.exists():
                try:
                    static_state = _static_cache.get(stem)
                    if static_state is None:
                        static_state = derive_static_pmp(str(src_asm), str(elf))
                        _static_cache[stem] = static_state
                    static_path = elfs_dir / (stem + ".pmp_static.json")
                    static_path.write_text(
                        json.dumps(static_state, indent=2, ensure_ascii=True) + "\n",
                        encoding="ascii",
                    )
                except (ValueError, OSError) as exc:
                    static_state = None
                    static_evidence = "deductive-failed: %s" % str(exc)[:80]
        if (
            static_state is not None
            and classified.get("observed_event") == "trap"
            and classified.get("observed_mcause") == 1
            and classified.get("observed_mtval_fingerprint") is not None
        ):
            recovered, unique = recover_trap_address(
                int(classified["observed_mtval_fingerprint"]),
                int(classified.get("observed_mepc_tag") or 0),
                str(elf),
            )
            if unique:
                static_address = recovered
            else:
                static_address = None
        readback_incomplete = False
        if (
            static_state is not None
            and snapshot
            and snapshot.get("final_snapshot")
            and all(
                int(v, 16) == 0 for v in (snapshot["final_snapshot"].get("pmpcfg") or [])
            )
            and any(int(v, 16) != 0 for v in (static_state.get("pmpcfg") or []))
        ):



            readback_incomplete = True
            static_evidence = "deductive-from-generated-stream (readback-incomplete)"
            snapshot = None
        bapc_result, reason = score_case_with_probe(
            snapshot,
            classified,
            probe_op,
            elfs_dir / (stem + ".graft.json") if graft_mode else None,
            dut,
            probe_mode,
            static_state=static_state,
            static_address=static_address,
            static_evidence=static_evidence,
            bapc_core_version=bapc_core_version,
        )
        bapc_eligible = bool(bapc_result.get("eligible"))
        if bapc_eligible and probe_op is not None:
            probe_attributed += 1
            channel = probe_op.get("context_evidence") or "unknown"
            probe_evidence_channels[channel] = probe_evidence_channels.get(channel, 0) + 1
        new_bins = []
        if bapc_eligible:
            eligible_bapc += 1
            eligible_total += 1
            classified_bins = classify_observed_bins(universe, bapc_result.get("observed_bins") or [])
            observed = sorted(set(classified_bins.get("covered") or []))
            new_bins = sorted(set(observed) - covered)
            covered.update(observed)
            if new_bins:
                last_novelty = time.monotonic() - start_wall
        elif classified.get("status") == "timeout":
            timeouts += 1
        elif classified.get("status") == "infra_failure":
            infra_failures += 1
        else:
            inconclusive += 1
        case_id = "%s_%03d" % (dut, idx - 1)
        completed = (
            classified.get("status") == "observed"
            and classified.get("observed_event") == "completion"
        )
        snap_present = bool(snapshot and snapshot.get("final_snapshot"))
        if snap_present:
            pats = _programmed_patterns(snapshot)
            stats_rows.append(
                {
                    "case_id": case_id,
                    "completed": completed,
                    "snapshot_present": True,
                    "graft_executed": (
                        graft_evidence.get("evidence_channel")
                        in ("commit-trace", "dasm-trace")
                        if graft_evidence is not None
                        else None
                    ),
                    "programmed_entries": len(pats),
                    "programmed_patterns": pats,
                    "off_patterns": sorted(_off_patterns(snapshot)),
                    "locked_entries": sum(1 for p in pats if p[4]),
                    "graft_evidence": graft_evidence,
                }
            )
        row = timeline_line(
            campaign_id=campaign_id,
            dut=dut,
            seed=seed,
            completion_seq=idx,
            case_id=case_id,
            elapsed_wall_seconds=time.monotonic() - start_wall,
            case_elapsed_seconds=0.0,
            completed_cases=idx,
            eligible_cases=eligible_total,
            eligible_bapc_cases=eligible_bapc,
            status=classified.get("status"),
            failure_class=classified.get("failure_class"),
            coverage_eligible=bapc_eligible,
            qualification_reason=str(reason or classified.get("failure_class") or ""),
            bapc_covered=len(covered),
            bapc_target=int(universe["bin_count"]),
            new_bapc_bins=len(new_bins),
            last_bapc_novelty_time=last_novelty,
        )
        timeline.append(row)
        snapshot_path = elfs_dir / (stem + ".snapshot.json")
        snapshot_path.write_text(
            json.dumps(snapshot or {}, indent=2, ensure_ascii=True) + "\n",
            encoding="ascii",
        )
        bapc_path = elfs_dir / (stem + ".bapc.json")
        bapc_payload = {
            "case_id": case_id,
            "eligible": bapc_eligible,
            "qualification_reason": reason,
            "observed_bins": bapc_result.get("observed_bins") or [],
            "new_bins": new_bins,
            "classification": classified,
        }
        if probe_op is not None and bapc_eligible:
            bapc_payload["designated_target_operation"] = {
                "privilege": "m",
                "access": "load",
                "size": 8,
                "physical_address": probe_op.get("physical_address"),
                "instruction_address": probe_op.get("instruction_address"),
                "provenance": probe_op.get("provenance"),
                "context_evidence": probe_op.get("context_evidence"),
                "probe_executed": probe_op.get("probe_executed"),
                "mepc_adjacency": probe_op.get("mepc_adjacency"),
            }
            bapc_payload["context"] = build_probe_context(
                snapshot,
                probe_op,
                elfs_dir / (stem + ".graft.json") if graft_mode else None,
                dut,
            )
        elif snapshot:
            bapc_payload["context"] = build_context(snapshot)
        elif static_state is not None:
            bapc_payload["context"] = bapc_result.get("context") or build_static_context(
                static_state,
                classified.get("observed_mcause"),
                static_address,
                _MCAUSE_ACCESS.get(classified.get("observed_mcause")),
                static_evidence,
            )
        if bapc_result.get("mode_decision_omitted_reason"):
            bapc_payload["mode_decision_omitted_reason"] = bapc_result["mode_decision_omitted_reason"]
        if bapc_result.get("context_evidence"):
            bapc_payload["context_evidence"] = bapc_result["context_evidence"]
        bapc_path.write_text(
            json.dumps(bapc_payload, indent=2, ensure_ascii=True) + "\n",
            encoding="ascii",
        )
        event_row = {
            "case_id": case_id,
            "completion_seq": idx,
            "status": classified.get("status"),
            "failure_class": classified.get("failure_class"),
            "exit_value": classified.get("exit_value"),
            "tohost_value": classified.get("tohost_value"),
            "cross_check": classified.get("cross_check"),
            "observed_event": classified.get("observed_event"),
            "bapc_eligible": bapc_eligible,
            "snapshot_relpath": stem + ".snapshot.json",
            "elf_relpath": stem + ".elf",
            "log_relpath": str(log_path.relative_to(campaign_dir)) if log_path.exists() else None,
        }
        if graft_evidence is not None:
            event_row["graft"] = graft_evidence.get("graft")
            event_row["graft_evidence_channel"] = graft_evidence.get("evidence_channel")
            event_row["graft_sidecar_relpath"] = stem + ".graft.json"
        if probe_op is not None:
            event_row["designated_probe"] = probe_op.get("probe")
            event_row["probe_context_evidence"] = probe_op.get("context_evidence")
            event_row["probe_relpath"] = stem + ".probe.json"
            event_row["probe_symbol"] = probe_op.get("probe_symbol")
            event_row["probe_executed"] = probe_op.get("probe_executed")
            event_row["probe_mepc_adjacency"] = probe_op.get("mepc_adjacency")
            if probe_op.get("physical_address") is not None:
                event_row["probe_physical_address"] = _hex(probe_op["physical_address"])
        if static_state is not None:
            event_row["pmp_static_relpath"] = stem + ".pmp_static.json"
            event_row["static_context_evidence"] = static_evidence
            if readback_incomplete:
                event_row["readback_incomplete"] = True
            if classified.get("observed_event") == "trap":
                event_row["mtval_recovered"] = static_address is not None
                if static_address is not None:
                    event_row["static_trap_address"] = _hex(static_address)
        events.append(event_row)
    pmp_stats = build_pmp_programming_stats(dut, stats_rows)
    if pmp_stats is not None:
        (metrics_dir / "pmp_programming_stats.json").write_text(
            json.dumps(pmp_stats, indent=2, ensure_ascii=True) + "\n",
            encoding="ascii",
        )
    elapsed = time.monotonic() - start_wall
    counts = {
        "completed": len(elfs),
        "eligible": eligible_total,
        "eligible_bapc": eligible_bapc,
        "timeouts": timeouts,
        "inconclusive": inconclusive,
        "infra_failures": infra_failures,
        "bapc_covered": len(covered),
    }
    meta = campaign_metadata(
        dut=dut,
        seed=seed,
        experiment_id=experiment_id,
        campaign_id=campaign_id,
        run_class=run_class,
        budget_class=budget_class,
        generator_variant=generator_variant,
        start_utc=start_utc,
        elapsed_wall_seconds=elapsed,
        per_case_timeout_seconds=per_case_timeout_seconds,
        jobs=1,
        simlen=simlen,
        rdv_commit=_git_head(RISCV_DV_ROOT),
        pyvsc_version="0.9.5.27214109393",
        universe=universe,
        counts=counts,
        stop_reason="budget-exhausted",
        dut_binary=dut_binary,
        mutant_id=mutant_id,
    )
    if graft_mode:
        meta["pmp_graft"] = "upstream-enable-all"
    else:
        meta["pmp_graft"] = None
    meta["static_pmp_mode"] = bool(static_src_dir is not None)
    meta["pmp_programming_stats_summary"] = (
        {
            "graft": pmp_stats["graft"],
            "cases_with_snapshot": pmp_stats["cases_with_snapshot"],
            "avg_programmed_entries": pmp_stats["avg_programmed_entries"],
            "distinct_programmed_patterns": pmp_stats["distinct_programmed_patterns"],
            "locked_entries": pmp_stats["locked_entries"],
            "locked_ratio": pmp_stats["locked_ratio"],
            "evidence_channels": pmp_stats["evidence_channels"],
        }
        if pmp_stats
        else None
    )
    if probe_mode:
        meta["designated_probe"] = "epilogue-load"
        meta["probe_attribution"] = {
            "attributed_cases": probe_attributed,
            "evidence_channels": dict(probe_evidence_channels),
        }
    else:
        meta["designated_probe"] = None
    (metrics_dir / "campaign_metadata.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    (metrics_dir / "coverage_timeline.jsonl").write_text(
        "\n".join(json.dumps(row, ensure_ascii=True, sort_keys=True) for row in timeline) + "\n",
        encoding="ascii",
    )
    (campaign_dir / "events.json").write_text(
        json.dumps(events, indent=2, ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    coverage_payload = json.dumps(
        {
            "schema_version": 6,
            "driver_mode": "campaign",
            "coverage_universe_hashes": {"bapc": universe["sha256"]},
            "execution_coverage": {
                "by_dut": {
                    dut: {
                        "bapc": {
                            "covered_target_bins": len(covered),
                            "total_target_bins": int(universe["bin_count"]),
                            "covered_bins": sorted(covered),
                            "target": "black-box-architectural-pmp-target-operation",
                            "universe_sha256": universe["sha256"],
                        }
                    }
                }
            },
        },
        indent=2,
        ensure_ascii=True,
    ) + "\n"
    (coverage_dir / "coverage.json").write_text(coverage_payload, encoding="ascii")




    artifact_root = campaign_dir.parents[1] if len(campaign_dir.parents) > 1 else campaign_dir
    manifests_dir = artifact_root / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    env_path = manifests_dir / "environment.json"
    if not env_path.exists():
        env_path.write_text(
            json.dumps(
                {
                    "host": platform.node(),
                    "python": "3.14.4",
                    "venv": str(RISCV_DV_VENV),
                    "venv_python": "3.11.15",
                    "pyvsc": "0.9.5.27214109393",
                    "riscv_gcc": "riscv64-unknown-elf-gcc (Xuantie-900 elf newlib gcc Toolchain V3.2.0 B-20250627) 14.1.1",
                },
                indent=2,
                ensure_ascii=True,
            )
            + "\n",
            encoding="ascii",
        )
    git_shas_path = manifests_dir / "git-shas.txt"
    if not git_shas_path.exists():
        rdv_sha = _git_head(RISCV_DV_ROOT)
        repo_sha = _git_head(_REPO_ROOT)
        chipyard_sha = _git_head(_CHIPYARD_ROOT)
        git_shas_path.write_text(
            "riscv-dv %s\nrepo %s\nchipyard %s\n" % (rdv_sha, repo_sha, chipyard_sha),
            encoding="ascii",
        )
    artifact_sha_path = manifests_dir / "artifact-sha256.txt"
    entries = {}
    if artifact_sha_path.exists():
        for line in artifact_sha_path.read_text(encoding="ascii", errors="replace").splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                entries[parts[1]] = parts[0]
    for rel in _campaign_manifest_relpaths(campaign_dir, artifact_root, graft_mode):
        entries[rel] = _file_sha256(Path(artifact_root) / rel)
    artifact_sha_path.write_text(
        "\n".join(
            "%s  %s" % (entries[rel], rel) for rel in sorted(entries)
        )
        + "\n",
        encoding="ascii",
    )
    return {
        "campaign_id": campaign_id,
        "cases": len(elfs),
        "eligible_bapc": eligible_bapc,
        "bapc_covered": len(covered),
        "bapc_target": int(universe["bin_count"]),
        "elapsed_wall_seconds": elapsed,
    }


def main():
    parser = argparse.ArgumentParser(description="riscv-dv baseline adapter")
    parser.add_argument("--campaign-dir", required=True)
    parser.add_argument("--dut", required=True, choices=SUPPORTED_DUTS)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--mode", choices=["score", "run"], default="score")
    parser.add_argument("--run-class", default="baseline-pilot")
    parser.add_argument("--generator-variant", default="pygen")
    parser.add_argument("--simlen", type=int, default=50000)
    parser.add_argument("--per-case-timeout", type=int, default=60)
    parser.add_argument(
        "--experiment-id",
        default="riscv-dv-baseline",
        help="experiment_id recorded in campaign_metadata (R3: riscv-dv-baseline-r3)",
    )
    parser.add_argument(
        "--static-pmp-src",
        default=None,
        help="R6: dir with the original generated .S files for static PMP derivation",
    )
    parser.add_argument(
        "--dut-binary-override",
        type=Path,
        default=None,
        help="B1: run/score against a mutant DUT binary (recorded in campaign_metadata)",
    )
    parser.add_argument(
        "--mutant-id",
        default=None,
        help="B1: mutant id recorded in campaign_metadata (e.g. M02, M04, ...)",
    )
    args = parser.parse_args()
    campaign_dir = Path(args.campaign_dir)
    if args.mode == "run":
        elfs_dir = campaign_dir / "elfs"
        logs_dir = campaign_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        for elf in sorted(elfs_dir.glob("*.elf")):
            log_path = logs_dir / (elf.stem + ".log")
            print("run %s" % elf.name)
            _run_one_sim(
                args.dut,
                elf,
                log_path,
                args.simlen,
                args.per_case_timeout,
                dut_binary=args.dut_binary_override,
            )
    summary = score_campaign(
        campaign_dir=campaign_dir,
        dut=args.dut,
        seed=args.seed,
        experiment_id=args.experiment_id,
        run_class=args.run_class,
        generator_variant=args.generator_variant,
        simlen=args.simlen,
        per_case_timeout_seconds=args.per_case_timeout,
        static_pmp_src=args.static_pmp_src,
        dut_binary=args.dut_binary_override,
        mutant_id=args.mutant_id,
    )
    print(json.dumps(summary, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
