#!/usr/bin/env python3
"""Cascade baseline adapter — Phase E engineering evaluation.

Uses the existing codex_cascade_cpu_fuzzing Docker container.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# DUT matrix (Section 3.3.A)
# ---------------------------------------------------------------------------

SUPPORTED_DUTS = (
    "rocket-clean",
    "boom-clean",
    "xiangshan-clean",
    "cva6-clean",
)

CASCADE_MOUNT_DIR = Path("/home/dubhe/wjs/cascade_cpu_fuzzing/mount")
CASCADE_CONTAINER = "codex_cascade_cpu_fuzzing"
CASCADE_IMAGE_SHA = "sha256:3d403b05be4a57fc1910b7e73bc807d499e382f73197ae8978ca1954524f0a11"

_DESIGN_MAP = {
    "rocket-clean": "rocket",
    "boom-clean": "boom",
    "cva6-clean": "cva6",
    "xiangshan-clean": "xiangshan",
}

_SIM_BINARIES = {
    "rocket-clean": "/home/dubhe/wjs/pmp-duts/chipyard-1.14.0/sims/verilator/simulator-chipyard.harness-RocketConfig",
    "boom-clean": "/home/dubhe/wjs/pmp-duts/chipyard-1.14.0/sims/verilator/simulator-chipyard.harness-SmallBoomV3Config",
    "cva6-clean": "/home/dubhe/wjs/pmp-duts/chipyard-1.14.0/sims/verilator/simulator-chipyard.harness-CVA6Config",
    "xiangshan-clean": "/home/dubhe/wjs/xiangshan_vanilla/build/verilator-compile/emu",
}

PROBE_RE = re.compile(r"PMFUZZ_PROBE\s+(.*)")

# ---------------------------------------------------------------------------
# Generation isolation (Section 3.3.B)
# ---------------------------------------------------------------------------


def _generation_workspace(out_dir: Path, seed: int) -> Path:
    """Return a stable, campaign-specific workspace path under the mount dir."""
    campaign_slug = f"{out_dir.resolve().name}__seed-{seed:04d}"
    stable_id = hashlib.sha256(campaign_slug.encode("ascii")).hexdigest()[:16]
    return CASCADE_MOUNT_DIR / "cascade-campaigns" / f"{stable_id}"


def _generate_elfs(num_elfs: int, out_dir: Path, *, seed: int, design: str) -> dict[str, Any]:
    """Generate ELFs in an isolated campaign workspace.

    The workspace is a subdirectory of CASCADE_MOUNT_DIR/cascade-campaigns/.
    ELFs are copied from the workspace to out_dir after generation.
    """
    import shutil

    start = time.monotonic()
    workspace = _generation_workspace(out_dir, seed)
    workspace.mkdir(parents=True, exist_ok=True)
    container_ws = f"/cascade-mountdir/cascade-campaigns/{workspace.name}"

    out_dir.mkdir(parents=True, exist_ok=True)

    proc = subprocess.run([
        "docker", "exec", CASCADE_CONTAINER,
        "bash", "-c",
        f"source /cascade-meta/env.sh && "
        f"mkdir -p {container_ws} && "
        f"python3 /cascade-meta/fuzzer/do_genmanyelfs.py {num_elfs} {container_ws}",
    ], capture_output=True, text=True, timeout=600, check=False)

    # Copy generated ELFs from workspace to out_dir
    gen_elfs = list(workspace.glob(f"{design}_*.elf"))
    for elf_path in gen_elfs:
        shutil.copy2(str(elf_path), str(out_dir / elf_path.name))

    elapsed = time.monotonic() - start
    # Compute ELF SHA256 if available
    elf_sha = ""
    if gen_elfs:
        elf_sha = hashlib.sha256(gen_elfs[0].read_bytes()).hexdigest()[:16]

    return {
        "success": proc.returncode == 0 and len(gen_elfs) >= num_elfs,
        "returncode": proc.returncode,
        "elapsed_seconds": elapsed,
        "stderr": proc.stderr[-500:] if proc.stderr else "",
        "workspace": str(workspace),
        "design": design,
        "seed": seed,
        "elf_sha256": elf_sha,
    }


# ---------------------------------------------------------------------------
# Simulator commands (Section 3.3.A)
# ---------------------------------------------------------------------------


def _simulator_command(dut: str, elf: Path, simlen: int) -> tuple[list[str], dict]:
    """Return (command_list, env_dict) for executing an ELF on a DUT.

    Rocket/BOOM/CVA6 use Verilator with +max-cycles.
    XiangShan uses emu --no-diff -C <simlen> -i <elf>.
    """
    if dut not in SUPPORTED_DUTS:
        raise ValueError(f"unsupported DUT: {dut}")

    binary = _SIM_BINARIES.get(dut, "")
    env = os.environ.copy()

    if dut == "xiangshan-clean":
        cmd = [
            binary,
            "--no-diff",
            "-C", str(simlen),
            "-i", str(elf),
        ]
    else:
        cmd = [
            binary,
            "+permissive",
            "+verbose",
            f"+max-cycles={simlen}",
            str(elf),
        ]
    return cmd, env


# ---------------------------------------------------------------------------
# Event extraction and timeline (Section 3.3.D)
# ---------------------------------------------------------------------------


def _extract_probe_events(stdout: str) -> list[dict[str, Any]]:
    """Extract PMFUZZ_PROBE events from simulation stdout."""
    events = []
    for line in stdout.split("\n"):
        m = PROBE_RE.search(line)
        if m:
            fields_str = m.group(1)
            fields = {}
            for pair in fields_str.split():
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    fields[k] = v
            chain = fields.get("chain", "")
            stage = fields.get("stage", "")
            events.append({
                "kind": "source_probe",
                "chain": chain,
                "stage": stage,
                "fields": fields,
            })
    return events


def _make_event_id(dut: str, chain: str, stage: str, privilege: str) -> str:
    """Stable event ID from cross-method, cross-case stable fields only.

    Does NOT include: case_id, seed, raw address, campaign_id, method.
    """
    key = f"source_probe|{dut}|{chain}|{stage}|{privilege}"
    return hashlib.sha256(key.encode("ascii")).hexdigest()[:16]


def _build_security_event_timeseries(
    timeline: list[dict[str, Any]],
    *,
    dut: str,
    campaign_id: str,
    seed: int,
) -> list[dict[str, Any]]:
    """Build normalized security event timeseries from probe events.

    Each case's events share the same completion_seq, with event_index
    starting at 1. event_id is stable and excludes case/address/campaign.
    """
    rows = []
    event_set: set[str] = set()

    for entry in timeline:
        case_id = entry.get("case_id", "")
        comp_seq = entry.get("completion_seq", 0)
        wall = entry.get("elapsed_wall_seconds", 0)
        probe_events = entry.get("probe_events", [])

        for event_idx, evt in enumerate(probe_events, start=1):
            chain = evt.get("chain", "")
            stage = evt.get("stage", "")
            privilege = evt.get("fields", {}).get("prv", "")
            eid = _make_event_id(dut, chain, stage, privilege)

            is_new = eid not in event_set
            if is_new:
                event_set.add(eid)

            rows.append({
                "schema_version": "1.0",
                "experiment_id": "cascade-baseline",
                "campaign_id": campaign_id,
                "method": "cascade",
                "variant": "baseline",
                "dut": dut,
                "seed": seed,
                "completion_seq": comp_seq,
                "event_index": event_idx,
                "elapsed_wall_seconds": wall,
                "event_namespace": "source_probe",
                "event_category": chain,
                "event_id": eid,
                "is_new_event": is_new,
                "total_distinct_events": len(event_set),
                "case_id": case_id,
            })
    return rows


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------


def run_cascade_baseline(
    dut: str,
    num_elfs: int,
    simlen: int,
    timeout_seconds: int,
    out_dir: Path,
    seed: int = 1,
) -> dict[str, Any]:
    """Run Cascade baseline campaign. Saves logs and normalized event timeline."""
    if dut not in SUPPORTED_DUTS:
        raise ValueError(f"unsupported DUT: {dut}")

    design = _DESIGN_MAP[dut]
    out_dir.mkdir(parents=True, exist_ok=True)
    start_utc = datetime.now(timezone.utc).isoformat()
    start_wall = time.monotonic()

    # 1. Generate ELFs
    elfs_dir = out_dir / "elfs"
    gen_result = _generate_elfs(num_elfs, elfs_dir, seed=seed, design=design)
    if not gen_result["success"]:
        return {
            "status": "infra_failure",
            "error": "elf_generation_failed",
            "generation_info": gen_result,
        }

    # 2. Execute and collect
    logs_dir = out_dir / "logs"
    logs_dir.mkdir(exist_ok=True)
    metrics_dir = out_dir / "metrics"
    metrics_dir.mkdir(exist_ok=True)

    timeline = []
    events_list = []
    completed = 0
    eligible_cases = 0
    timeouts = 0
    inconclusive = 0
    infra_failures = 0

    for case_idx in range(num_elfs):
        elf_name = f"{design}_{case_idx}.elf"
        elf_path = elfs_dir / elf_name
        if not elf_path.exists():
            infra_failures += 1
            continue

        case_id = f"cascade_{dut}_{case_idx:04d}"
        stdout_path = logs_dir / f"{case_id}.stdout.log"
        stderr_path = logs_dir / f"{case_id}.stderr.log"

        cmd, env = _simulator_command(dut, elf_path, simlen)
        case_start = time.monotonic()

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout_seconds, env=env,
                                  cwd=elf_path.parent)
            case_elapsed = time.monotonic() - case_start

            stdout_path.write_text(proc.stdout or "", encoding="utf-8", errors="replace")
            stderr_path.write_text(proc.stderr or "", encoding="utf-8", errors="replace")

            probe_events = _extract_probe_events(proc.stdout or "")
            if probe_events:
                status = "completed"
                completed += 1
                eligible_cases += 1
            else:
                status = "inconclusive"
                inconclusive += 1

        except subprocess.TimeoutExpired:
            case_elapsed = timeout_seconds
            status = "timeout"
            timeouts += 1
            probe_events = []
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
        except Exception:
            case_elapsed = time.monotonic() - case_start
            status = "infra_failure"
            infra_failures += 1
            probe_events = []
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")

        elapsed_wall = time.monotonic() - start_wall

        events_list.append({
            "case_id": case_id, "completion_seq": case_idx + 1,
            "status": status, "elapsed_wall_seconds": elapsed_wall,
            "case_elapsed_seconds": case_elapsed,
            "returncode": proc.returncode if "proc" in dir() else -1,
            "probe_event_count": len(probe_events),
            "stdout_log": str(stdout_path), "stderr_log": str(stderr_path),
            "elf_sha256": gen_result.get("elf_sha256", ""),
        })

        timeline.append({
            "case_id": case_id, "completion_seq": case_idx + 1,
            "elapsed_wall_seconds": elapsed_wall,
            "probe_events": probe_events,
        })

    # 3. Write outputs
    elapsed_total = time.monotonic() - start_wall
    campaign_id = f"cascade__{dut}__seed-{seed:04d}"
    end_utc = datetime.now(timezone.utc).isoformat()

    meta = {
        "schema_version": "1.0",
        "experiment_id": "cascade-baseline",
        "campaign_id": campaign_id,
        "method": "cascade",
        "variant": "baseline",
        "dut": dut,
        "seed": seed,
        "source_sha": "",
        "dut_binary_sha256": hashlib.sha256(
            Path(_SIM_BINARIES.get(dut, "")).read_bytes()
        ).hexdigest() if Path(_SIM_BINARIES.get(dut, "")).exists() else "",
        "container_image": CASCADE_IMAGE_SHA,
        "start_utc": start_utc,
        "end_utc": end_utc,
        "elapsed_wall_seconds": elapsed_total,
        "requested_cases": num_elfs,
        "completed_cases": completed,
        "eligible_cases": eligible_cases,
        "timeouts": timeouts,
        "inconclusive": inconclusive,
        "infra_failures": infra_failures,
        "simlen": simlen,
        "per_case_timeout": timeout_seconds,
        "generation_info": gen_result,
    }

    (metrics_dir / "campaign_metadata.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=True) + "\n", encoding="ascii")

    with (out_dir / "events.json").open("w", encoding="ascii") as f:
        json.dump(events_list, f, indent=2, ensure_ascii=True)

    event_rows = _build_security_event_timeseries(
        timeline, dut=dut, campaign_id=campaign_id, seed=seed,
    )
    if event_rows:
        (metrics_dir / "security_event_timeseries.jsonl").write_text(
            "\n".join(json.dumps(r, ensure_ascii=True) for r in event_rows) + "\n",
            encoding="ascii",
        )

    return meta


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cascade baseline adapter")
    parser.add_argument("--dut", choices=list(SUPPORTED_DUTS), default="rocket-clean")
    parser.add_argument("--num-elfs", type=int, default=5)
    parser.add_argument("--simlen", type=int, default=50000)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=1)

    args = parser.parse_args(argv)
    meta = run_cascade_baseline(
        dut=args.dut, num_elfs=args.num_elfs, simlen=args.simlen,
        timeout_seconds=args.timeout, out_dir=args.out.resolve(), seed=args.seed,
    )
    print(json.dumps(meta, indent=2, ensure_ascii=True))
    return 0 if meta.get("status") != "infra_failure" else 1


if __name__ == "__main__":
    raise SystemExit(main())
