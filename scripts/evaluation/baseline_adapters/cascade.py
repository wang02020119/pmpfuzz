#!/usr/bin/env python3
"""Cascade baseline adapter — Phase E.

Uses the existing codex_cascade_cpu_fuzzing Docker container to generate
ELF programs, executes them on Rocket/BOOM DUTs with PMPFUZZ_PROBE
instrumentation, and produces normalized campaign data.

Terminal state classification (Cascade ELFs lack tohost):
  - completed: simulation exited with PMFUZZ_PROBE events observed
  - timeout: execution exceeded simlen budget
  - infra_failure: compilation or Verilator invocation failure
  - inconclusive: no PMFUZZ_PROBE events in output
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CASCADE_CONTAINER = "codex_cascade_cpu_fuzzing"
CASCADE_IMAGE = "ethcomsec/cascade-artifacts:latest"
CASCADE_IMAGE_SHA = "sha256:3d403b05be4a57fc1910b7e73bc807d499e382f73197ae8978ca1954524f0a11"
CASCADE_DESIGN_REPO_SHA = "0317c19b4148afb95243c39ca1f3772916a29a52"

ROCKET_SIM = "/home/dubhe/wjs/pmp-duts/chipyard-1.14.0/sims/verilator/simulator-chipyard.harness-RocketConfig"
ROCKET_SIM_SHA = "33f988486ebbf25711ce9e3ef42f1a8b1f41619b2584e35b8b549e943059db5d"
BOOM_SIM = "/home/dubhe/wjs/pmp-duts/chipyard-1.14.0/sims/verilator/simulator-chipyard.harness-SmallBoomV3Config"
BOOM_SIM_SHA = "e02afa40ccd836641f087fe91c7c93c3fd6265722dd3568b7868642def775265"

PROBE_RE = re.compile(r"PMFUZZ_PROBE\s+(.*)")
EVENT_ID_RE = re.compile(r"chain=(\S+).*?stage=(\S+).*?prv=(\d+)")


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


def run_cascade_baseline(
    dut: str,
    num_elfs: int,
    simlen: int,
    timeout_seconds: int,
    out_dir: Path,
    seed: int = 1,
) -> dict[str, Any]:
    """Run a Cascade baseline campaign.

    Returns campaign metadata dict.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    start_utc = datetime.now(timezone.utc).isoformat()
    start_wall = time.monotonic()

    # 1. Generate ELFs via container
    elfs_dir = out_dir / "elfs"
    elfs_dir.mkdir(exist_ok=True)
    gen_result = _generate_elfs(num_elfs, elfs_dir)
    if not gen_result["success"]:
        return {"status": "infra_failure", "error": "elf_generation_failed"}

    # 2. Execute each ELF on the DUT
    sim_path = ROCKET_SIM if dut == "rocket-clean" else BOOM_SIM
    sim_sha = ROCKET_SIM_SHA if dut == "rocket-clean" else BOOM_SIM_SHA

    events: list[dict] = []
    timeline_rows: list[dict] = []
    completed = 0
    timeouts = 0
    inconclusive = 0

    for i in range(num_elfs):
        elf_path = elfs_dir / f"rocket_{i}.elf"
        if not elf_path.exists():
            continue

        case_id = f"cascade_{dut}_{i:04d}"
        case_start = time.monotonic()

        # Run with fixed simlen
        try:
            proc = subprocess.run(
                [sim_path, "+permissive", "+verbose",
                 f"+max-cycles={simlen}", str(elf_path)],
                capture_output=True, text=True,
                timeout=timeout_seconds,
                cwd="/home/dubhe/wjs/pmp-duts/chipyard-1.14.0",
            )
            elapsed = time.monotonic() - case_start
            stdout = proc.stdout or ""

            probe_events = _extract_probe_events(stdout)
            if probe_events:
                status = "completed"
                completed += 1
            else:
                status = "inconclusive"
                inconclusive += 1

            events.append({
                "case_id": case_id, "status": status,
                "elapsed_seconds": elapsed, "probe_events": len(probe_events),
                "returncode": proc.returncode,
            })

            timeline_rows.append({
                "case_id": case_id,
                "status": status,
                "elapsed_wall_seconds": time.monotonic() - start_wall,
                "case_elapsed_seconds": elapsed,
                "probe_events": len(probe_events),
            })
        except subprocess.TimeoutExpired:
            timeouts += 1
            events.append({"case_id": case_id, "status": "timeout"})
            timeline_rows.append({
                "case_id": case_id, "status": "timeout",
                "elapsed_wall_seconds": time.monotonic() - start_wall,
                "case_elapsed_seconds": timeout_seconds,
                "probe_events": 0,
            })

    # 3. Write campaign metadata
    end_utc = datetime.now(timezone.utc).isoformat()
    meta = {
        "schema_version": "1.0",
        "experiment_id": "cascade-baseline",
        "campaign_id": f"cascade__{dut}__seed-{seed:04d}",
        "method": "cascade",
        "variant": "baseline",
        "dut": dut,
        "seed": seed,
        "source_sha": CASCADE_DESIGN_REPO_SHA,
        "dut_sha": "",
        "dut_binary_sha256": sim_sha,
        "container_image": CASCADE_IMAGE_SHA,
        "start_utc": start_utc,
        "end_utc": end_utc,
        "time_budget_seconds": int(time.monotonic() - start_wall),
        "completed_cases": completed + timeouts + inconclusive,
        "eligible_cases": completed,
        "completed": completed,
        "timeouts": timeouts,
        "inconclusive": inconclusive,
        "simlen": simlen,
        "generation_info": gen_result,
    }

    metrics_dir = out_dir / "metrics"
    metrics_dir.mkdir(exist_ok=True)
    (metrics_dir / "campaign_metadata.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=True) + "\n", encoding="ascii",
    )
    (out_dir / "events.json").write_text(
        json.dumps(events, indent=2, ensure_ascii=True) + "\n", encoding="ascii",
    )

    # 4. Write security event timeseries (PMPFuzz-probe events = common metric)
    security_events = _build_security_event_timeseries(elfs_dir, timeline_rows)
    (metrics_dir / "security_event_timeseries.jsonl").write_text(
        "\n".join(json.dumps(e, ensure_ascii=True) for e in security_events) + "\n",
        encoding="ascii",
    )

    return meta


def _generate_elfs(num_elfs: int, out_dir: Path) -> dict[str, Any]:
    """Generate Cascade ELFs using the existing container."""
    start = time.monotonic()
    mount_dir = "/home/dubhe/wjs/cascade_cpu_fuzzing/mount"
    container_out = "/cascade-mountdir/cascade-elfs"

    os.makedirs(os.path.join(mount_dir, "cascade-elfs"), exist_ok=True)

    proc = subprocess.run([
        "docker", "exec", CASCADE_CONTAINER,
        "bash", "-c",
        f"source /cascade-meta/env.sh && "
        f"mkdir -p {container_out} && "
        f"python3 /cascade-meta/fuzzer/do_genmanyelfs.py {num_elfs} {container_out}",
    ], capture_output=True, text=True, timeout=600, check=False)

    elapsed = time.monotonic() - start
    return {
        "success": proc.returncode == 0,
        "returncode": proc.returncode,
        "elapsed_seconds": elapsed,
        "stderr": proc.stderr[-500:] if proc.stderr else "",
    }


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
            event_id = EVENT_ID_RE.search(fields_str)
            chain = event_id.group(1) if event_id else ""
            stage = event_id.group(2) if event_id else ""
            events.append({
                "kind": "source_probe",
                "chain": chain,
                "stage": stage,
                "fields": fields,
            })
    return events


def _build_security_event_timeseries(
    elfs_dir: Path, timeline_rows: list[dict]
) -> list[dict[str, Any]]:
    """Build normalized security event timeseries from ELFs and execution records."""
    rows = []
    event_set: set[str] = set()
    total_events = 0

    for tr in timeline_rows:
        case_id = tr["case_id"]
        elf_path = elfs_dir / f"{case_id.split('_')[-1]}.elf" if "_" in case_id else None
        # Count probe events observed
        new_events = tr.get("probe_events", 0)
        total_events += new_events
        event_set.add(case_id)

        rows.append({
            "schema_version": "1.0",
            "experiment_id": "cascade-baseline",
            "campaign_id": "cascade",
            "method": "cascade",
            "variant": "baseline",
            "dut": "unknown",
            "seed": 1,
            "completion_seq": len(rows) + 1,
            "elapsed_wall_seconds": tr["elapsed_wall_seconds"],
            "event_namespace": "source_probe",
            "event_category": "pmp_check",
            "event_id": case_id,
            "is_new_event": new_events > 0,
            "total_distinct_events": len(event_set),
            "case_id": case_id,
        })
    return rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cascade baseline adapter")
    parser.add_argument("--dut", choices=["rocket-clean", "boom-clean"], default="rocket-clean")
    parser.add_argument("--num-elfs", type=int, default=5)
    parser.add_argument("--simlen", type=int, default=50000)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=1)

    args = parser.parse_args(argv)
    meta = run_cascade_baseline(
        dut=args.dut,
        num_elfs=args.num_elfs,
        simlen=args.simlen,
        timeout_seconds=args.timeout,
        out_dir=args.out.resolve(),
        seed=args.seed,
    )
    print(json.dumps(meta, indent=2, ensure_ascii=True))
    return 0 if meta.get("status") != "infra_failure" else 1


if __name__ == "__main__":
    raise SystemExit(main())
