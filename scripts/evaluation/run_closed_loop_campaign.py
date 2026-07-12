#!/usr/bin/env python3
"""Closed-loop fuzzing campaign driver.

Runs a repeating round-loop:
1. Bootstrap batch (common for paired random/guided experiments)
2. Each round: schedule next cases via coverage scheduler or random order
3. Run batch, record timeline
4. Repeat until budget exhausted, pool depleted, or coverage complete
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def run_closed_loop(args: argparse.Namespace) -> int:
    """Execute a closed-loop campaign.

    Returns 0 on success, 1 on failure.
    """
    artifact_root = Path(args.artifact_root).resolve()
    campaign_dir = _campaign_output_dir(args, artifact_root)

    if campaign_dir.exists():
        print(f"ERROR: campaign output directory already exists: {campaign_dir}", file=sys.stderr)
        return 1

    campaign_dir.mkdir(parents=True)
    rounds_dir = campaign_dir / "rounds"
    rounds_dir.mkdir()
    metrics_dir = campaign_dir / "metrics"
    metrics_dir.mkdir()

    # Record start
    start_utc = datetime.now(timezone.utc).isoformat()
    start_wall = time.monotonic()

    # Write campaign metadata
    meta = {
        "schema_version": "1.0",
        "experiment_id": args.experiment_id,
        "campaign_id": args.campaign_id or campaign_dir.name,
        "variant": args.variant,
        "coverage_mode": args.coverage_mode,
        "dut": args.dut,
        "seed": args.seed,
        "round_size": args.round_size,
        "time_budget_seconds": args.time_budget,
        "per_case_timeout_seconds": args.per_case_timeout,
        "bootstrap_size": args.bootstrap_size,
        "start_utc": start_utc,
        "hostname": os.uname().nodename if hasattr(os, "uname") else "unknown",
        "command_line": " ".join(sys.argv),
    }
    (metrics_dir / "campaign_metadata.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )

    # Build the base command prefix (without --out, --schedule, --seed which vary)
    base_cmd = [
        sys.executable, "-m", "pmpfuzz", "run",
        "--dut", args.dut,
        "--time-budget", _format_budget(args.round_size * args.per_case_timeout * 2),  # per-round budget
        "--per-case-timeout", str(args.per_case_timeout),
        "--jobs", str(args.jobs),
        "--whitebox-artifacts" if args.whitebox else "",
    ]
    if args.spike:
        base_cmd.extend(["--spike", args.spike])
    if args.isa:
        base_cmd.extend(["--isa", args.isa])
    if args.chipyard_dir:
        base_cmd.extend(["--chipyard-dir", args.chipyard_dir])
    if args.dut_bin:
        base_cmd.extend(["--dut-bin", args.dut_bin])
    if args.no_smepmp:
        base_cmd.append("--no-smepmp")
    base_cmd = [c for c in base_cmd if c]  # remove empty strings

    # --- Step 1: Bootstrap batch ---
    print(f"[{datetime.now(timezone.utc).isoformat()}] Bootstrap batch (size={args.bootstrap_size})")
    bootstrap_dir = rounds_dir / "round_0000"
    bootstrap_profile = args.bootstrap_profile or args.profile

    bootstrap_cmd = base_cmd + [
        "--out", str(bootstrap_dir),
        "--profile", bootstrap_profile,
        "--count", str(args.bootstrap_size),
        "--seed", str(args.seed),
        "--record-timeline",
        "--campaign-id", f"{args.campaign_id or campaign_dir.name}__bootstrap",
        "--variant", f"{args.variant}__bootstrap",
    ]

    ret = _run_command(bootstrap_cmd, round_label="bootstrap")
    if ret != 0:
        print(f"ERROR: bootstrap failed with code {ret}", file=sys.stderr)
        _write_commands_log(metrics_dir)
        return ret

    # Compute initial coverage
    _run_coverage(bootstrap_dir)

    # --- Step 2: Closed-loop rounds ---
    round_idx = 1
    total_cases = args.bootstrap_size
    completed_rounds = [bootstrap_dir]

    while True:
        elapsed = time.monotonic() - start_wall
        if elapsed >= args.time_budget:
            print(f"Time budget exhausted after {round_idx} rounds")
            break

        print(f"\n[{datetime.now(timezone.utc).isoformat()}] Round {round_idx} (elapsed={elapsed:.0f}s)")

        round_dir = rounds_dir / f"round_{round_idx:04d}"

        # Determine next cases
        if args.variant == "random":
            # Random order: just run a batch with a different seed
            round_seed = args.seed + round_idx * 1000
            round_cmd = base_cmd + [
                "--out", str(round_dir),
                "--profile", args.profile,
                "--count", str(args.round_size),
                "--seed", str(round_seed),
                "--record-timeline",
                "--campaign-id", f"{args.campaign_id or campaign_dir.name}__round-{round_idx:04d}",
                "--variant", args.variant,
            ]
        else:
            # Guided: build schedule from previous rounds, then run
            schedule_path = _build_schedule(
                completed_rounds=completed_rounds,
                campaign_dir=campaign_dir,
                round_idx=round_idx,
                args=args,
            )
            if schedule_path is None:
                print("No schedule could be built — candidate pool exhausted")
                break

            round_seed = args.seed + round_idx * 1000
            round_cmd = base_cmd + [
                "--out", str(round_dir),
                "--schedule", str(schedule_path),
                "--seed", str(round_seed),
                "--record-timeline",
                "--campaign-id", f"{args.campaign_id or campaign_dir.name}__round-{round_idx:04d}",
                "--variant", args.variant,
            ]

        ret = _run_command(round_cmd, round_label=f"round_{round_idx:04d}")
        if ret != 0:
            print(f"WARNING: round {round_idx} had non-zero exit: {ret}", file=sys.stderr)

        _run_coverage(round_dir)
        completed_rounds.append(round_dir)
        round_idx += 1

        # Check round results for total case count
        summary_path = round_dir / "summary.json"
        if summary_path.exists():
            summary = json.loads(summary_path.read_text(encoding="ascii"))
            total_cases += summary.get("total", summary.get("total_cases", 0))

    # --- Step 3: Merge round timelines into campaign-level timeline ---
    _merge_timelines(campaign_dir, completed_rounds, meta)

    # --- Step 4: Final coverage ---
    end_utc = datetime.now(timezone.utc).isoformat()
    meta["end_utc"] = end_utc
    meta["completed_rounds"] = round_idx
    meta["total_cases"] = total_cases
    (metrics_dir / "campaign_metadata.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )

    _write_commands_log(metrics_dir)
    subprocess.run(
        [sys.executable, "-m", "pmpfuzz", "coverage", "--run-dir", str(campaign_dir)],
        check=False,
    )

    print(f"\nCampaign complete: {campaign_dir}")
    print(f"  Rounds: {round_idx}")
    print(f"  Total cases: {total_cases}")
    print(f"  Wall time: {time.monotonic() - start_wall:.0f}s")
    return 0


def _campaign_output_dir(args, artifact_root: Path) -> Path:
    """Determine the campaign output directory path."""
    if args.campaign_id:
        parts = args.campaign_id.split("__")
        if len(parts) >= 4:
            experiment = args.experiment_id
            dut = args.dut
            variant = args.variant
            cmode = args.coverage_mode
            seed_label = f"seed-{args.seed:04d}"
            return artifact_root / "campaigns" / experiment / dut / variant / cmode / seed_label
        return artifact_root / "campaigns" / args.campaign_id
    return artifact_root / "campaigns" / args.experiment_id / args.dut / args.variant / args.coverage_mode / f"seed-{args.seed:04d}"


def _build_schedule(
    completed_rounds: list[Path],
    campaign_dir: Path,
    round_idx: int,
    args: argparse.Namespace,
) -> Path | None:
    """Build a coverage-guided schedule from completed rounds."""
    from_runs = ",".join(str(d) for d in completed_rounds)
    schedule_path = campaign_dir / "metrics" / f"schedule_round_{round_idx:04d}.json"
    schedule_path.parent.mkdir(parents=True, exist_ok=True)

    schedule_cmd = [
        sys.executable, "-m", "pmpfuzz", "schedule",
        "--from-runs", from_runs,
        "--max-cases", str(args.round_size),
        "--seed", str(args.seed + round_idx * 1000),
        "--out", str(schedule_path),
        "--coverage-mode", args.coverage_mode,
        "--coverage-basis", "execution",
    ]
    if args.dut:
        schedule_cmd.extend(["--dut", args.dut])

    ret = subprocess.run(schedule_cmd, check=False, capture_output=True, text=True)
    if ret.returncode != 0:
        print(f"Schedule command failed: {ret.stderr}", file=sys.stderr)
        return None

    if not schedule_path.exists():
        return None

    # Check if schedule is empty
    schedule = json.loads(schedule_path.read_text(encoding="ascii"))
    if not schedule.get("entries"):
        return None

    return schedule_path


def _run_coverage(run_dir: Path) -> None:
    """Run pmpfuzz coverage on a run directory."""
    subprocess.run(
        [sys.executable, "-m", "pmpfuzz", "coverage", "--run-dir", str(run_dir)],
        check=False, capture_output=True,
    )


def _run_command(cmd: list[str], round_label: str = "") -> int:
    """Run a shell command and log its output."""
    print(f"  [{round_label}] {' '.join(cmd[:6])}...")
    result = subprocess.run(cmd, check=False)
    return result.returncode


def _merge_timelines(campaign_dir: Path, round_dirs: list[Path], meta: dict) -> None:
    """Merge per-round timeline JSONL files into one campaign-level file."""
    import shutil

    merged_path = campaign_dir / "metrics" / "coverage_timeline.jsonl"
    offset_seconds = 0.0

    with merged_path.open("w", encoding="ascii") as out:
        for i, round_dir in enumerate(round_dirs):
            tl_path = round_dir / "metrics" / "coverage_timeline.jsonl"
            if not tl_path.exists():
                continue
            lines = tl_path.read_text(encoding="ascii").strip().split("\n")
            for line in lines:
                if not line.strip():
                    continue
                obj = json.loads(line)
                if obj.get("completion_seq") == 0:
                    # Baseline: keep only for first round
                    if i == 0:
                        out.write(json.dumps(obj, ensure_ascii=True, sort_keys=True) + "\n")
                    continue
                # Adjust wall time for later rounds
                obj["elapsed_wall_seconds"] = round(obj.get("elapsed_wall_seconds", 0) + offset_seconds, 3)
                out.write(json.dumps(obj, ensure_ascii=True, sort_keys=True) + "\n")

            # Estimate offset for next round from the last line
            if lines:
                try:
                    last = json.loads(lines[-1])
                    offset_seconds += last.get("elapsed_wall_seconds", 0)
                except Exception:
                    pass

    # Also copy CSV if exists
    for round_dir in round_dirs:
        csv_path = round_dir / "metrics" / "coverage_timeline.csv"
        if csv_path.exists():
            shutil.copy2(csv_path, campaign_dir / "metrics" / "coverage_timeline.csv")
            break


def _write_commands_log(metrics_dir: Path) -> None:
    """Write the commands.log placeholder."""
    log_path = metrics_dir / "commands.log"
    if not log_path.exists():
        log_path.write_text(
            f"# PMPFuzz closed-loop campaign commands\n"
            f"# Recorded at {datetime.now(timezone.utc).isoformat()}\n"
            f"command: {' '.join(sys.argv)}\n",
            encoding="ascii",
        )


def _format_budget(seconds: int) -> str:
    """Format seconds as a human-readable budget string."""
    if seconds >= 3600:
        return f"{seconds // 3600}h"
    if seconds >= 60:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Closed-loop fuzzing campaign driver")
    parser.add_argument("--experiment-id", default="eval-v1")
    parser.add_argument("--variant", choices=["random", "guided", "bb", "bb-wb"], default="guided")
    parser.add_argument("--coverage-mode", choices=["semantic", "pairwise", "security-triples", "predicates"], default="semantic")
    parser.add_argument("--dut", default="spike")
    parser.add_argument("--profile", default="pmp-boundary")
    parser.add_argument("--bootstrap-profile", default=None)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--round-size", type=int, default=32)
    parser.add_argument("--bootstrap-size", type=int, default=32)
    parser.add_argument("--time-budget", type=int, default=3600, help="Total wall-clock seconds")
    parser.add_argument("--per-case-timeout", type=int, default=10)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--campaign-id", default=None)
    parser.add_argument("--spike", default=None)
    parser.add_argument("--isa", default=None)
    parser.add_argument("--chipyard-dir", default=None)
    parser.add_argument("--dut-bin", default=None)
    parser.add_argument("--no-smepmp", action="store_true")
    parser.add_argument("--whitebox", action="store_true", dest="whitebox")

    return run_closed_loop(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
