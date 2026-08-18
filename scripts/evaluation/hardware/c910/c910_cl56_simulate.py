#!/usr/bin/env python3
"""Offline closed-loop simulation for the C910 closedloop-56 campaign.

Treats each round's schedule predicted bins as the board's real coverage
(perfect-oracle simulation) to validate the generation loop and the
convergence rule without hardware.  Not part of the experiment.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

REPO = Path(__file__).resolve().parents[4]
GEN = REPO / "scripts" / "evaluation" / "c910_guided_generate.py"
AGG = REPO / "scripts" / "evaluation" / "c910_cl56_final_summary.py"


def run(cmd: list[str]) -> None:
    subprocess.run([sys.executable, *[str(c) for c in cmd]], check=True)


def write_round_coverage(root: Path, round_index: int) -> None:
    round_dir = root / "rounds" / f"round-{round_index:04d}"
    schedule = json.loads((round_dir / f"schedule_round_{round_index:04d}.json").read_text(encoding="utf-8"))
    covered = set()
    for entry in schedule["entries"]:
        covered.update(entry.get("predicted_bins") or [])
    payload = {
        "universe": "v4-nonpmp-56",
        "universe_size": 56,
        "covered_bins": sorted(covered),
        "covered_count": len(covered),
        "mapped": len(schedule["entries"]),
        "unsupported": 0,
        "observation_unqualified": 0,
        "compliant": 0,
        "known_violations": [],
    }
    out = round_dir / "run" / "coverage" / "shared56.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--seed-pool", type=Path, required=True)
    parser.add_argument("--max-rounds", type=int, default=8)
    args = parser.parse_args(argv)

    root = args.root
    seed_pool = args.seed_pool
    for r in range(args.max_rounds):
        round_dir = root / "rounds" / f"round-{r:04d}"
        prior = root / "aggregation" / f"round-{r - 1:04d}-summary.json"
        cmd = [GEN, "--seed-pool", seed_pool, "--round-index", str(r),
               "--budget", "16", "--seed", "4", "--out-dir", round_dir]
        if prior.exists():
            cmd += ["--prior-summary", prior]
        run(cmd)
        write_round_coverage(root, r)
        run([AGG, "--root", root, "--round-index", str(r)])
        conv = json.loads((root / "aggregation" / "convergence.json").read_text(encoding="utf-8"))
        if conv.get("stop_reason"):
            print(f"simulation stopped at round-{r:04d}: {conv['stop_reason']}")
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
