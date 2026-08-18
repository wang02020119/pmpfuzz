#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import u74_cl144_common as C

REPO_ROOT = Path(__file__).resolve().parents[4]
RUNNER = REPO_ROOT / "scripts" / "evaluation" / "run_u74_board_round.py"
SELECT_GUIDED = REPO_ROOT / "scripts" / "evaluation" / "u74_guided_select.py"
SELECT_RANDOM = REPO_ROOT / "scripts" / "evaluation" / "u74_random_select.py"
GENERATE_GUIDED = REPO_ROOT / "scripts" / "evaluation" / "u74_guided_generate.py"
GENERATE_RANDOM = REPO_ROOT / "scripts" / "evaluation" / "u74_random_generate.py"
AGGREGATE = REPO_ROOT / "scripts" / "evaluation" / "aggregate_u74_bapc.py"

CAPABILITY_FINGERPRINT = C.CONTRACT_CAPABILITY_FINGERPRINT
CAMPAIGN_ID = C.CAMPAIGN_ID


def run_py(args: list[str]) -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT)
    if "VF2_SUDO_PASSWORD" not in env:
        env["VF2_SUDO_PASSWORD"] = "starfive"
    result = subprocess.run(
        [sys.executable] + args,
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode != 0:
        raise SystemExit(f"command failed (exit {result.returncode}): {' '.join(args)}")


def _round_dir(root: Path, round_index: int) -> Path:
    return root / "rounds" / f"round-{round_index:04d}"


def _runner_args(
    *,
    root: Path,
    round_index: int,
    seed: int,
    campaign_id: str,
    universe: Path,
    observation_profile: Path,
    schedule_path: Path,
    catalog_path: Path,
    out_dir: Path,
    real: bool,
    board_patch_manifest: Path | None = None,
) -> list[str]:
    args = [
        str(RUNNER),
        "--mode", "real" if real else "fake",
        "--out", str(out_dir),
        "--schedule", str(schedule_path),
        "--seed", str(seed),
        "--campaign-id", campaign_id,
        "--u74-catalog", str(catalog_path),
        "--u74-observation-profile", str(observation_profile),
        "--capability-fingerprint", CAPABILITY_FINGERPRINT,
        "--u74-supported-bapc-universe", str(universe),
        "--u74-supported-bapc-universe-sha256", C.CONTRACT_UNIVERSE_SHA256,
        "--u74-supported-bapc-universe-file-sha256", C.sha256_file(universe),
    ]
    if board_patch_manifest is not None:
        args += ["--u74-board-patch-manifest", str(board_patch_manifest)]
    if real:
        args.append("--board-reboot-over-ssh")
    return args


def update_convergence(root: Path, summary: dict[str, Any]) -> None:
    conv_path = root / "aggregation" / "convergence.json"
    if conv_path.exists():
        conv = C.load_json(conv_path)
    else:
        conv = {"schema_version": 1, "campaign_id": CAMPAIGN_ID, "rows": []}
    conv["rows"].append(
        {
            "round_id": summary["round_id"],
            "round_index": int(str(summary["round_id"]).split("-")[1]),
            "cumulative_covered": summary["cumulative_covered_count"],
            "cumulative_reachable_covered": summary["reachable_covered_count"],
            "universe_bin_count": summary["universe_bin_count"],
            "reachable_bin_count": summary["reachable_bin_count"],
            "unsupported_bin_count": summary["unsupported_bin_count"],
            "new_bins_in_round": summary["round_new_count"],
            "eligible_cases_in_round": summary["eligible_count"],
            "eligible_cumulative": summary["eligible_cumulative"],
            "executed_cases_in_round": summary["executed_count"],
            "coverage_hash": summary["coverage_hash"],
            "error_count": (summary.get("validator") or {}).get("error_count"),
        }
    )
    C.write_json(conv_path, conv)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Drive one U74 closedloop-144 round")
    parser.add_argument("--round-index", type=int, required=True)
    parser.add_argument("--mode", choices=("round0", "guided", "random"), required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--budget", type=int, default=96)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--universe", type=Path, required=True)
    parser.add_argument("--observation-profile", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True,
                        help="campaign root (closedloop-144 or random/run-seed-NNNN)")
    parser.add_argument("--campaign-id", default=None)
    parser.add_argument("--prior-summary", type=Path, default=None)
    parser.add_argument("--skip-select", action="store_true")
    parser.add_argument("--skip-run", action="store_true")
    parser.add_argument("--fake", action="store_true", help="fake materialization instead of real board")
    parser.add_argument("--board-patch-manifest", type=Path, default=None,
                        help="placeholder patch manifest for fake materialization (real runs rebuild their own)")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    rdir = _round_dir(root, args.round_index)
    rdir.mkdir(parents=True, exist_ok=True)
    campaign_id = args.campaign_id or f"{CAMPAIGN_ID}__round-{args.round_index:04d}"

    if not args.skip_select:
        if args.mode == "random" and args.round_index >= 1:

            sel_args = [str(GENERATE_RANDOM)]
            common = [
                "--seed-pool", str(args.corpus), "--universe", str(args.universe),
                "--round-index", str(args.round_index), "--budget", str(args.budget),
                "--seed", str(args.seed), "--out-dir", str(rdir),
                "--prior-summary", str(args.prior_summary),
            ]
        elif args.mode == "random":
            sel_args = [str(SELECT_RANDOM)]
            common = [
                "--corpus", str(args.corpus), "--universe", str(args.universe),
                "--round-index", str(args.round_index), "--budget", str(args.budget),
                "--seed", str(args.seed), "--campaign-id", campaign_id,
                "--out-dir", str(rdir),
            ]
        elif args.mode == "guided" and args.round_index >= 1:

            sel_args = [str(GENERATE_GUIDED)]
            common = [
                "--seed-pool", str(args.corpus), "--universe", str(args.universe),
                "--round-index", str(args.round_index), "--budget", str(args.budget),
                "--seed", str(args.seed), "--out-dir", str(rdir),
                "--prior-summary", str(args.prior_summary),
            ]
        else:
            sel_args = [str(SELECT_GUIDED)]
            common = [
                "--corpus", str(args.corpus), "--universe", str(args.universe),
                "--round-index", str(args.round_index), "--budget", str(args.budget),
                "--seed", str(args.seed), "--campaign-id", campaign_id,
                "--out-dir", str(rdir),
            ]
            if args.round_index > 0:
                if args.prior_summary is None:
                    raise SystemExit("--prior-summary required for round_index >= 1")
                common += ["--prior-summary", str(args.prior_summary)]
            if args.mode == "round0":
                common += ["--mode", "round0"]
        run_py(sel_args + common)

    schedule_path = rdir / f"schedule_round_{args.round_index:04d}.json"
    catalog_path = rdir / "catalog.json"
    if not schedule_path.exists():
        raise SystemExit(f"schedule missing after selection: {schedule_path}")

    if not args.skip_run:
        runner_args = _runner_args(
            root=root, round_index=args.round_index, seed=args.seed,
            campaign_id=campaign_id, universe=args.universe,
            observation_profile=args.observation_profile,
            schedule_path=schedule_path, catalog_path=catalog_path,
            out_dir=rdir, real=not args.fake,
            board_patch_manifest=args.board_patch_manifest,
        )
        start = time.time()
        run_py(runner_args)
        print(f"[round {args.round_index}] runner finished in {time.time() - start:.1f}s")

    prior_arg = ["--prior-summary", str(args.prior_summary)] if args.prior_summary and Path(args.prior_summary).exists() else []
    out_summary = root / "aggregation" / f"round-{args.round_index:04d}-summary.json"
    run_py([str(AGGREGATE), "--round-dir", str(rdir),
            "--universe", str(args.universe), "--out", str(out_summary)] + prior_arg)
    summary = C.load_json(out_summary)
    update_convergence(root, summary)


    gen_manifest = rdir / "manifests" / "u74-generated-round-manifest.json"
    if gen_manifest.exists():
        C.write_json(rdir / "generated_round_manifest.json", C.load_json(gen_manifest))

    print(f"[round {args.round_index}] aggregate: "
          f"{summary['cumulative_covered_count']}/{summary['universe_bin_count']} cumulative "
          f"({summary['reachable_covered_count']}/{summary['reachable_bin_count']} reachable), "
          f"new {summary['round_new_count']}, missing reachable {summary['missing_reachable_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
