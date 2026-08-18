#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_c910_m2_campaign as m2

DEFAULT_ROOT = REPO_ROOT / "artifacts" / "hw-v2-m2" / "c910" / "closedloop-56"
DEFAULT_SEED_POOL = DEFAULT_ROOT / "aggregation" / "seed-pool.json"


def _run(args: list[str]) -> str:
    completed = subprocess.run(args, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(str(a) for a in args)}\n{completed.stdout}\n{completed.stderr}".strip()
        )
    return completed.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--round-index", type=int, required=True)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--seed-pool", type=Path, default=DEFAULT_SEED_POOL)
    parser.add_argument("--budget", type=int, default=16)
    parser.add_argument("--seed", type=int, default=4)
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--build-remote", action="store_true")
    parser.add_argument("--upload", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--analyze", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--remote-host", default=m2.DEFAULT_REMOTE_HOST)
    parser.add_argument("--remote-root", default=m2.DEFAULT_REMOTE_ROOT)
    parser.add_argument("--remote-tree", default=m2.DEFAULT_REMOTE_TREE)
    parser.add_argument("--security-probe", type=Path, default=m2.DEFAULT_SECURITY_PROBE)
    parser.add_argument("--jobs", type=int, default=48)
    parser.add_argument(
        "--upload-script",
        type=Path,
        default=REPO_ROOT / "scripts" / "transport" / "serial_linux_upload.py",
    )
    parser.add_argument("--serial-script", type=Path, default=None)
    parser.add_argument("--port", default=os.environ.get("PMPFUZZ_BOARD_SERIAL_PORT", ""))
    parser.add_argument(
        "--baud",
        type=int,
        default=int(os.environ.get("PMPFUZZ_BOARD_SERIAL_BAUD", "115200")),
    )
    parser.add_argument("--timeout-seconds", type=int, default=420)
    parser.add_argument("--login-user", default=os.environ.get("PMPFUZZ_BOARD_LOGIN_USER", ""))
    parser.add_argument("--login-password", default=os.environ.get("PMPFUZZ_BOARD_LOGIN_PASSWORD", ""))
    args = parser.parse_args()
    if args.build_remote and not args.remote_host:
        parser.error("--remote-host is required with --build-remote")

    root = Path(args.root)
    round_dir = root / "rounds" / f"round-{args.round_index:04d}"
    round_dir.mkdir(parents=True, exist_ok=True)

    if args.generate:
        prior = root / "aggregation" / f"round-{args.round_index - 1:04d}-summary.json"
        cmd = [
            sys.executable,
            str(Path(__file__).resolve().parent / "c910_guided_generate.py"),
            "--seed-pool", str(args.seed_pool),
            "--round-index", str(args.round_index),
            "--budget", str(args.budget),
            "--seed", str(args.seed),
            "--out-dir", str(round_dir),
        ]
        if prior.exists():
            cmd += ["--prior-summary", str(prior)]
        _run(cmd)

    if args.build_remote:
        remote_tree = args.remote_tree or f"{args.remote_root}/revyos-thead-opensbi"
        item = {
            "mode": f"cl56-r{args.round_index:04d}",
            "round_id": f"round-{args.round_index:04d}",
            "generated_c_path": str(round_dir / "c910_nonpmp_generated_manifest.c"),
            "sidecar_path": str(round_dir / "fw_dynamic.bin"),
            "build_log_path": str(round_dir / "build.log"),
            "round_out_dir": str(round_dir),
        }
        m2.build_remote_round(
            item,
            remote_host=args.remote_host,
            remote_root=args.remote_root,
            remote_tree=remote_tree,
            security_probe=(
                args.security_probe
                if args.security_probe is not None and args.security_probe.exists()
                else None
            ),
            jobs=args.jobs,
            dry_run=args.dry_run,
        )

    if args.upload:
        item = {
            "sidecar_path": str(round_dir / "fw_dynamic.bin"),
            "round_out_dir": str(round_dir),
        }
        m2.upload_sidecar(
            item,
            upload_script=args.upload_script,
            port=args.port,
            baud=args.baud,
            login_user=args.login_user,
            login_password=args.login_password,
            timeout_seconds=args.timeout_seconds,
            dry_run=args.dry_run,
        )

    if args.run:
        if args.serial_script is None:
            raise ValueError("--serial-script is required with --run")
        item = {
            "sidecar_path": str(round_dir / "fw_dynamic.bin"),
            "uart_log_path": str(round_dir / "uart.log"),
        }
        m2.run_board_round(
            item,
            serial_script=args.serial_script,
            port=args.port,
            baud=args.baud,
            timeout_seconds=args.timeout_seconds,
            login_user=args.login_user,
            login_password=args.login_password,
            dry_run=args.dry_run,
        )
        print(f"round-{args.round_index:04d} executed; POWER-CYCLE the board, then --analyze")

    if args.analyze:
        uart_log = round_dir / "uart.log"
        if not uart_log.exists():
            raise FileNotFoundError(f"missing UART log: {uart_log}")
        from aggregate_c910_shared56 import classify_run_shared56
        from pmpfuzz.c910_nonpmp_dynamic import write_dynamic_run

        write_dynamic_run(
            uart_log=uart_log,
            manifest_path=round_dir / "manifest-v3.json",
            out_dir=round_dir / "run",
        )
        classify_run_shared56(round_dir / "run")
        from c910_cl56_final_summary import main as final_summary

        final_summary(["--root", str(root), "--round-index", str(args.round_index)])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
