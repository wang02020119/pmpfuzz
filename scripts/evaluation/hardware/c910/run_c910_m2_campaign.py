#!/usr/bin/env python3
"""Run or prepare the pre-registered C910 M-2 guided-vs-random campaign.

The safe default is a dry run: parse the frozen manifests, materialize the C
manifest source needed by OpenSBI, and write a run plan.  Hardware actions are
enabled explicitly with --build-remote, --upload-sidecars, --run-board, and
--analyze.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

from pmpfuzz.c910_m2_scheduling import aggregate_shared56
from pmpfuzz.c910_nonpmp_dynamic import generated_manifest_source, write_dynamic_run
from pmpfuzz.v4_nonpmp_projection import classify_scenario


DEFAULT_M2_ROOT = REPO_ROOT / "artifacts" / "hw-v2-m2" / "c910"
DEFAULT_OUT_DIR = DEFAULT_M2_ROOT / "board-runs"
DEFAULT_REMOTE_HOST = os.environ.get("PMPFUZZ_C910_REMOTE_HOST", "")
DEFAULT_REMOTE_ROOT = os.environ.get("PMPFUZZ_C910_REMOTE_ROOT", "/tmp/pmpfuzz-c910")
DEFAULT_REMOTE_TREE = os.environ.get(
    "PMPFUZZ_C910_REMOTE_TREE",
    f"{DEFAULT_REMOTE_ROOT}/revyos-thead-opensbi",
)
_security_probe = os.environ.get("PMPFUZZ_C910_SECURITY_PROBE", "")
DEFAULT_SECURITY_PROBE = Path(_security_probe).expanduser() if _security_probe else None


def _read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="ascii"))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="ascii")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(args: list[str], *, cwd: Path | None = None, dry_run: bool = False) -> str:
    if dry_run:
        print("DRY-RUN", " ".join(args))
        return ""
    completed = subprocess.run(args, cwd=cwd, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed with exit code {completed.returncode}: {' '.join(args)}\n"
            f"{completed.stdout}\n{completed.stderr}".strip()
        )
    return completed.stdout


def _execution_modes(registration: dict[str, Any]) -> list[str]:
    guided = registration.get("campaigns", {}).get("guided", {})
    order = str(guided.get("execution_order") or "guided-first-then-random")
    if order != "guided-first-then-random":
        raise ValueError(f"unsupported C910 M-2 execution_order: {order!r}")
    return ["guided", "random"]


def build_round_plan(*, m2_root: Path, out_dir: Path) -> list[dict[str, Any]]:
    """Return the six pre-registered round descriptors in execution order."""
    m2_root = Path(m2_root)
    out_dir = Path(out_dir)
    registration = _read_json(m2_root / "registration.json")
    campaigns = registration["campaigns"]
    plan: list[dict[str, Any]] = []
    for mode in _execution_modes(registration):
        rounds = int(campaigns[mode].get("rounds") or 0)
        for round_index in range(rounds):
            round_id = f"round-{round_index:04d}"
            src_dir = m2_root / mode / round_id
            manifest_path = src_dir / "manifest.json"
            provenance_path = src_dir / "provenance.json"
            if not manifest_path.exists():
                raise FileNotFoundError(f"missing M-2 manifest: {manifest_path}")
            if not provenance_path.exists():
                raise FileNotFoundError(f"missing M-2 provenance: {provenance_path}")
            manifest = _read_json(manifest_path)
            label = f"{mode}.{round_id}"
            round_out = out_dir / mode / round_id
            plan.append(
                {
                    "mode": mode,
                    "round_index": round_index,
                    "round_id": round_id,
                    "label": label,
                    "campaign_id": manifest["campaign_id"],
                    "manifest_path": str(manifest_path),
                    "provenance_path": str(provenance_path),
                    "manifest_sha256": manifest["sha256"],
                    "case_count": int(manifest["case_count"]),
                    "round_out_dir": str(round_out),
                    "generated_c_path": str(round_out / "c910_nonpmp_generated_manifest.c"),
                    "local_manifest_copy": str(round_out / "manifest.json"),
                    "local_provenance_copy": str(round_out / "provenance.json"),
                    "sidecar_path": str(round_out / f"fw_dynamic.bin.{mode}.{round_id}"),
                    "build_log_path": str(round_out / "build.log"),
                    "uart_log_path": str(round_out / "uart.log"),
                    "run_dir": str(round_out / "run"),
                }
            )
    return plan


def materialize_round_sources(plan: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Write generated C sources and local manifest/provenance copies."""
    materialized: list[dict[str, Any]] = []
    for item in plan:
        manifest_path = Path(item["manifest_path"])
        manifest = _read_json(manifest_path)
        round_out = Path(item["round_out_dir"])
        round_out.mkdir(parents=True, exist_ok=True)
        generated_c_path = Path(item["generated_c_path"])
        generated_c_path.write_text(generated_manifest_source(manifest), encoding="ascii")
        shutil.copy2(manifest_path, Path(item["local_manifest_copy"]))
        shutil.copy2(Path(item["provenance_path"]), Path(item["local_provenance_copy"]))
        materialized.append(dict(item))
    return materialized


def build_remote_round(
    item: dict[str, Any],
    *,
    remote_host: str,
    remote_root: str,
    remote_tree: str,
    security_probe: Path | None,
    jobs: int,
    dry_run: bool = False,
) -> dict[str, Any]:
    normalized_remote_root = PurePosixPath(remote_root)
    if not normalized_remote_root.is_absolute() or ".." in normalized_remote_root.parts:
        raise ValueError(f"remote build root must be an absolute normalized path: {remote_root}")
    if len(normalized_remote_root.parts) < 3:
        raise ValueError(f"refusing overly broad remote build root: {remote_root}")
    remote_generic = f"{remote_tree.rstrip('/')}/platform/generic"
    remote_build = f"{remote_root.rstrip('/')}/build-{item['mode']}-{item['round_id']}"
    remote_log = f"{remote_root.rstrip('/')}/build-{item['mode']}-{item['round_id']}.log"
    remote_sidecar = f"{remote_build}/platform/generic/firmware/fw_dynamic.bin"
    generated_c = Path(item["generated_c_path"])
    local_sidecar = Path(item["sidecar_path"])
    local_log = Path(item["build_log_path"])

    if security_probe is not None and Path(security_probe).exists():
        _run(["scp", str(security_probe), f"{remote_host}:{remote_generic}/security_chain_probe.c"], dry_run=dry_run)
    _run(["scp", str(generated_c), f"{remote_host}:{remote_generic}/c910_nonpmp_generated_manifest.c"], dry_run=dry_run)
    build_cmd = (
        "set -e; "
        f"ROOT={_sh_quote(remote_root)}; "
        f"SRC={_sh_quote(remote_tree)}; "
        f"BUILD={_sh_quote(remote_build)}; "
        f"LOG={_sh_quote(remote_log)}; "
        'rm -rf "$BUILD"; '
        'cd "$SRC"; '
        f'make CROSS_COMPILE=riscv64-linux-gnu- PLATFORM=generic O="$BUILD" '
        f"platform-cflags-y=-std=gnu11 -j{int(jobs)} >\"$LOG\" 2>&1; "
        'sha256sum "$BUILD/platform/generic/firmware/fw_dynamic.bin"'
    )
    remote_sha = _run(["ssh", remote_host, build_cmd], dry_run=dry_run).strip()
    _run(["scp", f"{remote_host}:{remote_sidecar}", str(local_sidecar)], dry_run=dry_run)
    _run(["scp", f"{remote_host}:{remote_log}", str(local_log)], dry_run=dry_run)
    if not dry_run:
        item["sidecar_sha256"] = _sha256(local_sidecar)
        item["remote_sidecar_sha256"] = remote_sha
        (Path(item["round_out_dir"]) / "fw_dynamic.sha256.txt").write_text(
            f"{item['sidecar_sha256']}  {local_sidecar.name}\n{remote_sha}\n",
            encoding="ascii",
        )
    return item


def upload_sidecar(
    item: dict[str, Any],
    *,
    upload_script: Path,
    port: str,
    baud: int,
    login_user: str,
    login_password: str,
    timeout_seconds: int,
    dry_run: bool = False,
) -> None:
    sidecar = Path(item["sidecar_path"])
    if not dry_run and not sidecar.exists():
        raise FileNotFoundError(f"sidecar not built: {sidecar}")
    args = [
        sys.executable,
        str(upload_script),
        "--port",
        port,
        "--baud",
        str(int(baud)),
        "--login-user",
        login_user,
        "--login-password",
        login_password,
        "--timeout-seconds",
        str(int(timeout_seconds)),
        "--output-log",
        str(Path(item["round_out_dir"]) / "serial-upload.log"),
        "--remote-tmp-path",
        f"/tmp/{sidecar.name}",
        "--remote-dest-path",
        f"/boot/{sidecar.name}",
        str(sidecar),
    ]
    _run(args, dry_run=dry_run)


def run_board_round(
    item: dict[str, Any],
    *,
    serial_script: Path,
    port: str,
    baud: int,
    timeout_seconds: int,
    login_user: str,
    login_password: str,
    dry_run: bool = False,
) -> None:
    pwsh = shutil.which("pwsh.exe") or shutil.which("pwsh")
    if pwsh is None:
        raise FileNotFoundError("pwsh.exe is required for the C910 sidecar serial script")
    sidecar_name = Path(item["sidecar_path"]).name
    args = [
        pwsh,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(serial_script),
        "-Port",
        port,
        "-Baud",
        str(int(baud)),
        "-TimeoutSeconds",
        str(int(timeout_seconds)),
        "-Output",
        str(Path(item["uart_log_path"])),
        "-SidecarName",
        sidecar_name,
        "-LoginUser",
        login_user,
        "-LoginPassword",
        login_password,
    ]
    _run(args, dry_run=dry_run)


def analyze_round(item: dict[str, Any]) -> dict[str, Any]:
    uart_log = Path(item["uart_log_path"])
    if not uart_log.exists():
        raise FileNotFoundError(f"missing UART log: {uart_log}")
    write_dynamic_run(
        uart_log=uart_log,
        manifest_path=Path(item["local_manifest_copy"]),
        out_dir=Path(item["run_dir"]),
    )
    shared56 = classify_run_shared56(Path(item["run_dir"]))
    item["shared56"] = shared56
    return item


def classify_run_shared56(run_dir: Path) -> dict[str, Any]:
    run_dir = Path(run_dir)
    classifications: list[dict[str, Any]] = []
    for case_path in sorted((run_dir / "cases").glob("*/case.json")):
        case = _read_json(case_path)
        result_path = run_dir / "results" / str(case["name"]) / "result.json"
        result = _read_json(result_path)
        classifications.append(classify_scenario(case, result))
    shared56 = aggregate_shared56(classifications)
    shared56["classifications"] = classifications
    _write_json(run_dir / "coverage" / "shared56.json", shared56)
    return shared56


def summarize_campaign(plan: list[dict[str, Any]], out_dir: Path) -> dict[str, Any]:
    summary: dict[str, Any] = {"universe": "v4-nonpmp-56", "modes": {}}
    for mode in ("guided", "random"):
        covered: set[str] = set()
        rounds = []
        for item in [entry for entry in plan if entry["mode"] == mode]:
            shared56 = item.get("shared56")
            if not shared56:
                continue
            covered.update(shared56.get("covered_bins") or [])
            rounds.append(
                {
                    "round_id": item["round_id"],
                    "covered_count": len(covered),
                    "covered_bins": sorted(covered),
                    "round_shared56": shared56,
                }
            )
        summary["modes"][mode] = {"rounds": rounds}
    _write_json(Path(out_dir) / "m2-shared56-summary.json", summary)
    return summary


def _write_run_plan(out_dir: Path, plan: list[dict[str, Any]]) -> None:
    _write_json(Path(out_dir) / "run-plan.json", plan)


def _sh_quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare or run the C910 M-2 pre-registered campaign.")
    parser.add_argument("--m2-root", type=Path, default=DEFAULT_M2_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--build-remote", action="store_true")
    parser.add_argument("--upload-sidecars", action="store_true")
    parser.add_argument("--run-board", action="store_true")
    parser.add_argument("--analyze", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--remote-host", default=DEFAULT_REMOTE_HOST)
    parser.add_argument("--remote-root", default=DEFAULT_REMOTE_ROOT)
    parser.add_argument("--remote-tree", default=DEFAULT_REMOTE_TREE)
    parser.add_argument("--security-probe", type=Path, default=DEFAULT_SECURITY_PROBE)
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

    plan = build_round_plan(m2_root=args.m2_root, out_dir=args.out_dir)
    plan = materialize_round_sources(plan)
    for item in plan:
        if args.build_remote:
            build_remote_round(
                item,
                remote_host=args.remote_host,
                remote_root=args.remote_root,
                remote_tree=args.remote_tree,
                security_probe=args.security_probe,
                jobs=args.jobs,
                dry_run=args.dry_run,
            )
        if args.upload_sidecars:
            upload_sidecar(
                item,
                upload_script=args.upload_script,
                port=args.port,
                baud=args.baud,
                login_user=args.login_user,
                login_password=args.login_password,
                timeout_seconds=args.timeout_seconds,
                dry_run=args.dry_run,
            )
        if args.run_board:
            if args.serial_script is None:
                raise ValueError("--serial-script is required with --run-board")
            run_board_round(
                item,
                serial_script=args.serial_script,
                port=args.port,
                baud=args.baud,
                timeout_seconds=args.timeout_seconds,
                login_user=args.login_user,
                login_password=args.login_password,
                dry_run=args.dry_run,
            )
        if args.analyze:
            analyze_round(item)
    if args.analyze:
        summarize_campaign(plan, args.out_dir)
    _write_run_plan(args.out_dir, plan)
    print(f"rounds={len(plan)} plan={args.out_dir / 'run-plan.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
