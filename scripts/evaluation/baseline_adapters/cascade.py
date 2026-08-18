#!/usr/bin/env python3
"""Cascade baseline adapter.

Uses the existing ``codex_cascade_cpu_fuzzing`` Docker container and keeps the
original Phase E engineering contracts intact while adding optional HPM
coverage instrumentation and continuous multi-batch execution.
"""

from __future__ import annotations

import sys
from pathlib import Path as _Path
# Ensure repository-local imports work when the adapter is executed directly.
_script_root = _Path(__file__).resolve().parents[3]
if str(_script_root) not in sys.path:
    sys.path.insert(0, str(_script_root))

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pmpfuzz.bapc import (
    BAPC_SCHEMA_VERSION,
    build_bapc_coverage_universe,
    normalize_bapc_core_version,
    runtime_bapc_event_records_for_cascade_execution,
    summarize_bapc_for_cascade_execution,
)
from pmpfuzz.cascade_runtime import (
    CASCADE_TARGET_OPERATION_SCHEMA_VERSION,
    collect_cascade_runtime_attribution,
    summarize_cascade_runtime_measurement,
)
from pmpfuzz.capabilities import capability_for_dut
from pmpfuzz.coverage_universe import classify_observed_bins, coverage_universe_filename
from pmpfuzz.diagnostics import mtval_fingerprint
from pmpfuzz.dut import DEFAULT_CLEAN_CHIPYARD_DIR, parse_chipyard_log, parse_xiangshan_log
from pmpfuzz.experiment_protocols import (
    BAPC_CONVERGENCE_FORMAL,
    BAPC_FORMAL_SEEDS,
    BAPC_FORMAL_VARIANTS,
    build_bapc_convergence_contract,
    expected_bapc_formal_run_class,
    is_bapc_formal_campaign,
    is_bapc_convergence_protocol,
    is_bapc_formal_request,
    typed_int_matches,
    typed_numeric_matches,
)
from pmpfuzz.hpm import (
    build_hpm_coverage_universe,
    parse_hpm_uart_snapshots,
    summarize_hpm_coverage,
)
from pmpfuzz.stop_reasons import STOP_COVERAGE_CONVERGED, STOP_HARD_CAP_CENSORED
from pmpfuzz.xiangshan_emu_diag import xiangshan_diag_env_for_image
from scripts.evaluation.validation.validate_timeline import validate_timeline


SUPPORTED_DUTS = (
    "rocket-clean",
    "boom-clean",
    "xiangshan-clean",
    "cva6-clean",
)

_WORKSPACE_ROOT = Path(
    os.environ.get("PMPFUZZ_WORKSPACE", str(Path.home() / "pmpfuzz-workspace"))
).expanduser()
CASCADE_MOUNT_DIR = Path(
    os.environ.get("CASCADE_MOUNT_DIR", str(_WORKSPACE_ROOT / "cascade" / "mount"))
).expanduser()
CASCADE_CONTAINER = "codex_cascade_cpu_fuzzing"
CASCADE_IMAGE_SHA = "sha256:3d403b05be4a57fc1910b7e73bc807d499e382f73197ae8978ca1954524f0a11"
SECURITY_EVENT_TIMESERIES_DIGEST_SCHEMA_VERSION = "security-event-timeseries-sha256-v1"

_DESIGN_MAP = {
    "rocket-clean": "rocket",
    "boom-clean": "boom",
    "cva6-clean": "cva6",
    "xiangshan-clean": "xiangshan",
}

_CHIPYARD_SIM_DIR = Path(
    os.environ.get(
        "CHIPYARD_SIM_DIR",
        str(_WORKSPACE_ROOT / "chipyard" / "sims" / "verilator"),
    )
).expanduser()
_SIM_BINARIES = {
    "rocket-clean": os.environ.get(
        "PMPFUZZ_ROCKET_SIM",
        str(_CHIPYARD_SIM_DIR / "simulator-chipyard.harness-RocketConfig"),
    ),
    "boom-clean": os.environ.get(
        "PMPFUZZ_BOOM_SIM",
        str(_CHIPYARD_SIM_DIR / "simulator-chipyard.harness-SmallBoomV3Config"),
    ),
    "cva6-clean": os.environ.get(
        "PMPFUZZ_CVA6_SIM",
        str(_CHIPYARD_SIM_DIR / "simulator-chipyard.harness-CVA6Config"),
    ),
    "xiangshan-clean": os.environ.get(
        "PMPFUZZ_XIANGSHAN_SIM",
        str(_WORKSPACE_ROOT / "xiangshan" / "build" / "verilator-compile" / "emu"),
    ),
}

PROBE_RE = re.compile(r"PMFUZZ_PROBE\s+(.*)")
_HELPER_PATH = Path(__file__).resolve().parent / "cascade_generate_campaign.py"
_XIANGSHAN_CASCADE_META_ROOT = "/cascade-mountdir/cascade_xiangshan_adapt/cascade-meta"
_HOST_SUBPROCESS_RUN = subprocess.run
CASCADE_STAGE_TIMEOUT_SECONDS = 600
CASCADE_GENERATOR_TIMEOUT_SECONDS = 600
CASCADE_COPYBACK_TIMEOUT_SECONDS = 600
CASCADE_RETRYABLE_SPIKE_TIMEOUT_RETRIES = 2


def _is_retryable_cascade_generation_failure(stderr_text: str) -> bool:
    return "Spike timeout" in str(stderr_text or "")


def _string_matches_canonical(value: object, expected: str) -> bool:
    return str(value or "") == str(expected)


def _enforce_or_fill_protocol_value(
    current: object,
    *,
    field: str,
    expected: int | float | str,
    matches,
) -> int | float | str:
    if current is None:
        return expected
    if not matches(current, expected):
        raise ValueError(
            f"formal BAPC protocol requires {field}={expected!r}, got {current!r}"
        )
    return current


def _posix_arg(path: Path) -> str:
    return path.as_posix()


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _git_head_sha(cwd: Path | None = None) -> str | None:
    try:
        result = _HOST_SUBPROCESS_RUN(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(cwd or _project_root()),
        )
    except Exception:
        return None
    if result.returncode == 0:
        return result.stdout.strip()
    return None


def _git_text(cwd: Path, *args: str) -> str | None:
    try:
        result = _HOST_SUBPROCESS_RUN(
            ["git", *args],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(cwd),
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def _source_tree_sha256(root: Path) -> str | None:
    raw = _git_text(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    paths: list[str] = []
    if raw is not None:
        paths = [item for item in raw.split("\0") if item]
    else:
        for path in sorted(root.rglob("*")):
            if ".git" in path.parts or not path.is_file():
                continue
            paths.append(str(path.relative_to(root)).replace("\\", "/"))
    hasher = hashlib.sha256()
    for rel in paths:
        path = root / rel
        if not path.is_file():
            continue
        hasher.update(rel.replace("\\", "/").encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    if not paths:
        return None
    return hasher.hexdigest()


def _git_is_dirty(root: Path) -> bool:
    status = _git_text(root, "status", "--porcelain=v1", "--untracked-files=all")
    return bool(status and status.strip())


def _resolve_artifact_root_for_campaign(out_dir: Path) -> Path | None:
    parts = list(out_dir.resolve().parts)
    if "campaigns" in parts:
        index = parts.index("campaigns")
        if index > 0:
            return Path(*parts[:index])
    p = out_dir.resolve()
    for _ in range(12):
        if (p / "manifests").is_dir():
            return p
        if p.parent == p:
            break
        p = p.parent
    return None


def _sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _update_artifact_sha_manifest(artifact_root: Path, rel_paths: list[Path]) -> None:
    manifests_dir = artifact_root / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    lines: dict[str, str] = {}
    manifest_path = manifests_dir / "artifact-sha256.txt"
    if manifest_path.exists():
        for raw in manifest_path.read_text(encoding="ascii").splitlines():
            if "  " not in raw:
                continue
            digest, rel = raw.split("  ", 1)
            rel = rel.strip()
            if rel:
                lines[rel] = digest.strip()
    for rel_path in rel_paths:
        rel = rel_path.as_posix()
        target = artifact_root / rel_path
        if not target.exists() or not target.is_file():
            continue
        lines[rel] = _sha256_file(target)
    payload = "\n".join(f"{digest}  {rel}" for rel, digest in sorted(lines.items()))
    manifest_path.write_text((payload + "\n") if payload else "", encoding="ascii")


def _update_experiment_contract_manifest(
    *,
    artifact_root: Path | None,
    dut: str,
    variant_label: str,
    seed: int,
    coverage_mode: str,
    experiment_protocol_id: str,
    universe: dict[str, Any] | None,
    source_provenance: dict[str, Any] | None = None,
    dut_provenance: dict[str, Any] | None = None,
) -> None:
    if artifact_root is None or coverage_mode != "bapc" or not is_bapc_convergence_protocol(experiment_protocol_id):
        return
    if not isinstance(universe, dict):
        return
    manifests_dir = artifact_root / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    contract_path = manifests_dir / "experiment-contract.json"
    contract = build_bapc_convergence_contract(
        dut=dut,
        bin_count=int(universe.get("bin_count") or 0),
        bin_set_sha256=str(universe.get("bin_set_sha256") or ""),
        variants=BAPC_FORMAL_VARIANTS,
        seeds=BAPC_FORMAL_SEEDS,
        source_sha=str((source_provenance or {}).get("source_sha") or ""),
        source_tree_sha256=str((source_provenance or {}).get("source_tree_sha256") or ""),
        dut_sha=str((dut_provenance or {}).get("dut_sha") or ""),
        dut_binary_sha256=str((dut_provenance or {}).get("dut_binary_sha256") or ""),
    )
    if contract_path.exists():
        try:
            existing = json.loads(contract_path.read_text(encoding="ascii"))
        except Exception as exc:
            raise ValueError(f"experiment-contract.json unreadable: {exc}") from exc
        if existing != contract:
            raise ValueError("experiment-contract.json does not match formal BAPC protocol contract")
        return
    contract_path.write_text(
        json.dumps(contract, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )


def _cascade_source_provenance() -> dict[str, Any]:
    project_root = _project_root()
    source_sha = str(_git_head_sha(project_root) or "")
    return {
        "source_sha": source_sha,
        "source_sha_status": "git-head" if source_sha else "",
        "source_tree_sha256": str(_source_tree_sha256(project_root) or ""),
        "source_dirty": _git_is_dirty(project_root),
    }


def _cascade_dut_provenance(
    *,
    dut: str,
    dut_binary_path: Path,
    dut_source_dir: Path | None = None,
) -> dict[str, Any]:
    dut_sha = ""
    dut_sha_status = ""
    dut_sha_reason = ""
    resolved_dut_source_dir = dut_source_dir.resolve() if dut_source_dir is not None else None
    if resolved_dut_source_dir is not None:
        dut_sha = str(_git_head_sha(resolved_dut_source_dir) or "")
        if dut_sha:
            dut_sha_status = "git-head"
    elif dut in {"rocket-clean", "boom-clean", "cva6-clean"}:
        chipyard_dir = Path(DEFAULT_CLEAN_CHIPYARD_DIR)
        dut_sha = str(_git_head_sha(chipyard_dir) or "")
        if dut_sha:
            dut_sha_status = "git-head"
    elif dut == "xiangshan-clean":
        xiangshan_root = Path(_SIM_BINARIES["xiangshan-clean"]).resolve().parents[2]
        dut_sha = str(_git_head_sha(xiangshan_root) or "")
        if dut_sha:
            dut_sha_status = "git-head"
    if not dut_sha:
        dut_sha_status = "not-applicable"
        dut_sha_reason = "dut source repository unavailable"
    dut_binary_sha256 = ""
    dut_binary_error: str | None = None
    try:
        if dut_binary_path.exists() and dut_binary_path.is_file():
            dut_binary_sha256 = hashlib.sha256(dut_binary_path.read_bytes()).hexdigest()
        else:
            dut_binary_error = "binary_not_found_or_unreadable"
    except OSError as exc:
        dut_binary_error = f"unreadable: {exc}"
    return {
        "dut_sha": dut_sha,
        "dut_sha_status": dut_sha_status,
        "dut_sha_reason": dut_sha_reason,
        "dut_source_dir": str(resolved_dut_source_dir) if resolved_dut_source_dir is not None else "",
        "dut_source_tree_sha256": (
            str(_source_tree_sha256(resolved_dut_source_dir) or "")
            if resolved_dut_source_dir is not None
            else ""
        ),
        "dut_binary_path": str(dut_binary_path.resolve()),
        "dut_binary_sha256": dut_binary_sha256,
        "_dut_binary_error": dut_binary_error,
    }


def _generator_pythonpath(design: str) -> str:
    if design == "xiangshan":
        return f"{_XIANGSHAN_CASCADE_META_ROOT}/fuzzer"
    return "/cascade-meta/fuzzer"


def _generator_design_processing_root(design: str) -> str | None:
    if design == "xiangshan":
        return f"{_XIANGSHAN_CASCADE_META_ROOT}/design-processing"
    return None


def _generation_workspace(out_dir: Path, seed: int, *, design: str = "") -> Path:
    canonical = str(out_dir.resolve())
    campaign_key = f"{canonical}__design-{design}__seed-{seed:04d}"
    stable_id = hashlib.sha256(campaign_key.encode("ascii")).hexdigest()[:16]
    return CASCADE_MOUNT_DIR / "cascade-campaigns" / f"{stable_id}"


def _generate_elfs(
    num_elfs: int,
    out_dir: Path,
    *,
    seed: int,
    design: str,
    hpm_manifest_path: Path | None = None,
    start_index: int = 0,
    require_single_target_operation: bool = False,
    require_target_operation_candidate: bool = False,
) -> dict[str, Any]:
    import shutil

    allowed_designs = set(_DESIGN_MAP.values())
    if design not in allowed_designs:
        raise ValueError(
            f"unsupported design: {design!r}; allowed: {sorted(allowed_designs)}"
        )

    start = time.monotonic()
    workspace = _generation_workspace(out_dir, seed, design=design)
    workspace.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    helper_dest = workspace / "cascade_generate_campaign.py"
    shutil.copy2(str(_HELPER_PATH), str(helper_dest))
    helper_sha256 = hashlib.sha256(helper_dest.read_bytes()).hexdigest()

    copied_hpm_manifest = None
    if hpm_manifest_path is not None:
        copied_hpm_manifest = workspace / "hpm_manifest.json"
        shutil.copy2(str(hpm_manifest_path), str(copied_hpm_manifest))

    container_ws = f"/cascade-mountdir/cascade-campaigns/{workspace.name}"
    container_stage_dir = f"/tmp/pmpfuzz-cascade-{workspace.name}"
    container_helper = f"{container_stage_dir}/cascade_generate_campaign.py"
    output_dir_name = f"elfs-{start_index:08d}"
    batch_dir = workspace / output_dir_name
    container_output = f"{container_stage_dir}/{output_dir_name}"
    container_hpm_manifest = (
        f"{container_stage_dir}/hpm_manifest.json" if copied_hpm_manifest is not None else None
    )
    hpm_manifest_arg = (
        f" --hpm-manifest {shlex.quote(container_hpm_manifest)}"
        if container_hpm_manifest is not None
        else ""
    )
    target_operation_arg = (
        " --require-single-target-operation"
        if require_single_target_operation
        else (
            " --require-target-operation-candidate"
            if require_target_operation_candidate
            else ""
        )
    )
    generator_pythonpath = _generator_pythonpath(design)
    design_processing_root = _generator_design_processing_root(design)
    design_processing_export = (
        f"export CASCADE_DESIGN_PROCESSING_ROOT={shlex.quote(design_processing_root)} && "
        if design_processing_root is not None
        else ""
    )

    shutil.rmtree(batch_dir, ignore_errors=True)
    staging_error = ""
    staging_returncode = 0
    stage_commands = [
        [
            "docker",
            "exec",
            CASCADE_CONTAINER,
            "bash",
            "-c",
            f"mkdir -p {shlex.quote(container_stage_dir)} && "
            f"rm -rf {shlex.quote(container_output)} && "
            f"mkdir -p {shlex.quote(container_output)}",
        ],
        [
            "docker",
            "cp",
            str(helper_dest),
            f"{CASCADE_CONTAINER}:{container_helper}",
        ],
    ]
    if copied_hpm_manifest is not None and container_hpm_manifest is not None:
        stage_commands.append(
            [
                "docker",
                "cp",
                str(copied_hpm_manifest),
                f"{CASCADE_CONTAINER}:{container_hpm_manifest}",
            ]
        )

    proc = None
    generator_error = ""
    generator_returncode = 0
    copy_back_error = ""
    copy_back_returncode = 0
    generator_cmd = [
        "docker",
        "exec",
        CASCADE_CONTAINER,
        "bash",
        "-c",
        f"source /cascade-meta/env.sh && "
        f"{design_processing_export}"
        f"export PYTHONPATH={shlex.quote(generator_pythonpath)} && "
        f"python3 {shlex.quote(container_helper)} "
        f"--design {design} "
        f"--seed {seed} "
        f"--count {num_elfs} "
        f"--output {shlex.quote(container_output)} "
        f"--start-index {start_index}"
        f"{hpm_manifest_arg}"
        f"{target_operation_arg}",
    ]
    max_attempts = CASCADE_RETRYABLE_SPIKE_TIMEOUT_RETRIES + 1
    for attempt_index in range(max_attempts):
        shutil.rmtree(batch_dir, ignore_errors=True)
        staging_error = ""
        staging_returncode = 0
        proc = None
        generator_error = ""
        generator_returncode = 0
        copy_back_error = ""
        copy_back_returncode = 0
        try:
            for stage_cmd in stage_commands:
                stage_proc = subprocess.run(
                    stage_cmd,
                    capture_output=True,
                    text=True,
                    timeout=CASCADE_STAGE_TIMEOUT_SECONDS,
                    check=False,
                )
                if stage_proc.returncode != 0:
                    staging_returncode = stage_proc.returncode
                    staging_error = stage_proc.stderr[-500:] if stage_proc.stderr else (
                        "container staging failed: " + " ".join(stage_cmd[:3])
                    )
                    break
        except subprocess.TimeoutExpired as exc:
            staging_returncode = 124
            staging_error = f"container staging failed: {exc}"

        if not staging_error:
            try:
                proc = subprocess.run(
                    generator_cmd,
                    capture_output=True,
                    text=True,
                    timeout=CASCADE_GENERATOR_TIMEOUT_SECONDS,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                generator_returncode = 124
                generator_error = f"helper generation timed out: {exc}"

        if not staging_error and not generator_error and proc is not None and proc.returncode == 0:
            batch_dir.mkdir(parents=True, exist_ok=True)
            try:
                copy_back_proc = subprocess.run(
                    [
                        "docker",
                        "cp",
                        f"{CASCADE_CONTAINER}:{container_output}/.",
                        str(batch_dir),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=CASCADE_COPYBACK_TIMEOUT_SECONDS,
                    check=False,
                )
                if copy_back_proc.returncode != 0:
                    copy_back_returncode = copy_back_proc.returncode
                    copy_back_error = copy_back_proc.stderr[-500:] if copy_back_proc.stderr else "container output copy-back failed"
            except subprocess.TimeoutExpired as exc:
                copy_back_returncode = 124
                copy_back_error = f"container output copy-back failed: {exc}"

        retryable_helper_failure = (
            not staging_error
            and not generator_error
            and proc is not None
            and proc.returncode != 0
            and _is_retryable_cascade_generation_failure(proc.stderr)
        )
        if not retryable_helper_failure or attempt_index + 1 >= max_attempts:
            break
    expected_elf_names = {f"{design}_{start_index + i}.elf" for i in range(num_elfs)}
    expected_sidecar_names = {f"{design}_{start_index + i}.json" for i in range(num_elfs)}
    actual_elf_names = (
        {f.name for f in batch_dir.glob(f"{design}_*.elf")}
        if batch_dir.exists()
        else set()
    )
    actual_sidecar_names = (
        {f.name for f in batch_dir.glob(f"{design}_*.json")}
        if batch_dir.exists()
        else set()
    )
    exact_file_set_ok = (
        actual_elf_names == expected_elf_names
        and actual_sidecar_names == expected_sidecar_names
    )

    if batch_dir.exists():
        for item in batch_dir.iterdir():
            if item.is_file():
                shutil.copy2(str(item), str(out_dir / item.name))

    elapsed = time.monotonic() - start

    elf_hashes: dict[str, str] = {}
    for elf_path in out_dir.glob(f"{design}_*.elf"):
        try:
            elf_hashes[elf_path.name] = hashlib.sha256(
                elf_path.read_bytes()
            ).hexdigest()
        except OSError:
            elf_hashes[elf_path.name] = ""

    per_case: list[dict[str, Any]] = []
    for i in range(num_elfs):
        global_case_index = start_index + i
        elf_name = f"{design}_{global_case_index}.elf"
        sidecar_name = f"{design}_{global_case_index}.json"
        sidecar_path = out_dir / sidecar_name
        sidecar_data = None
        if sidecar_path.exists():
            try:
                sidecar_data = json.loads(sidecar_path.read_text(encoding="ascii"))
            except (OSError, json.JSONDecodeError):
                pass
        per_case.append(
            {
                "case_index": global_case_index,
                "elf": elf_name,
                "elf_sha256": elf_hashes.get(elf_name, ""),
                "sidecar": sidecar_name,
                "sidecar_data": sidecar_data,
            }
        )

    proc_returncode = proc.returncode if proc is not None else (generator_returncode or staging_returncode)
    stderr_parts = [staging_error, generator_error]
    if proc is not None and proc.stderr:
        stderr_parts.append(proc.stderr[-500:])
    if copy_back_error:
        stderr_parts.append(copy_back_error)
    stderr_tail = " | ".join(part for part in stderr_parts if part)
    if len(stderr_tail) > 500:
        stderr_tail = stderr_tail[-500:]

    return {
        "success": (
            not staging_error
            and not generator_error
            and proc is not None
            and proc.returncode == 0
            and not copy_back_error
            and exact_file_set_ok
        ),
        "returncode": copy_back_returncode or proc_returncode,
        "elapsed_seconds": elapsed,
        "stderr": stderr_tail,
        "workspace": str(workspace),
        "design": design,
        "campaign_seed": seed,
        "start_index": start_index,
        "helper_sha256": helper_sha256,
        "helper_relative_path": "cascade_generate_campaign.py",
        "hpm_manifest_relative_path": "hpm_manifest.json" if copied_hpm_manifest is not None else None,
        "expected_count": num_elfs,
        "generated_elf_count": len(actual_elf_names),
        "generated_sidecar_count": len(actual_sidecar_names),
        "elf_hashes": elf_hashes,
        "per_case": per_case,
    }


def _simulator_command(
    dut: str,
    elf: Path,
    simlen: int,
    *,
    dut_binary: Path | None = None,
) -> tuple[list[str], dict]:
    if dut not in SUPPORTED_DUTS:
        raise ValueError(f"unsupported DUT: {dut}")

    binary = _posix_arg(dut_binary) if dut_binary is not None else _SIM_BINARIES.get(dut, "")
    env = os.environ.copy()
    if dut == "xiangshan-clean":
        env.update(xiangshan_diag_env_for_image(elf))
        cmd = [binary, "--no-diff", "-C", str(simlen), "-i", str(elf)]
    else:
        dramsim_ini = (
            DEFAULT_CLEAN_CHIPYARD_DIR
            / "generators"
            / "testchipip"
            / "src"
            / "main"
            / "resources"
            / "dramsim2_ini"
        )
        cmd = [
            binary,
            "+permissive",
            "+verbose",
            "+dramsim",
            f"+dramsim_ini_dir={_posix_arg(dramsim_ini)}",
            f"+max-cycles={simlen}",
            f"+loadmem={_posix_arg(elf)}",
            "+permissive-off",
            _posix_arg(elf),
        ]
    return cmd, env


def _merge_log_streams(stdout: str, stderr: str) -> str:
    if stdout and stderr:
        return stdout + ("" if stdout.endswith("\n") else "\n") + stderr
    return stdout or stderr or ""


def _extract_probe_events(log_text: str) -> list[dict[str, Any]]:
    events = []
    for line in log_text.split("\n"):
        match = PROBE_RE.search(line)
        if not match:
            continue
        fields = {}
        for pair in match.group(1).split():
            if "=" not in pair:
                continue
            key, value = pair.split("=", 1)
            fields[key] = value
        events.append(
            {
                "kind": "source_probe",
                "chain": fields.get("chain", ""),
                "stage": fields.get("stage", ""),
                "fields": fields,
            }
        )
    return events


def _make_event_id(dut: str, chain: str, stage: str, privilege: str) -> str:
    key = f"source_probe|{dut}|{chain}|{stage}|{privilege}"
    return hashlib.sha256(key.encode("ascii")).hexdigest()[:16]


def _parse_int_like(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None


def _mcause_access(value: Any) -> str | None:
    return {
        1: "fetch",
        5: "load",
        7: "store",
        12: "fetch",
        13: "load",
        15: "store",
    }.get(_parse_int_like(value))


_CASCADE_MEM_BASE = 0x80000000


def _candidate_observed_addresses(candidate: dict[str, Any]) -> set[int]:
    address = _parse_int_like(candidate.get("physical_address"))
    if address is None:
        return set()
    addresses = {address}
    instruction = _parse_int_like(candidate.get("instruction_address"))
    if address < _CASCADE_MEM_BASE and instruction is not None and instruction >= _CASCADE_MEM_BASE:
        addresses.add(_CASCADE_MEM_BASE + address)
    return addresses


def _resolve_target_operation_sidecar(
    sidecar: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any] | None:
    if not isinstance(sidecar, dict):
        return None

    resolved = dict(sidecar)
    if (
        resolved.get("privilege") is not None
        and resolved.get("access") is not None
        and resolved.get("physical_address") is not None
    ):
        return resolved

    candidates = [
        dict(item)
        for item in (sidecar.get("target_operation_candidates") or [])
        if isinstance(item, dict)
    ]
    if not candidates:
        return None

    narrowed = list(candidates)
    if len(narrowed) > 1:
        if str(result.get("observed_event") or "").strip().lower() != "trap":
            return None

        access = _mcause_access(result.get("observed_mcause"))
        if access is not None:
            matched = [
                item
                for item in narrowed
                if str(item.get("access") or "").strip().lower() == access
            ]
            if matched:
                narrowed = matched

        observed_address = _parse_int_like(result.get("observed_fault_address"))
        if observed_address is not None and len(narrowed) > 1:
            matched = [
                item
                for item in narrowed
                if observed_address in _candidate_observed_addresses(item)
            ]
            if matched:
                narrowed = matched

        observed_mtval_fp = _parse_int_like(result.get("observed_mtval_fingerprint"))
        if observed_mtval_fp is not None and len(narrowed) > 1:
            matched = []
            for item in narrowed:
                for candidate_address in _candidate_observed_addresses(item):
                    if mtval_fingerprint(candidate_address) == observed_mtval_fp:
                        matched.append(item)
                        break
            if matched:
                narrowed = matched

        observed_mepc_tag = _parse_int_like(result.get("observed_mepc_tag"))
        if observed_mepc_tag is not None and len(narrowed) > 1:
            matched = [
                item
                for item in narrowed
                if _parse_int_like(item.get("instruction_page_tag")) == observed_mepc_tag
            ]
            if matched:
                narrowed = matched

    if len(narrowed) != 1:
        return None

    chosen = narrowed[0]
    for key in (
        "target_operation_id",
        "privilege",
        "access",
        "size",
        "physical_address",
        "instruction_address",
        "instruction_page_tag",
    ):
        if chosen.get(key) is not None:
            resolved[key] = chosen[key]
    return resolved


def _normalize_coverage_mode(
    coverage_mode: str | None,
    *,
    hpm_manifest: dict[str, Any] | None,
) -> str | None:
    normalized = str(coverage_mode or "").strip().lower()
    if not normalized:
        return "hpm" if hpm_manifest is not None else None
    if normalized not in {"hpm", "bapc"}:
        raise ValueError(
            f"unsupported cascade coverage_mode {coverage_mode!r}; expected one of ['bapc', 'hpm']"
        )
    if normalized == "hpm" and hpm_manifest is None:
        raise ValueError("coverage_mode='hpm' requires hpm_manifest")
    return normalized


def _bapc_actual_result_from_log(
    *,
    dut: str,
    log_text: str,
    returncode: int | None,
) -> dict[str, Any]:
    if dut == "xiangshan-clean":
        parsed = parse_xiangshan_log(log_text, returncode or 0)
    else:
        parsed = parse_chipyard_log(log_text, returncode or 0)
    observed_event = None
    observation_valid = False
    if parsed.observation is not None:
        observed_event = parsed.observation.kind.name.lower()
        observation_valid = True
    elif dut != "xiangshan-clean" and parsed.status == "pass":
        observed_event = "completion"
        observation_valid = True
    elif dut != "xiangshan-clean" and parsed.status == "fail":
        observed_event = "trap"
        observation_valid = True
    return {
        "status": parsed.status,
        "observation_valid": observation_valid,
        "observed_event": observed_event,
        "observed_mcause": parsed.observed_mcause,
        "observed_stage": parsed.observed_stage,
        "observed_fault_address": parsed.observed_fault_address,
        "observed_mepc_tag": (
            parsed.observation.mepc_tag if parsed.observation is not None else None
        ),
        "observed_mtval_fingerprint": (
            parsed.observation.mtval_fingerprint if parsed.observation is not None else None
        ),
    }


def _load_sidecar_data(
    *,
    gen_result: dict[str, Any],
    elfs_dir: Path,
    design: str,
    case_index: int,
) -> dict[str, Any] | None:
    per_case = gen_result.get("per_case") or []
    for item in per_case:
        if not isinstance(item, dict):
            continue
        if int(item.get("case_index") or -1) != int(case_index):
            continue
        payload = item.get("sidecar_data")
        if isinstance(payload, dict):
            return payload
    sidecar_path = elfs_dir / f"{design}_{case_index}.json"
    if not sidecar_path.exists():
        return None
    try:
        return json.loads(sidecar_path.read_text(encoding="ascii"))
    except (OSError, json.JSONDecodeError):
        return None


def _build_security_event_timeseries(
    timeline: list[dict[str, Any]],
    *,
    dut: str,
    campaign_id: str,
    seed: int,
) -> list[dict[str, Any]]:
    rows = []
    event_set: set[str] = set()
    for entry in timeline:
        case_id = entry.get("case_id", "")
        completion_seq = entry.get("completion_seq", 0)
        elapsed_wall_seconds = entry.get("elapsed_wall_seconds", 0)
        for event_index, event in enumerate(entry.get("probe_events", []), start=1):
            chain = event.get("chain", "")
            stage = event.get("stage", "")
            privilege = event.get("fields", {}).get("prv", "")
            event_id = _make_event_id(dut, chain, stage, privilege)
            is_new_event = event_id not in event_set
            if is_new_event:
                event_set.add(event_id)
            rows.append(
                {
                    "schema_version": "1.0",
                    "experiment_id": "cascade-baseline",
                    "campaign_id": campaign_id,
                    "method": "cascade",
                    "variant": "cascade",
                    "dut": dut,
                    "seed": seed,
                    "completion_seq": completion_seq,
                    "event_index": event_index,
                    "elapsed_wall_seconds": elapsed_wall_seconds,
                    "event_namespace": "source_probe",
                    "event_category": chain,
                    "event_id": event_id,
                    "is_new_event": is_new_event,
                    "total_distinct_events": len(event_set),
                    "case_id": case_id,
                }
            )
    return rows



def _security_event_rows_for_case(
    probe_events: list[dict[str, Any]],
    *,
    dut: str,
    campaign_id: str,
    seed: int,
    completion_seq: int,
    case_id: str,
    elapsed_wall_seconds: float,
    event_set: set[str],
) -> list[dict[str, Any]]:
    rows = []
    for event_index, event in enumerate(probe_events, start=1):
        chain = event.get("chain", "")
        stage = event.get("stage", "")
        privilege = event.get("fields", {}).get("prv", "")
        event_id = _make_event_id(dut, chain, stage, privilege)
        is_new_event = event_id not in event_set
        if is_new_event:
            event_set.add(event_id)
        rows.append(
            {
                "schema_version": "1.0",
                "experiment_id": "cascade-baseline",
                "campaign_id": campaign_id,
                "method": "cascade",
                "variant": "cascade",
                "dut": dut,
                "seed": seed,
                "completion_seq": completion_seq,
                "event_index": event_index,
                "elapsed_wall_seconds": elapsed_wall_seconds,
                "event_namespace": "source_probe",
                "event_category": chain,
                "event_id": event_id,
                "is_new_event": is_new_event,
                "total_distinct_events": len(event_set),
                "case_id": case_id,
            }
        )
    return rows


def _hpm_baseline_timeline_line(
    *,
    campaign_id: str,
    dut: str,
    seed: int,
    target_bins: int,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "variant": "cascade",
        "dut": dut,
        "seed": seed,
        "completion_seq": 0,
        "case_id": None,
        "profile": None,
        "elapsed_wall_seconds": 0.0,
        "case_elapsed_seconds": 0.0,
        "completed_cases": 0,
        "eligible_cases": 0,
        "eligible_hpm_cases": 0,
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
        "hpm_covered": 0,
        "hpm_target": target_bins,
        "hpm_rate": 0.0 if target_bins > 0 else None,
        "new_semantic_bins": 0,
        "new_pairwise_bins": 0,
        "new_security_triple_bins": 0,
        "new_predicate_bins": 0,
        "new_hpm_bins": 0,
        "hpm_eligible": False,
        "last_hpm_novelty_time": 0.0,
        "whitebox_distinct_events": 0,
        "new_whitebox_events": 0,
    }


def _hpm_timeline_line(
    *,
    campaign_id: str,
    dut: str,
    seed: int,
    completion_seq: int,
    case_id: str,
    elapsed_wall_seconds: float,
    case_elapsed_seconds: float,
    completed_cases: int,
    eligible_cases: int,
    eligible_hpm_cases: int,
    status: str,
    coverage_eligible: bool,
    qualification_reason: str,
    hpm_covered: int,
    hpm_target: int,
    new_hpm_bins: int,
    last_hpm_novelty_time: float,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "variant": "cascade",
        "dut": dut,
        "seed": seed,
        "completion_seq": completion_seq,
        "case_id": case_id,
        "profile": "cascade-baseline",
        "elapsed_wall_seconds": float(elapsed_wall_seconds),
        "case_elapsed_seconds": float(case_elapsed_seconds),
        "completed_cases": completed_cases,
        "eligible_cases": eligible_cases,
        "eligible_hpm_cases": eligible_hpm_cases,
        "status": status,
        "failure_class": None,
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
        "hpm_covered": hpm_covered,
        "hpm_target": hpm_target,
        "hpm_rate": (hpm_covered / hpm_target) if hpm_target > 0 else None,
        "new_semantic_bins": 0,
        "new_pairwise_bins": 0,
        "new_security_triple_bins": 0,
        "new_predicate_bins": 0,
        "new_hpm_bins": new_hpm_bins,
        "hpm_eligible": bool(coverage_eligible),
        "last_hpm_novelty_time": float(last_hpm_novelty_time),
        "whitebox_distinct_events": 0,
        "new_whitebox_events": 0,
    }


def _bapc_baseline_timeline_line(
    *,
    campaign_id: str,
    dut: str,
    seed: int,
    target_bins: int,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "variant": "cascade",
        "dut": dut,
        "seed": seed,
        "completion_seq": 0,
        "case_id": None,
        "profile": None,
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
        "bapc_target": target_bins,
        "bapc_rate": 0.0 if target_bins > 0 else None,
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


def _bapc_timeline_line(
    *,
    campaign_id: str,
    dut: str,
    seed: int,
    completion_seq: int,
    case_id: str,
    elapsed_wall_seconds: float,
    case_elapsed_seconds: float,
    completed_cases: int,
    eligible_cases: int,
    eligible_bapc_cases: int,
    status: str,
    coverage_eligible: bool,
    qualification_reason: str,
    bapc_covered: int,
    bapc_target: int,
    new_bapc_bins: int,
    last_bapc_novelty_time: float,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "variant": "cascade",
        "dut": dut,
        "seed": seed,
        "completion_seq": completion_seq,
        "case_id": case_id,
        "profile": "cascade-baseline",
        "elapsed_wall_seconds": float(elapsed_wall_seconds),
        "case_elapsed_seconds": float(case_elapsed_seconds),
        "completed_cases": completed_cases,
        "eligible_cases": eligible_cases,
        "eligible_bapc_cases": eligible_bapc_cases,
        "status": status,
        "failure_class": None,
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


def _cascade_convergence_metadata(
    *,
    continuous_mode: bool,
    min_runtime_seconds: float,
    confirmation_seconds: float,
    confirmation_eligible_cases: int,
    max_wall_time_seconds: float | None,
    budget_class: str,
) -> dict[str, Any]:
    max_wall = None if max_wall_time_seconds is None else float(max_wall_time_seconds)
    return {
        "convergence_enabled": bool(continuous_mode),
        "convergence_min_runtime_seconds": float(min_runtime_seconds or 0.0),
        "convergence_confirmation_seconds": float(confirmation_seconds or 0.0),
        "convergence_confirmation_eligible_cases": int(confirmation_eligible_cases or 0),
        "max_wall_time_seconds": max_wall,
        "time_budget_seconds": max_wall,
        "wall_clock_horizon_seconds": max_wall,
        "budget_class": str(budget_class or "primary-wall-clock"),
    }


def _base_cascade_metadata(
    *,
    dut: str,
    seed: int,
    active_coverage_mode: str,
    experiment_id: str,
    campaign_id: str,
    experiment_protocol_id: str,
    run_class: str,
    budget_class: str,
    batch_case_count: int,
    num_elfs: int,
    continuous_mode: bool,
    timeout_seconds: int,
    simlen: int,
    start_utc: str,
    dut_binary_path: Path,
    dut_provenance: dict[str, Any],
    source_provenance: dict[str, Any],
    universe: dict[str, Any] | None,
    universe_relpath: str | None,
    bapc_core_version: str = "v2",
) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "schema_version": "1.0",
        "experiment_id": str(experiment_id),
        "campaign_id": str(campaign_id),
        "experiment_protocol_id": str(experiment_protocol_id or ""),
        "method": "cascade",
        "variant": "cascade",
        "dut": str(dut),
        "seed": int(seed),
        "coverage_mode": str(active_coverage_mode),
        "run_class": str(run_class or ""),
        "jobs": 1,
        "driver_mode": "campaign",
        "generation_mode": "continuous-batches" if continuous_mode else "fixed-batch",
        "start_utc": start_utc,
        "end_utc": None,
        "elapsed_wall_seconds": None,
        "stop_reason": None,
        "command_line": " ".join(sys.argv),
        "batch_size": int(batch_case_count),
        "round_size": int(batch_case_count),
        "requested_cases": None if continuous_mode else int(num_elfs),
        "simlen": int(simlen),
        "per_case_timeout": int(timeout_seconds),
        "per_case_timeout_seconds": int(timeout_seconds),
        "dut_binary_path": str(dut_binary_path.resolve()),
        "dut_binary_sha256": str(dut_provenance.get("dut_binary_sha256") or ""),
        "dut_sha": str(dut_provenance.get("dut_sha") or ""),
        "dut_sha_status": str(dut_provenance.get("dut_sha_status") or ""),
        "dut_sha_reason": str(dut_provenance.get("dut_sha_reason") or ""),
        "dut_source_dir": str(dut_provenance.get("dut_source_dir") or ""),
        "dut_source_tree_sha256": str(dut_provenance.get("dut_source_tree_sha256") or ""),
        "source_sha": str(source_provenance.get("source_sha") or ""),
        "source_sha_status": str(source_provenance.get("source_sha_status") or ""),
        "source_tree_sha256": str(source_provenance.get("source_tree_sha256") or ""),
        "source_dirty": bool(source_provenance.get("source_dirty", False)),
        "container_image": CASCADE_IMAGE_SHA,
        "coverage_universe_hashes": {},
        "coverage_universe_files": {},
    }
    if universe is not None and universe_relpath:
        meta["coverage_universe_hashes"] = {active_coverage_mode: str(universe.get("sha256") or "")}
        meta["coverage_universe_files"] = {active_coverage_mode: universe_relpath}
        meta["capability_fingerprint"] = str(universe.get("capability_fingerprint") or "")
    else:
        meta["capability_fingerprint"] = ""
    if active_coverage_mode == "bapc":
        meta.update(
            {
                "bapc_schema_version": BAPC_SCHEMA_VERSION,
                "bapc_core_version": str(bapc_core_version),
                "bapc_measurement_mode": "target-operation",
                "probe_required": False,
                "instrumented_supplemental_enabled": False,
            }
        )
        if universe is not None:
            meta["bapc_target"] = int(universe.get("bin_count") or 0)
    elif active_coverage_mode == "hpm" and universe is not None:
        meta["hpm_target"] = int(universe.get("bin_count") or 0)
    return meta


def run_cascade_baseline(
    dut: str,
    num_elfs: int,
    simlen: int,
    timeout_seconds: int,
    out_dir: Path,
    seed: int = 1,
    *,
    coverage_mode: str | None = None,
    bapc_core_version: str = "v2",
    hpm_manifest: dict[str, Any] | None = None,
    batch_size: int | None = None,
    min_runtime_seconds: float | None = None,
    confirmation_seconds: float | None = None,
    confirmation_eligible_cases: int | None = None,
    max_wall_time_seconds: float | None = None,
    dut_bin: Path | None = None,
    dut_source_dir: Path | None = None,
    experiment_id: str = "cascade-baseline",
    campaign_id: str | None = None,
    experiment_protocol_id: str = "",
    run_class: str = "development-smoke",
    budget_class: str = "primary-wall-clock",
) -> dict[str, Any]:
    if dut not in SUPPORTED_DUTS:
        raise ValueError(f"unsupported DUT: {dut}")

    design = _DESIGN_MAP[dut]
    bapc_core_version = normalize_bapc_core_version(bapc_core_version)
    out_dir.mkdir(parents=True, exist_ok=True)
    start_utc = datetime.now(timezone.utc).isoformat()
    start_wall = time.monotonic()
    if run_class not in {"development-smoke", "baseline-pilot", "baseline-formal"}:
        raise ValueError(f"unsupported run_class for cascade: {run_class!r}")
    resolved_campaign_id = campaign_id or f"cascade__{dut}__seed-{seed:04d}"
    active_coverage_mode = _normalize_coverage_mode(
        coverage_mode,
        hpm_manifest=hpm_manifest,
    )
    formal_bapc_requested = is_bapc_formal_request(
        coverage_mode=active_coverage_mode,
        run_class=run_class,
        experiment_protocol_id=experiment_protocol_id,
    )
    requested_continuous_mode = any(
        (
            batch_size is not None,
            float(min_runtime_seconds or 0.0) > 0.0,
            float(confirmation_seconds or 0.0) > 0.0,
            int(confirmation_eligible_cases or 0) > 0,
        )
    )
    batch_case_count = int(batch_size or num_elfs)
    if batch_case_count <= 0:
        raise ValueError(f"batch size must be positive, got {batch_case_count}")
    if formal_bapc_requested and not is_bapc_formal_campaign(
        coverage_mode=active_coverage_mode,
        experiment_protocol_id=experiment_protocol_id,
    ):
        raise ValueError(
            "formal BAPC run requires experiment_protocol_id='bapc-convergence-v1'"
        )
    if is_bapc_formal_campaign(
        coverage_mode=active_coverage_mode,
        experiment_protocol_id=experiment_protocol_id,
    ):
        expected_run_class = expected_bapc_formal_run_class("cascade")
        if run_class != expected_run_class:
            raise ValueError(
                f"bapc convergence protocol requires cascade run_class={expected_run_class!r}, got {run_class!r}"
            )
        min_runtime_seconds = float(
            _enforce_or_fill_protocol_value(
                min_runtime_seconds,
                field="min_runtime_seconds",
                expected=BAPC_CONVERGENCE_FORMAL["convergence_min_runtime_seconds"],
                matches=typed_numeric_matches,
            )
        )
        confirmation_seconds = float(
            _enforce_or_fill_protocol_value(
                confirmation_seconds,
                field="confirmation_seconds",
                expected=BAPC_CONVERGENCE_FORMAL["convergence_confirmation_seconds"],
                matches=typed_numeric_matches,
            )
        )
        confirmation_eligible_cases = int(
            _enforce_or_fill_protocol_value(
                confirmation_eligible_cases,
                field="confirmation_eligible_cases",
                expected=BAPC_CONVERGENCE_FORMAL["convergence_confirmation_eligible_cases"],
                matches=typed_int_matches,
            )
        )
        max_wall_time_seconds = float(
            _enforce_or_fill_protocol_value(
                max_wall_time_seconds,
                field="max_wall_time_seconds",
                expected=BAPC_CONVERGENCE_FORMAL["max_wall_time_seconds"],
                matches=typed_numeric_matches,
            )
        )
        budget_class = str(
            _enforce_or_fill_protocol_value(
                budget_class,
                field="budget_class",
                expected=BAPC_CONVERGENCE_FORMAL["budget_class"],
                matches=_string_matches_canonical,
            )
        )
    continuous_mode = requested_continuous_mode or formal_bapc_requested
    dut_capability = capability_for_dut(dut)
    supports_smepmp = bool(dut_capability["supported_capabilities"].get("smepmp", False))
    supports_fault_stage = bool(dut_capability["supported_capabilities"].get("sv39", False))

    metrics_dir = out_dir / "metrics"
    logs_dir = out_dir / "logs"
    coverage_dir = metrics_dir / "coverage"
    campaign_coverage_dir = out_dir / "coverage"
    universe_dir = metrics_dir / "coverage_universe"
    elfs_dir = out_dir / "elfs"
    metrics_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    elfs_dir.mkdir(parents=True, exist_ok=True)

    hpm_universe = None
    bapc_universe = None
    hpm_manifest_path = None
    if active_coverage_mode == "hpm":
        hpm_universe = build_hpm_coverage_universe(
            dut=dut,
            generator_seed=seed,
            manifest_override=hpm_manifest,
        )
        universe_dir.mkdir(parents=True, exist_ok=True)
        hpm_manifest_path = universe_dir / "hpm_manifest_v1.json"
        (universe_dir / "hpm_v1.json").write_text(
            json.dumps(hpm_universe, indent=2, ensure_ascii=True) + "\n",
            encoding="ascii",
        )
        hpm_manifest_path.write_text(
            json.dumps(hpm_manifest, indent=2, ensure_ascii=True) + "\n",
            encoding="ascii",
        )
    elif active_coverage_mode == "bapc":
        bapc_universe = build_bapc_coverage_universe(
            dut=dut,
            generator_seed=seed,
            supports_fault_stage=supports_fault_stage,
            supports_smepmp=supports_smepmp,
            bapc_core_version=bapc_core_version,
        )
        bapc_universe_name = coverage_universe_filename("bapc", bapc_universe)
        universe_dir.mkdir(parents=True, exist_ok=True)
        (universe_dir / bapc_universe_name).write_text(
            json.dumps(bapc_universe, indent=2, ensure_ascii=True) + "\n",
            encoding="ascii",
        )

    dut_binary_path = Path(dut_bin) if dut_bin is not None else Path(_SIM_BINARIES.get(dut, ""))
    source_provenance = _cascade_source_provenance()
    if formal_bapc_requested and source_provenance.get("source_dirty") is not False:
        raise ValueError("formal BAPC requires source_dirty=False")
    dut_provenance = _cascade_dut_provenance(
        dut=dut,
        dut_binary_path=dut_binary_path,
        dut_source_dir=dut_source_dir,
    )
    dut_binary_error = str(dut_provenance.get("_dut_binary_error") or "") or None
    primary_universe = hpm_universe if active_coverage_mode == "hpm" else bapc_universe
    universe_relpath = None
    if active_coverage_mode == "hpm":
        universe_relpath = (universe_dir / "hpm_v1.json").relative_to(out_dir).as_posix()
    elif active_coverage_mode == "bapc":
        universe_relpath = (universe_dir / bapc_universe_name).relative_to(out_dir).as_posix()
    bapc_universe_path = universe_dir / (
        bapc_universe_name if active_coverage_mode == "bapc" else "bapc_v2.json"
    )
    artifact_root = _resolve_artifact_root_for_campaign(out_dir)
    _update_experiment_contract_manifest(
        artifact_root=artifact_root,
        dut=dut,
        variant_label="cascade",
        seed=seed,
        coverage_mode=active_coverage_mode,
        experiment_protocol_id=experiment_protocol_id,
        universe=bapc_universe,
        source_provenance=source_provenance,
        dut_provenance=dut_provenance,
    )
    base_meta = _base_cascade_metadata(
        dut=dut,
        seed=seed,
        active_coverage_mode=active_coverage_mode,
        experiment_id=experiment_id,
        campaign_id=resolved_campaign_id,
        experiment_protocol_id=experiment_protocol_id,
        run_class=run_class,
        budget_class=budget_class,
        batch_case_count=batch_case_count,
        num_elfs=num_elfs,
        continuous_mode=continuous_mode,
        timeout_seconds=timeout_seconds,
        simlen=simlen,
        start_utc=start_utc,
        dut_binary_path=dut_binary_path,
        dut_provenance=dut_provenance,
        source_provenance=source_provenance,
        universe=primary_universe,
        universe_relpath=universe_relpath,
        bapc_core_version=bapc_core_version,
    )
    base_meta.update(
        _cascade_convergence_metadata(
            continuous_mode=continuous_mode,
            min_runtime_seconds=min_runtime_seconds,
            confirmation_seconds=confirmation_seconds,
            confirmation_eligible_cases=confirmation_eligible_cases,
            max_wall_time_seconds=max_wall_time_seconds,
            budget_class=budget_class,
        )
    )

    if dut_binary_error is not None:
        elapsed_total = time.monotonic() - start_wall
        meta = dict(base_meta)
        meta.update(
            {
                "status": "infra_failure",
                "dut_binary_error": dut_binary_error,
                "end_utc": datetime.now(timezone.utc).isoformat(),
                "elapsed_wall_seconds": elapsed_total,
                "stop_reason": "infra_failure",
                "completed_cases": 0,
                "executed_cases": 0,
                "eligible_cases": 0,
                "eligible_hpm_cases": 0,
                "eligible_bapc_cases": 0,
                "timeouts": 0,
                "inconclusive": 0,
                "infra_failures": 0,
                "generation_batches": [],
            }
        )
        (metrics_dir / "campaign_metadata.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=True) + "\n",
            encoding="ascii",
        )
        (out_dir / "events.json").write_text("[]\n", encoding="ascii")
        if hpm_universe is not None or bapc_universe is not None:
            (out_dir / "validation.json").write_text(
                json.dumps(
                    {
                        "campaign_id": resolved_campaign_id,
                        "valid": False,
                        "error": dut_binary_error,
                    },
                    indent=2,
                    ensure_ascii=True,
                ) + "\n",
                    encoding="ascii",
                )
        if artifact_root is not None:
            rel_paths = [
                (metrics_dir / "campaign_metadata.json").relative_to(artifact_root),
                (out_dir / "events.json").relative_to(artifact_root),
            ]
            if (out_dir / "validation.json").exists():
                rel_paths.append((out_dir / "validation.json").relative_to(artifact_root))
            for optional_path in (
                universe_dir / "hpm_v1.json",
                universe_dir / "hpm_manifest_v1.json",
                bapc_universe_path,
                artifact_root / "manifests" / "experiment-contract.json",
            ):
                if optional_path.exists() and optional_path.is_file():
                    rel_paths.append(optional_path.relative_to(artifact_root))
            _update_artifact_sha_manifest(artifact_root, rel_paths)
        return meta

    security_event_rows_path = metrics_dir / "security_event_timeseries.jsonl"
    security_event_rows_digest_path = metrics_dir / "security_event_timeseries.sha256.json"
    security_event_rows_handle = None
    security_event_rows_sha256 = None
    security_event_rows_byte_count = 0
    security_event_rows_count = 0
    security_event_ids: set[str] = set()
    events_list: list[dict[str, Any]] = []
    generation_batches: list[dict[str, Any]] = []
    completed = 0
    executed_cases = 0
    eligible_cases = 0
    eligible_hpm_cases = 0
    eligible_bapc_cases = 0
    timeouts = 0
    inconclusive = 0
    infra_failures = 0
    covered_hpm: set[str] = set()
    covered_bapc: set[str] = set()
    last_hpm_novelty_time = 0.0
    last_hpm_novelty_eligible_seq = 0
    last_hpm_novelty_completed_seq = 0
    last_hpm_novelty_unique_scenario_count = 0
    last_bapc_novelty_time = 0.0
    last_bapc_novelty_eligible_seq = 0
    last_bapc_novelty_completed_seq = 0
    last_bapc_novelty_unique_scenario_count = 0
    unique_scenario_hashes: set[str] = set()
    stop_reason = None
    convergence_confirmed = False
    convergence_time_seconds = None
    convergence_completed_cases = None
    convergence_eligible_cases = None
    hpm_timeline: list[dict[str, Any]] = []
    bapc_timeline: list[dict[str, Any]] = []
    if hpm_universe is not None:
        hpm_timeline.append(
            _hpm_baseline_timeline_line(
                campaign_id=resolved_campaign_id,
                dut=dut,
                seed=seed,
                target_bins=int(hpm_universe["bin_count"]),
            )
        )
    if bapc_universe is not None:
        bapc_timeline.append(
            _bapc_baseline_timeline_line(
                campaign_id=resolved_campaign_id,
                dut=dut,
                seed=seed,
                target_bins=int(bapc_universe["bin_count"]),
            )
        )

    next_case_index = 0
    while True:
        if continuous_mode and max_wall_time_seconds is not None and executed_cases > 0:
            if (time.monotonic() - start_wall) >= float(max_wall_time_seconds):
                stop_reason = STOP_HARD_CAP_CENSORED
                break

        current_batch_size = batch_case_count if continuous_mode else int(num_elfs)
        generate_kwargs = {
            "seed": seed,
            "design": design,
        }
        if continuous_mode or next_case_index:
            generate_kwargs["start_index"] = next_case_index
        if hpm_manifest_path is not None:
            generate_kwargs["hpm_manifest_path"] = hpm_manifest_path
        if active_coverage_mode == "bapc":
            generate_kwargs["require_target_operation_candidate"] = True
        gen_result = _generate_elfs(current_batch_size, elfs_dir, **generate_kwargs)
        generation_batches.append(gen_result)
        if not gen_result.get("success"):
            if executed_cases == 0:
                meta = dict(base_meta)
                meta.update(
                    {
                        "status": "infra_failure",
                        "error": "elf_generation_failed",
                        "generation_info": gen_result,
                        "end_utc": datetime.now(timezone.utc).isoformat(),
                        "elapsed_wall_seconds": time.monotonic() - start_wall,
                        "stop_reason": "infra_failure",
                        "completed_cases": 0,
                        "executed_cases": 0,
                        "eligible_cases": 0,
                        "eligible_hpm_cases": 0,
                        "eligible_bapc_cases": 0,
                        "timeouts": 0,
                        "inconclusive": 0,
                        "infra_failures": 1,
                        "generation_batches": generation_batches,
                    }
                )
                (metrics_dir / "campaign_metadata.json").write_text(
                    json.dumps(meta, indent=2, ensure_ascii=True) + "\n",
                    encoding="ascii",
                )
                (out_dir / "events.json").write_text("[]\n", encoding="ascii")
                if hpm_universe is not None or bapc_universe is not None:
                    (out_dir / "validation.json").write_text(
                        json.dumps(
                            {
                                "campaign_id": resolved_campaign_id,
                                "valid": False,
                                "error": "elf_generation_failed",
                            },
                            indent=2,
                            ensure_ascii=True,
                        ) + "\n",
                            encoding="ascii",
                        )
                if artifact_root is not None:
                    rel_paths = [
                        (metrics_dir / "campaign_metadata.json").relative_to(artifact_root),
                        (out_dir / "events.json").relative_to(artifact_root),
                    ]
                    if (out_dir / "validation.json").exists():
                        rel_paths.append((out_dir / "validation.json").relative_to(artifact_root))
                    for optional_path in (
                        universe_dir / "hpm_v1.json",
                        universe_dir / "hpm_manifest_v1.json",
                        bapc_universe_path,
                        artifact_root / "manifests" / "experiment-contract.json",
                    ):
                        if optional_path.exists() and optional_path.is_file():
                            rel_paths.append(optional_path.relative_to(artifact_root))
                    _update_artifact_sha_manifest(artifact_root, rel_paths)
                return meta
            stop_reason = "infra_failure"
            infra_failures += 1
            break

        elf_hashes = gen_result.get("elf_hashes", {})
        for batch_offset in range(current_batch_size):
            case_index = next_case_index + batch_offset
            returncode = None
            stdout_text = ""
            stderr_text = ""
            elf_name = f"{design}_{case_index}.elf"
            elf_path = elfs_dir / elf_name
            case_id = f"cascade_{dut}_{case_index:04d}"
            stdout_path = logs_dir / f"{case_id}.stdout.log"
            stderr_path = logs_dir / f"{case_id}.stderr.log"
            elapsed_wall = time.monotonic() - start_wall

            if not elf_path.exists():
                infra_failures += 1
                executed_cases += 1
                stdout_path.write_text("", encoding="utf-8")
                stderr_path.write_text("", encoding="utf-8")
                events_list.append(
                    {
                        "case_id": case_id,
                        "completion_seq": executed_cases,
                        "status": "infra_failure",
                        "elapsed_wall_seconds": elapsed_wall,
                        "case_elapsed_seconds": 0.0,
                        "returncode": None,
                        "probe_event_count": 0,
                        "stdout_log": str(stdout_path.relative_to(out_dir)),
                        "stderr_log": str(stderr_path.relative_to(out_dir)),
                        "sidecar_relpath": None,
                        "elf_sha256": "",
                    }
                )
                if hpm_universe is not None:
                    hpm_timeline.append(
                        _hpm_timeline_line(
                            campaign_id=resolved_campaign_id,
                            dut=dut,
                            seed=seed,
                            completion_seq=executed_cases,
                            case_id=case_id,
                            elapsed_wall_seconds=elapsed_wall,
                            case_elapsed_seconds=0.0,
                            completed_cases=executed_cases,
                            eligible_cases=eligible_cases,
                            eligible_hpm_cases=eligible_hpm_cases,
                            status="infra_failure",
                            coverage_eligible=False,
                            qualification_reason="missing-elf",
                            hpm_covered=len(covered_hpm),
                            hpm_target=int(hpm_universe["bin_count"]),
                            new_hpm_bins=0,
                            last_hpm_novelty_time=last_hpm_novelty_time,
                        )
                    )
                if bapc_universe is not None:
                    bapc_timeline.append(
                        _bapc_timeline_line(
                            campaign_id=resolved_campaign_id,
                            dut=dut,
                            seed=seed,
                            completion_seq=executed_cases,
                            case_id=case_id,
                            elapsed_wall_seconds=elapsed_wall,
                            case_elapsed_seconds=0.0,
                            completed_cases=executed_cases,
                            eligible_cases=eligible_cases,
                            eligible_bapc_cases=eligible_bapc_cases,
                            status="infra_failure",
                            coverage_eligible=False,
                            qualification_reason="missing-elf",
                            bapc_covered=len(covered_bapc),
                            bapc_target=int(bapc_universe["bin_count"]),
                            new_bapc_bins=0,
                            last_bapc_novelty_time=last_bapc_novelty_time,
                        )
                    )
                continue

            case_elf_sha256 = ""
            try:
                case_elf_sha256 = elf_hashes.get(
                    elf_name,
                    hashlib.sha256(elf_path.read_bytes()).hexdigest(),
                )
            except OSError:
                case_elf_sha256 = ""
            if case_elf_sha256:
                unique_scenario_hashes.add(case_elf_sha256)

            cmd, env = _simulator_command(dut, elf_path, simlen, dut_binary=dut_binary_path)
            case_start = time.monotonic()
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                    env=env,
                    cwd=elf_path.parent,
                )
                returncode = proc.returncode
                case_elapsed = time.monotonic() - case_start
                stdout_text = proc.stdout or ""
                stderr_text = proc.stderr or ""
                stdout_path.write_text(stdout_text, encoding="utf-8", errors="replace")
                stderr_path.write_text(stderr_text, encoding="utf-8", errors="replace")
                combined_log = _merge_log_streams(stdout_text, stderr_text)
                probe_events = _extract_probe_events(combined_log)
                if probe_events:
                    status = "completed"
                    completed += 1
                    eligible_cases += 1
                else:
                    status = "inconclusive"
                    inconclusive += 1
            except subprocess.TimeoutExpired:
                case_elapsed = float(timeout_seconds)
                status = "timeout"
                timeouts += 1
                probe_events = []
                combined_log = ""
                stdout_path.write_text("", encoding="utf-8")
                stderr_path.write_text("", encoding="utf-8")
            except Exception:
                case_elapsed = time.monotonic() - case_start
                status = "infra_failure"
                infra_failures += 1
                probe_events = []
                combined_log = ""
                stdout_path.write_text("", encoding="utf-8")
                stderr_path.write_text("", encoding="utf-8")

            executed_cases += 1
            elapsed_wall = time.monotonic() - start_wall

            sidecar_data = _load_sidecar_data(
                gen_result=gen_result,
                elfs_dir=elfs_dir,
                design=design,
                case_index=case_index,
            )
            sidecar_path = elfs_dir / f"{design}_{case_index}.json"
            sidecar_relpath = (
                str(sidecar_path.relative_to(out_dir))
                if sidecar_path.exists()
                else None
            )
            hpm_case = None
            hpm_eligible = False
            new_hpm_bins: list[str] = []
            if hpm_universe is not None:
                snapshots = parse_hpm_uart_snapshots(combined_log)
                hpm_case = summarize_hpm_coverage(
                    manifest=hpm_manifest,
                    before=snapshots.get("before"),
                    after=snapshots.get("after"),
                )
                hpm_eligible = bool(hpm_case.get("eligible"))
                if hpm_eligible:
                    eligible_hpm_cases += 1
                    observed_bins = sorted(
                        {str(item) for item in (hpm_case.get("observed_bins") or [])}
                    )
                    new_hpm_bins = sorted(set(observed_bins) - covered_hpm)
                    covered_hpm.update(observed_bins)
                    if new_hpm_bins:
                        last_hpm_novelty_time = float(elapsed_wall)
                        last_hpm_novelty_eligible_seq = eligible_hpm_cases
                        last_hpm_novelty_completed_seq = executed_cases
                        last_hpm_novelty_unique_scenario_count = len(unique_scenario_hashes)

            bapc_case = None
            bapc_eligible = False
            bapc_out_of_contract: list[str] = []
            new_bapc_bins: list[str] = []
            cascade_runtime = None
            if bapc_universe is not None:
                if sidecar_data is None:
                    bapc_case = {
                        "eligible": False,
                        "qualification_reason": "missing-bapc-sidecar",
                        "observed_bins": [],
                        "artifact_valid": False,
                        "measurement_valid": False,
                    }
                else:
                    bapc_result = _bapc_actual_result_from_log(
                        dut=dut,
                        log_text=combined_log,
                        returncode=returncode,
                    )
                    resolved_sidecar = _resolve_target_operation_sidecar(
                        sidecar_data,
                        bapc_result,
                    )
                    if (
                        resolved_sidecar is None
                        and sidecar_data.get("target_operation_candidates") is not None
                    ):
                        bapc_case = {
                            "eligible": False,
                            "qualification_reason": "missing-or-ambiguous-target-operation",
                            "observed_bins": [],
                            "artifact_valid": False,
                            "measurement_valid": False,
                        }
                    else:
                        sidecar_for_bapc = resolved_sidecar or sidecar_data
                        strict_runtime_contract = (
                            dut in {"rocket-clean", "boom-clean", "cva6-clean"}
                            and str(sidecar_for_bapc.get("runtime_attribution_contract") or "").strip()
                            == CASCADE_TARGET_OPERATION_SCHEMA_VERSION
                        )
                        if strict_runtime_contract:
                            cascade_runtime = collect_cascade_runtime_attribution(
                                dut=dut,
                                case_id=case_id,
                                sidecar=sidecar_for_bapc,
                                result=bapc_result,
                                log_text=combined_log,
                            )
                            bapc_case = summarize_cascade_runtime_measurement(
                                sidecar=sidecar_for_bapc,
                                runtime_payload=cascade_runtime,
                                bapc_core_version=bapc_core_version,
                            )
                            bapc_case["bapc_schema_version"] = BAPC_SCHEMA_VERSION
                            bapc_case["bapc_core_version"] = str(bapc_core_version)
                        else:
                            event_records = runtime_bapc_event_records_for_cascade_execution(
                                sidecar_for_bapc,
                                bapc_result,
                                stdout_text=combined_log,
                                supports_smepmp=supports_smepmp,
                            )
                            bapc_case = summarize_bapc_for_cascade_execution(
                                sidecar_for_bapc,
                                bapc_result,
                                stdout_text=combined_log,
                                supports_smepmp=supports_smepmp,
                                event_records=event_records,
                                bapc_core_version=bapc_core_version,
                            )
                bapc_eligible = bool(bapc_case.get("eligible"))
                if bapc_eligible:
                    eligible_bapc_cases += 1
                    classified = classify_observed_bins(
                        bapc_universe,
                        bapc_case.get("observed_bins") or [],
                    )
                    bapc_out_of_contract = list(classified["out_of_contract"])
                    observed_bins = sorted(set(classified["covered"]))
                    new_bapc_bins = sorted(set(observed_bins) - covered_bapc)
                    covered_bapc.update(observed_bins)
                    if new_bapc_bins:
                        last_bapc_novelty_time = float(elapsed_wall)
                        last_bapc_novelty_eligible_seq = eligible_bapc_cases
                        last_bapc_novelty_completed_seq = executed_cases
                        last_bapc_novelty_unique_scenario_count = len(unique_scenario_hashes)

            events_list.append(
                {
                    "case_id": case_id,
                    "completion_seq": executed_cases,
                    "status": status,
                    "elapsed_wall_seconds": elapsed_wall,
                    "case_elapsed_seconds": case_elapsed,
                    "returncode": returncode,
                    "probe_event_count": len(probe_events),
                    "stdout_log": str(stdout_path.relative_to(out_dir)),
                    "stderr_log": str(stderr_path.relative_to(out_dir)),
                    "sidecar_relpath": sidecar_relpath,
                    "elf_sha256": case_elf_sha256,
                    "hpm_eligible": hpm_eligible,
                    "new_hpm_bins": len(new_hpm_bins),
                    "hpm_snapshot_before": None if hpm_case is None else hpm_case.get("before"),
                    "hpm_snapshot_after": None if hpm_case is None else hpm_case.get("after"),
                    "hpm_coverage": hpm_case,
                    "bapc_eligible": bapc_eligible,
                    "new_bapc_bins": len(new_bapc_bins),
                    "bapc_out_of_contract_bins": bapc_out_of_contract,
                    "cascade_runtime": cascade_runtime,
                    "bapc_coverage": bapc_case,
                }
            )
            case_event_rows = _security_event_rows_for_case(
                probe_events,
                dut=dut,
                campaign_id=resolved_campaign_id,
                seed=seed,
                completion_seq=executed_cases,
                case_id=case_id,
                elapsed_wall_seconds=elapsed_wall,
                event_set=security_event_ids,
            )
            if case_event_rows:
                if security_event_rows_handle is None:
                    security_event_rows_handle = security_event_rows_path.open(
                        "w", encoding="ascii", newline="\n"
                    )
                    security_event_rows_sha256 = hashlib.sha256()
                for row in case_event_rows:
                    payload = json.dumps(row, ensure_ascii=True) + "\n"
                    security_event_rows_handle.write(payload)
                    if security_event_rows_sha256 is not None:
                        encoded = payload.encode("ascii")
                        security_event_rows_sha256.update(encoded)
                        security_event_rows_byte_count += len(encoded)
                        security_event_rows_count += 1

            if hpm_universe is not None:
                qualification_reason = str(
                    (hpm_case or {}).get("qualification_reason", "missing-hpm-snapshot")
                )
                hpm_timeline.append(
                    _hpm_timeline_line(
                        campaign_id=resolved_campaign_id,
                        dut=dut,
                        seed=seed,
                        completion_seq=executed_cases,
                        case_id=case_id,
                        elapsed_wall_seconds=elapsed_wall,
                        case_elapsed_seconds=case_elapsed,
                        completed_cases=executed_cases,
                        eligible_cases=eligible_cases,
                        eligible_hpm_cases=eligible_hpm_cases,
                        status=status,
                        coverage_eligible=hpm_eligible,
                        qualification_reason=qualification_reason,
                        hpm_covered=len(covered_hpm),
                        hpm_target=int(hpm_universe["bin_count"]),
                        new_hpm_bins=len(new_hpm_bins),
                        last_hpm_novelty_time=last_hpm_novelty_time,
                    )
                )

                if continuous_mode:
                    confirmation_window_seconds = elapsed_wall - last_hpm_novelty_time
                    confirmation_window_eligible_cases = (
                        eligible_hpm_cases - last_hpm_novelty_eligible_seq
                    )
                    unique_scenarios_since_last_novelty = (
                        len(unique_scenario_hashes) - last_hpm_novelty_unique_scenario_count
                    )
                    executions_since_last_novelty = (
                        executed_cases - last_hpm_novelty_completed_seq
                    )
                    if (
                        elapsed_wall >= float(min_runtime_seconds or 0.0)
                        and confirmation_window_seconds >= float(confirmation_seconds or 0.0)
                        and confirmation_window_eligible_cases >= int(confirmation_eligible_cases or 0)
                        and unique_scenarios_since_last_novelty > 0
                        and executions_since_last_novelty > 0
                    ):
                        convergence_confirmed = True
                        convergence_time_seconds = float(elapsed_wall)
                        convergence_completed_cases = executed_cases
                        convergence_eligible_cases = eligible_hpm_cases
                        stop_reason = STOP_COVERAGE_CONVERGED
                        break

                    if (
                        max_wall_time_seconds is not None
                        and elapsed_wall >= float(max_wall_time_seconds)
                    ):
                        stop_reason = STOP_HARD_CAP_CENSORED
                        break
            if bapc_universe is not None:
                qualification_reason = str(
                    (bapc_case or {}).get("qualification_reason", "missing-actual-observation")
                )
                bapc_timeline.append(
                    _bapc_timeline_line(
                        campaign_id=resolved_campaign_id,
                        dut=dut,
                        seed=seed,
                        completion_seq=executed_cases,
                        case_id=case_id,
                        elapsed_wall_seconds=elapsed_wall,
                        case_elapsed_seconds=case_elapsed,
                        completed_cases=executed_cases,
                        eligible_cases=eligible_cases,
                        eligible_bapc_cases=eligible_bapc_cases,
                        status=status,
                        coverage_eligible=bapc_eligible,
                        qualification_reason=qualification_reason,
                        bapc_covered=len(covered_bapc),
                        bapc_target=int(bapc_universe["bin_count"]),
                        new_bapc_bins=len(new_bapc_bins),
                        last_bapc_novelty_time=last_bapc_novelty_time,
                    )
                )

                if continuous_mode:
                    confirmation_window_seconds = elapsed_wall - last_bapc_novelty_time
                    confirmation_window_eligible_cases = (
                        eligible_bapc_cases - last_bapc_novelty_eligible_seq
                    )
                    unique_scenarios_since_last_novelty = (
                        len(unique_scenario_hashes) - last_bapc_novelty_unique_scenario_count
                    )
                    executions_since_last_novelty = (
                        executed_cases - last_bapc_novelty_completed_seq
                    )
                    if (
                        elapsed_wall >= float(min_runtime_seconds or 0.0)
                        and confirmation_window_seconds >= float(confirmation_seconds or 0.0)
                        and confirmation_window_eligible_cases >= int(confirmation_eligible_cases or 0)
                        and unique_scenarios_since_last_novelty > 0
                        and executions_since_last_novelty > 0
                    ):
                        convergence_confirmed = True
                        convergence_time_seconds = float(elapsed_wall)
                        convergence_completed_cases = executed_cases
                        convergence_eligible_cases = eligible_bapc_cases
                        stop_reason = STOP_COVERAGE_CONVERGED
                        break

                    if (
                        max_wall_time_seconds is not None
                        and elapsed_wall >= float(max_wall_time_seconds)
                    ):
                        stop_reason = STOP_HARD_CAP_CENSORED
                        break

            if (
                continuous_mode
                and max_wall_time_seconds is not None
                and elapsed_wall >= float(max_wall_time_seconds)
            ):
                stop_reason = STOP_HARD_CAP_CENSORED
                break

        next_case_index += current_batch_size
        if not continuous_mode or stop_reason is not None:
            break

    elapsed_total = time.monotonic() - start_wall
    if stop_reason is None:
        stop_reason = "completed_requested_cases"

    meta = dict(base_meta)
    meta.update(
        {
            "status": "completed" if stop_reason != "infra_failure" else "infra_failure",
            "end_utc": datetime.now(timezone.utc).isoformat(),
            "elapsed_wall_seconds": elapsed_total,
            "stop_reason": stop_reason,
            "completed_cases": completed,
            "executed_cases": executed_cases,
            "eligible_cases": eligible_cases,
            "eligible_hpm_cases": eligible_hpm_cases,
            "eligible_bapc_cases": eligible_bapc_cases,
            "timeouts": timeouts,
            "inconclusive": inconclusive,
            "infra_failures": infra_failures,
            "generation_batches": generation_batches,
        }
    )
    if hpm_universe is not None:
        meta["coverage_mode"] = "hpm"
        meta["hpm_manifest_file"] = str(hpm_manifest_path.relative_to(out_dir))
        meta["convergence_confirmed"] = convergence_confirmed
        meta["convergence_time_seconds"] = convergence_time_seconds
        meta["convergence_completed_cases"] = convergence_completed_cases
        meta["convergence_eligible_cases"] = convergence_eligible_cases
        meta["last_hpm_novelty_time"] = last_hpm_novelty_time
        meta["last_hpm_novelty_eligible_seq"] = last_hpm_novelty_eligible_seq
        meta["unique_scenario_hashes"] = len(unique_scenario_hashes)
        meta["hpm_covered"] = len(covered_hpm)
        meta["hpm_target"] = int(hpm_universe["bin_count"])
    if bapc_universe is not None:
        meta["coverage_mode"] = "bapc"
        meta["coverage_universe_hashes"] = {"bapc": bapc_universe["sha256"]}
        meta["coverage_universe_files"] = {
            "bapc": bapc_universe_path.relative_to(out_dir).as_posix()
        }
        meta.update(
            {
                "bapc_schema_version": BAPC_SCHEMA_VERSION,
                "bapc_core_version": bapc_core_version,
                "bapc_measurement_mode": "target-operation",
                "probe_required": False,
                "instrumented_supplemental_enabled": False,
            }
        )
        meta["convergence_confirmed"] = convergence_confirmed
        meta["convergence_time_seconds"] = convergence_time_seconds
        meta["convergence_completed_cases"] = convergence_completed_cases
        meta["convergence_eligible_cases"] = convergence_eligible_cases
        meta["last_bapc_novelty_time"] = last_bapc_novelty_time
        meta["last_bapc_novelty_eligible_seq"] = last_bapc_novelty_eligible_seq
        meta["unique_scenario_hashes"] = len(unique_scenario_hashes)
        meta["bapc_covered"] = len(covered_bapc)
        meta["bapc_target"] = int(bapc_universe["bin_count"])
        meta["analysis_scope"] = {
            "guidance_mode": "bapc",
            "primary_metric": "bapc",
            "coverage_modes": ["bapc"],
        }

    (metrics_dir / "campaign_metadata.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    with (out_dir / "events.json").open("w", encoding="ascii") as handle:
        json.dump(events_list, handle, indent=2, ensure_ascii=True)

    if security_event_rows_handle is not None:
        security_event_rows_handle.close()
        if security_event_rows_sha256 is not None:
            security_event_rows_digest_path.write_text(
                json.dumps(
                    {
                        "schema_version": SECURITY_EVENT_TIMESERIES_DIGEST_SCHEMA_VERSION,
                        "file": security_event_rows_path.name,
                        "sha256": security_event_rows_sha256.hexdigest(),
                        "byte_count": security_event_rows_byte_count,
                        "row_count": security_event_rows_count,
                    },
                    indent=2,
                    ensure_ascii=True,
                    sort_keys=True,
                )
                + "\n",
                encoding="ascii",
            )

    if hpm_universe is not None:
        coverage_dir.mkdir(parents=True, exist_ok=True)
        campaign_coverage_dir.mkdir(parents=True, exist_ok=True)
        (metrics_dir / "coverage_timeline.jsonl").write_text(
            "\n".join(
                json.dumps(row, ensure_ascii=True, sort_keys=True)
                for row in hpm_timeline
            ) + "\n",
            encoding="ascii",
        )
        coverage_payload = json.dumps(
            {
                "schema_version": 6,
                "driver_mode": "campaign",
                "coverage_universe_hashes": {"hpm": hpm_universe["sha256"]},
                "execution_coverage": {
                    "by_dut": {
                        dut: {
                            "hpm": {
                                "covered_target_bins": len(covered_hpm),
                                "total_target_bins": int(hpm_universe["bin_count"]),
                                "covered_bins": sorted(covered_hpm),
                                "target": "pmp-relevant-hpm",
                                "universe_sha256": hpm_universe["sha256"],
                            }
                        }
                    }
                },
            },
            indent=2,
            ensure_ascii=True,
        ) + "\n"
        (coverage_dir / "coverage.json").write_text(coverage_payload, encoding="ascii")
        (campaign_coverage_dir / "coverage.json").write_text(coverage_payload, encoding="ascii")
        report = validate_timeline(out_dir)
        (out_dir / "validation.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
            encoding="ascii",
        )
    if bapc_universe is not None:
        coverage_dir.mkdir(parents=True, exist_ok=True)
        campaign_coverage_dir.mkdir(parents=True, exist_ok=True)
        (metrics_dir / "coverage_timeline.jsonl").write_text(
            "\n".join(
                json.dumps(row, ensure_ascii=True, sort_keys=True)
                for row in bapc_timeline
            ) + "\n",
            encoding="ascii",
        )
        coverage_payload = json.dumps(
            {
                "schema_version": 6,
                "driver_mode": "campaign",
                "coverage_universe_hashes": {"bapc": bapc_universe["sha256"]},
                "execution_coverage": {
                    "by_dut": {
                        dut: {
                            "bapc": {
                                "covered_target_bins": len(covered_bapc),
                                "total_target_bins": int(bapc_universe["bin_count"]),
                                "covered_bins": sorted(covered_bapc),
                                "target": "black-box-architectural-pmp-target-operation",
                                "universe_sha256": bapc_universe["sha256"],
                            }
                        }
                    }
                },
            },
            indent=2,
            ensure_ascii=True,
        ) + "\n"
        (coverage_dir / "coverage.json").write_text(coverage_payload, encoding="ascii")
        (campaign_coverage_dir / "coverage.json").write_text(coverage_payload, encoding="ascii")
        report = validate_timeline(out_dir)
        (out_dir / "validation.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
            encoding="ascii",
        )

    if artifact_root is not None:
        rel_paths = [
            (metrics_dir / "campaign_metadata.json").relative_to(artifact_root),
            (out_dir / "events.json").relative_to(artifact_root),
            (out_dir / "validation.json").relative_to(artifact_root),
        ]
        for optional_path in (
            metrics_dir / "coverage_timeline.jsonl",
            coverage_dir / "coverage.json",
            campaign_coverage_dir / "coverage.json",
            security_event_rows_digest_path,
            universe_dir / "hpm_v1.json",
            universe_dir / "hpm_manifest_v1.json",
            bapc_universe_path,
            artifact_root / "manifests" / "experiment-contract.json",
        ):
            if optional_path.exists() and optional_path.is_file():
                rel_paths.append(optional_path.relative_to(artifact_root))
        _update_artifact_sha_manifest(artifact_root, rel_paths)

    return meta


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cascade baseline adapter")
    parser.add_argument("--experiment-id", default="cascade-baseline")
    parser.add_argument("--campaign-id", default=None)
    parser.add_argument("--experiment-protocol-id", default="")
    parser.add_argument("--dut", choices=list(SUPPORTED_DUTS), default="rocket-clean")
    parser.add_argument("--num-elfs", type=int, default=5)
    parser.add_argument("--simlen", type=int, default=50000)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=None)
    parser.add_argument(
        "--convergence-min-runtime-seconds",
        "--min-runtime-seconds",
        dest="convergence_min_runtime_seconds",
        type=float,
        default=None,
    )
    parser.add_argument(
        "--convergence-confirmation-seconds",
        "--confirmation-seconds",
        dest="convergence_confirmation_seconds",
        type=float,
        default=None,
    )
    parser.add_argument(
        "--convergence-confirmation-eligible-cases",
        "--confirmation-eligible-cases",
        dest="convergence_confirmation_eligible_cases",
        type=int,
        default=None,
    )
    parser.add_argument("--max-wall-time-seconds", type=float, default=None)
    parser.add_argument("--coverage-mode", choices=["hpm", "bapc"], default=None)
    parser.add_argument("--bapc-core-version", choices=["v2", "v3", "v4"], default=None)
    parser.add_argument("--hpm-manifest", type=Path, default=None)
    parser.add_argument("--dut-bin", type=Path, default=None)
    parser.add_argument("--dut-source-dir", type=Path, default=None)
    parser.add_argument(
        "--run-class",
        choices=["development-smoke", "baseline-pilot", "baseline-formal"],
        default="development-smoke",
    )
    parser.add_argument("--budget-class", default="primary-wall-clock")

    args = parser.parse_args(argv)
    if args.coverage_mode == "bapc" and args.bapc_core_version in {None, ""}:
        raise ValueError("coverage mode 'bapc' requires explicit --bapc-core-version {v2,v3,v4}")
    hpm_manifest = None
    if args.hpm_manifest is not None:
        hpm_manifest = json.loads(args.hpm_manifest.read_text(encoding="utf-8"))
    meta = run_cascade_baseline(
        dut=args.dut,
        num_elfs=args.num_elfs,
        simlen=args.simlen,
        timeout_seconds=args.timeout,
        out_dir=args.out.resolve(),
        seed=args.seed,
        experiment_id=args.experiment_id,
        campaign_id=args.campaign_id,
        experiment_protocol_id=args.experiment_protocol_id,
        coverage_mode=args.coverage_mode,
        bapc_core_version=args.bapc_core_version,
        hpm_manifest=hpm_manifest,
        batch_size=args.batch_size,
        min_runtime_seconds=args.convergence_min_runtime_seconds,
        confirmation_seconds=args.convergence_confirmation_seconds,
        confirmation_eligible_cases=args.convergence_confirmation_eligible_cases,
        max_wall_time_seconds=args.max_wall_time_seconds,
        dut_bin=args.dut_bin,
        dut_source_dir=args.dut_source_dir,
        run_class=args.run_class,
        budget_class=args.budget_class,
    )
    print(json.dumps(meta, indent=2, ensure_ascii=True))
    return 0 if meta.get("status") != "infra_failure" else 1


if __name__ == "__main__":
    raise SystemExit(main())
