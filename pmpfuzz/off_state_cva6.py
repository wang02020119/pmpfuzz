from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from .bapc import (
    map_bapc_normalized_record,
    parse_probe_events,
    summarize_bapc_for_pmpfuzz_case,
)
from .diagnostics import emit_failure_tohost_lines, failed_tohost_from_log
from .dut import DEFAULT_CLEAN_CHIPYARD_DIR, make_dut
from .off_state import (
    OFF_STATE_ANALYSIS_KIND,
    OFF_STATE_ARTIFACT_KIND,
    OFF_STATE_RECORD_SCHEMA_VERSION,
    OFF_STATE_SCHEMA_VERSION,
    analyze_characterization_artifact,
    append_characterization_records,
    build_spec_encoding_sets,
    OFF_STATE_RECORD_SCHEMA_VERSION,
    build_raw_state_universe,
    capture_repo_metadata,
    enrich_metadata,
    off_state_encodings,
    raw_state_bin_id,
    sha256_file,
    spec_status_for_off_state,
    write_json,
)
from .pmp import AddressMode, PmpEntry
from .scenario import MEM_BASE, TARGET_BASE, TARGET_SIZE


CVA6_PILOT_PLAN_SCHEMA_VERSION = 1
CVA6_PILOT_RESULT_SCHEMA_VERSION = 1
CVA6_PILOT_PLAN_KIND = "pmp-off-state-cva6-pilot-plan-v1"
CVA6_PILOT_RESULT_KIND = "pmp-off-state-cva6-pilot-result-v1"
CVA6_FORMAL_BATCH_PLAN_SCHEMA_VERSION = 1
CVA6_FORMAL_BATCH_SUMMARY_SCHEMA_VERSION = 1
CVA6_FORMAL_BATCH_PLAN_KIND = "pmp-off-state-cva6-formal-plan-v1"
CVA6_FORMAL_BATCH_SUMMARY_KIND = "pmp-off-state-cva6-formal-batch-summary-v1"
CVA6_SUPPORTED_PROFILE = "base-pmp"
CVA6_SUPPORTED_ACCESS = "load"
_CVA6_CONTROL_PHASES = ("pre", "post")
_PILOT_CASE_ORDER = (
    "readback-off-control",
    "lock-positive-control",
    "behavior-napot-allow",
    "behavior-napot-deny",
    "behavior-off",
    "behavior-catch-all",
)
_CVA6_PILOT_TOHOST_SCHEMA_VERSION = 1
_CVA6_PILOT_TOHOST_VERSION_SHIFT = 56
_CVA6_PILOT_TOHOST_KIND_SHIFT = 52
_CVA6_PILOT_TOHOST_VERSION_MASK = 0xF
_CVA6_PILOT_TOHOST_KIND_MASK = 0xF
_CVA6_PILOT_TOHOST_READBACK_KIND = 1
_CVA6_PILOT_TOHOST_LOCK_KIND = 2
_CVA6_PILOT_TOHOST_BEHAVIOR_KIND = 3
_CVA6_PILOT_CFG_SHIFT_1 = 32
_CVA6_PILOT_CFG_SHIFT_2 = 40
_CVA6_PILOT_ALLOWED_SHIFT = 8
_CVA6_TRACE_SLOT_BYTES = 4
_CVA6_TRACE_VALUE_SPACE = 256
_CVA6_TRACE_SLOT_STRIDE_BYTES = _CVA6_TRACE_VALUE_SPACE * _CVA6_TRACE_SLOT_BYTES
_CVA6_TRACE_SENTINEL_START_SLOT = 16
_CVA6_TRACE_SENTINEL_END_SLOT = 17
_CVA6_TRACE_TABLE_SLOTS = _CVA6_TRACE_SENTINEL_END_SLOT + 1
_CVA6_TRACE_TABLE_BYTES = _CVA6_TRACE_TABLE_SLOTS * _CVA6_TRACE_SLOT_STRIDE_BYTES
_CVA6_FORMAL_PLAN_FILENAME = "cva6-formal-batch-plan.json"
_CVA6_FORMAL_RECORDS_FILENAME = "off-state-records.jsonl"
_CVA6_FORMAL_CHARACTERIZATION_FILENAME = "off-state-characterization.json"
_CVA6_FORMAL_ANALYSIS_FILENAME = "off-state-analysis.json"
_CVA6_FORMAL_SUMMARY_FILENAME = "cva6-formal-batch-summary.json"


def encode_cva6_pilot_readback_payload(
    *,
    requested_cfg: int,
    readback_cfg_1: int,
    readback_cfg_2: int,
    pmpaddr_value: int = 0,
) -> int:
    del requested_cfg
    raw = _encode_cva6_pilot_header(_CVA6_PILOT_TOHOST_READBACK_KIND)
    raw |= (readback_cfg_1 & 0xFF) << _CVA6_PILOT_CFG_SHIFT_1
    raw |= (readback_cfg_2 & 0xFF) << _CVA6_PILOT_CFG_SHIFT_2
    raw |= pmpaddr_value & 0xFFFFFFFF
    return _encode_cva6_pilot_tohost(raw)


def encode_cva6_pilot_lock_payload(
    *,
    pmpaddr_after: int,
    cfg_after_1: int,
    cfg_after_2: int,
) -> int:
    raw = _encode_cva6_pilot_header(_CVA6_PILOT_TOHOST_LOCK_KIND)
    raw |= (cfg_after_1 & 0xFF) << _CVA6_PILOT_CFG_SHIFT_1
    raw |= (cfg_after_2 & 0xFF) << _CVA6_PILOT_CFG_SHIFT_2
    raw |= pmpaddr_after & 0xFFFFFFFF
    return _encode_cva6_pilot_tohost(raw)


def encode_cva6_pilot_behavior_payload(*, allowed: bool, mcause: int) -> int:
    raw = _encode_cva6_pilot_header(_CVA6_PILOT_TOHOST_BEHAVIOR_KIND)
    if allowed:
        raw |= 1 << _CVA6_PILOT_ALLOWED_SHIFT
    raw |= mcause & 0xFF
    return _encode_cva6_pilot_tohost(raw)


def build_cva6_pilot_plan(
    *,
    entry_index: int,
    reset_count: int,
    access: str = CVA6_SUPPORTED_ACCESS,
    size: int = 4,
    include_main_cases: bool = False,
) -> dict[str, Any]:
    if entry_index != 0:
        raise ValueError("CVA6 pilot currently supports entry_index=0 only")
    if reset_count <= 0:
        raise ValueError("reset_count must be positive")
    if access != CVA6_SUPPORTED_ACCESS:
        raise ValueError(f"CVA6 pilot currently supports access={CVA6_SUPPORTED_ACCESS!r} only")
    if size != 4:
        raise ValueError("CVA6 pilot currently supports size=4 only")
    requested_raw_vocabulary = build_raw_state_universe(CVA6_SUPPORTED_PROFILE)
    cases: list[dict[str, Any]] = []
    for reset_index in range(reset_count):
        reset_id = f"reset-{reset_index:03d}"
        for case_kind in _PILOT_CASE_ORDER:
            cases.append(_build_control_case(case_kind, entry_index=entry_index, reset_id=reset_id))
        if include_main_cases:
            cases.extend(_build_main_cases(entry_index=entry_index, reset_id=reset_id))

    return {
        "schema_version": CVA6_PILOT_PLAN_SCHEMA_VERSION,
        "artifact_kind": CVA6_PILOT_PLAN_KIND,
        "profile_requested": CVA6_SUPPORTED_PROFILE,
        "entry_index": entry_index,
        "reset_count": reset_count,
        "access": access,
        "size": size,
        "include_main_cases": bool(include_main_cases),
        "requested_raw_vocabulary": requested_raw_vocabulary,
        "cases": cases,
    }


def build_cva6_formal_batch_plan(
    *,
    entry_index: int,
    reset_count: int,
    access: str = CVA6_SUPPORTED_ACCESS,
    size: int = 4,
) -> dict[str, Any]:
    if entry_index != 0:
        raise ValueError("CVA6 formal batch currently supports entry_index=0 only")
    if reset_count <= 0:
        raise ValueError("reset_count must be positive")
    if access != CVA6_SUPPORTED_ACCESS:
        raise ValueError(f"CVA6 formal batch currently supports access={CVA6_SUPPORTED_ACCESS!r} only")
    if size != 4:
        raise ValueError("CVA6 formal batch currently supports size=4 only")
    requested_raw_vocabulary = build_raw_state_universe(CVA6_SUPPORTED_PROFILE)
    pre_control_cases: list[dict[str, Any]] = []
    post_control_cases: list[dict[str, Any]] = []
    main_cases: list[dict[str, Any]] = []
    expected_main_case_ids: list[str] = []
    expected_execution_case_ids: list[str] = []
    for reset_index in range(reset_count):
        reset_id = f"reset-{reset_index:03d}"
        pre_ids = _control_case_ids_for_phase(reset_id, phase="pre")
        post_ids = _control_case_ids_for_phase(reset_id, phase="post")
        current_pre = [
            _build_control_case(case_kind, entry_index=entry_index, reset_id=reset_id, phase="pre")
            for case_kind in _PILOT_CASE_ORDER
        ]
        current_post = [
            _build_control_case(case_kind, entry_index=entry_index, reset_id=reset_id, phase="post")
            for case_kind in _PILOT_CASE_ORDER
        ]
        current_main = _build_main_cases(entry_index=entry_index, reset_id=reset_id)
        for case in current_main:
            case["case_group"] = "main"
            case["associated_control_case_ids"] = _associated_control_case_ids(
                reset_id,
                subexperiment=str(case["subexperiment"]),
                pre_ids=pre_ids,
                post_ids=post_ids,
            )
            case["control_group_id"] = f"{reset_id}::{case['subexperiment']}"
        pre_control_cases.extend(current_pre)
        post_control_cases.extend(current_post)
        main_cases.extend(current_main)
        expected_execution_case_ids.extend([item["case_id"] for item in current_pre])
        expected_execution_case_ids.extend([item["case_id"] for item in current_main])
        expected_execution_case_ids.extend([item["case_id"] for item in current_post])
        expected_main_case_ids.extend([item["case_id"] for item in current_main])
    return {
        "schema_version": CVA6_FORMAL_BATCH_PLAN_SCHEMA_VERSION,
        "artifact_kind": CVA6_FORMAL_BATCH_PLAN_KIND,
        "profile_requested": CVA6_SUPPORTED_PROFILE,
        "entry_index": entry_index,
        "entry_label": "first-writable-entry",
        "reset_count": reset_count,
        "access": access,
        "size": size,
        "requested_raw_vocabulary": requested_raw_vocabulary,
        "main_case_count": len(main_cases),
        "pre_control_cases": pre_control_cases,
        "post_control_cases": post_control_cases,
        "main_cases": main_cases,
        "expected_main_case_ids": expected_main_case_ids,
        "expected_execution_case_ids": expected_execution_case_ids,
    }


def render_cva6_pilot_assembly(case: dict[str, Any]) -> str:
    subexperiment = str(case.get("subexperiment") or "")
    if subexperiment == "readback":
        return _render_readback_case(case)
    if subexperiment == "lock":
        return _render_lock_case(case)
    if subexperiment == "behavior":
        return _render_behavior_case(case)
    raise ValueError(f"unsupported CVA6 pilot subexperiment {subexperiment!r}")


def parse_cva6_pilot_log(
    case: dict[str, Any],
    *,
    log_text: str,
    dut_status: str,
    failure_class: str | None,
    reason: str | None,
) -> dict[str, Any]:
    case_kind = str(case.get("case_kind") or "")
    termination_mode = str(case.get("termination_mode") or "pass-tohost")
    parsed: dict[str, Any] = {
        "schema_version": CVA6_PILOT_RESULT_SCHEMA_VERSION,
        "artifact_kind": CVA6_PILOT_RESULT_KIND,
        "case_id": str(case.get("case_id") or ""),
        "case_kind": case_kind,
        "dut_status": dut_status,
        "failure_class": failure_class,
        "reason": reason,
        "execution_status": "completed",
    }
    if dut_status == "timeout":
        if termination_mode != "host-timeout":
            parsed["execution_status"] = "harness-error"
            return parsed
    elif dut_status not in {"pass", "fail", "observed"}:
        parsed["execution_status"] = "harness-error"
        return parsed

    subexperiment = str(case.get("subexperiment") or "")
    if subexperiment == "readback":
        return _parse_readback_case(case, log_text=log_text, base=parsed)
    if subexperiment == "lock":
        return _parse_lock_case(case, log_text=log_text, base=parsed)
    if subexperiment == "behavior":
        return _parse_behavior_case(case, log_text=log_text, base=parsed)
    parsed["execution_status"] = "harness-error"
    parsed["reason"] = f"unsupported subexperiment {subexperiment!r}"
    return parsed


def run_cva6_pilot_case(
    case: dict[str, Any],
    *,
    out_dir: Path,
    reset_command: list[str],
    per_case_timeout_seconds: int = 60,
    chipyard_dir: Path = DEFAULT_CLEAN_CHIPYARD_DIR,
    dut_bin: Path | None = None,
    compile_runner: Callable[[list[str]], Any] | None = None,
    reset_runner: Callable[[list[str]], Any] | None = None,
    dut_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    if not reset_command:
        raise ValueError("reset_command must be non-empty")

    root = Path(__file__).resolve().parents[1]
    compile_script = root / "scripts" / "compile_one.sh"
    case_dir = Path(out_dir).resolve() / str(case["case_id"])
    case_dir.mkdir(parents=True, exist_ok=True)
    case_path = case_dir / "case.json"
    asm_path = case_dir / f"{case['case_id']}.S"
    elf_path = case_dir / f"{case['case_id']}.elf"
    log_path = case_dir / f"{case['case_id']}.log"
    result_path = case_dir / "result.json"

    write_json(case_path, dict(case))
    asm_path.write_text(render_cva6_pilot_assembly(case), encoding="ascii")

    reset_impl = reset_runner or _run_completed_process
    compile_impl = compile_runner or _run_completed_process
    reset_result = reset_impl(list(reset_command))
    if int(getattr(reset_result, "returncode", 1)) != 0:
        result = _harness_error_result(
            case,
            failure_class="reset-failed",
            reason="reset command failed",
        )
        write_json(result_path, result)
        return result

    compile_command = ["sh", str(compile_script), str(asm_path), str(elf_path)]
    compile_result = compile_impl(list(compile_command))
    if int(getattr(compile_result, "returncode", 1)) != 0:
        log_path.write_text(str(getattr(compile_result, "stdout", "") or ""), encoding="utf-8", errors="replace")
        result = _harness_error_result(
            case,
            failure_class="compile-failed",
            reason="compile failed",
        )
        result["log"] = str(log_path)
        write_json(result_path, result)
        return result

    compiled_case = dict(case)
    trace_table_base = _elf_symbol_address(elf_path, "trace_table")
    if trace_table_base is not None:
        compiled_case["trace_table_base"] = f"0x{trace_table_base:x}"
        write_json(case_path, compiled_case)

    dut_impl = dut_factory or _default_cva6_dut_factory
    dut = dut_impl(chipyard_dir=chipyard_dir, dut_bin=dut_bin)
    effective_timeout_seconds = per_case_timeout_seconds
    if str(compiled_case.get("termination_mode") or "") == "host-timeout":
        try:
            requested_timeout = int(compiled_case.get("host_timeout_seconds") or effective_timeout_seconds)
        except (TypeError, ValueError):
            requested_timeout = effective_timeout_seconds
        effective_timeout_seconds = min(effective_timeout_seconds, requested_timeout)
    start = time.monotonic()
    dut_result = dut.run(elf_path, timeout_seconds=effective_timeout_seconds, log_path=log_path)
    elapsed = time.monotonic() - start
    log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    parse_log_text = log_text
    if str(compiled_case.get("termination_mode") or "") == "host-timeout":
        parse_log_text = _capture_first_trace_frame(log_text, case=compiled_case)

    result = parse_cva6_pilot_log(
        compiled_case,
        log_text=parse_log_text,
        dut_status=str(getattr(dut_result, "status", "")),
        failure_class=getattr(dut_result, "failure_class", None),
        reason=getattr(dut_result, "reason", None),
    )
    execution_binding = _build_execution_binding(
        root=root,
        case=compiled_case,
        reset_command=list(reset_command),
        compile_command=compile_command,
        dut=dut,
        elf_path=elf_path,
        log_text=log_text,
        log_path=log_path,
    )
    result["execution_binding"] = execution_binding
    _attach_execution_binding(result, execution_binding)
    result["elapsed_seconds"] = elapsed
    result["log"] = str(log_path)
    write_json(result_path, result)
    return result


def run_cva6_formal_batch(
    plan: dict[str, Any],
    *,
    out_dir: Path,
    reset_command: list[str],
    per_case_timeout_seconds: int = 60,
    chipyard_dir: Path = DEFAULT_CLEAN_CHIPYARD_DIR,
    dut_bin: Path | None = None,
    case_runner: Callable[..., dict[str, Any]] | None = None,
    argv: list[str] | None = None,
) -> dict[str, Any]:
    if not reset_command:
        raise ValueError("reset_command must be non-empty")
    out_root = Path(out_dir).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    runs_dir = out_root / "runs"
    plan_path = out_root / _CVA6_FORMAL_PLAN_FILENAME
    records_path = out_root / _CVA6_FORMAL_RECORDS_FILENAME
    characterization_path = out_root / _CVA6_FORMAL_CHARACTERIZATION_FILENAME
    analysis_path = out_root / _CVA6_FORMAL_ANALYSIS_FILENAME
    summary_path = out_root / _CVA6_FORMAL_SUMMARY_FILENAME
    for path in (plan_path, records_path, characterization_path, analysis_path, summary_path):
        if path.exists():
            raise ValueError(f"formal batch output already exists: {path}")
    write_json(plan_path, dict(plan))

    runner = case_runner or run_cva6_pilot_case
    pre_control_results: list[dict[str, Any]] = []
    post_control_results: list[dict[str, Any]] = []
    main_case_results: list[dict[str, Any]] = []
    actual_execution_case_ids: list[str] = []
    executed_results: dict[str, dict[str, Any]] = {}
    pre_case_by_id = {str(item["case_id"]): dict(item) for item in list(plan.get("pre_control_cases") or [])}
    main_case_by_id = {str(item["case_id"]): dict(item) for item in list(plan.get("main_cases") or [])}
    post_case_by_id = {str(item["case_id"]): dict(item) for item in list(plan.get("post_control_cases") or [])}
    for expected_case_id in [str(item) for item in plan.get("expected_execution_case_ids") or []]:
        if expected_case_id in pre_case_by_id:
            case = pre_case_by_id[expected_case_id]
            case_bucket = pre_control_results
            is_main = False
        elif expected_case_id in main_case_by_id:
            case = main_case_by_id[expected_case_id]
            case_bucket = main_case_results
            is_main = True
        elif expected_case_id in post_case_by_id:
            case = post_case_by_id[expected_case_id]
            case_bucket = post_control_results
            is_main = False
        else:
            raise ValueError(f"formal plan references unknown case_id {expected_case_id}")
        result = runner(
            dict(case),
            out_dir=runs_dir,
            reset_command=list(reset_command),
            per_case_timeout_seconds=per_case_timeout_seconds,
            chipyard_dir=chipyard_dir,
            dut_bin=dut_bin,
        )
        case_id = str(result.get("case_id") or "")
        actual_execution_case_ids.append(case_id)
        executed_results[case_id] = dict(result)
        if is_main:
            record = _formal_main_record(case, result)
            append_characterization_records(records_path, [record])
        case_bucket.append(_formal_case_result_summary(result))

    _validate_case_id_sequence(
        expected=[str(item) for item in plan.get("expected_execution_case_ids") or []],
        actual=actual_execution_case_ids,
        label="formal execution",
    )
    _validate_case_id_sequence(
        expected=[str(item) for item in plan.get("expected_main_case_ids") or []],
        actual=[str(item["case_id"]) for item in main_case_results],
        label="formal main-case",
    )
    _validate_associated_controls(
        plan,
        executed_results=executed_results,
    )
    raw_log_validation = _validate_raw_log_hashes(executed_results.values())
    if not raw_log_validation["all_valid"]:
        raise ValueError("raw log hash validation failed")

    main_records = _load_jsonl_records(records_path)
    characterization = _build_formal_characterization_artifact(
        plan,
        records=main_records,
        argv=argv,
        reset_command=list(reset_command),
        executed_results=executed_results,
    )
    analysis = analyze_characterization_artifact(characterization)
    write_json(characterization_path, characterization)
    write_json(analysis_path, analysis)

    summary = {
        "schema_version": CVA6_FORMAL_BATCH_SUMMARY_SCHEMA_VERSION,
        "artifact_kind": CVA6_FORMAL_BATCH_SUMMARY_KIND,
        "plan_artifact_kind": CVA6_FORMAL_BATCH_PLAN_KIND,
        "characterization_artifact_kind": OFF_STATE_ARTIFACT_KIND,
        "analysis_artifact_kind": OFF_STATE_ANALYSIS_KIND,
        "profile_requested": str(plan.get("profile_requested") or CVA6_SUPPORTED_PROFILE),
        "entry_index": int(plan.get("entry_index") or 0),
        "reset_count": int(plan.get("reset_count") or 0),
        "main_case_count": len(main_case_results),
        "expected_main_case_ids": [str(item) for item in plan.get("expected_main_case_ids") or []],
        "expected_execution_case_ids": [str(item) for item in plan.get("expected_execution_case_ids") or []],
        "records_path": str(records_path),
        "characterization_path": str(characterization_path),
        "analysis_path": str(analysis_path),
        "pre_control_results": pre_control_results,
        "main_case_results": main_case_results,
        "post_control_results": post_control_results,
        "raw_log_validation": raw_log_validation,
        "analysis_summary": {
            "record_count": int(analysis.get("record_count") or 0),
            "execution_status_counts": dict(analysis.get("execution_status_counts") or {}),
            "mapper_witness_set": dict(analysis.get("mapper_witness_set") or {}),
        },
    }
    write_json(summary_path, summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Materialize and run the CVA6 PMP OFF-state pilot controls")
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan")
    plan.add_argument("--entry-index", type=int, default=0)
    plan.add_argument("--reset-count", type=int, default=3)
    plan.add_argument("--include-main-cases", action="store_true")
    plan.add_argument("--out", type=Path, required=True)

    run_case = subparsers.add_parser("run-case")
    run_case.add_argument("--case-json", type=Path, required=True)
    run_case.add_argument("--out", type=Path, required=True)
    run_case.add_argument("--reset-command", nargs="+", required=True)
    run_case.add_argument("--per-case-timeout", type=int, default=60)
    run_case.add_argument("--chipyard-dir", type=Path, default=DEFAULT_CLEAN_CHIPYARD_DIR)
    run_case.add_argument("--dut-bin", type=Path, default=None)

    formal_plan = subparsers.add_parser("formal-plan")
    formal_plan.add_argument("--entry-index", type=int, default=0)
    formal_plan.add_argument("--reset-count", type=int, default=3)
    formal_plan.add_argument("--out", type=Path, required=True)

    formal_run = subparsers.add_parser("formal-run")
    formal_run.add_argument("--entry-index", type=int, default=0)
    formal_run.add_argument("--reset-count", type=int, default=3)
    formal_run.add_argument("--out", type=Path, required=True)
    formal_run.add_argument("--reset-command", nargs="+", required=True)
    formal_run.add_argument("--per-case-timeout", type=int, default=60)
    formal_run.add_argument("--chipyard-dir", type=Path, default=DEFAULT_CLEAN_CHIPYARD_DIR)
    formal_run.add_argument("--dut-bin", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "plan":
        plan = build_cva6_pilot_plan(
            entry_index=args.entry_index,
            reset_count=args.reset_count,
            include_main_cases=bool(args.include_main_cases),
        )
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        write_json(out_dir / "cva6-pilot-plan.json", plan)
        return 0

    if args.command == "formal-plan":
        plan = build_cva6_formal_batch_plan(
            entry_index=args.entry_index,
            reset_count=args.reset_count,
        )
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        write_json(out_dir / _CVA6_FORMAL_PLAN_FILENAME, plan)
        return 0

    if args.command == "formal-run":
        plan = build_cva6_formal_batch_plan(
            entry_index=args.entry_index,
            reset_count=args.reset_count,
        )
        run_cva6_formal_batch(
            plan,
            out_dir=args.out,
            reset_command=list(args.reset_command),
            per_case_timeout_seconds=args.per_case_timeout,
            chipyard_dir=args.chipyard_dir,
            dut_bin=args.dut_bin,
            argv=list(argv or []),
        )
        return 0

    case = json.loads(Path(args.case_json).read_text(encoding="utf-8"))
    run_cva6_pilot_case(
        case,
        out_dir=args.out,
        reset_command=list(args.reset_command),
        per_case_timeout_seconds=args.per_case_timeout,
        chipyard_dir=args.chipyard_dir,
        dut_bin=args.dut_bin,
    )
    return 0


def _control_case_ids_for_phase(reset_id: str, *, phase: str) -> dict[str, str]:
    if phase not in _CVA6_CONTROL_PHASES:
        raise ValueError(f"unsupported CVA6 control phase {phase!r}")
    return {
        case_kind: f"{reset_id}__{phase}__{case_kind}"
        for case_kind in _PILOT_CASE_ORDER
    }


def _associated_control_case_ids(
    reset_id: str,
    *,
    subexperiment: str,
    pre_ids: dict[str, str],
    post_ids: dict[str, str],
) -> list[str]:
    del reset_id
    if subexperiment == "readback":
        return [pre_ids["readback-off-control"], post_ids["readback-off-control"]]
    if subexperiment == "lock":
        return [pre_ids["lock-positive-control"], post_ids["lock-positive-control"]]
    return [
        pre_ids["behavior-napot-allow"],
        pre_ids["behavior-napot-deny"],
        pre_ids["behavior-off"],
        pre_ids["behavior-catch-all"],
        post_ids["behavior-napot-allow"],
        post_ids["behavior-napot-deny"],
        post_ids["behavior-off"],
        post_ids["behavior-catch-all"],
    ]


def _formal_case_result_summary(result: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "case_id": str(result.get("case_id") or ""),
        "case_kind": str(result.get("case_kind") or ""),
        "execution_status": str(result.get("execution_status") or ""),
        "control_pass": bool(result.get("control_pass")),
        "failure_class": result.get("failure_class"),
        "reason": result.get("reason"),
        "log": result.get("log"),
    }
    binding = dict(result.get("execution_binding") or {})
    if binding:
        summary["execution_binding"] = {
            "source_git_sha": binding.get("source_git_sha"),
            "experiment_branch": binding.get("experiment_branch"),
            "dut_name": binding.get("dut_name"),
            "simulator_version": binding.get("simulator_version"),
            "payload_sha256": binding.get("payload_sha256"),
            "raw_log_sha256": binding.get("raw_log_sha256"),
            "dut_command": list(binding.get("dut_command") or []),
            "reset_command": list(binding.get("reset_command") or []),
            "reset_id": binding.get("reset_id"),
            "transport": dict(binding.get("transport") or {}),
        }
    if "transport_completion" in result:
        summary["transport_completion"] = dict(result["transport_completion"])
    return summary


def _formal_main_record(case: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    parsed = dict(result.get("parsed_record") or {})
    record = parsed or {
        "record_schema_version": OFF_STATE_RECORD_SCHEMA_VERSION,
        "dut": "cva6",
        "profile_requested": str(case.get("profile_requested") or CVA6_SUPPORTED_PROFILE),
        "profile_observed": str(case.get("profile_requested") or CVA6_SUPPORTED_PROFILE),
        "entry_index": int(case.get("entry_index") or 0),
        "reset_id": str(case.get("reset_id") or ""),
        "subexperiment": str(case.get("subexperiment") or ""),
        "requested_bits": dict(case.get("requested_bits") or {}),
        "spec_status": str(case.get("spec_status") or spec_status_for_off_state(CVA6_SUPPORTED_PROFILE, case.get("requested_bits") or {})),
        "execution_status": str(result.get("execution_status") or "harness-error"),
    }
    record.setdefault("record_schema_version", OFF_STATE_RECORD_SCHEMA_VERSION)
    record.setdefault("dut", "cva6")
    record.setdefault("profile_requested", str(case.get("profile_requested") or CVA6_SUPPORTED_PROFILE))
    record.setdefault("profile_observed", str(case.get("profile_requested") or CVA6_SUPPORTED_PROFILE))
    record.setdefault("entry_index", int(case.get("entry_index") or 0))
    record.setdefault("reset_id", str(case.get("reset_id") or ""))
    record.setdefault("subexperiment", str(case.get("subexperiment") or ""))
    record.setdefault("requested_bits", dict(case.get("requested_bits") or {}))
    record.setdefault(
        "spec_status",
        str(case.get("spec_status") or spec_status_for_off_state(CVA6_SUPPORTED_PROFILE, case.get("requested_bits") or {})),
    )
    record["execution_status"] = str(result.get("execution_status") or record.get("execution_status") or "harness-error")
    record["case_id"] = str(result.get("case_id") or case.get("case_id") or "")
    record["case_kind"] = str(result.get("case_kind") or case.get("case_kind") or "")
    record["case_group"] = "main"
    record["associated_control_case_ids"] = list(case.get("associated_control_case_ids") or [])
    record["control_group_id"] = str(case.get("control_group_id") or "")
    if result.get("failure_class") is not None:
        record["failure_class"] = result.get("failure_class")
    if result.get("reason") is not None:
        record["reason"] = result.get("reason")
    if result.get("log") is not None:
        record["log_path"] = str(result.get("log"))
    if "transport_completion" in result:
        record["transport_completion"] = dict(result["transport_completion"])
    binding = dict(result.get("execution_binding") or {})
    if binding:
        _attach_execution_binding({"parsed_record": record, "execution_binding": binding}, binding)
    if (
        str(record.get("subexperiment") or "") == "behavior"
        and str(result.get("execution_status") or "") == "completed"
        and "requested_raw_bin_id" in case
        and "normalized_record" not in record
    ):
        record["normalized_record"] = _normalized_record_for_main_behavior(case, record)
        record.setdefault("raw_trace_sha256", str(record.get("raw_log_sha256") or ""))
        record.setdefault("supports_fault_stage", True)
        record.setdefault("supports_smepmp", False)
    if (
        str(record.get("subexperiment") or "") == "behavior"
        and "normalized_record" in record
        and "raw_trace_sha256" not in record
    ):
        record["raw_trace_sha256"] = str(record.get("raw_log_sha256") or "")
    return record


def _validate_case_id_sequence(*, expected: list[str], actual: list[str], label: str) -> None:
    if len(set(expected)) != len(expected):
        raise ValueError(f"{label} expected case ids must be unique")
    if len(set(actual)) != len(actual):
        raise ValueError(f"{label} duplicate case ids detected")
    if actual != expected:
        missing = [item for item in expected if item not in set(actual)]
        unexpected = [item for item in actual if item not in set(expected)]
        if missing or unexpected:
            raise ValueError(
                f"{label} case closure mismatch: missing={missing[:5]} unexpected={unexpected[:5]}"
            )
        raise ValueError(f"{label} case order mismatch")


def _validate_associated_controls(
    plan: dict[str, Any],
    *,
    executed_results: dict[str, dict[str, Any]],
) -> None:
    expected_controls = {
        str(item["case_id"])
        for item in list(plan.get("pre_control_cases") or []) + list(plan.get("post_control_cases") or [])
    }
    for case_id in expected_controls:
        result = dict(executed_results.get(case_id) or {})
        if str(result.get("execution_status") or "") != "completed":
            raise ValueError(f"control {case_id} did not complete")
        if not bool(result.get("control_pass")):
            raise ValueError(f"control {case_id} did not pass")
    for case in list(plan.get("main_cases") or []):
        for control_case_id in list(case.get("associated_control_case_ids") or []):
            result = dict(executed_results.get(control_case_id) or {})
            if str(result.get("execution_status") or "") != "completed" or not bool(result.get("control_pass")):
                raise ValueError(
                    f"associated control {control_case_id} not valid for main case {case.get('case_id')}"
                )


def _validate_raw_log_hashes(results: Any) -> dict[str, Any]:
    checked = 0
    mismatches: list[dict[str, str]] = []
    for result in results:
        item = dict(result or {})
        binding = dict(item.get("execution_binding") or {})
        log_path = item.get("log")
        expected = str(binding.get("raw_log_sha256") or "")
        if not log_path or not expected:
            continue
        path = Path(str(log_path))
        if not path.exists():
            mismatches.append({"case_id": str(item.get("case_id") or ""), "reason": "missing-log"})
            continue
        actual = sha256_file(path)
        checked += 1
        if actual != expected:
            mismatches.append(
                {
                    "case_id": str(item.get("case_id") or ""),
                    "expected": expected,
                    "actual": actual,
                }
            )
    return {
        "checked_count": checked,
        "mismatch_count": len(mismatches),
        "all_valid": not mismatches,
        "mismatches": mismatches,
    }


def _load_jsonl_records(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _build_formal_characterization_artifact(
    plan: dict[str, Any],
    *,
    records: list[dict[str, Any]],
    argv: list[str] | None,
    reset_command: list[str],
    executed_results: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1]
    metadata = capture_repo_metadata(root, argv=argv or [])
    first_binding = {}
    for result in executed_results.values():
        binding = dict(result.get("execution_binding") or {})
        if binding:
            first_binding = binding
            break
    metadata.update(_selected_batch_metadata(first_binding))
    metadata["reset_command"] = list(reset_command)
    requested_raw_vocabularies = {
        CVA6_SUPPORTED_PROFILE: build_raw_state_universe(CVA6_SUPPORTED_PROFILE),
    }
    spec_encoding_sets = build_spec_encoding_sets([CVA6_SUPPORTED_PROFILE])
    return {
        "schema_version": OFF_STATE_SCHEMA_VERSION,
        "artifact_kind": OFF_STATE_ARTIFACT_KIND,
        "record_schema_version": OFF_STATE_RECORD_SCHEMA_VERSION,
        "metadata": metadata,
        "dut": "cva6",
        "profiles": [CVA6_SUPPORTED_PROFILE],
        "entry_indices": [int(plan.get("entry_index") or 0)],
        "reset_count": int(plan.get("reset_count") or 0),
        "spec_encoding_sets": spec_encoding_sets,
        "requested_raw_vocabularies": requested_raw_vocabularies,
        "requested_raw_set": {
            profile: list(manifest["bin_ids"])
            for profile, manifest in requested_raw_vocabularies.items()
        },
        "spec_defined_set": {
            profile: list(spec_encoding_sets[profile]["spec-defined"])
            for profile in requested_raw_vocabularies
        },
        "plan": dict(plan),
        "record_count": len(records),
        "records": [dict(item) for item in records],
    }


def _selected_batch_metadata(binding: dict[str, Any]) -> dict[str, Any]:
    selected: dict[str, Any] = {}
    for key in (
        "dut_name",
        "dut_binary_sha256",
        "simulator_version",
        "isa_profile_configuration",
        "xlen",
        "reset_method",
        "experiment_branch",
    ):
        if key in binding:
            selected[key] = binding[key]
    command_line = list(binding.get("dut_command") or binding.get("command_line") or [])
    if command_line:
        selected["command_line"] = command_line
    return selected


def _build_control_case(
    case_kind: str,
    *,
    entry_index: int,
    reset_id: str,
    phase: str | None = None,
) -> dict[str, Any]:
    if phase is not None and phase not in _CVA6_CONTROL_PHASES:
        raise ValueError(f"unsupported CVA6 control phase {phase!r}")
    target_pmpaddr = PmpEntry.encode_napot(base=TARGET_BASE, size=TARGET_SIZE)
    catchall_pmpaddr = PmpEntry.encode_napot(base=MEM_BASE, size=0x20000)
    case_id = f"{reset_id}__{case_kind}" if phase is None else f"{reset_id}__{phase}__{case_kind}"
    common: dict[str, Any] = {
        "case_id": case_id,
        "case_kind": case_kind,
        "reset_id": reset_id,
        "profile_requested": CVA6_SUPPORTED_PROFILE,
        "entry_index": entry_index,
        "termination_mode": "pass-tohost",
        "case_group": "control",
    }
    if phase is not None:
        common["control_phase"] = phase

    if case_kind == "readback-off-control":
        common.update(
            {
                "subexperiment": "readback",
                "requested_bits": {"l": 0, "r": 0, "w": 0, "x": 0},
                "requested_cfg_byte": 0x00,
                "target_pmpaddr": target_pmpaddr,
            }
        )
        return common

    if case_kind == "lock-positive-control":
        common.update(
            {
                "subexperiment": "lock",
                "requested_bits": {"l": 1, "r": 1, "w": 0, "x": 0},
                "locked_cfg_byte": _cfg_byte(AddressMode.NAPOT, read=True, write=False, execute=False, locked=True),
                "target_pmpaddr": target_pmpaddr,
                "alternate_pmpaddr": PmpEntry.encode_napot(base=TARGET_BASE + TARGET_SIZE, size=TARGET_SIZE),
                "attempt_cfg_byte": 0x00,
            }
        )
        return common

    if case_kind == "behavior-catch-all":
        pmp_entries = [
            _entry_dict(
                index=1,
                mode=AddressMode.NAPOT,
                pmpaddr=catchall_pmpaddr,
                read=False,
                write=False,
                execute=False,
                locked=False,
            )
        ]
        pmpcfg0_value = _cfg_byte(AddressMode.NAPOT, read=False, write=False, execute=False, locked=False) << 8
        expected_allow = False
        requested_bits = {"l": 0, "r": 0, "w": 0, "x": 0}
    else:
        catchall_allow = case_kind == "behavior-napot-deny"
        catchall_entry = _entry_dict(
            index=1,
            mode=AddressMode.NAPOT,
            pmpaddr=catchall_pmpaddr,
            read=catchall_allow,
            write=False,
            execute=False,
            locked=False,
        )
        catchall_cfg = _cfg_byte(
            AddressMode.NAPOT,
            read=catchall_allow,
            write=False,
            execute=False,
            locked=False,
        )
        if case_kind == "behavior-napot-allow":
            target_entry = _entry_dict(
                index=0,
                mode=AddressMode.NAPOT,
                pmpaddr=target_pmpaddr,
                read=True,
                write=False,
                execute=False,
                locked=False,
            )
            target_cfg = _cfg_byte(AddressMode.NAPOT, read=True, write=False, execute=False, locked=False)
            expected_allow = True
            requested_bits = {"l": 0, "r": 1, "w": 0, "x": 0}
        elif case_kind == "behavior-napot-deny":
            target_entry = _entry_dict(
                index=0,
                mode=AddressMode.NAPOT,
                pmpaddr=target_pmpaddr,
                read=False,
                write=False,
                execute=False,
                locked=False,
            )
            target_cfg = _cfg_byte(AddressMode.NAPOT, read=False, write=False, execute=False, locked=False)
            expected_allow = False
            requested_bits = {"l": 0, "r": 0, "w": 0, "x": 0}
        elif case_kind == "behavior-off":
            target_entry = _entry_dict(
                index=0,
                mode=AddressMode.OFF,
                pmpaddr=target_pmpaddr,
                read=False,
                write=False,
                execute=False,
                locked=False,
            )
            target_cfg = 0x00
            expected_allow = False
            requested_bits = {"l": 0, "r": 0, "w": 0, "x": 0}
        else:
            raise ValueError(f"unsupported CVA6 pilot control {case_kind!r}")
        pmp_entries = [target_entry, catchall_entry]
        pmpcfg0_value = target_cfg | (catchall_cfg << 8)

    common.update(
        {
            "subexperiment": "behavior",
            "requested_bits": requested_bits,
            "access": CVA6_SUPPORTED_ACCESS,
            "size": 4,
            "expected_allow": expected_allow,
            "target_address": TARGET_BASE,
            "target_pmpaddr": target_pmpaddr,
            "catchall_pmpaddr": catchall_pmpaddr,
            "pmp_entries": pmp_entries,
            "pmpcfg0_value": pmpcfg0_value,
            "bapc_case": _bapc_case(case_kind, pmp_entries=pmp_entries, expected_allow=expected_allow),
        }
    )
    return common


def _build_main_cases(*, entry_index: int, reset_id: str) -> list[dict[str, Any]]:
    target_pmpaddr = PmpEntry.encode_napot(base=TARGET_BASE, size=TARGET_SIZE)
    catchall_pmpaddr = PmpEntry.encode_napot(base=MEM_BASE, size=0x20000)
    catchall_entry = _entry_dict(
        index=1,
        mode=AddressMode.NAPOT,
        pmpaddr=catchall_pmpaddr,
        read=False,
        write=False,
        execute=False,
        locked=False,
    )
    catchall_cfg = _cfg_byte(
        AddressMode.NAPOT,
        read=False,
        write=False,
        execute=False,
        locked=False,
    )
    cases: list[dict[str, Any]] = []
    for subexperiment in ("readback", "lock", "behavior"):
        for encoding in off_state_encodings():
            bits = encoding.as_dict()
            cfg_byte = encoding.cfg_byte()
            raw_bin_id = raw_state_bin_id(CVA6_SUPPORTED_PROFILE, bits)
            case_id = (
                f"{reset_id}__{subexperiment}"
                f"__l{bits['l']}r{bits['r']}w{bits['w']}x{bits['x']}"
            )
            common: dict[str, Any] = {
                "case_id": case_id,
                "case_kind": f"{subexperiment}-off-encoding",
                "reset_id": reset_id,
                "profile_requested": CVA6_SUPPORTED_PROFILE,
                "entry_index": entry_index,
                "subexperiment": subexperiment,
                "case_group": "main",
                "termination_mode": "host-timeout",
                "host_timeout_seconds": 2,
                "requested_bits": bits,
                "requested_cfg_byte": cfg_byte,
                "requested_raw_bin_id": raw_bin_id,
                "spec_status": spec_status_for_off_state(CVA6_SUPPORTED_PROFILE, bits),
                "target_pmpaddr": target_pmpaddr,
            }
            if subexperiment == "readback":
                cases.append(common)
                continue
            if subexperiment == "lock":
                common.update(
                    {
                        "alternate_pmpaddr": PmpEntry.encode_napot(
                            base=TARGET_BASE + TARGET_SIZE,
                            size=TARGET_SIZE,
                        ),
                        "attempt_cfg_byte": 0x00 if cfg_byte != 0x00 else 0x85,
                    }
                )
                cases.append(common)
                continue

            target_entry = _entry_dict(
                index=0,
                mode=AddressMode.OFF,
                pmpaddr=target_pmpaddr,
                read=bool(bits["r"]),
                write=bool(bits["w"]),
                execute=bool(bits["x"]),
                locked=bool(bits["l"]),
            )
            common.update(
                {
                    "access": CVA6_SUPPORTED_ACCESS,
                    "size": 4,
                    "target_address": TARGET_BASE,
                    "catchall_pmpaddr": catchall_pmpaddr,
                    "pmp_entries": [target_entry, catchall_entry],
                    "pmpcfg0_value": cfg_byte | (catchall_cfg << 8),
                }
            )
            cases.append(common)
    return cases


def _bapc_case(case_kind: str, *, pmp_entries: list[dict[str, Any]], expected_allow: bool) -> dict[str, Any]:
    return {
        "name": f"pilot-{case_kind}",
        "profile": CVA6_SUPPORTED_PROFILE,
        "privilege": "M",
        "access": CVA6_SUPPORTED_ACCESS,
        "size": 4,
        "translation": "bare",
        "mprv": True,
        "mpp": "U",
        "physical_address": f"0x{TARGET_BASE:x}",
        "pmp_entries": list(pmp_entries),
        "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
        "expected": {"allowed": expected_allow, "trap_cause": None if expected_allow else 5, "stage": "final"},
        "scenario_hash": f"pilot-{case_kind}",
    }


def _encode_cva6_pilot_header(kind: int) -> int:
    return (
        (_CVA6_PILOT_TOHOST_SCHEMA_VERSION << _CVA6_PILOT_TOHOST_VERSION_SHIFT)
        | ((kind & _CVA6_PILOT_TOHOST_KIND_MASK) << _CVA6_PILOT_TOHOST_KIND_SHIFT)
    )


def _encode_cva6_pilot_tohost(raw_payload: int) -> int:
    return (raw_payload << 1) | 0x1


def _decode_cva6_pilot_payload(log_text: str, *, expected_kind: int) -> dict[str, int] | None:
    observed_tohost = failed_tohost_from_log(log_text)
    if observed_tohost is None:
        return None
    raw_payload = observed_tohost >> 1 if observed_tohost & 0x1 else observed_tohost
    version = (raw_payload >> _CVA6_PILOT_TOHOST_VERSION_SHIFT) & _CVA6_PILOT_TOHOST_VERSION_MASK
    kind = (raw_payload >> _CVA6_PILOT_TOHOST_KIND_SHIFT) & _CVA6_PILOT_TOHOST_KIND_MASK
    if version != _CVA6_PILOT_TOHOST_SCHEMA_VERSION or kind != expected_kind:
        return None
    return {
        "observed_tohost": observed_tohost,
        "raw": raw_payload,
        "kind": kind,
    }


def _trace_table_base(case: dict[str, Any]) -> int | None:
    raw_base = case.get("trace_table_base")
    if raw_base in {None, ""}:
        return None
    try:
        return int(str(raw_base), 0)
    except ValueError:
        return None


def _capture_first_trace_frame(log_text: str, *, case: dict[str, Any]) -> str:
    base = _trace_table_base(case)
    if base is None:
        return log_text
    start_addr = base + (_CVA6_TRACE_SENTINEL_START_SLOT * _CVA6_TRACE_SLOT_STRIDE_BYTES)
    end_addr = base + (_CVA6_TRACE_SENTINEL_END_SLOT * _CVA6_TRACE_SLOT_STRIDE_BYTES)
    start_token = f"vaddr=0x{start_addr:x}"
    end_token = f"vaddr=0x{end_addr:x}"
    collecting = False
    captured: list[str] = []
    for line in str(log_text or "").splitlines():
        if not collecting and start_token not in line:
            continue
        collecting = True
        captured.append(line)
        if end_token in line:
            return "\n".join(captured) + "\n"
    return log_text


def _extract_trace_bytes(
    log_text: str,
    *,
    case: dict[str, Any],
    expected_count: int,
) -> tuple[list[int] | None, str | None]:
    base = _trace_table_base(case)
    if base is None:
        return None, None
    start_addr = base + (_CVA6_TRACE_SENTINEL_START_SLOT * _CVA6_TRACE_SLOT_STRIDE_BYTES)
    end_addr = base + (_CVA6_TRACE_SENTINEL_END_SLOT * _CVA6_TRACE_SLOT_STRIDE_BYTES)
    payload_limit = base + (_CVA6_TRACE_SENTINEL_START_SLOT * _CVA6_TRACE_SLOT_STRIDE_BYTES)
    collecting = False
    frame: list[int] = []
    next_slot = 0
    completed_frames: list[list[int]] = []
    errors: list[str] = []
    saw_trace_probe = False
    for event in parse_probe_events(log_text):
        fields = dict((event or {}).get("fields") or {})
        # CVA6 whitebox transport is carried by vaddr-tagged probe lines. Ignore
        # torn or unrelated probe text without the required field and fail closed
        # unless a single complete sentinel-delimited frame is reconstructed.
        vaddr_text = fields.get("vaddr")
        if not vaddr_text:
            continue
        saw_trace_probe = True
        try:
            vaddr = int(str(vaddr_text), 0)
        except ValueError:
            errors.append("invalid-trace-vaddr")
            continue
        if vaddr == start_addr:
            if collecting or completed_frames:
                errors.append("duplicate-trace-frame")
            collecting = True
            frame = []
            next_slot = 0
            continue
        if vaddr == end_addr:
            if not collecting:
                errors.append("trace-end-without-start")
                continue
            if len(frame) != expected_count:
                errors.append("truncated-trace-frame")
            else:
                completed_frames.append(list(frame))
            collecting = False
            continue
        if not (base <= vaddr < payload_limit):
            continue
        relative = vaddr - base
        slot = relative // _CVA6_TRACE_SLOT_STRIDE_BYTES
        offset = relative % _CVA6_TRACE_SLOT_STRIDE_BYTES
        if slot >= _CVA6_TRACE_SENTINEL_START_SLOT:
            errors.append("trace-slot-out-of-range")
            continue
        if offset % _CVA6_TRACE_SLOT_BYTES != 0:
            errors.append("unaligned-trace-byte")
            continue
        value = offset // _CVA6_TRACE_SLOT_BYTES
        if value >= _CVA6_TRACE_VALUE_SPACE:
            errors.append("trace-byte-out-of-range")
            continue
        if not collecting:
            errors.append("trace-payload-without-start")
            continue
        if slot != next_slot:
            errors.append("out-of-order-trace-slot")
            continue
        frame.append(value)
        next_slot += 1
    if collecting:
        errors.append("unterminated-trace-frame")
    if errors:
        return None, ";".join(dict.fromkeys(errors))
    if len(completed_frames) != 1:
        if saw_trace_probe:
            return None, "missing-complete-trace-frame"
        return None, "missing-trace-probes"
    return completed_frames[0], None


def _little_endian_word(bytes_: list[int]) -> int:
    value = 0
    for index, byte in enumerate(bytes_):
        value |= (int(byte) & 0xFF) << (8 * index)
    return value


def _render_readback_case(case: dict[str, Any]) -> str:
    requested_cfg = int(case.get("requested_cfg_byte") or 0)
    return _emit_program(
        setup_lines=[
            f"    li t0, 0x{int(case['target_pmpaddr']):x}",
            "    csrw pmpaddr0, t0",
            "    csrr s0, pmpaddr0",
            f"    li t0, 0x{requested_cfg:x}",
            "    csrw pmpcfg0, t0",
            "    csrr s1, pmpcfg0",
            "    csrr s2, pmpcfg0",
        ],
        body_lines=_emit_trace_sentinel(_CVA6_TRACE_SENTINEL_START_SLOT)
        + _emit_trace_byte_from_reg("s1", slot=0)
        + _emit_trace_byte_from_reg("s2", slot=1)
        + _emit_trace_word_bytes_from_reg("s0", start_slot=2)
        + _emit_trace_sentinel(_CVA6_TRACE_SENTINEL_END_SLOT)
        + _emit_trace_drain_lines()
        + _successful_completion_lines(case),
        trap_lines=_emit_harness_failure_lines(),
    )


def _render_lock_case(case: dict[str, Any]) -> str:
    locked_cfg = int(case.get("locked_cfg_byte", case.get("requested_cfg_byte") or 0))
    return _emit_program(
        setup_lines=[
            f"    li t0, 0x{int(case['target_pmpaddr']):x}",
            "    csrw pmpaddr0, t0",
            "    csrr s0, pmpaddr0",
            f"    li t0, 0x{locked_cfg:x}",
            "    csrw pmpcfg0, t0",
            f"    li t0, 0x{int(case['alternate_pmpaddr']):x}",
            "    csrw pmpaddr0, t0",
            "    csrr s1, pmpaddr0",
            f"    li t0, 0x{int(case['attempt_cfg_byte']):x}",
            "    csrw pmpcfg0, t0",
            "    csrr s2, pmpcfg0",
            "    csrr s3, pmpcfg0",
        ],
        body_lines=_emit_lock_payload_lines(
            pmpaddr_after_reg="s1",
            cfg_after_1_reg="s2",
            cfg_after_2_reg="s3",
            case=case,
        ),
        trap_lines=_emit_harness_failure_lines(),
    )


def _render_behavior_case(case: dict[str, Any]) -> str:
    target_address = int(case["target_address"])
    trace_prefix = []
    trace_success = []
    trace_trap = []
    if "requested_raw_bin_id" in case:
        trace_prefix = [
            "    csrr s0, pmpcfg0",
            "    csrr s1, pmpcfg0",
            "    csrr s2, pmpaddr0",
        ]
        trace_success = (
            _emit_trace_sentinel(_CVA6_TRACE_SENTINEL_START_SLOT)
            + _emit_trace_byte_from_reg("s0", slot=0)
            + _emit_trace_byte_from_reg("s1", slot=1)
            + _emit_trace_word_bytes_from_reg("s2", start_slot=2)
            + _emit_trace_byte_immediate(1, slot=6)
            + _emit_trace_byte_immediate(0, slot=7)
            + _emit_trace_word_bytes_from_reg("zero", start_slot=8)
            + _emit_trace_sentinel(_CVA6_TRACE_SENTINEL_END_SLOT)
            + _emit_trace_drain_lines()
        )
        trace_trap = (
            _emit_trace_sentinel(_CVA6_TRACE_SENTINEL_START_SLOT)
            + _emit_trace_byte_from_reg("s0", slot=0)
            + _emit_trace_byte_from_reg("s1", slot=1)
            + _emit_trace_word_bytes_from_reg("s2", start_slot=2)
            + _emit_trace_byte_immediate(0, slot=6)
            + _emit_trace_byte_from_reg("t2", slot=7)
            + _emit_trace_word_bytes_from_reg("t3", start_slot=8)
            + _emit_trace_sentinel(_CVA6_TRACE_SENTINEL_END_SLOT)
            + _emit_trace_drain_lines()
        )
    else:
        trace_success = (
            _emit_trace_sentinel(_CVA6_TRACE_SENTINEL_START_SLOT)
            + _emit_trace_byte_immediate(1, slot=0)
            + _emit_trace_byte_immediate(0, slot=1)
            + _emit_trace_sentinel(_CVA6_TRACE_SENTINEL_END_SLOT)
            + _emit_trace_drain_lines()
        )
        trace_trap = (
            _emit_trace_sentinel(_CVA6_TRACE_SENTINEL_START_SLOT)
            + _emit_trace_byte_immediate(0, slot=0)
            + _emit_trace_byte_from_reg("t2", slot=1)
            + _emit_trace_sentinel(_CVA6_TRACE_SENTINEL_END_SLOT)
            + _emit_trace_drain_lines()
        )
    return _emit_program(
        setup_lines=[
            f"    li t0, 0x{int(case['target_pmpaddr']):x}",
            "    csrw pmpaddr0, t0",
            f"    li t0, 0x{int(case['catchall_pmpaddr']):x}",
            "    csrw pmpaddr1, t0",
            f"    li t0, 0x{int(case['pmpcfg0_value']):x}",
            "    csrw pmpcfg0, t0",
            "    csrr t0, mstatus",
            "    li t1, ~((3 << 11) | (1 << 17) | (1 << 18) | (1 << 19))",
            "    and t0, t0, t1",
            "    li t1, (1 << 17)",
            "    or t0, t0, t1",
            "    csrw mstatus, t0",
        ]
        + trace_prefix,
        body_lines=[
            f"    li t0, 0x{target_address:x}",
            "    lw t1, 0(t0)",
        ]
        + _emit_restore_mmode_access_lines(scratch_reg="t0", mask_reg="t1")
        + trace_success
        + _successful_completion_lines(case),
        trap_lines=["    csrr t2, mcause", "    csrr t3, mtval"]
        + _emit_restore_mmode_access_lines(scratch_reg="t0", mask_reg="t1")
        + trace_trap
        + _successful_completion_lines(case),
    )


def _parse_readback_case(case: dict[str, Any], *, log_text: str, base: dict[str, Any]) -> dict[str, Any]:
    requested_cfg = int(case.get("requested_cfg_byte") or 0)
    trace_bytes, trace_error = _extract_trace_bytes(log_text, case=case, expected_count=6)
    if trace_error is not None:
        base["execution_status"] = "harness-error"
        base["reason"] = trace_error
        return base
    transport_mode = str(case.get("termination_mode") or "pass-tohost")
    if trace_bytes is not None:
        base["transport_completion"] = _transport_completion_metadata(
            mode=transport_mode,
            frame_complete=True,
            end_marker="trace-end-sentinel",
            required_fields_complete=True,
        )
        readback_1 = trace_bytes[0]
        readback_2 = trace_bytes[1]
        pmpaddr_value = _little_endian_word(trace_bytes[2:6])
    else:
        decoded = _decode_cva6_pilot_payload(log_text, expected_kind=_CVA6_PILOT_TOHOST_READBACK_KIND)
        if decoded is None:
            base["execution_status"] = "harness-error"
            return base
        readback_1 = (decoded["raw"] >> _CVA6_PILOT_CFG_SHIFT_1) & 0xFF
        readback_2 = (decoded["raw"] >> _CVA6_PILOT_CFG_SHIFT_2) & 0xFF
        pmpaddr_value = decoded["raw"] & 0xFFFFFFFF
        base["observed_tohost"] = decoded["observed_tohost"]
        base["transport_completion"] = _transport_completion_metadata(
            mode=transport_mode,
            frame_complete=False,
            end_marker="tohost",
            required_fields_complete=True,
        )
    exact = readback_1 == requested_cfg and readback_2 == requested_cfg
    base["control_pass"] = exact
    requested_bits = dict(case.get("requested_bits") or _bits_from_cfg_byte(requested_cfg))
    base["parsed_record"] = {
        "record_schema_version": OFF_STATE_RECORD_SCHEMA_VERSION,
        "dut": "cva6",
        "profile_requested": CVA6_SUPPORTED_PROFILE,
        "profile_observed": CVA6_SUPPORTED_PROFILE,
        "entry_index": int(case["entry_index"]),
        "reset_id": str(case["reset_id"]),
        "subexperiment": "readback",
        "requested_bits": requested_bits,
        "spec_status": str(case.get("spec_status") or spec_status_for_off_state(CVA6_SUPPORTED_PROFILE, requested_bits)),
        "execution_status": "completed",
        "write_outcome": "accepted",
        "readback_relation": "exact" if exact else "canonicalized",
        "readback_bits_1": _bits_from_cfg_byte(readback_1),
        "readback_bits_2": _bits_from_cfg_byte(readback_2),
        "pmpaddr_value": f"0x{pmpaddr_value:x}",
    }
    return base


def _parse_lock_case(case: dict[str, Any], *, log_text: str, base: dict[str, Any]) -> dict[str, Any]:
    initial_addr = int(case["target_pmpaddr"])
    trace_bytes, trace_error = _extract_trace_bytes(log_text, case=case, expected_count=6)
    if trace_error is not None:
        base["execution_status"] = "harness-error"
        base["reason"] = trace_error
        return base
    transport_mode = str(case.get("termination_mode") or "pass-tohost")
    if trace_bytes is not None:
        base["transport_completion"] = _transport_completion_metadata(
            mode=transport_mode,
            frame_complete=True,
            end_marker="trace-end-sentinel",
            required_fields_complete=True,
        )
        addr_after = _little_endian_word(trace_bytes[:4])
        cfg_after_1 = trace_bytes[4]
        cfg_after_2 = trace_bytes[5]
    else:
        decoded = _decode_cva6_pilot_payload(log_text, expected_kind=_CVA6_PILOT_TOHOST_LOCK_KIND)
        if decoded is None:
            base["execution_status"] = "harness-error"
            return base
        addr_after = decoded["raw"] & 0xFFFFFFFF
        cfg_after_1 = (decoded["raw"] >> _CVA6_PILOT_CFG_SHIFT_1) & 0xFF
        cfg_after_2 = (decoded["raw"] >> _CVA6_PILOT_CFG_SHIFT_2) & 0xFF
        base["observed_tohost"] = decoded["observed_tohost"]
        base["transport_completion"] = _transport_completion_metadata(
            mode=transport_mode,
            frame_complete=False,
            end_marker="tohost",
            required_fields_complete=True,
        )
    attempted_addr = int(case["alternate_pmpaddr"])
    attempted_cfg = int(case["attempt_cfg_byte"])
    addr_blocked = addr_after != attempted_addr
    cfg_blocked = cfg_after_2 != attempted_cfg
    base["control_pass"] = addr_blocked and cfg_blocked
    requested_bits = dict(case.get("requested_bits") or _bits_from_cfg_byte(int(case.get("requested_cfg_byte", 0) or 0)))
    base["parsed_record"] = {
        "record_schema_version": OFF_STATE_RECORD_SCHEMA_VERSION,
        "dut": "cva6",
        "profile_requested": CVA6_SUPPORTED_PROFILE,
        "profile_observed": CVA6_SUPPORTED_PROFILE,
        "entry_index": int(case["entry_index"]),
        "reset_id": str(case["reset_id"]),
        "subexperiment": "lock",
        "requested_bits": requested_bits,
        "spec_status": str(case.get("spec_status") or spec_status_for_off_state(CVA6_SUPPORTED_PROFILE, requested_bits)),
        "execution_status": "completed",
        "cfg_lock_effect": "blocked" if cfg_blocked else "not-blocked",
        "addr_lock_effect": "blocked" if addr_blocked else "not-blocked",
        "initial_addr": f"0x{initial_addr:x}",
        "addr_after": f"0x{addr_after:x}",
        "cfg_after_1": f"0x{cfg_after_1:x}",
        "cfg_after_2": f"0x{cfg_after_2:x}",
    }
    return base


def _parse_behavior_case(case: dict[str, Any], *, log_text: str, base: dict[str, Any]) -> dict[str, Any]:
    expected_trace_bytes = 12 if "requested_raw_bin_id" in case else 2
    trace_bytes, trace_error = _extract_trace_bytes(log_text, case=case, expected_count=expected_trace_bytes)
    readback_1: int | None = None
    readback_2: int | None = None
    pmpaddr_value: int | None = None
    observed_mtval: int | None = None
    if trace_error is not None:
        base["execution_status"] = "harness-error"
        base["reason"] = trace_error
        return base
    transport_mode = str(case.get("termination_mode") or "pass-tohost")
    if trace_bytes is not None:
        base["transport_completion"] = _transport_completion_metadata(
            mode=transport_mode,
            frame_complete=True,
            end_marker="trace-end-sentinel",
            required_fields_complete=True,
        )
        if expected_trace_bytes == 12:
            readback_1 = trace_bytes[0]
            readback_2 = trace_bytes[1]
            pmpaddr_value = _little_endian_word(trace_bytes[2:6])
            actual_allow = bool(trace_bytes[6])
            observed_mcause = trace_bytes[7]
            observed_mtval = _little_endian_word(trace_bytes[8:12])
        else:
            actual_allow = bool(trace_bytes[0])
            observed_mcause = trace_bytes[1]
    else:
        decoded = _decode_cva6_pilot_payload(log_text, expected_kind=_CVA6_PILOT_TOHOST_BEHAVIOR_KIND)
        if decoded is not None:
            actual_allow = bool((decoded["raw"] >> _CVA6_PILOT_ALLOWED_SHIFT) & 0x1)
            observed_mcause = decoded["raw"] & 0xFF
            base["observed_tohost"] = decoded["observed_tohost"]
            base["transport_completion"] = _transport_completion_metadata(
                mode=transport_mode,
                frame_complete=False,
                end_marker="tohost",
                required_fields_complete=True,
            )
        else:
            probe_events = parse_probe_events(log_text)
            if not probe_events:
                base["execution_status"] = "harness-error"
                return base
            fields = dict((probe_events[0] or {}).get("fields") or {})
            actual_allow = str(fields.get("allow") or fields.get("allowed") or "").strip().lower() in {
                "1",
                "true",
                "allow",
                "allowed",
            }
            observed_mcause = None
            mcause_text = str(fields.get("mcause") or "").strip()
            if mcause_text:
                try:
                    observed_mcause = int(mcause_text, 0)
                except ValueError:
                    observed_mcause = None

    if "requested_raw_bin_id" in case:
        requested_bits = dict(case["requested_bits"])
        parsed_record = {
            "record_schema_version": OFF_STATE_RECORD_SCHEMA_VERSION,
            "dut": "cva6",
            "profile_requested": CVA6_SUPPORTED_PROFILE,
            "profile_observed": CVA6_SUPPORTED_PROFILE,
            "entry_index": int(case["entry_index"]),
            "reset_id": str(case["reset_id"]),
            "subexperiment": "behavior",
            "requested_bits": requested_bits,
            "spec_status": str(case.get("spec_status") or spec_status_for_off_state(CVA6_SUPPORTED_PROFILE, requested_bits)),
            "execution_status": "completed",
            "probe_result": "unexpected-match" if actual_allow else "expected-nonmatch",
            "access": str(case.get("access") or CVA6_SUPPORTED_ACCESS),
            "size": int(case.get("size") or 4),
            "current_privilege": "m",
            "effective_privilege": "u",
            "exception_cause": "none" if actual_allow else _mcause_token(observed_mcause),
            "fault_address": f"0x{int(observed_mtval or 0):x}",
            "matched_control_case": "behavior-napot-allow" if actual_allow else "behavior-catch-all",
            "readback_bits_1": _bits_from_cfg_byte(int(readback_1 or 0)),
            "readback_bits_2": _bits_from_cfg_byte(int(readback_2 or 0)),
            "pmpaddr_value": f"0x{int(pmpaddr_value or 0):x}",
        }
        parsed_record["normalized_record"] = _normalized_record_for_main_behavior(case, parsed_record)
        parsed_record["supports_fault_stage"] = True
        parsed_record["supports_smepmp"] = False
        base["parsed_record"] = parsed_record

    result = {
        "status": "pass" if actual_allow else "fail",
        "observation_valid": True,
        "observed_event": "completion" if actual_allow else "trap",
        "observed_mcause": observed_mcause,
        "observed_stage": "final",
    }
    if "expected_allow" in case:
        base["control_pass"] = actual_allow == bool(case.get("expected_allow"))
    if "bapc_case" in case:
        base["bapc_summary"] = summarize_bapc_for_pmpfuzz_case(
            dict(case["bapc_case"]),
            result,
            log_text=log_text,
            supports_smepmp=False,
            bapc_core_version="v3",
        )
    return base


def _transport_completion_metadata(
    *,
    mode: str,
    frame_complete: bool,
    end_marker: str,
    required_fields_complete: bool,
) -> dict[str, Any]:
    return {
        "mode": str(mode),
        "frame_complete": bool(frame_complete),
        "end_marker": str(end_marker),
        "required_fields_complete": bool(required_fields_complete),
    }


def _normalized_record_for_main_behavior(case: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    readback_bits = dict(record.get("readback_bits_2") or record.get("requested_bits") or {})
    pmpaddr_text = str(record.get("pmpaddr_value") or case.get("target_pmpaddr") or "0")
    try:
        pmpaddr_value = int(pmpaddr_text, 0)
    except ValueError:
        pmpaddr_value = int(case.get("target_pmpaddr") or 0)
    actual_pmp_entries = _actual_behavior_pmp_entries(
        case,
        readback_bits=readback_bits,
        pmpaddr_value=pmpaddr_value,
    )
    allow_or_deny = "allow" if str(record.get("probe_result") or "") == "unexpected-match" else "deny"
    mapped = map_bapc_normalized_record(
        {
            "pmp_entries": actual_pmp_entries,
            "translation": "bare",
            "privilege": str(record.get("current_privilege") or "m"),
            "access": str(record.get("access") or CVA6_SUPPORTED_ACCESS),
            "size": int(record.get("size") or 4),
            "address": int(case.get("target_address") or TARGET_BASE),
            "mprv": True,
            "mpp": str(record.get("effective_privilege") or "u"),
            "allow_or_deny": allow_or_deny,
            "mcause_class": _behavior_mcause_class(record, allow_or_deny=allow_or_deny),
        },
        bapc_core_version="v3",
    )
    if not bool(mapped.get("eligible")):
        raise ValueError(
            f"main behavior normalized record is ineligible for BAPC replay: {mapped.get('qualification_reason')}"
        )
    return dict(mapped["normalized_record"])


def _actual_behavior_pmp_entries(
    case: dict[str, Any],
    *,
    readback_bits: dict[str, Any],
    pmpaddr_value: int,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    target_index = int(case.get("entry_index") or 0)
    for raw in list(case.get("pmp_entries") or []):
        item = dict(raw)
        if int(item.get("index") or -1) == target_index:
            item["address_mode"] = "off"
            item["pmpaddr"] = f"0x{pmpaddr_value:x}"
            item["read"] = bool(readback_bits.get("r"))
            item["write"] = bool(readback_bits.get("w"))
            item["execute"] = bool(readback_bits.get("x"))
            item["locked"] = bool(readback_bits.get("l"))
        entries.append(item)
    return entries


def _behavior_mcause_class(record: dict[str, Any], *, allow_or_deny: str) -> str:
    if allow_or_deny == "allow":
        return "none"
    token = str(record.get("exception_cause") or "").strip().lower()
    if token in {
        "instruction_access_fault",
        "load_access_fault",
        "store_access_fault",
        "instruction_page_fault",
        "load_page_fault",
        "store_page_fault",
        "other",
    }:
        return token
    access = str(record.get("access") or CVA6_SUPPORTED_ACCESS).strip().lower()
    if access == "fetch":
        return "instruction_access_fault"
    if access == "store":
        return "store_access_fault"
    return "load_access_fault"


def _emit_lock_payload_lines(
    *,
    pmpaddr_after_reg: str,
    cfg_after_1_reg: str,
    cfg_after_2_reg: str,
    case: dict[str, Any],
) -> list[str]:
    return (
        _emit_trace_sentinel(_CVA6_TRACE_SENTINEL_START_SLOT)
        + _emit_trace_word_bytes_from_reg(pmpaddr_after_reg, start_slot=0)
        + _emit_trace_byte_from_reg(cfg_after_1_reg, slot=4)
        + _emit_trace_byte_from_reg(cfg_after_2_reg, slot=5)
        + _emit_trace_sentinel(_CVA6_TRACE_SENTINEL_END_SLOT)
        + _emit_trace_drain_lines()
        + _successful_completion_lines(case)
    )


def _emit_restore_mmode_access_lines(*, scratch_reg: str = "t2", mask_reg: str = "t3") -> list[str]:
    return [
        f"    csrr {scratch_reg}, mstatus",
        f"    li {mask_reg}, ~(1 << 17)",
        f"    and {scratch_reg}, {scratch_reg}, {mask_reg}",
        f"    csrw mstatus, {scratch_reg}",
    ]


def _successful_completion_lines(case: dict[str, Any]) -> list[str]:
    if str(case.get("termination_mode") or "") == "host-timeout":
        return ["    j host_wait"]
    return ["    li a0, 1", "    j finish"]


def _emit_trace_drain_lines() -> list[str]:
    return [
        "    li t0, 1024",
        "1:",
        "    addi t0, t0, -1",
        "    bnez t0, 1b",
    ]


def _emit_trace_sentinel(slot: int) -> list[str]:
    return [
        "    la t5, trace_table",
        f"    li t6, {slot * _CVA6_TRACE_SLOT_STRIDE_BYTES}",
        "    add t5, t5, t6",
        "    lw t6, 0(t5)",
    ]


def _emit_trace_byte_immediate(value: int, *, slot: int) -> list[str]:
    return [f"    li t4, {value & 0xFF}"] + _emit_trace_byte_from_reg("t4", slot=slot)


def _emit_trace_byte_from_reg(reg: str, *, slot: int) -> list[str]:
    return [
        "    la t5, trace_table",
        f"    li t3, {slot * _CVA6_TRACE_SLOT_STRIDE_BYTES}",
        "    add t5, t5, t3",
        f"    andi t6, {reg}, 0xff",
        f"    slli t6, t6, {2}",
        "    add t5, t5, t6",
        "    lw t6, 0(t5)",
    ]


def _emit_trace_word_bytes_from_reg(reg: str, *, start_slot: int) -> list[str]:
    lines: list[str] = []
    for index, shift in enumerate((0, 8, 16, 24)):
        if shift == 0:
            lines.append(f"    mv t4, {reg}")
        else:
            lines.append(f"    srli t4, {reg}, {shift}")
        lines.extend(_emit_trace_byte_from_reg("t4", slot=start_slot + index))
    return lines


def _emit_harness_failure_lines() -> list[str]:
    return [
        "    csrr t2, mcause",
        "    csrr t3, mtval",
    ] + emit_failure_tohost_lines("INFRA_ERROR", mcause_reg="t2", mtval_reg="t3")


def _emit_program(
    *,
    setup_lines: list[str],
    body_lines: list[str],
    trap_lines: list[str],
) -> str:
    lines = [
        "    .option norvc",
        "    .option norelax",
        "    .section .text",
        "    .globl _start",
        "_start:",
        "    la sp, stack_top",
        "    la t0, trap_handler",
        "    csrw mtvec, t0",
        "    csrw medeleg, zero",
        "    csrw mideleg, zero",
        "    csrw satp, zero",
        "    sfence.vma",
        *setup_lines,
        *body_lines,
        "trap_handler:",
        *trap_lines,
        "finish:",
        "    csrr t2, mstatus",
        "    li t3, ~(1 << 17)",
        "    and t2, t2, t3",
        "    csrw mstatus, t2",
        "    la t0, result",
        "    sd a0, 32(t0)",
        "    la t0, tohost",
        "    sd a0, 0(t0)",
        "host_wait:",
        "finish_wait:",
        "    wfi",
        "    j finish_wait",
        "    .section .bss",
        "    .align 12",
        "scratch:",
        "    .skip 4096",
        "stack:",
        "    .skip 4096",
        "stack_top:",
        "    .section .tohost,\"aw\",@progbits",
        "    .align 6",
        "    .globl tohost",
        "tohost:",
        "    .dword 0",
        "    .globl fromhost",
        "fromhost:",
        "    .dword 0",
        "    .section .data",
        "    .align 3",
        "    .globl result",
        "result:",
        "    .dword 0",
        "    .dword 0",
        "    .dword 0",
        "    .dword 0",
        "    .dword 0",
        "observation_phase:",
        "    .word 0",
        "    .align 2",
        "    .globl trace_table",
        "trace_table:",
        f"    .skip {_CVA6_TRACE_TABLE_BYTES}",
    ]
    return "\n".join(lines) + "\n"


def _harness_error_result(case: dict[str, Any], *, failure_class: str, reason: str) -> dict[str, Any]:
    return {
        "schema_version": CVA6_PILOT_RESULT_SCHEMA_VERSION,
        "artifact_kind": CVA6_PILOT_RESULT_KIND,
        "case_id": str(case["case_id"]),
        "case_kind": str(case["case_kind"]),
        "execution_status": "harness-error",
        "failure_class": failure_class,
        "reason": reason,
    }


def _build_execution_binding(
    *,
    root: Path,
    case: dict[str, Any],
    reset_command: list[str],
    compile_command: list[str],
    dut: Any,
    elf_path: Path,
    log_text: str,
    log_path: Path | None = None,
) -> dict[str, Any]:
    dut_command = _dut_command(dut, elf_path)
    dut_binary = _dut_binary_path(dut)
    binding = enrich_metadata(
        capture_repo_metadata(root, argv=dut_command),
        dut_binary=dut_binary if dut_binary is not None and dut_binary.exists() else None,
        firmware_payload=elf_path if elf_path.exists() else None,
        simulator_version=_simulator_version(dut),
        isa_configuration="rv64gc",
        xlen=64,
        reset_method="external-supervisor-command",
    )
    binding["dut_name"] = str(getattr(dut, "name", ""))
    binding["reset_id"] = str(case.get("reset_id") or "")
    binding["reset_command"] = list(reset_command)
    binding["compile_command"] = list(compile_command)
    binding["dut_command"] = dut_command
    if elf_path.exists():
        binding["payload_sha256"] = sha256_file(elf_path)
    binding["raw_log_sha256"] = (
        sha256_file(log_path)
        if log_path is not None and log_path.exists()
        else hashlib.sha256(log_text.encode("utf-8")).hexdigest()
    )
    binding["transport"] = _transport_metadata(dut)
    return binding


def _dut_command(dut: Any, elf_path: Path) -> list[str]:
    command_for = getattr(dut, "command_for", None)
    if callable(command_for):
        command = command_for(elf_path)
        return [str(item) for item in command]
    return []


def _dut_binary_path(dut: Any) -> Path | None:
    simulator_path = getattr(dut, "simulator_path", None)
    if callable(simulator_path):
        candidate = simulator_path()
        if candidate is not None:
            return Path(candidate)
    simulator_binary = getattr(dut, "simulator_binary", None)
    if simulator_binary is not None:
        return Path(simulator_binary)
    return None


def _simulator_version(dut: Any) -> str:
    config = getattr(dut, "config", None)
    if config:
        return str(config)
    simulator_binary = _dut_binary_path(dut)
    if simulator_binary is not None:
        return simulator_binary.name
    return str(getattr(dut, "name", "unknown"))


def _transport_metadata(dut: Any) -> dict[str, Any]:
    dut_name = str(getattr(dut, "name", "") or "")
    whitebox = bool(getattr(dut, "whitebox_artifacts", False))
    if whitebox and dut_name.startswith("cva6"):
        return {
            "kind": "cva6-whitebox-artifacts",
            "dut_specific": True,
            "public_default": False,
        }
    return {
        "kind": "stdout-log",
        "dut_specific": False,
        "public_default": True,
    }


def _attach_execution_binding(result: dict[str, Any], binding: dict[str, Any]) -> None:
    parsed_record = result.get("parsed_record")
    if isinstance(parsed_record, dict):
        parsed_record["source_git_sha"] = binding.get("source_git_sha")
        parsed_record["experiment_branch"] = binding.get("experiment_branch")
        parsed_record["payload_sha256"] = binding.get("payload_sha256")
        parsed_record["raw_log_sha256"] = binding.get("raw_log_sha256")
        parsed_record["command_line"] = list(binding.get("dut_command") or [])
        parsed_record["reset_method"] = binding.get("reset_method")
        parsed_record["transport_kind"] = str((binding.get("transport") or {}).get("kind") or "")


def _cfg_byte(
    mode: AddressMode,
    *,
    read: bool,
    write: bool,
    execute: bool,
    locked: bool,
) -> int:
    value = 0
    value |= 0x01 if read else 0
    value |= 0x02 if write else 0
    value |= 0x04 if execute else 0
    value |= mode.value << 3
    value |= 0x80 if locked else 0
    return value


def _entry_dict(
    *,
    index: int,
    mode: AddressMode,
    pmpaddr: int,
    read: bool,
    write: bool,
    execute: bool,
    locked: bool,
) -> dict[str, Any]:
    return {
        "index": index,
        "address_mode": mode.name.lower(),
        "pmpaddr": f"0x{pmpaddr:x}",
        "read": read,
        "write": write,
        "execute": execute,
        "locked": locked,
    }


def _bits_from_cfg_byte(value: int) -> dict[str, int]:
    return {
        "l": 1 if value & 0x80 else 0,
        "r": 1 if value & 0x01 else 0,
        "w": 1 if value & 0x02 else 0,
        "x": 1 if value & 0x04 else 0,
    }


def _mcause_token(value: int | None) -> str:
    mapping = {
        0: "none",
        1: "instruction_access_fault",
        5: "load_access_fault",
        7: "store_access_fault",
    }
    return mapping.get(int(value or 0), f"mcause-{int(value or 0)}")


def _asm_string(value: str) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


def _elf_symbol_address(elf_path: Path, symbol_name: str) -> int | None:
    completed = subprocess.run(
        ["readelf", "-s", str(elf_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) < 8 or fields[-1] != symbol_name:
            continue
        try:
            return int(fields[1], 16)
        except ValueError:
            return None
    return None


def _run_completed_process(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _default_cva6_dut_factory(*, chipyard_dir: Path, dut_bin: Path | None) -> Any:
    return make_dut(
        dut="cva6-clean",
        spike="spike",
        isa="rv64gc",
        chipyard_dir=chipyard_dir,
        dut_bin=dut_bin,
        whitebox_artifacts=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
