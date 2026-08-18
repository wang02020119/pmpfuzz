from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

from .capabilities import capability_for_dut, capability_matrix, oracle_applicability_for_result
from .c910_nonpmp import write_bootstrap_run
from .c910_nonpmp_dynamic import (
    default_pilot_case_names,
    write_dynamic_manifest,
    write_dynamic_run,
)
from .coverage import write_coverage
from .dut import DEFAULT_CHIPYARD_DIR, DEFAULT_CLEAN_CHIPYARD_DIR, DEFAULT_RISCV, DEFAULT_XIANGSHAN_EMU, XIANGSHAN_VANILLA_ROOT, make_dut
from .dut_coverage import write_dut_coverage, write_dut_coverage_matrix
from .emitter import AssemblyEmitter
from .feedback import write_feedback
from .judgment import judge_observation
from .mmu import AdUpdateMode
from .runner import DEFAULT_SPIKE, RunnerConfig, parse_time_budget, run_campaign
from .scenario import ScenarioGenerator
from .schema import read_json, result_to_dict, scenario_to_case_dict, write_aggregate, write_json
from .semantic_coverage import CORE_STATEFUL_TARGET, scenarios_from_schedule, write_schedule
from .source_probe import write_source_probe_instrumentation, write_source_probe_manifest
from .timeline import TimelineRecorder, timeline_on_complete_factory
from .triage import triage_run, write_report
from .whitebox import write_whitebox_signals


CLEAN_CHIPYARD_DUTS = {"rocket-clean", "boom-clean", "cva6", "cva6-clean"}
DUT_CHOICES = [
    "spike",
    "rocket",
    "cva6",
    "cva6-clean",
    "rocket-cascade",
    "rocket-clean",
    "boom-clean",
    "xiangshan-clean",
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m pmpfuzz", description="Engineering CLI for PMP fuzz campaigns")
    subparsers = parser.add_subparsers(dest="command", required=True)

    env_check = subparsers.add_parser("env-check", help="check local/server tool paths")
    _add_common_env_args(env_check)

    probe_dut = subparsers.add_parser("probe-dut", help="write DUT capability metadata")
    probe_dut.add_argument("--dut", default="spike,rocket-clean,boom-clean,cva6-clean,xiangshan-clean")
    probe_dut.add_argument("--out", type=Path, required=True)
    probe_dut.add_argument("--probe-smepmp", action="store_true")
    _add_common_env_args(probe_dut)

    probe_source = subparsers.add_parser("probe-source", help="discover source-level probe insertion points")
    probe_source.add_argument("--dut", default="xiangshan-clean,boom-clean,rocket-clean,cva6-clean")
    probe_source.add_argument("--out", type=Path, required=True)
    probe_source.add_argument("--xiangshan-root", type=Path, default=None)
    _add_common_env_args(probe_source)

    source_probe_instrument = subparsers.add_parser(
        "source-probe-instrument",
        help="write source-level PMFUZZ_PROBE instrumentation patches",
    )
    source_probe_instrument.add_argument("--dut", default="rocket-clean,boom-clean,cva6-clean")
    source_probe_instrument.add_argument("--out", type=Path, required=True)
    source_probe_instrument.add_argument("--xiangshan-root", type=Path, default=None)
    _add_common_env_args(source_probe_instrument)

    gen = subparsers.add_parser("gen", help="generate cases without running a DUT")
    _add_generation_args(gen)
    gen.add_argument("--backend", choices=["tohost", "cascade-mmio", "xiangshan-goodtrap"], default="tohost")

    run = subparsers.add_parser("run", help="run a fuzz campaign")
    _add_generation_args(run)
    _add_common_env_args(run)
    run.add_argument("--dut", choices=DUT_CHOICES, default="spike")
    run.add_argument("--jobs", type=int, default=max(1, os.cpu_count() or 1))
    run.add_argument("--time-budget", default="7h")
    run.add_argument("--per-case-timeout", type=int, default=10)
    run.add_argument("--dut-bin", type=Path, default=None)
    run.add_argument("--simlen", type=int, default=100000)
    run.add_argument("--whitebox-artifacts", action="store_true")
    run.add_argument("--record-timeline", action="store_true",
                     help="Record execution-qualified coverage timeline as JSONL")
    run.add_argument("--campaign-id", default=None,
                     help="Campaign identifier for timeline recording")
    run.add_argument("--variant", default=None,
                     help="Experiment variant label (e.g. random, guided, bb, bb-wb)")
    run.add_argument("--hpm-manifest", type=Path, default=None)
    run.add_argument("--bapc-core-version", choices=["v2", "v3", "v4"], default=None)

    repro = subparsers.add_parser("repro", help="reproduce one generated case on one or more DUTs")
    repro.add_argument("--case", type=Path, required=True)
    repro.add_argument("--dut", default="spike,rocket-clean,boom-clean")
    repro.add_argument("--out", type=Path, required=True)
    repro.add_argument("--per-case-timeout", type=int, default=60)
    repro.add_argument("--dut-bin", type=Path, default=None)
    repro.add_argument("--simlen", type=int, default=100000)
    repro.add_argument("--no-smepmp", action="store_true")
    repro.add_argument("--whitebox-artifacts", action="store_true")
    _add_common_env_args(repro)

    triage = subparsers.add_parser("triage", help="classify and deduplicate campaign failures")
    triage.add_argument("--run-dir", type=Path, required=True)

    coverage = subparsers.add_parser("coverage", help="write coverage bins for a campaign")
    coverage.add_argument("--run-dir", type=Path, required=True)

    c910_nonpmp_analyze = subparsers.add_parser(
        "c910-nonpmp-analyze",
        help="parse a fixed-probe C910 UART log into a coverage-qualified bootstrap run",
    )
    c910_nonpmp_analyze.add_argument("--uart-log", type=Path, required=True)
    c910_nonpmp_analyze.add_argument("--out", type=Path, required=True)

    c910_nonpmp_dynamic_manifest = subparsers.add_parser(
        "c910-nonpmp-dynamic-manifest",
        help="write a dynamic C910 non-PMP round manifest and optional generated C source",
    )
    c910_nonpmp_dynamic_manifest.add_argument("--out-json", type=Path, required=True)
    c910_nonpmp_dynamic_manifest.add_argument("--out-c", type=Path, default=None)
    c910_nonpmp_dynamic_manifest.add_argument("--campaign-id", required=True)
    c910_nonpmp_dynamic_manifest.add_argument("--round-id", required=True)
    c910_nonpmp_dynamic_manifest.add_argument("--timebase-hz", type=int, default=3_000_000)
    c910_nonpmp_dynamic_manifest.add_argument(
        "--selection-source",
        default="bootstrap",
        choices=["bootstrap", "blackbox", "manual"],
    )
    c910_nonpmp_dynamic_manifest.add_argument(
        "--case",
        action="append",
        default=[],
        help="selected case name; repeat the flag to select multiple cases",
    )
    c910_nonpmp_dynamic_manifest.add_argument(
        "--pilot-bootstrap",
        action="store_true",
        help="use the built-in 8-case dynamic pilot subset when --case is omitted",
    )

    c910_nonpmp_dynamic_analyze = subparsers.add_parser(
        "c910-nonpmp-dynamic-analyze",
        help="parse a manifest-selected C910 UART log into a dynamic pilot run",
    )
    c910_nonpmp_dynamic_analyze.add_argument("--uart-log", type=Path, required=True)
    c910_nonpmp_dynamic_analyze.add_argument("--manifest", type=Path, required=True)
    c910_nonpmp_dynamic_analyze.add_argument("--out", type=Path, required=True)

    dut_coverage = subparsers.add_parser("dut-coverage", help="write observed whitebox DUT coverage for a campaign")
    dut_coverage.add_argument("--run-dir", type=Path, required=True)
    dut_coverage.add_argument("--out", type=Path, default=None)
    dut_coverage.add_argument("--artifact-dir", type=Path, default=None)

    dut_coverage_matrix = subparsers.add_parser(
        "dut-coverage-matrix",
        help="write a cross-DUT observed whitebox coverage matrix",
    )
    dut_coverage_matrix.add_argument("--from-runs", required=True, help="comma-separated run directories")
    dut_coverage_matrix.add_argument("--out", type=Path, required=True)

    schedule = subparsers.add_parser("schedule", help="build the next semantic coverage-guided campaign")
    schedule.add_argument("--from-runs", required=True, help="comma-separated run directories")
    schedule.add_argument("--target", default=CORE_STATEFUL_TARGET)
    schedule.add_argument("--max-cases", type=int, default=64)
    schedule.add_argument("--seed", type=int, default=20260628)
    schedule.add_argument("--out", type=Path, required=True)
    schedule.add_argument("--include-experimental", action="store_true")
    schedule.add_argument("--coverage-mode", choices=["semantic", "pairwise", "security-triples", "predicates"], default="semantic")
    schedule.add_argument("--coverage-basis", choices=["execution", "manifest"], default="execution",
                          help="execution: use execution-qualified coverage (default); manifest: use generated case.json only")
    schedule.add_argument("--dut", default=None, help="DUT name for execution coverage (required if the run contains multiple DUTs)")

    feedback = subparsers.add_parser("feedback", help="build the next behavior feedback-guided campaign")
    feedback.add_argument("--from-runs", required=True, help="comma-separated run or repro directories")
    feedback.add_argument("--target", default=CORE_STATEFUL_TARGET)
    feedback.add_argument("--max-cases", type=int, default=64)
    feedback.add_argument("--seed", type=int, default=20260629)
    feedback.add_argument("--out", type=Path, required=True)
    feedback.add_argument("--include-experimental", action="store_true")
    feedback.add_argument("--signal-file", type=Path, action="append", default=[])

    whitebox = subparsers.add_parser("whitebox", help="extract security-chain whitebox signals from a run")
    whitebox.add_argument("--run-dir", type=Path, required=True)
    whitebox.add_argument("--out", type=Path, default=None)
    whitebox.add_argument("--artifact-dir", type=Path, default=None)

    report = subparsers.add_parser("report", help="write a Markdown report for a campaign")
    report.add_argument("--run-dir", type=Path, required=True)

    return parser


def _add_generation_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", default="legacy-data")
    parser.add_argument("--profiles", default=None, help="comma-separated profiles; each gets --count cases")
    parser.add_argument("--count", type=int, default=16)
    parser.add_argument("--seed", type=int, default=20260628)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--no-smepmp", action="store_true")
    parser.add_argument("--generator-variant", choices=["full", "syntax"], default="full")
    parser.add_argument("--indices", default=None, help="comma-separated scenario indices to generate/run")
    parser.add_argument("--schedule", type=Path, default=None, help="semantic schedule.json to generate/run exactly")


def _add_common_env_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--spike", default=os.environ.get("SPIKE", DEFAULT_SPIKE))
    parser.add_argument("--isa", default=None)
    parser.add_argument("--chipyard-dir", type=Path, default=None)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "env-check":
        return _cmd_env_check(args)
    if args.command == "probe-dut":
        return _cmd_probe_dut(args)
    if args.command == "probe-source":
        return _cmd_probe_source(args)
    if args.command == "source-probe-instrument":
        return _cmd_source_probe_instrument(args)
    if args.command == "gen":
        return _cmd_gen(args)
    if args.command == "run":
        return _cmd_run(args)
    if args.command == "repro":
        return _cmd_repro(args)
    if args.command == "triage":
        triage = triage_run(args.run_dir)
        print(f"triage-groups={triage['group_count']} out={args.run_dir / 'triage' / 'triage.json'}")
        return 0
    if args.command == "coverage":
        out = write_coverage(args.run_dir)
        print(f"coverage={out}")
        return 0
    if args.command == "c910-nonpmp-analyze":
        return _cmd_c910_nonpmp_analyze(args)
    if args.command == "c910-nonpmp-dynamic-manifest":
        return _cmd_c910_nonpmp_dynamic_manifest(args)
    if args.command == "c910-nonpmp-dynamic-analyze":
        return _cmd_c910_nonpmp_dynamic_analyze(args)
    if args.command == "dut-coverage":
        out = write_dut_coverage(args.run_dir, out_dir=args.out, artifact_dir=args.artifact_dir)
        print(f"dut-coverage={out}")
        return 0
    if args.command == "dut-coverage-matrix":
        out = write_dut_coverage_matrix(_parse_run_dirs(args.from_runs), out_dir=args.out)
        print(f"dut-coverage-matrix={out}")
        return 0
    if args.command == "schedule":
        schedule_path = write_schedule(
            _parse_run_dirs(args.from_runs),
            target=args.target,
            max_cases=args.max_cases,
            seed=args.seed,
            out_dir=args.out,
            include_experimental=args.include_experimental,
            coverage_mode=args.coverage_mode,
            coverage_basis=args.coverage_basis,
            dut=args.dut,
        )
        print(f"schedule={schedule_path}")
        return 0
    if args.command == "feedback":
        schedule_path = write_feedback(
            _parse_run_dirs(args.from_runs),
            target=args.target,
            max_cases=args.max_cases,
            seed=args.seed,
            out_dir=args.out,
            include_experimental=args.include_experimental,
            signal_files=args.signal_file,
        )
        print(f"feedback={schedule_path.parent / 'feedback.json'} schedule={schedule_path}")
        return 0
    if args.command == "whitebox":
        signal_path = write_whitebox_signals(args.run_dir, out_dir=args.out, artifact_dir=args.artifact_dir)
        print(f"whitebox-signals={signal_path}")
        return 0
    if args.command == "report":
        write_aggregate(args.run_dir)
        triage_run(args.run_dir)
        report_path = write_report(args.run_dir)
        print(f"report={report_path}")
        return 0
    raise ValueError(f"unsupported command: {args.command}")


def _cmd_env_check(args: argparse.Namespace) -> int:
    chipyard_dir = args.chipyard_dir or DEFAULT_CLEAN_CHIPYARD_DIR
    xiangshan_capability = capability_for_dut("xiangshan-clean")
    checks = [
        ("spike", Path(args.spike).exists() or shutil.which(args.spike) is not None, args.spike),
        (
            "riscv-gcc",
            shutil.which("riscv64-unknown-elf-gcc") is not None
            or (DEFAULT_RISCV / "bin" / "riscv64-unknown-elf-gcc").exists(),
            "riscv64-unknown-elf-gcc",
        ),
        ("chipyard", chipyard_dir.exists(), str(chipyard_dir)),
        (
            "rocket-clean",
            (chipyard_dir / "sims/verilator/simulator-chipyard.harness-RocketConfig").exists(),
            str(chipyard_dir / "sims/verilator/simulator-chipyard.harness-RocketConfig"),
        ),
        (
            "boom-clean",
            (chipyard_dir / "sims/verilator/simulator-chipyard.harness-SmallBoomV3Config").exists(),
            str(chipyard_dir / "sims/verilator/simulator-chipyard.harness-SmallBoomV3Config"),
        ),
        (
            "cva6-clean",
            _cva6_simulator_exists(chipyard_dir),
            " or ".join(str(path) for path in _cva6_simulator_candidates(chipyard_dir)),
        ),
        (
            "xiangshan-clean",
            bool(xiangshan_capability["available"]),
            f"{xiangshan_capability['path']} oracle={xiangshan_capability['oracle_applicability']}",
        ),
    ]
    ok = True
    for name, passed, detail in checks:
        ok = ok and passed
        print(f"{name}: {'ok' if passed else 'missing'} {detail}")
    return 0 if ok else 1


def _cmd_probe_dut(args: argparse.Namespace) -> int:
    duts = [item.strip() for item in args.dut.split(",") if item.strip()]
    matrix = capability_matrix(duts, probe_smepmp=args.probe_smepmp)
    if args.probe_smepmp:
        for dut_name, capability in matrix["duts"].items():
            smepmp = _runtime_smepmp_probe(args, dut_name, capability)
            capability["smepmp"] = smepmp
            capability["supported_capabilities"]["smepmp"] = smepmp["probe_status"] == "supported"
            capability["supported_capabilities"]["smepmp_rlb"] = bool(smepmp["rlb"])
    write_json(args.out / "dut_capabilities.json", matrix)
    for dut_name, capability in matrix["duts"].items():
        smepmp = capability.get("smepmp") or {}
        print(
            f"{dut_name}: {'ok' if capability['available'] else 'missing'} "
            f"finish={capability['finish_protocol']} diagnostic={capability['diagnostic_depth']} "
            f"oracle={capability['oracle_applicability']} smepmp={smepmp.get('probe_status', 'unknown')}"
        )
    return 0


def _cmd_probe_source(args: argparse.Namespace) -> int:
    duts = [item.strip() for item in args.dut.split(",") if item.strip()]
    roots = _source_probe_roots(args, duts)
    out = write_source_probe_manifest(duts, roots=roots, out_dir=args.out)
    manifest = read_json(out)
    summary = manifest["summary"]
    print(
        f"source-probes={out} total={summary['total']} found={summary['source_found']} "
        f"missing={summary['source_missing'] + summary['root_missing']} pattern_missing={summary['pattern_missing']}"
    )
    return 0


def _cmd_c910_nonpmp_analyze(args: argparse.Namespace) -> int:
    payload = write_bootstrap_run(uart_log=args.uart_log, out_dir=args.out)
    print(f"coverage={payload['coverage']} report={payload['report']} run={payload['run_dir']}")
    return 0


def _cmd_c910_nonpmp_dynamic_manifest(args: argparse.Namespace) -> int:
    case_names = list(args.case)
    if not case_names:
        case_names = default_pilot_case_names() if args.pilot_bootstrap else []
    if not case_names:
        raise ValueError("select at least one --case or pass --pilot-bootstrap")
    manifest = write_dynamic_manifest(
        out_json=args.out_json,
        out_c=args.out_c,
        case_names=case_names,
        campaign_id=args.campaign_id,
        round_id=args.round_id,
        selection_source=args.selection_source,
        timebase_hz=args.timebase_hz,
    )
    c_path = f" generated_c={args.out_c}" if args.out_c is not None else ""
    print(f"manifest={args.out_json}{c_path} case_count={manifest['case_count']} sha256={manifest['sha256']}")
    return 0


def _cmd_c910_nonpmp_dynamic_analyze(args: argparse.Namespace) -> int:
    payload = write_dynamic_run(
        uart_log=args.uart_log,
        manifest_path=args.manifest,
        out_dir=args.out,
    )
    print(f"coverage={payload['coverage']} report={payload['report']} run={payload['run_dir']}")
    return 0


def _cmd_source_probe_instrument(args: argparse.Namespace) -> int:
    duts = [item.strip() for item in args.dut.split(",") if item.strip()]
    roots = _source_probe_roots(args, duts)
    payload = write_source_probe_instrumentation(duts, roots=roots, out_dir=args.out)
    summary = payload["summary"]
    print(
        f"source-probe-instrumentation={args.out / 'source_probe_instrumentation.json'} "
        f"instrumented={summary['instrumented']} patches={summary['patch_count']} "
        f"unsupported={summary['unsupported_template']} anchor_missing={summary['anchor_missing']}"
    )
    return 0


def _source_probe_roots(args: argparse.Namespace, duts: list[str]) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    for dut_name in duts:
        if dut_name == "xiangshan-clean":
            roots[dut_name] = args.xiangshan_root or XIANGSHAN_VANILLA_ROOT
        elif dut_name in {"boom-clean", "rocket-clean", "cva6-clean", "cva6"}:
            roots[dut_name] = args.chipyard_dir or DEFAULT_CLEAN_CHIPYARD_DIR
        else:
            roots[dut_name] = args.chipyard_dir or DEFAULT_CHIPYARD_DIR
    return roots


def _runtime_smepmp_probe(args: argparse.Namespace, dut_name: str, capability: dict) -> dict:
    static = capability.get("smepmp") or {}
    if not capability.get("available"):
        return static
    if static.get("probe_status") != "supported":
        return {
            "csr_access": False,
            "mml": False,
            "mmwp": False,
            "rlb": False,
            "warl_behavior": "not_probed_static_unsupported",
            "probe_status": "unsupported",
        }

    probe_dir = args.out / "smepmp_probe_runs" / dut_name
    config = RunnerConfig(
        profile="smepmp-mmwp-mmode-default-deny",
        profiles=("smepmp-mmwp-mmode-default-deny",),
        count=1,
        seed=20260629,
        jobs=1,
        time_budget_seconds=120,
        out=probe_dir,
        dut=dut_name,
        spike=args.spike,
        isa=args.isa or "rv64gc_smepmp",
        chipyard_dir=args.chipyard_dir or (DEFAULT_CLEAN_CHIPYARD_DIR if dut_name in CLEAN_CHIPYARD_DUTS else DEFAULT_CHIPYARD_DIR),
        simlen=50000,
        per_case_timeout_seconds=30,
        include_smepmp=True,
        bapc_core_version="v2",
    )
    try:
        results = run_campaign(config)
    except Exception as exc:
        return {
            "csr_access": False,
            "mml": False,
            "mmwp": False,
            "rlb": False,
            "warl_behavior": f"probe_exception:{type(exc).__name__}",
            "probe_status": "infra_unadapted",
        }

    result = results[0] if results else None
    if result is None:
        return {
            "csr_access": False,
            "mml": False,
            "mmwp": False,
            "rlb": False,
            "warl_behavior": "probe_no_result",
            "probe_status": "infra_unadapted",
        }
    if result.status == "setup_unsupported":
        return {
            "csr_access": False,
            "mml": False,
            "mmwp": False,
            "rlb": False,
            "warl_behavior": "probe_setup_unsupported",
            "probe_status": "unsupported",
        }
    if result.status in {"compile_fail", "infra_failure", "timeout"}:
        return {
            "csr_access": False,
            "mml": False,
            "mmwp": False,
            "rlb": False,
            "warl_behavior": f"probe_{result.status}",
            "probe_status": "infra_unadapted",
        }
    return {
        "csr_access": True,
        "mml": True,
        "mmwp": True,
        "rlb": bool(static.get("rlb")),
        "warl_behavior": "runtime_pass" if result.status == "pass" else f"runtime_nonpass:{result.failure_class or result.status}",
        "probe_status": "supported",
    }


def _cmd_gen(args: argparse.Namespace) -> int:
    scenarios = _selected_scenarios(args)
    cases_dir = args.out / "cases"
    emitter = AssemblyEmitter()
    for index, scenario in scenarios:
        case_dir = cases_dir / scenario.name
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / f"{scenario.name}.S").write_text(emitter.emit(scenario, backend=args.backend), encoding="ascii")
        write_json(
            case_dir / "case.json",
            scenario_to_case_dict(
                scenario,
                seed=args.seed,
                index=index,
                generator_variant=args.generator_variant,
                generation_seed=args.seed,
                scenario_index=index,
                mutation_operator="root",
            ),
        )
    print(f"generated={len(scenarios)} out={cases_dir}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    if not args.bapc_core_version:
        raise ValueError("pmpfuzz run requires --bapc-core-version")
    hpm_manifest = read_json(args.hpm_manifest) if args.hpm_manifest else None
    config = RunnerConfig(
        profile=args.profile,
        profiles=tuple(_profiles_from_args(args)),
        count=_effective_count(args.count, args.indices),
        seed=args.seed,
        jobs=args.jobs,
        time_budget_seconds=parse_time_budget(args.time_budget),
        out=args.out,
        dut=args.dut,
        spike=args.spike,
        isa=args.isa or os.environ.get("SPIKE_ISA") or ("rv64gc" if args.no_smepmp else "rv64gc_smepmp"),
        chipyard_dir=args.chipyard_dir or (DEFAULT_CLEAN_CHIPYARD_DIR if args.dut in CLEAN_CHIPYARD_DUTS else DEFAULT_CHIPYARD_DIR),
        dut_bin=args.dut_bin,
        simlen=args.simlen,
        per_case_timeout_seconds=args.per_case_timeout,
        include_smepmp=not args.no_smepmp,
        indices=_parse_indices(args.indices),
        schedule=args.schedule,
        whitebox_artifacts=args.whitebox_artifacts,
        record_timeline=args.record_timeline,
        campaign_id=args.campaign_id,
        variant=args.variant,
        generator_variant=args.generator_variant,
        hpm_manifest=hpm_manifest,
        bapc_core_version=args.bapc_core_version,
    )

    on_complete = None
    recorder = None
    if args.record_timeline:

        campaign_id = args.campaign_id or f"{config.dut}__{config.profile}__seed-{config.seed}"
        variant = args.variant or "unknown"
        metrics_dir = config.out / "metrics"
        metrics_dir.mkdir(parents=True, exist_ok=True)

        recorder = TimelineRecorder(
            run_dir=config.out,
            campaign_id=campaign_id,
            variant=variant,
            dut=config.dut,
            seed=config.seed,
        )
        _populate_timeline_targets(recorder, config)
        recorder.write_metadata(
            source_sha=_git_head_sha(),
            time_budget_seconds=config.time_budget_seconds,
            jobs=config.jobs,
            per_case_timeout_seconds=config.per_case_timeout_seconds,
            hostname=os.uname().nodename if hasattr(os, "uname") else None,
        )
        on_complete = timeline_on_complete_factory(
            recorder, enable_whitebox=args.whitebox_artifacts,
        )

    results = run_campaign(config, on_complete=on_complete)

    if args.whitebox_artifacts:
        signal_path, dut_coverage_path = _write_observed_whitebox_outputs(config.out)
        print(f"whitebox-signals={signal_path} dut-coverage={dut_coverage_path}")
    failed = [result for result in results if result.status not in {"pass", "setup_unsupported"}]
    print(
        f"campaign-total={len(results)} pass={sum(1 for result in results if result.status == 'pass')} "
        f"nonpass={len(failed)} out={config.out}"
    )
    return 1 if failed else 0


def _cmd_repro(args: argparse.Namespace) -> int:
    case_dir, case = _load_case(args.case)
    out = args.out.resolve()
    out_cases = out / "cases" / case["name"]
    out_results = out / "results"
    out_cases.mkdir(parents=True, exist_ok=True)
    out_results.mkdir(parents=True, exist_ok=True)
    write_json(out_cases / "case.json", case)


    dut_names = [item.strip() for item in args.dut.split(",") if item.strip()]
    isa = args.isa or ("rv64gc" if args.no_smepmp else "rv64gc_smepmp")


    write_json(
        out / "run.json",
        {
            "mode": "repro",
            "source_case": str(case_dir),
            "duts": dut_names,
            "isa": isa,
            "no_smepmp": args.no_smepmp,
        },
    )


    repro_capabilities = {}
    for dut_name in dut_names:
        chipyard_dir = args.chipyard_dir or (
            DEFAULT_CLEAN_CHIPYARD_DIR if dut_name in CLEAN_CHIPYARD_DUTS else DEFAULT_CHIPYARD_DIR
        )
        if dut_name == "spike":
            repro_capabilities[dut_name] = capability_for_dut(
                dut_name, path=args.spike, isa=isa,
            )
        elif args.dut_bin:
            repro_capabilities[dut_name] = capability_for_dut(
                dut_name, path=args.dut_bin, isa=isa,
            )
        else:
            repro_capabilities[dut_name] = capability_for_dut(
                dut_name, isa=isa,
            )
    write_json(
        out / "dut_capabilities.json",
        {
            "schema_version": 3,
            "duts": repro_capabilities,
        },
    )

    root = Path(__file__).resolve().parents[1]
    compile_script = root / "scripts" / "compile_one.sh"

    any_failed = False
    for dut_name in dut_names:
        result_dir = out_results / f"{case['name']}_{dut_name}"
        result_dir.mkdir(parents=True, exist_ok=True)
        asm = out_cases / f"{case['name']}.{dut_name}.S"
        elf = out_cases / f"{case['name']}.{dut_name}.elf"
        log = result_dir / f"{case['name']}.{dut_name}.log"
        asm.write_text(_repro_assembly_for_dut(case, dut_name), encoding="ascii")
        compile_run = subprocess.run(
            ["sh", str(compile_script), str(asm), str(elf)],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if compile_run.returncode != 0:
            log.write_text(compile_run.stdout, encoding="ascii", errors="replace")
            write_json(
                result_dir / "result.json",
                result_to_dict(
                    case=case,
                    dut=dut_name,
                    status="compile_fail",
                    elapsed_seconds=0.0,
                    returncode=compile_run.returncode,
                    log=log,
                    reason="compile failed",
                    failure_class="compile_fail",
                ),
            )
            any_failed = True
            print(f"{dut_name}: compile_fail failure_class=compile_fail")
            continue
        chipyard_dir = args.chipyard_dir or (
            DEFAULT_CLEAN_CHIPYARD_DIR if dut_name in CLEAN_CHIPYARD_DUTS else DEFAULT_CHIPYARD_DIR
        )
        dut = make_dut(
            dut=dut_name,
            spike=args.spike,
            isa=isa,
            chipyard_dir=chipyard_dir,
            dut_bin=args.dut_bin,
            simlen=args.simlen,
            whitebox_artifacts=args.whitebox_artifacts,
        )
        start = time.monotonic()
        dut_result = dut.run(elf, timeout_seconds=args.per_case_timeout, log_path=log)
        status = dut_result.status
        failure_class = dut_result.failure_class
        reason = dut_result.reason
        observation_valid = False
        stage_verified = False
        if status == "observed" and dut_result.observation is not None:
            judgment = judge_observation(
                case,
                dut_result.observation,
                observed_stage=dut_result.observed_stage,
                observed_ptw_level=dut_result.observed_ptw_level,
                observed_fault_address=dut_result.observed_fault_address,
            )
            status = judgment.status
            failure_class = judgment.failure_class
            reason = judgment.reason
            observation_valid = judgment.observation_valid
            stage_verified = judgment.stage_verified
        capability = repro_capabilities[dut_name]
        applicability = oracle_applicability_for_result(
            case,
            capability,
            status=status,
            failure_class=failure_class,
        )
        if applicability == "capability_dependent" and status in {"pass", "fail"}:
            status = "inconclusive"
            failure_class = "capability_dependent"
            reason = "DUT A/D update mode is unknown; observation cannot select one architectural oracle"
        result = result_to_dict(
            case=case,
            dut=dut_name,
            status=status,
            elapsed_seconds=time.monotonic() - start,
            returncode=dut_result.returncode,
            log=log,
            reason=reason,
            observed_tohost=dut_result.observed_tohost,
            observed_mcause=dut_result.observed_mcause,
            observed_mtval=dut_result.observed_mtval,
            observed_mepc_tag=(dut_result.observation.mepc_tag if dut_result.observation else None),
            observed_mtval_fingerprint=(
                dut_result.observation.mtval_fingerprint if dut_result.observation else None
            ),
            observed_event=(dut_result.observation.kind.name.lower() if dut_result.observation else None),
            observed_phase=(dut_result.observation.phase.name.lower() if dut_result.observation else None),
            observed_stage=dut_result.observed_stage,
            observed_ptw_level=dut_result.observed_ptw_level,
            observed_fault_address=dut_result.observed_fault_address,
            observation_valid=observation_valid,
            stage_verified=stage_verified,
            failure_class=failure_class,
            oracle_applicability=applicability,
        )
        write_json(result_dir / "result.json", result)
        any_failed = any_failed or status != "pass"
        print(f"{dut_name}: {status} failure_class={failure_class}")

    write_aggregate(out)
    if args.whitebox_artifacts:
        signal_path, dut_coverage_path = _write_observed_whitebox_outputs(out)
        print(f"whitebox-signals={signal_path} dut-coverage={dut_coverage_path}")
    return 1 if any_failed else 0


def _write_observed_whitebox_outputs(run_dir: Path) -> tuple[Path, Path]:
    return write_whitebox_signals(run_dir), write_dut_coverage(run_dir)


def _repro_assembly_for_dut(case: dict, dut_name: str) -> str:
    scenario = _scenario_from_case(case)
    return AssemblyEmitter().emit(scenario, backend=_repro_backend_for_dut(dut_name))


def _scenario_from_case(case: dict):
    if "scenario_spec" in case:
        from .scenario_codec import scenario_from_spec, scenario_hash

        spec = case["scenario_spec"]
        expected_hash = case.get("scenario_hash")
        actual_hash = scenario_hash(spec)
        if expected_hash is not None and str(expected_hash) != actual_hash:
            raise ValueError(
                f"case scenario_hash mismatch: expected {expected_hash}, got {actual_hash}"
            )
        scenario = scenario_from_spec(spec)
    else:
        seed = int(case.get("seed", 1))
        index = int(case.get("index", 0))
        profile = str(case["profile"])
        generator = ScenarioGenerator(
            seed=seed,
            include_smepmp=_case_uses_smepmp(case),
            profile=profile,
            generator_variant=str(case.get("generator_variant") or "full"),
        )
        scenario = generator.generate_one(index)
    return replace(
        scenario,
        name=str(case["name"]),
        ad_update_mode=AdUpdateMode(str(case.get("ad_update_mode") or scenario.ad_update_mode.value)),
    )


def _case_uses_smepmp(case: dict) -> bool:
    if str(case.get("profile") or "").startswith("smepmp"):
        return True
    if case.get("smepmp_rule"):
        return True
    mseccfg = case.get("mseccfg") or {}
    return any(bool(mseccfg.get(bit)) for bit in ("mml", "mmwp", "rlb"))


def _repro_backend_for_dut(dut_name: str) -> str:
    if dut_name == "rocket-cascade":
        return "cascade-mmio"
    if dut_name == "xiangshan-clean":
        return "xiangshan-goodtrap"
    return "tohost"


def _selected_scenarios(args: argparse.Namespace):
    if args.schedule is not None:
        return scenarios_from_schedule(args.schedule)
    selected = {int(item.strip()) for item in args.indices.split(",") if item.strip()} if args.indices else set()
    profiles = _profiles_from_args(args)
    multi_profile = len(profiles) > 1
    out = []
    for profile in profiles:
        generator = ScenarioGenerator(
            seed=args.seed,
            include_smepmp=not args.no_smepmp,
            profile=profile,
            generator_variant=args.generator_variant,
        )
        scenarios = generator.generate_batch(_effective_count(args.count, args.indices))
        for index, scenario in enumerate(scenarios):
            if args.indices and index not in selected:
                continue
            if multi_profile:
                scenario = replace(scenario, name=f"{profile}__{scenario.name}")
            out.append((index, scenario))
    return out


def _parse_indices(value: str | None) -> tuple[int, ...] | None:
    if not value:
        return None
    return tuple(int(item.strip()) for item in value.split(",") if item.strip())


def _effective_count(count: int, indices: str | None) -> int:
    parsed = _parse_indices(indices)
    if not parsed:
        return count
    return max(count, max(parsed) + 1)


def _profiles_from_args(args: argparse.Namespace) -> list[str]:
    if getattr(args, "profiles", None):
        return [item.strip() for item in args.profiles.split(",") if item.strip()]
    return [args.profile]


def _parse_run_dirs(value: str) -> list[Path]:
    return [Path(item.strip()) for item in value.split(",") if item.strip()]


def _cva6_simulator_candidates(chipyard_dir: Path) -> tuple[Path, ...]:
    return (
        chipyard_dir / "sims/verilator/simulator-chipyard.harness-CVA6Config",
        chipyard_dir / "sims/verilator/simulator-chipyard-CVA6Config",
    )


def _cva6_simulator_exists(chipyard_dir: Path) -> bool:
    return any(path.exists() for path in _cva6_simulator_candidates(chipyard_dir))


def _load_case(case_path: Path) -> tuple[Path, dict]:
    if case_path.is_dir():
        case_dir = case_path
        return case_dir, read_json(case_dir / "case.json")
    if case_path.name == "case.json":
        return case_path.parent, read_json(case_path)
    raise ValueError("--case must point to a generated case directory or case.json")


def _populate_timeline_targets(recorder, config: RunnerConfig) -> None:
    from .capabilities import capability_for_dut
    from .coverage import compute_coverage_targets
    from .semantic_coverage import CORE_STATEFUL_TARGET

    if config.dut == "spike":
        capability = capability_for_dut(
            config.dut,
            path=config.spike,
            isa=config.isa,
        )
    elif config.dut_bin:
        capability = capability_for_dut(
            config.dut,
            path=config.dut_bin,
            isa=config.isa,
        )
    else:
        capability = capability_for_dut(
            config.dut,
            isa=config.isa,
        )

    targets = compute_coverage_targets(
        target=CORE_STATEFUL_TARGET,
        capability=capability,
        include_experimental=False,
        seed=config.seed,
    )
    recorder.target_semantic = targets["semantic"]["target_bins"]
    recorder.target_pairwise = targets["pairwise"]["target_bins"]
    recorder.target_security_triples = targets["security_triples"]["target_bins"]
    recorder.target_predicates = targets["predicates"]["target_bins"]


def _git_head_sha() -> str | None:
    try:
        import subprocess
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, check=False,
            cwd=Path(__file__).resolve().parents[1],
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
