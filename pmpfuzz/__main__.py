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
from .coverage import write_coverage
from .dut import DEFAULT_CHIPYARD_DIR, DEFAULT_CLEAN_CHIPYARD_DIR, DEFAULT_XIANGSHAN_EMU, LEGACY_XIANGSHAN_EMU, make_dut
from .emitter import AssemblyEmitter
from .runner import DEFAULT_SPIKE, RunnerConfig, parse_time_budget, run_campaign
from .scenario import ScenarioGenerator
from .schema import read_json, result_to_dict, scenario_to_case_dict, write_aggregate, write_json
from .semantic_coverage import CORE_STATEFUL_TARGET, scenarios_from_schedule, write_schedule
from .triage import triage_run, write_report


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
    _add_common_env_args(probe_dut)

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

    repro = subparsers.add_parser("repro", help="reproduce one generated case on one or more DUTs")
    repro.add_argument("--case", type=Path, required=True)
    repro.add_argument("--dut", default="spike,rocket-clean,boom-clean")
    repro.add_argument("--out", type=Path, required=True)
    repro.add_argument("--per-case-timeout", type=int, default=60)
    repro.add_argument("--dut-bin", type=Path, default=None)
    repro.add_argument("--no-smepmp", action="store_true")
    _add_common_env_args(repro)

    triage = subparsers.add_parser("triage", help="classify and deduplicate campaign failures")
    triage.add_argument("--run-dir", type=Path, required=True)

    coverage = subparsers.add_parser("coverage", help="write coverage bins for a campaign")
    coverage.add_argument("--run-dir", type=Path, required=True)

    schedule = subparsers.add_parser("schedule", help="build the next semantic coverage-guided campaign")
    schedule.add_argument("--from-runs", required=True, help="comma-separated run directories")
    schedule.add_argument("--target", default=CORE_STATEFUL_TARGET)
    schedule.add_argument("--max-cases", type=int, default=64)
    schedule.add_argument("--seed", type=int, default=20260628)
    schedule.add_argument("--out", type=Path, required=True)
    schedule.add_argument("--include-experimental", action="store_true")
    schedule.add_argument("--coverage-mode", choices=["semantic", "pairwise", "security-triples"], default="semantic")

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
    if args.command == "schedule":
        schedule_path = write_schedule(
            _parse_run_dirs(args.from_runs),
            target=args.target,
            max_cases=args.max_cases,
            seed=args.seed,
            out_dir=args.out,
            include_experimental=args.include_experimental,
            coverage_mode=args.coverage_mode,
        )
        print(f"schedule={schedule_path}")
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
    checks = [
        ("spike", Path(args.spike).exists() or shutil.which(args.spike) is not None, args.spike),
        (
            "riscv-gcc",
            shutil.which("riscv64-unknown-elf-gcc") is not None
            or Path("/home/dubhe/wjs/boom_host_deploy/opt-riscv/bin/riscv64-unknown-elf-gcc").exists(),
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
            DEFAULT_XIANGSHAN_EMU.exists() or LEGACY_XIANGSHAN_EMU.exists(),
            f"{DEFAULT_XIANGSHAN_EMU} fallback={LEGACY_XIANGSHAN_EMU}",
        ),
    ]
    ok = True
    for name, passed, detail in checks:
        ok = ok and passed
        print(f"{name}: {'ok' if passed else 'missing'} {detail}")
    return 0 if ok else 1


def _cmd_probe_dut(args: argparse.Namespace) -> int:
    duts = [item.strip() for item in args.dut.split(",") if item.strip()]
    matrix = capability_matrix(duts)
    write_json(args.out / "dut_capabilities.json", matrix)
    for dut_name, capability in matrix["duts"].items():
        print(
            f"{dut_name}: {'ok' if capability['available'] else 'missing'} "
            f"finish={capability['finish_protocol']} diagnostic={capability['diagnostic_depth']} "
            f"oracle={capability['oracle_applicability']}"
        )
    return 0


def _cmd_gen(args: argparse.Namespace) -> int:
    scenarios = _selected_scenarios(args)
    cases_dir = args.out / "cases"
    emitter = AssemblyEmitter()
    for index, scenario in scenarios:
        case_dir = cases_dir / scenario.name
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / f"{scenario.name}.S").write_text(emitter.emit(scenario, backend=args.backend), encoding="ascii")
        write_json(case_dir / "case.json", scenario_to_case_dict(scenario, seed=args.seed, index=index))
    print(f"generated={len(scenarios)} out={cases_dir}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
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
    )
    results = run_campaign(config)
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
    source_asm = case_dir / f"{case['name']}.S"
    asm = out_cases / source_asm.name
    elf = out_cases / f"{case['name']}.elf"
    shutil.copy2(source_asm, asm)
    write_json(out_cases / "case.json", case)

    root = Path(__file__).resolve().parents[1]
    compile_run = subprocess.run(
        ["sh", str(root / "scripts" / "compile_one.sh"), str(asm), str(elf)],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if compile_run.returncode != 0:
        (out / "compile.log").write_text(compile_run.stdout, encoding="ascii", errors="replace")
        print(f"compile-failed out={out / 'compile.log'}")
        return 1

    any_failed = False
    for dut_name in [item.strip() for item in args.dut.split(",") if item.strip()]:
        result_dir = out_results / f"{case['name']}_{dut_name}"
        result_dir.mkdir(parents=True, exist_ok=True)
        log = result_dir / f"{case['name']}.{dut_name}.log"
        chipyard_dir = args.chipyard_dir or (
            DEFAULT_CLEAN_CHIPYARD_DIR if dut_name in CLEAN_CHIPYARD_DUTS else DEFAULT_CHIPYARD_DIR
        )
        dut = make_dut(
            dut=dut_name,
            spike=args.spike,
            isa=args.isa or ("rv64gc" if args.no_smepmp else "rv64gc_smepmp"),
            chipyard_dir=chipyard_dir,
            dut_bin=args.dut_bin,
        )
        start = time.monotonic()
        dut_result = dut.run(elf, timeout_seconds=args.per_case_timeout, log_path=log)
        capability = (
            capability_for_dut(dut_name, path=args.dut_bin)
            if args.dut_bin and dut_name == "xiangshan-clean"
            else capability_for_dut(dut_name)
        )
        applicability = oracle_applicability_for_result(
            case,
            capability,
            status=dut_result.status,
            failure_class=dut_result.failure_class,
        )
        result = result_to_dict(
            case=case,
            dut=dut_name,
            status=dut_result.status,
            elapsed_seconds=time.monotonic() - start,
            returncode=dut_result.returncode,
            log=log,
            reason=dut_result.reason,
            observed_tohost=dut_result.observed_tohost,
            observed_mcause=dut_result.observed_mcause,
            observed_mtval=dut_result.observed_mtval,
            failure_class=dut_result.failure_class,
            oracle_applicability=applicability,
        )
        write_json(result_dir / "result.json", result)
        any_failed = any_failed or dut_result.status != "pass"
        print(f"{dut_name}: {dut_result.status} failure_class={dut_result.failure_class}")

    write_aggregate(out)
    return 1 if any_failed else 0


def _selected_scenarios(args: argparse.Namespace):
    if args.schedule is not None:
        return scenarios_from_schedule(args.schedule)
    selected = {int(item.strip()) for item in args.indices.split(",") if item.strip()} if args.indices else set()
    profiles = _profiles_from_args(args)
    multi_profile = len(profiles) > 1
    out = []
    for profile in profiles:
        generator = ScenarioGenerator(seed=args.seed, include_smepmp=not args.no_smepmp, profile=profile)
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


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
