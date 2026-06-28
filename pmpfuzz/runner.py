from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from .dut import DEFAULT_CHIPYARD_DIR, DEFAULT_CLEAN_CHIPYARD_DIR, make_dut
from .emitter import AssemblyEmitter
from .oracle import evaluate_scenario
from .scenario import ScenarioGenerator
from .schema import scenario_to_case_dict, result_to_dict, write_aggregate, write_json
from .semantic_coverage import scenarios_from_schedule


DEFAULT_SPIKE = "/home/dubhe/wjs/boom_host_deploy/opt-riscv/bin/spike"


@dataclass(frozen=True)
class RunnerConfig:
    profile: str
    count: int
    seed: int
    jobs: int
    time_budget_seconds: int
    out: Path
    profiles: tuple[str, ...] | None = None
    dut: str = "spike"
    spike: str = DEFAULT_SPIKE
    isa: str = "rv64gc_smepmp"
    chipyard_dir: Path = DEFAULT_CHIPYARD_DIR
    dut_bin: Path | None = None
    simlen: int = 100000
    per_case_timeout_seconds: int = 10
    include_smepmp: bool = True
    indices: tuple[int, ...] | None = None
    schedule: Path | None = None


@dataclass(frozen=True)
class CampaignResult:
    name: str
    profile: str
    status: str
    expected_allowed: bool
    expected_cause: int | None
    elapsed_seconds: float
    returncode: int | None = None
    failure_class: str | None = None
    observed_tohost: int | None = None
    observed_mcause: int | None = None
    observed_mtval: int | None = None
    log: str | None = None
    reason: str | None = None


def parse_time_budget(value: str) -> int:
    unit = value[-1]
    amount = int(value[:-1]) if unit in {"h", "m", "s"} else int(value)
    if unit == "h":
        return amount * 60 * 60
    if unit == "m":
        return amount * 60
    if unit == "s":
        return amount
    return amount


def write_summary(*, config: RunnerConfig, results: list[CampaignResult]) -> None:
    config.out.mkdir(parents=True, exist_ok=True)
    passed = sum(1 for result in results if result.status == "pass")
    failed = sum(1 for result in results if result.status == "fail")
    timed_out = sum(1 for result in results if result.status == "timeout")
    compile_failed = sum(1 for result in results if result.status == "compile_fail")
    infra_failed = sum(1 for result in results if result.status == "infra_failure")
    setup_unsupported = sum(1 for result in results if result.status == "setup_unsupported")
    nonpass = sum(1 for result in results if result.status not in {"pass", "setup_unsupported"})
    summary = {
        "profile": config.profile,
        "profiles": list(config.profiles or (config.profile,)),
        "dut": config.dut,
        "seed": config.seed,
        "count_requested": config.count,
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "timed_out": timed_out,
        "compile_failed": compile_failed,
        "infra_failed": infra_failed,
        "nonpass": nonpass,
        "setup_unsupported": setup_unsupported,
        "time_budget_seconds": config.time_budget_seconds,
        "spike": config.spike,
        "isa": config.isa,
        "chipyard_dir": str(config.chipyard_dir),
        "results": [asdict(result) for result in results],
        "schedule": str(config.schedule) if config.schedule else None,
    }
    (config.out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="ascii")

    with (config.out / "coverage.csv").open("w", encoding="ascii", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["profile", "status", "expected_allowed", "expected_cause", "count"])
        buckets: dict[tuple[str, str, bool, int | None], int] = {}
        for result in results:
            key = (result.profile, result.status, result.expected_allowed, result.expected_cause)
            buckets[key] = buckets.get(key, 0) + 1
        for (profile, status, expected_allowed, expected_cause), count in sorted(buckets.items()):
            writer.writerow([profile, status, int(expected_allowed), expected_cause if expected_cause is not None else "", count])


def run_campaign(config: RunnerConfig) -> list[CampaignResult]:
    out_dir = config.out.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    cases_dir = out_dir / "cases"
    results_dir = out_dir / "results"
    failures = out_dir / "failures"
    cases_dir.mkdir(exist_ok=True)
    results_dir.mkdir(exist_ok=True)
    failures.mkdir(exist_ok=True)
    write_json(
        out_dir / "run.json",
        {
            "profile": config.profile,
            "profiles": list(config.profiles or (config.profile,)),
            "dut": config.dut,
            "seed": config.seed,
            "count_requested": config.count,
            "jobs": config.jobs,
            "time_budget_seconds": config.time_budget_seconds,
            "spike": config.spike,
            "isa": config.isa,
            "chipyard_dir": str(config.chipyard_dir),
            "include_smepmp": config.include_smepmp,
            "schedule": str(config.schedule) if config.schedule else None,
        },
    )
    emitter = AssemblyEmitter()
    dut_runner = make_dut(
        dut=config.dut,
        spike=config.spike,
        isa=config.isa,
        chipyard_dir=config.chipyard_dir,
        dut_bin=config.dut_bin,
        simlen=config.simlen,
    )
    emitter_backend = "cascade-mmio" if config.dut == "rocket-cascade" else "tohost"
    indexed_scenarios = _scenario_plan(config)
    root = Path(__file__).resolve().parents[1]
    compile_script = root / "scripts" / "compile_one.sh"
    start = time.monotonic()

    def run_one(index: int, scenario) -> CampaignResult:
        case_start = time.monotonic()
        outcome = evaluate_scenario(scenario)
        expected_cause = int(outcome.trap_cause) if outcome.trap_cause is not None else None
        case = scenario_to_case_dict(scenario, seed=config.seed, index=index)
        case_dir = cases_dir / scenario.name
        result_dir = results_dir / scenario.name
        case_dir.mkdir(parents=True, exist_ok=True)
        result_dir.mkdir(parents=True, exist_ok=True)
        asm = case_dir / f"{scenario.name}.S"
        elf = case_dir / f"{scenario.name}.elf"
        log = result_dir / f"{scenario.name}.log"
        case_path = case_dir / "case.json"
        asm.write_text(emitter.emit(scenario, backend=emitter_backend), encoding="ascii")
        write_json(case_path, case)
        if _requires_rlb_for_setup(scenario):
            result = CampaignResult(
                name=scenario.name,
                profile=scenario.profile,
                status="setup_unsupported",
                expected_allowed=outcome.allowed,
                expected_cause=expected_cause,
                elapsed_seconds=time.monotonic() - case_start,
                failure_class="setup_unsupported",
                reason="locked Smepmp RW=01 setup requires mseccfg.RLB; this Spike hardwires RLB to zero",
            )
            write_json(
                result_dir / "result.json",
                result_to_dict(
                    case=case,
                    dut=config.dut,
                    status=result.status,
                    elapsed_seconds=result.elapsed_seconds,
                    returncode=None,
                    log=log,
                    reason=result.reason,
                    failure_class=result.failure_class,
                ),
            )
            return result

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
            _copy_failure_artifacts(failures, case_dir, result_dir)
            result = CampaignResult(
                name=scenario.name,
                profile=scenario.profile,
                status="compile_fail",
                expected_allowed=outcome.allowed,
                expected_cause=expected_cause,
                elapsed_seconds=time.monotonic() - case_start,
                returncode=compile_run.returncode,
                failure_class="compile_fail",
                log=str(log),
                reason="compile failed",
            )
            write_json(
                result_dir / "result.json",
                result_to_dict(
                    case=case,
                    dut=config.dut,
                    status=result.status,
                    elapsed_seconds=result.elapsed_seconds,
                    returncode=result.returncode,
                    log=log,
                    reason=result.reason,
                    failure_class=result.failure_class,
                ),
            )
            return result

        dut_result = dut_runner.run(elf, timeout_seconds=config.per_case_timeout_seconds, log_path=log)
        status = dut_result.status
        if status != "pass":
            _copy_failure_artifacts(failures, case_dir, result_dir)
        result = CampaignResult(
            name=scenario.name,
            profile=scenario.profile,
            status=status,
            expected_allowed=outcome.allowed,
            expected_cause=expected_cause,
            elapsed_seconds=time.monotonic() - case_start,
            returncode=dut_result.returncode,
            failure_class=dut_result.failure_class,
            observed_tohost=dut_result.observed_tohost,
            observed_mcause=dut_result.observed_mcause,
            observed_mtval=dut_result.observed_mtval,
            log=str(log),
            reason=dut_result.reason,
        )
        write_json(
            result_dir / "result.json",
            result_to_dict(
                case=case,
                dut=config.dut,
                status=result.status,
                elapsed_seconds=result.elapsed_seconds,
                returncode=result.returncode,
                log=log,
                reason=result.reason,
                observed_tohost=result.observed_tohost,
                observed_mcause=result.observed_mcause,
                observed_mtval=result.observed_mtval,
                failure_class=result.failure_class,
            ),
        )
        return result

    results: list[CampaignResult] = []
    make_based_duts = {"rocket", "cva6", "cva6-clean", "rocket-clean", "boom-clean"}
    effective_jobs = 1 if config.dut in make_based_duts else max(1, config.jobs)
    with ThreadPoolExecutor(max_workers=effective_jobs) as executor:
        futures = []
        for index, _scenario in indexed_scenarios:
            if time.monotonic() - start >= config.time_budget_seconds:
                break
            futures.append(executor.submit(run_one, index, _scenario))
        for future in as_completed(futures):
            results.append(future.result())
            if time.monotonic() - start >= config.time_budget_seconds:
                break

    results.sort(key=lambda result: result.name)
    write_summary(config=config, results=results)
    write_aggregate(out_dir)
    return results


def _scenario_plan(config: RunnerConfig):
    if config.schedule is not None:
        return scenarios_from_schedule(config.schedule)
    profiles = config.profiles or (config.profile,)
    multi_profile = len(profiles) > 1
    selected = set(config.indices or ())
    indexed_scenarios = []
    for profile in profiles:
        generator = ScenarioGenerator(seed=config.seed, include_smepmp=config.include_smepmp, profile=profile)
        scenarios = generator.generate_batch(config.count)
        for index, scenario in enumerate(scenarios):
            if selected and index not in selected:
                continue
            if multi_profile:
                scenario = replace(scenario, name=f"{profile}__{scenario.name}")
            indexed_scenarios.append((index, scenario))
    return indexed_scenarios


def _copy_failure_artifacts(failures: Path, case_dir: Path, result_dir: Path) -> None:
    failure_dir = failures / case_dir.name
    failure_dir.mkdir(parents=True, exist_ok=True)
    for path in list(case_dir.iterdir()) + list(result_dir.iterdir()):
        if path.is_file():
            shutil.copy2(path, failure_dir / path.name)


def _requires_rlb_for_setup(scenario) -> bool:
    if not scenario.mseccfg.mml:
        return False
    for entry in scenario.entries:
        if entry.index <= 2:
            continue
        if entry.locked and entry.write and not entry.read:
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a PMP/Smepmp/MMU Spike campaign")
    parser.add_argument("--profile", default="mixed-smepmp-mmu")
    parser.add_argument("--count", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=20260628)
    parser.add_argument("--jobs", type=int, default=max(1, os.cpu_count() or 1))
    parser.add_argument("--time-budget", default="7h")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--dut",
        choices=[
            "spike",
            "rocket",
            "cva6",
            "cva6-clean",
            "rocket-cascade",
            "rocket-clean",
            "boom-clean",
            "xiangshan-clean",
        ],
        default="spike",
    )
    parser.add_argument("--spike", default=os.environ.get("SPIKE", DEFAULT_SPIKE))
    parser.add_argument("--isa", default=None)
    parser.add_argument("--chipyard-dir", type=Path, default=None)
    parser.add_argument("--dut-bin", type=Path, default=None)
    parser.add_argument("--simlen", type=int, default=100000)
    parser.add_argument("--per-case-timeout", type=int, default=10)
    parser.add_argument("--indices", default=None)
    parser.add_argument("--no-smepmp", action="store_true")
    args = parser.parse_args()

    config = RunnerConfig(
        profile=args.profile,
        count=_effective_count(args.count, args.indices),
        seed=args.seed,
        jobs=args.jobs,
        time_budget_seconds=parse_time_budget(args.time_budget),
        out=args.out,
        dut=args.dut,
        spike=args.spike,
        isa=args.isa or os.environ.get("SPIKE_ISA") or ("rv64gc" if args.no_smepmp else "rv64gc_smepmp"),
        chipyard_dir=args.chipyard_dir
        or (DEFAULT_CLEAN_CHIPYARD_DIR if args.dut in {"rocket-clean", "boom-clean", "cva6", "cva6-clean"} else DEFAULT_CHIPYARD_DIR),
        dut_bin=args.dut_bin,
        simlen=args.simlen,
        per_case_timeout_seconds=args.per_case_timeout,
        include_smepmp=not args.no_smepmp,
        indices=_parse_indices(args.indices),
    )
    results = run_campaign(config)
    failed = [result for result in results if result.status not in {"pass", "setup_unsupported"}]
    skipped = [result for result in results if result.status == "setup_unsupported"]
    print(
        f"campaign-total={len(results)} pass={sum(1 for result in results if result.status == 'pass')} "
        f"setup_unsupported={len(skipped)} nonpass={len(failed)} out={config.out}"
    )
    return 1 if failed else 0


def _parse_indices(value: str | None) -> tuple[int, ...] | None:
    if not value:
        return None
    return tuple(int(item.strip()) for item in value.split(",") if item.strip())


def _effective_count(count: int, indices: str | None) -> int:
    parsed = _parse_indices(indices)
    if not parsed:
        return count
    return max(count, max(parsed) + 1)


if __name__ == "__main__":
    raise SystemExit(main())
