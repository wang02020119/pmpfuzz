from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from .capabilities import (
    DEFAULT_CAPABILITY_SCHEMA_VERSION,
    capability_for_dut,
    oracle_applicability_for_case,
    oracle_applicability_for_result,
)
from .dut import DEFAULT_CHIPYARD_DIR, DEFAULT_CLEAN_CHIPYARD_DIR, make_dut
from .emitter import AssemblyEmitter
from .judgment import judge_observation
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
    whitebox_artifacts: bool = False


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
    observed_mepc_tag: int | None = None
    observed_mtval_fingerprint: int | None = None
    observed_event: str | None = None
    observed_phase: str | None = None
    observed_stage: str | None = None
    observed_ptw_level: str | None = None
    observed_fault_address: int | None = None
    observation_valid: bool = False
    stage_verified: bool = False
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
    inconclusive = sum(1 for result in results if result.status == "inconclusive")
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
        "inconclusive": inconclusive,
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


def _run_indexed_work_with_budget(
    indexed_work,
    run_one,
    *,
    max_workers: int,
    start_time: float,
    time_budget_seconds: int,
    time_fn=time.monotonic,
):
    results = []
    work_iter = iter(indexed_work)
    pending = {}

    def submit_next(executor: ThreadPoolExecutor) -> bool:
        if time_fn() - start_time >= time_budget_seconds:
            return False
        try:
            index, item = next(work_iter)
        except StopIteration:
            return False
        pending[executor.submit(run_one, index, item)] = (index, item)
        return True

    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        for _ in range(max(1, max_workers)):
            if not submit_next(executor):
                break
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                pending.pop(future)
                results.append(future.result())
            if time_fn() - start_time >= time_budget_seconds:
                for future in pending:
                    future.cancel()
                break
            while len(pending) < max(1, max_workers):
                if not submit_next(executor):
                    break
    return results


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
            "whitebox_artifacts": config.whitebox_artifacts,
        },
    )
    # Create capability with actual binary path and ISA
    if config.dut == "spike":
        dut_capability = capability_for_dut(
            config.dut,
            path=config.spike,
            isa=config.isa,
        )
    elif config.dut_bin:
        dut_capability = capability_for_dut(
            config.dut,
            path=config.dut_bin,
            isa=config.isa,
        )
    else:
        dut_capability = capability_for_dut(
            config.dut,
            isa=config.isa,
        )
    write_json(
        out_dir / "dut_capabilities.json",
        {
            "schema_version": DEFAULT_CAPABILITY_SCHEMA_VERSION,
            "duts": {config.dut: dut_capability},
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
        whitebox_artifacts=config.whitebox_artifacts,
    )
    emitter_backend = _emitter_backend_for_dut(config.dut)
    indexed_scenarios = _scenario_plan(config)
    root = Path(__file__).resolve().parents[1]
    compile_script = root / "scripts" / "compile_one.sh"
    start = time.monotonic()

    def run_one(index: int, scenario) -> CampaignResult:
        case_start = time.monotonic()
        case = scenario_to_case_dict(scenario, seed=config.seed, index=index)
        expected_allowed = bool(case["expected"]["allowed"])
        expected_cause = case["expected"]["trap_cause"]
        case_applicability = oracle_applicability_for_case(case, dut_capability)
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
        if case_applicability == "unsupported":
            result = CampaignResult(
                name=scenario.name,
                profile=scenario.profile,
                status="setup_unsupported",
                expected_allowed=expected_allowed,
                expected_cause=expected_cause,
                elapsed_seconds=time.monotonic() - case_start,
                failure_class="setup_unsupported",
                reason="case requires capabilities not implemented by this DUT",
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
                    oracle_applicability=case_applicability,
                ),
            )
            return result
        if _requires_rlb_for_setup(scenario):
            result = CampaignResult(
                name=scenario.name,
                profile=scenario.profile,
                status="setup_unsupported",
                expected_allowed=expected_allowed,
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
                    oracle_applicability="unsupported",
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
                expected_allowed=expected_allowed,
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
                    oracle_applicability=case_applicability,
                ),
            )
            return result

        dut_result = dut_runner.run(elf, timeout_seconds=config.per_case_timeout_seconds, log_path=log)
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
        if case_applicability == "capability_dependent" and status in {"pass", "fail"}:
            status = "inconclusive"
            failure_class = "capability_dependent"
            reason = "DUT A/D update mode is unknown; observation cannot select one architectural oracle"
        result_applicability = oracle_applicability_for_result(
            case,
            dut_capability,
            status=status,
            failure_class=failure_class,
        )
        if status != "pass":
            _copy_failure_artifacts(failures, case_dir, result_dir)
        result = CampaignResult(
            name=scenario.name,
            profile=scenario.profile,
            status=status,
            expected_allowed=expected_allowed,
            expected_cause=expected_cause,
            elapsed_seconds=time.monotonic() - case_start,
            returncode=dut_result.returncode,
            failure_class=failure_class,
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
            log=str(log),
            reason=reason,
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
                observed_mepc_tag=result.observed_mepc_tag,
                observed_mtval_fingerprint=result.observed_mtval_fingerprint,
                observed_event=result.observed_event,
                observed_phase=result.observed_phase,
                observed_stage=result.observed_stage,
                observed_ptw_level=result.observed_ptw_level,
                observed_fault_address=result.observed_fault_address,
                observation_valid=result.observation_valid,
                stage_verified=result.stage_verified,
                failure_class=result.failure_class,
                oracle_applicability=result_applicability,
            ),
        )
        return result

    make_based_duts = {"rocket", "cva6", "cva6-clean", "rocket-clean", "boom-clean"}
    effective_jobs = 1 if config.dut in make_based_duts else max(1, config.jobs)
    results: list[CampaignResult] = _run_indexed_work_with_budget(
        indexed_scenarios,
        run_one,
        max_workers=effective_jobs,
        start_time=start,
        time_budget_seconds=config.time_budget_seconds,
    )

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


def _emitter_backend_for_dut(dut: str) -> str:
    if dut == "rocket-cascade":
        return "cascade-mmio"
    if dut == "xiangshan-clean":
        return "xiangshan-goodtrap"
    return "tohost"


def _copy_failure_artifacts(failures: Path, case_dir: Path, result_dir: Path) -> None:
    failure_dir = failures / case_dir.name
    failure_dir.mkdir(parents=True, exist_ok=True)
    for path in list(case_dir.iterdir()) + list(result_dir.iterdir()):
        if path.is_file():
            shutil.copy2(path, failure_dir / path.name)


def _requires_rlb_for_setup(scenario) -> bool:
    if not scenario.mseccfg.mml:
        return False
    if scenario.mseccfg.rlb:
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
