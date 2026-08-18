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
from .bapc import normalize_bapc_core_version, summarize_bapc_for_pmpfuzz_case
from .dut import DEFAULT_CHIPYARD_DIR, DEFAULT_CLEAN_CHIPYARD_DIR, DutRunResult, make_dut
from .emitter import AssemblyEmitter
from .hpm import parse_hpm_uart_snapshots, summarize_hpm_coverage
from .judgment import judge_observation
from .scenario import ScenarioGenerator
from .schema import scenario_to_case_dict, result_to_dict, write_aggregate, write_json
from .semantic_coverage import scenarios_from_schedule


DEFAULT_SPIKE = os.environ.get("PMPFUZZ_SPIKE", shutil.which("spike") or "spike")


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
    record_timeline: bool = False
    campaign_id: str | None = None
    variant: str | None = None
    generator_variant: str = "full"
    hpm_manifest: dict[str, Any] | None = None
    bapc_core_version: str | None = None


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


def _bapc_actual_result(dut_result: DutRunResult) -> dict[str, object]:
    observed_mepc_tag = getattr(dut_result, "observed_mepc_tag", None)
    observed_mtval_fingerprint = getattr(dut_result, "observed_mtval_fingerprint", None)
    if dut_result.observation is not None:
        if observed_mepc_tag is None:
            observed_mepc_tag = dut_result.observation.mepc_tag
        if observed_mtval_fingerprint is None:
            observed_mtval_fingerprint = dut_result.observation.mtval_fingerprint
    observed_event = None
    observation_valid = False
    if dut_result.observation is not None:
        observed_event = dut_result.observation.kind.name.lower()
        observation_valid = True
    elif dut_result.dut != "xiangshan-clean" and dut_result.status == "pass":
        observed_event = "completion"
        observation_valid = True
    elif dut_result.dut != "xiangshan-clean" and dut_result.status == "fail":
        observed_event = "trap"
        observation_valid = True
    return {
        "status": dut_result.status,
        "observation_valid": observation_valid,
        "observed_event": observed_event,
        "observed_mcause": dut_result.observed_mcause,
        "observed_stage": dut_result.observed_stage,
        "observed_fault_address": dut_result.observed_fault_address,
        "observed_mepc_tag": observed_mepc_tag,
        "observed_mtval_fingerprint": observed_mtval_fingerprint,
    }


def _ineligible_bapc_coverage(
    *,
    case: dict[str, Any],
    dut: str,
    status: str,
    elapsed_seconds: float,
    returncode: int | None,
    failure_class: str | None,
    reason: str | None,
    log_text: str,
    supports_smepmp: bool,
    bapc_core_version: str,
) -> dict[str, Any]:
    return summarize_bapc_for_pmpfuzz_case(
        case,
        _bapc_actual_result(
            DutRunResult(
                dut=dut,
                status=status,
                elapsed_seconds=elapsed_seconds,
                returncode=returncode,
                failure_class=failure_class,
                reason=reason,
            )
        ),
        log_text=log_text,
        supports_smepmp=supports_smepmp,
        bapc_core_version=bapc_core_version,
    )


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
        "generator_variant": config.generator_variant,
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
    on_complete=None,
):
    results = []
    work_iter = iter(indexed_work)
    pending = {}
    completion_seq = 0

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
                index, scenario = pending.pop(future)
                result = future.result()
                results.append(result)
                completion_seq += 1
                if on_complete is not None:
                    campaign_elapsed = time_fn() - start_time
                    on_complete(index, scenario, result, completion_seq, campaign_elapsed)
            if time_fn() - start_time >= time_budget_seconds:
                for future in pending:
                    future.cancel()
                break
            while len(pending) < max(1, max_workers):
                if not submit_next(executor):
                    break
    return results


def run_campaign(config: RunnerConfig, *, on_complete=None) -> list[CampaignResult]:
    if not str(config.bapc_core_version or "").strip():
        raise ValueError("run_campaign requires explicit bapc_core_version")
    config = replace(
        config,
        bapc_core_version=normalize_bapc_core_version(config.bapc_core_version),
    )
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
            "generator_variant": config.generator_variant,
            "schedule": str(config.schedule) if config.schedule else None,
            "whitebox_artifacts": config.whitebox_artifacts,
            "bapc_core_version": config.bapc_core_version,
        },
    )

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
    schedule_metadata = _schedule_metadata_by_name(config.schedule)
    root = Path(__file__).resolve().parents[1]
    compile_script = root / "scripts" / "compile_one.sh"
    start = time.monotonic()

    def run_one(index: int, scenario) -> CampaignResult:
        case_start = time.monotonic()
        case = scenario_to_case_dict(
            scenario,
            seed=config.seed,
            index=index,
            generator_variant=config.generator_variant,
            generation_seed=config.seed,
            scenario_index=index,
            mutation_operator="root",
        )
        case.update(schedule_metadata.get(scenario.name, {}))
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
        asm.write_text(
            emitter.emit(scenario, backend=emitter_backend, hpm_manifest=config.hpm_manifest),
            encoding="ascii",
        )
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
            bapc_coverage = _ineligible_bapc_coverage(
                case=case,
                dut=config.dut,
                status=result.status,
                elapsed_seconds=result.elapsed_seconds,
                returncode=None,
                failure_class=result.failure_class,
                reason=result.reason,
                log_text="",
                supports_smepmp=bool(dut_capability["supported_capabilities"].get("smepmp", False)),
                bapc_core_version=config.bapc_core_version,
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
                    bapc_coverage=bapc_coverage,
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
            bapc_coverage = _ineligible_bapc_coverage(
                case=case,
                dut=config.dut,
                status=result.status,
                elapsed_seconds=result.elapsed_seconds,
                returncode=None,
                failure_class=result.failure_class,
                reason=result.reason,
                log_text="",
                supports_smepmp=bool(dut_capability["supported_capabilities"].get("smepmp", False)),
                bapc_core_version=config.bapc_core_version,
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
                    bapc_coverage=bapc_coverage,
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
            bapc_coverage = _ineligible_bapc_coverage(
                case=case,
                dut=config.dut,
                status=result.status,
                elapsed_seconds=result.elapsed_seconds,
                returncode=result.returncode,
                failure_class=result.failure_class,
                reason=result.reason,
                log_text=compile_run.stdout or "",
                supports_smepmp=bool(dut_capability["supported_capabilities"].get("smepmp", False)),
                bapc_core_version=config.bapc_core_version,
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
                    bapc_coverage=bapc_coverage,
                ),
            )
            return result

        dut_result = dut_runner.run(elf, timeout_seconds=config.per_case_timeout_seconds, log_path=log)
        log_text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
        hpm_snapshot_before = None
        hpm_snapshot_after = None
        hpm_coverage = None
        bapc_coverage = None
        if config.hpm_manifest is not None:
            hpm_snapshots = parse_hpm_uart_snapshots(log_text)
            hpm_snapshot_before = hpm_snapshots.get("before")
            hpm_snapshot_after = hpm_snapshots.get("after")
            hpm_coverage = summarize_hpm_coverage(
                manifest=config.hpm_manifest,
                before=hpm_snapshot_before,
                after=hpm_snapshot_after,
            )
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
        bapc_coverage = summarize_bapc_for_pmpfuzz_case(
            case,
            _bapc_actual_result(dut_result),
            log_text=log_text,
            supports_smepmp=bool(dut_capability["supported_capabilities"].get("smepmp", False)),
            bapc_core_version=config.bapc_core_version,
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
                hpm_manifest=config.hpm_manifest,
                hpm_snapshot_before=hpm_snapshot_before,
                hpm_snapshot_after=hpm_snapshot_after,
                hpm_coverage=hpm_coverage,
                bapc_coverage=bapc_coverage,
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
        on_complete=on_complete,
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
        generator = ScenarioGenerator(
            seed=config.seed,
            include_smepmp=config.include_smepmp,
            profile=profile,
            generator_variant=config.generator_variant,
        )
        scenarios = generator.generate_batch(config.count)
        for index, scenario in enumerate(scenarios):
            if selected and index not in selected:
                continue
            if multi_profile:
                scenario = replace(scenario, name=f"{profile}__{scenario.name}")
            indexed_scenarios.append((index, scenario))
    return indexed_scenarios


def _schedule_metadata_by_name(schedule_path: Path | None) -> dict[str, dict[str, Any]]:
    if schedule_path is None:
        return {}
    try:
        schedule = json.loads(Path(schedule_path).read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    entries = schedule.get("entries") or []
    if not isinstance(entries, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    default_seed = int(schedule.get("seed") or 0)
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "")
        if not name:
            continue
        metadata = {
            "generator_variant": str(entry.get("generator_variant") or "full"),
            "generation_seed": int(entry.get("generation_seed") or entry.get("seed") or default_seed),
            "scenario_index": int(
                entry.get("scenario_index")
                if entry.get("scenario_index") is not None
                else entry.get("index", 0)
            ),
            "mutation_operator": str(entry.get("mutation_operator") or "root"),
        }
        if entry.get("continuous_sequence") is not None:
            metadata["continuous_sequence"] = int(entry["continuous_sequence"])
        out[name] = metadata
    return out


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
    parser.add_argument("--generator-variant", choices=["full", "syntax"], default="full")
    parser.add_argument("--indices", default=None)
    parser.add_argument("--no-smepmp", action="store_true")
    parser.add_argument("--bapc-core-version", choices=["v2", "v3", "v4"], default=None)
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
        generator_variant=args.generator_variant,
        include_smepmp=not args.no_smepmp,
        indices=_parse_indices(args.indices),
        bapc_core_version=args.bapc_core_version,
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
