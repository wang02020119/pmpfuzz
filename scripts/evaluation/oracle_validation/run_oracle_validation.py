from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Mapping

from pmpfuzz.capabilities import capability_for_dut, oracle_applicability_for_case, oracle_applicability_for_result
from pmpfuzz.dut import DEFAULT_CHIPYARD_DIR, DEFAULT_CLEAN_CHIPYARD_DIR, make_dut
from pmpfuzz.emitter import AssemblyEmitter, CVA6_SV39_TLB_STALE_PTE_COMPACT
from pmpfuzz.judgment import judge_observation
from pmpfuzz.runner import DEFAULT_SPIKE
from pmpfuzz.scenario_codec import scenario_from_spec
from pmpfuzz.schema import result_to_dict, scenario_to_case_dict

from .directed_suite import build_directed_suite_plans
from .mutate_observations import run_counterfactual_judgment

ONLINE_EXPERIMENT_ID = "E3-ONLINE"
ONLINE_CONTROL_MUTANT_ID = "clean-control"
ORACLE_VALIDATION_PROTOCOL_ID = "oracle-validation-v1"


def _requires_whitebox_artifacts(*, dut: str, materialize_only: bool) -> bool:

    return not materialize_only and dut != "spike"


def run_clean_suite(
    *,
    cases_path: Path,
    labels_path: Path,
    out_dir: Path,
    dut: str,
    order_seed: int,
    spike: str = DEFAULT_SPIKE,
    isa: str = "rv64gc_smepmp",
    chipyard_dir: Path | None = None,
    dut_bin: Path | None = None,
    simlen: int = 100000,
    per_case_timeout: int = 30,
    limit: int | None = None,
    include_case_ids: set[str] | None = None,
    materialize_only: bool = False,
    suite_root: Path | None = None,
    archive_existing: bool = False,
) -> dict[str, Any]:
    cases = _load_jsonl(cases_path)
    labels = {str(item["case_id"]): item for item in _load_jsonl(labels_path)}
    selected = [case for case in cases if not include_case_ids or str(case["case_id"]) in include_case_ids]
    random.Random(order_seed).shuffle(selected)
    if limit is not None:
        selected = selected[:limit]

    seed_root = suite_root or (out_dir / "clean" / dut / f"seed-{order_seed:04d}")
    archived_previous_suite_root = _archive_existing_suite_root(seed_root) if archive_existing else None
    seed_root.mkdir(parents=True, exist_ok=True)

    repo_root = Path(__file__).resolve().parents[3]
    compile_script = repo_root / "scripts" / "compile_one.sh"
    emitter = AssemblyEmitter()
    resolved_chipyard = chipyard_dir or (
        DEFAULT_CLEAN_CHIPYARD_DIR if dut in {"rocket-clean", "boom-clean", "cva6", "cva6-clean"} else DEFAULT_CHIPYARD_DIR
    )
    capability = capability_for_dut(
        dut,
        path=spike if dut == "spike" else dut_bin,
        isa=isa,
    )
    whitebox_artifacts = _requires_whitebox_artifacts(dut=dut, materialize_only=materialize_only)
    dut_runner = None if materialize_only else make_dut(
        dut=dut,
        spike=spike,
        isa=isa,
        chipyard_dir=resolved_chipyard,
        dut_bin=dut_bin,
        simlen=simlen,
        whitebox_artifacts=whitebox_artifacts,
    )
    backend = "xiangshan-goodtrap" if dut == "xiangshan-clean" else "cascade-mmio" if dut == "rocket-cascade" else "tohost"

    rows: list[dict[str, Any]] = []
    for ordinal, frozen_case in enumerate(selected):
        case_id = str(frozen_case["case_id"])
        label = labels[case_id]
        scenario = scenario_from_spec(dict(frozen_case["scenario_spec"]))
        execution_case = scenario_to_case_dict(scenario, seed=order_seed, index=ordinal)
        lowering_profile = _clean_suite_lowering_profile(dut=dut, scenario=scenario, emitter=emitter)
        lowering_metadata = emitter.lowering_metadata(scenario, lowering_profile=lowering_profile)
        case_root = seed_root / case_id
        case_root.mkdir(parents=True, exist_ok=True)
        asm_path = case_root / f"{case_id}.S"
        elf_path = case_root / f"{case_id}.elf"
        log_path = case_root / "raw.log"
        scenario_path = case_root / "scenario.json"
        case_path = case_root / "case.json"
        label_path = case_root / "reference-label.json"
        trace_path = case_root / "contract-trace.json"
        lowering_path = case_root / "lowering.json"
        observation_path = case_root / "observation.json"
        result_path = case_root / "result.json"

        asm_path.write_text(
            emitter.emit(scenario, backend=backend, lowering_profile=lowering_profile),
            encoding="ascii",
        )
        _write_json(scenario_path, frozen_case)
        _write_json(case_path, execution_case)
        _write_json(label_path, label)
        _write_json(trace_path, execution_case.get("contract_trace") or {})
        _write_json(
            lowering_path,
            {
                "case_id": case_id,
                "dut": dut,
                **lowering_metadata,
            },
        )

        applicability = oracle_applicability_for_case(execution_case, capability)
        if applicability == "unsupported":
            result = result_to_dict(
                case=execution_case,
                dut=dut,
                status="setup_unsupported",
                elapsed_seconds=0.0,
                returncode=None,
                log=log_path,
                reason="case requires capabilities not implemented by this DUT",
                failure_class="setup_unsupported",
                oracle_applicability=applicability,
            )
            _write_json(observation_path, {"schema_version": 1, "available": False})
            _write_json(result_path, result)
            rows.append({"case_id": case_id, "status": "setup_unsupported"})
            continue

        if materialize_only:
            _write_json(observation_path, {"schema_version": 1, "available": False, "materialized_only": True})
            _write_json(
                result_path,
                result_to_dict(
                    case=execution_case,
                    dut=dut,
                    status="materialized_only",
                    elapsed_seconds=0.0,
                    returncode=None,
                    log=log_path,
                    reason="materialized without execution",
                    oracle_applicability=applicability,
                ),
            )
            rows.append({"case_id": case_id, "status": "materialized_only"})
            continue

        compile_run = subprocess.run(
            ["sh", str(compile_script), str(asm_path), str(elf_path)],
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if compile_run.returncode != 0:
            log_path.write_text(compile_run.stdout, encoding="utf-8", errors="replace")
            _write_json(observation_path, {"schema_version": 1, "available": False})
            _write_json(
                result_path,
                result_to_dict(
                    case=execution_case,
                    dut=dut,
                    status="compile_fail",
                    elapsed_seconds=0.0,
                    returncode=compile_run.returncode,
                    log=log_path,
                    reason="compile failed",
                    failure_class="compile_fail",
                    oracle_applicability=applicability,
                ),
            )
            rows.append({"case_id": case_id, "status": "compile_fail"})
            continue

        start = time.monotonic()
        dut_result = dut_runner.run(elf_path, timeout_seconds=per_case_timeout, log_path=log_path)
        elapsed = time.monotonic() - start
        status = dut_result.status
        failure_class = dut_result.failure_class
        reason = dut_result.reason
        observation_valid = False
        stage_verified = False
        observed_record = _observed_record(dut_result)
        if status == "observed" and dut_result.observation is not None:
            judgment = judge_observation(
                execution_case,
                dut_result.observation,
                observed_stage=dut_result.observed_stage,
                observed_ptw_level=dut_result.observed_ptw_level,
                observed_fault_address=dut_result.observed_fault_address,
                observed_probe_vaddr=dut_result.observed_probe_vaddr,
            )
            status = judgment.status
            failure_class = judgment.failure_class
            reason = judgment.reason
            observation_valid = judgment.observation_valid
            stage_verified = judgment.stage_verified

        applicability_result = oracle_applicability_for_result(
            execution_case,
            capability,
            status=status,
            failure_class=failure_class,
        )
        result = result_to_dict(
            case=execution_case,
            dut=dut,
            status=status,
            elapsed_seconds=elapsed,
            returncode=dut_result.returncode,
            log=log_path,
            reason=reason,
            observed_tohost=dut_result.observed_tohost,
            observed_mcause=dut_result.observed_mcause,
            observed_mtval=dut_result.observed_mtval,
            observed_mepc_tag=(dut_result.observation.mepc_tag if dut_result.observation else None),
            observed_mtval_fingerprint=(dut_result.observation.mtval_fingerprint if dut_result.observation else None),
            observed_event=(dut_result.observation.kind.name.lower() if dut_result.observation else None),
            observed_phase=(dut_result.observation.phase.name.lower() if dut_result.observation else None),
            observed_stage=dut_result.observed_stage,
            observed_ptw_level=dut_result.observed_ptw_level,
            observed_fault_address=dut_result.observed_fault_address,
            observed_probe_vaddr=dut_result.observed_probe_vaddr,
            observation_valid=observation_valid,
            stage_verified=stage_verified,
            failure_class=failure_class,
            oracle_applicability=applicability_result,
        )
        _write_json(observation_path, observed_record)
        _write_json(result_path, result)
        rows.append({"case_id": case_id, "status": status, "failure_class": failure_class})

    summary = {
        "schema_version": 1,
        "dut": dut,
        "order_seed": order_seed,
        "case_count": len(rows),
        "materialize_only": materialize_only,
        "whitebox_artifacts": whitebox_artifacts,
        "suite_root": str(seed_root),
        "archived_previous_suite_root": (
            str(archived_previous_suite_root) if archived_previous_suite_root is not None else None
        ),
        "results": rows,
    }
    _write_json(seed_root / "summary.json", summary)
    return summary


def _clean_suite_lowering_profile(*, dut: str, scenario: Any, emitter: AssemblyEmitter) -> str | None:
    if dut not in {"cva6", "cva6-clean"}:
        return None
    if emitter.supports_lowering_profile(scenario, CVA6_SV39_TLB_STALE_PTE_COMPACT):
        return CVA6_SV39_TLB_STALE_PTE_COMPACT
    return None


def plan_directed_suite(
    *,
    artifact_root: Path,
    max_controls_per_mutant: int = 8,
) -> dict[str, Any]:
    return build_directed_suite_plans(
        artifact_root=artifact_root,
        max_controls_per_mutant=max_controls_per_mutant,
    )


def run_directed_suite(
    *,
    artifact_root: Path,
    dut: str,
    mutant_id: str,
    order_seed: int,
    spike: str = DEFAULT_SPIKE,
    isa: str = "rv64gc_smepmp",
    chipyard_dir: Path | None = None,
    dut_bin: Path | None = None,
    simlen: int = 100000,
    per_case_timeout: int = 30,
    materialize_only: bool = False,
    max_controls_per_mutant: int = 8,
    refresh_plan: bool = False,
) -> dict[str, Any]:
    artifact_root = Path(artifact_root)
    plan_path = artifact_root / "mutants" / dut / mutant_id / "activation-plan.json"
    if refresh_plan or not plan_path.exists():
        plan_directed_suite(
            artifact_root=artifact_root,
            max_controls_per_mutant=max_controls_per_mutant,
        )
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    activation_ids = [str(item) for item in plan.get("activation_case_ids") or []]
    control_ids = [str(item) for item in plan.get("control_case_ids") or []]
    selected_case_ids = set(activation_ids) | set(control_ids)
    if not selected_case_ids:
        raise ValueError(f"directed suite has no selected cases for {dut}/{mutant_id}")

    mutant_root = artifact_root / "mutants" / dut / mutant_id
    resolved_dut_bin = dut_bin or _dut_bin_from_build_manifest(mutant_root / "build-manifest.json")
    if resolved_dut_bin is None or not resolved_dut_bin.exists():
        raise ValueError(f"directed suite DUT binary is unavailable for {dut}/{mutant_id}")
    suite_root = mutant_root / "directed" / f"seed-{order_seed:04d}"
    summary = run_clean_suite(
        cases_path=artifact_root / "reference" / "cases.jsonl",
        labels_path=artifact_root / "reference" / "labels.jsonl",
        out_dir=artifact_root,
        dut=dut,
        order_seed=order_seed,
        spike=spike,
        isa=isa,
        chipyard_dir=chipyard_dir,
        dut_bin=resolved_dut_bin,
        simlen=simlen,
        per_case_timeout=per_case_timeout,
        include_case_ids=selected_case_ids,
        materialize_only=materialize_only,
        suite_root=suite_root,
        archive_existing=True,
    )
    summary.update(
        {
            "mutant_id": mutant_id,
            "activation_case_count": len(activation_ids),
            "control_case_count": len(control_ids),
            "selected_case_count": len(selected_case_ids),
        }
    )
    _write_json(suite_root / "summary.json", summary)
    return summary


def run_counterfactual_suite(
    *,
    cases_path: Path,
    counterfactuals_path: Path,
    out_dir: Path,
) -> dict[str, Any]:
    cases = {str(item["case_id"]): _normalize_counterfactual_case(item) for item in _load_jsonl(cases_path)}
    counterfactuals = _load_jsonl(counterfactuals_path)
    out_root = out_dir / "counterfactual"
    out_root.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []

    for item in counterfactuals:
        case_id = str(item["case_id"])
        case = cases[case_id]
        case_dir = out_root / case_id / str(item["mutation_id"])
        case_dir.mkdir(parents=True, exist_ok=True)
        actual = run_counterfactual_judgment(case_record=case, counterfactual=item)
        _write_json(case_dir / "counterfactual.json", item)
        _write_json(case_dir / "judgment.json", actual)
        rows.append(
            {
                "case_id": case_id,
                "mutation_id": item["mutation_id"],
                "status": actual["status"],
                "failure_class": actual["failure_class"],
            }
        )

    summary = {"schema_version": 1, "counterfactual_count": len(rows), "results": rows}
    _write_json(out_root / "summary.json", summary)
    return summary


def run_online_campaign(
    *,
    artifact_root: Path,
    dut: str,
    seed: int,
    mutant_id: str | None = None,
    clean_control: bool = False,
    control_mutant_id: str = ONLINE_CONTROL_MUTANT_ID,
    experiment_id: str = ONLINE_EXPERIMENT_ID,
    variant: str = "bb-guided",
    spike: str = DEFAULT_SPIKE,
    isa: str = "rv64gc_smepmp",
    chipyard_dir: Path | None = None,
    dut_bin: Path | None = None,
    time_budget_seconds: int = 7200,
    candidate_budget: int = 2048,
    round_size: int = 32,
    bootstrap_size: int = 32,
    per_case_timeout: int = 10,
    jobs: int = 1,
    resume: bool = False,
) -> dict[str, Any]:
    artifact_root = Path(artifact_root).resolve()
    resolved_chipyard = chipyard_dir or (
        DEFAULT_CLEAN_CHIPYARD_DIR if dut in {"rocket-clean", "boom-clean", "cva6", "cva6-clean"} else DEFAULT_CHIPYARD_DIR
    )
    protocol_id = _oracle_validation_protocol_id(artifact_root)

    if clean_control:
        if mutant_id not in {None, "", control_mutant_id}:
            raise ValueError("clean-control campaign must not use a semantic mutant id")
        selected_mutant_id = str(control_mutant_id)
        resolved_dut_bin = _resolve_online_clean_dut_binary(
            dut=dut,
            chipyard_dir=resolved_chipyard,
            dut_bin=dut_bin,
        )
        fault_family = "clean_control"
        critical_family = False
        _record_online_control_binary(
            artifact_root=artifact_root,
            dut=dut,
            control_mutant_id=selected_mutant_id,
            binary_path=resolved_dut_bin,
        )
    else:
        if not mutant_id:
            raise ValueError("online mutant campaign requires --mutant-id or --clean-control")
        selected_mutant_id = str(mutant_id)
        entry = _mutant_manifest_entry(
            artifact_root=artifact_root,
            dut=dut,
            mutant_id=selected_mutant_id,
        )
        resolved_dut_bin = (
            Path(dut_bin).expanduser().resolve()
            if dut_bin is not None
            else _dut_bin_from_build_manifest(
                artifact_root / "mutants" / dut / selected_mutant_id / "build-manifest.json"
            )
        )
        if resolved_dut_bin is None or not resolved_dut_bin.exists():
            raise ValueError(f"missing built binary for online campaign {dut}/{selected_mutant_id}")
        fault_family = str(entry.get("fault_family") or "")
        critical_family = bool(entry.get("critical_family"))

    campaign_root = (
        artifact_root
        / "mutants"
        / dut
        / selected_mutant_id
        / "campaigns"
        / f"seed-{int(seed):04d}"
    )
    if campaign_root.exists() and not resume:
        raise ValueError(f"online campaign directory already exists: {campaign_root}")

    repo_root = Path(__file__).resolve().parents[3]
    campaign_id = f"{experiment_id}__{dut}__{selected_mutant_id}__seed-{int(seed):04d}"
    command = [
        sys.executable,
        "-m",
        "scripts.evaluation.campaigns.run_closed_loop_campaign",
        "--artifact-root",
        str(artifact_root),
        "--campaign-dir",
        str(campaign_root),
        "--campaign-id",
        campaign_id,
        "--experiment-id",
        experiment_id,
        "--variant",
        variant,
        "--coverage-mode",
        "semantic",
        "--dut",
        dut,
        "--seed",
        str(int(seed)),
        "--round-size",
        str(int(round_size)),
        "--bootstrap-size",
        str(int(bootstrap_size)),
        "--time-budget",
        str(int(time_budget_seconds)),
        "--per-case-timeout",
        str(int(per_case_timeout)),
        "--jobs",
        str(int(jobs)),
        "--run-class",
        "formal",
        "--budget-class",
        "primary-wall-clock",
        "--experiment-protocol-id",
        protocol_id,
        "--max-completed-cases",
        str(int(candidate_budget)),
        "--chipyard-dir",
        str(Path(resolved_chipyard).expanduser().resolve()),
        "--dut-bin",
        str(resolved_dut_bin),
        "--fault-family",
        fault_family,
        "--skip-artifact-root-prep",
        "--skip-artifact-root-finalize",
    ]
    if critical_family:
        command.append("--critical-family")
    if spike:
        command.extend(["--spike", spike])
    if isa:
        command.extend(["--isa", isa])
    if resume:
        command.append("--resume")

    subprocess.run(command, cwd=repo_root, check=True)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.evaluation.validation.validate_timeline",
            "--campaign",
            str(campaign_root),
        ],
        cwd=repo_root,
        check=True,
    )
    return {
        "schema_version": 1,
        "artifact_root": str(artifact_root),
        "campaign_root": str(campaign_root),
        "campaign_id": campaign_id,
        "dut": dut,
        "mutant_id": selected_mutant_id,
        "seed": int(seed),
        "clean_control": bool(clean_control),
        "fault_family": fault_family,
        "critical_family": critical_family,
    }


def _normalize_counterfactual_case(item: dict[str, Any]) -> dict[str, Any]:
    if "case_id" not in item:
        raise KeyError("case_id")
    if {"expected", "access", "privilege", "translation"} <= set(item.keys()):
        return dict(item)
    scenario_spec = item.get("scenario_spec")
    if not isinstance(scenario_spec, dict):
        raise ValueError("counterfactual cases row must be an execution case or contain scenario_spec")
    scenario = scenario_from_spec(dict(scenario_spec))
    case = scenario_to_case_dict(
        scenario,
        seed=int(item.get("seed") or 0),
        index=int(item.get("index") or 0),
    )
    case["case_id"] = item["case_id"]
    return case


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Section 7.6 oracle-validation workflows")
    subparsers = parser.add_subparsers(dest="command", required=True)

    clean = subparsers.add_parser("clean", help="run frozen clean cases on one DUT and one order seed")
    clean.add_argument("--cases", type=Path, required=True)
    clean.add_argument("--labels", type=Path, required=True)
    clean.add_argument("--out-dir", type=Path, required=True)
    clean.add_argument("--dut", required=True)
    clean.add_argument("--order-seed", type=int, required=True)
    clean.add_argument("--spike", default=DEFAULT_SPIKE)
    clean.add_argument("--isa", default="rv64gc_smepmp")
    clean.add_argument("--chipyard-dir", type=Path, default=None)
    clean.add_argument("--dut-bin", type=Path, default=None)
    clean.add_argument("--simlen", type=int, default=100000)
    clean.add_argument("--per-case-timeout", type=int, default=30)
    clean.add_argument("--limit", type=int, default=None)
    clean.add_argument("--case-id", action="append", default=[])
    clean.add_argument("--materialize-only", action="store_true")

    counter = subparsers.add_parser("counterfactual", help="run frozen counterfactual observations offline")
    counter.add_argument("--cases", type=Path, required=True)
    counter.add_argument("--counterfactuals", type=Path, required=True)
    counter.add_argument("--out-dir", type=Path, required=True)

    directed_plan = subparsers.add_parser("directed-plan", help="freeze directed-suite activating/control plans")
    directed_plan.add_argument("--artifact-root", type=Path, required=True)
    directed_plan.add_argument("--max-controls-per-mutant", type=int, default=8)

    directed = subparsers.add_parser("directed", help="run or materialize one mutant directed suite")
    directed.add_argument("--artifact-root", type=Path, required=True)
    directed.add_argument("--dut", required=True)
    directed.add_argument("--mutant-id", required=True)
    directed.add_argument("--order-seed", type=int, required=True)
    directed.add_argument("--spike", default=DEFAULT_SPIKE)
    directed.add_argument("--isa", default="rv64gc_smepmp")
    directed.add_argument("--chipyard-dir", type=Path, default=None)
    directed.add_argument("--dut-bin", type=Path, default=None)
    directed.add_argument("--simlen", type=int, default=100000)
    directed.add_argument("--per-case-timeout", type=int, default=30)
    directed.add_argument("--materialize-only", action="store_true")
    directed.add_argument("--max-controls-per-mutant", type=int, default=8)
    directed.add_argument("--refresh-plan", action="store_true")

    online = subparsers.add_parser("online", help="run one Section 7.6 online discovery campaign")
    online.add_argument("--artifact-root", type=Path, required=True)
    online.add_argument("--dut", required=True)
    online.add_argument("--seed", type=int, required=True)
    online.add_argument("--mutant-id", default=None)
    online.add_argument("--clean-control", action="store_true")
    online.add_argument("--control-mutant-id", default=ONLINE_CONTROL_MUTANT_ID)
    online.add_argument("--experiment-id", default=ONLINE_EXPERIMENT_ID)
    online.add_argument("--variant", choices=["bb-guided"], default="bb-guided")
    online.add_argument("--spike", default=DEFAULT_SPIKE)
    online.add_argument("--isa", default="rv64gc_smepmp")
    online.add_argument("--chipyard-dir", type=Path, default=None)
    online.add_argument("--dut-bin", type=Path, default=None)
    online.add_argument("--time-budget-seconds", type=int, default=7200)
    online.add_argument("--candidate-budget", type=int, default=2048)
    online.add_argument("--round-size", type=int, default=32)
    online.add_argument("--bootstrap-size", type=int, default=32)
    online.add_argument("--per-case-timeout", type=int, default=10)
    online.add_argument("--jobs", type=int, default=1)
    online.add_argument("--resume", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "clean":
        summary = run_clean_suite(
            cases_path=args.cases,
            labels_path=args.labels,
            out_dir=args.out_dir,
            dut=args.dut,
            order_seed=args.order_seed,
            spike=args.spike,
            isa=args.isa,
            chipyard_dir=args.chipyard_dir,
            dut_bin=args.dut_bin,
            simlen=args.simlen,
            per_case_timeout=args.per_case_timeout,
            limit=args.limit,
            include_case_ids=set(args.case_id) if args.case_id else None,
            materialize_only=args.materialize_only,
        )
        print(
            f"clean-suite dut={summary['dut']} order_seed={summary['order_seed']} "
            f"cases={summary['case_count']} materialize_only={summary['materialize_only']}"
        )
        return 0
    if args.command == "counterfactual":
        summary = run_counterfactual_suite(
            cases_path=args.cases,
            counterfactuals_path=args.counterfactuals,
            out_dir=args.out_dir,
        )
        print(f"counterfactuals={summary['counterfactual_count']} out={args.out_dir / 'counterfactual'}")
        return 0
    if args.command == "directed-plan":
        summary = plan_directed_suite(
            artifact_root=args.artifact_root,
            max_controls_per_mutant=args.max_controls_per_mutant,
        )
        print(
            f"directed-plans={summary['plan_count']} "
            f"out={args.artifact_root / 'manifests' / 'directed-suite-plan.json'}"
        )
        return 0
    if args.command == "online":
        summary = run_online_campaign(
            artifact_root=args.artifact_root,
            dut=args.dut,
            seed=args.seed,
            mutant_id=args.mutant_id,
            clean_control=args.clean_control,
            control_mutant_id=args.control_mutant_id,
            experiment_id=args.experiment_id,
            variant=args.variant,
            spike=args.spike,
            isa=args.isa,
            chipyard_dir=args.chipyard_dir,
            dut_bin=args.dut_bin,
            time_budget_seconds=args.time_budget_seconds,
            candidate_budget=args.candidate_budget,
            round_size=args.round_size,
            bootstrap_size=args.bootstrap_size,
            per_case_timeout=args.per_case_timeout,
            jobs=args.jobs,
            resume=args.resume,
        )
        print(
            f"online-campaign dut={summary['dut']} mutant={summary['mutant_id']} "
            f"seed={summary['seed']} path={summary['campaign_root']}"
        )
        return 0
    summary = run_directed_suite(
        artifact_root=args.artifact_root,
        dut=args.dut,
        mutant_id=args.mutant_id,
        order_seed=args.order_seed,
        spike=args.spike,
        isa=args.isa,
        chipyard_dir=args.chipyard_dir,
        dut_bin=args.dut_bin,
        simlen=args.simlen,
        per_case_timeout=args.per_case_timeout,
        materialize_only=args.materialize_only,
        max_controls_per_mutant=args.max_controls_per_mutant,
        refresh_plan=args.refresh_plan,
    )
    print(
        f"directed-suite dut={summary['dut']} mutant={summary['mutant_id']} "
        f"order_seed={summary['order_seed']} cases={summary['selected_case_count']} "
        f"materialize_only={summary['materialize_only']}"
    )
    return 0


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError(f"expected object row in {path}")
        rows.append(payload)
    return rows


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object payload in {path}")
    return payload


def _oracle_validation_protocol_id(artifact_root: Path) -> str:
    for candidate in (
        artifact_root / "manifests" / "experiment-contract.json",
        artifact_root / "experiment-contract.json",
    ):
        if not candidate.exists():
            continue
        payload = _load_json(candidate)
        protocol_id = str(payload.get("experiment_protocol_id") or "")
        if protocol_id:
            return protocol_id
    return ORACLE_VALIDATION_PROTOCOL_ID


def _mutant_manifest_entry(*, artifact_root: Path, dut: str, mutant_id: str) -> dict[str, Any]:
    manifest_path = artifact_root / "manifests" / "mutants.json"
    payload = _load_json(manifest_path)
    for entry in payload.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("dut") or "") == dut and str(entry.get("mutant_id") or "") == mutant_id:
            return dict(entry)
    raise ValueError(f"unknown semantic mutant {dut}/{mutant_id}")


def _resolve_online_clean_dut_binary(*, dut: str, chipyard_dir: Path | str, dut_bin: Path | None) -> Path:
    if dut_bin is not None:
        resolved = Path(dut_bin).expanduser().resolve()
        if not resolved.exists():
            raise ValueError(f"clean-control DUT binary does not exist: {resolved}")
        return resolved
    chipyard_root = Path(chipyard_dir).expanduser().resolve()
    candidate_map = {
        "rocket-clean": [chipyard_root / "sims/verilator/simulator-chipyard.harness-RocketConfig"],
        "boom-clean": [chipyard_root / "sims/verilator/simulator-chipyard.harness-SmallBoomV3Config"],
        "cva6-clean": [
            chipyard_root / "sims/verilator/simulator-chipyard.harness-CVA6Config",
            chipyard_root / "sims/verilator/simulator-chipyard-CVA6Config",
        ],
    }
    candidates = candidate_map.get(dut) or []
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    raise ValueError(f"unable to infer clean-control DUT binary for {dut}; pass --dut-bin explicitly")


def _record_online_control_binary(
    *,
    artifact_root: Path,
    dut: str,
    control_mutant_id: str,
    binary_path: Path,
) -> None:
    resolved_binary = Path(binary_path).expanduser().resolve()
    digest = hashlib.sha256(resolved_binary.read_bytes()).hexdigest()
    control_root = artifact_root / "mutants" / dut / control_mutant_id
    control_root.mkdir(parents=True, exist_ok=True)
    (control_root / "binary.sha256").write_text(digest + "\n", encoding="ascii")
    _write_json(
        control_root / "build-manifest.json",
        {
            "schema_version": 1,
            "status": "built",
            "binary_path": str(resolved_binary),
            "dut_bin": str(resolved_binary),
            "simulator_binary": str(resolved_binary),
            "binary_sha256": digest,
            "control": True,
        },
    )


def _archive_existing_suite_root(seed_root: Path) -> Path | None:
    if not seed_root.exists():
        return None
    if not any(seed_root.iterdir()):
        return None

    archive_root = seed_root.parent / "_archived_reruns"
    archive_root.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    archived_root = archive_root / f"{seed_root.name}.{stamp}"
    counter = 1
    while archived_root.exists():
        archived_root = archive_root / f"{seed_root.name}.{stamp}-{counter:02d}"
        counter += 1
    shutil.move(str(seed_root), str(archived_root))
    return archived_root


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _observed_record(dut_result: Any) -> dict[str, Any]:
    observation = dut_result.observation
    fault_address = dut_result.observed_fault_address
    if isinstance(fault_address, str):
        try:
            fault_address = int(fault_address, 0)
        except ValueError:
            fault_address = None
    return {
        "schema_version": 1,
        "available": observation is not None,
        "kind": observation.kind.name.lower() if observation is not None else None,
        "mcause": observation.mcause if observation is not None else dut_result.observed_mcause,
        "mtval_fingerprint": observation.mtval_fingerprint if observation is not None else None,
        "mepc_tag": observation.mepc_tag if observation is not None else None,
        "phase": observation.phase.name.lower() if observation is not None else None,
        "observed_stage": dut_result.observed_stage,
        "observed_ptw_level": dut_result.observed_ptw_level,
        "observed_fault_address": fault_address,
        "observed_probe_vaddr": dut_result.observed_probe_vaddr,
    }


def _dut_bin_from_build_manifest(path: Path) -> Path | None:
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return None
    expected_sha256 = str(payload.get("binary_sha256") or "").strip().lower()
    candidates = (
        payload.get("binary_path"),
        payload.get("dut_bin"),
        payload.get("simulator_binary"),
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            resolved = Path(candidate).expanduser().resolve()
            if expected_sha256:
                if not resolved.exists():
                    raise ValueError(
                        f"build-manifest binary path does not exist for sha validation: {resolved}"
                    )
                actual_sha256 = _sha256_file(resolved)
                if actual_sha256.lower() != expected_sha256:
                    raise ValueError(
                        "build-manifest binary sha256 mismatch: "
                        f"expected {expected_sha256}, got {actual_sha256} for {resolved}"
                    )
            return resolved
    return None


if __name__ == "__main__":
    raise SystemExit(main())
