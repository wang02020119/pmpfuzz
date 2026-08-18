#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pmpfuzz.bapc import (
    BAPC_SCHEMA_VERSION,
    BAPC_TARGET,
    build_bapc_coverage_universe,
    runtime_bapc_event_records_for_cascade_execution,
    summarize_bapc_for_cascade_execution,
    summarize_bapc_for_pmpfuzz_case,
)
from pmpfuzz.coverage_universe import classify_observed_bins
from scripts.evaluation.analysis.aggregate_results import _write_artifact_hashes, aggregate
from scripts.evaluation.baseline_adapters.cascade import _bapc_actual_result_from_log, _merge_log_streams
from scripts.evaluation.campaigns.run_closed_loop_campaign import _git_head_sha, _project_root, _source_tree_sha256
from scripts.evaluation.validation.validate_timeline import validate_timeline


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="ascii"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n", encoding="ascii")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(row, ensure_ascii=True, sort_keys=True) for row in rows) + "\n",
        encoding="ascii",
    )


def _load_raw_campaigns(raw_artifact_root: Path) -> list[tuple[Path, dict[str, Any]]]:
    campaigns: list[tuple[Path, dict[str, Any]]] = []
    for metadata_path in sorted((raw_artifact_root / "campaigns").rglob("metrics/campaign_metadata.json")):
        campaign_dir = metadata_path.parent.parent
        meta = _read_json(metadata_path)
        if str(meta.get("coverage_mode") or "") != "bapc":
            continue
        method = str(meta.get("method") or "")
        if method not in {"pmpfuzz", "cascade"}:
            continue
        campaigns.append((campaign_dir, meta))
    if not campaigns:
        raise ValueError(f"no raw BAPC campaigns found under {raw_artifact_root}")
    return campaigns


def _artifact_paths(root: Path) -> list[Path]:
    return sorted(
        path.resolve()
        for path in root.rglob("*")
        if path.is_file() and path.name != "artifact-sha256.txt"
    )


def _variant_from_path(campaign_dir: Path, meta: dict[str, Any]) -> str:
    try:
        return str(campaign_dir.parent.parent.name)
    except IndexError:
        return str(meta.get("variant") or "")


def _load_legacy_bapc_universe(raw_campaign_dir: Path, meta: dict[str, Any]) -> dict[str, Any]:
    rel = str((meta.get("coverage_universe_files") or {}).get("bapc") or "metrics/coverage_universe/bapc_v1.json")
    path = raw_campaign_dir / rel
    if not path.exists():
        path = raw_campaign_dir / "metrics" / "coverage_universe" / "bapc_v1.json"
    if not path.exists():
        raise ValueError(f"missing legacy BAPC universe for {raw_campaign_dir}")
    return _read_json(path)


def _build_v2_universe(raw_campaign_dir: Path, meta: dict[str, Any]) -> dict[str, Any]:
    legacy = _load_legacy_bapc_universe(raw_campaign_dir, meta)
    capabilities = dict(legacy.get("capabilities") or {})
    return build_bapc_coverage_universe(
        dut=str(meta.get("dut") or legacy.get("dut") or ""),
        generator_seed=int(meta.get("seed") or legacy.get("generator_seed") or 0),
        supports_fault_stage=bool(capabilities.get("fault_stage", True)),
        supports_smepmp=bool(capabilities.get("smepmp", False)),
        bapc_core_version="v2",
    )


def _classify_bapc_bins(universe: dict[str, Any], observed_bins: list[str]) -> list[str]:
    classified = classify_observed_bins(universe, observed_bins)
    out_of_contract = list(classified["out_of_contract"])
    if out_of_contract:
        raise ValueError(f"observed bins outside BAPC-core v2 universe: {out_of_contract[:5]}")
    return sorted(set(classified["covered"]))


def _rebuild_bapc_timeline(
    raw_lines: list[dict[str, Any]],
    observations: dict[str, dict[str, Any]],
    universe: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], int]:
    rebuilt: list[dict[str, Any]] = []
    covered: set[str] = set()
    eligible_bapc_cases = 0
    last_novelty_time = 0.0

    for raw_line in raw_lines:
        line = dict(raw_line)
        completion_seq = int(line.get("completion_seq", 0) or 0)
        if completion_seq <= 0 or not line.get("case_id"):
            line["bapc_target"] = int(universe["bin_count"])
            line["bapc_covered"] = len(covered)
            line["bapc_rate"] = (len(covered) / int(universe["bin_count"])) if universe["bin_count"] else 0.0
            line["new_bapc_bins"] = 0
            line["bapc_eligible"] = False
            line["coverage_eligible"] = False
            line["qualification_reason"] = None
            line["eligible_bapc_cases"] = eligible_bapc_cases
            line["last_bapc_novelty_time"] = last_novelty_time
            rebuilt.append(line)
            continue

        case_id = str(line["case_id"])
        summary = observations.get(case_id)
        if summary is None:
            raise ValueError(f"missing raw observation for case {case_id}")
        eligible = bool(summary.get("eligible"))
        new_bins: list[str] = []
        if eligible:
            eligible_bapc_cases += 1
            observed_bins = _classify_bapc_bins(universe, [str(item) for item in (summary.get("observed_bins") or [])])
            new_bins = sorted(set(observed_bins) - covered)
            covered.update(observed_bins)
            if new_bins:
                last_novelty_time = float(line.get("elapsed_wall_seconds", 0.0) or 0.0)

        line["bapc_target"] = int(universe["bin_count"])
        line["bapc_covered"] = len(covered)
        line["bapc_rate"] = (len(covered) / int(universe["bin_count"])) if universe["bin_count"] else 0.0
        line["new_bapc_bins"] = len(new_bins)
        line["bapc_eligible"] = eligible
        line["coverage_eligible"] = eligible
        line["qualification_reason"] = summary.get("qualification_reason")
        line["eligible_bapc_cases"] = eligible_bapc_cases
        line["last_bapc_novelty_time"] = last_novelty_time
        rebuilt.append(line)
    return rebuilt, sorted(covered), eligible_bapc_cases


def _collect_pmpfuzz_observations(raw_campaign_dir: Path) -> dict[str, dict[str, Any]]:
    observations: dict[str, dict[str, Any]] = {}
    for result_path in sorted(raw_campaign_dir.glob("rounds/round_*/results/*/result.json")):
        case_id = result_path.parent.name
        case_path = raw_campaign_dir / "rounds" / result_path.parents[2].name / "cases" / case_id / "case.json"
        if not case_path.exists():
            raise ValueError(f"missing raw case for {case_id} in {raw_campaign_dir}")
        log_path = result_path.with_name(f"{case_id}.log")
        summary = summarize_bapc_for_pmpfuzz_case(
            _read_json(case_path),
            _read_json(result_path),
            log_text=log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else "",
            bapc_core_version="v2",
        )
        observations[case_id] = summary
    return observations


def _load_cascade_events(raw_campaign_dir: Path) -> dict[str, dict[str, Any]]:
    path = raw_campaign_dir / "events.json"
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="ascii"))
    if not isinstance(payload, list):
        return {}
    return {
        str(item.get("case_id") or ""): item
        for item in payload
        if isinstance(item, dict) and str(item.get("case_id") or "")
    }


def _case_index_from_case_id(case_id: str) -> int:
    suffix = case_id.rsplit("_", 1)[-1]
    return int(suffix)


def _collect_cascade_observations(raw_campaign_dir: Path, meta: dict[str, Any]) -> dict[str, dict[str, Any]]:
    observations: dict[str, dict[str, Any]] = {}
    events = _load_cascade_events(raw_campaign_dir)
    design = "rocket" if str(meta.get("dut") or "").startswith("rocket") else "boom"
    for sidecar_path in sorted((raw_campaign_dir / "elfs").glob(f"{design}_*.json")):
        case_index = int(sidecar_path.stem.rsplit("_", 1)[-1])
        case_id = f"cascade_{meta.get('dut')}_{case_index:04d}"
        event = events.get(case_id, {})
        stdout_log = raw_campaign_dir / str(event.get("stdout_log") or f"logs/{case_id}.stdout.log")
        stderr_log = raw_campaign_dir / str(event.get("stderr_log") or f"logs/{case_id}.stderr.log")
        if not stdout_log.exists() and not stderr_log.exists():
            raise ValueError(f"missing cascade logs for {case_id}")
        stdout_text = stdout_log.read_text(encoding="utf-8", errors="replace") if stdout_log.exists() else ""
        stderr_text = stderr_log.read_text(encoding="utf-8", errors="replace") if stderr_log.exists() else ""
        combined_log = _merge_log_streams(stdout_text, stderr_text)
        returncode = event.get("returncode")
        result = _bapc_actual_result_from_log(
            dut=str(meta.get("dut") or ""),
            log_text=combined_log,
            returncode=None if returncode is None else int(returncode),
        )
        bapc_event_records = []
        if isinstance(event.get("bapc_coverage"), dict):
            raw_records = event["bapc_coverage"].get("event_records") or []
            bapc_event_records = [
                dict(item)
                for item in raw_records
                if isinstance(item, dict)
            ]
        if not bapc_event_records:
            bapc_event_records = runtime_bapc_event_records_for_cascade_execution(
                _read_json(sidecar_path),
                result,
                stdout_text=combined_log,
            )
        summary = summarize_bapc_for_cascade_execution(
            _read_json(sidecar_path),
            result,
            stdout_text=combined_log,
            event_records=bapc_event_records,
            bapc_core_version="v2",
        )
        observations[case_id] = summary
    return observations


def _write_coverage_contract(universe_dir: Path, universe: dict[str, Any]) -> None:
    _write_json(
        universe_dir / "coverage_contract_v1.json",
        {
            "schema_version": 1,
            "modes": {"bapc": "bapc_v2.json"},
            "hashes": {"bapc": universe["sha256"]},
        },
    )


def _build_metadata(
    *,
    raw_campaign_dir: Path,
    raw_meta: dict[str, Any],
    out_campaign_dir: Path,
    universe: dict[str, Any],
    variant: str,
    covered_bins: list[str],
    eligible_bapc_cases: int,
) -> dict[str, Any]:
    meta = dict(raw_meta)
    meta["variant"] = variant
    meta["driver_mode"] = "campaign"
    meta["coverage_schema"] = "bapc-v2-reanalysis"
    meta["coverage_universe_hashes"] = {"bapc": universe["sha256"]}
    meta["coverage_universe_files"] = {
        "bapc": "metrics/coverage_universe/bapc_v2.json",
        "contract": "metrics/coverage_universe/coverage_contract_v1.json",
    }
    meta["bapc_schema_version"] = BAPC_SCHEMA_VERSION
    meta["bapc_measurement_mode"] = "target-operation"
    meta["probe_required"] = False
    meta["instrumented_supplemental_enabled"] = False
    meta["bapc_covered"] = len(covered_bins)
    meta["bapc_target"] = int(universe["bin_count"])
    meta["eligible_bapc_cases"] = eligible_bapc_cases
    meta["analysis_scope"] = {
        "guidance_mode": "bapc",
        "primary_metric": "bapc",
        "coverage_modes": ["bapc"],
    }
    meta["reanalysis_raw_campaign_dir"] = str(raw_campaign_dir)
    meta["reanalysis_output_campaign_dir"] = str(out_campaign_dir)
    meta["reanalysis_source_sha"] = str(_git_head_sha(_project_root()) or meta.get("source_sha") or "")
    tree_sha = _source_tree_sha256(_project_root())
    if tree_sha:
        meta["source_tree_sha256"] = str(tree_sha)
    meta["method"] = str(raw_meta.get("method") or "")
    meta.pop("schedule_v4", None)
    return meta


def _write_coverage_json(campaign_dir: Path, meta: dict[str, Any], universe: dict[str, Any], covered_bins: list[str]) -> None:
    _write_json(
        campaign_dir / "coverage" / "coverage.json",
        {
            "schema_version": 6,
            "driver_mode": "campaign",
            "coverage_universe_hashes": {"bapc": universe["sha256"]},
            "execution_coverage": {
                "by_dut": {
                    str(meta.get("dut") or ""): {
                        "bapc": {
                            "covered_target_bins": len(covered_bins),
                            "total_target_bins": int(universe["bin_count"]),
                            "covered_bins": covered_bins,
                            "target": BAPC_TARGET,
                            "universe_sha256": universe["sha256"],
                        }
                    }
                }
            },
        },
    )


def _write_manifests(out_root: Path, experiment_id: str, campaigns: list[dict[str, Any]]) -> None:
    manifests_dir = out_root / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    source_sha = str(_git_head_sha(_project_root()) or "")
    git_lines = [f"{source_sha}  pmpfuzz"] if source_sha else []
    dut_shas = sorted({str(item.get("dut_sha") or "") for item in campaigns if str(item.get("dut_sha") or "")})
    for dut_sha in dut_shas:
        git_lines.append(f"{dut_sha}  chipyard")
    if not git_lines:
        git_lines.append(f"{'0' * 40}  unavailable")
    _write_json(
        manifests_dir / "environment.json",
        {
            "artifact_root": str(out_root),
            "cwd": str(Path.cwd()),
            "python_executable": str(Path(__file__).resolve()),
        },
    )
    (manifests_dir / "git-shas.txt").write_text("\n".join(git_lines) + "\n", encoding="ascii")
    _write_json(
        manifests_dir / "analysis-scope.json",
        {
            "schema_version": 1,
            "artifact_root": str(out_root),
            "experiment_id": experiment_id,
            "dut": campaigns[0].get("dut") if campaigns else "",
            "run_class": campaigns[0].get("run_class") if campaigns else "",
            "guidance_mode": "bapc",
            "primary_metric": "bapc",
            "primary_variants": sorted({str(item.get("variant") or "") for item in campaigns}),
            "primary_seeds": sorted({int(item.get("seed") or 0) for item in campaigns}),
            "coverage_modes": ["bapc"],
        },
    )


def _campaign_output_dir(out_root: Path, meta: dict[str, Any], variant: str) -> Path:
    return (
        out_root
        / "campaigns"
        / str(meta.get("experiment_id") or "reanalysis")
        / str(meta.get("dut") or "")
        / variant
        / "bapc"
        / f"seed-{int(meta.get('seed') or 0):04d}"
    )


def _rebuild_single_campaign(raw_campaign_dir: Path, raw_meta: dict[str, Any], out_root: Path) -> dict[str, Any]:
    variant = _variant_from_path(raw_campaign_dir, raw_meta)
    universe = _build_v2_universe(raw_campaign_dir, raw_meta)
    raw_timeline = [
        json.loads(line)
        for line in (raw_campaign_dir / "metrics" / "coverage_timeline.jsonl").read_text(encoding="ascii").splitlines()
        if line.strip()
    ]
    if str(raw_meta.get("method") or "") == "cascade":
        observations = _collect_cascade_observations(raw_campaign_dir, raw_meta)
    else:
        observations = _collect_pmpfuzz_observations(raw_campaign_dir)
    rebuilt_timeline, covered_bins, eligible_bapc_cases = _rebuild_bapc_timeline(raw_timeline, observations, universe)

    out_campaign_dir = _campaign_output_dir(out_root, raw_meta, variant)
    universe_dir = out_campaign_dir / "metrics" / "coverage_universe"
    _write_json(universe_dir / "bapc_v2.json", universe)
    _write_coverage_contract(universe_dir, universe)
    _write_jsonl(out_campaign_dir / "metrics" / "coverage_timeline.jsonl", rebuilt_timeline)
    meta = _build_metadata(
        raw_campaign_dir=raw_campaign_dir,
        raw_meta=raw_meta,
        out_campaign_dir=out_campaign_dir,
        universe=universe,
        variant=variant,
        covered_bins=covered_bins,
        eligible_bapc_cases=eligible_bapc_cases,
    )
    _write_json(out_campaign_dir / "metrics" / "campaign_metadata.json", meta)
    _write_coverage_json(out_campaign_dir, meta, universe, covered_bins)
    return {"campaign_dir": out_campaign_dir, "metadata": meta}


def reanalyze_bapc_artifact(raw_artifact_root: Path | str, out_root: Path | str) -> dict[str, Path]:
    raw_root = Path(raw_artifact_root).resolve()
    output_root = Path(out_root).resolve()
    campaigns = _load_raw_campaigns(raw_root)
    rebuilt: list[dict[str, Any]] = []
    for raw_campaign_dir, raw_meta in campaigns:
        rebuilt.append(_rebuild_single_campaign(raw_campaign_dir, raw_meta, output_root))

    experiment_id = str(rebuilt[0]["metadata"].get("experiment_id") or "reanalysis")
    _write_manifests(output_root, experiment_id, [item["metadata"] for item in rebuilt])
    _write_artifact_hashes(output_root, _artifact_paths(output_root), output_root / "manifests" / "artifact-sha256.txt")

    for item in rebuilt:
        report = validate_timeline(Path(item["campaign_dir"]))
        _write_json(Path(item["campaign_dir"]) / "validation.json", report)

    outputs = aggregate(output_root, experiment_id)
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reanalyze raw BAPC artifacts using BAPC-core v2")
    parser.add_argument("--raw-artifact-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    reanalyze_bapc_artifact(args.raw_artifact_root, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
