#!/usr/bin/env python3
"""Merge formal evaluation roots into a unified final summary."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

EXPECTED_FORMAL_COUNTS = {
    "section_8_2_batches": 18,
    "section_8_3_8_4_campaigns": 27,
    "section_8_4_pairs": 9,
    "section_8_5_campaigns": 18,
}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--main-root", type=Path, required=True)
    parser.add_argument("--cascade-root", dest="cascade_roots", action="append", type=Path, default=[])
    parser.add_argument("--section85-root", dest="section85_roots", action="append", type=Path, default=[])
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--allow-partial-counts", action="store_true")
    return parser.parse_args(argv)


def _read_json(path: Path) -> dict[str, Any] | list[Any]:
    return json.loads(path.read_text(encoding="ascii"))


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="ascii", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        fieldnames = []
    else:
        fieldnames = list(rows[0].keys())
        for row in rows[1:]:
            for key in row.keys():
                if key not in fieldnames:
                    fieldnames.append(key)
    with path.open("w", encoding="ascii", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(
            [
                {
                    key: (
                        json.dumps(value, ensure_ascii=True, sort_keys=True)
                        if isinstance(value, (dict, list))
                        else value
                    )
                    for key, value in row.items()
                }
                for row in rows
            ]
        )


def _parse_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _parse_float(value: Any) -> float | None:
    if value in {None, ""}:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_scalar(value: Any) -> Any:
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if not isinstance(value, str):
        return value
    ivalue = _parse_int(value)
    if ivalue is not None and value.strip().lower() not in {"true", "false"}:
        return ivalue
    fvalue = _parse_float(value)
    if fvalue is not None:
        return fvalue
    if value == "true":
        return True
    if value == "false":
        return False
    return value


def _normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    return {str(key): _normalize_scalar(value) for key, value in row.items()}


@lru_cache(maxsize=None)
def _load_artifact_context(artifact_path_text: str) -> dict[str, Any]:
    if not artifact_path_text:
        return {}
    artifact_path = Path(artifact_path_text)
    context: dict[str, Any] = {}
    metadata_path = artifact_path / "metrics" / "campaign_metadata.json"
    coverage_paths = (
        artifact_path / "metrics" / "coverage" / "coverage.json",
        artifact_path / "coverage" / "coverage.json",
    )
    runtime_validation_path = artifact_path / "metrics" / "cascade_runtime_validation.json"
    if metadata_path.exists():
        payload = _read_json(metadata_path)
        if isinstance(payload, dict):
            context["metadata"] = payload
    for coverage_path in coverage_paths:
        if not coverage_path.exists():
            continue
        payload = _read_json(coverage_path)
        if isinstance(payload, dict):
            context["coverage"] = payload
            break
    if runtime_validation_path.exists():
        payload = _read_json(runtime_validation_path)
        if isinstance(payload, dict):
            context["runtime_validation"] = payload
    return context


def _identity_key(row: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    return (
        str(row.get("experiment_id") or ""),
        str(row.get("method") or ""),
        str(row.get("variant") or ""),
        str(row.get("dut") or ""),
        str(row.get("seed") or ""),
        str(row.get("generator_variant") or ""),
    )


def _campaign_id_key(row: dict[str, Any]) -> tuple[str, str]:
    return (
        str(row.get("experiment_id") or ""),
        str(row.get("campaign_id") or ""),
    )


def _campaign_sort_key(row: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    return (
        str(row.get("experiment_id") or ""),
        str(row.get("dut") or ""),
        str(row.get("variant") or ""),
        str(row.get("generator_variant") or ""),
        str(row.get("seed") or ""),
        str(row.get("campaign_id") or ""),
    )


def _find_root_aggregate_dirs(root: Path) -> list[Path]:
    return sorted(path for path in root.glob("dut-roots/*/aggregate") if path.is_dir())


def _find_root_campaign_artifacts(root: Path) -> list[Path]:
    artifacts: list[Path] = []
    seen: set[Path] = set()
    for metadata_path in sorted(root.glob("dut-roots/*/campaigns/**/metrics/campaign_metadata.json")):
        artifact_path = metadata_path.parent.parent
        if artifact_path in seen:
            continue
        seen.add(artifact_path)
        artifacts.append(artifact_path)
    return artifacts


def _read_jsonl_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="ascii") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            payload = json.loads(text)
            if isinstance(payload, dict):
                rows.append(payload)
    return rows


def _fill_missing(row: dict[str, Any], source: dict[str, Any] | None, keys: Iterable[str]) -> None:
    if not source:
        return
    for key in keys:
        if row.get(key) in {None, ""} and source.get(key) not in {None, ""}:
            row[key] = source[key]


def _coverage_bapc_count(coverage: dict[str, Any], dut: str) -> int | None:
    count = _parse_int(coverage.get("covered_target_bapc_bins"))
    if count is not None:
        return count
    execution_coverage = coverage.get("execution_coverage")
    if not isinstance(execution_coverage, dict):
        return None
    by_dut = execution_coverage.get("by_dut")
    if not isinstance(by_dut, dict):
        return None
    dut_payload = by_dut.get(dut)
    if not isinstance(dut_payload, dict):
        return None
    bapc_payload = dut_payload.get("bapc")
    if not isinstance(bapc_payload, dict):
        return None
    covered_bins = bapc_payload.get("covered_bins")
    if not isinstance(covered_bins, list):
        return None
    return len(covered_bins)


def _apply_runtime_validation(row: dict[str, Any], validation: dict[str, Any]) -> None:
    _fill_missing(
        row,
        validation,
        [
            "artifact_valid",
            "artifact_valid_cases",
            "measurement_valid",
            "measurement_valid_cases",
            "runtime_record_cases",
            "runtime_record_rate",
            "eligible_bapc_cases",
            "eligible_bapc_rate",
            "replay_failure_count",
        ],
    )
    for key in (
        "qualification_reason_counts",
        "family_coverage",
        "covered_bins",
        "out_of_contract_bins",
        "unexpected_mapper_bins",
        "replay_failures",
    ):
        if (row.get(key) is None or row.get(key) == "") and validation.get(key) is not None and validation.get(key) != "":
            row[key] = validation[key]

    measurement_valid = row.get("measurement_valid")
    completed_cases = _parse_int(row.get("completed_cases")) or 0
    eligible_bapc_cases = _parse_int(row.get("eligible_bapc_cases")) or 0
    if measurement_valid is False or (completed_cases > 0 and eligible_bapc_cases == 0):
        row["covered_bin_count"] = None
        row["coverage_denominator"] = None
        row["bapc_covered"] = None
        row["bapc_target"] = None
        row["bapc_rate"] = None
        return

    if row.get("covered_bin_count") in {None, ""} and validation.get("covered_bin_count") not in {None, ""}:
        row["covered_bin_count"] = validation["covered_bin_count"]
    if row.get("coverage_denominator") in {None, ""} and validation.get("coverage_denominator") not in {None, ""}:
        row["coverage_denominator"] = validation["coverage_denominator"]
    if row.get("bapc_covered") in {None, ""} and row.get("covered_bin_count") not in {None, ""}:
        row["bapc_covered"] = row["covered_bin_count"]
    if row.get("bapc_target") in {None, ""} and row.get("coverage_denominator") not in {None, ""}:
        row["bapc_target"] = row["coverage_denominator"]
    covered_bin_count = _parse_int(row.get("covered_bin_count"))
    coverage_denominator = _parse_int(row.get("coverage_denominator"))
    if (
        row.get("bapc_rate") in {None, ""}
        and covered_bin_count is not None
        and coverage_denominator not in {None, 0}
    ):
        row["bapc_rate"] = covered_bin_count / coverage_denominator


def _enrich_campaign_row(row: dict[str, Any]) -> dict[str, Any]:
    merged = dict(row)
    context = _load_artifact_context(str(merged.get("artifact_path") or ""))
    metadata = context.get("metadata") if isinstance(context.get("metadata"), dict) else {}
    coverage = context.get("coverage") if isinstance(context.get("coverage"), dict) else {}
    runtime_validation = (
        context.get("runtime_validation")
        if isinstance(context.get("runtime_validation"), dict)
        else {}
    )
    _fill_missing(
        merged,
        metadata,
        [
            "generator_variant",
            "bapc_core_version",
            "bapc_target",
            "coverage_mode",
            "completed_cases",
            "eligible_cases",
            "eligible_hpm_cases",
            "eligible_bapc_cases",
            "source_sha",
            "source_tree_sha256",
            "source_dirty",
            "dut_sha",
            "dut_binary_path",
            "dut_binary_sha256",
            "capability_fingerprint",
            "experiment_protocol_id",
            "driver_mode",
            "coverage_schema",
            "start_utc",
            "end_utc",
            "time_budget_seconds",
            "wall_clock_horizon_seconds",
            "budget_class",
            "run_class",
            "stop_reason",
            "convergence_enabled",
            "convergence_min_runtime_seconds",
            "convergence_confirmation_seconds",
            "convergence_confirmation_eligible_cases",
            "max_wall_time_seconds",
            "round_size",
            "jobs",
            "per_case_timeout_seconds",
            "variant",
            "method",
            "dut",
            "seed",
        ],
    )
    if merged.get("coverage_mode") == "bapc":
        dut = str(merged.get("dut") or metadata.get("dut") or "")
        covered_bin_count = merged.get("covered_bin_count")
        if covered_bin_count in {None, ""}:
            count = _coverage_bapc_count(coverage, dut)
            if count is not None:
                merged["covered_bin_count"] = count
        if merged.get("bapc_covered") in {None, ""} and merged.get("covered_bin_count") not in {None, ""}:
            merged["bapc_covered"] = merged["covered_bin_count"]
        if merged.get("coverage_denominator") in {None, ""}:
            if metadata.get("bapc_target") not in {None, ""}:
                merged["coverage_denominator"] = metadata["bapc_target"]
            elif merged.get("bapc_target") not in {None, ""}:
                merged["coverage_denominator"] = merged["bapc_target"]
        if merged.get("bapc_target") in {None, ""} and merged.get("coverage_denominator") not in {None, ""}:
            merged["bapc_target"] = merged["coverage_denominator"]
    if runtime_validation:
        _apply_runtime_validation(merged, runtime_validation)
    return _normalize_row(merged)


def _merge_campaign_row(row: dict[str, Any], campaign_index_row: dict[str, Any] | None) -> dict[str, Any]:
    merged = dict(row)
    if campaign_index_row:
        for key, value in campaign_index_row.items():
            if merged.get(key) in {None, ""}:
                merged[key] = value
    if merged.get("coverage_mode") == "bapc":
        if merged.get("covered_bin_count") in {None, ""}:
            merged["covered_bin_count"] = merged.get("bapc_covered")
        if merged.get("coverage_denominator") in {None, ""}:
            merged["coverage_denominator"] = merged.get("bapc_target")
    return _enrich_campaign_row(merged)


def _load_aggregate_campaigns(
    roots: Iterable[Path],
    *,
    experiment_id: str,
) -> tuple[list[dict[str, Any]], dict[tuple[str, str, str, str, str, str], list[dict[str, Any]]]]:
    campaigns_by_identity: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}
    campaigns_by_campaign_id: dict[tuple[str, str], dict[str, Any]] = {}
    timeseries_by_identity: dict[tuple[str, str, str, str, str, str], list[dict[str, Any]]] = {}
    for root in roots:
        for aggregate_dir in _find_root_aggregate_dirs(root):
            coverage_final_path = aggregate_dir / "coverage_final.csv"
            if not coverage_final_path.exists():
                continue
            coverage_rows = [_normalize_row(row) for row in _read_csv(coverage_final_path)]
            coverage_rows = [
                row for row in coverage_rows
                if str(row.get("experiment_id") or "") == experiment_id
            ]
            if not coverage_rows:
                continue
            campaign_index_path = aggregate_dir / "campaign_index.csv"
            campaign_index_rows = [_normalize_row(row) for row in _read_csv(campaign_index_path)] if campaign_index_path.exists() else []
            campaign_index_by_identity = {_identity_key(row): row for row in campaign_index_rows}
            campaign_index_by_campaign_id = {_campaign_id_key(row): row for row in campaign_index_rows}
            for row in coverage_rows:
                campaign_index_row = campaign_index_by_campaign_id.get(_campaign_id_key(row)) or campaign_index_by_identity.get(_identity_key(row))
                merged = _merge_campaign_row(row, campaign_index_row)
                identity = _identity_key(merged)
                campaigns_by_identity[identity] = merged
                campaigns_by_campaign_id[_campaign_id_key(merged)] = merged
            timeseries_path = aggregate_dir / "coverage_timeseries.csv"
            if not timeseries_path.exists():
                continue
            grouped: dict[tuple[str, str, str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
            for row in (_normalize_row(item) for item in _read_csv(timeseries_path)):
                if str(row.get("experiment_id") or "") != experiment_id:
                    continue
                campaign_row = campaigns_by_campaign_id.get(_campaign_id_key(row)) or campaign_index_by_campaign_id.get(_campaign_id_key(row))
                merged_row = dict(row)
                if campaign_row:
                    for key, value in campaign_row.items():
                        if merged_row.get(key) in {None, ""}:
                            merged_row[key] = value
                merged_row = _normalize_row(merged_row)
                grouped[_identity_key(merged_row)].append(merged_row)
            for identity, rows in grouped.items():
                rows.sort(
                    key=lambda item: (
                        _parse_int(item.get("completion_seq")) or 0,
                        _parse_float(item.get("elapsed_wall_seconds")) or 0.0,
                    )
                )
                timeseries_by_identity[identity] = rows
        for artifact_path in _find_root_campaign_artifacts(root):
            metadata_path = artifact_path / "metrics" / "campaign_metadata.json"
            if not metadata_path.exists():
                continue
            payload = _read_json(metadata_path)
            if not isinstance(payload, dict):
                continue
            if str(payload.get("experiment_id") or "") != experiment_id:
                continue
            direct_row = _merge_campaign_row(
                {
                    "artifact_path": str(artifact_path),
                    "experiment_id": payload.get("experiment_id"),
                    "campaign_id": payload.get("campaign_id"),
                    "method": payload.get("method"),
                    "variant": payload.get("variant"),
                    "generator_variant": payload.get("generator_variant"),
                    "dut": payload.get("dut"),
                    "seed": payload.get("seed"),
                    "coverage_mode": payload.get("coverage_mode"),
                },
                None,
            )
            campaign_id_key = _campaign_id_key(direct_row)
            identity = _identity_key(direct_row)
            if campaign_id_key in campaigns_by_campaign_id or identity in campaigns_by_identity:
                continue
            campaigns_by_identity[identity] = direct_row
            campaigns_by_campaign_id[campaign_id_key] = direct_row
            timeline_path = artifact_path / "metrics" / "coverage_timeline.jsonl"
            if not timeline_path.exists():
                continue
            rows: list[dict[str, Any]] = []
            for row in (_normalize_row(item) for item in _read_jsonl_rows(timeline_path)):
                merged_row = dict(row)
                for key, value in direct_row.items():
                    if merged_row.get(key) in {None, ""}:
                        merged_row[key] = value
                rows.append(_normalize_row(merged_row))
            rows.sort(
                key=lambda item: (
                    _parse_int(item.get("completion_seq")) or 0,
                    _parse_float(item.get("elapsed_wall_seconds")) or 0.0,
                )
            )
            timeseries_by_identity[identity] = rows
    campaigns = sorted(campaigns_by_identity.values(), key=_campaign_sort_key)
    return campaigns, timeseries_by_identity


def _load_section_82_batches(roots: Iterable[Path]) -> list[dict[str, Any]]:
    batches_by_id: dict[str, dict[str, Any]] = {}
    for root in roots:
        for manifest_path in sorted(root.glob("section-8.2/*/*/*/batch_manifest.json")):
            payload = _read_json(manifest_path)
            if not isinstance(payload, dict):
                continue
            batch_id = str(payload.get("batch_id") or manifest_path.relative_to(root).as_posix())
            row = dict(payload)
            row["artifact_root"] = str(root)
            row["manifest_path"] = str(manifest_path)
            batches_by_id[batch_id] = _normalize_row(row)
    return sorted(batches_by_id.values(), key=lambda row: str(row.get("batch_id") or ""))


def _load_formal_freeze(root: Path) -> dict[str, Any] | None:
    path = root / "manifests" / "formal-freeze.json"
    if not path.exists():
        return None
    payload = _read_json(path)
    if not isinstance(payload, dict):
        return None
    return {"root": str(root), **payload}


def _reached_endpoint(rows: list[dict[str, Any]], endpoint: int) -> dict[str, Any]:
    for row in rows:
        covered = _parse_int(row.get("covered_bins")) or 0
        if covered >= endpoint:
            return {
                "status": "reached",
                "elapsed_wall_seconds": _parse_float(row.get("elapsed_wall_seconds")),
                "completed_cases": _parse_int(row.get("completed_cases")),
                "eligible_bapc_cases": _parse_int(row.get("eligible_bapc_cases")),
                "censor_time_seconds": None,
                "censor_completed_cases": None,
            }
    last = rows[-1] if rows else {}
    return {
        "status": "censored",
        "elapsed_wall_seconds": None,
        "completed_cases": None,
        "eligible_bapc_cases": None,
        "censor_time_seconds": _parse_float(last.get("elapsed_wall_seconds")),
        "censor_completed_cases": _parse_int(last.get("completed_cases")),
    }


def _build_section_84_pairs(
    campaigns: list[dict[str, Any]],
    timeseries_by_identity: dict[tuple[str, str, str, str, str, str], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    by_seed_dut: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in campaigns:
        by_seed_dut[(str(row.get("dut") or ""), str(row.get("seed") or ""))][str(row.get("variant") or "")] = row
    pairs: list[dict[str, Any]] = []
    for (dut, seed), variants in sorted(by_seed_dut.items()):
        random_row = variants.get("random-mutation")
        guided_row = variants.get("bb-guided")
        if random_row is None or guided_row is None:
            continue
        endpoint = _parse_int(random_row.get("covered_bin_count"))
        if endpoint is None:
            continue
        random_progress = _reached_endpoint(timeseries_by_identity.get(_identity_key(random_row), []), endpoint)
        guided_progress = _reached_endpoint(timeseries_by_identity.get(_identity_key(guided_row), []), endpoint)
        pairs.append(
            {
                "dut": dut,
                "seed": _parse_int(seed) if _parse_int(seed) is not None else seed,
                "coverage_mode": str(random_row.get("coverage_mode") or ""),
                "endpoint_variant": "random-mutation",
                "endpoint_covered_bin_count": endpoint,
                "coverage_denominator": _parse_int(random_row.get("coverage_denominator")),
                "random_campaign_id": random_row.get("campaign_id"),
                "random_elapsed_wall_seconds": random_progress["elapsed_wall_seconds"],
                "random_completed_cases": random_progress["completed_cases"],
                "random_eligible_bapc_cases": random_progress["eligible_bapc_cases"],
                "random_status": random_progress["status"],
                "random_censor_time_seconds": random_progress["censor_time_seconds"],
                "random_censor_completed_cases": random_progress["censor_completed_cases"],
                "guided_campaign_id": guided_row.get("campaign_id"),
                "guided_elapsed_wall_seconds": guided_progress["elapsed_wall_seconds"],
                "guided_completed_cases": guided_progress["completed_cases"],
                "guided_eligible_bapc_cases": guided_progress["eligible_bapc_cases"],
                "guided_status": guided_progress["status"],
                "guided_censor_time_seconds": guided_progress["censor_time_seconds"],
                "guided_censor_completed_cases": guided_progress["censor_completed_cases"],
            }
        )
    return pairs


def _build_section_85_pairs(campaigns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in campaigns:
        grouped[(str(row.get("dut") or ""), str(row.get("seed") or ""))][str(row.get("generator_variant") or "")] = row
    pairs: list[dict[str, Any]] = []
    for (dut, seed), variants in sorted(grouped.items()):
        full = variants.get("full")
        syntax = variants.get("syntax")
        if full is None or syntax is None:
            continue
        full_covered = _parse_int(full.get("covered_bin_count")) or 0
        syntax_covered = _parse_int(syntax.get("covered_bin_count")) or 0
        pairs.append(
            {
                "dut": dut,
                "seed": _parse_int(seed) if _parse_int(seed) is not None else seed,
                "coverage_denominator": _parse_int(full.get("coverage_denominator")),
                "full_campaign_id": full.get("campaign_id"),
                "full_covered_bin_count": full_covered,
                "full_bapc_rate": _parse_float(full.get("bapc_rate")),
                "full_eligible_bapc_cases": _parse_int(full.get("eligible_bapc_cases")),
                "syntax_campaign_id": syntax.get("campaign_id"),
                "syntax_covered_bin_count": syntax_covered,
                "syntax_bapc_rate": _parse_float(syntax.get("bapc_rate")),
                "syntax_eligible_bapc_cases": _parse_int(syntax.get("eligible_bapc_cases")),
                "covered_bin_delta": full_covered - syntax_covered,
            }
        )
    return pairs


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_sha256_manifest(output_root: Path, output_files: list[Path]) -> Path:
    sha_path = output_root / "sha256.txt"
    lines = [f"{_hash_file(path)}  {path.name}" for path in sorted(output_files)]
    sha_path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return sha_path


def _build_validation_report(
    *,
    freeze_manifests: list[dict[str, Any]],
    section82_batches: list[dict[str, Any]],
    section834_campaigns: list[dict[str, Any]],
    section84_pairs: list[dict[str, Any]],
    section85_campaigns: list[dict[str, Any]],
    allow_partial_counts: bool,
) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    if not freeze_manifests:
        errors.append({"kind": "missing-freeze-manifests"})
    versions = sorted({str(item.get("bapc_core_version") or "") for item in freeze_manifests})
    targets = sorted({int(item.get("bapc_target") or 0) for item in freeze_manifests})
    hashes = sorted({str(item.get("bin_set_sha256") or "") for item in freeze_manifests})
    if len({item for item in versions if item}) > 1:
        errors.append({"kind": "inconsistent-bapc-core-version", "values": versions})
    if len({item for item in targets if item}) > 1:
        errors.append({"kind": "inconsistent-bapc-target", "values": targets})
    if len({item for item in hashes if item}) > 1:
        errors.append({"kind": "inconsistent-bin-set-sha256", "values": hashes})
    for row in section834_campaigns:
        if row.get("artifact_valid") is False:
            errors.append({
                "kind": "artifact-invalid-campaign",
                "campaign_id": row.get("campaign_id"),
                "experiment_id": row.get("experiment_id"),
            })
        if row.get("measurement_valid") is False:
            errors.append({
                "kind": "measurement-invalid-campaign",
                "campaign_id": row.get("campaign_id"),
                "experiment_id": row.get("experiment_id"),
            })
            continue
        if row.get("covered_bin_count") in {None, ""} or row.get("coverage_denominator") in {None, ""}:
            errors.append({
                "kind": "missing-bapc-counts",
                "campaign_id": row.get("campaign_id"),
                "experiment_id": row.get("experiment_id"),
            })
    for row in section85_campaigns:
        if row.get("generator_variant") not in {"full", "syntax"}:
            errors.append({
                "kind": "missing-generator-variant",
                "campaign_id": row.get("campaign_id"),
            })
        if row.get("covered_bin_count") in {None, ""} or row.get("coverage_denominator") in {None, ""}:
            errors.append({
                "kind": "missing-bapc-counts",
                "campaign_id": row.get("campaign_id"),
                "experiment_id": row.get("experiment_id"),
            })
    counts = {
        "section_8_2_batches": len(section82_batches),
        "section_8_3_8_4_campaigns": len(section834_campaigns),
        "section_8_4_pairs": len(section84_pairs),
        "section_8_5_campaigns": len(section85_campaigns),
    }
    if not allow_partial_counts:
        for key, expected in EXPECTED_FORMAL_COUNTS.items():
            actual = counts[key]
            if actual != expected:
                errors.append({
                    "kind": f"unexpected-{key.replace('_', '-')}-count",
                    "expected": expected,
                    "actual": actual,
                })
    return {
        "valid": not errors,
        "error_count": len(errors),
        "errors": errors,
        "counts": counts,
        "expected_counts": EXPECTED_FORMAL_COUNTS,
        "freeze_manifests": freeze_manifests,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    output_root = args.output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    main_root = args.main_root.resolve()
    cascade_roots = [path.resolve() for path in args.cascade_roots]
    section85_roots = [path.resolve() for path in args.section85_roots]

    section82_batches = _load_section_82_batches([main_root])
    section834_campaigns, section834_timeseries = _load_aggregate_campaigns(
        [main_root, *cascade_roots],
        experiment_id="section-8.3-8.4-formal-v4",
    )
    section85_campaigns, _ = _load_aggregate_campaigns(
        section85_roots,
        experiment_id="section-8.5-formal-v4",
    )
    section84_pairs = _build_section_84_pairs(section834_campaigns, section834_timeseries)
    section85_pairs = _build_section_85_pairs(section85_campaigns)

    freeze_manifests = [
        item for item in (
            _load_formal_freeze(main_root),
            *(_load_formal_freeze(root) for root in cascade_roots),
            *(_load_formal_freeze(root) for root in section85_roots),
        )
        if item is not None
    ]
    validation = _build_validation_report(
        freeze_manifests=freeze_manifests,
        section82_batches=section82_batches,
        section834_campaigns=section834_campaigns,
        section84_pairs=section84_pairs,
        section85_campaigns=section85_campaigns,
        allow_partial_counts=args.allow_partial_counts,
    )
    consistency_audit = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "input_roots": {
            "main_root": str(main_root),
            "cascade_roots": [str(path) for path in cascade_roots],
            "section85_roots": [str(path) for path in section85_roots],
        },
        "freeze_manifests": freeze_manifests,
        "campaign_counts": validation["counts"],
    }
    manifest = {
        "schema_version": "1.0",
        "generated_utc": consistency_audit["generated_utc"],
        "main_root": str(main_root),
        "cascade_roots": [str(path) for path in cascade_roots],
        "section85_roots": [str(path) for path in section85_roots],
        "output_root": str(output_root),
    }

    files: list[Path] = []
    for name, payload in (
        ("manifest.json", manifest),
        ("section-8.2-batches.json", section82_batches),
        ("section-8.3-8.4-campaigns.json", section834_campaigns),
        ("section-8.4-paired-endpoints.json", section84_pairs),
        ("section-8.5-campaigns.json", section85_campaigns),
        ("section-8.5-pairs.json", section85_pairs),
        ("consistency-audit.json", consistency_audit),
        ("validation_report.json", validation),
    ):
        path = output_root / name
        _write_json(path, payload)
        files.append(path)

    for name, rows in (
        ("section-8.3-8.4-campaigns.csv", section834_campaigns),
        ("section-8.4-paired-endpoints.csv", section84_pairs),
        ("section-8.5-campaigns.csv", section85_campaigns),
        ("section-8.5-pairs.csv", section85_pairs),
    ):
        path = output_root / name
        _write_csv(path, rows)
        files.append(path)

    index_rows = [
        {
            "file": path.name,
            "sha256": _hash_file(path),
        }
        for path in sorted(files)
    ]
    index_path = output_root / "aggregate-file-index.json"
    _write_json(index_path, index_rows)
    files.append(index_path)

    sha_path = _write_sha256_manifest(output_root, files)
    files.append(sha_path)
    return 0 if validation["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
