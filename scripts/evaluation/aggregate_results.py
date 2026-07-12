#!/usr/bin/env python3
"""Aggregate results across all campaigns into standard CSV tables for plotting.

Produces:
- aggregate/campaign_index.csv
- aggregate/coverage_final.csv
- aggregate/coverage_threshold_times.csv
- aggregate/coverage_auc.csv
- aggregate/coverage_timeseries.csv
- aggregate/statistics.json
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


CAMPAIGN_FIELDS = [
    "schema_version", "experiment_id", "campaign_id", "method", "variant",
    "dut", "seed", "coverage_mode", "source_sha", "dut_sha",
    "dut_binary_sha256", "start_utc", "end_utc", "time_budget_seconds",
    "round_size", "jobs", "per_case_timeout_seconds", "completed_cases",
    "eligible_cases", "semantic_final_rate", "pairwise_final_rate",
    "triples_final_rate", "predicates_final_rate", "artifact_path",
]

EVENT_FIELDS = [
    "schema_version", "experiment_id", "campaign_id", "method", "variant",
    "dut", "seed", "completion_seq", "event_index", "elapsed_wall_seconds",
    "event_namespace", "event_category", "event_id", "is_new_event",
    "total_distinct_events", "case_id",
]


def aggregate(artifact_root: Path, experiment_id: str) -> dict[str, Path]:
    """Scan *artifact_root* for campaigns, extract data, write CSV tables.

    Returns a dict mapping table names to output Paths.
    """
    aggregate_dir = artifact_root / "aggregate"
    aggregate_dir.mkdir(parents=True, exist_ok=True)
    normalized_dir = artifact_root / "normalized"
    normalized_dir.mkdir(parents=True, exist_ok=True)
    schemas_dir = artifact_root / "schemas"
    schemas_dir.mkdir(parents=True, exist_ok=True)
    manifests_dir = artifact_root / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)

    campaigns: list[dict[str, Any]] = []
    timeseries_rows: list[dict[str, Any]] = []
    security_event_rows: list[dict[str, Any]] = []

    # Scan campaigns directory tree
    campaigns_root = artifact_root / "campaigns"
    if campaigns_root.is_dir():
        for tl_path in campaigns_root.rglob("coverage_timeline.jsonl"):
            if "rounds" in tl_path.parts:
                continue
            campaign_dir = tl_path.parents[1]  # metrics/ -> campaign/
            meta_path = tl_path.parent / "campaign_metadata.json"
            try:
                lines = _parse_jsonl(tl_path)
                meta = json.loads(meta_path.read_text(encoding="ascii")) if meta_path.exists() else {}
                campaign = _build_campaign_row(experiment_id, campaign_dir, meta, lines)
                campaigns.append(campaign)
                security_event_rows.extend(_load_security_events(campaign_dir, campaign))

                for line in lines:
                    row = _build_timeseries_row(experiment_id, campaign, line)
                    if row is not None:
                        timeseries_rows.append(row)
            except Exception as exc:
                print(f"WARNING: skipping {campaign_dir}: {exc}", file=sys.stderr)

    # Also scan pilot directory
    pilot_root = artifact_root / "pilot"
    if pilot_root.is_dir():
        for tl_path in pilot_root.rglob("coverage_timeline.jsonl"):
            if "rounds" in tl_path.parts:
                continue
            campaign_dir = tl_path.parents[1]
            meta_path = tl_path.parent / "campaign_metadata.json"
            try:
                lines = _parse_jsonl(tl_path)
                meta = json.loads(meta_path.read_text(encoding="ascii")) if meta_path.exists() else {}
                campaign = _build_campaign_row(experiment_id, campaign_dir, meta, lines)
                campaigns.append(campaign)
                security_event_rows.extend(_load_security_events(campaign_dir, campaign))

                for line in lines:
                    row = _build_timeseries_row(experiment_id, campaign, line)
                    if row is not None:
                        timeseries_rows.append(row)
            except Exception as exc:
                print(f"WARNING: skipping {campaign_dir}: {exc}", file=sys.stderr)

    outputs: dict[str, Path] = {}

    # --- normalized/campaigns.csv ---
    campaigns_path = normalized_dir / "campaigns.csv"
    _write_csv_with_fields(campaigns_path, campaigns, CAMPAIGN_FIELDS)
    outputs["normalized_campaigns"] = campaigns_path

    # --- normalized/coverage_timeseries.csv ---
    normalized_coverage_path = normalized_dir / "coverage_timeseries.csv"
    _write_csv_with_fields(
        normalized_coverage_path,
        timeseries_rows,
        list(timeseries_rows[0].keys()) if timeseries_rows else [
            "schema_version", "experiment_id", "campaign_id", "method", "variant",
            "dut", "seed", "coverage_mode", "completion_seq",
            "elapsed_wall_seconds", "completed_cases", "eligible_cases",
            "covered_bins", "target_bins", "coverage_rate", "new_bins",
            "status", "failure_class", "case_id",
        ],
    )
    outputs["normalized_coverage_timeseries"] = normalized_coverage_path

    # --- normalized/security_event_timeseries.csv ---
    normalized_events_path = normalized_dir / "security_event_timeseries.csv"
    _write_csv_with_fields(normalized_events_path, security_event_rows, EVENT_FIELDS)
    outputs["normalized_security_event_timeseries"] = normalized_events_path

    # --- campaign_index.csv ---
    if campaigns:
        path = aggregate_dir / "campaign_index.csv"
        _write_csv(path, campaigns)
        outputs["campaign_index"] = path
        print(f"campaign_index: {len(campaigns)} rows -> {path}")

    # --- coverage_final.csv ---
    coverage_final = [_coverage_final_row(c) for c in campaigns if c.get("eligible_cases", 0) > 0]
    if coverage_final:
        path = aggregate_dir / "coverage_final.csv"
        _write_csv(path, coverage_final)
        outputs["coverage_final"] = path
        print(f"coverage_final: {len(coverage_final)} rows -> {path}")

    # --- coverage_threshold_times.csv ---
    threshold_rows = _compute_thresholds(timeseries_rows)
    if threshold_rows:
        path = aggregate_dir / "coverage_threshold_times.csv"
        _write_csv(path, threshold_rows)
        outputs["coverage_threshold_times"] = path
        print(f"coverage_threshold_times: {len(threshold_rows)} rows -> {path}")

    # --- coverage_timeseries.csv (normalized) ---
    if timeseries_rows:
        path = aggregate_dir / "coverage_timeseries.csv"
        _write_csv(path, timeseries_rows)
        outputs["coverage_timeseries"] = path
        print(f"coverage_timeseries: {len(timeseries_rows)} rows -> {path}")

    # --- coverage_auc.csv ---
    auc_rows = _compute_auc(timeseries_rows)
    auc_path = aggregate_dir / "coverage_auc.csv"
    _write_csv_with_fields(
        auc_path,
        auc_rows,
        list(auc_rows[0].keys()) if auc_rows else [
            "schema_version", "experiment_id", "campaign_id", "method", "variant",
            "dut", "seed", "coverage_mode", "horizon_seconds", "auc",
            "normalized_auc",
        ],
    )
    outputs["coverage_auc"] = auc_path

    # --- overhead.csv ---
    overhead_rows = _compute_overhead(campaigns, timeseries_rows)
    overhead_path = aggregate_dir / "overhead.csv"
    _write_csv_with_fields(
        overhead_path,
        overhead_rows,
        list(overhead_rows[0].keys()) if overhead_rows else [
            "schema_version", "experiment_id", "campaign_id", "method", "variant",
            "dut", "seed", "wall_seconds", "completed_cases", "eligible_cases",
            "tests_per_second", "jobs",
        ],
    )
    outputs["overhead"] = overhead_path

    # --- exclusions.csv ---
    exclusions_path = aggregate_dir / "exclusions.csv"
    if not exclusions_path.exists():
        _write_csv_with_fields(
            exclusions_path,
            [],
            ["campaign_id", "excluded", "reason", "recorded_utc"],
        )
    outputs["exclusions"] = exclusions_path

    # --- statistics.json ---
    stats = _compute_statistics(campaigns, timeseries_rows)
    path = aggregate_dir / "statistics.json"
    path.write_text(json.dumps(stats, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
    outputs["statistics"] = path

    # --- schema documentation ---
    dictionary_path = schemas_dir / "data_dictionary.md"
    dictionary_path.write_text(_data_dictionary(), encoding="utf-8")
    outputs["data_dictionary"] = dictionary_path

    # --- aggregate validation report ---
    validation_path = aggregate_dir / "validation_report.json"
    validation = _validate_normalized_outputs(
        campaigns_path, normalized_coverage_path, normalized_events_path,
        auc_path, overhead_path, exclusions_path, dictionary_path,
    )
    validation_path.write_text(
        json.dumps(validation, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )
    outputs["validation_report"] = validation_path

    # --- artifact hashes (written last; the manifest does not hash itself) ---
    hash_path = manifests_dir / "artifact-sha256.txt"
    _write_artifact_hashes(
        artifact_root,
        [path for path in outputs.values() if path != hash_path],
        hash_path,
    )
    outputs["artifact_hashes"] = hash_path

    return outputs


def _load_security_events(campaign_dir: Path, campaign: dict[str, Any]) -> list[dict[str, Any]]:
    path = campaign_dir / "metrics" / "security_event_timeseries.jsonl"
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="ascii").splitlines():
        if not raw.strip():
            continue
        row = json.loads(raw)
        normalized = {field: row.get(field) for field in EVENT_FIELDS}
        normalized["experiment_id"] = normalized.get("experiment_id") or campaign["experiment_id"]
        normalized["campaign_id"] = normalized.get("campaign_id") or campaign["campaign_id"]
        normalized["method"] = normalized.get("method") or campaign["method"]
        normalized["variant"] = normalized.get("variant") or campaign["variant"]
        normalized["dut"] = normalized.get("dut") or campaign["dut"]
        normalized["seed"] = normalized.get("seed") if normalized.get("seed") is not None else campaign["seed"]
        rows.append(normalized)
    return rows


def _parse_jsonl(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="ascii").strip()
    if not raw:
        return []
    return [json.loads(line) for line in raw.split("\n") if line.strip()]


def _build_campaign_row(experiment_id: str, campaign_dir: Path, meta: dict, lines: list[dict]) -> dict:
    last = lines[-1] if lines else {}
    return {
        "schema_version": "1.0",
        "experiment_id": experiment_id,
        "campaign_id": meta.get("campaign_id") or last.get("campaign_id", ""),
        "method": meta.get("method") or "pmpfuzz",
        "variant": meta.get("variant") or last.get("variant", ""),
        "dut": meta.get("dut") or last.get("dut", ""),
        "seed": meta.get("seed"),
        "coverage_mode": meta.get("coverage_mode") or "",
        "source_sha": meta.get("source_sha") or "",
        "dut_sha": meta.get("dut_sha") or "",
        "dut_binary_sha256": meta.get("dut_binary_sha256") or "",
        "start_utc": meta.get("start_utc") or "",
        "end_utc": meta.get("end_utc") or "",
        "time_budget_seconds": meta.get("time_budget_seconds"),
        "round_size": meta.get("round_size") or 0,
        "jobs": meta.get("jobs") or 1,
        "per_case_timeout_seconds": meta.get("per_case_timeout_seconds"),
        "completed_cases": last.get("completed_cases", 0),
        "eligible_cases": last.get("eligible_cases", 0),
        "semantic_final_rate": last.get("semantic_rate"),
        "pairwise_final_rate": last.get("pairwise_rate"),
        "triples_final_rate": last.get("security_triples_rate"),
        "predicates_final_rate": last.get("predicates_rate"),
        "artifact_path": str(campaign_dir),
    }


def _build_timeseries_row(experiment_id: str, campaign: dict, line: dict) -> dict:
    coverage_mode = campaign.get("coverage_mode", "semantic")
    covered_key = {
        "semantic": "semantic_covered",
        "pairwise": "pairwise_covered",
        "security-triples": "security_triples_covered",
        "predicates": "predicates_covered",
    }
    target_key = {
        "semantic": "semantic_target",
        "pairwise": "pairwise_target",
        "security-triples": "security_triples_target",
        "predicates": "predicates_target",
    }
    rate_key = {
        "semantic": "semantic_rate",
        "pairwise": "pairwise_rate",
        "security-triples": "security_triples_rate",
        "predicates": "predicates_rate",
    }
    # D1: Skip synthetic baseline row (completion_seq=0)
    if line.get("completion_seq", 0) == 0:
        return None

    # D2: Correct field name mapping for new_bins
    new_bins_key = {
        "semantic": "new_semantic_bins",
        "pairwise": "new_pairwise_bins",
        "security-triples": "new_security_triple_bins",
        "predicates": "new_predicate_bins",
    }

    return {
        "schema_version": "1.0",
        "experiment_id": experiment_id,
        "campaign_id": campaign["campaign_id"],
        "method": campaign["method"],
        "variant": campaign["variant"],
        "dut": campaign["dut"],
        "seed": campaign["seed"],
        "coverage_mode": coverage_mode,
        "completion_seq": line.get("completion_seq", 0),
        "elapsed_wall_seconds": line.get("elapsed_wall_seconds", 0),
        "completed_cases": line.get("completed_cases", 0),
        "eligible_cases": line.get("eligible_cases", 0),
        "covered_bins": line.get(covered_key.get(coverage_mode, "semantic_covered"), 0),
        "target_bins": line.get(target_key.get(coverage_mode, "semantic_target"), 0),
        "coverage_rate": line.get(rate_key.get(coverage_mode, "semantic_rate")),
        "new_bins": line.get(new_bins_key.get(coverage_mode, "new_semantic_bins"), 0),
        "status": line.get("status") or "",
        "failure_class": line.get("failure_class") or "",
        "case_id": line.get("case_id") or "",
    }


def _coverage_final_row(campaign: dict) -> dict:
    return {
        "schema_version": "1.0",
        "experiment_id": campaign["experiment_id"],
        "campaign_id": campaign["campaign_id"],
        "method": campaign["method"],
        "variant": campaign["variant"],
        "dut": campaign["dut"],
        "seed": campaign["seed"],
        "coverage_mode": campaign["coverage_mode"],
        "semantic_rate": campaign.get("semantic_final_rate"),
        "pairwise_rate": campaign.get("pairwise_final_rate"),
        "triples_rate": campaign.get("triples_final_rate"),
        "predicates_rate": campaign.get("predicates_final_rate"),
        "completed_cases": campaign.get("completed_cases", 0),
        "eligible_cases": campaign.get("eligible_cases", 0),
    }


def _compute_thresholds(timeseries: list[dict]) -> list[dict]:
    """Compute time and case count to reach coverage thresholds."""
    from collections import defaultdict

    # Group by campaign_id and coverage_mode
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in timeseries:
        key = (row["campaign_id"], row["coverage_mode"])
        groups[key].append(row)

    thresholds = [0.25, 0.50, 0.75, 0.90, 1.0]
    result = []

    for (cid, cmode), rows in groups.items():
        rows.sort(key=lambda r: r["completion_seq"])
        for thresh in thresholds:
            reached = False
            for row in rows:
                rate = row.get("coverage_rate")
                if rate is not None and rate >= thresh:
                    reached = True
                    result.append({
                        "schema_version": "1.0",
                        "experiment_id": rows[0]["experiment_id"],
                        "campaign_id": cid,
                        "method": rows[0]["method"],
                        "variant": rows[0]["variant"],
                        "dut": rows[0]["dut"],
                        "seed": rows[0]["seed"],
                        "coverage_mode": cmode,
                        "threshold": thresh,
                        "threshold_reached": True,
                        "elapsed_wall_seconds": row["elapsed_wall_seconds"],
                        "completed_cases": row["completed_cases"],
                        "eligible_cases": row["eligible_cases"],
                        "censored": False,
                    })
                    break
            if not reached and rows:
                result.append({
                    "schema_version": "1.0",
                    "experiment_id": rows[0]["experiment_id"],
                    "campaign_id": cid,
                    "method": rows[0]["method"],
                    "variant": rows[0]["variant"],
                    "dut": rows[0]["dut"],
                    "seed": rows[0]["seed"],
                    "coverage_mode": cmode,
                    "threshold": thresh,
                    "threshold_reached": False,
                    "elapsed_wall_seconds": "",
                    "completed_cases": "",
                    "eligible_cases": "",
                    "censored": True,
                })

    return result


def _compute_statistics(campaigns: list[dict], timeseries: list[dict]) -> dict:
    """Compute basic summary statistics."""
    import statistics as st
    from collections import defaultdict

    stats: dict[str, Any] = {
        "schema_version": "1.0",
        "total_campaigns": len(campaigns),
        "total_timeseries_rows": len(timeseries),
    }

    # Per-method per-variant per-dut final coverage stats
    groups: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    for c in campaigns:
        for cmode, key in [("semantic", "semantic_final_rate"), ("pairwise", "pairwise_final_rate"),
                            ("security-triples", "triples_final_rate"), ("predicates", "predicates_final_rate")]:
            rate = c.get(key)
            if rate is not None:
                groups[(c.get("method", ""), c.get("variant", ""), cmode)].append(rate)

    per_group = {}
    for (method, variant, cmode), rates in groups.items():
        if len(rates) >= 2:
            per_group[f"{method}/{variant}/{cmode}"] = {
                "n": len(rates),
                "median": st.median(rates),
                "q1": st.median(sorted(rates)[:len(rates)//2]) if len(rates) >= 4 else None,
                "q3": st.median(sorted(rates)[len(rates)//2:]) if len(rates) >= 4 else None,
                "mean": st.mean(rates),
                "min": min(rates),
                "max": max(rates),
            }

    stats["per_group"] = per_group
    return stats


def _compute_auc(timeseries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compute trapezoidal coverage AUC for every campaign/mode."""
    from collections import defaultdict

    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in timeseries:
        groups[(str(row["campaign_id"]), str(row["coverage_mode"]))].append(row)

    output: list[dict[str, Any]] = []
    for (_, coverage_mode), rows in groups.items():
        rows.sort(key=lambda item: (float(item["elapsed_wall_seconds"]), int(item["completion_seq"])))
        points = [(0.0, 0.0)]
        for row in rows:
            rate = row.get("coverage_rate")
            if rate is None or rate == "":
                continue
            points.append((float(row["elapsed_wall_seconds"]), float(rate)))
        if len(points) < 2:
            continue
        area = 0.0
        for index in range(1, len(points)):
            x0, y0 = points[index - 1]
            x1, y1 = points[index]
            area += max(0.0, x1 - x0) * (y0 + y1) / 2.0
        horizon = points[-1][0]
        first = rows[0]
        output.append({
            "schema_version": "1.0",
            "experiment_id": first["experiment_id"],
            "campaign_id": first["campaign_id"],
            "method": first["method"],
            "variant": first["variant"],
            "dut": first["dut"],
            "seed": first["seed"],
            "coverage_mode": coverage_mode,
            "horizon_seconds": horizon,
            "auc": area,
            "normalized_auc": area / horizon if horizon > 0 else None,
        })
    return output


def _compute_overhead(
    campaigns: list[dict[str, Any]], timeseries: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Build campaign-level throughput rows without interpreting result content."""
    last_by_campaign: dict[str, dict[str, Any]] = {}
    for row in timeseries:
        campaign_id = str(row["campaign_id"])
        previous = last_by_campaign.get(campaign_id)
        if previous is None or int(row["completion_seq"]) > int(previous["completion_seq"]):
            last_by_campaign[campaign_id] = row

    rows: list[dict[str, Any]] = []
    for campaign in campaigns:
        last = last_by_campaign.get(str(campaign["campaign_id"]), {})
        wall = float(last.get("elapsed_wall_seconds") or 0.0)
        completed = int(last.get("completed_cases") or campaign.get("completed_cases") or 0)
        eligible = int(last.get("eligible_cases") or campaign.get("eligible_cases") or 0)
        rows.append({
            "schema_version": "1.0",
            "experiment_id": campaign["experiment_id"],
            "campaign_id": campaign["campaign_id"],
            "method": campaign["method"],
            "variant": campaign["variant"],
            "dut": campaign["dut"],
            "seed": campaign["seed"],
            "wall_seconds": wall,
            "completed_cases": completed,
            "eligible_cases": eligible,
            "tests_per_second": completed / wall if wall > 0 else None,
            "jobs": campaign.get("jobs"),
        })
    return rows


def _data_dictionary() -> str:
    return """# PMPFuzz normalized evaluation data dictionary

All time values use seconds. Missing or non-applicable values are empty in CSV
and `null` in JSON. Synthetic `completion_seq=0` baseline rows are excluded from
normalized completion tables.

## normalized/campaigns.csv

One row per `(experiment_id, campaign_id)`. It records method, variant, DUT,
seed, version hashes, resource budget, final coverage, and artifact path.

## normalized/coverage_timeseries.csv

One row per completed case and coverage mode. `elapsed_wall_seconds` is measured
from the campaign origin at actual case completion. `covered_bins` is cumulative;
`new_bins` is the increment from that completion. Only execution-qualified
results contribute coverage.

## normalized/security_event_timeseries.csv

One row per normalized DUT event. `completion_seq` refers to the completing
case; `event_index` distinguishes multiple events from the same case. Event IDs
must not depend on method name or case ID.

## aggregate tables

`coverage_threshold_times.csv` stores threshold crossing or right-censoring.
`coverage_auc.csv` stores trapezoidal AUC and normalized AUC. `overhead.csv`
stores campaign wall time, throughput, and resource allocation.
`exclusions.csv` records predeclared campaign exclusions.
"""


def _validate_normalized_outputs(*paths: Path) -> dict[str, Any]:
    errors: list[str] = []
    checks: list[dict[str, Any]] = []
    for path in paths:
        exists = path.exists()
        checks.append({"name": f"exists:{path.name}", "passed": exists})
        if not exists:
            errors.append(f"missing output: {path}")

    csv_paths = [path for path in paths if path.suffix == ".csv" and path.exists()]
    for path in csv_paths:
        with path.open("r", encoding="ascii", newline="") as handle:
            list(csv.DictReader(handle))

    return {
        "schema_version": "1.0",
        "error_count": len(errors),
        "warning_count": 0,
        "errors": errors,
        "checks": checks,
        "valid": not errors,
    }


def _write_artifact_hashes(
    artifact_root: Path, paths: list[Path], output_path: Path
) -> None:
    unique = sorted({path.resolve() for path in paths if path.exists()})
    lines: list[str] = []
    for path in unique:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        relative = path.relative_to(artifact_root.resolve()).as_posix()
        lines.append(f"{digest}  {relative}")
    output_path.write_text("\n".join(lines) + "\n", encoding="ascii")


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="ascii", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_csv_with_fields(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="ascii", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate evaluation results")
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--experiment-id", default="eval-v1")
    args = parser.parse_args(argv)

    outputs = aggregate(args.artifact_root, args.experiment_id)
    if not outputs:
        print("WARNING: no campaign data found")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
