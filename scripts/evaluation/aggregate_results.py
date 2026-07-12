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
import json
import sys
from pathlib import Path
from typing import Any


def aggregate(artifact_root: Path, experiment_id: str) -> dict[str, Path]:
    """Scan *artifact_root* for campaigns, extract data, write CSV tables.

    Returns a dict mapping table names to output Paths.
    """
    aggregate_dir = artifact_root / "aggregate"
    aggregate_dir.mkdir(parents=True, exist_ok=True)

    campaigns: list[dict[str, Any]] = []
    timeseries_rows: list[dict[str, Any]] = []

    # Scan campaigns directory tree
    campaigns_root = artifact_root / "campaigns"
    if campaigns_root.is_dir():
        for tl_path in campaigns_root.rglob("coverage_timeline.jsonl"):
            campaign_dir = tl_path.parents[1]  # metrics/ -> campaign/
            meta_path = tl_path.parent / "campaign_metadata.json"
            try:
                lines = _parse_jsonl(tl_path)
                meta = json.loads(meta_path.read_text(encoding="ascii")) if meta_path.exists() else {}
                campaign = _build_campaign_row(experiment_id, campaign_dir, meta, lines)
                campaigns.append(campaign)

                for line in lines:
                    if line.get("completion_seq", 0) > 0:
                        timeseries_rows.append(_build_timeseries_row(experiment_id, campaign, line))
            except Exception as exc:
                print(f"WARNING: skipping {campaign_dir}: {exc}", file=sys.stderr)

    # Also scan pilot directory
    pilot_root = artifact_root / "pilot"
    if pilot_root.is_dir():
        for tl_path in pilot_root.rglob("coverage_timeline.jsonl"):
            campaign_dir = tl_path.parents[1]
            meta_path = tl_path.parent / "campaign_metadata.json"
            try:
                lines = _parse_jsonl(tl_path)
                meta = json.loads(meta_path.read_text(encoding="ascii")) if meta_path.exists() else {}
                campaign = _build_campaign_row(experiment_id, campaign_dir, meta, lines)
                campaigns.append(campaign)

                for line in lines:
                    if line.get("completion_seq", 0) > 0:
                        timeseries_rows.append(_build_timeseries_row(experiment_id, campaign, line))
            except Exception as exc:
                print(f"WARNING: skipping {campaign_dir}: {exc}", file=sys.stderr)

    outputs: dict[str, Path] = {}

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

    # --- statistics.json ---
    stats = _compute_statistics(campaigns, timeseries_rows)
    path = aggregate_dir / "statistics.json"
    path.write_text(json.dumps(stats, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
    outputs["statistics"] = path

    return outputs


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
        "method": "pmpfuzz",
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
        "new_bins": line.get(f"new_{coverage_mode}_bins" if coverage_mode != "security-triples" else "new_security_triple_bins", 0),
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


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="ascii", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
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
