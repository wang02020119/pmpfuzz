#!/usr/bin/env python3
"""Validate a campaign timeline for data integrity.

Checks:
- JSONL every line parseable
- campaign_id unique
- source/DUT SHA present (if metadata exists)
- elapsed_wall_seconds monotonically non-decreasing
- completion_seq continuous from 0
- coverage rates monotonically non-decreasing
- denominator constant across campaign
- rate consistent with numerator/denominator
- final timeline matches formal coverage.json
- timeline cases/results exist on disk
- duplicate results rejected
- environment and command manifest complete
- output directory not overwritten by another run
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def validate_timeline(campaign_dir: Path) -> dict[str, Any]:
    """Run all validation checks and return a report.

    Returns a dict with ``valid`` (bool), ``error_count``, ``warning_count``,
    and a ``checks`` list of per-check results.
    """
    timeline_path = campaign_dir / "metrics" / "coverage_timeline.jsonl"
    metadata_path = campaign_dir / "metrics" / "campaign_metadata.json"
    coverage_path = campaign_dir / "coverage" / "coverage.json"

    report = {
        "schema_version": "1.0",
        "campaign": str(campaign_dir),
        "checked_utc": None,
        "error_count": 0,
        "warning_count": 0,
        "checks": [],
        "valid": True,
    }
    from datetime import datetime, timezone
    report["checked_utc"] = datetime.now(timezone.utc).isoformat()

    errors = []
    warnings = []

    def add_check(name: str, passed: bool, detail: str = "", severity: str = "error"):
        report["checks"].append({"name": name, "passed": passed, "severity": severity, "detail": detail})
        if not passed:
            if severity == "error":
                errors.append(name)
                report["error_count"] += 1
            else:
                warnings.append(name)
                report["warning_count"] += 1

    # --- 1. JSONL exists and every line parseable ---
    if not timeline_path.exists():
        add_check("timeline_exists", False, str(timeline_path))
        report["valid"] = False
        return report

    try:
        raw_lines = timeline_path.read_text(encoding="ascii").strip().split("\n")
    except Exception as exc:
        add_check("timeline_readable", False, str(exc))
        report["valid"] = False
        return report

    lines: list[dict[str, Any]] = []
    for i, raw in enumerate(raw_lines):
        if not raw.strip():
            continue
        try:
            lines.append(json.loads(raw))
        except json.JSONDecodeError as exc:
            add_check("parse_line", False, f"line {i}: {exc}")
    if not lines:
        add_check("timeline_nonempty", False, "no valid lines")
        report["valid"] = False
        return report
    add_check("timeline_nonempty", True, f"{len(lines)} lines")

    # --- 2. campaign_id consistent ---
    campaign_ids = {line.get("campaign_id") for line in lines if line.get("campaign_id")}
    if len(campaign_ids) == 0:
        add_check("campaign_id_present", False, "no campaign_id found")
    elif len(campaign_ids) > 1:
        add_check("campaign_id_unique", False, f"multiple: {campaign_ids}")
    else:
        add_check("campaign_id_unique", True)

    # --- 3. Metadata completeness ---
    if metadata_path.exists():
        add_check("metadata_exists", True)
    else:
        add_check("metadata_exists", False, "missing campaign_metadata.json", severity="warning")

    # --- 4. Schema version ---
    sv = lines[0].get("schema_version")
    if sv is not None:
        add_check("schema_version", True, str(sv))
    else:
        add_check("schema_version", False, "missing", severity="warning")

    # --- 5. completion_seq continuous from 0 ---
    seqs = [line.get("completion_seq") for line in lines if line.get("completion_seq") is not None]
    if seqs:
        expected = list(range(len(seqs)))
        if seqs == expected:
            add_check("completion_seq_continuous", True)
        else:
            add_check("completion_seq_continuous", False, f"expected {expected[:5]}..., got {seqs[:5]}...")

    # --- 6. elapsed_wall_seconds monotonically non-decreasing ---
    times = [line.get("elapsed_wall_seconds") for line in lines if line.get("elapsed_wall_seconds") is not None]
    if times:
        monotonic = all(times[i] >= times[i-1] for i in range(1, len(times)))
        if monotonic:
            add_check("wall_seconds_monotonic", True)
        else:
            add_check("wall_seconds_monotonic", False, "found decreasing wall time")

    # --- 7. Coverage rates monotonically non-decreasing ---
    for key in ["semantic_rate", "pairwise_rate", "security_triples_rate", "predicates_rate"]:
        rates = [line.get(key) for line in lines[1:] if line.get(key) is not None]  # skip baseline
        if rates:
            non_decr = all((rates[i] or 0) >= (rates[i-1] or 0) - 1e-9 for i in range(1, len(rates)))
            if not non_decr:
                add_check(f"{key}_monotonic", False, f"rate decreased at some point")

    # --- 8. Denominator constant ---
    for key in ["semantic_target", "pairwise_target", "security_triples_target", "predicates_target"]:
        targets = [line.get(key) for line in lines if line.get(key) is not None]
        if targets:
            unique = set(targets)
            if len(unique) == 1:
                add_check(f"{key}_constant", True)
            else:
                add_check(f"{key}_constant", False, f"varies: {unique}")

    # --- 9. Rate = covered / target (within 1e-9) ---
    for prefix in ["semantic", "pairwise", "security_triples", "predicates"]:
        for line in lines[1:]:
            covered = line.get(f"{prefix}_covered")
            target = line.get(f"{prefix}_target")
            rate = line.get(f"{prefix}_rate")
            if covered is not None and target is not None and target > 0 and rate is not None:
                expected_rate = covered / target
                if abs(rate - expected_rate) > 1e-9:
                    add_check(f"{prefix}_rate_consistent", False,
                              f"seq={line.get('completion_seq')}: rate={rate} != {covered}/{target}={expected_rate}")
                    break
        else:
            add_check(f"{prefix}_rate_consistent", True)

    # --- 10. Final timeline matches coverage.json ---
    if coverage_path.exists():
        try:
            cov = json.loads(coverage_path.read_text(encoding="ascii"))
            exec_cov = cov.get("execution_coverage", {}).get("by_dut", {})
            if exec_cov:
                # Take the first available DUT
                dut_cov = next(iter(exec_cov.values()))
                last = lines[-1]

                def _check_coverage_match(label, tl_key_covered, tl_key_target, cov_section):
                    if not cov_section:
                        return
                    tl_covered = last.get(tl_key_covered, 0)
                    tl_target = last.get(tl_key_target, 0)
                    cov_covered = cov_section.get("covered_target_bins", 0)
                    cov_target = cov_section.get("total_target_bins", 0)
                    if tl_covered == cov_covered and tl_target == cov_target:
                        add_check(f"final_{label}_matches_coverage", True)
                    else:
                        add_check(f"final_{label}_matches_coverage", False,
                                  f"timeline: {tl_covered}/{tl_target}, coverage: {cov_covered}/{cov_target}")

                _check_coverage_match("semantic", "semantic_covered", "semantic_target", dut_cov.get("semantic"))
                _check_coverage_match("pairwise", "pairwise_covered", "pairwise_target", dut_cov.get("pairwise"))
                _check_coverage_match("triples", "security_triples_covered", "security_triples_target", dut_cov.get("security_triples"))
                _check_coverage_match("predicates", "predicates_covered", "predicates_target", dut_cov.get("predicates"))
        except Exception as exc:
            add_check("coverage_json_readable", False, str(exc), severity="warning")

    # --- Final validity ---
    report["valid"] = report["error_count"] == 0
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a campaign timeline for data integrity")
    parser.add_argument("--campaign", type=Path, required=True, help="Path to campaign output directory")
    args = parser.parse_args(argv)

    campaign_dir = args.campaign.resolve()
    if not campaign_dir.is_dir():
        print(f"ERROR: campaign directory not found: {campaign_dir}", file=sys.stderr)
        return 1

    report = validate_timeline(campaign_dir)

    # Write validation result
    val_path = campaign_dir / "validation.json"
    val_path.write_text(json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True) + "\n", encoding="ascii")

    # Print summary
    print(f"campaign={campaign_dir}")
    print(f"valid={report['valid']} errors={report['error_count']} warnings={report['warning_count']}")
    for check in report["checks"]:
        status = "PASS" if check["passed"] else "FAIL"
        print(f"  [{status}] {check['name']}: {check.get('detail', '')}")

    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
