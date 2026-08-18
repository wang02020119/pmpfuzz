#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from pathlib import Path as _Path
from typing import Any

_source_root_override = os.environ.get("PMPFUZZ_SOURCE_ROOT")
_script_root = (
    _Path(_source_root_override).resolve()
    if _source_root_override
    else _Path(__file__).resolve().parents[3]
)
if str(_script_root) not in sys.path:
    sys.path.insert(0, str(_script_root))

from pmpfuzz.cascade_runtime import replay_cascade_runtime_record


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate Cascade runtime attribution replay and measurement closure."
    )
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--report", type=Path, default=None)
    return parser


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _family_counts(bin_ids: set[str]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for bin_id in bin_ids:
        family = ""
        for part in str(bin_id).split("|"):
            if part.startswith("family="):
                family = part.split("=", 1)[1]
                break
        counts[family or "unknown"] += 1
    return dict(sorted(counts.items()))


def _sidecar_path(campaign_dir: Path, event: dict[str, Any]) -> Path | None:
    rel = event.get("sidecar_relpath")
    if isinstance(rel, str) and rel.strip():
        path = campaign_dir / rel
        if path.exists():
            return path
    case_id = str(event.get("case_id") or "")
    if not case_id:
        return None
    try:
        _, dut, case_index = case_id.rsplit("_", 2)
    except ValueError:
        return None
    design = dut.split("-", 1)[0]
    path = campaign_dir / "elfs" / f"{design}_{int(case_index):d}.json"
    return path if path.exists() else None


def validate_campaign(campaign_dir: Path) -> dict[str, Any]:
    campaign_dir = campaign_dir.resolve()
    events_path = campaign_dir / "events.json"
    metadata_path = campaign_dir / "metrics" / "campaign_metadata.json"
    events = list(_load_json(events_path))
    metadata = dict(_load_json(metadata_path))
    bapc_core_version = str(metadata.get("bapc_core_version") or "v4")
    universe_rel = (
        dict(metadata.get("coverage_universe_files") or {}).get("bapc")
        if isinstance(metadata.get("coverage_universe_files"), dict)
        else None
    )
    universe_path = campaign_dir / universe_rel if universe_rel else None
    universe_payload = dict(_load_json(universe_path)) if universe_path and universe_path.exists() else {}
    universe_bins = {str(item) for item in (universe_payload.get("bin_ids") or [])}

    completed_cases = len(events)
    qualification_counts: Counter[str] = Counter()
    measurement_valid_cases = 0
    artifact_valid_cases = 0
    runtime_record_cases = 0
    eligible_bapc_cases = 0
    covered_bins: set[str] = set()
    out_of_contract_bins: set[str] = set()
    unexpected_mapper_bins: set[str] = set()
    replay_failures: list[dict[str, Any]] = []
    per_case: list[dict[str, Any]] = []

    for event in events:
        case_id = str(event.get("case_id") or "")
        runtime_payload = dict(event.get("cascade_runtime") or {})
        bapc_payload = dict(event.get("bapc_coverage") or {})
        qualification_reason = str(
            bapc_payload.get("qualification_reason")
            or runtime_payload.get("qualification_reason")
            or "missing-qualification-reason"
        )
        qualification_counts[qualification_reason] += 1
        artifact_valid = bool(
            bapc_payload.get("artifact_valid")
            if "artifact_valid" in bapc_payload
            else runtime_payload.get("artifact_valid")
        )
        measurement_valid = bool(
            bapc_payload.get("measurement_valid")
            if "measurement_valid" in bapc_payload
            else runtime_payload.get("measurement_valid")
        )
        if artifact_valid:
            artifact_valid_cases += 1
        if measurement_valid:
            measurement_valid_cases += 1
        runtime_records = [
            dict(item)
            for item in (runtime_payload.get("runtime_records") or [])
            if isinstance(item, dict)
        ]
        if runtime_records:
            runtime_record_cases += 1
        event_bins = {str(item) for item in (bapc_payload.get("observed_bins") or [])}
        covered_bins.update(event_bins)
        out_of_contract_bins.update(str(item) for item in (event.get("bapc_out_of_contract_bins") or []))
        if bool(event.get("bapc_eligible")):
            eligible_bapc_cases += 1

        replay_bins: set[str] = set()
        replay_ok = True
        replay_reasons: list[str] = []
        if measurement_valid:
            sidecar_path = _sidecar_path(campaign_dir, event)
            if sidecar_path is None:
                replay_ok = False
                replay_reasons.append("missing-sidecar-for-replay")
            else:
                sidecar = dict(_load_json(sidecar_path))
                for runtime_record in runtime_records:
                    replay = replay_cascade_runtime_record(
                        sidecar=sidecar,
                        runtime_record=runtime_record,
                        bapc_core_version=bapc_core_version,
                    )
                    if not replay.get("eligible"):
                        replay_ok = False
                        replay_reasons.append(
                            str(replay.get("qualification_reason") or "runtime-replay-ineligible")
                        )
                        continue
                    mapped_bins = {str(item) for item in (replay.get("observed_bins") or [])}
                    replay_bins.update(mapped_bins)
                    unexpected_mapper_bins.update(mapped_bins - universe_bins)
            if replay_bins != event_bins:
                replay_ok = False
                replay_reasons.append("replay-bin-mismatch")

        if not replay_ok:
            replay_failures.append(
                {
                    "case_id": case_id,
                    "qualification_reason": qualification_reason,
                    "reasons": replay_reasons,
                    "runtime_record_count": len(runtime_records),
                    "bapc_bins": sorted(event_bins),
                    "replayed_bins": sorted(replay_bins),
                }
            )

        per_case.append(
            {
                "case_id": case_id,
                "artifact_valid": artifact_valid,
                "measurement_valid": measurement_valid,
                "bapc_eligible": bool(event.get("bapc_eligible")),
                "qualification_reason": qualification_reason,
                "runtime_record_count": len(runtime_records),
                "covered_bin_count": len(event_bins),
                "replay_ok": replay_ok,
            }
        )

    measurement_valid_campaign = (
        completed_cases == 0
        or (
            eligible_bapc_cases > 0
            and not replay_failures
            and not out_of_contract_bins
            and not unexpected_mapper_bins
        )
    )
    report = {
        "schema_version": "cascade-runtime-validation-v1",
        "campaign_dir": str(campaign_dir),
        "bapc_core_version": bapc_core_version,
        "completed_cases": completed_cases,
        "artifact_valid": artifact_valid_cases == completed_cases,
        "artifact_valid_cases": artifact_valid_cases,
        "measurement_valid": measurement_valid_campaign,
        "measurement_valid_cases": measurement_valid_cases,
        "runtime_record_cases": runtime_record_cases,
        "runtime_record_rate": (
            runtime_record_cases / completed_cases if completed_cases > 0 else None
        ),
        "eligible_bapc_cases": eligible_bapc_cases,
        "eligible_bapc_rate": (
            eligible_bapc_cases / completed_cases if completed_cases > 0 else None
        ),
        "covered_bin_count": len(covered_bins) if eligible_bapc_cases > 0 else None,
        "coverage_denominator": int(universe_payload.get("bin_count") or 0) or None,
        "covered_bins": sorted(covered_bins),
        "family_coverage": _family_counts(covered_bins),
        "qualification_reason_counts": dict(sorted(qualification_counts.items())),
        "out_of_contract_bins": sorted(out_of_contract_bins),
        "unexpected_mapper_bins": sorted(unexpected_mapper_bins),
        "replay_failure_count": len(replay_failures),
        "replay_failures": replay_failures,
        "per_case": per_case,
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    report = validate_campaign(args.campaign_dir)
    report_path = args.report or (args.campaign_dir / "metrics" / "cascade_runtime_validation.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
