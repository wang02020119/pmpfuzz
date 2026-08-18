from __future__ import annotations

import argparse
import json
from hashlib import sha256
from pathlib import Path
from typing import Any

from .mutate_observations import (
    build_counterfactuals_from_reference_cases,
    select_counterfactual_rows,
)


def freeze_counterfactual_holdout(
    *,
    cases_jsonl: Path,
    labels_jsonl: Path,
    class_targets: dict[str, int],
    out_jsonl: Path,
    manifest_json: Path,
) -> dict[str, Any]:
    cases = _load_jsonl(cases_jsonl)
    labels = _load_jsonl(labels_jsonl)
    all_rows = build_counterfactuals_from_reference_cases(cases=cases, labels=labels, require_applicable=True)
    selected_rows = select_counterfactual_rows(all_rows, target_counts=class_targets)

    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with out_jsonl.open("w", encoding="utf-8", newline="") as handle:
        for row in selected_rows:
            handle.write(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n")

    available_counts = _counts_by_failure_class(all_rows)
    selected_counts = _counts_by_failure_class(selected_rows)
    payload = {
        "schema_version": 1,
        "cases_jsonl": str(cases_jsonl),
        "labels_jsonl": str(labels_jsonl),
        "total_cases": len(cases),
        "total_labels": len(labels),
        "target_counts": dict(sorted((str(key), int(value)) for key, value in class_targets.items())),
        "available_counts": dict(sorted(available_counts.items())),
        "selected_counts": dict(sorted(selected_counts.items())),
        "selected_total": len(selected_rows),
        "sha256": sha256(out_jsonl.read_bytes()).hexdigest(),
    }
    manifest_json.parent.mkdir(parents=True, exist_ok=True)
    manifest_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze a deterministic Section 7.6 counterfactual holdout")
    parser.add_argument("--cases-jsonl", type=Path, required=True)
    parser.add_argument("--labels-jsonl", type=Path, required=True)
    parser.add_argument("--class-targets-json", type=Path, required=True)
    parser.add_argument("--out-jsonl", type=Path, required=True)
    parser.add_argument("--manifest-json", type=Path, required=True)
    args = parser.parse_args(argv)

    payload = json.loads(args.class_targets_json.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("class targets JSON must be an object")
    targets = {str(key): int(value) for key, value in payload.items()}
    summary = freeze_counterfactual_holdout(
        cases_jsonl=args.cases_jsonl,
        labels_jsonl=args.labels_jsonl,
        class_targets=targets,
        out_jsonl=args.out_jsonl,
        manifest_json=args.manifest_json,
    )
    print(
        f"counterfactuals={summary['selected_total']} "
        f"sha256={summary['sha256']} out={args.out_jsonl}"
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
            raise ValueError(f"expected object JSONL row in {path}")
        rows.append(payload)
    return rows


def _counts_by_failure_class(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        failure_class = str(((row.get("expected_judgment") or {}).get("failure_class")) or "")
        counts[failure_class] = counts.get(failure_class, 0) + 1
    return counts


if __name__ == "__main__":
    raise SystemExit(main())
