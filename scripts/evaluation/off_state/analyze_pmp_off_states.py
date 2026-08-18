from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from pmpfuzz.off_state import (
    analyze_characterization_artifact,
    analyze_characterization_records,
    load_records,
    write_json,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze PMP OFF-state characterization artifacts")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def _load_analysis_payload(path: Path) -> dict | list:
    if path.suffix == ".jsonl":
        return load_records(path)
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    payload = _load_analysis_payload(args.input)
    if isinstance(payload, dict):
        report = analyze_characterization_artifact(payload)
    elif isinstance(payload, list):
        report = analyze_characterization_artifact(
            {
                "schema_version": 1,
                "artifact_kind": "pmp-off-state-characterization-v1",
                "record_schema_version": 1,
                "reset_count": 1,
                "records": [dict(item) for item in payload],
            }
        )
    else:
        report = analyze_characterization_artifact(
            {
                "schema_version": 1,
                "artifact_kind": "pmp-off-state-characterization-v1",
                "record_schema_version": 1,
                "reset_count": 1,
                "records": [dict(item) for item in payload],
            }
        )
    write_json(args.output, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
