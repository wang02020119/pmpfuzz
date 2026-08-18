#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from pmpfuzz.c910_nonpmp_dynamic import write_dynamic_run
from pmpfuzz.c910_m2_scheduling import aggregate_shared56
from pmpfuzz.v4_nonpmp_projection import classify_scenario


def classify_run_shared56(run_dir: Path) -> dict:
    run_dir = Path(run_dir)
    classifications = []
    for case_path in sorted((run_dir / "cases").glob("*/case.json")):
        case = json.loads(case_path.read_text(encoding="utf-8"))
        result_path = run_dir / "results" / str(case["name"]) / "result.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        classifications.append(classify_scenario(case, result))
    shared56 = aggregate_shared56(classifications)
    shared56["classifications"] = classifications
    (run_dir / "coverage" / "shared56.json").write_text(
        json.dumps(shared56, indent=2), encoding="utf-8"
    )
    return shared56


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--uart-log", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    write_dynamic_run(
        uart_log=args.uart_log,
        manifest_path=args.manifest,
        out_dir=args.out_dir,
    )
    shared56 = classify_run_shared56(args.out_dir)
    print(
        f"shared-56: covered={shared56['covered_count']}/56 "
        f"mapped={shared56['mapped']} unsupported={shared56['unsupported']} "
        f"violations={shared56['known_violations']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
