#!/usr/bin/env python3
"""Adapter: run riscv-dv as a PMPFuzz-compatible baseline.

Translates riscv-dv output into the unified campaign data contract
(normalized/campaigns.csv, coverage_timeseries.csv, security_event_timeseries.csv).

Status: STUB — to be completed after riscv-dv installation and verification.
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="riscv-dv baseline adapter (STUB)")
    parser.add_argument("--out", type=str, required=True)
    args = parser.parse_args(argv)
    print("riscv-dv baseline adapter: not yet implemented", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
