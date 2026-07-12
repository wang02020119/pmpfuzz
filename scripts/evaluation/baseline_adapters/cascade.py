#!/usr/bin/env python3
"""Adapter: run Cascade as a PMPFuzz-compatible baseline.

Wraps the existing Docker-hosted Cascade artifact to produce unified
campaign data (normalized/campaigns.csv, coverage_timeseries.csv).

Status: STUB — to be completed after Cascade audit and verification.
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cascade baseline adapter (STUB)")
    parser.add_argument("--out", type=str, required=True)
    args = parser.parse_args(argv)
    print("Cascade baseline adapter: not yet implemented", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
