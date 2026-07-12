#!/usr/bin/env python3
"""Generate time—coverage plots from timeline CSV data.

Produces:
- fig_coverage_vs_time_internal.pdf / .png
- fig_coverage_vs_cases_internal.pdf / .png
- figure_metadata.json
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


def plot_from_csv(csv_path: Path, out_dir: Path, prefix: str = "fig") -> dict[str, Path]:
    """Read *csv_path* (coverage_timeseries.csv) and generate plots.

    Returns a dict mapping plot names to output paths.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    outputs: dict[str, Path] = {}

    rows = _read_csv(csv_path)
    if not rows:
        print(f"WARNING: no data in {csv_path}", file=sys.stderr)
        return outputs

    # Group by (variant, coverage_mode, seed)
    series: dict[tuple[str, str, int], list[dict]] = defaultdict(list)
    for row in rows:
        key = (row.get("variant", ""), row.get("coverage_mode", ""), int(row.get("seed", 0) or 0))
        series[key].append(row)

    for key in series:
        series[key].sort(key=lambda r: (r.get("elapsed_wall_seconds", 0) or 0))

    # Check if matplotlib is available
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        HAS_MPL = True
    except ImportError:
        HAS_MPL = False
        print("WARNING: matplotlib not available — skipping plot generation", file=sys.stderr)
        # Write empty placeholder
        _write_text(out_dir / "figure_metadata.json", json.dumps({
            "schema_version": "1.0",
            "error": "matplotlib not installed",
        }, indent=2))
        return outputs

    # Color-blind-friendly palette
    COLORS = {
        "random": "#E69F00",
        "guided": "#56B4E9",
        "bb": "#009E73",
        "bb-wb": "#F0E442",
    }

    # --- Coverage mode labels ---
    MODE_LABELS = {
        "semantic": "Semantic coverage",
        "pairwise": "Pairwise coverage",
        "security-triples": "Security-triple coverage",
        "predicates": "Protection-predicate coverage",
    }

    coverage_modes = ["semantic", "pairwise", "security-triples", "predicates"]

    # 1. Coverage vs wall-clock time (2x2 subplot)
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    axes = axes.flatten()

    for ax, cmode in zip(axes, coverage_modes):
        ax.set_title(MODE_LABELS.get(cmode, cmode))
        ax.set_xlabel("Wall-clock time (hours)")
        ax.set_ylabel("Execution-qualified coverage")
        ax.set_ylim(0, 1.05)
        ax.grid(True, alpha=0.3)

        for (variant, cm, seed), srows in sorted(series.items()):
            if cm != cmode:
                continue
            color = COLORS.get(variant, "#333333")
            times = [(r.get("elapsed_wall_seconds", 0) or 0) / 3600.0 for r in srows]
            rates = [r.get("coverage_rate") or 0 for r in srows]
            if times and rates:
                ax.step(times, rates, where="post", color=color, alpha=0.4, linewidth=0.8)

        # Add legend with unique variants
        handles = []
        seen_variants = set()
        for (variant, cm, seed), srows in sorted(series.items()):
            if cm == cmode and variant not in seen_variants:
                seen_variants.add(variant)
                color = COLORS.get(variant, "#333333")
                from matplotlib.lines import Line2D
                handles.append(Line2D([0], [0], color=color, linewidth=2, label=variant))
        if handles:
            ax.legend(handles=handles, fontsize=8)

    plt.tight_layout()

    pdf_path = out_dir / f"{prefix}_coverage_vs_time_internal.pdf"
    png_path = out_dir / f"{prefix}_coverage_vs_time_internal.png"
    fig.savefig(pdf_path, dpi=300, bbox_inches="tight")
    fig.savefig(png_path, dpi=300, bbox_inches="tight")
    plt.close(fig)

    outputs["coverage_vs_time"] = pdf_path
    print(f"Plot: {pdf_path}")
    print(f"Plot: {png_path}")

    # 2. Coverage vs completed cases (2x2 subplot)
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    axes = axes.flatten()

    for ax, cmode in zip(axes, coverage_modes):
        ax.set_title(MODE_LABELS.get(cmode, cmode))
        ax.set_xlabel("Completed cases")
        ax.set_ylabel("Execution-qualified coverage")
        ax.set_ylim(0, 1.05)
        ax.grid(True, alpha=0.3)

        for (variant, cm, seed), srows in sorted(series.items()):
            if cm != cmode:
                continue
            color = COLORS.get(variant, "#333333")
            cases = [r.get("completed_cases", 0) for r in srows]
            rates = [r.get("coverage_rate") or 0 for r in srows]
            if cases and rates:
                ax.step(cases, rates, where="post", color=color, alpha=0.4, linewidth=0.8)

        handles = []
        seen_variants = set()
        for (variant, cm, seed), srows in sorted(series.items()):
            if cm == cmode and variant not in seen_variants:
                seen_variants.add(variant)
                color = COLORS.get(variant, "#333333")
                from matplotlib.lines import Line2D
                handles.append(Line2D([0], [0], color=color, linewidth=2, label=variant))
        if handles:
            ax.legend(handles=handles, fontsize=8)

    plt.tight_layout()

    pdf_path = out_dir / f"{prefix}_coverage_vs_cases_internal.pdf"
    png_path = out_dir / f"{prefix}_coverage_vs_cases_internal.png"
    fig.savefig(pdf_path, dpi=300, bbox_inches="tight")
    fig.savefig(png_path, dpi=300, bbox_inches="tight")
    plt.close(fig)

    outputs["coverage_vs_cases"] = pdf_path
    print(f"Plot: {pdf_path}")
    print(f"Plot: {png_path}")

    # 3. Figure metadata
    metadata = {
        "schema_version": "1.0",
        "plots": [
            {"name": "coverage_vs_time", "x": "elapsed_wall_hours", "y": "coverage_rate",
             "description": "Execution-qualified coverage vs wall-clock time"},
            {"name": "coverage_vs_cases", "x": "completed_cases", "y": "coverage_rate",
             "description": "Execution-qualified coverage vs completed cases"},
        ],
        "colormap": COLORS,
        "coverage_modes": MODE_LABELS,
        "source_csv": str(csv_path),
    }
    meta_path = out_dir / "figure_metadata.json"
    _write_text(meta_path, json.dumps(metadata, indent=2, ensure_ascii=True))
    outputs["metadata"] = meta_path

    return outputs


def _read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open("r", encoding="ascii", newline="") as fh:
        reader = csv.DictReader(fh)
        return list(reader)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="ascii")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate time—coverage plots")
    parser.add_argument("--input", type=Path, required=True, help="Path to coverage_timeseries.csv or campaign dir")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--prefix", default="fig")
    args = parser.parse_args(argv)

    input_path = args.input.resolve()

    # If pointing to a campaign dir, look for the CSV inside
    if input_path.is_dir():
        csv_path = input_path / "aggregate" / "coverage_timeseries.csv"
        if not csv_path.exists():
            # Fall back to individual timeline
            print(f"ERROR: no aggregate CSV found in {input_path}", file=sys.stderr)
            return 1
    else:
        csv_path = input_path

    outputs = plot_from_csv(csv_path, args.out.resolve(), args.prefix)
    if not outputs:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
