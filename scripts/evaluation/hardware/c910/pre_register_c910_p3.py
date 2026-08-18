#!/usr/bin/env python3
"""Pre-register the C910 M-3 multi-run campaign (expanded catalog).

Six independent runs: guided x2 seeds and random x4 seeds, each 4 rounds of 16
cases over the expanded mapped-only shared-56 pool.  No board is touched; the
manifests are executed by the board adapter.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from pmpfuzz.c910_m2_scheduling import M2_BUDGET_PER_ROUND, build_m2_round
from pmpfuzz.c910_nonpmp_dynamic import catalog_cases

GUIDED_SEEDS = (4, 5)
RANDOM_SEEDS = (104, 105, 106, 107)
ROUNDS_PER_RUN = 4
BUDGET = M2_BUDGET_PER_ROUND
DEFAULT_OUT = Path(os.environ.get("PMPFUZZ_ARTIFACT_ROOT", "artifacts")) / "hw-v2-m2" / "c910-p3"


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    catalog = catalog_cases()
    name_to_hash = {c["name"]: str(c.get("scenario_hash") or c.get("name") or "") for c in catalog}
    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)

    registration = {
        "protocol": "hw-v2-m3",
        "universe": "v4-nonpmp-56",
        "catalog_case_count": len(catalog),
        "budget_per_round": BUDGET,
        "rounds_per_run": ROUNDS_PER_RUN,
        "runs": {
            "guided": {"seeds": list(GUIDED_SEEDS), "count": len(GUIDED_SEEDS)},
            "random": {"seeds": list(RANDOM_SEEDS), "count": len(RANDOM_SEEDS)},
        },
        "execution_order": "guided-then-random",
    }

    catalog_index = [{"name": c["name"], "scenario_hash": name_to_hash[c["name"]]} for c in catalog]
    (out / "catalog-index.json").write_text(json.dumps(catalog_index, indent=2), encoding="utf-8")

    for mode, seeds in (("guided", GUIDED_SEEDS), ("random", RANDOM_SEEDS)):
        for seed in seeds:
            covered_bins: set[str] = set()
            used_fingerprints: set[str] = set()
            run_id = f"run-{seed:04d}"
            for round_index in range(ROUNDS_PER_RUN):
                built = build_m2_round(
                    catalog,
                    mode=mode,
                    round_index=round_index,
                    campaign_id=f"hw-v2-m3-c910-{mode}-{run_id}",
                    covered_bins=covered_bins,
                    used_fingerprints=used_fingerprints,
                    seed=seed,
                    budget=BUDGET,
                )
                round_dir = out / mode / run_id / f"round-{round_index:04d}"
                round_dir.mkdir(parents=True, exist_ok=True)
                (round_dir / "manifest.json").write_text(
                    json.dumps(built["manifest"], indent=2), encoding="utf-8"
                )
                (round_dir / "provenance.json").write_text(
                    json.dumps(built["provenance"], indent=2), encoding="utf-8"
                )
                for cname, detail in built["provenance"]["selection_details"].items():
                    used_fingerprints.add(name_to_hash.get(cname, cname))
                    covered_bins.update(detail.get("predicted_bins") or [])
                print(
                    f"[{mode}] {run_id} round {round_index}: "
                    f"selected={built['provenance']['selected_count']} "
                    f"simulated_cumulative_shared56={len(covered_bins)}"
                )
            print(f"[{mode}] {run_id} FINAL cumulative={len(covered_bins)}/56")

    (out / "registration.json").write_text(
        json.dumps(registration, indent=2), encoding="utf-8"
    )
    print("wrote pre-registration to", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
