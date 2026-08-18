#!/usr/bin/env python3
"""Pre-register the C910 M-2 campaign (guided vs random replay).

Generates, for both conditions, three frozen round manifests over the frozen
256-case catalog, with full provenance (seed, candidate pool, covered-bin
prediction input, per-case predicted bins, selection rationale).  No board is
touched; the manifests are executed by the board adapter when hardware is
available.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from pmpfuzz.c910_m2_scheduling import (
    M2_BUDGET_PER_ROUND,
    M2_NUM_ROUNDS,
    build_m2_round,
)
from pmpfuzz.c910_nonpmp_dynamic import catalog_cases

CAMPAIGN_GUIDED = "hw-v2-m2-c910-guided"
CAMPAIGN_RANDOM = "hw-v2-m2-c910-random"
SEEDS_GUIDED = (4, 5, 6)
SEEDS_RANDOM = (104, 105, 106)  # distinct seeds, pre-registered
BUDGET = M2_BUDGET_PER_ROUND
DEFAULT_OUT = Path(os.environ.get("PMPFUZZ_ARTIFACT_ROOT", "artifacts")) / "hw-v2-m2" / "c910"


def _fingerprint(case: dict) -> str:
    return str(case.get("scenario_hash") or case.get("name") or "")


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    catalog = catalog_cases()
    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    catalog_index = [
        {"name": c["name"], "scenario_hash": _fingerprint(c), "profile": c.get("profile")}
        for c in catalog
    ]
    (out / "catalog-index.json").write_text(
        json.dumps(catalog_index, ensure_ascii=True, indent=2), encoding="utf-8"
    )

    registration = {
        "protocol": "hw-v2-m2",
        "campaigns": {
            "guided": {
                "campaign_id": CAMPAIGN_GUIDED,
                "selection": "predicted-coverage-guided (BAPC shared-56 novelty)",
                "seeds": list(SEEDS_GUIDED),
                "budget_per_round": BUDGET,
                "rounds": M2_NUM_ROUNDS,
                "universe": "v4-nonpmp-56",
                "execution_order": "guided-first-then-random",
            },
            "random": {
                "campaign_id": CAMPAIGN_RANDOM,
                "selection": "seeded uniform from mapped shared-56 candidate pool",
                "seeds": list(SEEDS_RANDOM),
                "budget_per_round": BUDGET,
                "rounds": M2_NUM_ROUNDS,
                "universe": "v4-nonpmp-56",
            },
        },
    }

    for mode, campaign_id, seeds in (
        ("guided", CAMPAIGN_GUIDED, SEEDS_GUIDED),
        ("random", CAMPAIGN_RANDOM, SEEDS_RANDOM),
    ):
        covered_bins: set[str] = set()
        used_fingerprints: set[str] = set()
        for round_index, seed in enumerate(seeds):
            built = build_m2_round(
                catalog,
                mode=mode,
                round_index=round_index,
                campaign_id=campaign_id,
                covered_bins=covered_bins,
                used_fingerprints=used_fingerprints,
                seed=seed,
                budget=BUDGET,
            )
            round_dir = out / mode / f"round-{round_index:04d}"
            round_dir.mkdir(parents=True, exist_ok=True)
            (round_dir / "manifest.json").write_text(
                json.dumps(built["manifest"], ensure_ascii=True, indent=2), encoding="utf-8"
            )
            (round_dir / "provenance.json").write_text(
                json.dumps(built["provenance"], ensure_ascii=True, indent=2), encoding="utf-8"
            )
            # Simulate coverage feedback from the selected cases' predicted bins
            # for the purposes of pre-registration (the board run replaces this
            # with real observations).  Dedup by scenario fingerprint.
            name_to_hash = {c["name"]: str(c.get("scenario_hash") or c.get("name") or "") for c in catalog}
            for name, detail in built["provenance"]["selection_details"].items():
                used_fingerprints.add(name_to_hash.get(name, name))
                covered_bins.update(detail.get("predicted_bins") or [])
            print(
                f"[{mode}] round {round_index}: selected={len(built['provenance']['selection_details'])} "
                f"estimated_new_bins={built['provenance']['estimated_new_bins_total']} "
                f"simulated_cumulative_shared56={len(covered_bins)}"
            )

    (out / "registration.json").write_text(
        json.dumps(registration, ensure_ascii=True, indent=2), encoding="utf-8"
    )
    print("wrote pre-registration to", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
