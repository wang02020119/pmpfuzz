from __future__ import annotations

import unittest
import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from pmpfuzz.c910_m2_scheduling import build_m2_round, predict_shared56_bins, select_random
from pmpfuzz.c910_nonpmp_dynamic import catalog_cases


def _fingerprint(case: dict) -> str:
    return str(case.get("scenario_hash") or case.get("name") or "")


def _simulate_rounds(*, catalog: list[dict], mode: str, seeds: tuple[int, ...]) -> list[int]:
    covered_bins: set[str] = set()
    used_fingerprints: set[str] = set()
    by_name = {case["name"]: case for case in catalog}
    trajectory: list[int] = []
    for round_index, seed in enumerate(seeds):
        built = build_m2_round(
            catalog,
            mode=mode,
            round_index=round_index,
            campaign_id=f"test-{mode}",
            covered_bins=covered_bins,
            used_fingerprints=used_fingerprints,
            seed=seed,
        )
        for name, detail in built["provenance"]["selection_details"].items():
            used_fingerprints.add(_fingerprint(by_name[name]))
            covered_bins.update(detail.get("predicted_bins") or [])
        trajectory.append(len(covered_bins))
    return trajectory


class C910M2SchedulingTest(unittest.TestCase):
    def test_random_selection_excludes_unmapped_candidates(self):
        catalog = catalog_cases()
        by_name = {case["name"]: case for case in catalog}
        used_fingerprints: set[str] = set()
        selected_names: list[str] = []

        for seed in (104, 105, 106):
            selected = select_random(
                catalog,
                used_fingerprints=used_fingerprints,
                seed=seed,
                budget=16,
            )
            for name, _ in selected:
                selected_names.append(name)
                used_fingerprints.add(_fingerprint(by_name[name]))

        self.assertTrue(selected_names)
        self.assertTrue(
            all(predict_shared56_bins(by_name[name])["status"] == "mapped" for name in selected_names)
        )

    def test_preregistered_prediction_trajectory_uses_fair_mapped_pool(self):
        catalog = catalog_cases()

        self.assertEqual(_simulate_rounds(catalog=catalog, mode="guided", seeds=(4, 5, 6)), [32, 42, 42])
        self.assertEqual(_simulate_rounds(catalog=catalog, mode="random", seeds=(104, 105, 106)), [13, 28, 32])

    def test_random_provenance_reports_predicted_incremental_bins(self):
        built = build_m2_round(
            catalog_cases(),
            mode="random",
            round_index=0,
            campaign_id="test-random",
            covered_bins=set(),
            used_fingerprints=set(),
            seed=104,
        )

        self.assertEqual(built["provenance"]["estimated_new_bins_total"], 13)
        self.assertTrue(
            any(
                detail.get("estimated_new_bins", 0) > 0
                for detail in built["provenance"]["selection_details"].values()
            )
        )

    def test_pre_registration_declares_guided_first_execution_order(self):
        repo = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as tmp:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(repo / "scripts" / "evaluation" / "pre_register_c910_m2.py"),
                    "--out-dir",
                    tmp,
                ],
                cwd=repo,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            registration = json.loads((Path(tmp) / "registration.json").read_text(encoding="utf-8"))

        self.assertEqual(
            registration["campaigns"]["guided"]["execution_order"],
            "guided-first-then-random",
        )


if __name__ == "__main__":
    unittest.main()
