import unittest
from unittest.mock import patch

from pmpfuzz.coverage_universe import (
    classify_observed_bins,
    freeze_coverage_universes,
    make_coverage_universe,
    validate_coverage_universe,
)


class CoverageUniverseTest(unittest.TestCase):
    def test_make_coverage_universe_sorts_and_hashes(self):
        universe = make_coverage_universe(
            coverage_mode="semantic",
            bin_ids=["b", "a", "b"],
            capability_fingerprint="cap-1",
            target="core-stateful",
            include_experimental=False,
            generator_seed=20260628,
            generation_rule_version="v1",
        )

        self.assertEqual(universe["bin_ids"], ["a", "b"])
        self.assertEqual(universe["bin_count"], 2)
        self.assertEqual(len(universe["bin_set_sha256"]), 64)
        self.assertEqual(len(universe["sha256"]), 64)
        validate_coverage_universe(universe)

    def test_bin_set_sha256_tracks_bin_ids_not_generator_seed(self):
        first = make_coverage_universe(
            coverage_mode="semantic",
            bin_ids=["bin:b", "bin:a"],
            capability_fingerprint="cap-1",
            target="core-stateful",
            include_experimental=False,
            generator_seed=1,
            generation_rule_version="v1",
        )
        second = make_coverage_universe(
            coverage_mode="semantic",
            bin_ids=["bin:a", "bin:b"],
            capability_fingerprint="cap-1",
            target="core-stateful",
            include_experimental=False,
            generator_seed=2,
            generation_rule_version="v1",
        )
        different = make_coverage_universe(
            coverage_mode="semantic",
            bin_ids=["bin:a", "bin:c"],
            capability_fingerprint="cap-1",
            target="core-stateful",
            include_experimental=False,
            generator_seed=2,
            generation_rule_version="v1",
        )

        self.assertEqual(first["bin_set_sha256"], second["bin_set_sha256"])
        self.assertNotEqual(first["sha256"], second["sha256"])
        self.assertNotEqual(first["bin_set_sha256"], different["bin_set_sha256"])

    def test_validate_rejects_hash_mismatch(self):
        universe = make_coverage_universe(
            coverage_mode="predicates",
            bin_ids=["pred:a"],
            capability_fingerprint="cap-1",
            target="core-stateful",
            include_experimental=False,
            generator_seed=20260628,
            generation_rule_version="v1",
        )
        universe["sha256"] = "0" * 64

        with self.assertRaises(ValueError):
            validate_coverage_universe(universe)

    def test_classify_observed_bins_reports_out_of_contract(self):
        universe = make_coverage_universe(
            coverage_mode="pairwise",
            bin_ids=["combo2:a", "combo2:b"],
            capability_fingerprint="cap-1",
            target="core-stateful",
            include_experimental=False,
            generator_seed=20260628,
            generation_rule_version="v1",
        )

        classified = classify_observed_bins(universe, ["combo2:b", "combo2:x"])

        self.assertEqual(classified["covered"], ["combo2:b"])
        self.assertEqual(classified["out_of_contract"], ["combo2:x"])

    @patch("pmpfuzz.coverage_universe.compute_coverage_targets")
    def test_freeze_coverage_universes_uses_frozen_target_sets(self, compute_targets):
        compute_targets.return_value = {
            "capability_fingerprint": "cap-2",
            "semantic": {"target_bins": {"s:1", "s:2"}, "total": 2},
            "pairwise": {"target_bins": {"combo2:1"}, "total": 1},
            "security_triples": {"target_bins": {"combo3:1"}, "total": 1},
            "predicates": {"target_bins": {"pred:1"}, "total": 1},
        }

        bundle = freeze_coverage_universes(
            target="core-stateful",
            capability={"available": True},
            include_experimental=False,
            seed=20260628,
        )

        self.assertEqual(set(bundle), {"semantic", "pairwise", "security_triples", "predicates"})
        self.assertEqual(bundle["semantic"]["bin_ids"], ["s:1", "s:2"])
        self.assertEqual(bundle["pairwise"]["bin_ids"], ["combo2:1"])
        self.assertEqual(bundle["security_triples"]["bin_ids"], ["combo3:1"])
        self.assertEqual(bundle["predicates"]["bin_ids"], ["pred:1"])


if __name__ == "__main__":
    unittest.main()
