from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
YAML_PATH = ROOT / "configs" / "evaluation" / "compact_experiment_matrix.yaml"

FROZEN_FORMAL = list(range(101, 111))
FROZEN_PILOT = [1, 2, 3]
FROZEN_MANDATORY = ["rocket-clean", "boom-clean", "xiangshan-clean"]
FROZEN_EXCLUDABLE = ["cva6-clean"]
FROZEN_E1_VARIANTS = ["random", "bb", "bb-wb"]
FROZEN_E2_METHODS = ["pmpfuzz-bb-wb", "cascade"]

def _yaml():
    with YAML_PATH.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


class TestYamlFormalSeeds(unittest.TestCase):
    def test_formal_seeds_are_101_to_110(self):
        self.assertEqual(_yaml()["common"]["formal_seeds"], FROZEN_FORMAL)

    def test_formal_seeds_length_is_10(self):
        self.assertEqual(len(_yaml()["common"]["formal_seeds"]), 10)

    def test_pilot_seeds_are_1_2_3(self):
        self.assertEqual(_yaml()["common"]["pilot_seeds"], FROZEN_PILOT)

    def test_pilot_formal_seeds_no_overlap(self):
        cfg = _yaml()
        s = set(cfg["common"]["pilot_seeds"]) & set(cfg["common"]["formal_seeds"])
        self.assertEqual(len(s), 0, f"Overlap: {s}")


class TestYamlDutClassification(unittest.TestCase):
    def test_mandatory_duts(self):
        self.assertEqual(_yaml()["common"]["mandatory_duts"], FROZEN_MANDATORY)

    def test_excludable_duts(self):
        self.assertEqual(_yaml()["common"]["conditionally_excludable_duts"],
                         FROZEN_EXCLUDABLE)

    def test_all_four_duts(self):
        self.assertEqual(set(_yaml()["common"]["duts"]),
                         {"rocket-clean", "boom-clean", "xiangshan-clean", "cva6-clean"})

    def test_xiangshan_mandatory(self):
        cfg = _yaml()
        self.assertIn("xiangshan-clean", cfg["common"]["mandatory_duts"])
        self.assertNotIn("xiangshan-clean", cfg["common"]["conditionally_excludable_duts"])


class TestYamlExperiments(unittest.TestCase):
    def test_e1_variants(self):
        e1 = _yaml()["experiments"]["E1-COVERAGE-FEEDBACK"]
        self.assertTrue(e1["enabled"])
        self.assertEqual(e1["variants"], FROZEN_E1_VARIANTS)

    def test_e2_methods(self):
        e2 = _yaml()["experiments"]["E2-BASELINE"]
        self.assertTrue(e2["enabled"])
        self.assertEqual(e2["methods"], FROZEN_E2_METHODS)

    def test_e3_disabled_designed_only(self):
        e3 = _yaml()["experiments"]["E3-PORTABILITY"]
        self.assertFalse(e3["enabled"])
        self.assertEqual(e3["status"], "DESIGNED_ONLY")
        self.assertTrue(e3.get("run_requires_new_user_authorization", False))


class TestYamlCampaignCounts(unittest.TestCase):
    def test_e1_mandatory_count_90(self):
        cfg = _yaml()
        e1 = cfg["experiments"]["E1-COVERAGE-FEEDBACK"]
        m = [d for d in e1["duts"] if d in set(cfg["common"]["mandatory_duts"])]
        self.assertEqual(len(m) * len(e1["variants"]) * 10, 90)

    def test_e1_with_cva6_count_120(self):
        cfg = _yaml()
        e1 = cfg["experiments"]["E1-COVERAGE-FEEDBACK"]
        self.assertEqual(len(e1["duts"]) * len(e1["variants"]) * 10, 120)

    def test_e2_mandatory_count_60(self):
        cfg = _yaml()
        e2 = cfg["experiments"]["E2-BASELINE"]
        m = [d for d in e2["duts"] if d in set(cfg["common"]["mandatory_duts"])]
        self.assertEqual(len(m) * len(e2["methods"]) * 10, 60)

    def test_e2_with_cva6_count_80(self):
        cfg = _yaml()
        e2 = cfg["experiments"]["E2-BASELINE"]
        self.assertEqual(len(e2["duts"]) * len(e2["methods"]) * 10, 80)


class TestYamlGeneral(unittest.TestCase):
    def test_schema_version(self):
        self.assertEqual(_yaml()["schema_version"], "2.0")

    def test_coverage_basis(self):
        self.assertEqual(_yaml()["common"]["coverage_basis"], "execution-qualified")

    def test_primary_mode_semantic(self):
        self.assertEqual(_yaml()["common"]["primary_coverage_mode"], "semantic")

    def test_analyze_nonpass_false(self):
        self.assertFalse(_yaml()["common"]["analyze_nonpass"])

    def test_forbid_paper_modification(self):
        self.assertTrue(_yaml()["validation"]["forbid_paper_modification"])


if __name__ == "__main__":
    unittest.main()
