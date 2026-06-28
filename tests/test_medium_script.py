import unittest
from pathlib import Path


class MediumSmokeScriptTest(unittest.TestCase):
    def test_medium_multidut_script_exists_and_uses_conservative_jobs(self):
        script = Path("scripts/run_medium_multidut_smoke.sh")
        self.assertTrue(script.exists())
        text = script.read_text(encoding="ascii")

        self.assertIn("probe-dut", text)
        self.assertIn("--coverage-mode pairwise", text)
        self.assertIn("--jobs 1", text)
        self.assertIn("rocket-clean", text)
        self.assertIn("boom-clean", text)
        self.assertIn("cva6-clean", text)
        self.assertIn("xiangshan-clean", text)


if __name__ == "__main__":
    unittest.main()
