import unittest
from pathlib import Path


class MediumSmokeScriptTest(unittest.TestCase):
    def test_medium_multidut_script_exists_and_uses_conservative_jobs(self):
        script = Path("scripts/smoke/run_medium_multidut_smoke.sh")
        self.assertTrue(script.exists())
        text = script.read_text(encoding="ascii")

        self.assertIn("probe-dut", text)
        self.assertIn("--coverage-mode pairwise", text)
        self.assertIn("--jobs 1", text)
        self.assertIn("rocket-clean", text)
        self.assertIn("boom-clean", text)
        self.assertIn("cva6-clean", text)
        self.assertIn("xiangshan-clean", text)

    def test_medium_multidut_script_has_three_hour_outer_budget_and_per_dut_budgets(self):
        script = Path("scripts/smoke/run_medium_multidut_smoke.sh")
        text = script.read_text(encoding="ascii")

        self.assertIn('TOTAL_BUDGET="${TOTAL_BUDGET:-3h}"', text)
        self.assertIn("timeout \"$TOTAL_BUDGET\" bash -c 'run_all_duts'", text)
        self.assertIn('run_one_dut spike 256 30 100000 "5m"', text)
        self.assertIn('run_one_dut rocket-clean 128 220 100000 "25m"', text)
        self.assertIn('run_one_dut boom-clean 128 260 100000 "30m"', text)
        self.assertIn('run_one_dut cva6-clean 96 260 100000 "30m"', text)
        self.assertIn('run_one_dut xiangshan-clean 64 160 200000 "45m"', text)
        self.assertIn('--time-budget "$dut_budget"', text)

    def test_smepmp_hardening_script_is_capability_gated_and_skips_cva6_by_default(self):
        script = Path("scripts/smoke/run_smepmp_hardening_smoke.sh")
        self.assertTrue(script.exists())
        text = script.read_text(encoding="ascii")

        self.assertIn("--probe-smepmp", text)
        self.assertIn("spike,rocket-clean,boom-clean,xiangshan-clean", text)
        self.assertIn("smepmp-mmwp-mmode-default-deny", text)
        self.assertNotIn("cva6-clean", text)


if __name__ == "__main__":
    unittest.main()
