import unittest
from pathlib import Path

from pmpfuzz.hpm import ROCKET_CLEAN_HPM_MANIFEST
from pmpfuzz.schema import result_to_dict, scenario_to_case_dict
from pmpfuzz.scenario import ScenarioGenerator


class HpmRunResultTest(unittest.TestCase):
    def test_result_schema_preserves_raw_and_derived_hpm_fields(self):
        scenario = ScenarioGenerator(seed=13, include_smepmp=False, profile="pmp-boundary").generate_batch(1)[0]
        case = scenario_to_case_dict(scenario, seed=13, index=0)
        result = result_to_dict(
            case=case,
            dut="rocket-clean",
            status="pass",
            elapsed_seconds=0.25,
            returncode=0,
            log=Path("/tmp/case.log"),
            reason="ok",
            hpm_manifest=ROCKET_CLEAN_HPM_MANIFEST,
            hpm_snapshot_before={"minstret": 1, "mcycle": 2, "c3": 3, "c4": 4, "c5": 5, "c6": 6},
            hpm_snapshot_after={"minstret": 11, "mcycle": 22, "c3": 13, "c4": 14, "c5": 15, "c6": 16},
            hpm_coverage={
                "eligible": True,
                "qualification_reason": "eligible",
                "observed_bins": ["event=exception|bucket=0-0.1"],
                "event_metrics": {
                    "exception": {
                        "counter": "c3",
                        "before": 3,
                        "after": 13,
                        "delta": 10,
                        "rate_per_kilo_instruction": 1000.0,
                        "bucket": "10-100",
                    }
                },
            },
        )

        self.assertEqual(result["hpm_manifest"]["dut"], "rocket-clean")
        self.assertEqual(result["hpm_snapshot_before"]["c4"], 4)
        self.assertEqual(result["hpm_snapshot_after"]["c6"], 16)
        self.assertEqual(result["hpm_coverage"]["observed_bins"], ["event=exception|bucket=0-0.1"])


if __name__ == "__main__":
    unittest.main()
