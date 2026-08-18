import json
import subprocess
import sys
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "scripts" / "evaluation" / "baseline_adapters"))
import riscv_dv
import riscv_dv_splice


class TestR5Stats(unittest.TestCase):
    def test_no_graft_stats_locked_ratio(self):
        rows = []
        for i in range(10):
            rows.append(
                {
                    "case_id": "rocket-clean_%03d" % i,
                    "completed": True,
                    "snapshot_present": True,
                    "graft_executed": None,
                    "programmed_entries": 3,
                    "programmed_patterns": [
                        ("tor", 1, 1, 1, 0),
                        ("na4", 0, 1, 0, 1),
                        ("tor", 0, 1, 1, 1),
                    ],
                    "off_patterns": [(0, 0, 0, 0)],
                    "locked_entries": 2,
                    "graft_evidence": None,
                }
            )
        stats = riscv_dv.build_pmp_programming_stats("rocket-clean", rows)
        self.assertEqual(stats["graft"], "none (SV-generator programs program PMP themselves)")
        self.assertEqual(stats["cases_with_snapshot"], 10)
        self.assertEqual(stats["avg_programmed_entries"], 3.0)
        self.assertEqual(stats["distinct_programmed_patterns"], 3)
        self.assertEqual(stats["locked_entries"], 20)
        self.assertAlmostEqual(stats["locked_ratio"], 2.0 / 3.0)
        self.assertEqual(stats["evidence_channels"]["readback_snapshot"], 10)
        self.assertEqual(stats["evidence_channels"]["graft_execution_trace"], 0)

    def test_r5_probe_provenance(self):
        spec = riscv_dv_splice.PROBE_VARIANTS["epilogue-load"]
        self.assertIn("SV-generator", spec["provenance"])
        self.assertIn("no protection semantics", spec["provenance"])


if __name__ == "__main__":
    unittest.main()
