import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "scripts" / "evaluation" / "baseline_adapters"))
import riscv_dv


def _file_sha256(p):
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def _counts():
    return {
        "completed": 0,
        "eligible": 0,
        "eligible_bapc": 0,
        "timeouts": 0,
        "inconclusive": 0,
        "infra_failures": 0,
        "bapc_covered": 0,
    }


class TestB1MutantOverride(unittest.TestCase):
    def test_campaign_metadata_records_override_provenance(self):
        with tempfile.TemporaryDirectory() as td:
            fake_bin = Path(td) / "simulator-chipyard.harness-CVA6Config-M02"
            fake_bin.write_bytes(b"fake-mutant-binary")
            meta = riscv_dv.campaign_metadata(
                dut="cva6-clean",
                seed=7,
                experiment_id="riscv-dv-baseline-b1",
                campaign_id="b1-cva6-M02",
                run_class="baseline-pilot",
                budget_class="fixed-input-budget",
                generator_variant="sv",
                start_utc="2026-08-15T00:00:00Z",
                elapsed_wall_seconds=1.0,
                per_case_timeout_seconds=60,
                jobs=1,
                simlen=50000,
                rdv_commit="b7a0b4b",
                pyvsc_version="0.9.5",
                universe={"bin_count": 144},
                counts=_counts(),
                stop_reason="budget-exhausted",
                dut_binary=fake_bin,
                mutant_id="M02",
            )
            self.assertEqual(meta["mutant_id"], "M02")
            self.assertTrue(meta["dut_binary_is_override"])
            self.assertEqual(meta["dut_binary_sha256"], _file_sha256(fake_bin))
            self.assertEqual(meta["dut_binary_path"], str(fake_bin))

    def test_campaign_metadata_default_is_not_override(self):
        meta = riscv_dv.campaign_metadata(
            dut="cva6-clean",
            seed=7,
            experiment_id="riscv-dv-baseline",
            campaign_id="x",
            run_class="baseline-pilot",
            budget_class="fixed-input-budget",
            generator_variant="sv",
            start_utc="2026-08-15T00:00:00Z",
            elapsed_wall_seconds=1.0,
            per_case_timeout_seconds=60,
            jobs=1,
            simlen=50000,
            rdv_commit="b7a0b4b",
            pyvsc_version="0.9.5",
            universe={"bin_count": 144},
            counts=_counts(),
            stop_reason="budget-exhausted",
        )
        self.assertFalse(meta["dut_binary_is_override"])
        self.assertIsNone(meta["mutant_id"])


if __name__ == "__main__":
    unittest.main()
