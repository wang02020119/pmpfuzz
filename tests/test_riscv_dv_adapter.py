"""Unit tests for the riscv-dv baseline adapter (engineering contract only)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from scripts.evaluation.baseline_adapters import riscv_dv


def _snap(mcause, mtval, mstatus, satp, pmpcfg, pmpaddr, mseccfg=None):
    return {
        "schema_version": 1,
        "dut": "rocket-clean",
        "handler_pc": "0x80000048",
        "trap_records": [
            {
                "mcause": mcause,
                "mtval": hex(mtval),
                "mepc": "0x80000064",
                "mstatus": hex(mstatus),
                "satp": hex(satp),
                "mseccfg": mseccfg,
            }
        ],
        "final_snapshot": {
            "pmpcfg": [hex(v) for v in pmpcfg],
            "pmpaddr": [hex(v) for v in pmpaddr],
            "satp": hex(satp),
            "mseccfg": mseccfg,
            "mstatus": hex(mstatus),
        },
    }


def _classified(event="trap", mcause=7, tag=0, fp=0):
    return {
        "status": "observed",
        "observation_valid": True,
        "observed_event": event,
        "failure_class": None,
        "observed_mcause": mcause,
        "observed_mepc_tag": tag,
        "observed_mtval_fingerprint": fp,
        "infra": None,
    }


class TestRiscvDvAdapter(unittest.TestCase):

    def test_context_off_entries_keep_raw_rwx_bits(self):
        # pmpcfg0 bytes 0x07 = OFF with R/W/X=1 raw readback bits (config family)
        snap = _snap(7, 0x80004000, 0x0A00000800, 0x0,
                     [0x0707070707070707, 0x0707070707070707], [0] * 16)
        ctx = riscv_dv.build_context(snap)
        self.assertEqual(ctx["translation"], "bare")
        self.assertEqual(ctx["default_privilege"], "s")
        self.assertEqual(ctx["default_access"], "store")
        self.assertEqual(ctx["default_size"], 4)
        self.assertEqual(ctx["size_source"], "default")
        entry0 = ctx["pmp_entries"][0]
        self.assertEqual(entry0["address_mode"], "off")
        self.assertTrue(entry0["read"] and entry0["write"] and entry0["execute"])
        self.assertFalse(entry0["locked"])

    def test_smode_store_deny_is_eligible_with_config_and_decision_bins(self):
        # entry0: TOR @0x80002000 RWX (0x0F); entry1: NAPOT deny [0x80004000,0x80008000) (0x18)
        pmpcfg0 = 0x0F | (0x18 << 8)
        snap = _snap(
            7,
            0x80004000,
            0x0A00000800,
            0x0,
            [pmpcfg0, 0],
            [0x20000800, 0x200017FF] + [0] * 14,
        )
        bapc, reason = riscv_dv.score_case(snap, _classified())
        self.assertTrue(bapc["eligible"], reason)
        bins = bapc["observed_bins"]
        self.assertTrue(bins, "expected non-empty bin set")
        self.assertTrue(any("config" in str(b) for b in bins))
        self.assertTrue(any("decision" in str(b) for b in bins))
        self.assertEqual(bapc["qualification_reason"], "eligible")

    def test_sv39_trap_is_ineligible(self):
        snap = _snap(13, 0x40000000, 0x0A00000800, 8 << 60, [0] * 2, [0] * 16)
        bapc, reason = riscv_dv.score_case(snap, _classified(mcause=13))
        self.assertFalse(bapc["eligible"])
        self.assertEqual(reason, "sv39-address-unresolved")

    def test_completion_is_ineligible(self):
        bapc, reason = riscv_dv.score_case(None, _classified(event="completion", mcause=11))
        self.assertFalse(bapc["eligible"])
        self.assertEqual(reason, "completion-no-designated-target-op")

    def test_missing_snapshot_is_ineligible(self):
        bapc, reason = riscv_dv.score_case(None, _classified())
        self.assertFalse(bapc["eligible"])
        self.assertEqual(reason, "missing-runtime-snapshot")

    def test_infra_record_classification(self):
        text = "Assertion failed: *** FAILED *** (exit code =  2147483648)"
        cls = riscv_dv.classify_case(text, 0)
        self.assertEqual(cls["status"], "infra_failure")
        self.assertEqual(cls["failure_class"], "handler-self-fault")
        self.assertFalse(cls["observation_valid"])

    def test_observation_classification(self):
        text = "*** FAILED *** (tohost = 585105408)\n"
        text += "Assertion failed: *** FAILED *** (exit code =  585105408)"
        cls = riscv_dv.classify_case(text, 0)
        self.assertEqual(cls["status"], "observed")
        self.assertEqual(cls["observed_event"], "trap")
        self.assertEqual(cls["observed_mcause"], 7)

    def test_context_napot_entries_decoded(self):
        pmpcfg0 = 0x0F | (0x18 << 8)
        snap = _snap(7, 0x80004000, 0x0A00000800, 0x0,
                     [pmpcfg0, 0], [0x20000800, 0x200017FF] + [0] * 14)
        ctx = riscv_dv.build_context(snap)
        self.assertEqual(ctx["pmp_entries"][0]["address_mode"], "tor")
        self.assertEqual(ctx["pmp_entries"][1]["address_mode"], "napot")
        self.assertEqual(ctx["pmp_entries"][1]["pmpaddr"], 0x200017FF)


if __name__ == "__main__":
    unittest.main()
