import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "scripts" / "evaluation" / "baseline_adapters"))
import riscv_dv
import riscv_dv_static_pmp as st

_CC = os.environ.get("RISCV_GCC", "riscv64-unknown-elf-gcc")
_RDV_ROOT = riscv_dv.RISCV_DV_ROOT
_HAS_RISCV_TOOLCHAIN = shutil.which(_CC) is not None and (_RDV_ROOT / "scripts" / "link.ld").is_file()


def _build_main_elf(directory, name):
    asm = directory / (name + ".S")
    asm.write_text(
        ".section .text\n.globl main\nmain:\n  ret\n",
        encoding="ascii",
    )
    elf = directory / (name + ".elf")
    subprocess.run(
        [
            _CC, "-static", "-mcmodel=medany", "-fvisibility=hidden",
            "-nostdlib", "-nostartfiles",
            f"-T{_RDV_ROOT / 'scripts' / 'link.ld'}",
            str(asm), "-o", str(elf),
            "-march=rv64imc_zicsr_zifencei", "-mabi=lp64",
        ],
        check=True, capture_output=True, timeout=120,
    )
    return elf


@unittest.skipUnless(
    _HAS_RISCV_TOOLCHAIN,
    "requires RISCV_GCC and RISCV_DV_ROOT with scripts/link.ld",
)
class TestStaticPmpDeriver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="r6test_"))
        cls.elf = _build_main_elf(cls.tmp, "tiny")

    def _asm_with_setup(self, setup_lines):
        lines = [
            ".section .text",
            ".globl _start",
            "_start:",
            "pmp_setup:",
        ] + setup_lines + [
            "mepc_setup:",
            "  la x15, main",
            "  csrw 0x341, x15",
            "init_machine_mode:",
            "  mret",
            "init:",
            "  j main",
        ]
        path = self.tmp / ("case_%d.S" % self._test_id)
        path.write_text("\n".join(lines) + "\n", encoding="ascii")
        return path

    def setUp(self):
        self._test_id = getattr(self, "_case_counter", 0)
        type(self)._case_counter = self._test_id + 1

    def test_tor_single_region(self):
        asm = self._asm_with_setup([
            "  la x4, main",
            "  srli x4, x4, 2",
            "  csrw 0x3b0, x4",
            "  li x4, 0x000000000000000f",
            "  csrw 0x3a0, x4",
        ])
        state = st.derive_static_pmp(str(asm), str(self.elf))
        e0 = state["entries"][0]
        self.assertEqual(e0["address_mode"], "tor")
        self.assertTrue(e0["read"] and e0["write"] and e0["execute"])
        self.assertFalse(e0["locked"])
        main_addr = st._symbol_address(self.elf, "main")
        self.assertEqual(e0["pmpaddr"], main_addr >> 2)
        for i in range(1, 16):
            self.assertEqual(state["entries"][i]["address_mode"], "off")

    def test_multi_region_modes_and_lock(self):
        asm = self._asm_with_setup([
            "  la x4, main",
            "  srli x4, x4, 2",
            "  csrw 0x3b0, x4",
            "  la x4, main",
            "  li x7, 0x100",
            "  add x4, x4, x7",
            "  srli x4, x4, 2",
            "  csrw 0x3b1, x4",
            "  la x4, main",
            "  li x7, 0x200",
            "  add x4, x4, x7",
            "  srli x4, x4, 2",
            "  csrw 0x3b2, x4",
            "  la x4, main",
            "  li x7, 0x300",
            "  add x4, x4, x7",
            "  srli x4, x4, 2",
            "  csrw 0x3b3, x4",
            "  li x4, 0x00000000178f940f",
            "  csrw 0x3a0, x4",
        ])
        state = st.derive_static_pmp(str(asm), str(self.elf))
        main_addr = st._symbol_address(self.elf, "main")
        self.assertEqual(state["entries"][0]["address_mode"], "tor")

        e1 = state["entries"][1]
        self.assertEqual((e1["address_mode"], e1["read"], e1["write"], e1["execute"], e1["locked"]),
                         ("na4", False, False, True, True))
        e2 = state["entries"][2]
        self.assertEqual((e2["address_mode"], e2["read"], e2["write"], e2["execute"], e2["locked"]),
                         ("tor", True, True, True, True))
        e3 = state["entries"][3]
        self.assertEqual((e3["address_mode"], e3["read"], e3["write"], e3["execute"]),
                         ("na4", True, True, True))
        self.assertEqual(state["entries"][1]["pmpaddr"], (main_addr + 0x100) >> 2)
        self.assertEqual(state["entries"][3]["pmpaddr"], (main_addr + 0x300) >> 2)

    def test_handler_blocks_ignored(self):
        asm = self._asm_with_setup([
            "  la x4, main",
            "  srli x4, x4, 2",
            "  csrw 0x3b0, x4",
            "  li x4, 0x000000000000000f",
            "  csrw 0x3a0, x4",
        ])
        path = Path(asm)
        text = path.read_text(encoding="ascii")
        text = text.replace(
            "init:\n  j main",
            "init:\n  j main\nmmode_intr_vector_1:\n  csrw 0x3a0, zero\n  csrr x17, 0x3a0\n  csrw 0x3a0, x17",
        )
        path.write_text(text, encoding="ascii")
        state = st.derive_static_pmp(str(path), str(self.elf))
        self.assertEqual(state["entries"][0]["address_mode"], "tor")
        self.assertTrue(state["entries"][0]["execute"])


class TestFingerprintRecovery(unittest.TestCase):
    def test_recover_unique(self):
        for addr in (0x80003100, 0x80004234, 0x8001FFFE, 0x80000B0C):
            fp = st.fold17(addr)
            tag = (addr >> 12) & 0xF
            rec, unique = st.recover_trap_address(fp, tag, None, main_addr=0x80000000)
            self.assertTrue(unique)
            self.assertEqual(rec, addr)

    def test_recover_wrong_tag_rejected(self):
        addr = 0x80003100
        fp = st.fold17(addr)
        rec, unique = st.recover_trap_address(fp, (addr >> 12) & 0xF ^ 1, None, main_addr=0x80000000)
        self.assertIsNone(rec)


class TestR6StaticScoring(unittest.TestCase):
    def test_trap_eligible_with_static_context(self):
        static_state = {
            "pmpcfg": ["0xf", "0", "0", "0", "0", "0", "0", "0"],
            "pmpaddr": ["0x%x" % (0x80000000 >> 2)] + ["0x0"] * 15,
            "entries": [
                {"index": 0, "address_mode": "tor", "pmpaddr": 0x80000000 >> 2,
                 "read": True, "write": True, "execute": True, "locked": False},
            ] + [
                {"index": i, "address_mode": "off", "pmpaddr": 0,
                 "read": False, "write": False, "execute": False, "locked": False}
                for i in range(1, 16)
            ],
        }
        classified = {
            "status": "observed", "observation_valid": True,
            "observed_event": "trap", "observed_mcause": 1,
            "observed_mepc_tag": 0, "observed_mtval_fingerprint": st.fold17(0x80003100),
            "infra": None, "failure_class": None,
        }
        bapc, reason = riscv_dv.score_case(
            None, classified, static_state=static_state, static_address=0x80003100,
        )
        self.assertEqual(reason, "eligible")
        self.assertTrue(bapc["eligible"])
        bins = bapc["observed_bins"]
        self.assertTrue(any("family=decision|access=fetch|allow_or_deny=deny" in b for b in bins), bins)
        self.assertTrue(any("family=config|pmp_mode=tor|permission_rwx=111|locked=false" in b for b in bins), bins)

    def test_trap_mode_decision_omitted_when_address_unrecoverable(self):
        static_state = {
            "pmpcfg": ["0xf"] + ["0"] * 7,
            "pmpaddr": ["0x%x" % (0x80000000 >> 2)] + ["0x0"] * 15,
            "entries": [
                {"index": 0, "address_mode": "tor", "pmpaddr": 0x80000000 >> 2,
                 "read": True, "write": True, "execute": True, "locked": False},
            ] + [
                {"index": i, "address_mode": "off", "pmpaddr": 0,
                 "read": False, "write": False, "execute": False, "locked": False}
                for i in range(1, 16)
            ],
        }
        classified = {
            "status": "observed", "observation_valid": True,
            "observed_event": "trap", "observed_mcause": 1,
            "observed_mepc_tag": 0, "observed_mtval_fingerprint": 0x1FFFF,
            "infra": None, "failure_class": None,
        }
        bapc, reason = riscv_dv.score_case(
            None, classified, static_state=static_state, static_address=None,
        )
        self.assertEqual(reason, "eligible")
        self.assertFalse(any("family=mode-decision" in b for b in bapc["observed_bins"]))
        self.assertIn("mode_decision_omitted_reason", bapc)

    def test_bapc_py_not_modified(self):
        out = subprocess.run(
            ["git", "-C", str(_REPO), "diff", "--name-only", "HEAD"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertNotIn("pmpfuzz/bapc.py", out.stdout.splitlines())


if __name__ == "__main__":
    unittest.main()
