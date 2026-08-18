
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from scripts.evaluation.baseline_adapters import riscv_dv

SPLICER = _REPO / "scripts" / "evaluation" / "baseline_adapters" / "riscv_dv_splice.py"
V1_SPLICER_SHA = "bdd59435d0b613ad6e519c5473dcc35697f0347b"
RDV_ROOT = riscv_dv.RISCV_DV_ROOT
RDV_LINK_LD = RDV_ROOT / "scripts" / "link.ld"
RDV_USER_EXT = RDV_ROOT / "user_extension"
RISCV_GCC = os.environ.get("RISCV_GCC", "riscv64-unknown-elf-gcc")
HAS_RISCV_TOOLCHAIN = shutil.which(RISCV_GCC) is not None and RDV_LINK_LD.is_file()


def _git_spec_exists(spec: str) -> bool:
    return subprocess.run(
        ["git", "-C", str(_REPO), "cat-file", "-e", spec],
        capture_output=True,
        timeout=60,
    ).returncode == 0


HAS_V1_SPLICER_HISTORY = _git_spec_exists(
    f"{V1_SPLICER_SHA}:scripts/evaluation/baseline_adapters/riscv_dv_splice.py"
)


FIXTURE_S = """.globl _start
.section .text
_start:
    csrw 0x305, x0
init:
    csrr t0, 0x300
    la t1, tohost
    li a0, 1
    sd a0, 0(t1)
    ecall
    j .
.section .data
    .align 6
    .globl tohost
tohost:
    .dword 0
"""


def _run_py(script, src, dst, extra_args=None):
    cmd = [sys.executable, str(script), str(src), str(dst), "--dut", "rocket-clean"]
    if extra_args:
        cmd.extend(extra_args)
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, "splicer failed: %s" % out.stderr
    return dst


def _compile(s_path, elf_path):
    out = subprocess.run(
        [
            RISCV_GCC,
            "-static",
            "-mcmodel=medany",
            "-fvisibility=hidden",
            "-nostdlib",
            "-nostartfiles",
            "-I" + str(RDV_USER_EXT),
            "-T" + str(RDV_LINK_LD),
            str(s_path),
            "-o",
            str(elf_path),
            "-march=rv64imc_zicsr_zifencei",
            "-mabi=lp64",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert out.returncode == 0, "gcc failed: %s" % out.stderr
    return elf_path


def _li_value(lui, addiw):
    lui_imm = (lui >> 12) & 0xFFFFF
    imm = (((addiw >> 12) & 0x1) << 5) | ((addiw >> 2) & 0x1F)
    if imm & 0x20:
        imm -= 0x40
    return (lui_imm << 12) + imm


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


class TestRiscvDvGraft(unittest.TestCase):

    @unittest.skipUnless(
        HAS_RISCV_TOOLCHAIN,
        "requires RISCV_GCC and RISCV_DV_ROOT with scripts/link.ld",
    )
    def test_graft_elf_contains_exactly_two_pmp_csr_writes(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            src = td_path / "fixture.S"
            src.write_text(FIXTURE_S, encoding="utf-8")
            spliced = td_path / "fixture_spliced.S"
            _run_py(SPLICER, src, spliced, ["--pmp-graft", "upstream-enable-all"])
            sidecar = Path(str(spliced) + ".graft.json")
            self.assertTrue(sidecar.exists(), "graft.json sidecar must be emitted")
            elf = td_path / "fixture.elf"
            _compile(spliced, elf)
            window = riscv_dv._graft_window(elf)
            self.assertIsNotNone(window, "rdv_graft_start/end symbols must be present")
            words = riscv_dv._graft_inst_words(elf)
            self.assertIsNotNone(words)
            self.assertEqual(
                [w for _, w in words],
                [0x20000DB7, 0x3DFD, 0x3B0D9073, 0x3A0FD073],
                "graft instruction words (verified against objdump 2026-08-14)",
            )
            csr_words = [w for _, w in words if (w & 0x7F) == 0x73]
            self.assertEqual(len(csr_words), 2, "exactly two PMP CSR writes")

            csrwi = [w for w in csr_words if (w >> 20) == 0x3A0]
            self.assertEqual(len(csrwi), 1)
            self.assertEqual((csrwi[0] >> 15) & 0x1F, 0x1F)

            csrw = [w for w in csr_words if (w >> 20) == 0x3B0]
            self.assertEqual(len(csrw), 1)
            self.assertEqual((csrw[0] >> 15) & 0x1F, 27)

            self.assertEqual(_li_value(words[0][1], words[1][1]), 0x1FFFFFFF)

    def test_grafted_snapshot_programmed_entries(self):
        snap = _snap(11, 0, 0x1800, 0x0, [0x1F] + [0] * 7, [0x1FFFFFFF] + [0] * 15)
        pats = riscv_dv._programmed_patterns(snap)
        self.assertEqual(len(pats), 1, "exactly one non-OFF entry")
        self.assertEqual(pats[0], ("napot", 1, 1, 1, 0), "napot / RWX / unlocked")
        offs = riscv_dv._off_patterns(snap)
        self.assertEqual(len(offs), 1, "all remaining entries OFF with byte 0")
        self.assertIn((0, 0, 0, 0), offs)

    def test_pmp_programming_stats_aggregation_rocket(self):
        case_rows = []
        for i in range(512):
            case_rows.append(
                {
                    "case_id": "rocket-clean_%03d" % i,
                    "completed": True,
                    "snapshot_present": True,
                    "graft_executed": True,
                    "programmed_entries": 1,
                    "programmed_patterns": [("napot", 1, 1, 1, 0)],
                    "off_patterns": [(0, 0, 0, 0)],
                    "graft_evidence": {"sidecar_present": True},
                }
            )
        stats = riscv_dv.build_pmp_programming_stats("rocket-clean", case_rows)
        self.assertEqual(stats["cases_with_snapshot"], 512)
        self.assertEqual(stats["avg_programmed_entries"], 1.0)
        self.assertEqual(stats["distinct_programmed_patterns"], 1)
        self.assertEqual(
            stats["pattern_breakdown"],
            [{"mode": "napot", "r": 1, "w": 1, "x": 1, "l": 0, "count": 512}],
        )
        self.assertEqual(stats["reset_off_patterns"], 8)
        self.assertEqual(stats["evidence_channels"]["readback_snapshot"], 512)

    def test_pmp_programming_stats_boom_static_channel(self):
        case_rows = []
        for i in range(512):
            case_rows.append(
                {
                    "case_id": "boom-clean_%03d" % i,
                    "completed": True,
                    "snapshot_present": False,
                    "graft_executed": False,
                    "programmed_entries": None,
                    "programmed_patterns": [],
                    "off_patterns": [],
                    "graft_evidence": {"sidecar_present": True},
                }
            )
        stats = riscv_dv.build_pmp_programming_stats("boom-clean", case_rows)
        self.assertEqual(stats["cases_with_snapshot"], 0)
        self.assertIsNone(stats["avg_programmed_entries"])
        self.assertEqual(stats["evidence_channels"]["static_sidecar_deductive"], 512)
        self.assertIsNone(stats["reset_off_patterns"])

    def test_bapc_py_not_modified(self):
        out = subprocess.run(
            ["git", "-C", str(_REPO), "diff", "--name-only", "HEAD"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        changed = [line.strip() for line in out.stdout.splitlines() if line.strip()]
        self.assertNotIn("pmpfuzz/bapc.py", changed)

    @unittest.skipUnless(
        HAS_V1_SPLICER_HISTORY,
        "requires the frozen V1 splicer commit in local Git history",
    )
    def test_no_graft_output_identical_to_v1_splicer(self):
        old_code = subprocess.run(
            [
                "git",
                "-C",
                str(_REPO),
                "show",
                "%s:scripts/evaluation/baseline_adapters/riscv_dv_splice.py" % V1_SPLICER_SHA,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        ).stdout
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            src = td_path / "fixture.S"
            src.write_text(FIXTURE_S, encoding="utf-8")
            v1_splicer = td_path / "riscv_dv_splice_v1.py"
            v1_splicer.write_text(old_code, encoding="utf-8")
            old_out = td_path / "v1.S"
            new_out = td_path / "new.S"
            _run_py(v1_splicer, src, old_out)
            _run_py(SPLICER, src, new_out)
            self.assertEqual(
                old_out.read_bytes(),
                new_out.read_bytes(),
                "no-graft output must be byte-identical to the v1 splicer",
            )
            self.assertFalse(
                Path(str(new_out) + ".graft.json").exists(),
                "no graft sidecar without --pmp-graft",
            )


if __name__ == "__main__":
    unittest.main()
