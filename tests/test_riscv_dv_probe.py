
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
R3_SPLICER_SHA = "928329596668be1acb489d9b7ba33a2e87458bfd"
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


HAS_R3_SPLICER_HISTORY = _git_spec_exists(
    f"{R3_SPLICER_SHA}:scripts/evaluation/baseline_adapters/riscv_dv_splice.py"
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
test_done:
    li gp, 1
    ecall
write_tohost:
    sw gp, tohost, t5
_exit:
    j write_tohost
.section .data
    .align 6
    .globl tohost
tohost:
    .dword 0
    .align 3
user_stack_start:
    .skip 32
"""



EXPECTED_BINS = [
    "family=config|pmp_mode=napot|permission_rwx=111|locked=false",
    "family=config|pmp_mode=off|permission_rwx=000|locked=false",
    "family=decision|access=load|allow_or_deny=allow|mcause_class=none",
    "family=mode-decision|pmp_mode=napot|access=load|allow_or_deny=allow",
    "family=privilege-decision|effective_privilege=m|access=load|allow_or_deny=allow",
    "family=stimulus|privilege=m|effective_privilege=m|access=load|translation=bare",
]


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


def _objdump_words(elf_path):
    out = subprocess.run(
        ["riscv64-unknown-elf-objdump", "-d", str(elf_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    words = []
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(":"):
            try:
                words.append(int(parts[1], 16))
            except ValueError:
                pass
    return words


def _grafted_snapshot():
    return {
        "schema_version": 1,
        "dut": "rocket-clean",
        "handler_pc": "0x80000048",
        "trap_records": [
            {
                "mcause": 11,
                "mtval": "0x0",
                "mepc": "0x8000104a",
                "mstatus": "0xa00001800",
                "satp": "0x0",
                "mseccfg": None,
            }
        ],
        "final_snapshot": {
            "pmpcfg": ["0x1f"] + ["0x0"] * 7,
            "pmpaddr": ["0x1fffffff"] + ["0x0"] * 15,
            "satp": "0x0",
            "mseccfg": None,
            "mstatus": "0xa00001800",
        },
    }


class TestRiscvDvProbe(unittest.TestCase):

    @unittest.skipUnless(
        HAS_RISCV_TOOLCHAIN,
        "requires RISCV_GCC and RISCV_DV_ROOT with scripts/link.ld",
    )
    def test_probe_elf_has_probe_window_and_no_new_pmp_writes(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            src = td_path / "fixture.S"
            src.write_text(FIXTURE_S, encoding="utf-8")
            spliced = td_path / "fixture_spliced.S"
            _run_py(SPLICER, src, spliced, [
                "--pmp-graft", "upstream-enable-all",
                "--designated-probe", "epilogue-load",
            ])
            probe_sidecar = Path(str(spliced) + ".probe.json")
            self.assertTrue(probe_sidecar.exists(), "probe.json sidecar must be emitted")
            elf = td_path / "fixture.elf"
            _compile(spliced, elf)
            window = riscv_dv._probe_window(elf)
            self.assertIsNotNone(window, "rdv_probe_start/end must be present")
            words = riscv_dv._window_inst_words(elf, window)
            self.assertIsNotNone(words)

            last = words[-1][1]
            self.assertEqual(last & 0x7F, 0x03, "probe must end with a load")
            self.assertEqual((last >> 12) & 0x7, 3, "ld funct3=3")

            for _, w in words:
                self.assertNotEqual(w & 0x7F, 0x73, "probe must not write CSRs")



            all_words = _objdump_words(elf)
            pmp_writes = [
                w for w in all_words
                if (w & 0x7F) == 0x73
                and ((w >> 12) & 0x7) in (1, 5)
                and ((w >> 20) in (0x3A0, 0x3B0))
            ]
            self.assertEqual(len(pmp_writes), 2, "exactly two PMP CSR writes (graft only)")

            import json
            sidecar = json.loads(probe_sidecar.read_text(encoding="utf-8"))
            self.assertEqual(sidecar["probe_symbol"], "user_stack_start")
            self.assertFalse(sidecar["fallback_slot"])
            self.assertIn("no protection semantics", sidecar["provenance"])

            addr = riscv_dv._symbol_address(elf, "user_stack_start")
            self.assertIsNotNone(addr)
            self.assertEqual(addr % 8, 0, "probe address must be 8B aligned")

    def test_synthetic_completion_probe_yields_allow_bins(self):
        probe_op = {
            "probe": "epilogue-load",
            "physical_address": 0x80006430,
            "instruction_address": 0x80001048,
            "probe_executed": True,
            "context_evidence": "readback",
            "provenance": "wrapper-epilogue-probe: no protection semantics injected",
        }
        snap = _grafted_snapshot()
        bapc, reason = riscv_dv.score_probe_completion(snap, probe_op, None, "rocket-clean")
        self.assertTrue(bapc["eligible"], reason)
        bins = bapc["observed_bins"]
        self.assertEqual(len(bins), 6, "expected exactly 6 allow-side bins")
        self.assertEqual(set(bins), set(EXPECTED_BINS))

        import collections
        families = collections.Counter(str(b).split("|")[0] for b in bins)
        self.assertEqual(families["family=config"], 2)
        self.assertEqual(families["family=decision"], 1)
        self.assertEqual(families["family=mode-decision"], 1)
        self.assertEqual(families["family=privilege-decision"], 1)
        self.assertEqual(families["family=stimulus"], 1)

    def test_trap_before_completion_voids_probe(self):
        classified = {
            "status": "observed",
            "observation_valid": True,
            "observed_event": "trap",
            "failure_class": None,
            "observed_mcause": 7,
            "observed_mepc_tag": 0,
            "observed_mtval_fingerprint": 0,
            "infra": None,
        }
        snap = _grafted_snapshot()
        probe_op = {"physical_address": 0x80006430, "probe_executed": True}
        legacy, legacy_reason = riscv_dv.score_case(snap, classified)
        branch, branch_reason = riscv_dv.score_case_with_probe(
            snap, classified, probe_op, None, "rocket-clean", probe_mode=True
        )
        self.assertEqual(branch_reason, legacy_reason, "trap keeps the legacy path")
        self.assertEqual(branch.get("eligible"), legacy.get("eligible"))

        completion = dict(classified)
        completion["observed_event"] = "completion"
        voided, voided_reason = riscv_dv.score_case_with_probe(
            snap, completion, None, None, "rocket-clean", probe_mode=True
        )
        self.assertFalse(voided["eligible"])
        self.assertEqual(voided_reason, "probe-not-resolved")

    @unittest.skipUnless(
        HAS_R3_SPLICER_HISTORY,
        "requires the frozen R3 splicer commit in local Git history",
    )
    def test_bapc_py_not_modified_since_r3(self):
        out = subprocess.run(
            ["git", "-C", str(_REPO), "diff", "--name-only", R3_SPLICER_SHA, "HEAD"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        changed = [line.strip() for line in out.stdout.splitlines() if line.strip()]
        self.assertNotIn("pmpfuzz/bapc.py", changed)

    @unittest.skipUnless(
        HAS_R3_SPLICER_HISTORY,
        "requires the frozen R3 splicer commit in local Git history",
    )
    def test_no_probe_output_identical_to_r3_splicer(self):
        r3_code = subprocess.run(
            [
                "git",
                "-C",
                str(_REPO),
                "show",
                "%s:scripts/evaluation/baseline_adapters/riscv_dv_splice.py" % R3_SPLICER_SHA,
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
            r3_splicer = td_path / "riscv_dv_splice_r3.py"
            r3_splicer.write_text(r3_code, encoding="utf-8")
            r3_out = td_path / "r3.S"
            new_out = td_path / "new.S"
            _run_py(r3_splicer, src, r3_out, ["--pmp-graft", "upstream-enable-all"] )
            _run_py(SPLICER, src, new_out, ["--pmp-graft", "upstream-enable-all"])
            self.assertEqual(
                r3_out.read_bytes(),
                new_out.read_bytes(),
                "graft-only output must be byte-identical to the R3 splicer",
            )
            self.assertFalse(
                Path(str(new_out) + ".probe.json").exists(),
                "no probe sidecar without --designated-probe",
            )


if __name__ == "__main__":
    unittest.main()
