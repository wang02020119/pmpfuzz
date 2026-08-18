import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pmpfuzz.bapc import build_bapc_coverage_universe
from pmpfuzz.diagnostics import ObservationKind, ObservationPhase, encode_observation_payload
from pmpfuzz.experiment_protocols import (
    BAPC_CONVERGENCE_FORMAL,
    BAPC_CONVERGENCE_PROTOCOL_ID,
    build_bapc_convergence_contract,
)
from pmpfuzz.bapc import summarize_bapc_for_cascade_execution
from scripts.evaluation.baseline_adapters import cascade, cascade_generate_campaign
from scripts.evaluation.validation.validate_timeline import validate_timeline


def _fake_sidecar() -> dict:
    return {
        "campaign_seed": 101,
        "case_index": 0,
        "derived_instance_id": 101,
        "design": "rocket",
        "translation": "bare",
        "privilege": "S",
        "access": "load",
        "size": 4,
        "physical_address": "0x80008020",
        "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
        "pmp_entries": [
            {
                "index": 0,
                "address_mode": "napot",
                "pmpaddr": "0x20001fff",
                "read": True,
                "write": True,
                "execute": True,
                "locked": False,
            }
        ],
    }


class BapcCascadeAdapterTest(unittest.TestCase):
    def test_cascade_target_operation_records_instruction_width(self):
        class Instruction:
            def __init__(self, mnemonic: str):
                self.instr_str = mnemonic

        expected = {
            "lb": 1,
            "lh": 2,
            "lw": 4,
            "ld": 8,
            "sb": 1,
            "sh": 2,
            "sw": 4,
            "sd": 8,
        }

        for mnemonic, size in expected.items():
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(
                    cascade_generate_campaign._candidate_size(Instruction(mnemonic)),
                    size,
                )

    def test_xiangshan_goodtrap_without_structured_observation_is_not_bapc_valid(self):
        actual = cascade._bapc_actual_result_from_log(
            dut="xiangshan-clean",
            log_text="HIT GOOD TRAP at pc = 0x80000000\n",
            returncode=0,
        )

        self.assertFalse(actual["observation_valid"])
        self.assertIsNone(actual["observed_event"])

    def test_xiangshan_cascade_bapc_requires_structured_target_operation_observation(self):
        sidecar = _fake_sidecar() | {"design": "xiangshan"}

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(
                json.dumps(sidecar, indent=2, ensure_ascii=True) + "\n",
                encoding="ascii",
            )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(
            returncode=0,
            stdout="HIT GOOD TRAP at pc = 0x80000000\n",
            stderr="",
        )

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "emu"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(
                cascade._SIM_BINARIES, {"xiangshan-clean": str(real_binary)}, clear=False
            ):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        meta = cascade.run_cascade_baseline(
                            dut="xiangshan-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            coverage_mode="bapc",
                        )

            events = json.loads((out_dir / "events.json").read_text(encoding="ascii"))

        self.assertEqual(meta["executed_cases"], 1)
        self.assertEqual(meta["eligible_bapc_cases"], 0)
        self.assertEqual(meta["bapc_covered"], 0)
        self.assertFalse(events[0]["bapc_eligible"])
        self.assertEqual(
            events[0]["bapc_coverage"]["qualification_reason"],
            "missing-actual-observation",
        )

    def test_xiangshan_structured_diag_is_bapc_valid_for_cascade(self):
        payload = encode_observation_payload(
            ObservationKind.TRAP,
            mcause=5,
            mtval=0x80008020,
            mepc=0x80004000,
            phase=ObservationPhase.PROBE,
        )
        actual = cascade._bapc_actual_result_from_log(
            dut="xiangshan-clean",
            log_text=(
                f"PMFUZZ_DIAG tohost=0x{payload:x} mcause=0x5 mtval=0x80008020\n"
                "PMFUZZ_PROBE probe=xiangshan_pmp chain=pmp-check stage=final exception=1 addr=0x80008020\n"
                "HIT BAD TRAP at pc = 0x80004000\n"
            ),
            returncode=0,
        )

        self.assertTrue(actual["observation_valid"])
        self.assertEqual(actual["observed_event"], "trap")
        self.assertEqual(actual["observed_mcause"], 5)
        self.assertEqual(actual["observed_fault_address"], 0x80008020)

    def test_xiangshan_candidate_sidecar_can_select_trap_target_without_probes(self):
        sidecar = {
            "campaign_seed": 101,
            "case_index": 0,
            "derived_instance_id": 101,
            "design": "xiangshan",
            "translation": "bare",
            "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
            "pmp_entries": _fake_sidecar()["pmp_entries"],
            "target_operation_candidates": [
                {
                    "target_operation_id": "bb1-i0",
                    "privilege": "M",
                    "access": "load",
                    "size": 8,
                    "physical_address": "0x80008020",
                    "instruction_address": "0x80001000",
                    "instruction_page_tag": 1,
                },
                {
                    "target_operation_id": "bb2-i0",
                    "privilege": "M",
                    "access": "store",
                    "size": 8,
                    "physical_address": "0x80008100",
                    "instruction_address": "0x80002010",
                    "instruction_page_tag": 2,
                },
            ],
        }

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(
                json.dumps(sidecar, indent=2, ensure_ascii=True) + "\n",
                encoding="ascii",
            )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        payload = encode_observation_payload(
            ObservationKind.TRAP,
            mcause=7,
            mtval=0x80008100,
            mepc=0x80002010,
            phase=ObservationPhase.PROBE,
        )
        process = unittest.mock.Mock(
            returncode=0,
            stdout=(
                f"PMFUZZ_DIAG tohost=0x{payload:x} mcause=0x7 mtval=0x80008100\n"
                "HIT BAD TRAP at pc = 0x80002010\n"
            ),
            stderr="",
        )

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "emu"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(
                cascade._SIM_BINARIES, {"xiangshan-clean": str(real_binary)}, clear=False
            ):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        meta = cascade.run_cascade_baseline(
                            dut="xiangshan-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            coverage_mode="bapc",
                        )

            events = json.loads((out_dir / "events.json").read_text(encoding="ascii"))

        self.assertEqual(meta["eligible_bapc_cases"], 1)
        self.assertGreater(meta["bapc_covered"], 0)
        self.assertTrue(events[0]["bapc_eligible"])
        self.assertEqual(events[0]["bapc_coverage"]["qualification_reason"], "eligible")

    def test_relative_candidate_sidecar_matches_absolute_fault_address(self):
        sidecar = {
            "translation": "bare",
            "target_operation_candidates": [
                {
                    "target_operation_id": "bb1-i0",
                    "privilege": "M",
                    "access": "load",
                    "size": 8,
                    "physical_address": "0x8020",
                    "instruction_address": "0x80001000",
                    "instruction_page_tag": 1,
                },
                {
                    "target_operation_id": "bb2-i0",
                    "privilege": "M",
                    "access": "store",
                    "size": 8,
                    "physical_address": "0x8100",
                    "instruction_address": "0x80002010",
                    "instruction_page_tag": 2,
                },
            ],
        }

        resolved = cascade._resolve_target_operation_sidecar(
            sidecar,
            {
                "observed_event": "trap",
                "observed_mcause": 7,
                "observed_fault_address": 0x80008100,
                "observed_mtval_fingerprint": None,
                "observed_mepc_tag": None,
            },
        )

        self.assertIsNotNone(resolved)
        self.assertEqual(resolved["target_operation_id"], "bb2-i0")
        self.assertEqual(resolved["access"], "store")
        self.assertEqual(resolved["physical_address"], "0x8100")

    def test_xiangshan_candidate_sidecar_keeps_ambiguous_completion_ineligible(self):
        sidecar = {
            "campaign_seed": 101,
            "case_index": 0,
            "derived_instance_id": 101,
            "design": "xiangshan",
            "translation": "bare",
            "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
            "pmp_entries": _fake_sidecar()["pmp_entries"],
            "target_operation_candidates": [
                {
                    "target_operation_id": "bb1-i0",
                    "privilege": "M",
                    "access": "load",
                    "size": 8,
                    "physical_address": "0x80008020",
                    "instruction_address": "0x80001000",
                    "instruction_page_tag": 1,
                },
                {
                    "target_operation_id": "bb2-i0",
                    "privilege": "M",
                    "access": "store",
                    "size": 8,
                    "physical_address": "0x80008100",
                    "instruction_address": "0x80002010",
                    "instruction_page_tag": 2,
                },
            ],
        }

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(
                json.dumps(sidecar, indent=2, ensure_ascii=True) + "\n",
                encoding="ascii",
            )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        payload = encode_observation_payload(
            ObservationKind.COMPLETION,
            mcause=0,
            mtval=0x0,
            mepc=0x80003000,
            phase=ObservationPhase.COMPLETED,
        )
        process = unittest.mock.Mock(
            returncode=0,
            stdout=(
                f"PMFUZZ_DIAG tohost=0x{payload:x} mcause=0x0 mtval=0x0\n"
                "HIT GOOD TRAP at pc = 0x80003000\n"
            ),
            stderr="",
        )

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "emu"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(
                cascade._SIM_BINARIES, {"xiangshan-clean": str(real_binary)}, clear=False
            ):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        meta = cascade.run_cascade_baseline(
                            dut="xiangshan-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            coverage_mode="bapc",
                        )

            events = json.loads((out_dir / "events.json").read_text(encoding="ascii"))

        self.assertEqual(meta["eligible_bapc_cases"], 0)
        self.assertFalse(events[0]["bapc_eligible"])
        self.assertEqual(
            events[0]["bapc_coverage"]["qualification_reason"],
            "missing-or-ambiguous-target-operation",
        )

    def test_bapc_campaign_writes_single_mode_artifacts_from_actual_observations(self):
        sidecar = _fake_sidecar()

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(
                json.dumps(sidecar, indent=2, ensure_ascii=True) + "\n",
                encoding="ascii",
            )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(
            returncode=0,
            stdout="*** PASSED ***\n",
            stderr="",
        )
        expected = summarize_bapc_for_cascade_execution(
            sidecar,
            {
                "status": "pass",
                "observation_valid": True,
                "observed_event": "completion",
                "observed_mcause": None,
                "observed_stage": None,
            },
            stdout_text=process.stdout,
        )

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(
                cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False
            ):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        meta = cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            coverage_mode="bapc",
                        )

            timeline_rows = [
                json.loads(line)
                for line in (out_dir / "metrics" / "coverage_timeline.jsonl")
                .read_text(encoding="ascii")
                .splitlines()
            ]
            coverage = json.loads(
                (out_dir / "metrics" / "coverage" / "coverage.json").read_text(encoding="ascii")
            )
            validation = json.loads((out_dir / "validation.json").read_text(encoding="ascii"))

        self.assertEqual(meta["coverage_mode"], "bapc")
        self.assertEqual(meta["eligible_bapc_cases"], 1)
        self.assertEqual(timeline_rows[0]["completion_seq"], 0)
        self.assertEqual(timeline_rows[-1]["new_bapc_bins"], len(expected["observed_bins"]))
        self.assertEqual(
            coverage["execution_coverage"]["by_dut"]["rocket-clean"]["bapc"]["covered_bins"],
            expected["observed_bins"],
        )
        self.assertTrue(validation["valid"], validation)

    def test_bapc_campaign_does_not_force_single_target_generation(self):
        sidecar = _fake_sidecar()
        captured_kwargs = {}

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            captured_kwargs.update(kwargs)
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(
                json.dumps(sidecar, indent=2, ensure_ascii=True) + "\n",
                encoding="ascii",
            )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(
            returncode=0,
            stdout="PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x80008020\n",
            stderr="",
        )

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(
                cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False
            ):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            coverage_mode="bapc",
                        )

        self.assertNotIn("require_single_target_operation", captured_kwargs)
        self.assertTrue(captured_kwargs.get("require_target_operation_candidate"))

    def test_bapc_campaign_accepts_probe_and_pass_markers_from_stderr(self):
        sidecar = _fake_sidecar()

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(
                json.dumps(sidecar, indent=2, ensure_ascii=True) + "\n",
                encoding="ascii",
            )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(
            returncode=0,
            stdout="Usage: simulator ...\n",
            stderr=(
                "PMFUZZ_PROBE dut=rocket-clean probe=rocket_tlb_exception_arbitration "
                "chain=exception-arbitration stage=tlb vaddr=0x80008020 ae_ld=0 ae_st=0\n"
                "*** PASSED ***\n"
            ),
        )
        combined_log = process.stdout + process.stderr
        expected = summarize_bapc_for_cascade_execution(
            sidecar,
            {
                "status": "pass",
                "observation_valid": True,
                "observed_event": "completion",
                "observed_mcause": None,
                "observed_stage": None,
            },
            stdout_text=combined_log,
        )

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(
                cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False
            ):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        meta = cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            coverage_mode="bapc",
                        )

            events = json.loads((out_dir / "events.json").read_text(encoding="ascii"))
            coverage = json.loads(
                (out_dir / "metrics" / "coverage" / "coverage.json").read_text(encoding="ascii")
            )

        self.assertEqual(meta["completed_cases"], 1)
        self.assertEqual(meta["eligible_cases"], 1)
        self.assertEqual(meta["eligible_bapc_cases"], 1)
        self.assertEqual(events[0]["probe_event_count"], 1)
        self.assertEqual(
            coverage["execution_coverage"]["by_dut"]["rocket-clean"]["bapc"]["covered_bins"],
            expected["observed_bins"],
        )

    def test_bapc_campaign_accepts_explicit_failed_marker_without_tohost(self):
        sidecar = _fake_sidecar()

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(
                json.dumps(sidecar, indent=2, ensure_ascii=True) + "\n",
                encoding="ascii",
            )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(
            returncode=255,
            stdout="[50001000] %Fatal: TestDriver.v:147: Assertion failed in TOP.TestDriver\n",
            stderr=(
                "PMFUZZ_PROBE dut=rocket-clean probe=rocket_ptw_access_exception "
                "chain=ptw-response stage=ptw ae_ptw=1 ae_final=0 paddr=0x80008020\n"
                "*** FAILED ***                       (timeout) after                50001 simulation cycles\n"
            ),
        )

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(
                cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False
            ):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        meta = cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            coverage_mode="bapc",
                        )

            events = json.loads((out_dir / "events.json").read_text(encoding="ascii"))

        self.assertEqual(meta["completed_cases"], 1)
        self.assertEqual(meta["eligible_cases"], 1)
        self.assertEqual(meta["eligible_bapc_cases"], 1)
        self.assertGreater(meta["bapc_covered"], 0)
        self.assertTrue(events[0]["bapc_eligible"])

    def test_bapc_campaign_uses_target_operation_outcome_for_failed_execution(self):
        sidecar = _fake_sidecar()
        sidecar["translation"] = "sv39"

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(
                json.dumps(sidecar, indent=2, ensure_ascii=True) + "\n",
                encoding="ascii",
            )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(
            returncode=255,
            stdout="",
            stderr=(
                "PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker "
                "chain=pmp-check stage=final prv=3 access=fetch allow=1 addr=0x80008020 r=1 w=1 x=1\n"
                "PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker "
                "chain=pmp-check stage=ptw prv=1 access=load allow=0 addr=0x48ea797c r=0 w=0 x=0\n"
                "*** FAILED ***                       (timeout) after                50001 simulation cycles\n"
            ),
        )

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(
                cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False
            ):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        meta = cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            coverage_mode="bapc",
                        )

            coverage = json.loads(
                (out_dir / "metrics" / "coverage" / "coverage.json").read_text(encoding="ascii")
            )

        observed = set(
            coverage["execution_coverage"]["by_dut"]["rocket-clean"]["bapc"]["covered_bins"]
        )
        self.assertEqual(meta["eligible_bapc_cases"], 1)
        self.assertIn(
            "family=decision|access=load|allow_or_deny=deny|mcause_class=load_access_fault",
            observed,
        )
        self.assertNotIn("family=translation-stage|translation=sv39|fault_stage=ptw|allow_or_deny=deny", observed)
        self.assertNotIn("family=decision|access=fetch|allow_or_deny=allow|mcause_class=none", observed)

    def test_cva6_timeout_without_target_runtime_record_is_not_bapc_eligible(self):
        sidecar = _fake_sidecar()
        sidecar.update(
            {
                "design": "cva6",
                "privilege": "M",
                "access": "load",
                "size": 4,
                "physical_address": "0xa1618",
            }
        )

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(
                json.dumps(sidecar, indent=2, ensure_ascii=True) + "\n",
                encoding="ascii",
            )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(
            returncode=255,
            stdout=(
                "[UART] UART0 is here (stdin/stdout).\n"
                "PMFUZZ_PROBE dut=cva6-clean probe=cva6_mmu_pmp_check "
                "schema=2 role=diagnostic chain=pmp-check stage=final "
                "addr=0x10000 prv=3 access=fetch allow=1\n"
                "PMFUZZ_PROBE dut=cva6-clean probe=cva6_mmu_pmp_check "
                "schema=2 role=diagnostic chain=pmp-check stage=final "
                "addr=0x2000004 prv=3 access=load allow=1\n"
                "[50001000] %Fatal: TestDriver.v:147: Assertion failed in TOP.TestDriver\n"
            ),
            stderr=(
                "PMFUZZ_PROBE dut=cva6-clean probe=cva6_tlb_exception_arbitration "
                "schema=2 role=diagnostic chain=exception-arbitration stage=tlb "
                "vaddr=0x10000 hit=0 flush=0 update=0\n"
                "*** FAILED ***                       (timeout) after                50001 simulation cycles\n"
            ),
        )

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(
                cascade._SIM_BINARIES, {"cva6-clean": str(real_binary)}, clear=False
            ):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        meta = cascade.run_cascade_baseline(
                            dut="cva6-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            coverage_mode="bapc",
                            bapc_core_version="v4",
                        )

            coverage = json.loads(
                (out_dir / "metrics" / "coverage" / "coverage.json").read_text(encoding="ascii")
            )
            events = json.loads((out_dir / "events.json").read_text(encoding="ascii"))

        self.assertEqual(meta["eligible_bapc_cases"], 0)
        self.assertEqual(meta["bapc_covered"], 0)
        self.assertFalse(events[0]["bapc_eligible"])
        self.assertEqual(
            events[0]["bapc_coverage"]["qualification_reason"],
            "missing-actual-runtime-record",
        )
        observed = coverage["execution_coverage"]["by_dut"]["cva6-clean"]["bapc"]["covered_bins"]
        self.assertEqual(observed, [])

    def test_bapc_campaign_uses_runtime_allow_records_when_failed_execution_lacks_runtime_deny_record(self):
        sidecar = _fake_sidecar()
        sidecar["translation"] = "sv39"

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(
                json.dumps(sidecar, indent=2, ensure_ascii=True) + "\n",
                encoding="ascii",
            )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(
            returncode=255,
            stdout="",
            stderr=(
                "PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker "
                "chain=pmp-check stage=final prv=3 access=fetch allow=1 addr=0x80008020 r=1 w=1 x=1\n"
                "PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker "
                "chain=pmp-check stage=final prv=3 access=load allow=1 addr=0x80008020 r=1 w=1 x=1\n"
                "*** FAILED ***                       (timeout) after                50001 simulation cycles\n"
            ),
        )

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(
                cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False
            ):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        meta = cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            coverage_mode="bapc",
                        )

            coverage = json.loads(
                (out_dir / "metrics" / "coverage" / "coverage.json").read_text(encoding="ascii")
            )

        observed = set(
            coverage["execution_coverage"]["by_dut"]["rocket-clean"]["bapc"]["covered_bins"]
        )
        self.assertEqual(meta["eligible_bapc_cases"], 1)
        self.assertIn(
            "family=decision|access=fetch|allow_or_deny=allow|mcause_class=none",
            observed,
        )
        self.assertIn(
            "family=decision|access=load|allow_or_deny=allow|mcause_class=none",
            observed,
        )
        self.assertNotIn(
            "family=decision|access=load|allow_or_deny=deny|mcause_class=load_access_fault",
            observed,
        )

    def test_bapc_campaign_recovers_boom_target_operation_when_sidecar_lacks_explicit_context(self):
        sidecar = {
            "campaign_seed": 101,
            "case_index": 0,
            "derived_instance_id": 101,
            "design": "boom",
            "translation": "bare",
            "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
            "pmp_entries": [
                {
                    "index": 0,
                    "address_mode": "napot",
                    "pmpaddr": "0x20001fff",
                    "read": False,
                    "write": True,
                    "execute": False,
                    "locked": False,
                }
            ],
            "actual_csr_state": {"mstatus": 0},
        }

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(
                json.dumps(sidecar, indent=2, ensure_ascii=True) + "\n",
                encoding="ascii",
            )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(
            returncode=255,
            stdout="",
            stderr=(
                "PMFUZZ_PROBE dut=boom-clean probe=boom_lsu_tlb_pmp_check "
                "schema=2 role=diagnostic chain=pmp-check stage=final "
                "addr=0x80008020 prv=1 access=0 size=4 r=0 w=1 x=0\n"
                "*** FAILED ***                       (timeout) after                50001 simulation cycles\n"
            ),
        )

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(
                cascade._SIM_BINARIES, {"boom-clean": str(real_binary)}, clear=False
            ):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        meta = cascade.run_cascade_baseline(
                            dut="boom-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            coverage_mode="bapc",
                        )

            events = json.loads((out_dir / "events.json").read_text(encoding="ascii"))

        self.assertEqual(meta["eligible_bapc_cases"], 1)
        self.assertGreater(meta["bapc_covered"], 0)
        self.assertTrue(events[0]["bapc_eligible"])
        self.assertEqual(events[0]["bapc_coverage"]["qualification_reason"], "eligible")

    def test_bapc_baseline_formal_metadata_contains_complete_protocol_fields(self):
        sidecar = _fake_sidecar() | {"design": "boom"}

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(json.dumps(sidecar, ensure_ascii=True), encoding="ascii")
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(returncode=0, stdout="*** PASSED ***\n", stderr="")
        monotonic_values = iter([0.0, 0.0, 7200.0, 7200.0, 7200.0, 7200.0])

        def fake_monotonic():
            try:
                return next(monotonic_values)
            except StopIteration:
                return 7200.0

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            expected_binary_path = str(real_binary.resolve())
            expected_binary_sha = hashlib.sha256(real_binary.read_bytes()).hexdigest()
            with patch.dict(cascade._SIM_BINARIES, {"boom-clean": str(real_binary)}, clear=False):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        with patch.object(cascade, "_git_head_sha", return_value="a" * 40):
                            with patch.object(cascade, "_source_tree_sha256", return_value="b" * 64):
                                with patch.object(cascade, "_git_is_dirty", return_value=False):
                                    with patch.object(cascade.time, "monotonic", side_effect=fake_monotonic):
                                        meta = cascade.run_cascade_baseline(
                                            dut="boom-clean",
                                            num_elfs=1,
                                            simlen=100,
                                            timeout_seconds=5,
                                            out_dir=out_dir,
                                            seed=4,
                                            coverage_mode="bapc",
                                            experiment_id="boom-formal",
                                            campaign_id="cascade-formal-seed4",
                                            experiment_protocol_id=BAPC_CONVERGENCE_PROTOCOL_ID,
                                            run_class="baseline-formal",
                                            budget_class="primary-wall-clock",
                                            max_wall_time_seconds=7200,
                                            dut_bin=real_binary,
                                        )
            expected_capability_fingerprint = json.loads(
                (out_dir / "metrics" / "coverage_universe" / "bapc_v2.json").read_text(encoding="ascii")
            )["capability_fingerprint"]

        for field in (
            "experiment_id",
            "campaign_id",
            "experiment_protocol_id",
            "method",
            "run_class",
            "budget_class",
            "convergence_enabled",
            "convergence_min_runtime_seconds",
            "convergence_confirmation_seconds",
            "convergence_confirmation_eligible_cases",
            "max_wall_time_seconds",
            "time_budget_seconds",
            "wall_clock_horizon_seconds",
            "source_sha",
            "source_sha_status",
            "source_tree_sha256",
            "source_dirty",
            "dut_sha_status",
            "dut_binary_path",
            "dut_binary_sha256",
            "capability_fingerprint",
            "coverage_universe_hashes",
            "coverage_universe_files",
            "bapc_schema_version",
            "command_line",
            "batch_size",
            "round_size",
            "per_case_timeout",
            "per_case_timeout_seconds",
        ):
            self.assertIn(field, meta, field)
        self.assertEqual(meta["experiment_protocol_id"], BAPC_CONVERGENCE_PROTOCOL_ID)
        self.assertEqual(meta["run_class"], "baseline-formal")
        self.assertEqual(meta["budget_class"], "primary-wall-clock")
        self.assertEqual(meta["time_budget_seconds"], 7200.0)
        self.assertEqual(meta["wall_clock_horizon_seconds"], 7200.0)
        self.assertEqual(meta["convergence_confirmation_seconds"], 600.0)
        self.assertEqual(meta["convergence_confirmation_eligible_cases"], 300)
        self.assertFalse(meta["source_dirty"])
        self.assertEqual(meta["source_sha"], "a" * 40)
        self.assertEqual(meta["source_tree_sha256"], "b" * 64)
        self.assertEqual(meta["dut_binary_path"], expected_binary_path)
        self.assertEqual(meta["dut_binary_sha256"], expected_binary_sha)
        self.assertEqual(meta["capability_fingerprint"], expected_capability_fingerprint)

    def test_bapc_formal_requires_protocol_id_before_simulator_launch(self):
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.object(
                cascade,
                "_generate_elfs",
                side_effect=AssertionError("formal preflight must fail before generation"),
            ):
                with patch.object(
                    cascade.subprocess,
                    "run",
                    side_effect=AssertionError("formal preflight must fail before DUT execution"),
                ):
                    with self.assertRaisesRegex(ValueError, "protocol"):
                        cascade.run_cascade_baseline(
                            dut="boom-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=4,
                            coverage_mode="bapc",
                            experiment_id="boom-formal",
                            campaign_id="cascade-formal-seed4",
                            experiment_protocol_id="",
                            run_class="baseline-formal",
                            budget_class="primary-wall-clock",
                            dut_bin=real_binary,
                        )

    def test_bapc_formal_rejects_explicit_wrong_protocol_parameters(self):
        scenarios = [
            ("min_runtime_seconds", 1),
            ("confirmation_seconds", 601),
            ("confirmation_eligible_cases", 301),
            ("max_wall_time_seconds", 28800),
            ("budget_class", "secondary-wall-clock"),
        ]
        for field, bad_value in scenarios:
            with self.subTest(field=field, bad_value=bad_value):
                with TemporaryDirectory() as tmp:
                    out_dir = Path(tmp) / "campaign"
                    real_binary = Path(tmp) / "sim"
                    real_binary.write_bytes(b"binary-content")
                    kwargs = {
                        "dut": "boom-clean",
                        "num_elfs": 1,
                        "simlen": 100,
                        "timeout_seconds": 5,
                        "out_dir": out_dir,
                        "seed": 4,
                        "coverage_mode": "bapc",
                        "experiment_id": "boom-formal",
                        "campaign_id": "cascade-formal-seed4",
                        "experiment_protocol_id": BAPC_CONVERGENCE_PROTOCOL_ID,
                        "run_class": "baseline-formal",
                        "budget_class": "primary-wall-clock",
                        "dut_bin": real_binary,
                    }
                    kwargs[field] = bad_value
                    with patch.object(
                        cascade,
                        "_generate_elfs",
                        side_effect=AssertionError("formal preflight must fail before generation"),
                    ):
                        with patch.object(
                            cascade.subprocess,
                            "run",
                            side_effect=AssertionError("formal preflight must fail before DUT execution"),
                        ):
                            with self.assertRaisesRegex(ValueError, field):
                                cascade.run_cascade_baseline(**kwargs)

    def test_bapc_formal_contract_manifest_is_full_matrix_from_first_campaign(self):
        with TemporaryDirectory() as tmp:
            artifact_root = Path(tmp)
            universe = build_bapc_coverage_universe(
                dut="boom-clean",
                generator_seed=1,
                supports_fault_stage=True,
                supports_smepmp=False,
            )
            cascade._update_experiment_contract_manifest(
                artifact_root=artifact_root,
                dut="boom-clean",
                variant_label="cascade",
                seed=4,
                coverage_mode="bapc",
                experiment_protocol_id=BAPC_CONVERGENCE_PROTOCOL_ID,
                universe=universe,
            )
            contract = json.loads(
                (artifact_root / "manifests" / "experiment-contract.json").read_text(
                    encoding="ascii"
                )
            )

        self.assertEqual(
            sorted(contract["variants"]),
            ["bb-guided", "cascade", "random-mutation"],
        )
        self.assertEqual(contract["seeds"], [4, 5, 6])

    def test_bapc_v3_campaign_writes_v3_universe_file_and_hash(self):
        sidecar = _fake_sidecar()

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(
                json.dumps(sidecar, indent=2, ensure_ascii=True) + "\n",
                encoding="ascii",
            )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(returncode=0, stdout="*** PASSED ***\n", stderr="")

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        meta = cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            coverage_mode="bapc",
                            bapc_core_version="v3",
                        )
            universe = json.loads(
                (out_dir / "metrics" / "coverage_universe" / "bapc_v3.json").read_text(
                    encoding="ascii"
                )
            )

        self.assertEqual(meta["coverage_mode"], "bapc")
        self.assertEqual(meta["coverage_universe_hashes"]["bapc"], universe["sha256"])
        self.assertEqual(Path(meta["coverage_universe_files"]["bapc"]).name, "bapc_v3.json")
        self.assertEqual(universe["bin_count"], 129)

    def test_bapc_v4_campaign_writes_v4_universe_file_and_hash(self):
        sidecar = _fake_sidecar()

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(
                json.dumps(sidecar, indent=2, ensure_ascii=True) + "\n",
                encoding="ascii",
            )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(returncode=0, stdout="*** PASSED ***\n", stderr="")

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        meta = cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            coverage_mode="bapc",
                            bapc_core_version="v4",
                        )
            universe = json.loads(
                (out_dir / "metrics" / "coverage_universe" / "bapc_v4.json").read_text(
                    encoding="ascii"
                )
            )

        self.assertEqual(meta["coverage_mode"], "bapc")
        self.assertEqual(meta["bapc_target"], 144)
        self.assertEqual(meta["coverage_universe_hashes"]["bapc"], universe["sha256"])
        self.assertEqual(Path(meta["coverage_universe_files"]["bapc"]).name, "bapc_v4.json")
        self.assertEqual(universe["bin_count"], 144)

    def test_bapc_v4_campaign_ingests_noncanonical_off_readback_from_sidecar(self):
        sidecar = _fake_sidecar()
        sidecar["pmp_entries"] = [
            {
                "index": 0,
                "address_mode": "off",
                "pmpaddr": "0x0",
                "read": True,
                "write": True,
                "execute": True,
                "locked": True,
            }
        ]
        sidecar["actual_csr_state"] = {"mstatus": 0, "pmpcfg0": 0x84, "pmpaddr0": 0}

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(
                json.dumps(sidecar, indent=2, ensure_ascii=True) + "\n",
                encoding="ascii",
            )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(returncode=0, stdout="*** PASSED ***\n", stderr="")

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            coverage_mode="bapc",
                            bapc_core_version="v4",
                        )
            events = json.loads((out_dir / "events.json").read_text(encoding="ascii"))
            result = events[0]

        self.assertEqual(result["bapc_coverage"]["bapc_core_version"], "v4")
        self.assertIn(
            "family=config|pmp_mode=off|permission_rwx=000|locked=false",
            result["bapc_coverage"]["observed_bins"],
        )
        self.assertNotIn("actual_pmpcfg_entries", result["bapc_coverage"]["event_records"][0])

    def test_bapc_formal_contract_manifest_is_immutable(self):
        with TemporaryDirectory() as tmp:
            artifact_root = Path(tmp)
            manifests_dir = artifact_root / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            universe = build_bapc_coverage_universe(
                dut="boom-clean",
                generator_seed=1,
                supports_fault_stage=True,
                supports_smepmp=False,
            )
            payload = build_bapc_convergence_contract(
                dut="boom-clean",
                bin_count=int(universe["bin_count"]),
                bin_set_sha256=str(universe["bin_set_sha256"]),
                variants=["cascade"],
                seeds=[4],
            )
            contract_path = manifests_dir / "experiment-contract.json"
            original = json.dumps(payload, indent=2, ensure_ascii=True) + "\n"
            contract_path.write_text(original, encoding="ascii")

            with self.assertRaisesRegex(ValueError, "experiment-contract"):
                cascade._update_experiment_contract_manifest(
                    artifact_root=artifact_root,
                    dut="boom-clean",
                    variant_label="cascade",
                    seed=4,
                    coverage_mode="bapc",
                    experiment_protocol_id=BAPC_CONVERGENCE_PROTOCOL_ID,
                    universe=universe,
                )

            self.assertEqual(contract_path.read_text(encoding="ascii"), original)

    def test_bapc_formal_infra_failure_uses_same_protocol_metadata_schema(self):
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            missing_binary = Path(tmp) / "missing-sim"
            with patch.object(cascade, "_git_head_sha", return_value="a" * 40):
                with patch.object(cascade, "_source_tree_sha256", return_value="b" * 64):
                    with patch.object(cascade, "_git_is_dirty", return_value=False):
                        meta = cascade.run_cascade_baseline(
                            dut="boom-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=4,
                            coverage_mode="bapc",
                            experiment_id="boom-formal",
                            campaign_id="cascade-formal-seed4",
                            experiment_protocol_id=BAPC_CONVERGENCE_PROTOCOL_ID,
                            run_class="baseline-formal",
                            budget_class="primary-wall-clock",
                            max_wall_time_seconds=7200,
                            dut_bin=missing_binary,
                        )

        self.assertEqual(meta["status"], "infra_failure")
        self.assertEqual(meta["experiment_protocol_id"], BAPC_CONVERGENCE_PROTOCOL_ID)
        self.assertEqual(meta["run_class"], "baseline-formal")
        self.assertEqual(meta["budget_class"], "primary-wall-clock")
        self.assertEqual(meta["time_budget_seconds"], 7200.0)
        self.assertEqual(meta["wall_clock_horizon_seconds"], 7200.0)
        self.assertEqual(meta["dut_binary_path"], str(missing_binary.resolve()))
        self.assertEqual(meta["source_sha"], "a" * 40)
        self.assertEqual(meta["source_tree_sha256"], "b" * 64)
        self.assertEqual(meta["bapc_core_version"], "v2")
        self.assertEqual(meta["bapc_target"], 208)
        self.assertEqual(meta["coverage_universe_files"]["bapc"], "metrics/coverage_universe/bapc_v2.json")

    def test_bapc_formal_without_batch_size_forces_continuous_mode(self):
        sidecar = _fake_sidecar() | {"design": "boom"}

        def fake_generate(num_elfs, out_dir, *, seed, design, start_index=0, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_{start_index}.elf"
            sidecar_path = out_dir / f"{design}_{start_index}.json"
            elf_path.write_bytes(f"ELF-{start_index}".encode("ascii"))
            sidecar_path.write_text(json.dumps(sidecar, ensure_ascii=True), encoding="ascii")
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": start_index,
                "elf_hashes": {elf_path.name: f"sha-case-{start_index}"},
                "per_case": [
                    {
                        "case_index": start_index,
                        "elf": elf_path.name,
                        "elf_sha256": f"sha-case-{start_index}",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(returncode=0, stdout="*** PASSED ***\n", stderr="")
        monotonic_values = iter([0.0, 0.0, 7200.0, 7200.0, 7200.0, 7200.0])

        def fake_monotonic():
            try:
                return next(monotonic_values)
            except StopIteration:
                return 7200.0

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(cascade._SIM_BINARIES, {"boom-clean": str(real_binary)}, clear=False):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        with patch.object(cascade, "_git_head_sha", return_value="a" * 40):
                            with patch.object(cascade, "_source_tree_sha256", return_value="b" * 64):
                                with patch.object(cascade, "_git_is_dirty", return_value=False):
                                    with patch.object(cascade.time, "monotonic", side_effect=fake_monotonic):
                                        meta = cascade.run_cascade_baseline(
                                            dut="boom-clean",
                                            num_elfs=1,
                                            simlen=100,
                                            timeout_seconds=5,
                                            out_dir=out_dir,
                                            seed=4,
                                            coverage_mode="bapc",
                                            experiment_id="boom-formal",
                                            campaign_id="cascade-formal-seed4",
                                            experiment_protocol_id=BAPC_CONVERGENCE_PROTOCOL_ID,
                                            run_class="baseline-formal",
                                            budget_class="primary-wall-clock",
                                            max_wall_time_seconds=7200,
                                            dut_bin=real_binary,
                                        )

        self.assertEqual(meta["generation_mode"], "continuous-batches")
        self.assertTrue(meta["convergence_enabled"])

    def test_bapc_formal_never_stops_as_completed_requested_cases(self):
        sidecar = _fake_sidecar() | {"design": "boom"}

        def fake_generate(num_elfs, out_dir, *, seed, design, start_index=0, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_{start_index}.elf"
            sidecar_path = out_dir / f"{design}_{start_index}.json"
            elf_path.write_bytes(f"ELF-{start_index}".encode("ascii"))
            sidecar_path.write_text(json.dumps(sidecar, ensure_ascii=True), encoding="ascii")
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": start_index,
                "elf_hashes": {elf_path.name: f"sha-case-{start_index}"},
                "per_case": [
                    {
                        "case_index": start_index,
                        "elf": elf_path.name,
                        "elf_sha256": f"sha-case-{start_index}",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(returncode=0, stdout="*** PASSED ***\n", stderr="")
        monotonic_values = iter([0.0, 0.0, 7200.0, 7200.0, 7200.0, 7200.0])

        def fake_monotonic():
            try:
                return next(monotonic_values)
            except StopIteration:
                return 7200.0

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(cascade._SIM_BINARIES, {"boom-clean": str(real_binary)}, clear=False):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        with patch.object(cascade, "_git_head_sha", return_value="a" * 40):
                            with patch.object(cascade, "_source_tree_sha256", return_value="b" * 64):
                                with patch.object(cascade, "_git_is_dirty", return_value=False):
                                    with patch.object(cascade.time, "monotonic", side_effect=fake_monotonic):
                                        meta = cascade.run_cascade_baseline(
                                            dut="boom-clean",
                                            num_elfs=1,
                                            simlen=100,
                                            timeout_seconds=5,
                                            out_dir=out_dir,
                                            seed=4,
                                            coverage_mode="bapc",
                                            experiment_id="boom-formal",
                                            campaign_id="cascade-formal-seed4",
                                            experiment_protocol_id=BAPC_CONVERGENCE_PROTOCOL_ID,
                                            run_class="baseline-formal",
                                            budget_class="primary-wall-clock",
                                            max_wall_time_seconds=7200,
                                            dut_bin=real_binary,
                                        )

        self.assertNotEqual(meta["stop_reason"], "completed_requested_cases")
        self.assertEqual(meta["stop_reason"], "hard_cap_censored")

    def test_bapc_formal_boom_dut_sha_uses_explicit_dut_source_dir(self):
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            missing_binary = Path(tmp) / "missing-sim"
            dut_source_dir = Path(tmp) / "isolated-chipyard"
            dut_source_dir.mkdir(parents=True, exist_ok=True)

            def fake_git_head_sha(cwd=None):
                path = Path(cwd or cascade._project_root()).resolve()
                if path == dut_source_dir.resolve():
                    return "d" * 40
                return "a" * 40

            with patch.object(cascade, "_git_head_sha", side_effect=fake_git_head_sha):
                with patch.object(cascade, "_source_tree_sha256", return_value="b" * 64):
                    with patch.object(cascade, "_git_is_dirty", return_value=False):
                        meta = cascade.run_cascade_baseline(
                            dut="boom-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=4,
                            coverage_mode="bapc",
                            experiment_id="boom-formal",
                            campaign_id="cascade-formal-seed4",
                            experiment_protocol_id=BAPC_CONVERGENCE_PROTOCOL_ID,
                            run_class="baseline-formal",
                            budget_class="primary-wall-clock",
                            max_wall_time_seconds=7200,
                            dut_bin=missing_binary,
                            dut_source_dir=dut_source_dir,
                        )

        self.assertEqual(meta["dut_sha"], "d" * 40)

    def test_bapc_formal_hard_cap_fixture_validates_against_experiment_contract(self):
        sidecar = _fake_sidecar() | {"design": "boom"}

        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_path = out_dir / f"{design}_0.elf"
            sidecar_path = out_dir / f"{design}_0.json"
            elf_path.write_bytes(b"ELF")
            sidecar_path.write_text(json.dumps(sidecar, ensure_ascii=True), encoding="ascii")
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": 0,
                "elf_hashes": {elf_path.name: "sha-case-0"},
                "per_case": [
                    {
                        "case_index": 0,
                        "elf": elf_path.name,
                        "elf_sha256": "sha-case-0",
                        "sidecar": sidecar_path.name,
                        "sidecar_data": sidecar,
                    }
                ],
            }

        process = unittest.mock.Mock(returncode=0, stdout="*** PASSED ***\n", stderr="")
        monotonic_values = iter([0.0, 0.0, 7200.0, 7200.0, 7200.0])

        def fake_monotonic():
            try:
                return next(monotonic_values)
            except StopIteration:
                return 7200.0

        with TemporaryDirectory() as tmp:
            artifact_root = Path(tmp) / "artifact"
            out_dir = artifact_root / "campaigns" / "boom-formal" / "boom-clean" / "cascade" / "bapc" / "seed-0004"
            manifests_dir = artifact_root / "manifests"
            manifests_dir.mkdir(parents=True, exist_ok=True)
            (manifests_dir / "environment.json").write_text(json.dumps({"platform": "linux"}), encoding="ascii")
            (manifests_dir / "git-shas.txt").write_text(("a" * 40) + "  pmpfuzz\n", encoding="ascii")
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(cascade._SIM_BINARIES, {"boom-clean": str(real_binary)}, clear=False):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        with patch.object(cascade, "_git_head_sha", return_value="a" * 40):
                            with patch.object(cascade, "_source_tree_sha256", return_value="b" * 64):
                                with patch.object(cascade, "_git_is_dirty", return_value=False):
                                    with patch.object(cascade.time, "monotonic", side_effect=fake_monotonic):
                                        meta = cascade.run_cascade_baseline(
                                            dut="boom-clean",
                                            num_elfs=1,
                                            simlen=100,
                                            timeout_seconds=5,
                                            out_dir=out_dir,
                                            seed=4,
                                            coverage_mode="bapc",
                                            experiment_id="boom-formal",
                                            campaign_id="cascade-formal-seed4",
                                            experiment_protocol_id=BAPC_CONVERGENCE_PROTOCOL_ID,
                                            run_class="baseline-formal",
                                            budget_class="primary-wall-clock",
                                            min_runtime_seconds=0.0,
                                            confirmation_seconds=600.0,
                                            confirmation_eligible_cases=300,
                                            max_wall_time_seconds=7200,
                                            dut_bin=real_binary,
                                        )
            universe = json.loads(
                (out_dir / "metrics" / "coverage_universe" / "bapc_v2.json").read_text(encoding="ascii")
            )
            (manifests_dir / "experiment-contract.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "experiment_protocol_id": BAPC_CONVERGENCE_PROTOCOL_ID,
                        "dut": "boom-clean",
                        "coverage_mode": "bapc",
                        "bin_count": 208,
                        "bin_set_sha256": universe["bin_set_sha256"],
                        "variants": ["random-mutation", "bb-guided", "cascade"],
                        "seeds": [4, 5, 6],
                        **BAPC_CONVERGENCE_FORMAL,
                    },
                    ensure_ascii=True,
                    indent=2,
                ),
                encoding="ascii",
            )
            tracked = []
            for rel in (
                Path("campaigns/boom-formal/boom-clean/cascade/bapc/seed-0004/metrics/campaign_metadata.json"),
                Path("campaigns/boom-formal/boom-clean/cascade/bapc/seed-0004/metrics/coverage_timeline.jsonl"),
                Path("campaigns/boom-formal/boom-clean/cascade/bapc/seed-0004/coverage/coverage.json"),
            ):
                payload = (artifact_root / rel).read_bytes()
                tracked.append(f"{hashlib.sha256(payload).hexdigest()}  {rel.as_posix()}")
            (manifests_dir / "artifact-sha256.txt").write_text("\n".join(tracked) + "\n", encoding="ascii")
            report = validate_timeline(out_dir)
            metadata_rel = Path("metrics/campaign_metadata.json")
            metadata_sha = hashlib.sha256((out_dir / metadata_rel).read_bytes()).hexdigest()

        self.assertEqual(meta["stop_reason"], "hard_cap_censored")
        self.assertTrue(report["valid"], report)
        self.assertEqual(report["stop_reason"], "hard_cap_censored")
        self.assertEqual(report["inputs"]["metadata"]["path"], metadata_rel.as_posix())
        self.assertEqual(report["inputs"]["metadata"]["sha256"], metadata_sha)


if __name__ == "__main__":
    unittest.main()
