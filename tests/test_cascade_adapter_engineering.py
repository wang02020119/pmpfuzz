"""Engineering-only contract tests for the Cascade evaluation adapter."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.evaluation.baseline_adapters import cascade
from pmpfuzz.hpm import manifest_for_dut


def _generator_run_commands(mock_run):
    commands = []
    for call in mock_run.call_args_list:
        if not call.args:
            continue
        cmd = call.args[0]
        if not isinstance(cmd, list):
            continue
        if cmd[:3] != ["docker", "exec", cascade.CASCADE_CONTAINER]:
            continue
        if len(cmd) < 6 or "python3 " not in cmd[5] or "cascade_generate_campaign.py" not in cmd[5]:
            continue
        commands.append(cmd)
    return commands


def _last_generator_bash_script(mock_run):
    commands = _generator_run_commands(mock_run)
    if not commands:
        raise AssertionError(f"generator docker exec call not found: {mock_run.call_args_list}")
    return commands[-1][5]


def _helper_copy_command(mock_run):
    for call in mock_run.call_args_list:
        if not call.args:
            continue
        cmd = call.args[0]
        if not isinstance(cmd, list):
            continue
        if cmd[:2] != ["docker", "cp"]:
            continue
        if len(cmd) < 4 or not str(cmd[2]).endswith("cascade_generate_campaign.py"):
            continue
        return cmd
    raise AssertionError(f"generator docker cp helper call not found: {mock_run.call_args_list}")



class TestCascadeDutMatrix(unittest.TestCase):
    def test_adapter_declares_all_evaluation_duts(self):
        self.assertEqual(
            set(cascade.SUPPORTED_DUTS),
            {"rocket-clean", "boom-clean", "xiangshan-clean", "cva6-clean"},
        )

    def test_simulator_commands_are_dut_specific(self):
        elf = Path("/tmp/case.elf")
        rocket_command, _ = cascade._simulator_command("rocket-clean", elf, 1234)
        cva6_command, _ = cascade._simulator_command("cva6-clean", elf, 1234)
        xiangshan_command, _ = cascade._simulator_command("xiangshan-clean", elf, 1234)

        self.assertIn("RocketConfig", rocket_command[0])
        self.assertIn("+permissive", rocket_command)
        self.assertIn("+max-cycles=1234", rocket_command)
        self.assertIn(f"+loadmem={elf.as_posix()}", rocket_command)
        self.assertIn("+permissive-off", rocket_command)
        self.assertEqual(rocket_command[-1], elf.as_posix())
        self.assertLess(
            rocket_command.index(f"+loadmem={elf.as_posix()}"),
            rocket_command.index("+permissive-off"),
        )
        self.assertIn("CVA6Config", cva6_command[0])
        self.assertIn("+max-cycles=1234", cva6_command)
        self.assertEqual(xiangshan_command[1:3], ["--no-diff", "-C"])
        self.assertIn("1234", xiangshan_command)
        self.assertEqual(xiangshan_command[-2:], ["-i", str(elf)])

    def test_xiangshan_simulator_command_exports_structured_diag_env(self):
        elf = Path("/tmp/case.elf")

        with patch.object(
            cascade,
            "xiangshan_diag_env_for_image",
            return_value={
                "PMFUZZ_TOHOST_ADDR": "0x80002080",
                "PMFUZZ_RESULT_SLOT_ADDR": "0x80002060",
            },
        ):
            _, env = cascade._simulator_command("xiangshan-clean", elf, 1234)

        self.assertEqual(env["PMFUZZ_TOHOST_ADDR"], "0x80002080")
        self.assertEqual(env["PMFUZZ_RESULT_SLOT_ADDR"], "0x80002060")

    def test_simulator_command_uses_explicit_binary_override(self):
        elf = Path("/tmp/case.elf")
        command, _ = cascade._simulator_command(
            "boom-clean",
            elf,
            1234,
            dut_binary=Path("/tmp/custom-boom-sim"),
        )

        self.assertEqual(command[0], "/tmp/custom-boom-sim")


class TestCascadeGenerationIsolation(unittest.TestCase):
    def test_generation_workspace_is_campaign_specific_and_stable(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                first = cascade._generation_workspace(Path("/artifacts/a"), seed=101)
                repeated = cascade._generation_workspace(Path("/artifacts/a"), seed=101)
                other = cascade._generation_workspace(Path("/artifacts/b"), seed=101)

        self.assertEqual(first, repeated)
        self.assertNotEqual(first, other)
        self.assertEqual(first.parent.name, "cascade-campaigns")

    def test_artifact_root_prefers_current_campaign_tree_over_parent_manifest(self):
        with TemporaryDirectory() as tmp:
            shared_root = Path(tmp) / "bapc-convergence"
            current_root = shared_root / "rocket-clean-cascade-test"
            (shared_root / "manifests").mkdir(parents=True)
            out_dir = (
                current_root
                / "campaigns"
                / "experiment"
                / "rocket-clean"
                / "cascade"
                / "bapc"
                / "seed-0004"
            )
            out_dir.mkdir(parents=True)

            resolved = cascade._resolve_artifact_root_for_campaign(out_dir)

        self.assertEqual(resolved, current_root.resolve())

    def test_hpm_manifest_is_forwarded_to_container_helper(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = unittest.mock.Mock(returncode=0, stderr="")
                    out = Path(tmp) / "out"
                    manifest = Path(tmp) / "hpm_manifest.json"
                    manifest.write_text(json.dumps(manifest_for_dut("rocket-clean")), encoding="ascii")
                    cascade._generate_elfs(
                        1,
                        out,
                        seed=7,
                        design="rocket",
                        hpm_manifest_path=manifest,
                    )
                    bash_script = _last_generator_bash_script(mock_run)
        self.assertIn("--hpm-manifest", bash_script)
        self.assertIn("hpm_manifest.json", bash_script)

    def test_generator_stages_helper_outside_workspace_mount(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = unittest.mock.Mock(returncode=0, stderr="")
                    out = Path(tmp) / "out"
                    cascade._generate_elfs(
                        1,
                        out,
                        seed=7,
                        design="rocket",
                    )
                    bash_script = _last_generator_bash_script(mock_run)
                    copy_cmd = _helper_copy_command(mock_run)
        self.assertIn("/tmp/pmpfuzz-cascade-", bash_script)
        self.assertIn("cascade_generate_campaign.py", bash_script)
        self.assertTrue(copy_cmd[3].startswith(f"{cascade.CASCADE_CONTAINER}:/tmp/pmpfuzz-cascade-"))

    def test_generator_bootstraps_cascade_pythonpath_inside_container(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = unittest.mock.Mock(returncode=0, stderr="")
                    out = Path(tmp) / "out"
                    cascade._generate_elfs(
                        1,
                        out,
                        seed=7,
                        design="rocket",
                    )
                    bash_script = _last_generator_bash_script(mock_run)
        self.assertIn("export PYTHONPATH=/cascade-meta/fuzzer", bash_script)

    def test_generator_can_require_single_target_operation_sidecars(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = unittest.mock.Mock(returncode=0, stderr="")
                    out = Path(tmp) / "out"
                    cascade._generate_elfs(
                        1,
                        out,
                        seed=7,
                        design="rocket",
                        require_single_target_operation=True,
                    )
                    bash_script = _last_generator_bash_script(mock_run)
        self.assertIn("--require-single-target-operation", bash_script)

    def test_generator_can_require_nonempty_target_operation_sidecars(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = unittest.mock.Mock(returncode=0, stderr="")
                    out = Path(tmp) / "out"
                    cascade._generate_elfs(
                        1,
                        out,
                        seed=7,
                        design="rocket",
                        require_target_operation_candidate=True,
                    )
                    bash_script = _last_generator_bash_script(mock_run)
        self.assertIn("--require-target-operation-candidate", bash_script)
        self.assertNotIn("--require-single-target-operation", bash_script)

    def test_target_operation_candidates_preserve_generation_order(self):
        from scripts.evaluation.baseline_adapters import cascade_generate_campaign as helper

        class FakeInstr:
            def __init__(self, producer_id: int):
                self.instr_str = "lw"
                self.producer_id = producer_id
                self.imm = 0

        instr_objs_seq = [[]]
        bb_start_addr_seq = [0]
        producer_map = {}
        for bb_id, producer_id in ((2, 2), (10, 10)):
            while len(instr_objs_seq) <= bb_id:
                instr_objs_seq.append([])
                bb_start_addr_seq.append(0x40 * len(bb_start_addr_seq))
            instr_objs_seq[bb_id] = [FakeInstr(producer_id)]
            producer_map[producer_id] = 0x1000 + producer_id

        fake_state = unittest.mock.Mock(
            instr_objs_seq=instr_objs_seq,
            bb_start_addr_seq=bb_start_addr_seq,
            producer_id_to_tgtaddr=producer_map,
            design_base_addr=0x80000000,
        )

        candidates = helper._extract_target_operation_candidates(fake_state)

        self.assertEqual(
            [candidate["target_operation_id"] for candidate in candidates],
            ["bb2-i0", "bb10-i0"],
        )

    def test_target_operation_candidates_include_floating_point_memory_ops(self):
        from scripts.evaluation.baseline_adapters import cascade_generate_campaign as helper

        class FakeInstr:
            def __init__(self, mnemonic: str):
                self.instr_str = mnemonic
                self.imm = 0

        fake_state = unittest.mock.Mock(
            instr_objs_seq=[[], [FakeInstr("fsw"), FakeInstr("flw"), FakeInstr("fsd")]],
            bb_start_addr_seq=[0, 0x40],
            producer_id_to_tgtaddr={},
            design_base_addr=0x80000000,
        )

        candidates = helper._extract_target_operation_candidates(fake_state)

        self.assertEqual(
            [candidate["target_operation_id"] for candidate in candidates],
            ["bb1-i0", "bb1-i1", "bb1-i2"],
        )
        self.assertEqual(
            [(candidate["access"], candidate["size"]) for candidate in candidates],
            [("store", 4), ("load", 4), ("store", 8)],
        )
        self.assertEqual(
            [candidate["instruction_address"] for candidate in candidates],
            ["0x80000040", "0x80000044", "0x80000048"],
        )
        self.assertTrue(all("physical_address" not in candidate for candidate in candidates))

    def test_cva6_reserved_fence_encodings_are_canonicalized_before_elf_emission(self):
        from scripts.evaluation.baseline_adapters import cascade_generate_campaign as helper

        class FakeInstr:
            def __init__(self, instr_str: str, word: int):
                self.instr_str = instr_str
                self._word = int(word) & 0xFFFFFFFF

            def gen_bytecode_int(self, is_spike_resolution: bool):
                return self._word

        fake_state = unittest.mock.Mock(
            instr_objs_seq=[
                [],
                [
                    FakeInstr("fence.i", 0x0002928F),
                    FakeInstr("fence", 0x0FF2020F),
                    FakeInstr("addi", 0x00200113),
                ],
            ],
            final_bb=[
                FakeInstr("fence.i", 0x0004100F),
                FakeInstr("fence", 0x0FF3828F),
            ],
            ctxsv_bb=[],
            ctxdmp_bb=[],
        )

        canonicalized = helper._canonicalize_cva6_reserved_special_instructions(fake_state)

        self.assertEqual(canonicalized, 4)
        self.assertEqual(fake_state.instr_objs_seq[1][0].gen_bytecode_int(False), 0x0000100F)
        self.assertEqual(fake_state.instr_objs_seq[1][1].gen_bytecode_int(False), 0x0FF0000F)
        self.assertEqual(fake_state.instr_objs_seq[1][2].gen_bytecode_int(False), 0x00200113)
        self.assertEqual(fake_state.final_bb[0].gen_bytecode_int(False), 0x0000100F)
        self.assertEqual(fake_state.final_bb[1].gen_bytecode_int(False), 0x0FF0000F)

    def test_xiangshan_generator_uses_adapted_cascade_tree(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = unittest.mock.Mock(returncode=0, stderr="")
                    out = Path(tmp) / "out"
                    cascade._generate_elfs(
                        1,
                        out,
                        seed=7,
                        design="xiangshan",
                    )
                    bash_script = _last_generator_bash_script(mock_run)
        self.assertIn(
            "export PYTHONPATH=/cascade-mountdir/cascade_xiangshan_adapt/cascade-meta/fuzzer",
            bash_script,
        )
        self.assertIn(
            "export CASCADE_DESIGN_PROCESSING_ROOT=/cascade-mountdir/cascade_xiangshan_adapt/cascade-meta/design-processing",
            bash_script,
        )

    def test_target_operation_candidates_ignore_initial_block_and_resolve_addresses(self):
        from scripts.evaluation.baseline_adapters import cascade_generate_campaign as helper

        class FakeLoad:
            instr_str = "lw"
            producer_id = 1.0
            imm = 0

        class FakeStore:
            instr_str = "sd"
            producer_id = 2.0
            imm = 0

        class FakeInitial:
            instr_str = "ld"
            producer_id = -1
            imm = 16

        fake_state = unittest.mock.Mock(
            instr_objs_seq=[[FakeInitial()], [FakeLoad()], [FakeStore()]],
            bb_start_addr_seq=[0x0, 0x40, 0x80],
            producer_id_to_tgtaddr={1.0: 0x1000, 2.0: 0x2000},
            design_base_addr=0x80000000,
        )

        candidates = helper._extract_target_operation_candidates(fake_state)

        self.assertEqual(
            candidates,
            [
                {
                    "target_operation_id": "bb1-i0",
                    "privilege": "M",
                    "access": "load",
                    "size": 4,
                    "physical_address": "0x1000",
                    "instruction_address": "0x80000040",
                    "instruction_page_tag": 0,
                },
                {
                    "target_operation_id": "bb2-i0",
                    "privilege": "M",
                    "access": "store",
                    "size": 8,
                    "physical_address": "0x2000",
                    "instruction_address": "0x80000080",
                    "instruction_page_tag": 0,
                },
            ],
        )


class TestCascadeEventTimeline(unittest.TestCase):
    def test_event_identity_ignores_case_and_raw_address(self):
        timeline = [
            {
                "case_id": "case-a",
                "completion_seq": 1,
                "elapsed_wall_seconds": 1.0,
                "probe_events": [
                    {
                        "kind": "source_probe",
                        "chain": "pmp",
                        "stage": "final",
                        "fields": {"prv": "1", "addr": "0x1000"},
                    },
                    {
                        "kind": "source_probe",
                        "chain": "pmp",
                        "stage": "final",
                        "fields": {"prv": "1", "addr": "0x2000"},
                    },
                ],
            },
            {
                "case_id": "case-b",
                "completion_seq": 2,
                "elapsed_wall_seconds": 2.0,
                "probe_events": [
                    {
                        "kind": "source_probe",
                        "chain": "pmp",
                        "stage": "final",
                        "fields": {"prv": "1", "addr": "0x3000"},
                    }
                ],
            },
        ]

        rows = cascade._build_security_event_timeseries(
            timeline, dut="rocket-clean", campaign_id="campaign", seed=101
        )

        self.assertEqual([row["completion_seq"] for row in rows], [1, 1, 2])
        self.assertEqual([row["event_index"] for row in rows], [1, 2, 1])
        self.assertEqual(len({row["event_id"] for row in rows}), 1)
        self.assertEqual([row["is_new_event"] for row in rows], [True, False, False])


class TestCascadeArtifactPersistence(unittest.TestCase):
    def test_cli_help_runs_without_py_path_bootstrap(self):
        repo_root = Path(__file__).resolve().parents[1]
        script = repo_root / "scripts" / "evaluation" / "baseline_adapters" / "cascade.py"
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        proc = subprocess.run(
            [sys.executable, str(script), "--help"],
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("usage:", proc.stdout)

    def test_campaign_persists_case_logs_and_normalized_events(self):
        def fake_generate(num_elfs, out_dir, *, seed, design):
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"{design}_0.elf").write_bytes(b"ELF")
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
            }

        process = unittest.mock.Mock(
            returncode=1,
            stdout=(
                "PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1000\n"
            ),
            stderr="opaque simulator status\n",
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
                        )

            stdout_log = out_dir / "logs" / "cascade_rocket-clean_0000.stdout.log"
            stderr_log = out_dir / "logs" / "cascade_rocket-clean_0000.stderr.log"
            rows = [
                json.loads(line)
                for line in (out_dir / "metrics/security_event_timeseries.jsonl")
                .read_text(encoding="ascii")
                .splitlines()
            ]
            stdout_text = stdout_log.read_text(encoding="utf-8")
            stderr_text = stderr_log.read_text(encoding="utf-8")

        self.assertEqual(meta["completed_cases"], 1)
        self.assertEqual(meta["eligible_cases"], 1)
        self.assertIn("PMFUZZ_PROBE", stdout_text)
        self.assertIn("opaque simulator status", stderr_text)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["completion_seq"], 1)

    def test_hpm_campaign_writes_timeline_coverage_and_validation(self):
        def fake_generate(num_elfs, out_dir, *, seed, design, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"{design}_0.elf").write_bytes(b"ELF")
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
            }

        process = unittest.mock.Mock(
            returncode=1,
            stdout=(
                "PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1000\n"
                "PMFUZZ_HPM phase=before width=40 minstret=0x0 mcycle=0x0 c3=0x0 c4=0x0 c5=0x0 c6=0x0\n"
                "PMFUZZ_HPM phase=after width=40 minstret=0x64 mcycle=0x96 c3=0x1 c4=0x2 c5=0x0 c6=0x0\n"
            ),
            stderr="opaque simulator status\n",
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
                            hpm_manifest=manifest_for_dut("rocket-clean"),
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

        self.assertEqual(meta["coverage_mode"], "hpm")
        self.assertEqual(meta["eligible_hpm_cases"], 1)
        self.assertEqual(timeline_rows[0]["completion_seq"], 0)
        self.assertEqual(timeline_rows[-1]["new_hpm_bins"], 4)
        self.assertEqual(
            coverage["execution_coverage"]["by_dut"]["rocket-clean"]["hpm"]["covered_bins"],
            [
                "event=dtlb_miss|bucket=0",
                "event=exception|bucket=1-10",
                "event=itlb_miss|bucket=10-100",
                "event=l2_tlb_miss|bucket=0",
            ],
        )
        self.assertTrue(validation["valid"], validation)

    def test_hpm_continuous_batches_advance_start_index_and_stop_on_convergence(self):
        generate_calls = []

        def fake_generate(num_elfs, out_dir, *, seed, design, start_index=0, **kwargs):
            generate_calls.append(start_index)
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_name = f"{design}_{start_index}.elf"
            (out_dir / elf_name).write_bytes(f"ELF-{start_index}".encode("ascii"))
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": start_index,
                "elf_hashes": {elf_name: f"sha-{start_index}"},
            }

        process_a = unittest.mock.Mock(
            returncode=0,
            stdout=(
                "PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1000\n"
                "PMFUZZ_HPM phase=before width=40 minstret=0x0 mcycle=0x0 c3=0x0 c4=0x0 c5=0x0 c6=0x0\n"
                "PMFUZZ_HPM phase=after width=40 minstret=0x64 mcycle=0x96 c3=0x1 c4=0x0 c5=0x0 c6=0x0\n"
            ),
            stderr="",
        )
        process_b = unittest.mock.Mock(
            returncode=0,
            stdout=(
                "PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x2000\n"
                "PMFUZZ_HPM phase=before width=40 minstret=0x0 mcycle=0x0 c3=0x0 c4=0x0 c5=0x0 c6=0x0\n"
                "PMFUZZ_HPM phase=after width=40 minstret=0x64 mcycle=0x96 c3=0x1 c4=0x0 c5=0x0 c6=0x0\n"
            ),
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
                    with patch.object(
                        cascade.subprocess, "run", side_effect=[process_a, process_b]
                    ):
                        meta = cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            hpm_manifest=manifest_for_dut("rocket-clean"),
                            batch_size=1,
                            min_runtime_seconds=0.0,
                            confirmation_seconds=0.0,
                            confirmation_eligible_cases=1,
                            max_wall_time_seconds=60.0,
                        )

        self.assertEqual(generate_calls, [0, 1])
        self.assertEqual(meta["stop_reason"], "coverage_converged")
        self.assertEqual(meta["executed_cases"], 2)

    def test_hpm_continuous_hard_cap_uses_hard_cap_censored(self):
        def fake_generate(num_elfs, out_dir, *, seed, design, start_index=0, **kwargs):
            out_dir.mkdir(parents=True, exist_ok=True)
            elf_name = f"{design}_{start_index}.elf"
            (out_dir / elf_name).write_bytes(f"ELF-{start_index}".encode("ascii"))
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.1,
                "workspace": "/isolated/workspace",
                "design": design,
                "seed": seed,
                "start_index": start_index,
                "elf_hashes": {elf_name: f"sha-{start_index}"},
            }

        process = unittest.mock.Mock(
            returncode=0,
            stdout=(
                "PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1000\n"
                "PMFUZZ_HPM phase=before width=40 minstret=0x0 mcycle=0x0 c3=0x0 c4=0x0 c5=0x0 c6=0x0\n"
                "PMFUZZ_HPM phase=after width=40 minstret=0x64 mcycle=0x96 c3=0x1 c4=0x0 c5=0x0 c6=0x0\n"
            ),
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
                        meta = cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                            hpm_manifest=manifest_for_dut("rocket-clean"),
                            batch_size=1,
                            min_runtime_seconds=999.0,
                            confirmation_seconds=999.0,
                            confirmation_eligible_cases=999,
                            max_wall_time_seconds=0.0,
                        )

        self.assertEqual(meta["stop_reason"], "hard_cap_censored")
        self.assertEqual(meta["executed_cases"], 1)


if __name__ == "__main__":
    unittest.main()
