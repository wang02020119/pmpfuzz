
from __future__ import annotations

import hashlib
import json
import re
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import ANY, MagicMock, patch

from scripts.evaluation.baseline_adapters import cascade


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
        if (
            len(cmd) < 6
            or "python3 " not in cmd[5]
            or "cascade_generate_campaign.py" not in cmd[5]
        ):
            continue
        commands.append(cmd)
    return commands


def _last_generator_bash_script(mock_run):
    commands = _generator_run_commands(mock_run)
    if not commands:
        raise AssertionError(f"generator docker exec call not found: {mock_run.call_args_list}")
    return commands[-1][5]








class TestWorkspaceIdIncludesDesign(unittest.TestCase):

    def test_different_designs_produce_different_workspace_ids(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    out = Path(tmp, "shared-out")
                    res_a = cascade._generate_elfs(1, out, seed=1, design="rocket")
                    res_b = cascade._generate_elfs(1, out, seed=1, design="boom")
        self.assertNotEqual(
            res_a["workspace"],
            res_b["workspace"],
            "Contract 3 violation: workspace ID must differ when design differs. "
            "Currently _generation_workspace() ignores the design parameter.",
        )







class TestSeedReachesGenerator(unittest.TestCase):

    def test_seed_appears_in_generator_command(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    out = Path(tmp, "out")
                    cascade._generate_elfs(3, out, seed=42, design="rocket")

                    cmd_list = _generator_run_commands(mock_run)[-1]
                    bash_script = cmd_list[5]
        self.assertIn(
            "42",
            bash_script,
            "Contract 4 violation: seed '42' must appear in the generator invocation "
            "arguments. Currently the seed is only used for workspace naming and is "
            "never passed to do_genmanyelfs.py.",
        )

    def test_two_seeds_produce_different_generator_commands(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    out = Path(tmp, "out")

                    cascade._generate_elfs(2, out, seed=7, design="rocket")
                    cmd_a = _last_generator_bash_script(mock_run)

                    cascade._generate_elfs(2, out, seed=13, design="rocket")
                    cmd_b = _last_generator_bash_script(mock_run)

        self.assertNotEqual(
            cmd_a,
            cmd_b,
            "Contract 4 violation: different seeds must produce different generator "
            "invocations. Currently seed does not reach the generator command at all.",
        )







class TestRelativeLogPaths(unittest.TestCase):

    def test_events_json_records_relative_log_paths(self):
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
                "elf_sha256": "deadbeef",
            }

        process = MagicMock(
            returncode=0,
            stdout="PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1000\n",
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
                        )

            events = json.loads((out_dir / "events.json").read_text(encoding="ascii"))
            self.assertGreater(len(events), 0, "Expected at least one terminal record")
            for record in events:
                for key in ("stdout_log", "stderr_log"):
                    path_str = record.get(key, "")
                    is_abs = Path(path_str).is_absolute()
                    self.assertFalse(
                        is_abs,
                        f"Contract 5 violation: {key} must be a relative path, "
                        f"got absolute: {path_str!r}",
                    )







class TestDutBinaryShaFailsClosed(unittest.TestCase):

    def test_missing_dut_binary_is_infra_failure(self):
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

        process = MagicMock(
            returncode=0,
            stdout="PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1000\n",
            stderr="",
        )
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            nonexistent = str(Path(tmp) / "nonexistent_simulator")
            with patch.dict(
                cascade._SIM_BINARIES,
                {"rocket-clean": nonexistent},
                clear=False,
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

        self.assertEqual(
            meta.get("status"),
            "infra_failure",
            "Contract 2 violation: missing DUT binary must produce infra_failure, "
            f"not '{meta.get('status')}'. Currently dut_binary_sha256 silently "
            "defaults to empty string.",
        )

    def test_dut_binary_sha_is_not_empty_when_binary_exists(self):
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

        process = MagicMock(
            returncode=0,
            stdout="PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1000\n",
            stderr="",
        )
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "real_simulator"
            real_binary.write_bytes(b"binary-content-for-sha")
            with patch.dict(
                cascade._SIM_BINARIES,
                {"rocket-clean": str(real_binary)},
                clear=False,
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

        dut_sha = meta.get("dut_binary_sha256", "")
        self.assertTrue(
            len(dut_sha) >= 16 and all(c in "0123456789abcdef" for c in dut_sha),
            f"Contract 2 violation: dut_binary_sha256 must be a non-trivial hex "
            f"digest, got {dut_sha!r}",
        )
        self.assertNotEqual(
            dut_sha,
            cascade.CASCADE_IMAGE_SHA[:16],
            "Contract 2 violation: dut_binary_sha256 must not equal "
            "CASCADE_IMAGE_SHA (the container image digest).",
        )







class TestNonzeroReturnClassification(unittest.TestCase):

    def test_nonzero_return_with_probe_events_is_completed(self):
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


        process = MagicMock(
            returncode=1,
            stdout="PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1000\n",
            stderr="some error output",
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

            self.assertEqual(
                meta["completed_cases"], 1,
                "Contract 6 violation: nonzero-return case with probe events must "
                "count as completed.",
            )
            self.assertEqual(
                meta["infra_failures"], 0,
                "Contract 6 violation: nonzero return alone is not infra_failure.",
            )

            events = json.loads(
                (out_dir / "events.json").read_text(encoding="ascii"))
            self.assertEqual(events[0]["status"], "completed")
            self.assertEqual(events[0]["returncode"], 1)







class TestMetadataBudgetSeparation(unittest.TestCase):

    def test_time_budget_seconds_is_not_elapsed_wall_time(self):
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

        process = MagicMock(
            returncode=0,
            stdout="PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1000\n",
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
                        )



        budget = meta.get("time_budget_seconds")
        elapsed = meta.get("elapsed_wall_seconds")
        if budget is not None and elapsed is not None:
            self.assertNotEqual(
                budget,
                elapsed,
                "Contract 8 violation: time_budget_seconds must not contain "
                "actual elapsed wall time.",
            )

        self.assertGreaterEqual(
            elapsed, 0,
            "elapsed_wall_seconds must be a non-negative number")







class TestCompletionSeqAndEventIndex(unittest.TestCase):

    def test_completion_seq_shared_event_index_per_case(self):
        timeline = [
            {
                "case_id": "case-a",
                "completion_seq": 1,
                "elapsed_wall_seconds": 1.0,
                "probe_events": [
                    {"kind": "source_probe", "chain": "pmp", "stage": "init",
                     "fields": {"prv": "3"}},
                    {"kind": "source_probe", "chain": "pmp", "stage": "final",
                     "fields": {"prv": "1"}},
                ],
            },
            {
                "case_id": "case-b",
                "completion_seq": 2,
                "elapsed_wall_seconds": 2.0,
                "probe_events": [
                    {"kind": "source_probe", "chain": "dmem", "stage": "x",
                     "fields": {"prv": "0"}},
                ],
            },
            {
                "case_id": "case-c",
                "completion_seq": 3,
                "elapsed_wall_seconds": 3.0,
                "probe_events": [],
            },
        ]

        rows = cascade._build_security_event_timeseries(
            timeline, dut="rocket-clean", campaign_id="camp", seed=1,
        )


        self.assertEqual(rows[0]["completion_seq"], 1)
        self.assertEqual(rows[0]["event_index"], 1)
        self.assertEqual(rows[1]["completion_seq"], 1)
        self.assertEqual(rows[1]["event_index"], 2)

        self.assertEqual(rows[2]["completion_seq"], 2)
        self.assertEqual(rows[2]["event_index"], 1)

        self.assertEqual(len(rows), 3)

    def test_event_index_resets_per_case(self):
        timeline = [
            {
                "case_id": "case-1",
                "completion_seq": 1,
                "elapsed_wall_seconds": 1.0,
                "probe_events": [
                    {"kind": "source_probe", "chain": "a", "stage": "s",
                     "fields": {"prv": "1"}},
                ],
            },
            {
                "case_id": "case-2",
                "completion_seq": 2,
                "elapsed_wall_seconds": 2.0,
                "probe_events": [
                    {"kind": "source_probe", "chain": "a", "stage": "s",
                     "fields": {"prv": "1"}},
                    {"kind": "source_probe", "chain": "b", "stage": "t",
                     "fields": {"prv": "0"}},
                ],
            },
        ]
        rows = cascade._build_security_event_timeseries(
            timeline, dut="rocket-clean", campaign_id="c", seed=1,
        )

        self.assertEqual(rows[0]["event_index"], 1)

        self.assertEqual(rows[1]["event_index"], 1)
        self.assertEqual(rows[2]["event_index"], 2)


class TestSecurityEventTimeseriesStreaming(unittest.TestCase):
    def test_security_event_timeseries_is_emitted_without_final_rebuild(self):
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

        process = MagicMock(
            returncode=0,
            stdout=(
                "PMFUZZ_PROBE chain=pmp stage=init prv=3 addr=0x1000\n"
                "PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1004\n"
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
                        cascade,
                        "_build_security_event_timeseries",
                        side_effect=AssertionError("must not rebuild full security_event_timeseries at campaign end"),
                    ):
                        with patch.object(cascade.subprocess, "run", return_value=process):
                            cascade.run_cascade_baseline(
                                dut="rocket-clean",
                                num_elfs=1,
                                simlen=100,
                                timeout_seconds=5,
                                out_dir=out_dir,
                                seed=101,
                            )

            rows = [
                json.loads(line)
                for line in (out_dir / "metrics" / "security_event_timeseries.jsonl").read_text(encoding="ascii").splitlines()
                if line.strip()
            ]
            self.assertEqual(
                [(row["completion_seq"], row["event_index"]) for row in rows],
                [(1, 1), (1, 2)],
            )


class TestArtifactShaManifestStreaming(unittest.TestCase):
    def test_update_artifact_sha_manifest_hashes_without_read_bytes(self):
        with TemporaryDirectory() as tmp:
            artifact_root = Path(tmp)
            target = artifact_root / "metrics" / "payload.bin"
            target.parent.mkdir(parents=True, exist_ok=True)
            payload = (b"cascade-runtime-artifact" * 64)
            target.write_bytes(payload)

            with patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("must not read whole file into memory"),
            ):
                cascade._update_artifact_sha_manifest(
                    artifact_root, [Path("metrics/payload.bin")]
                )

            manifest = (artifact_root / "manifests" / "artifact-sha256.txt").read_text(
                encoding="ascii"
            )
            self.assertIn(
                f"{hashlib.sha256(payload).hexdigest()}  metrics/payload.bin",
                manifest,
            )

    def test_campaign_artifact_manifest_uses_security_event_digest_sidecar(self):
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

        process = MagicMock(
            returncode=0,
            stdout=(
                "PMFUZZ_PROBE chain=pmp stage=init prv=3 addr=0x1000\n"
                "PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1004\n"
            ),
            stderr="",
        )

        captured_rel_paths: list[str] = []

        def capture_manifest(artifact_root, rel_paths):
            captured_rel_paths[:] = [path.as_posix() for path in rel_paths]

        with TemporaryDirectory() as tmp:
            artifact_root = Path(tmp) / "artifact-root"
            out_dir = (
                artifact_root
                / "dut-roots"
                / "rocket-clean"
                / "campaigns"
                / "section-8.3-test"
                / "rocket-clean"
                / "cascade"
                / "bapc"
                / "seed-0001"
            )
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")
            with patch.dict(
                cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False
            ):
                with patch.object(cascade, "_generate_elfs", side_effect=fake_generate):
                    with patch.object(cascade.subprocess, "run", return_value=process):
                        with patch.object(
                            cascade,
                            "_update_artifact_sha_manifest",
                            side_effect=capture_manifest,
                        ):
                            cascade.run_cascade_baseline(
                                dut="rocket-clean",
                                num_elfs=1,
                                simlen=100,
                                timeout_seconds=5,
                                out_dir=out_dir,
                                seed=101,
                            )

            rows_path = out_dir / "metrics" / "security_event_timeseries.jsonl"
            digest_path = out_dir / "metrics" / "security_event_timeseries.sha256.json"
            self.assertTrue(rows_path.exists())
            self.assertTrue(digest_path.exists())
            digest_payload = json.loads(digest_path.read_text(encoding="ascii"))
            self.assertEqual(
                digest_payload["file"],
                "security_event_timeseries.jsonl",
            )
            self.assertEqual(digest_payload["row_count"], 2)
            self.assertEqual(digest_payload["byte_count"], rows_path.stat().st_size)
            self.assertEqual(
                digest_payload["sha256"],
                hashlib.sha256(rows_path.read_bytes()).hexdigest(),
            )
            self.assertTrue(
                any(
                    path.endswith("/metrics/security_event_timeseries.sha256.json")
                    for path in captured_rel_paths
                ),
                captured_rel_paths,
            )
            self.assertFalse(
                any(
                    path.endswith("/metrics/security_event_timeseries.jsonl")
                    for path in captured_rel_paths
                ),
                captured_rel_paths,
            )









class TestStaleReturncodeIsolation(unittest.TestCase):

    def _make_generate_side_effect(self, num_elfs, design):

        def _fake_generate(n, out_dir, *, seed, design):
            out_dir.mkdir(parents=True, exist_ok=True)
            for i in range(n):
                (out_dir / f"{design}_{i}.elf").write_bytes(
                    bytes([(seed + i) % 256]) * 64
                )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.01,
                "workspace": "/fake/ws",
                "design": design,
                "seed": seed,
                "elf_sha256": "0" * 16,
            }

        return _fake_generate

    def test_timeout_after_success_does_not_inherit_previous_returncode(self):
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")

            with patch.dict(
                cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False
            ):
                with patch.object(
                    cascade, "_generate_elfs",
                    side_effect=self._make_generate_side_effect(2, "rocket"),
                ):

                    success_proc = MagicMock(
                        returncode=0,
                        stdout="PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1000\n",
                        stderr="",
                    )
                    with patch.object(
                        cascade.subprocess, "run",
                        side_effect=[
                            success_proc,
                            cascade.subprocess.TimeoutExpired(
                                cmd=["sim"], timeout=5
                            ),
                        ],
                    ):
                        meta = cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=2,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                        )

            events = json.loads(
                (out_dir / "events.json").read_text(encoding="ascii")
            )
            self.assertEqual(len(events), 2,
                             "Both cases must produce terminal records")
            self.assertEqual(events[0]["status"], "completed")

            timeout_rc = events[1]["returncode"]
            self.assertIsNone(
                timeout_rc,
                f"Timeout case must have returncode=None, not {timeout_rc!r} "
                "(stale proc from prior iteration leaked)",
            )

    def test_exception_after_success_does_not_inherit_previous_returncode(self):
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")

            with patch.dict(
                cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False
            ):
                with patch.object(
                    cascade, "_generate_elfs",
                    side_effect=self._make_generate_side_effect(2, "rocket"),
                ):
                    success_proc = MagicMock(
                        returncode=0,
                        stdout="PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1000\n",
                        stderr="",
                    )
                    with patch.object(
                        cascade.subprocess, "run",
                        side_effect=[
                            success_proc,
                            OSError("simulator launch failure"),
                        ],
                    ):
                        meta = cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=2,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                        )

            events = json.loads(
                (out_dir / "events.json").read_text(encoding="ascii")
            )
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0]["status"], "completed")
            exc_rc = events[1]["returncode"]
            self.assertIsNone(
                exc_rc,
                f"OSError case must have returncode=None, not {exc_rc!r} "
                "(stale proc from prior iteration leaked)",
            )

    def test_terminal_statuses_and_log_files_always_exist(self):
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")

            with patch.dict(
                cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False
            ):
                with patch.object(
                    cascade, "_generate_elfs",
                    side_effect=self._make_generate_side_effect(3, "rocket"),
                ):
                    success_proc = MagicMock(
                        returncode=0,
                        stdout="PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1000\n",
                        stderr="",
                    )
                    with patch.object(
                        cascade.subprocess, "run",
                        side_effect=[
                            success_proc,
                            cascade.subprocess.TimeoutExpired(
                                cmd=["sim"], timeout=5
                            ),
                            OSError("launch failure"),
                        ],
                    ):
                        cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=3,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                        )

            events = json.loads(
                (out_dir / "events.json").read_text(encoding="ascii")
            )
            self.assertEqual(len(events), 3)

            for i, evt in enumerate(events):
                with self.subTest(case_index=i):
                    self.assertIn(
                        evt["status"],
                        ("completed", "timeout", "infra_failure"),
                    )

                    for key in ("stdout_log", "stderr_log"):
                        self.assertFalse(
                            Path(evt[key]).is_absolute(),
                            f"{key} must be relative, got {evt[key]!r}",
                        )
                        log_path = out_dir / evt[key]
                        self.assertTrue(
                            log_path.exists(),
                            f"Log file {log_path} must exist for status={evt['status']}",
                        )





class TestWorkspacePathCanonicalIdentity(unittest.TestCase):

    def test_different_full_paths_same_basename_yield_different_workspaces(self):
        with TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            dir_a = tmp_p / "a" / "campaign"
            dir_b = tmp_p / "b" / "campaign"
            dir_a.mkdir(parents=True, exist_ok=True)
            dir_b.mkdir(parents=True, exist_ok=True)

            with patch.object(cascade, "CASCADE_MOUNT_DIR", tmp_p / "mount"):
                ws_a = cascade._generation_workspace(dir_a, seed=1, design="rocket")
                ws_b = cascade._generation_workspace(dir_b, seed=1, design="rocket")

            self.assertNotEqual(
                ws_a,
                ws_b,
                "Different absolute paths with same basename must produce "
                "different workspace IDs. Currently only basename is hashed.",
            )

    def test_same_canonical_path_is_deterministic(self):
        with TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            dir_x = tmp_p / "campaign"
            dir_x.mkdir(parents=True, exist_ok=True)

            with patch.object(cascade, "CASCADE_MOUNT_DIR", tmp_p / "mount"):
                first = cascade._generation_workspace(dir_x, seed=42, design="boom")
                second = cascade._generation_workspace(dir_x, seed=42, design="boom")

            self.assertEqual(
                first,
                second,
                "Same canonical path + seed + design must yield deterministic "
                "workspace ID.",
            )





class TestPerCaseElfFullHash(unittest.TestCase):

    def test_different_elf_contents_produce_different_full_hashes(self):
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")


            def fake_generate(n, out_dir, *, seed, design):
                out_dir.mkdir(parents=True, exist_ok=True)
                for i in range(n):

                    content = bytes([(seed + i * 7) % 256]) * 128
                    (out_dir / f"{design}_{i}.elf").write_bytes(content)


                import hashlib
                first_elf_content = (out_dir / f"{design}_0.elf").read_bytes()
                first_short = hashlib.sha256(first_elf_content).hexdigest()[:16]
                return {
                    "success": True,
                    "returncode": 0,
                    "elapsed_seconds": 0.01,
                    "workspace": "/fake/ws",
                    "design": design,
                    "seed": seed,
                    "elf_sha256": first_short,
                }

            success_proc = MagicMock(
                returncode=0,
                stdout="PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1000\n",
                stderr="",
            )
            with patch.dict(
                cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False
            ):
                with patch.object(
                    cascade, "_generate_elfs", side_effect=fake_generate
                ):
                    with patch.object(
                        cascade.subprocess, "run",
                        side_effect=[success_proc, success_proc],
                    ):
                        cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=2,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                        )

            events = json.loads(
                (out_dir / "events.json").read_text(encoding="ascii")
            )
            self.assertEqual(len(events), 2)

            import hashlib

            for i, evt in enumerate(events):
                with self.subTest(case_index=i):
                    elf_path = out_dir / "elfs" / f"rocket_{i}.elf"
                    expected_full = hashlib.sha256(
                        elf_path.read_bytes()
                    ).hexdigest()
                    self.assertEqual(
                        len(expected_full), 64,
                        "SHA256 hex digest must be 64 characters",
                    )
                    recorded = evt.get("elf_sha256", "")
                    self.assertEqual(
                        recorded,
                        expected_full,
                        f"Case {i}: recorded elf_sha256 must be the full "
                        f"64-hex SHA256 of that case's actual ELF. "
                        f"Got {recorded!r}, expected {expected_full!r}",
                    )

                    if i > 0:
                        prev = events[i - 1].get("elf_sha256", "")
                        self.assertNotEqual(
                            recorded,
                            prev,
                            f"Cases {i-1} and {i} have different ELF content "
                            f"but identical recorded hashes ({recorded!r})",
                        )





class TestMissingElfTerminalEvidence(unittest.TestCase):

    def _make_partial_generator(self, num_create, _design):

        def _fake(n, out_dir, *, seed, design):
            out_dir.mkdir(parents=True, exist_ok=True)
            for i in range(min(n, num_create)):
                (out_dir / f"{design}_{i}.elf").write_bytes(
                    bytes([(seed + i) % 256]) * 64
                )
            return {
                "success": True,
                "returncode": 0,
                "elapsed_seconds": 0.01,
                "workspace": "/fake/ws",
                "design": design,
                "seed": seed,
                "elf_sha256": "0" * 16,
            }

        return _fake

    def test_missing_elf_yields_infra_failure_terminal_record(self):
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")

            success_proc = MagicMock(
                returncode=0,
                stdout="PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1000\n",
                stderr="",
            )
            with patch.dict(
                cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False
            ):
                with patch.object(
                    cascade, "_generate_elfs",
                    side_effect=self._make_partial_generator(2, "rocket"),
                ):
                    with patch.object(
                        cascade.subprocess, "run",
                        side_effect=[success_proc, success_proc],
                    ):
                        cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=3,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                        )

            events = json.loads(
                (out_dir / "events.json").read_text(encoding="ascii")
            )
            self.assertEqual(
                len(events),
                3,
                "All 3 requested cases MUST produce terminal records; "
                f"only {len(events)} found (missing ELF was silently skipped)",
            )


            seqs = [e["completion_seq"] for e in events]
            self.assertEqual(
                seqs,
                [1, 2, 3],
                f"completion_seq must be contiguous 1..N, got {seqs}",
            )


            missing = events[2]
            self.assertEqual(missing["status"], "infra_failure")

            for key in ("stdout_log", "stderr_log"):
                log_rel = missing[key]
                self.assertFalse(
                    Path(log_rel).is_absolute(),
                    f"{key} must be relative, got {log_rel!r}",
                )
                log_abs = out_dir / log_rel
                self.assertTrue(
                    log_abs.exists(),
                    f"Log file {log_abs} must exist even for missing-ELF case",
                )

    def test_missing_elf_reconciliation_counts_match(self):
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            real_binary = Path(tmp) / "sim"
            real_binary.write_bytes(b"binary-content")

            success_proc = MagicMock(
                returncode=0,
                stdout="PMFUZZ_PROBE chain=pmp stage=final prv=1 addr=0x1000\n",
                stderr="",
            )
            with patch.dict(
                cascade._SIM_BINARIES, {"rocket-clean": str(real_binary)}, clear=False
            ):
                with patch.object(
                    cascade, "_generate_elfs",
                    side_effect=self._make_partial_generator(1, "rocket"),
                ):
                    with patch.object(
                        cascade.subprocess, "run",
                        side_effect=[success_proc],
                    ):
                        meta = cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=3,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                        )

            events = json.loads(
                (out_dir / "events.json").read_text(encoding="ascii")
            )
            self.assertEqual(
                len(events),
                meta["requested_cases"],
                "Number of terminal records must equal requested_cases",
            )
            total = (
                meta.get("completed_cases", 0)
                + meta.get("inconclusive", 0)
                + meta.get("timeouts", 0)
                + meta.get("infra_failures", 0)
            )
            self.assertEqual(
                total,
                meta["requested_cases"],
                f"completed + inconclusive + timeouts + infra_failures "
                f"(={total}) must equal requested_cases "
                f"(={meta['requested_cases']})",
            )





class TestDutBinaryPreflightValidation(unittest.TestCase):

    def test_missing_dut_binary_prevents_generation(self):
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            nonexistent = str(Path(tmp) / "nonexistent_simulator")

            gen_mock = MagicMock(return_value={
                "success": True, "returncode": 0, "elapsed_seconds": 0,
                "workspace": "/should/not/exist", "design": "rocket",
                "seed": 1, "elf_sha256": "0" * 16,
            })

            with patch.dict(
                cascade._SIM_BINARIES, {"rocket-clean": nonexistent}, clear=False
            ):
                with patch.object(cascade, "_generate_elfs", gen_mock):


                    with patch.object(cascade.subprocess, "run") as mock_run:
                        mock_run.return_value = MagicMock(
                            returncode=0, stdout="", stderr=""
                        )
                        meta = cascade.run_cascade_baseline(
                            dut="rocket-clean",
                            num_elfs=1,
                            simlen=100,
                            timeout_seconds=5,
                            out_dir=out_dir,
                            seed=101,
                        )

            gen_mock.assert_not_called()
            self.assertEqual(meta.get("status"), "infra_failure")

    def test_unreadable_dut_binary_returns_infra_failure_not_exception(self):
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            dut_binary = Path(tmp) / "unreadable_sim"
            dut_binary.write_bytes(b"binary-content")

            gen_mock = MagicMock(return_value={
                "success": True, "returncode": 0, "elapsed_seconds": 0,
                "workspace": "/should/not/exist", "design": "rocket",
                "seed": 1, "elf_sha256": "0" * 16,
            })


            real_read_bytes = Path.read_bytes

            def _se(path_self):
                if str(path_self) == str(dut_binary):
                    raise OSError("Permission denied")
                return real_read_bytes(path_self)

            with patch.dict(
                cascade._SIM_BINARIES, {"rocket-clean": str(dut_binary)}, clear=False
            ):
                with patch.object(cascade, "_generate_elfs", gen_mock):
                    with patch.object(cascade.subprocess, "run") as mock_run:
                        mock_run.return_value = MagicMock(
                            returncode=0, stdout="", stderr=""
                        )
                        with patch.object(
                            Path, "read_bytes", autospec=True, side_effect=_se
                        ):
                            try:
                                meta = cascade.run_cascade_baseline(
                                    dut="rocket-clean",
                                    num_elfs=1,
                                    simlen=100,
                                    timeout_seconds=5,
                                    out_dir=out_dir,
                                    seed=101,
                                )
                            except (OSError, PermissionError):
                                self.fail(
                                    "OSError from DUT binary read_bytes must "
                                    "be caught as structured infra_failure, "
                                    "not propagated"
                                )

            gen_mock.assert_not_called()
            self.assertEqual(meta.get("status"), "infra_failure")
            self.assertIn(
                "dut_binary_error", meta,
                "dut_binary_error key must be present to preserve diagnosis",
            )





class TestDesignReachesGeneratorInvocation(unittest.TestCase):

    @staticmethod
    def _last_bash_script(mock_run):
        return _last_generator_bash_script(mock_run)

    def test_different_designs_produce_different_helper_commands(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp) / "mount"):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    out = Path(tmp) / "out"
                    out.mkdir(parents=True, exist_ok=True)

                    cascade._generate_elfs(1, out, seed=1, design="rocket")
                    script_rocket = self._last_bash_script(mock_run)

                    cascade._generate_elfs(2, out, seed=1, design="boom")
                    script_boom = self._last_bash_script(mock_run)

            self.assertIn("--design rocket", script_rocket,
                          "Command must include '--design rocket' for rocket DUT")
            self.assertIn("--design boom", script_boom,
                          "Command must include '--design boom' for boom DUT")
            self.assertNotEqual(
                script_rocket, script_boom,
                "Different designs must produce different generator invocations",
            )

    def test_design_value_appears_as_parsed_flag(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp) / "mount"):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    out = Path(tmp) / "out"
                    out.mkdir(parents=True, exist_ok=True)
                    cascade._generate_elfs(1, out, seed=42, design="rocket")
                    script = self._last_bash_script(mock_run)

            self.assertIn(
                "--design",
                script,
                "Generator invocation must include --design flag; "
                "currently design is only used for workspace naming.",
            )
            self.assertIn(
                "--design rocket",
                script,
                "Generator invocation must include '--design rocket' "
                "as a parsed argument to the helper script.",
            )





class TestDesignValidationBeforeSubprocess(unittest.TestCase):

    def test_invalid_design_rejected_before_subprocess(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir(parents=True, exist_ok=True)
            with patch.object(cascade.subprocess, "run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stderr="")
                with self.assertRaises(ValueError):
                    cascade._generate_elfs(
                        1, out, seed=1, design="invalid_design_xyz"
                    )

            mock_run.assert_not_called()

    def test_valid_designs_are_accepted(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir(parents=True, exist_ok=True)
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp) / "mount"):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    for design in set(cascade._DESIGN_MAP.values()):
                        try:
                            cascade._generate_elfs(
                                1, out, seed=1, design=design
                            )
                        except ValueError:
                            self.fail(
                                f"Valid design {design!r} (from _DESIGN_MAP) "
                                f"must be accepted"
                            )

            self.assertGreaterEqual(
                mock_run.call_count,
                len(set(cascade._DESIGN_MAP.values())),
                "Each valid design must reach the generator subprocess",
            )








class TestNoLegacyDoGenmanyelfs(unittest.TestCase):

    def test_generator_command_does_not_invoke_do_genmanyelfs(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    out = Path(tmp, "out")
                    cascade._generate_elfs(3, out, seed=42, design="rocket")
                    script = _last_generator_bash_script(mock_run)

        self.assertNotIn(
            "do_genmanyelfs.py",
            script,
            "RED3-1 violation: _generate_elfs still invokes do_genmanyelfs.py. "
            "Must use the new cascade_generate_campaign.py helper instead.",
        )

    def test_generator_uses_new_helper_not_legacy_script(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    out = Path(tmp, "out")
                    cascade._generate_elfs(1, out, seed=0, design="boom")
                    script = _last_generator_bash_script(mock_run)

        self.assertIn(
            "cascade_generate_campaign.py",
            script,
            "RED3-1 violation: generator invocation must reference "
            "cascade_generate_campaign.py, not the legacy do_genmanyelfs.py.",
        )





class TestHelperInvocationArgs(unittest.TestCase):

    def test_helper_invocation_has_design_flag(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    out = Path(tmp, "out")
                    cascade._generate_elfs(2, out, seed=7, design="boom")
                    script = _last_generator_bash_script(mock_run)

        self.assertIn(
            "--design boom", script,
            "RED3-2 violation: helper must receive --design boom as a parsed flag",
        )

    def test_helper_invocation_has_seed_flag(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    out = Path(tmp, "out")
                    cascade._generate_elfs(1, out, seed=42, design="rocket")
                    script = _last_generator_bash_script(mock_run)

        self.assertIn(
            "cascade_generate_campaign.py", script,
            "RED3-2: must invoke cascade_generate_campaign.py, not legacy script",
        )
        self.assertIn(
            "--seed 42", script,
            "RED3-2 violation: --seed 42 must reach the helper "
            "(not silently ignored as on the legacy do_genmanyelfs.py)",
        )

    def test_helper_invocation_has_count_flag(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    out = Path(tmp, "out")
                    cascade._generate_elfs(5, out, seed=0, design="xiangshan")
                    script = _last_generator_bash_script(mock_run)

        self.assertIn(
            "--count 5", script,
            "RED3-2 violation: helper must receive --count 5 as a parsed flag",
        )

    def test_helper_invocation_has_output_flag(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    out = Path(tmp, "out")
                    cascade._generate_elfs(1, out, seed=0, design="cva6")
                    script = _last_generator_bash_script(mock_run)

        self.assertIn(
            "--output", script,
            "RED3-2 violation: helper must receive --output flag with isolated "
            "output directory path",
        )

    def test_all_four_designs_propagate_to_helper_invocation(self):
        failures = []
        for dut, design in cascade._DESIGN_MAP.items():
            with TemporaryDirectory() as tmp:
                with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                    with patch.object(cascade.subprocess, "run") as mock_run:
                        mock_run.return_value = MagicMock(
                            returncode=0, stderr="")
                        out = Path(tmp, "out")
                        out.mkdir(parents=True, exist_ok=True)
                        cascade._generate_elfs(
                            1, out, seed=0, design=design)
                        script = _last_generator_bash_script(mock_run)

            if f"--design {design}" not in script:
                failures.append(
                    f"--design {design} not in command for DUT {dut}: {script}"
                )

        self.assertEqual(
            [], failures,
            "All four designs must appear as --design <design> in helper "
            "invocation. Failures:\n" + "\n".join(failures),
        )


class TestContainerWorkspaceStaging(unittest.TestCase):

    def test_generate_elfs_stages_helper_into_container_before_generator_exec(self):
        invocations = []
        with TemporaryDirectory() as tmp:
            mount_root = Path(tmp) / "mount"
            out = Path(tmp) / "out"

            def fake_run(cmd, *args, **kwargs):
                invocations.append(cmd)
                return MagicMock(returncode=0, stderr="", stdout="")

            with patch.object(cascade, "CASCADE_MOUNT_DIR", mount_root):
                workspace = cascade._generation_workspace(out, 11, design="rocket")
                container_stage_dir = f"/tmp/pmpfuzz-cascade-{workspace.name}"
                container_helper = f"{container_stage_dir}/cascade_generate_campaign.py"
                helper_dest = workspace / "cascade_generate_campaign.py"
                with patch.object(cascade.subprocess, "run", side_effect=fake_run):
                    cascade._generate_elfs(1, out, seed=11, design="rocket")

        helper_cp = [
            "docker",
            "cp",
            str(helper_dest),
            f"{cascade.CASCADE_CONTAINER}:{container_helper}",
        ]
        try:
            helper_cp_index = invocations.index(helper_cp)
        except ValueError:
            self.fail(
                "Cascade helper must be staged into the container workspace via "
                f"'docker cp' before generator exec. Invocations: {invocations}"
            )
        generator_exec_index = next(
            (
                idx for idx, cmd in enumerate(invocations)
                if cmd[:3] == ["docker", "exec", cascade.CASCADE_CONTAINER]
                and len(cmd) >= 6
                and f"python3 {container_helper}" in cmd[5]
            ),
            None,
        )
        self.assertIsNotNone(
            generator_exec_index,
            "Generator docker exec command not found in subprocess calls.",
        )
        self.assertLess(
            helper_cp_index,
            generator_exec_index,
            "Helper docker cp must happen before generator exec so the helper is "
            "visible even when the bind mount is stale inside the container.",
        )

    def test_generate_elfs_copies_generated_outputs_back_from_container(self):
        with TemporaryDirectory() as tmp:
            mount_root = Path(tmp) / "mount"
            out = Path(tmp) / "out"
            batch_count = 2
            invocations = []

            with patch.object(cascade, "CASCADE_MOUNT_DIR", mount_root):
                workspace = cascade._generation_workspace(out, 3, design="rocket")
                container_stage_dir = f"/tmp/pmpfuzz-cascade-{workspace.name}"
                output_dir_name = "elfs-00000000"
                container_output = f"{container_stage_dir}/{output_dir_name}"
                batch_dir = workspace / output_dir_name

                def fake_run(cmd, *args, **kwargs):
                    invocations.append(cmd)
                    if cmd == [
                        "docker",
                        "cp",
                        f"{cascade.CASCADE_CONTAINER}:{container_output}/.",
                        str(batch_dir),
                    ]:
                        batch_dir.mkdir(parents=True, exist_ok=True)
                        for idx in range(batch_count):
                            (batch_dir / f"rocket_{idx}.elf").write_bytes(b"ELF" + bytes([idx]))
                            (batch_dir / f"rocket_{idx}.json").write_text(
                                json.dumps({"case_index": idx}) + "\n",
                                encoding="ascii",
                            )
                    return MagicMock(returncode=0, stderr="", stdout="")

                with patch.object(cascade.subprocess, "run", side_effect=fake_run):
                    result = cascade._generate_elfs(batch_count, out, seed=3, design="rocket")

        self.assertTrue(
            result["success"],
            "Successful generator exec must copy container outputs back to host so "
            "the exact ELF/sidecar set becomes observable even if the bind mount "
            "is not live inside the container.",
        )
        self.assertEqual(result["generated_elf_count"], batch_count)
        self.assertEqual(result["generated_sidecar_count"], batch_count)
        self.assertIn(
            [
                "docker",
                "cp",
                f"{cascade.CASCADE_CONTAINER}:{container_output}/.",
                str(batch_dir),
            ],
            invocations,
            "Generated outputs must be copied back from the container workspace to the host batch directory.",
        )





class TestHelperArgumentParsing(unittest.TestCase):

    _helper = None
    _import_error = None

    @classmethod
    def setUpClass(cls):
        try:
            from scripts.evaluation.baseline_adapters import\
                cascade_generate_campaign as _h
            cls._helper = _h
        except ImportError as e:
            cls._import_error = str(e)

    def setUp(self):
        if self._helper is None:
            self.fail(
                f"RED3: Helper module cascade_generate_campaign.py not found. "
                f"Import error: {self._import_error}"
            )

    def test_module_import_does_not_load_cascade_modules(self):
        cascade_internals = {
            k for k in sys.modules
            if k.startswith("analyzeelfs") or k.startswith("cascade_meta")
        }
        self.assertEqual(
            set(), cascade_internals,
            f"Helper module import must not load Cascade internals. "
            f"Found: {cascade_internals}",
        )

    def test_rejects_invalid_design(self):
        with self.assertRaises((SystemExit, ValueError)):
            parser = self._helper.build_arg_parser()
            parser.parse_args([
                "--design", "invalid_madeup",
                "--seed", "0", "--count", "1", "--output", "/tmp/out",
            ])

    def test_rejects_negative_seed(self):
        with self.assertRaises((SystemExit, ValueError)):
            parser = self._helper.build_arg_parser()
            args = parser.parse_args([
                "--design", "rocket",
                "--seed", "-1", "--count", "1", "--output", "/tmp/out",
            ])
            self._helper.validate_args(args)

    def test_rejects_zero_count(self):
        with self.assertRaises((SystemExit, ValueError)):
            parser = self._helper.build_arg_parser()
            args = parser.parse_args([
                "--design", "rocket",
                "--seed", "0", "--count", "0", "--output", "/tmp/out",
            ])
            self._helper.validate_args(args)

    def test_rejects_negative_count(self):
        with self.assertRaises((SystemExit, ValueError)):
            parser = self._helper.build_arg_parser()
            args = parser.parse_args([
                "--design", "rocket",
                "--seed", "0", "--count", "-5", "--output", "/tmp/out",
            ])
            self._helper.validate_args(args)

    def test_accepts_valid_args(self):
        for design in sorted(self._helper.ALLOWED_DESIGNS):
            with self.subTest(design=design):
                parser = self._helper.build_arg_parser()
                args = parser.parse_args([
                    "--design", design,
                    "--seed", "100",
                    "--count", "10",
                    "--output", "/tmp/test_out",
                ])
                self._helper.validate_args(args)

    def test_allowed_designs_matches_design_map_values(self):
        self.assertEqual(
            self._helper.ALLOWED_DESIGNS,
            frozenset(cascade._DESIGN_MAP.values()),
            "ALLOWED_DESIGNS must be {rocket, boom, cva6, xiangshan}",
        )





























def _red4_mock_modules(*, descriptor_side_effect=None, elf_side_effect=None):
    mock_fuzz = MagicMock()
    mock_spike = MagicMock()
    mock_profile = MagicMock()

    if descriptor_side_effect is not None:
        mock_fuzz.gen_new_test_instance = MagicMock(
            side_effect=descriptor_side_effect)
    if elf_side_effect is not None:
        mock_fuzz.gen_fuzzerstate_elf_expectedvals = MagicMock(
            side_effect=elf_side_effect)

    mock_spike.calibrate_spikespeed = MagicMock()
    mock_profile.profile_get_medeleg_mask = MagicMock()



    mock_cascade_pkg = MagicMock()
    mock_cascade_pkg.fuzzfromdescriptor = mock_fuzz
    mock_common_pkg = MagicMock()
    mock_common_pkg.spike = mock_spike
    mock_common_pkg.profiledesign = mock_profile

    return {
        "cascade": mock_cascade_pkg,
        "cascade.fuzzfromdescriptor": mock_fuzz,
        "common": mock_common_pkg,
        "common.spike": mock_spike,
        "common.profiledesign": mock_profile,
    }, mock_fuzz, mock_spike, mock_profile


def _red4_descriptor_fake():
    import random as _random

    def _fake(design_name, randseed, can_auth,
              fixed_memsize=None, fixed_num_bbs=None):
        r = _random.random()
        memsize = (fixed_memsize
                   if fixed_memsize is not None
                   else int(4096 + r * 4096))
        nmax_bbs = (fixed_num_bbs
                    if fixed_num_bbs is not None
                    else int(5 + r * 15))
        return (memsize, design_name, randseed, nmax_bbs, can_auth)

    return _fake


def _red4_elf_fake():
    import tempfile as _tempfile

    def _fake(memsize, design_name, randseed, nmax_bbs, authorize_privileges,
              check_pc_spike_again, max_num_instructions=None,
              no_dependency_bias=False):
        tmp = _tempfile.NamedTemporaryFile(suffix=".elf", delete=False)
        tmp.write(bytes([randseed % 256]) * 64)
        tmp.close()
        rtl_elfpath = str(Path(tmp.name))
        return (None, rtl_elfpath, None, 0.1, 0.2, 0.3)

    return _fake


def _red4_spikespeed_lock_worker(queue, lock_path: str, worker_id: int):
    import os
    import time

    from scripts.evaluation.baseline_adapters import cascade_generate_campaign as helper

    os.environ["PMPFUZZ_CASCADE_SPIKESPEED_LOCK"] = lock_path

    def _critical():
        enter = time.monotonic()
        queue.put(("enter", worker_id, enter))
        time.sleep(0.25)
        leave = time.monotonic()
        queue.put(("exit", worker_id, leave))

    helper._call_with_spikespeed_lock(_critical)





class TestDescriptorTupleContract(unittest.TestCase):

    _helper = None
    _import_error = None

    @classmethod
    def setUpClass(cls):
        try:
            from scripts.evaluation.baseline_adapters import\
                cascade_generate_campaign as _h
            cls._helper = _h
        except ImportError as e:
            cls._import_error = str(e)

    def setUp(self):
        if self._helper is None:
            self.fail(
                f"RED4: Helper module cascade_generate_campaign.py not found. "
                f"Import error: {self._import_error}"
            )

    def test_descriptor_is_5_tuple_not_object(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, mock_fuzz, mock_spike, mock_profile = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=_red4_elf_fake(),
            )
            with patch.dict(sys.modules, modules):
                rc = self._helper.generate_campaign(
                    "rocket", seed=42, count=1, output_dir=out)


            call = mock_fuzz.gen_new_test_instance.call_args
            self.assertEqual(call[0][0], "rocket")
            self.assertEqual(call[0][1], 42)
            self.assertEqual(call[0][2], True)

    def test_derived_instance_ids_are_seed_plus_case_index(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, mock_fuzz, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=_red4_elf_fake(),
            )
            with patch.dict(sys.modules, modules):
                self._helper.generate_campaign("rocket", seed=100, count=4,
                                               output_dir=out)

        calls = mock_fuzz.gen_new_test_instance.call_args_list
        expected_ids = [100, 101, 102, 103]
        for i, call in enumerate(calls):
            instance_id = call[0][1]
            self.assertEqual(
                instance_id, expected_ids[i],
                f"Case {i}: derived instance_id must be {expected_ids[i]}, "
                f"got {instance_id}",
            )

    def test_same_inputs_produce_identical_descriptor_calls(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"

            modules_a, mock_fuzz_a, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=_red4_elf_fake(),
            )
            modules_b, mock_fuzz_b, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=_red4_elf_fake(),
            )

            with patch.dict(sys.modules, modules_a):
                self._helper.generate_campaign("rocket", seed=42, count=3,
                                               output_dir=out)
            with patch.dict(sys.modules, modules_b):
                self._helper.generate_campaign("rocket", seed=42, count=3,
                                               output_dir=out)

        calls_a = mock_fuzz_a.gen_new_test_instance.call_args_list
        calls_b = mock_fuzz_b.gen_new_test_instance.call_args_list
        self.assertEqual(len(calls_a), 3)
        self.assertEqual(len(calls_b), 3)
        for i in range(3):
            with self.subTest(case_index=i):
                self.assertEqual(calls_a[i], calls_b[i])

    def test_different_seeds_produce_different_descriptor_calls(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules_a, mock_fuzz_a, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=_red4_elf_fake(),
            )
            modules_b, mock_fuzz_b, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=_red4_elf_fake(),
            )

            with patch.dict(sys.modules, modules_a):
                self._helper.generate_campaign("rocket", seed=7, count=3,
                                               output_dir=out)
            with patch.dict(sys.modules, modules_b):
                self._helper.generate_campaign("rocket", seed=13, count=3,
                                               output_dir=out)

        calls_a = mock_fuzz_a.gen_new_test_instance.call_args_list
        calls_b = mock_fuzz_b.gen_new_test_instance.call_args_list
        self.assertEqual(len(calls_a), 3)
        self.assertEqual(len(calls_b), 3)
        for i in range(3):
            with self.subTest(case_index=i):
                self.assertNotEqual(calls_a[i], calls_b[i])

    def test_design_propagates_as_first_arg(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, mock_fuzz, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=_red4_elf_fake(),
            )
            with patch.dict(sys.modules, modules):
                self._helper.generate_campaign("boom", seed=0, count=2,
                                               output_dir=out)

        calls = mock_fuzz.gen_new_test_instance.call_args_list
        self.assertEqual(len(calls), 2)
        for i, call in enumerate(calls):
            self.assertEqual(call[0][0], "boom",
                             f"Case {i}: first arg must be 'boom'")

    def test_bapc_single_target_filter_resamples_ambiguous_cases(self):
        class FakeMemInstr:
            def __init__(self, mnemonic, producer_id):
                self.instr_str = mnemonic
                self.producer_id = producer_id
                self.imm = 0

        def fake_state(candidate_count):
            instr_objs_seq = [[]]
            bb_start_addr_seq = [0]
            producer_map = {}
            for i in range(candidate_count):
                producer_id = i + 1
                mnemonic = "lw" if i % 2 == 0 else "sd"
                instr_objs_seq.append([FakeMemInstr(mnemonic, producer_id)])
                bb_start_addr_seq.append(0x40 * (i + 1))
                producer_map[producer_id] = 0x1000 + (0x100 * i)
            return unittest.mock.Mock(
                instr_objs_seq=instr_objs_seq,
                bb_start_addr_seq=bb_start_addr_seq,
                producer_id_to_tgtaddr=producer_map,
                design_base_addr=0x80000000,
            )

        elf_side_effect = _red4_elf_fake()
        states = [fake_state(2), fake_state(1)]

        def fake_elf(*args, **kwargs):
            _unused_state, path, expected, t_bbs, t_spike, t_elf = elf_side_effect(
                *args, **kwargs
            )
            return (states.pop(0), path, expected, t_bbs, t_spike, t_elf)

        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, mock_fuzz, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=fake_elf,
            )
            with patch.dict(sys.modules, modules):
                rc = self._helper.generate_campaign(
                    "rocket",
                    seed=42,
                    count=1,
                    output_dir=out,
                    require_single_target_operation=True,
                    max_target_operation_attempts_per_case=3,
                )

            self.assertEqual(rc, 0)
            self.assertEqual(mock_fuzz.gen_fuzzerstate_elf_expectedvals.call_count, 2)
            sidecar = json.loads((out / "rocket_0.json").read_text(encoding="ascii"))
            self.assertEqual(sidecar["target_operation_filter"], "single")
            self.assertEqual(sidecar["target_operation_attempt"], 1)
            self.assertEqual(len(sidecar["target_operation_candidates"]), 1)
            self.assertEqual(sidecar["target_operation_id"], "bb1-i0")

    def test_bapc_sidecar_selects_first_natural_candidate_without_resampling(self):
        class FakeMemInstr:
            def __init__(self, mnemonic, producer_id):
                self.instr_str = mnemonic
                self.producer_id = producer_id
                self.imm = 0

        fake_state = unittest.mock.Mock(
            instr_objs_seq=[[], [FakeMemInstr("lw", 1)], [FakeMemInstr("sd", 2)]],
            bb_start_addr_seq=[0, 0x40, 0x80],
            producer_id_to_tgtaddr={1: 0x1000, 2: 0x2000},
            design_base_addr=0x80000000,
        )

        def fake_elf(*args, **kwargs):
            _unused_state, path, expected, t_bbs, t_spike, t_elf = _red4_elf_fake()(*args, **kwargs)
            return (fake_state, path, expected, t_bbs, t_spike, t_elf)

        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, mock_fuzz, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=fake_elf,
            )
            with patch.dict(sys.modules, modules):
                rc = self._helper.generate_campaign(
                    "rocket",
                    seed=42,
                    count=1,
                    output_dir=out,
                    require_target_operation_candidate=True,
                )

            self.assertEqual(rc, 0)
            self.assertEqual(mock_fuzz.gen_fuzzerstate_elf_expectedvals.call_count, 1)
            sidecar = json.loads((out / "rocket_0.json").read_text(encoding="ascii"))
            self.assertEqual(sidecar["target_operation_filter"], "nonempty")
            self.assertEqual(
                sidecar["target_operation_selection_rule"],
                "deterministic-first-natural-candidate",
            )
            self.assertEqual(sidecar["target_operation_attempt"], 0)
            self.assertEqual(sidecar["target_operation_id"], "bb1-i0")
            self.assertEqual(sidecar["access"], "load")
            self.assertEqual(sidecar["instruction_address"], "0x80000040")

    def test_non_cva6_sidecar_rejects_runtime_only_candidates_without_static_address(self):
        class FakeMemInstr:
            def __init__(self, mnemonic, producer_id=None):
                self.instr_str = mnemonic
                self.producer_id = producer_id
                self.imm = 0

        fake_state = unittest.mock.Mock(
            instr_objs_seq=[[], [FakeMemInstr("lw", 1), FakeMemInstr("fsw")]],
            bb_start_addr_seq=[0, 0x40],
            producer_id_to_tgtaddr={1: 0x1000},
            design_base_addr=0x80000000,
        )

        def fake_elf(*args, **kwargs):
            _unused_state, path, expected, t_bbs, t_spike, t_elf = _red4_elf_fake()(*args, **kwargs)
            return (fake_state, path, expected, t_bbs, t_spike, t_elf)

        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, mock_fuzz, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=fake_elf,
            )
            with patch.dict(sys.modules, modules):
                rc = self._helper.generate_campaign(
                    "rocket",
                    seed=42,
                    count=1,
                    output_dir=out,
                    require_target_operation_candidate=True,
                )

            self.assertEqual(rc, 0)
            self.assertEqual(mock_fuzz.gen_fuzzerstate_elf_expectedvals.call_count, 1)
            sidecar = json.loads((out / "rocket_0.json").read_text(encoding="ascii"))
            self.assertEqual(len(sidecar["target_operation_candidates"]), 1)
            self.assertEqual(sidecar["target_operation_candidates"][0]["target_operation_id"], "bb1-i0")
            self.assertEqual(sidecar["target_operation_selection_rule"], "deterministic-first-natural-candidate")

    def test_bapc_nonempty_target_filter_resamples_zero_candidate_cases(self):
        class FakeMemInstr:
            def __init__(self, mnemonic, producer_id):
                self.instr_str = mnemonic
                self.producer_id = producer_id
                self.imm = 0

        empty_state = unittest.mock.Mock(
            instr_objs_seq=[[]],
            bb_start_addr_seq=[0],
            producer_id_to_tgtaddr={},
            design_base_addr=0x80000000,
        )
        selected_state = unittest.mock.Mock(
            instr_objs_seq=[[], [FakeMemInstr("lw", 1)], [FakeMemInstr("sd", 2)]],
            bb_start_addr_seq=[0, 0x40, 0x80],
            producer_id_to_tgtaddr={1: 0x1000, 2: 0x2000},
            design_base_addr=0x80000000,
        )
        states = [empty_state, selected_state]

        def fake_elf(*args, **kwargs):
            _unused_state, path, expected, t_bbs, t_spike, t_elf = _red4_elf_fake()(*args, **kwargs)
            return (states.pop(0), path, expected, t_bbs, t_spike, t_elf)

        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, mock_fuzz, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=fake_elf,
            )
            with patch.dict(sys.modules, modules):
                rc = self._helper.generate_campaign(
                    "rocket",
                    seed=42,
                    count=1,
                    output_dir=out,
                    require_target_operation_candidate=True,
                    max_target_operation_attempts_per_case=3,
                )

            self.assertEqual(rc, 0)
            self.assertEqual(mock_fuzz.gen_fuzzerstate_elf_expectedvals.call_count, 2)
            sidecar = json.loads((out / "rocket_0.json").read_text(encoding="ascii"))
            self.assertEqual(sidecar["target_operation_filter"], "nonempty")
            self.assertEqual(sidecar["target_operation_attempt"], 1)
            self.assertEqual(sidecar["target_operation_id"], "bb1-i0")





class TestGenFunctionExactSignature(unittest.TestCase):

    _helper = None
    _import_error = None

    @classmethod
    def setUpClass(cls):
        try:
            from scripts.evaluation.baseline_adapters import\
                cascade_generate_campaign as _h
            cls._helper = _h
        except ImportError as e:
            cls._import_error = str(e)

    def setUp(self):
        if self._helper is None:
            self.fail(
                f"RED4: Helper not found. Import error: {self._import_error}"
            )

    def test_gen_fuzzerstate_called_with_exact_six_args(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, _, mock_spike, mock_profile = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=_red4_elf_fake(),
            )
            mock_fuzz = modules["cascade.fuzzfromdescriptor"]
            with patch.dict(sys.modules, modules):
                self._helper.generate_campaign("rocket", seed=10, count=1,
                                               output_dir=out)

        elf_call = mock_fuzz.gen_fuzzerstate_elf_expectedvals.call_args
        self.assertIsNotNone(
            elf_call,
            "gen_fuzzerstate_elf_expectedvals must be called",
        )
        args = elf_call[0]
        self.assertEqual(
            len(args), 6,
            f"Expected exactly 6 positional args, got {len(args)}: {args!r}",
        )



        self.assertIsInstance(args[0], int, "memsize must be int")
        self.assertEqual(args[1], "rocket", "design_name must be 'rocket'")
        self.assertIsInstance(args[2], int, "randseed must be int")
        self.assertIsInstance(args[3], int, "nmax_bbs must be int")
        self.assertIsInstance(args[4], bool, "authorize_privileges must be bool")
        self.assertIs(
            args[5], False,
            f"check_pc_spike_again must be False, got {args[5]!r}",
        )

    def test_gen_fuzzerstate_args_match_descriptor_tuple_fields(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"


            def _fixed_descriptor(dn, rs, ca, fm=None, fn=None):
                return (8192, dn, rs, 20, ca)

            modules, mock_fuzz, _, _ = _red4_mock_modules(
                descriptor_side_effect=_fixed_descriptor,
                elf_side_effect=_red4_elf_fake(),
            )
            with patch.dict(sys.modules, modules):
                self._helper.generate_campaign("cva6", seed=5, count=1,
                                               output_dir=out)

        elf_call = mock_fuzz.gen_fuzzerstate_elf_expectedvals.call_args
        self.assertEqual(elf_call[0][0], 8192)
        self.assertEqual(elf_call[0][1], "cva6")
        self.assertEqual(elf_call[0][2], 5)
        self.assertEqual(elf_call[0][3], 20)
        self.assertEqual(elf_call[0][4], True)
        self.assertIs(elf_call[0][5], False)





class TestElfMoveFromReturnedPath(unittest.TestCase):

    _helper = None
    _import_error = None

    @classmethod
    def setUpClass(cls):
        try:
            from scripts.evaluation.baseline_adapters import\
                cascade_generate_campaign as _h
            cls._helper = _h
        except ImportError as e:
            cls._import_error = str(e)

    def setUp(self):
        if self._helper is None:
            self.fail(
                f"RED4: Helper not found. Import error: {self._import_error}"
            )

    def test_elf_is_moved_from_returned_path_to_output_name(self):
        source_paths = []

        def _capturing_elf_fake(memsize, design_name, randseed, nmax_bbs,
                                authorize_privileges, check_pc_spike_again,
                                max_num_instructions=None,
                                no_dependency_bias=False):
            import tempfile
            tmp = tempfile.NamedTemporaryFile(suffix=".elf", delete=False)
            tmp.write(bytes([randseed % 256]) * 128)
            tmp.close()
            rtl_path = str(Path(tmp.name))
            source_paths.append(rtl_path)
            return (None, rtl_path, None, 0.1, 0.2, 0.3)

        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, _, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=_capturing_elf_fake,
            )
            with patch.dict(sys.modules, modules):
                self._helper.generate_campaign("rocket", seed=1, count=2,
                                               output_dir=out)


            for i in range(2):
                dest = out / f"rocket_{i}.elf"
                self.assertTrue(
                    dest.exists(),
                    f"Output ELF {dest} must exist after generation",
                )
                self.assertGreater(
                    dest.stat().st_size, 0,
                    f"Output ELF {dest} must not be empty",
                )


            for src in source_paths:
                self.assertFalse(
                    Path(src).exists(),
                    f"Source ELF {src} must not exist after move; "
                    f"helper must use shutil.move, not copy",
                )

    def test_elf_naming_uses_case_index(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, _, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=_red4_elf_fake(),
            )
            with patch.dict(sys.modules, modules):
                self._helper.generate_campaign("boom", seed=99, count=3,
                                               output_dir=out)

            expected = {"boom_0.elf", "boom_1.elf", "boom_2.elf"}
            actual = {f.name for f in out.glob("*.elf")}
            self.assertEqual(expected, actual,
                             f"ELF names must use case_index, got {actual}")





class TestSidecarFullTupleFields(unittest.TestCase):

    _helper = None
    _import_error = None

    @classmethod
    def setUpClass(cls):
        try:
            from scripts.evaluation.baseline_adapters import\
                cascade_generate_campaign as _h
            cls._helper = _h
        except ImportError as e:
            cls._import_error = str(e)

    def setUp(self):
        if self._helper is None:
            self.fail(
                f"RED4: Helper not found. Import error: {self._import_error}"
            )

    def test_sidecar_records_all_tuple_fields(self):

        def _fixed_descriptor(dn, rs, ca, fm=None, fn=None):
            return (8192, dn, rs, 20, ca)

        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, _, _, _ = _red4_mock_modules(
                descriptor_side_effect=_fixed_descriptor,
                elf_side_effect=_red4_elf_fake(),
            )
            with patch.dict(sys.modules, modules):
                self._helper.generate_campaign("rocket", seed=5, count=2,
                                               output_dir=out)

            for case_index in range(2):
                sidecar_path = out / f"rocket_{case_index}.json"
                with self.subTest(case_index=case_index):
                    self.assertTrue(
                        sidecar_path.exists(),
                        f"Sidecar {sidecar_path} must exist",
                    )
                    sc = json.loads(sidecar_path.read_text(encoding="ascii"))


                    self.assertEqual(sc["campaign_seed"], 5)
                    self.assertEqual(sc["case_index"], case_index)
                    self.assertEqual(
                        sc["derived_instance_id"], 5 + case_index,
                    )


                    self.assertEqual(sc["memsize"], 8192)
                    self.assertEqual(sc["design"], "rocket")
                    self.assertEqual(sc["randseed"], 5 + case_index)
                    self.assertEqual(sc["nmax_bbs"], 20)
                    self.assertEqual(sc["authorize_privileges"], True)

    def test_sidecars_are_one_to_one_with_elfs(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, _, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=_red4_elf_fake(),
            )
            with patch.dict(sys.modules, modules):
                self._helper.generate_campaign("cva6", seed=0, count=2,
                                               output_dir=out)

            all_files = list(out.iterdir())
            self.assertEqual(
                len(all_files), 4,
                f"Expected exactly 4 files (2 ELFs + 2 sidecars), "
                f"got {len(all_files)}: {[f.name for f in all_files]}",
            )
            for case_index in range(2):
                self.assertTrue(
                    (out / f"cva6_{case_index}.elf").exists(),
                )
                self.assertTrue(
                    (out / f"cva6_{case_index}.json").exists(),
                )





class TestCalibrationSetupContract(unittest.TestCase):

    _helper = None
    _import_error = None

    @classmethod
    def setUpClass(cls):
        try:
            from scripts.evaluation.baseline_adapters import\
                cascade_generate_campaign as _h
            cls._helper = _h
        except ImportError as e:
            cls._import_error = str(e)

    def setUp(self):
        if self._helper is None:
            self.fail(
                f"RED4: Helper not found. Import error: {self._import_error}"
            )

    def test_calibrate_spikespeed_called_before_elf_generation(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, _, mock_spike, mock_profile = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=_red4_elf_fake(),
            )
            with patch.dict(sys.modules, modules):
                self._helper.generate_campaign("rocket", seed=1, count=1,
                                               output_dir=out)

        mock_spike.calibrate_spikespeed.assert_called_once()
        mock_profile.profile_get_medeleg_mask.assert_called_once_with("rocket")

    def test_calibration_runs_under_shared_spikespeed_lock(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, _, mock_spike, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=_red4_elf_fake(),
            )
            with patch.dict(sys.modules, modules):
                with patch.object(
                    self._helper,
                    "_call_with_spikespeed_lock",
                    side_effect=lambda fn: fn(),
                ) as mock_lock:
                    self._helper.generate_campaign("rocket", seed=1, count=1, output_dir=out)

        mock_lock.assert_called_once()
        mock_spike.calibrate_spikespeed.assert_called_once()

    def test_calibration_runs_before_descriptor_generation(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, mock_fuzz, mock_spike, mock_profile = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=_red4_elf_fake(),
            )


            parent = MagicMock()
            parent.attach_mock(mock_spike.calibrate_spikespeed,
                               "calibrate_spikespeed")
            parent.attach_mock(mock_profile.profile_get_medeleg_mask,
                               "profile_get_medeleg_mask")
            parent.attach_mock(mock_fuzz.gen_new_test_instance,
                               "gen_new_test_instance")

            with patch.dict(sys.modules, modules):
                self._helper.generate_campaign("boom", seed=7, count=2,
                                               output_dir=out)


        calib_idx = parent.mock_calls.index(
            unittest.mock.call.calibrate_spikespeed())
        profile_idx = parent.mock_calls.index(
            unittest.mock.call.profile_get_medeleg_mask("boom"))
        first_desc_idx = parent.mock_calls.index(
            unittest.mock.call.gen_new_test_instance("boom", 7, True))

        self.assertLess(calib_idx, first_desc_idx,
                        "calibrate_spikespeed must run before gen_new_test_instance")
        self.assertLess(profile_idx, first_desc_idx,
                        "profile_get_medeleg_mask must run before gen_new_test_instance")

    def test_shared_spikespeed_lock_serializes_parallel_calibration(self):
        import multiprocessing
        import os

        if os.name != "posix":
            self.skipTest("fcntl-based lock serialization is only enforced on POSIX")

        with TemporaryDirectory() as tmp:
            lock_path = str(Path(tmp) / "spikespeed.lock")
            queue = multiprocessing.Queue()
            workers = [
                multiprocessing.Process(
                    target=_red4_spikespeed_lock_worker,
                    args=(queue, lock_path, worker_id),
                )
                for worker_id in (0, 1)
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=15)
            for worker in workers:
                self.assertFalse(worker.is_alive(), "worker must exit")
                self.assertEqual(worker.exitcode, 0, "worker must complete successfully")

            events = [queue.get(timeout=5) for _ in range(4)]

        spans = {}
        for kind, worker_id, ts in events:
            spans.setdefault(worker_id, {})[kind] = ts
        self.assertEqual(set(spans.keys()), {0, 1})
        for worker_id, span in spans.items():
            self.assertIn("enter", span, f"worker {worker_id} missing enter event")
            self.assertIn("exit", span, f"worker {worker_id} missing exit event")

        ordered = sorted(
            ((span["enter"], span["exit"], worker_id) for worker_id, span in spans.items()),
            key=lambda item: item[0],
        )
        self.assertGreaterEqual(
            ordered[1][0],
            ordered[0][1] - 1e-6,
            "shared spikespeed lock must prevent overlapping calibration critical sections",
        )

    def test_different_designs_get_correct_profile_call(self):
        for design in ("rocket", "boom", "cva6", "xiangshan"):
            with self.subTest(design=design):
                with TemporaryDirectory() as tmp:
                    out = Path(tmp) / "elfs"
                    modules, _, _, mock_profile = _red4_mock_modules(
                        descriptor_side_effect=_red4_descriptor_fake(),
                        elf_side_effect=_red4_elf_fake(),
                    )
                    with patch.dict(sys.modules, modules):
                        self._helper.generate_campaign(
                            design, seed=0, count=1, output_dir=out)

                mock_profile.profile_get_medeleg_mask.assert_called_with(design)





class TestGenerationFailureModes(unittest.TestCase):

    _helper = None
    _import_error = None

    @classmethod
    def setUpClass(cls):
        try:
            from scripts.evaluation.baseline_adapters import\
                cascade_generate_campaign as _h
            cls._helper = _h
        except ImportError as e:
            cls._import_error = str(e)

    def setUp(self):
        if self._helper is None:
            self.fail(
                f"RED4: Helper not found. Import error: {self._import_error}"
            )



    @staticmethod
    def _malformed_descriptor_fake():
        def _fake(dn, rs, ca, fm=None, fn=None):
            return (4096, dn, rs)
        return _fake

    @staticmethod
    def _missing_elf_fake():
        def _fake(memsize, dn, rs, nmax, auth, check_pc, *args, **kwargs):
            import tempfile
            tmp = tempfile.NamedTemporaryFile(suffix=".elf", delete=False)
            nonexistent = str(Path(tmp.name))
            tmp.close()
            Path(nonexistent).unlink()
            return (None, nonexistent, None, 0.1, 0.2, 0.3)
        return _fake

    @staticmethod
    def _raising_elf_fake():
        def _fake(*args, **kwargs):
            raise RuntimeError("simulated generation crash")
        return _fake

    @staticmethod
    def _move_blocking_elf_fake():
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".elf", delete=False)
        tmp.write(b"ELF")
        tmp.close()
        rtl = str(Path(tmp.name))

        def _fake(memsize, dn, rs, nmax, auth, check_pc, *args, **kwargs):
            return (None, rtl, None, 0.1, 0.2, 0.3)
        return _fake, rtl



    def test_malformed_descriptor_returns_nonzero(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, _, _, _ = _red4_mock_modules(
                descriptor_side_effect=self._malformed_descriptor_fake(),
                elf_side_effect=_red4_elf_fake(),
            )
            with patch.dict(sys.modules, modules):
                rc = self._helper.generate_campaign(
                    "rocket", seed=1, count=1, output_dir=out)

        self.assertNotEqual(
            rc, 0,
            "Malformed descriptor must cause nonzero return",
        )

        self.assertFalse(
            (out / "rocket_0.json").exists(),
            "No sidecar must be written for a failed case",
        )

    def test_missing_returned_elf_returns_nonzero(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, _, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=self._missing_elf_fake(),
            )
            with patch.dict(sys.modules, modules):
                rc = self._helper.generate_campaign(
                    "rocket", seed=2, count=1, output_dir=out)

        self.assertNotEqual(rc, 0,
                            "Missing returned ELF must cause nonzero return")
        self.assertFalse((out / "rocket_0.json").exists(),
                         "No sidecar for failed case")

    def test_generation_exception_returns_nonzero(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, _, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=self._raising_elf_fake(),
            )
            with patch.dict(sys.modules, modules):
                rc = self._helper.generate_campaign(
                    "rocket", seed=3, count=1, output_dir=out)

        self.assertNotEqual(rc, 0,
                            "Generation exception must cause nonzero return")
        self.assertFalse((out / "rocket_0.json").exists(),
                         "No sidecar for failed case")

    def test_move_failure_returns_nonzero_and_cleans_up(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            elf_fake, rtl_path = self._move_blocking_elf_fake()


            out.mkdir(parents=True, exist_ok=True)
            modules, _, _, _ = _red4_mock_modules(
                descriptor_side_effect=_red4_descriptor_fake(),
                elf_side_effect=elf_fake,
            )
            with patch.dict(sys.modules, modules):








                with patch("shutil.move", side_effect=OSError("move failed")):
                    rc = self._helper.generate_campaign(
                        "rocket", seed=4, count=1, output_dir=out)

        self.assertNotEqual(rc, 0,
                            "Move failure must cause nonzero return")
        self.assertFalse((out / "rocket_0.json").exists(),
                         "No sidecar for failed move")

        try:
            Path(rtl_path).unlink(missing_ok=True)
        except Exception:
            pass

    def test_first_case_fails_second_succeeds(self):
        call_count = [0]

        def _alternating_descriptor(dn, rs, ca, fm=None, fn=None):
            call_count[0] += 1
            if call_count[0] == 1:
                return (4096, dn, rs)
            else:
                return (4096, dn, rs, 10, ca)

        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "elfs"
            modules, _, _, _ = _red4_mock_modules(
                descriptor_side_effect=_alternating_descriptor,
                elf_side_effect=_red4_elf_fake(),
            )
            with patch.dict(sys.modules, modules):
                rc = self._helper.generate_campaign(
                    "rocket", seed=5, count=2, output_dir=out)

        self.assertNotEqual(rc, 0,
                            "Any case failure must cause nonzero return")

        self.assertFalse(
            (out / "rocket_0.json").exists(),
            "Case 0 failed → no sidecar",
        )
        self.assertFalse(
            (out / "rocket_0.elf").exists(),
            "Case 0 failed → no ELF",
        )










class TestHelperFailureModes(unittest.TestCase):

    def test_nonzero_helper_return_causes_generation_failure(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(
                        returncode=1, stderr="helper crashed")
                    out = Path(tmp, "out")
                    result = cascade._generate_elfs(
                        1, out, seed=0, design="rocket")

        self.assertFalse(
            result["success"],
            "Nonzero helper returncode must cause generation failure",
        )
        self.assertEqual(result["returncode"], 1)

    def test_spike_timeout_helper_failure_retries_generation_once(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                out = Path(tmp, "out")
                ws = cascade._generation_workspace(out, seed=6, design="boom")
                batch_dir = ws / "elfs-00000304"
                stage_ok = MagicMock(returncode=0, stderr="", stdout="")
                spike_timeout = MagicMock(
                    returncode=1,
                    stderr="Case boom_1: Spike timeout (A) for identifier str: 876679_boom_311_53",
                    stdout="",
                )
                helper_ok = MagicMock(returncode=0, stderr="", stdout="")
                copy_ok = MagicMock(returncode=0, stderr="", stdout="")
                scripted = iter([
                    stage_ok,
                    stage_ok,
                    spike_timeout,
                    stage_ok,
                    stage_ok,
                    helper_ok,
                ])

                def fake_run(cmd, *args, **kwargs):
                    if (
                        isinstance(cmd, list)
                        and cmd[:2] == ["docker", "cp"]
                        and len(cmd) >= 4
                        and str(cmd[2]).startswith(f"{cascade.CASCADE_CONTAINER}:")
                    ):
                        batch_dir.mkdir(parents=True, exist_ok=True)
                        (batch_dir / "boom_304.elf").write_bytes(b"ELF")
                        (batch_dir / "boom_304.json").write_text("{}", encoding="ascii")
                        return copy_ok
                    return next(scripted)

                with patch.object(cascade.subprocess, "run", side_effect=fake_run) as mock_run:
                    result = cascade._generate_elfs(
                        1,
                        out,
                        seed=6,
                        design="boom",
                        start_index=304,
                    )

        self.assertTrue(
            result["success"],
            "Retryable Spike timeout must not fail the entire generation batch.",
        )
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(
            len(_generator_run_commands(mock_run)),
            2,
            "Retryable Spike timeout must issue a second generator exec attempt.",
        )

    def test_missing_expected_elf_causes_failure(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    out = Path(tmp, "out")

                    ws = cascade._generation_workspace(
                        out, seed=0, design="rocket")
                    elfs_dir = ws / "elfs"
                    elfs_dir.mkdir(parents=True, exist_ok=True)
                    (elfs_dir / "rocket_0.elf").write_bytes(b"a")
                    (elfs_dir / "rocket_0.json").write_text("{}")

                    result = cascade._generate_elfs(
                        3, out, seed=0, design="rocket")

        self.assertFalse(
            result["success"],
            "Missing expected ELFs must cause generation failure. "
            "Requested 3 but only 1 ELF was produced.",
        )

    def test_extra_unexpected_elf_causes_failure(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    out = Path(tmp, "out")
                    ws = cascade._generation_workspace(
                        out, seed=0, design="rocket")
                    elfs_dir = ws / "elfs"
                    elfs_dir.mkdir(parents=True, exist_ok=True)

                    for i in range(3):
                        (elfs_dir / f"rocket_{i}.elf").write_bytes(b"x")
                        (elfs_dir / f"rocket_{i}.json").write_text("{}")

                    result = cascade._generate_elfs(
                        1, out, seed=0, design="rocket")

        self.assertFalse(
            result["success"],
            "Extra/unexpected ELFs in output must cause generation failure. "
            "Requested 1 but 3 ELFs were produced.",
        )

    def test_elf_without_sidecar_causes_failure(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    out = Path(tmp, "out")
                    ws = cascade._generation_workspace(
                        out, seed=0, design="rocket")
                    elfs_dir = ws / "elfs"
                    elfs_dir.mkdir(parents=True, exist_ok=True)

                    (elfs_dir / "rocket_0.elf").write_bytes(b"a")


                    result = cascade._generate_elfs(
                        1, out, seed=0, design="rocket")

        self.assertFalse(
            result["success"],
            "ELF without matching sidecar must cause generation failure",
        )

    def test_sidecar_without_elf_causes_failure(self):
        with TemporaryDirectory() as tmp:
            with patch.object(cascade, "CASCADE_MOUNT_DIR", Path(tmp)):
                with patch.object(cascade.subprocess, "run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0, stderr="")
                    out = Path(tmp, "out")
                    ws = cascade._generation_workspace(
                        out, seed=0, design="rocket")
                    elfs_dir = ws / "elfs"
                    elfs_dir.mkdir(parents=True, exist_ok=True)

                    (elfs_dir / "rocket_0.json").write_text("{}")


                    result = cascade._generate_elfs(
                        1, out, seed=0, design="rocket")

        self.assertFalse(
            result["success"],
            "Sidecar without matching ELF must cause generation failure",
        )


if __name__ == "__main__":
    unittest.main()
