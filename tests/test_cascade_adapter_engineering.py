"""Engineering-only contract tests for the Cascade evaluation adapter."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.evaluation.baseline_adapters import cascade


class TestCascadeDutMatrix(unittest.TestCase):
    def test_adapter_declares_all_evaluation_duts(self):
        self.assertEqual(
            set(cascade.SUPPORTED_DUTS),
            {"rocket-clean", "boom-clean", "xiangshan-clean", "cva6-clean"},
        )

    def test_simulator_commands_are_dut_specific(self):
        elf = Path("/tmp/case.elf")
        cva6_command, _ = cascade._simulator_command("cva6-clean", elf, 1234)
        xiangshan_command, _ = cascade._simulator_command("xiangshan-clean", elf, 1234)

        self.assertIn("CVA6Config", cva6_command[0])
        self.assertIn("+max-cycles=1234", cva6_command)
        self.assertEqual(xiangshan_command[1:3], ["--no-diff", "-C"])
        self.assertIn("1234", xiangshan_command)
        self.assertEqual(xiangshan_command[-2:], ["-i", str(elf)])


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


if __name__ == "__main__":
    unittest.main()
