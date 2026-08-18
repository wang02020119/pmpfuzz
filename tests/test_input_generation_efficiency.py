import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.evaluation.analysis.run_input_generation_efficiency import (
    build_parser,
    resolve_profiles,
    run_batch,
)


class InputGenerationEfficiencyScriptTest(unittest.TestCase):
    def test_parser_restricts_duts_to_formal_matrix(self):
        parser = build_parser()

        args = parser.parse_args(["--tool", "pmpfuzz", "--dut", "rocket", "--seed", "4", "--out", "out"])
        self.assertEqual(args.dut, "rocket")
        self.assertEqual(args.count, 300)

        with self.assertRaises(SystemExit):
            parser.parse_args(["--tool", "pmpfuzz", "--dut", "xiangshan", "--seed", "4", "--out", "out"])

    def test_resolve_profiles_expands_core_stateful_target(self):
        profiles = resolve_profiles("core-stateful")

        self.assertIn("pmp-boundary", profiles)
        self.assertIn("smepmp-locked-entry", profiles)
        self.assertNotIn("core-stateful", profiles)

    @patch("scripts.evaluation.analysis.run_input_generation_efficiency._measure_static_instructions")
    @patch("scripts.evaluation.analysis.run_input_generation_efficiency._run_pmpfuzz_batch")
    def test_run_batch_times_only_generate_to_elf(self, run_pmpfuzz_batch, measure_static_instructions):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            elf_dir = out_dir / "batch"
            elf_dir.mkdir(parents=True, exist_ok=True)
            elf_paths = []
            for index in range(3):
                elf_path = elf_dir / f"case_{index:04d}.elf"
                elf_path.write_bytes(b"ELF")
                elf_paths.append(elf_path)

            run_pmpfuzz_batch.return_value = {
                "elf_paths": elf_paths,
                "profile_distribution": {"pmp-boundary": 1.0},
            }
            measure_static_instructions.return_value = {
                "total_static_instructions": 21,
                "per_elf": {path.name: 7 for path in elf_paths},
            }

            parser = build_parser()
            args = parser.parse_args(
                ["--tool", "pmpfuzz", "--dut", "boom", "--seed", "5", "--count", "3", "--out", str(out_dir)]
            )
            clock_values = iter([10.0, 14.5, 20.0, 23.0])

            report = run_batch(args, monotonic=lambda: next(clock_values))

        self.assertEqual(report["timed_generation_seconds"], 4.5)
        self.assertEqual(report["post_timed_analysis_seconds"], 3.0)
        self.assertEqual(report["timed_scope"], "generate-to-elf")
        self.assertTrue(report["objdump_counted_outside_timed_window"])
        self.assertEqual(run_pmpfuzz_batch.call_count, 1)
        self.assertEqual(measure_static_instructions.call_count, 1)

    @patch("scripts.evaluation.analysis.run_input_generation_efficiency._measure_static_instructions")
    @patch("scripts.evaluation.analysis.run_input_generation_efficiency._run_pmpfuzz_batch")
    def test_run_batch_writes_manifest_with_exact_batch_size(self, run_pmpfuzz_batch, measure_static_instructions):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            batch_dir = out_dir / "batch"
            batch_dir.mkdir(parents=True, exist_ok=True)
            elf_paths = []
            for index in range(300):
                elf_path = batch_dir / f"case_{index:04d}.elf"
                elf_path.write_bytes(b"ELF")
                elf_paths.append(elf_path)

            run_pmpfuzz_batch.return_value = {
                "elf_paths": elf_paths,
                "profile_distribution": {"pmp-boundary": 1.0},
            }
            measure_static_instructions.return_value = {
                "total_static_instructions": 900,
                "per_elf": {path.name: 3 for path in elf_paths},
            }

            parser = build_parser()
            args = parser.parse_args(["--tool", "pmpfuzz", "--dut", "cva6", "--seed", "6", "--out", str(out_dir)])
            report = run_batch(args, monotonic=iter([0.0, 30.0, 30.0, 45.0]).__next__)
            manifest = json.loads((out_dir / "batch_manifest.json").read_text(encoding="ascii"))

        self.assertEqual(report["count_requested"], 300)
        self.assertEqual(report["generated_elf_count"], 300)
        self.assertEqual(report["elfs_per_second"], 10.0)
        self.assertEqual(manifest["tool"], "pmpfuzz")
        self.assertEqual(manifest["dut"], "cva6")
        self.assertEqual(manifest["generated_elf_count"], 300)
        self.assertEqual(manifest["timed_generation_seconds"], 30.0)

    @patch("scripts.evaluation.analysis.run_input_generation_efficiency._measure_static_instructions")
    @patch("scripts.evaluation.analysis.run_input_generation_efficiency._run_cascade_batch")
    def test_cascade_batch_uses_design_name_matching_dut(self, run_cascade_batch, measure_static_instructions):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            elf_path = out_dir / "rocket_0000.elf"
            elf_path.parent.mkdir(parents=True, exist_ok=True)
            elf_path.write_bytes(b"ELF")

            run_cascade_batch.return_value = {
                "elf_paths": [elf_path],
                "generator_report": {"success": True},
            }
            measure_static_instructions.return_value = {
                "total_static_instructions": 4,
                "per_elf": {elf_path.name: 4},
            }

            parser = build_parser()
            args = parser.parse_args(
                ["--tool", "cascade", "--dut", "rocket", "--seed", "4", "--count", "1", "--out", str(out_dir)]
            )
            run_batch(args, monotonic=iter([0.0, 1.0, 1.0, 1.5]).__next__)

        self.assertEqual(run_cascade_batch.call_args.kwargs["design"], "rocket")
        self.assertEqual(run_cascade_batch.call_args.kwargs["count"], 1)


if __name__ == "__main__":
    unittest.main()
