import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pmpfuzz.__main__ import build_parser, main


class BapcRunnerVersioningTest(unittest.TestCase):
    def test_run_parser_defaults_bapc_core_version_to_none(self):
        parser = build_parser()

        args = parser.parse_args(
            [
                "run",
                "--out",
                "out",
            ]
        )

        self.assertIsNone(args.bapc_core_version)

    def test_run_parser_accepts_bapc_core_version(self):
        parser = build_parser()

        args = parser.parse_args(
            [
                "run",
                "--out",
                "out",
                "--bapc-core-version",
                "v3",
            ]
        )

        self.assertEqual(args.bapc_core_version, "v3")

    def test_run_parser_accepts_bapc_core_version_v4(self):
        parser = build_parser()

        args = parser.parse_args(
            [
                "run",
                "--out",
                "out",
                "--bapc-core-version",
                "v4",
            ]
        )

        self.assertEqual(args.bapc_core_version, "v4")

    @patch("pmpfuzz.__main__.run_campaign", return_value=[])
    def test_run_command_threads_bapc_core_version_into_runner_config(self, mock_run_campaign):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            rc = main(
                [
                    "run",
                    "--out",
                    str(out),
                    "--dut",
                    "spike",
                    "--count",
                    "1",
                    "--jobs",
                    "1",
                    "--time-budget",
                    "1s",
                    "--per-case-timeout",
                    "1",
                    "--bapc-core-version",
                    "v3",
                ]
            )

        self.assertEqual(rc, 0)
        config = mock_run_campaign.call_args.args[0]
        self.assertEqual(config.bapc_core_version, "v3")

    @patch("pmpfuzz.__main__.run_campaign", return_value=[])
    def test_run_command_threads_bapc_core_version_v4_into_runner_config(self, mock_run_campaign):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            rc = main(
                [
                    "run",
                    "--out",
                    str(out),
                    "--dut",
                    "spike",
                    "--count",
                    "1",
                    "--jobs",
                    "1",
                    "--time-budget",
                    "1s",
                    "--per-case-timeout",
                    "1",
                    "--bapc-core-version",
                    "v4",
                ]
            )

        self.assertEqual(rc, 0)
        config = mock_run_campaign.call_args.args[0]
        self.assertEqual(config.bapc_core_version, "v4")

    @patch("pmpfuzz.__main__.run_campaign", return_value=[])
    def test_run_command_requires_explicit_bapc_core_version(self, mock_run_campaign):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            with self.assertRaisesRegex(ValueError, "bapc-core-version"):
                main(
                    [
                        "run",
                        "--out",
                        str(out),
                        "--dut",
                        "spike",
                        "--count",
                        "1",
                        "--jobs",
                        "1",
                        "--time-budget",
                        "1s",
                        "--per-case-timeout",
                        "1",
                    ]
                )

        mock_run_campaign.assert_not_called()


if __name__ == "__main__":
    unittest.main()
