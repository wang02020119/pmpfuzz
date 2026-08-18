from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmpfuzz.c910_nonpmp_dynamic import (
    DEFAULT_PILOT_CASE_NAMES,
    build_dynamic_manifest,
    catalog_cases,
    generated_manifest_source,
    parse_case_timings,
    write_dynamic_manifest,
    write_dynamic_run,
)
from pmpfuzz.schema import read_json


SAMPLE_DYNAMIC_LOG = """
[nonpmp-chain] case begin case_id=c910-nonpmp-privilege__bare-s-ecall-fw-text scenario_hash=fe1a8c09cb0c27517eb7ba62337c158641f32140adfe13f4d9d7f4d0d14faa09 record=bare-s-ecall-fw-text start_ticks=100
[nonpmp-chain] real-mode record=bare-s-ecall-fw-text entry=0x80200000 mpp=1 arg0=0x0 arg1=0x0 satp=0x0 extra=0x0 result=trap cause=0x9 trap_name=supervisor_ecall tval=0x0 mepc=0x80200000 payload_result=0xfacefeeddeadbeef
[nonpmp-chain] case end case_id=c910-nonpmp-privilege__bare-s-ecall-fw-text scenario_hash=fe1a8c09cb0c27517eb7ba62337c158641f32140adfe13f4d9d7f4d0d14faa09 record=bare-s-ecall-fw-text end_ticks=160 elapsed_ticks=60
[nonpmp-chain] case begin case_id=c910-nonpmp-side-effect__translated-u-store-final-pa scenario_hash=794ed4e23d8d6d9dbc1a2f4ec53c9545ddfb25d221cc07fd98501d14c537c37f record=translated-u-store-final-pa start_ticks=200
[security-chain] mprv-store sv39-u-store-data-page-translated addr=0x1234e000 mpp=0 extra=0x0 result=allow val=0xfeed0000cafe1111
[security-chain] side-effect translated-u-store-final-pa direct=0xfeed0000cafe1111 same_va=0xfeed0000cafe1111 observer_va=0xfeed0000cafe1111 observer_changed=1 expected_changed=0xfeed0000cafe1111
[nonpmp-chain] case end case_id=c910-nonpmp-side-effect__translated-u-store-final-pa scenario_hash=794ed4e23d8d6d9dbc1a2f4ec53c9545ddfb25d221cc07fd98501d14c537c37f record=translated-u-store-final-pa end_ticks=350 elapsed_ticks=150
[nonpmp-chain] case begin case_id=c910-nonpmp-side-effect__store-stale-fill scenario_hash=5367c183ec9335a881df9ae54508af9a13bb5c5005a837415a3635b30fa06f4c record=store-stale-fill start_ticks=400
[uarch-chain] side-effect record=store-stale-fill direct=0x1111111111111111 same_va=0x2222222222222222 observer_va=0x2222222222222222 observer_changed=1 expected=0x2222222222222222
[nonpmp-chain] case end case_id=c910-nonpmp-side-effect__store-stale-fill scenario_hash=5367c183ec9335a881df9ae54508af9a13bb5c5005a837415a3635b30fa06f4c record=store-stale-fill end_ticks=520 elapsed_ticks=120
""".strip()


class C910NonPmpDynamicManifestTest(unittest.TestCase):
    def test_catalog_cases_expands_beyond_fixed_bootstrap(self):
        cases = catalog_cases()

        self.assertGreaterEqual(len(cases), 256)
        self.assertTrue(any(case.get("runner_params") for case in cases))
        self.assertGreater(
            len({tuple(sorted((case.get("runner_params") or {}).items())) for case in cases}),
            64,
        )

    def test_build_dynamic_manifest_tracks_selected_subset(self):
        names = list(DEFAULT_PILOT_CASE_NAMES[:2])

        manifest = build_dynamic_manifest(
            case_names=names,
            campaign_id="camp-a",
            round_id="round-0000",
        )

        self.assertEqual(manifest["schema_version"], 2)
        self.assertEqual(manifest["case_count"], 2)
        self.assertGreaterEqual(manifest["catalog_case_count"], 256)
        self.assertEqual([entry["case_id"] for entry in manifest["entries"]], names)
        self.assertTrue(all(entry["scenario_hash"] for entry in manifest["entries"]))
        self.assertTrue(all(entry["runner_params"] for entry in manifest["entries"]))
        self.assertEqual(manifest["selection_source"], "bootstrap")

    def test_generated_manifest_source_embeds_record_lookup(self):
        manifest = build_dynamic_manifest(
            case_names=list(DEFAULT_PILOT_CASE_NAMES[:2]),
            campaign_id="camp-b",
            round_id="round-0001",
        )

        source = generated_manifest_source(manifest)

        self.assertIn('const char *c910_nonpmp_manifest_campaign_id(void)', source)
        self.assertIn('int c910_nonpmp_record_selected(const char *record)', source)
        self.assertIn("const struct c910_nonpmp_case_entry *c910_nonpmp_manifest_case_at", source)
        self.assertIn('c910_nonpmp_case_name_for_record', source)
        self.assertIn(manifest["entries"][0]["record"], source)
        self.assertIn("runner_kind", source)
        self.assertIn(manifest["sha256"], source)


class C910NonPmpDynamicTimingTest(unittest.TestCase):
    def test_parse_case_timings_reads_begin_end_pairs(self):
        timings = parse_case_timings(SAMPLE_DYNAMIC_LOG)

        first = timings["c910-nonpmp-privilege__bare-s-ecall-fw-text"]
        self.assertEqual(first["elapsed_ticks"], 60)
        self.assertEqual(first["start_ticks"], 100)
        self.assertEqual(first["end_ticks"], 160)


class C910NonPmpDynamicRunTest(unittest.TestCase):
    def test_write_dynamic_run_writes_subset_results_and_timeline(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            uart_log = root / "uart.log"
            uart_log.write_text(SAMPLE_DYNAMIC_LOG, encoding="utf-8")
            manifest_path = root / "round_manifest.json"
            manifest = write_dynamic_manifest(
                out_json=manifest_path,
                out_c=None,
                case_names=[
                    "c910-nonpmp-privilege__bare-s-ecall-fw-text",
                    "c910-nonpmp-side-effect__translated-u-store-final-pa",
                    "c910-nonpmp-side-effect__store-stale-fill",
                ],
                campaign_id="camp-live",
                round_id="round-0000",
            )

            summary = write_dynamic_run(
                uart_log=uart_log,
                manifest_path=manifest_path,
                out_dir=root / "run",
            )

            self.assertEqual(summary["dut"], "c910-nonpmp")
            cases_root = root / "run" / "cases"
            results_root = root / "run" / "results"
            self.assertEqual(
                sorted(path.name for path in cases_root.iterdir()),
                sorted(entry["case_id"] for entry in manifest["entries"]),
            )
            pass_result = read_json(
                results_root / "c910-nonpmp-privilege__bare-s-ecall-fw-text" / "result.json"
            )
            self.assertEqual(pass_result["status"], "pass")
            self.assertEqual(pass_result["elapsed_ticks"], 60)
            self.assertAlmostEqual(pass_result["elapsed_seconds"], 60 / 3_000_000)
            side_effect = read_json(
                results_root / "c910-nonpmp-side-effect__translated-u-store-final-pa" / "result.json"
            )
            self.assertEqual(side_effect["status"], "pass")
            self.assertEqual(side_effect["elapsed_ticks"], 150)
            stale_fill = read_json(
                results_root / "c910-nonpmp-side-effect__store-stale-fill" / "result.json"
            )
            self.assertEqual(stale_fill["status"], "pass")
            self.assertEqual(stale_fill["elapsed_ticks"], 120)

            timeline_lines = [
                json.loads(line)
                for line in (root / "run" / "metrics" / "coverage_timeline.jsonl").read_text(
                    encoding="ascii"
                ).splitlines()
                if line.strip()
            ]
            self.assertEqual(len(timeline_lines), 4)
            self.assertIsNone(timeline_lines[0]["case_id"])
            self.assertEqual(timeline_lines[-1]["case_id"], "c910-nonpmp-side-effect__store-stale-fill")

            coverage = read_json(root / "run" / "coverage" / "coverage.json")
            execution = coverage["execution_coverage"]["by_dut"]["c910-nonpmp"]
            self.assertEqual(execution["qualification"]["eligible_results"], 3)
            self.assertGreater(execution["semantic"]["total_target_bins"], execution["semantic"]["covered_target_bins"])
