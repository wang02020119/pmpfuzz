from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "evaluation"))

from pmpfuzz.c910_nonpmp_dynamic import (
    GENERATED_MANIFEST_SCHEMA_VERSION,
    build_dynamic_manifest,
    build_generated_case,
    generated_manifest_source,
    write_dynamic_run,
)
from pmpfuzz.c910_m2_scheduling import predict_shared56_bins
from pmpfuzz.v4_nonpmp_projection import classify_scenario
from pmpfuzz.schema import read_json

from c910_cl56_common import REACHABLE_BINS, construct_params_for_bin
from c910_guided_generate import breadth_round, guided_round
from c910_build_seed_pool import build_seed_pool


def _uart_for_record(case: dict, *, result: str, cause: int | None) -> str:
    """Synthetic UART case block for a generated sv39_access/mprv_bare case."""
    record = case["uart_record"]
    parser = case["uart_parser"]
    if parser == "mprv":
        op = "mprv-store" if case["access"] == "store" else "mprv-load"
        if result == "trap":
            line = (
                f"[security-chain] {op} {record} addr=0x1234a000 mpp=1 extra=0x0 "
                f"result=trap cause=0x{cause:x} trap_name=page_fault tval=0x1234a000"
            )
        else:
            line = f"[security-chain] {op} {record} addr=0x1234a000 mpp=1 extra=0x0 result=allow val=0x42"
    else:
        raise ValueError(f"no synthetic UART for parser {parser}")
    return (
        f"[nonpmp-chain] case begin case_id={case['name']} "
        f"scenario_hash={case['scenario_hash']} record={record} start_ticks=100\n"
        f"{line}\n"
        f"[nonpmp-chain] case end case_id={case['name']} "
        f"scenario_hash={case['scenario_hash']} record={record} end_ticks=200 elapsed_ticks=100"
    )


class C910GeneratedCaseTest(unittest.TestCase):
    def test_generated_case_targets_privdec_s_store_deny(self):
        params = construct_params_for_bin(
            "family=privilege-decision|effective_privilege=s|access=store|allow_or_deny=deny",
            index=0, seed=4,
        )
        self.assertIsNotNone(params)
        case = build_generated_case(params=params, index=0)
        predicted = predict_shared56_bins(case)
        self.assertEqual(predicted["status"], "mapped")
        self.assertIn(
            "family=privilege-decision|effective_privilege=s|access=store|allow_or_deny=deny",
            predicted["bins"],
        )
        self.assertEqual(case["uart_parser"], "mprv")
        self.assertEqual(case["generated_params"]["runner_code"], 1)  # sv39_access

    def test_generated_case_mprv_bare_translation_bare(self):
        params = construct_params_for_bin(
            "family=stimulus|privilege=m|effective_privilege=s|access=load|translation=bare",
            index=1, seed=4,
        )
        case = build_generated_case(params=params, index=1)
        self.assertEqual(case["translation"], "bare")
        self.assertEqual(case["generated_params"]["runner_code"], 2)  # mprv_bare

    def test_every_reachable_bin_constructs_or_is_declared(self):
        for bin_id in REACHABLE_BINS:
            params = construct_params_for_bin(bin_id, index=0, seed=4)
            if params is None:
                continue
            case = build_generated_case(params=params, index=0)
            predicted = predict_shared56_bins(case)
            self.assertEqual(predicted["status"], "mapped", bin_id)
            self.assertIn(bin_id, predicted["bins"], bin_id)

    def test_reachable_declaration_covers_46(self):
        self.assertEqual(len(REACHABLE_BINS), 46)
        self.assertEqual(56 - len(REACHABLE_BINS), 10)


class C910ManifestV3Test(unittest.TestCase):
    def test_generated_manifest_is_schema3_with_params(self):
        case = build_generated_case(
            params=construct_params_for_bin(
                "family=privilege-decision|effective_privilege=s|access=store|allow_or_deny=deny",
                index=0, seed=4,
            ),
            index=0,
        )
        manifest = build_dynamic_manifest(
            case_names=[], campaign_id="camp", round_id="round-0001",
            selection_source="c910-guided-generate-v1", generated_cases=[case],
        )
        self.assertEqual(manifest["schema_version"], GENERATED_MANIFEST_SCHEMA_VERSION)
        self.assertEqual(manifest["generated_case_count"], 1)
        entry = manifest["entries"][0]
        self.assertEqual(entry["runner_code"], 1)
        self.assertIn("params", entry)
        self.assertIn("case", entry)

    def test_catalog_only_manifest_stays_v2(self):
        manifest = build_dynamic_manifest(
            case_names=["c910-nonpmp-privilege__guard-as-m"],
            campaign_id="camp", round_id="round-0000",
        )
        self.assertEqual(manifest["schema_version"], 2)
        self.assertNotIn("params", manifest["entries"][0])

    def test_generated_source_emits_params_struct_and_initializer(self):
        case = build_generated_case(
            params=construct_params_for_bin(
                "family=privilege-decision|effective_privilege=s|access=store|allow_or_deny=deny",
                index=0, seed=4,
            ),
            index=0,
        )
        manifest = build_dynamic_manifest(
            case_names=[], campaign_id="camp", round_id="round-0001",
            selection_source="c910-guided-generate-v1", generated_cases=[case],
        )
        src = generated_manifest_source(manifest)
        self.assertIn("struct c910_nonpmp_case_params", src)
        self.assertIn("runner_code", src)
        self.assertIn("params;", src)
        self.assertIn(case["uart_record"], src)


class C910WriteRunV3Test(unittest.TestCase):
    def test_write_dynamic_run_resolves_embedded_generated_case(self):
        params = construct_params_for_bin(
            "family=privilege-decision|effective_privilege=s|access=store|allow_or_deny=deny",
            index=0, seed=4,
        )
        case = build_generated_case(params=params, index=0)
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            uart_log = root / "uart.log"
            uart_log.write_text(_uart_for_record(case, result="trap", cause=0xf), encoding="utf-8")
            manifest_path = root / "manifest-v3.json"
            manifest = build_dynamic_manifest(
                case_names=[], campaign_id="camp", round_id="round-0001",
                selection_source="c910-guided-generate-v1", generated_cases=[case],
            )
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            write_dynamic_run(
                uart_log=uart_log, manifest_path=manifest_path, out_dir=root / "run",
            )

            cases_dir = root / "run" / "cases"
            self.assertEqual(
                sorted(p.name for p in cases_dir.iterdir()),
                [case["name"]],
            )
            result = read_json(root / "run" / "results" / case["name"] / "result.json")
            self.assertEqual(result["status"], "pass")
            report = classify_scenario(case, result)
            self.assertEqual(report["status"], "mapped")
            self.assertIn(
                "family=privilege-decision|effective_privilege=s|access=store|allow_or_deny=deny",
                report["bins"],
            )
            self.assertEqual(report["known_violation"], False)


class C910GeneratorTest(unittest.TestCase):
    def test_seed_pool_has_catalog_and_constructed(self):
        candidates, summary = build_seed_pool()
        self.assertGreater(summary["catalog_count"], 200)
        self.assertGreater(summary["constructed_count"], 0)

    def test_breadth_round_selects_budget(self):
        from c910_guided_generate import _catalog_mapped_cases, _constructed_breadth_pool

        pool = _catalog_mapped_cases() + _constructed_breadth_pool(4)
        selected, result = breadth_round(pool=pool, budget=16, seed=4, used_hashes=set())
        self.assertEqual(len(selected), 16)
        self.assertGreaterEqual(result["stats"]["covered_bins_estimate"], 30)

    def test_guided_round_targets_all_missing_reachable_bins(self):
        candidates, _ = build_seed_pool()
        covered = {
            "family=decision|access=load|allow_or_deny=allow|mcause_class=none",
            "family=privilege-decision|effective_privilege=m|access=load|allow_or_deny=allow",
            "family=stimulus|privilege=m|effective_privilege=m|access=load|translation=bare",
        }
        missing = [b for b in REACHABLE_BINS if b not in covered]
        catalog_selected, generated, result = guided_round(
            seed_pool=candidates, missing=missing, budget=16, seed=4, used_hashes=set(),
        )
        self.assertEqual(result["stats"]["targeted_bin_count"], min(len(missing), 16))
        self.assertEqual(len(catalog_selected) + len(generated), 16)
        # skipped bins are benign duplicates: already covered by a selected case.
        all_pred = set()
        for case in catalog_selected + generated:
            all_pred.update(case.get("predicted_bins") or [])
        for item in result["log"].get("skipped_targets") or []:
            self.assertIn(item["bin"], all_pred)


if __name__ == "__main__":
    unittest.main()
