from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.evaluation.hardware.c910.run_c910_m2_campaign import build_round_plan, materialize_round_sources


REPO = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = Path(os.environ.get("PMPFUZZ_EVIDENCE_ROOT", REPO / "artifacts"))
M2_ROOT = EVIDENCE_ROOT / "hw-v2-m2" / "c910"


@unittest.skipUnless(
    (M2_ROOT / "registration.json").is_file(),
    "requires external C910 M2 evidence; set PMPFUZZ_EVIDENCE_ROOT",
)
class C910M2DriverTest(unittest.TestCase):
    def test_build_round_plan_uses_registered_guided_first_order(self):
        with TemporaryDirectory() as tmp:
            plan = build_round_plan(m2_root=M2_ROOT, out_dir=Path(tmp))

        self.assertEqual(len(plan), 6)
        self.assertEqual([(item["mode"], item["round_id"]) for item in plan[:3]], [
            ("guided", "round-0000"),
            ("guided", "round-0001"),
            ("guided", "round-0002"),
        ])
        self.assertEqual([(item["mode"], item["round_id"]) for item in plan[3:]], [
            ("random", "round-0000"),
            ("random", "round-0001"),
            ("random", "round-0002"),
        ])
        self.assertTrue(all(Path(item["manifest_path"]).exists() for item in plan))

    def test_materialize_round_sources_writes_generated_c_for_each_manifest(self):
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            plan = build_round_plan(m2_root=M2_ROOT, out_dir=out_dir)
            materialized = materialize_round_sources(plan)

            self.assertEqual(len(materialized), 6)
            first = materialized[0]
            source_path = Path(first["generated_c_path"])
            source = source_path.read_text(encoding="ascii")
            manifest = json.loads(Path(first["manifest_path"]).read_text(encoding="ascii"))

        self.assertEqual(source_path.name, "c910_nonpmp_generated_manifest.c")
        self.assertIn("c910_nonpmp_manifest_sha256", source)
        self.assertIn(manifest["sha256"], source)
        self.assertIn(manifest["entries"][0]["case_id"], source)


if __name__ == "__main__":
    unittest.main()
