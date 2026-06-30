import tempfile
import unittest
from pathlib import Path

from pmpfuzz.__main__ import build_parser, main
from pmpfuzz.source_probe import default_source_probe_specs, discover_source_probes, write_source_probe_manifest


class SourceProbeTest(unittest.TestCase):
    def test_default_specs_cover_xiangshan_boom_and_rocket_security_chain(self):
        specs = default_source_probe_specs()
        by_dut = {}
        for spec in specs:
            by_dut.setdefault(spec.dut, set()).add(spec.security_chain)

        self.assertIn("xiangshan-clean", by_dut)
        self.assertIn("boom-clean", by_dut)
        self.assertIn("rocket-clean", by_dut)
        self.assertIn("pmp-check", by_dut["xiangshan-clean"])
        self.assertIn("ptw-request", by_dut["boom-clean"])
        self.assertIn("exception-arbitration", by_dut["rocket-clean"])
        self.assertTrue(all("PMFUZZ_PROBE" in spec.instrumentation_hint for spec in specs))

    def test_discovers_source_probe_sites_in_fake_dut_trees(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xiangshan = root / "xiangshan"
            chipyard = root / "chipyard"
            _write(
                xiangshan / "src/main/scala/xiangshan/backend/fu/PMP.scala",
                "class PMP { val pmp_hit = true }\n",
            )
            _write(
                xiangshan / "src/main/scala/xiangshan/cache/mmu/L2TLB.scala",
                "class L2TLB { val ptw_req_count = 0 }\n",
            )
            _write(
                chipyard / "generators/boom/src/main/scala/v3/lsu/tlb.scala",
                "val pmp = Module(new PMPChecker(lgMaxSize))\n"
                "newEntry.ae := io.ptw.resp.bits.ae_final\n"
                "val ptw_ae_array = Wire(Vec(nWays, Bool()))\n",
            )
            _write(
                chipyard / "generators/rocket-chip/src/main/scala/rocket/PMP.scala",
                "class PMPChecker(lgMaxSize: Int) extends Module\n",
            )
            _write(
                chipyard / "generators/rocket-chip/src/main/scala/rocket/PTW.scala",
                "class PTW { val ae_ptw = true; val ae_final = false }\n",
            )
            _write(
                chipyard / "generators/rocket-chip/src/main/scala/rocket/TLB.scala",
                "val ptw_ae_array = Reg(Vec(nWays, Bool()))\n",
            )

            manifest = discover_source_probes(
                ["xiangshan-clean", "boom-clean", "rocket-clean"],
                roots={"xiangshan-clean": xiangshan, "boom-clean": chipyard, "rocket-clean": chipyard},
            )

        found = [probe for probe in manifest["probes"] if probe["status"] == "source_found"]
        self.assertGreaterEqual(len(found), 6)
        self.assertTrue(any(probe["probe_id"] == "boom_ptw_response_ae" for probe in found))
        self.assertTrue(any(probe["probe_id"] == "rocket_ptw_access_exception" for probe in found))
        self.assertTrue(all(probe["line"] >= 1 for probe in found))
        self.assertTrue(all(probe["matched_text"] for probe in found))
        self.assertTrue(all("PMFUZZ_PROBE" in probe["instrumentation_hint"] for probe in found))

    def test_write_source_probe_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xiangshan = root / "xiangshan"
            _write(
                xiangshan / "src/main/scala/xiangshan/backend/fu/PMP.scala",
                "class PMP { val pmp_hit = true }\n",
            )

            out = write_source_probe_manifest(["xiangshan-clean"], roots={"xiangshan-clean": xiangshan}, out_dir=root / "out")

            text = out.read_text(encoding="ascii")

        self.assertEqual(out.name, "source_probe_manifest.json")
        self.assertIn("xiangshan_pmp_checker", text)

    def test_cli_accepts_probe_source_command(self):
        parser = build_parser()

        args = parser.parse_args(["probe-source", "--dut", "xiangshan-clean,boom-clean,rocket-clean", "--out", "out"])

        self.assertEqual(args.command, "probe-source")
        self.assertEqual(args.dut, "xiangshan-clean,boom-clean,rocket-clean")
        self.assertEqual(args.out, Path("out"))

    def test_cli_writes_probe_source_manifest_with_explicit_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            xiangshan = root / "xiangshan"
            chipyard = root / "chipyard"
            _write(
                xiangshan / "src/main/scala/xiangshan/backend/fu/PMP.scala",
                "class PMP { val pmp_hit = true }\n",
            )
            _write(
                chipyard / "generators/rocket-chip/src/main/scala/rocket/PMP.scala",
                "class PMPChecker(lgMaxSize: Int) extends Module\n",
            )

            rc = main(
                [
                    "probe-source",
                    "--dut",
                    "xiangshan-clean,rocket-clean",
                    "--xiangshan-root",
                    str(xiangshan),
                    "--chipyard-dir",
                    str(chipyard),
                    "--out",
                    str(root / "out"),
                ]
            )

            manifest = root / "out" / "source_probe_manifest.json"
            exists = manifest.exists()

        self.assertEqual(rc, 0)
        self.assertTrue(exists)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="ascii")


if __name__ == "__main__":
    unittest.main()
