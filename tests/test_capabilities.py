import json
import tempfile
import unittest
from pathlib import Path

from pmpfuzz.__main__ import build_parser, main
from pmpfuzz.capabilities import (
    DEFAULT_CAPABILITY_SCHEMA_VERSION,
    capability_for_dut,
    capability_matrix,
    oracle_applicability_for_case,
    required_capabilities_for_case,
)
from pmpfuzz.schema import result_to_dict, scenario_to_case_dict, write_json
from pmpfuzz.scenario import ScenarioGenerator
from pmpfuzz.triage import write_report


class CapabilityModelTest(unittest.TestCase):
    def test_parser_accepts_probe_dut_command(self):
        parser = build_parser()

        args = parser.parse_args(["probe-dut", "--dut", "spike,rocket-clean,xiangshan-clean", "--out", "out"])
        smepmp_args = parser.parse_args(["probe-dut", "--dut", "spike", "--probe-smepmp", "--out", "out"])

        self.assertEqual(args.command, "probe-dut")
        self.assertEqual(args.dut, "spike,rocket-clean,xiangshan-clean")
        self.assertTrue(smepmp_args.probe_smepmp)

    def test_capability_schema_v2_records_smepmp_probe_details(self):
        matrix = capability_matrix(["spike", "rocket-clean"], probe_smepmp=True)

        self.assertEqual(matrix["schema_version"], 2)
        spike = matrix["duts"]["spike"]
        rocket = matrix["duts"]["rocket-clean"]
        self.assertIn("smepmp", spike)
        self.assertEqual(
            set(spike["smepmp"]),
            {"csr_access", "mml", "mmwp", "rlb", "warl_behavior", "probe_status"},
        )
        self.assertIn(spike["smepmp"]["probe_status"], {"supported", "unsupported", "infra_unadapted", "unknown"})
        self.assertIn("smepmp", rocket)
        self.assertEqual(rocket["supported_capabilities"]["smepmp"], rocket["smepmp"]["probe_status"] == "supported")

    def test_capability_schema_records_finish_protocol_and_diagnostic_depth(self):
        spike = capability_for_dut("spike", available=True)
        with tempfile.TemporaryDirectory() as tmp:
            emu = Path(tmp) / "emu"
            emu.write_text("", encoding="ascii")
            (Path(tmp) / "VSimTop.mk").write_text("CXXFLAGS += -DDIFFTEST\n", encoding="ascii")
            xiangshan = capability_for_dut("xiangshan-clean", path=emu, available=True)

        self.assertEqual(spike["schema_version"], DEFAULT_CAPABILITY_SCHEMA_VERSION)
        self.assertEqual(spike["finish_protocol"], "tohost")
        self.assertEqual(spike["diagnostic_depth"], "structured_tohost")
        self.assertEqual(spike["oracle_applicability"], "valid")
        self.assertEqual(xiangshan["finish_protocol"], "xiangshan-goodtrap")
        self.assertEqual(xiangshan["diagnostic_depth"], "pass_fail_only")
        self.assertEqual(xiangshan["oracle_applicability"], "valid")

    def test_xiangshan_no_difftest_emu_is_infra_unadapted(self):
        with tempfile.TemporaryDirectory() as tmp:
            emu = Path(tmp) / "emu"
            emu.write_text("", encoding="ascii")
            (Path(tmp) / "VSimTop.mk").write_text("CXXFLAGS += -DCONFIG_NO_DIFFTEST\n", encoding="ascii")

            xiangshan = capability_for_dut("xiangshan-clean", path=emu, available=True)

        self.assertEqual(xiangshan["path"], str(emu))
        self.assertEqual(xiangshan["oracle_applicability"], "infra_unadapted")
        self.assertTrue(any("CONFIG_NO_DIFFTEST" in note for note in xiangshan["notes"]))

    def test_xiangshan_difftest_emu_is_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            emu = Path(tmp) / "emu"
            emu.write_text("", encoding="ascii")
            (Path(tmp) / "VSimTop.mk").write_text("CXXFLAGS += -DDIFFTEST\n", encoding="ascii")

            xiangshan = capability_for_dut("xiangshan-clean", path=emu, available=True)

        self.assertEqual(xiangshan["oracle_applicability"], "valid")

    def test_case_schema_includes_required_capabilities_and_oracle_applicability(self):
        scenario = ScenarioGenerator(seed=9, include_smepmp=False, profile="sv39-final-pmp").generate_batch(1)[0]
        case = scenario_to_case_dict(scenario, seed=9, index=0)

        self.assertIn("required_capabilities", case)
        self.assertIn("oracle_applicability", case)
        self.assertIn("pmp", case["required_capabilities"])
        self.assertIn("sv39", case["required_capabilities"])

    def test_result_schema_carries_oracle_applicability(self):
        scenario = ScenarioGenerator(seed=1, include_smepmp=False, profile="legacy-data").generate_batch(1)[0]
        case = scenario_to_case_dict(scenario, seed=1, index=0)
        result = result_to_dict(
            case=case,
            dut="xiangshan-clean",
            status="infra_failure",
            elapsed_seconds=0.1,
            returncode=0,
            log=Path("/tmp/case.log"),
            reason="no good trap",
            failure_class="infra_unadapted",
            oracle_applicability="infra_unadapted",
        )

        self.assertEqual(result["oracle_applicability"], "infra_unadapted")
        self.assertEqual(result["required_capabilities"], case["required_capabilities"])

    def test_probe_dut_writes_capability_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = main(["probe-dut", "--dut", "spike,xiangshan-clean", "--out", tmp])
            data = json.loads((Path(tmp) / "dut_capabilities.json").read_text(encoding="ascii"))

        self.assertEqual(rc, 0)
        self.assertIn("spike", data["duts"])
        self.assertIn("xiangshan-clean", data["duts"])
        self.assertEqual(data["duts"]["spike"]["finish_protocol"], "tohost")

    def test_report_shows_capability_matrix_and_oracle_applicability(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=3, include_smepmp=False, profile="legacy-data").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=3, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)
            write_json(
                run_dir / "results" / case["name"] / "result.json",
                result_to_dict(
                    case=case,
                    dut="xiangshan-clean",
                    status="infra_failure",
                    elapsed_seconds=0.1,
                    returncode=0,
                    log=run_dir / "results" / case["name"] / "case.log",
                    reason="no marker",
                    failure_class="infra_unadapted",
                    oracle_applicability="infra_unadapted",
                ),
            )
            write_json(
                run_dir / "dut_capabilities.json",
                {
                    "schema_version": DEFAULT_CAPABILITY_SCHEMA_VERSION,
                    "duts": {"xiangshan-clean": capability_for_dut("xiangshan-clean", available=True)},
                },
            )

            report = write_report(run_dir).read_text(encoding="ascii")

        self.assertIn("DUT Capability Matrix", report)
        self.assertIn("Oracle Applicability", report)
        self.assertIn("infra_unadapted", report)

    def test_required_capabilities_reflect_core_chain_features(self):
        bare = ScenarioGenerator(seed=1, include_smepmp=False, profile="legacy-data").generate_batch(1)[0]
        sv39 = ScenarioGenerator(seed=1, include_smepmp=False, profile="sv39-ptw-pmp-matrix").generate_batch(1)[0]
        smepmp = ScenarioGenerator(seed=1, include_smepmp=True, profile="smepmp-mmwp-mmode-default-deny").generate_batch(1)[0]

        bare_required = required_capabilities_for_case(scenario_to_case_dict(bare, seed=1, index=0))
        self.assertIn("pmp", bare_required)
        self.assertNotIn("sv39", bare_required)
        self.assertIn("sv39", required_capabilities_for_case(scenario_to_case_dict(sv39, seed=1, index=0)))
        self.assertIn("smepmp", required_capabilities_for_case(scenario_to_case_dict(smepmp, seed=1, index=0)))

    def test_unsupported_smepmp_result_does_not_create_vulnerability_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            scenario = ScenarioGenerator(seed=2, include_smepmp=True, profile="smepmp-mmwp-mmode-default-deny").generate_batch(1)[0]
            case = scenario_to_case_dict(scenario, seed=2, index=0)
            write_json(run_dir / "cases" / case["name"] / "case.json", case)
            write_json(
                run_dir / "results" / case["name"] / "result.json",
                result_to_dict(
                    case=case,
                    dut="rocket-clean",
                    status="setup_unsupported",
                    elapsed_seconds=0.1,
                    returncode=None,
                    log=run_dir / "results" / case["name"] / "case.log",
                    reason="smepmp unsupported",
                    failure_class="setup_unsupported",
                    oracle_applicability="unsupported",
                ),
            )

            report = write_report(run_dir).read_text(encoding="ascii")

        self.assertIn("unsupported", report)
        self.assertIn("Vulnerability found: `false`", report)

    def test_smepmp_rlb_dependent_case_is_capability_gated(self):
        scenario = ScenarioGenerator(seed=30, include_smepmp=True, profile="smepmp-mml-shared-code").generate_batch(1)[0]
        case = scenario_to_case_dict(scenario, seed=30, index=0)
        spike = capability_for_dut("spike", available=True)

        self.assertIn("smepmp_rlb", required_capabilities_for_case(case))
        self.assertFalse(spike["supported_capabilities"]["smepmp_rlb"])
        self.assertEqual(oracle_applicability_for_case(case, spike), "unsupported")


if __name__ == "__main__":
    unittest.main()
