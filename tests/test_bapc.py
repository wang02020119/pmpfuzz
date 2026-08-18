import hashlib
import unittest
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory

import pmpfuzz.bapc as bapc_module
from pmpfuzz.coverage_universe import make_coverage_universe
from pmpfuzz.pmp import PmpEntry

from pmpfuzz.bapc import (
    build_bapc_coverage_universe,
    map_bapc_normalized_record,
    runtime_bapc_event_records_for_cascade_execution,
    summarize_bapc_for_cascade_execution,
    summarize_bapc_for_pmpfuzz_case,
)
from pmpfuzz.schema import result_to_dict


def _entry_dict(*, mode: str = "napot", rwx: str = "111", locked: bool = False, pmpaddr: int | None = None) -> dict:
    return {
        "index": 0,
        "address_mode": mode,
        "pmpaddr": f"0x{(pmpaddr if pmpaddr is not None else PmpEntry.encode_napot(base=0x80008000, size=0x1000)):x}",
        "read": rwx[0] == "1",
        "write": rwx[1] == "1",
        "execute": rwx[2] == "1",
        "locked": locked,
    }


def _case(*, profile: str = "sv39-final-pmp") -> dict:
    return {
        "name": "case-1",
        "profile": profile,
        "privilege": "S",
        "access": "load",
        "size": 4,
        "translation": "bare",
        "mprv": False,
        "mpp": "M",
        "physical_address": "0x80008020",
        "pmp_entries": [_entry_dict()],
        "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
        "expected": {"allowed": False, "trap_cause": 12, "stage": "page_table_walk"},
        "scenario_hash": "ignored-by-bapc",
    }


def _result(**overrides) -> dict:
    result = {
        "status": "pass",
        "observation_valid": True,
        "observed_event": "completion",
        "observed_mcause": None,
        "observed_stage": "final",
    }
    result.update(overrides)
    return result


def _probe_line(**fields) -> str:
    ordered = " ".join(f"{key}={value}" for key, value in fields.items())
    return f"PMFUZZ_PROBE {ordered}\n"


def _family_counts(universe: dict) -> Counter:
    return Counter(item.split("|", 1)[0].split("=", 1)[1] for item in universe["bin_ids"])


def _off_state_evidence_record(bits: dict[str, int], *, include_evidence: bool = True) -> dict:
    record = {
        "pmp_entries": [_entry_dict(mode="off", rwx="111", locked=True, pmpaddr=0)],
        "translation": "bare",
        "privilege": "m",
        "access": "load",
        "size": 4,
        "address": "0x9000",
        "mprv": True,
        "mpp": "u",
        "allow_or_deny": "deny",
        "mcause_class": "load_access_fault",
    }
    if include_evidence:
        record["actual_pmpcfg_entries"] = [
            {
                "index": 0,
                "address_mode": "off",
                "read": bool(bits["r"]),
                "write": bool(bits["w"]),
                "execute": bool(bits["x"]),
                "locked": bool(bits["l"]),
                "evidence_kind": "csr-readback",
                "raw_log_sha256": "f" * 64,
            }
        ]
    return record


class BapcCoreTest(unittest.TestCase):
    def test_bapc_core_v2_universe_is_seed_stable_and_capability_comparable(self):
        first = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
        )
        second = build_bapc_coverage_universe(
            dut="boom-clean",
            generator_seed=2,
            supports_fault_stage=True,
            supports_smepmp=False,
        )

        self.assertEqual(first["bin_set_sha256"], second["bin_set_sha256"])
        self.assertNotEqual(first["sha256"], second["sha256"])
        self.assertEqual(first["bin_count"], 208)
        self.assertEqual(first["coverage_mode"], "bapc")
        self.assertEqual(first["generation_rule_version"], "bapc-core-universe-v2")
        self.assertEqual(first["target"], "black-box-architectural-pmp-target-operation")
        self.assertFalse(any("family=translation-stage" in item for item in first["bin_ids"]))

    def test_xiangshan_bapc_core_v2_matches_rocket_and_boom_bin_set(self):
        rocket = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
        )
        boom = build_bapc_coverage_universe(
            dut="boom-clean",
            generator_seed=2,
            supports_fault_stage=True,
            supports_smepmp=False,
        )
        xiangshan = build_bapc_coverage_universe(
            dut="xiangshan-clean",
            generator_seed=3,
            supports_fault_stage=True,
            supports_smepmp=False,
        )

        self.assertEqual(rocket["bin_count"], 208)
        self.assertEqual(rocket["bin_set_sha256"], boom["bin_set_sha256"])
        self.assertEqual(rocket["bin_set_sha256"], xiangshan["bin_set_sha256"])
        self.assertNotEqual(rocket["sha256"], xiangshan["sha256"])

    def test_bapc_core_v3_family_counts_match_mapper_closed_candidates(self):
        universe = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
            bapc_core_version="v3",
        )
        family_counts = _family_counts(universe)

        self.assertEqual(universe["bin_count"], 129)
        self.assertEqual(universe["generation_rule_version"], "bapc-core-universe-v3")
        self.assertEqual(family_counts["config"], 49)
        self.assertEqual(family_counts["stimulus"], 26)
        self.assertEqual(family_counts["decision"], 12)
        self.assertEqual(family_counts["privilege-decision"], 18)
        self.assertEqual(family_counts["mode-decision"], 24)

    def test_bapc_core_v3_excludes_noncanonical_off_bins(self):
        universe = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
            bapc_core_version="v3",
        )
        v3_bins = set(universe["bin_ids"])
        excluded = [
            f"family=config|pmp_mode=off|permission_rwx={permission_rwx}|locked={locked}"
            for permission_rwx in (f"{value:03b}" for value in range(8))
            for locked in ("false", "true")
            if not (permission_rwx == "000" and locked == "false")
        ]

        self.assertEqual(len(excluded), 15)
        self.assertTrue(set(excluded).isdisjoint(v3_bins))

    def test_bapc_core_v3_excludes_illegal_current_effective_privilege_pairs(self):
        universe = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
            bapc_core_version="v3",
        )
        v3_bins = set(universe["bin_ids"])
        legal = set()
        for privilege in ("m", "s", "u"):
            for translation in ("bare", "sv39"):
                legal.add(
                    f"family=stimulus|privilege={privilege}|effective_privilege={privilege}|access=fetch|translation={translation}"
                )
            for access in ("load", "store"):
                if privilege == "m":
                    effective_privileges = ("m", "s", "u")
                elif privilege == "s":
                    effective_privileges = ("s",)
                else:
                    effective_privileges = ("u",)
                for effective_privilege in effective_privileges:
                    for translation in ("bare", "sv39"):
                        legal.add(
                            "family=stimulus"
                            f"|privilege={privilege}"
                            f"|effective_privilege={effective_privilege}"
                            f"|access={access}"
                            f"|translation={translation}"
                        )
        excluded = [
            "family=stimulus"
            f"|privilege={privilege}"
            f"|effective_privilege={effective_privilege}"
            f"|access={access}"
            f"|translation={translation}"
            for privilege in ("m", "s", "u")
            for effective_privilege in ("m", "s", "u")
            for access in ("fetch", "load", "store")
            for translation in ("bare", "sv39")
            if (
                "family=stimulus"
                f"|privilege={privilege}"
                f"|effective_privilege={effective_privilege}"
                f"|access={access}"
                f"|translation={translation}"
            )
            not in legal
        ]

        self.assertEqual(len(excluded), 28)
        self.assertTrue(set(excluded).isdisjoint(v3_bins))

    def test_bapc_core_v3_excludes_allow_fault_bins(self):
        universe = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
            bapc_core_version="v3",
        )
        v3_bins = set(universe["bin_ids"])
        excluded = [
            f"family=decision|access={access}|allow_or_deny=allow|mcause_class={mcause_class}"
            for access in ("fetch", "load", "store")
            for mcause_class in (
                "instruction_access_fault",
                "load_access_fault",
                "store_access_fault",
                "instruction_page_fault",
                "load_page_fault",
                "store_page_fault",
                "other",
            )
        ]

        self.assertEqual(len(excluded), 21)
        self.assertTrue(set(excluded).isdisjoint(v3_bins))

    def test_bapc_core_v3_excludes_deny_none_bins(self):
        universe = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
            bapc_core_version="v3",
        )
        v3_bins = set(universe["bin_ids"])
        excluded = [
            f"family=decision|access={access}|allow_or_deny=deny|mcause_class=none"
            for access in ("fetch", "load", "store")
        ]

        self.assertEqual(len(excluded), 3)
        self.assertTrue(set(excluded).isdisjoint(v3_bins))

    def test_bapc_core_v3_excludes_cross_access_fault_bins(self):
        universe = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
            bapc_core_version="v3",
        )
        v3_bins = set(universe["bin_ids"])
        excluded = [
            "family=decision|access=fetch|allow_or_deny=deny|mcause_class=load_access_fault",
            "family=decision|access=fetch|allow_or_deny=deny|mcause_class=load_page_fault",
            "family=decision|access=fetch|allow_or_deny=deny|mcause_class=store_access_fault",
            "family=decision|access=fetch|allow_or_deny=deny|mcause_class=store_page_fault",
            "family=decision|access=load|allow_or_deny=deny|mcause_class=instruction_access_fault",
            "family=decision|access=load|allow_or_deny=deny|mcause_class=instruction_page_fault",
            "family=decision|access=load|allow_or_deny=deny|mcause_class=store_access_fault",
            "family=decision|access=load|allow_or_deny=deny|mcause_class=store_page_fault",
            "family=decision|access=store|allow_or_deny=deny|mcause_class=instruction_access_fault",
            "family=decision|access=store|allow_or_deny=deny|mcause_class=instruction_page_fault",
            "family=decision|access=store|allow_or_deny=deny|mcause_class=load_access_fault",
            "family=decision|access=store|allow_or_deny=deny|mcause_class=load_page_fault",
        ]

        self.assertEqual(len(excluded), 12)
        self.assertTrue(set(excluded).isdisjoint(v3_bins))

    def test_v2_and_v3_preserve_different_cause_mapping_rules(self):
        record = {
            "pmp_entries": [_entry_dict()],
            "translation": "bare",
            "privilege": "S",
            "access": "load",
            "size": 4,
            "address": "0x80008020",
            "mprv": False,
            "mpp": "M",
            "allow_or_deny": "deny",
            "mcause_class": "store_access_fault",
        }

        v2 = map_bapc_normalized_record(record, bapc_core_version="v2")
        v3 = map_bapc_normalized_record(record, bapc_core_version="v3")

        self.assertTrue(v2["eligible"])
        self.assertIn(
            "family=decision|access=load|allow_or_deny=deny|mcause_class=store_access_fault",
            v2["observed_bins"],
        )
        self.assertFalse(v3["eligible"])
        self.assertEqual(v3["qualification_reason"], "missing-actual-mcause-class")

    def test_same_behavior_across_pmpfuzz_and_cascade_produces_same_bins(self):
        pm_summary = summarize_bapc_for_pmpfuzz_case(
            _case(),
            _result(),
            log_text="",
        )
        cascade_summary = summarize_bapc_for_cascade_execution(
            {
                "translation": "bare",
                "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
                "pmp_entries": [_entry_dict()],
                "privilege": "S",
                "access": "load",
                "size": 4,
                "physical_address": "0x80008020",
            },
            _result(),
            stdout_text="",
        )

        self.assertTrue(pm_summary["eligible"])
        self.assertTrue(cascade_summary["eligible"])
        self.assertEqual(pm_summary["observed_bins"], cascade_summary["observed_bins"])

    def test_cascade_runtime_records_are_union_mapped_instead_of_selecting_one(self):
        sidecar = {
            "translation": "bare",
            "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
            "pmp_entries": [_entry_dict()],
            "mprv": False,
            "mpp": "M",
        }
        result = _result(
            status="fail",
            observed_event="trap",
            observed_mcause=5,
            observed_stage="final",
            observed_fault_address="0x80008020",
        )
        stdout_text = (
            _probe_line(
                dut="rocket-clean",
                probe="rocket_pmp_checker",
                chain="pmp-check",
                stage="final",
                prv=3,
                access="load",
                allow=0,
                addr="0x80008020",
                size=4,
                mcause=5,
                r=1,
                w=1,
                x=1,
            )
            + _probe_line(
                dut="rocket-clean",
                probe="rocket_pmp_checker",
                chain="pmp-check",
                stage="final",
                prv=3,
                access="store",
                allow=0,
                addr="0x80008028",
                size=8,
                mcause=7,
                r=1,
                w=1,
                x=1,
            )
            + _probe_line(
                dut="rocket-clean",
                probe="rocket_tlb_exception_arbitration",
                chain="exception-arbitration",
                stage="tlb",
                vaddr="0x80008020",
                ae_ld=1,
                ae_st=1,
            )
        )
        event_records = runtime_bapc_event_records_for_cascade_execution(
            sidecar,
            result,
            stdout_text=stdout_text,
        )

        summary = summarize_bapc_for_cascade_execution(
            sidecar,
            result,
            stdout_text=stdout_text,
            event_records=event_records,
        )

        self.assertTrue(summary["eligible"])
        observed = set(summary["observed_bins"])
        self.assertIn(
            "family=stimulus|privilege=m|effective_privilege=m|access=load|translation=bare",
            observed,
        )
        self.assertIn(
            "family=stimulus|privilege=m|effective_privilege=m|access=store|translation=bare",
            observed,
        )
        self.assertIn(
            "family=decision|access=load|allow_or_deny=deny|mcause_class=load_access_fault",
            observed,
        )
        self.assertIn(
            "family=decision|access=store|allow_or_deny=deny|mcause_class=store_access_fault",
            observed,
        )
        self.assertEqual(summary["ignored_probe_events"], 1)
        self.assertEqual(len(summary["event_records"]), 2)

    def test_ptw_pmp_check_runtime_record_forces_sv39_translation(self):
        sidecar = {
            "translation": "bare",
            "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
            "pmp_entries": [_entry_dict()],
            "mprv": False,
            "mpp": "M",
        }
        result = _result(
            status="fail",
            observed_event="trap",
            observed_mcause=5,
            observed_stage="page_table_walk",
            observed_fault_address="0x80008020",
        )
        stdout_text = _probe_line(
            dut="cva6-clean",
            probe="cva6_ptw_pmp_check",
            schema=2,
            role="diagnostic",
            chain="pmp-check",
            stage="ptw",
            prv=1,
            access="load",
            allow=0,
            addr="0x80008020",
            size=8,
        )

        event_records = runtime_bapc_event_records_for_cascade_execution(
            sidecar,
            result,
            stdout_text=stdout_text,
        )

        self.assertEqual(len(event_records), 1)
        self.assertEqual(event_records[0]["translation"], "sv39")
        self.assertEqual(event_records[0]["privilege"], "s")
        self.assertEqual(event_records[0]["effective_privilege"], "s")
        self.assertEqual(event_records[0]["access"], "load")
        self.assertEqual(event_records[0]["size"], 8)
        self.assertEqual(event_records[0]["allow_or_deny"], "deny")
        self.assertEqual(event_records[0]["mcause_class"], "load_access_fault")

    def test_cva6_ptw_response_probe_becomes_runtime_bapc_record(self):
        sidecar = {
            "translation": "bare",
            "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
            "pmp_entries": [_entry_dict()],
            "mprv": False,
            "mpp": "M",
        }
        result = _result(
            status="fail",
            observed_event="trap",
            observed_mcause=5,
            observed_stage="page_table_walk",
            observed_fault_address="0x80008020",
        )
        stdout_text = _probe_line(
            dut="cva6-clean",
            probe="cva6_ptw_exception",
            chain="ptw-response",
            stage="ptw",
            paddr="0x80008020",
            allow=0,
            exception=1,
        )

        event_records = runtime_bapc_event_records_for_cascade_execution(
            sidecar,
            result,
            stdout_text=stdout_text,
        )
        summary = summarize_bapc_for_cascade_execution(
            sidecar,
            result,
            stdout_text=stdout_text,
            event_records=event_records,
        )

        self.assertEqual(len(event_records), 1)
        self.assertEqual(event_records[0]["translation"], "sv39")
        self.assertEqual(event_records[0]["privilege"], "s")
        self.assertEqual(event_records[0]["effective_privilege"], "s")
        self.assertEqual(event_records[0]["access"], "load")
        self.assertEqual(event_records[0]["size"], 8)
        self.assertEqual(event_records[0]["allow_or_deny"], "deny")
        self.assertTrue(summary["eligible"])
        self.assertIn(
            "family=stimulus|privilege=s|effective_privilege=s|access=load|translation=sv39",
            set(summary["observed_bins"]),
        )
        self.assertIn(
            "family=decision|access=load|allow_or_deny=deny|mcause_class=load_access_fault",
            set(summary["observed_bins"]),
        )

    def test_final_pmp_check_records_are_filtered_to_declared_target_and_make_deny_case_eligible(self):
        sidecar = {
            "translation": "bare",
            "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
            "pmp_entries": [_entry_dict()],
            "privilege": "S",
            "access": "load",
            "size": 4,
            "physical_address": "0x80008020",
            "mprv": False,
            "mpp": "M",
        }
        result = _result(
            status="fail",
            observed_event="trap",
            observed_mcause=None,
            observed_stage="",
            observed_fault_address=None,
        )
        stdout_text = (
            _probe_line(
                dut="cva6-clean",
                probe="cva6_mmu_pmp_check",
                schema=2,
                role="diagnostic",
                chain="pmp-check",
                stage="final",
                prv=1,
                access="fetch",
                allow=1,
                addr="0x80000000",
            )
            + _probe_line(
                dut="cva6-clean",
                probe="cva6_mmu_pmp_check",
                schema=2,
                role="diagnostic",
                chain="pmp-check",
                stage="final",
                prv=1,
                access="load",
                allow=0,
                addr="0x80008020",
            )
        )

        event_records = runtime_bapc_event_records_for_cascade_execution(
            sidecar,
            result,
            stdout_text=stdout_text,
        )
        summary = summarize_bapc_for_cascade_execution(
            sidecar,
            result,
            stdout_text=stdout_text,
            event_records=event_records,
        )

        self.assertEqual(len(event_records), 1)
        self.assertEqual(event_records[0]["access"], "load")
        self.assertEqual(event_records[0]["address"], "0x80008020")
        self.assertEqual(event_records[0]["allow_or_deny"], "deny")
        self.assertEqual(event_records[0]["mcause_class"], "load_access_fault")
        self.assertTrue(summary["eligible"])
        self.assertIn(
            "family=decision|access=load|allow_or_deny=deny|mcause_class=load_access_fault",
            set(summary["observed_bins"]),
        )
        self.assertEqual(summary["ignored_probe_events"], 1)

    def test_mapper_outputs_stay_within_v3_universe(self):
        universe = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
            bapc_core_version="v3",
        )
        allowed = set(universe["bin_ids"])

        pm_summary = summarize_bapc_for_pmpfuzz_case(_case(), _result(), log_text="")
        cascade_summary = summarize_bapc_for_cascade_execution(
            {
                "translation": "bare",
                "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
                "pmp_entries": [_entry_dict()],
                "privilege": "S",
                "access": "load",
                "size": 4,
                "physical_address": "0x80008020",
            },
            _result(),
            stdout_text="",
        )

        self.assertTrue(set(pm_summary["observed_bins"]).issubset(allowed))
        self.assertTrue(set(cascade_summary["observed_bins"]).issubset(allowed))

    def test_mode_decision_uses_the_complete_access_byte_range(self):
        case = _case()
        case["physical_address"] = "0x80007ffc"
        case["size"] = 8
        case["pmp_entries"] = [
            _entry_dict(
                mode="na4",
                pmpaddr=0x80008000 >> 2,
            )
        ]

        summary = summarize_bapc_for_pmpfuzz_case(case, _result(), log_text="")

        self.assertTrue(summary["eligible"])
        self.assertIn(
            "family=mode-decision|pmp_mode=na4|access=load|allow_or_deny=allow",
            summary["observed_bins"],
        )

    def test_target_operation_without_access_size_is_ineligible(self):
        case = _case()
        case.pop("size")

        summary = summarize_bapc_for_pmpfuzz_case(case, _result(), log_text="")

        self.assertFalse(summary["eligible"])
        self.assertEqual(summary["qualification_reason"], "missing-actual-size")

    def test_profile_rename_and_expected_fields_do_not_change_bins(self):
        first_case = _case(profile="sv39-final-pmp")
        second_case = _case(profile="renamed-profile")
        second_case["expected"] = {
            "allowed": True,
            "trap_cause": 7,
            "stage": "stateful_final",
        }

        first = summarize_bapc_for_pmpfuzz_case(first_case, _result(), log_text="")
        second = summarize_bapc_for_pmpfuzz_case(second_case, _result(), log_text="")

        self.assertEqual(first["observed_bins"], second["observed_bins"])
        self.assertFalse(any(token in "|".join(first["observed_bins"]) for token in ("profile", "expected", "scenario")))

    def test_target_operation_does_not_require_probe(self):
        summary = summarize_bapc_for_pmpfuzz_case(
            _case(),
            _result(observed_event="trap", observed_mcause=5, status="fail", observed_stage=None),
            log_text="",
        )

        self.assertTrue(summary["eligible"])
        self.assertEqual(summary["qualification_reason"], "eligible")
        self.assertTrue(any("family=stimulus" in item for item in summary["observed_bins"]))
        self.assertTrue(any("family=decision|access=load|allow_or_deny=deny" in item for item in summary["observed_bins"]))

    def test_xiangshan_requires_structured_actual_observation_for_target_operation(self):
        summary = summarize_bapc_for_pmpfuzz_case(
            _case(),
            _result(status="pass", observation_valid=False, observed_event=None, observed_mcause=None),
            log_text="",
        )

        self.assertFalse(summary["eligible"])
        self.assertEqual(summary["qualification_reason"], "missing-actual-observation")

    def test_incomplete_probe_payload_is_ignored_for_core_target_operation(self):
        baseline = summarize_bapc_for_pmpfuzz_case(_case(), _result(), log_text="")
        summary = summarize_bapc_for_pmpfuzz_case(
            _case(),
            _result(),
            log_text="PMFUZZ_PROBE chain=pmp-check stage=final\n",
        )

        self.assertTrue(summary["eligible"])
        self.assertEqual(summary["observed_bins"], baseline["observed_bins"])

    def test_internal_probe_access_does_not_override_bound_target_operation(self):
        baseline = summarize_bapc_for_pmpfuzz_case(
            _case(),
            _result(observed_event="trap", observed_mcause=5, status="fail", observed_stage="ptw"),
            log_text="",
        )
        summary = summarize_bapc_for_cascade_execution(
            {
                "translation": "bare",
                "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
                "pmp_entries": [_entry_dict()],
                "privilege": "S",
                "access": "load",
                "size": 4,
                "physical_address": "0x80008020",
            },
            _result(status="fail", observed_event="trap", observed_mcause=5, observed_stage="ptw"),
            stdout_text=(
                _probe_line(
                    dut="rocket-clean",
                    probe="rocket_pmp_checker",
                    chain="pmp-check",
                    stage="final",
                    prv="3",
                    access="fetch",
                    allow="1",
                    addr="0x80008020",
                    r="1",
                    w="1",
                    x="1",
                )
                + _probe_line(
                    dut="rocket-clean",
                    probe="rocket_pmp_checker",
                    chain="pmp-check",
                    stage="final",
                    prv="1",
                    access="load",
                    allow="0",
                    addr="0x48ea797c",
                    r="0",
                    w="0",
                    x="0",
                )
            ),
        )

        self.assertTrue(summary["eligible"])
        self.assertEqual(summary["observed_bins"], baseline["observed_bins"])
        self.assertFalse(any("family=translation-stage" in item for item in summary["observed_bins"]))

    def test_cascade_relative_sidecar_address_matches_absolute_runtime_probe(self):
        sidecar = {
            "translation": "bare",
            "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
            "pmp_entries": [_entry_dict()],
            "privilege": "M",
            "access": "load",
            "size": 2,
            "physical_address": "0x3d232",
            "instruction_address": "0x8002d4a4",
            "target_operation_candidates": [
                {
                    "target_operation_id": "bb24-i77",
                    "privilege": "M",
                    "access": "load",
                    "size": 2,
                    "physical_address": "0x3d232",
                    "instruction_address": "0x8002d4a4",
                    "instruction_page_tag": 13,
                }
            ],
        }
        stdout_text = (
            _probe_line(
                dut="rocket-clean",
                probe="rocket_pmp_checker",
                chain="pmp-check",
                stage="final",
                prv="3",
                access="fetch",
                allow="1",
                addr="0x8002d4a4",
                size="2",
                r="1",
                w="1",
                x="1",
            )
            + _probe_line(
                dut="rocket-clean",
                probe="rocket_pmp_checker",
                chain="pmp-check",
                stage="final",
                prv="3",
                access="load",
                allow="1",
                addr="0x8003d232",
                size="1",
                r="1",
                w="1",
                x="1",
            )
        )

        runtime_records = runtime_bapc_event_records_for_cascade_execution(
            sidecar,
            _result(),
            stdout_text=stdout_text,
        )
        summary = summarize_bapc_for_cascade_execution(
            sidecar,
            _result(),
            stdout_text=stdout_text,
            event_records=runtime_records,
            bapc_core_version="v4",
        )

        self.assertEqual(len(runtime_records), 1)
        self.assertEqual(runtime_records[0]["address"], "0x8003d232")
        self.assertEqual(runtime_records[0]["access"], "load")
        self.assertTrue(summary["eligible"], summary)
        self.assertIn(
            "family=decision|access=load|allow_or_deny=allow|mcause_class=none",
            summary["observed_bins"],
        )

    def test_startup_and_diagnostic_probe_noise_do_not_change_core_bins(self):
        baseline = summarize_bapc_for_pmpfuzz_case(_case(), _result(), log_text="")
        noise = "".join(
            _probe_line(
                dut="rocket-clean",
                probe="rocket_tlb_exception_arbitration",
                chain="exception-arbitration",
                stage="tlb",
                vaddr=f"0x{0x80008020 + index * 4:x}",
                ae_ld="0",
                ae_st="0",
            )
            for index in range(1000)
        )
        noisy = summarize_bapc_for_pmpfuzz_case(_case(), _result(), log_text=noise)

        self.assertTrue(noisy["eligible"])
        self.assertEqual(noisy["observed_bins"], baseline["observed_bins"])

    def test_translation_stage_diagnostic_data_does_not_enter_core_universe(self):
        summary = summarize_bapc_for_cascade_execution(
            {
                "translation": "sv39",
                "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
                "pmp_entries": [_entry_dict()],
                "privilege": "S",
                "access": "load",
                "size": 4,
                "physical_address": "0x80008020",
            },
            _result(status="fail", observed_event="trap", observed_mcause=5, observed_stage="ptw"),
            stdout_text=(
                _probe_line(
                    dut="rocket-clean",
                    probe="rocket_ptw_access_exception",
                    chain="ptw-response",
                    stage="ptw",
                    ae_ptw="1",
                    ae_final="0",
                    paddr="0x80008020",
                )
                + _probe_line(
                    dut="rocket-clean",
                    probe="rocket_tlb_exception_arbitration",
                    chain="exception-arbitration",
                    stage="tlb",
                    vaddr="0x80008020",
                    ae_ld="1",
                    ae_st="0",
                )
            ),
        )

        self.assertTrue(summary["eligible"])
        self.assertFalse(any("family=translation-stage" in item for item in summary["observed_bins"]))

    def test_cascade_sidecar_missing_target_operation_context_fails_closed(self):
        summary = summarize_bapc_for_cascade_execution(
            {
                "translation": "bare",
                "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
                "pmp_entries": [_entry_dict()],
            },
            _result(),
            stdout_text="",
        )

        self.assertFalse(summary["eligible"])
        self.assertEqual(summary["qualification_reason"], "missing-actual-privilege")

    def test_cascade_explicit_runtime_target_operation_recovers_missing_sidecar_context(self):
        summary = summarize_bapc_for_cascade_execution(
            {
                "translation": "bare",
                "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
                "pmp_entries": [_entry_dict()],
            },
            _result(status="fail", observed_event="trap", observed_mcause=5, observed_stage="final"),
            stdout_text="",
            event_records=[
                {
                    "address": "0x80008020",
                    "privilege": "s",
                    "effective_privilege": "s",
                    "access": "load",
                    "size": 4,
                    "translation": "bare",
                    "allow_or_deny": "deny",
                    "mcause_class": "load_access_fault",
                    "fault_stage": "final",
                    "matched_pmp_mode": "napot",
                }
            ],
        )

        self.assertTrue(summary["eligible"])
        self.assertEqual(summary["qualification_reason"], "eligible")
        self.assertIn(
            "family=stimulus|privilege=s|effective_privilege=s|access=load|translation=bare",
            summary["observed_bins"],
        )
        self.assertIn(
            "family=decision|access=load|allow_or_deny=deny|mcause_class=load_access_fault",
            summary["observed_bins"],
        )

    def test_legacy_v1_artifact_is_not_silently_loaded_as_v2(self):
        loader = getattr(bapc_module, "load_bapc_coverage_universe", None)
        self.assertIsNotNone(loader, "BAPC v2 requires an explicit loader that rejects legacy v1 universes")
        legacy = make_coverage_universe(
            coverage_mode="bapc",
            bin_ids=["legacy:0"],
            capability_fingerprint="cap-legacy",
            target="black-box-architectural-pmp-behavior",
            include_experimental=False,
            generator_seed=1,
            generation_rule_version="bapc-coverage-universe-v1",
        )
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "bapc_v1.json"
            path.write_text(__import__("json").dumps(legacy, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "legacy|v1|v2"):
                loader(path)

    def test_result_schema_preserves_bapc_coverage(self):
        scenario_case = _case()
        bapc = summarize_bapc_for_pmpfuzz_case(
            scenario_case,
            _result(),
            log_text="",
        )
        result = result_to_dict(
            case=scenario_case,
            dut="rocket-clean",
            status="pass",
            elapsed_seconds=0.25,
            returncode=0,
            log=Path("/tmp/case.log"),
            reason="ok",
            bapc_coverage=bapc,
        )

        self.assertTrue(result["bapc_coverage"]["eligible"])
        self.assertEqual(result["bapc_coverage"]["observed_bins"], bapc["observed_bins"])


class BapcCoreV4Test(unittest.TestCase):
    def test_bapc_core_v4_preserves_v2_v3_and_has_expected_family_counts(self):
        v2 = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
            bapc_core_version="v2",
        )
        v3 = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
            bapc_core_version="v3",
        )
        v4 = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
            bapc_core_version="v4",
        )
        family_counts = _family_counts(v4)

        self.assertEqual(v2["bin_count"], 208)
        self.assertEqual(v3["bin_count"], 129)
        self.assertEqual(v4["bin_count"], 144)
        self.assertEqual(family_counts["config"], 64)
        self.assertEqual(family_counts["stimulus"], 26)
        self.assertEqual(family_counts["decision"], 12)
        self.assertEqual(family_counts["privilege-decision"], 18)
        self.assertEqual(family_counts["mode-decision"], 24)

    def test_bapc_core_v4_extends_v3_with_15_noncanonical_off_bins(self):
        v3 = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
            bapc_core_version="v3",
        )
        v4 = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
            bapc_core_version="v4",
        )
        extra = set(v4["bin_ids"]) - set(v3["bin_ids"])

        self.assertEqual(
            len([item for item in v4["bin_ids"] if item.startswith("family=config|pmp_mode=off|")]),
            16,
        )
        self.assertEqual(len(extra), 15)
        self.assertEqual(set(v4["bin_ids"]), set(v3["bin_ids"]) | extra)

    def test_bapc_core_v4_maps_16_off_readbacks_while_v3_canonicalizes_them(self):
        v3_config_bins = set()
        v4_config_bins = set()
        for l in (0, 1):
            for r in (0, 1):
                for w in (0, 1):
                    for x in (0, 1):
                        record = _off_state_evidence_record({"l": l, "r": r, "w": w, "x": x})
                        v3 = map_bapc_normalized_record(record, bapc_core_version="v3")
                        v4 = map_bapc_normalized_record(record, bapc_core_version="v4")
                        self.assertTrue(v3["eligible"])
                        self.assertTrue(v4["eligible"])
                        v3_config_bins.update(
                            item for item in v3["observed_bins"] if item.startswith("family=config|")
                        )
                        v4_config_bins.update(
                            item for item in v4["observed_bins"] if item.startswith("family=config|")
                        )

        self.assertEqual(
            v3_config_bins,
            {"family=config|pmp_mode=off|permission_rwx=000|locked=false"},
        )
        self.assertEqual(len(v4_config_bins), 16)

    def test_bapc_core_v4_requires_actual_off_state_evidence_for_noncanonical_bins(self):
        mapped = map_bapc_normalized_record(
            _off_state_evidence_record({"l": 1, "r": 1, "w": 1, "x": 1}, include_evidence=False),
            bapc_core_version="v4",
        )

        self.assertTrue(mapped["eligible"])
        self.assertEqual(
            [item for item in mapped["observed_bins"] if item.startswith("family=config|")],
            ["family=config|pmp_mode=off|permission_rwx=000|locked=false"],
        )

    def test_bapc_core_v4_ignores_malformed_off_state_evidence(self):
        malformed_cases = (
            {"index": "0"},
            {"read": "true"},
            {"locked": "false"},
            {"evidence_kind": "invalid-evidence"},
            {"raw_log_sha256": "not-a-sha256"},
        )

        for overrides in malformed_cases:
            with self.subTest(overrides=overrides):
                record = _off_state_evidence_record({"l": 1, "r": 0, "w": 0, "x": 1})
                record["actual_pmpcfg_entries"][0].update(overrides)
                mapped = map_bapc_normalized_record(record, bapc_core_version="v4")

                self.assertTrue(mapped["eligible"])
                self.assertEqual(
                    [item for item in mapped["observed_bins"] if item.startswith("family=config|")],
                    ["family=config|pmp_mode=off|permission_rwx=000|locked=false"],
                )
                self.assertNotIn("actual_pmpcfg_entries", mapped["normalized_record"])

    def test_pmpfuzz_v4_uses_runtime_pmpcsr_probe_for_noncanonical_off_bin(self):
        case = _case()
        case["pmp_entries"] = [_entry_dict(mode="off", rwx="111", locked=True, pmpaddr=0)]
        log_text = _probe_line(
            dut="cva6-clean",
            probe="cva6_pmp_csr_state",
            chain="pmp-csr",
            stage="csr",
            cfg="0x84",
            addr="0x0",
        )

        summary = summarize_bapc_for_pmpfuzz_case(
            case,
            _result(),
            log_text=log_text,
            bapc_core_version="v4",
        )

        self.assertTrue(summary["eligible"])
        self.assertIn(
            "family=config|pmp_mode=off|permission_rwx=001|locked=true",
            summary["observed_bins"],
        )
        self.assertEqual(
            summary["event_records"][0]["actual_pmpcfg_entries"][0]["raw_log_sha256"],
            hashlib.sha256(log_text.encode("utf-8")).hexdigest(),
        )

    def test_pmpfuzz_v4_nonzero_off_entry_requires_explicit_entry_field(self):
        case = _case()
        off_entry = _entry_dict(mode="off", rwx="111", locked=True, pmpaddr=0)
        off_entry["index"] = 3
        case["pmp_entries"] = [off_entry]

        without_entry = summarize_bapc_for_pmpfuzz_case(
            case,
            _result(),
            log_text=_probe_line(
                dut="cva6-clean",
                probe="cva6_pmp_csr_state",
                chain="pmp-csr",
                stage="csr",
                cfg="0x84",
            ),
            bapc_core_version="v4",
        )
        with_entry = summarize_bapc_for_pmpfuzz_case(
            case,
            _result(),
            log_text=_probe_line(
                dut="cva6-clean",
                probe="cva6_pmp_csr_state",
                chain="pmp-csr",
                stage="csr",
                entry="3",
                cfg="0x84",
            ),
            bapc_core_version="v4",
        )

        self.assertTrue(without_entry["eligible"])
        self.assertIn(
            "family=config|pmp_mode=off|permission_rwx=000|locked=false",
            without_entry["observed_bins"],
        )
        self.assertNotIn("actual_pmpcfg_entries", without_entry["event_records"][0])
        self.assertTrue(with_entry["eligible"])
        self.assertIn(
            "family=config|pmp_mode=off|permission_rwx=001|locked=true",
            with_entry["observed_bins"],
        )
        self.assertEqual(with_entry["event_records"][0]["actual_pmpcfg_entries"][0]["index"], 3)

    def test_pmpfuzz_v4_runtime_readback_ignores_non_off_context_entries(self):
        case = _case()
        off_entry = _entry_dict(mode="off", rwx="111", locked=True, pmpaddr=0)
        off_entry["index"] = 0
        tor_entry = _entry_dict(mode="tor", rwx="000", locked=False, pmpaddr=0x100)
        tor_entry["index"] = 1
        case["pmp_entries"] = [
            off_entry,
            tor_entry,
        ]
        log_text = "\n".join(
            [
                _probe_line(
                    dut="cva6-clean",
                    probe="cva6_pmp_csr_state",
                    chain="pmp-csr",
                    stage="csr",
                    entry="0",
                    cfg="0x84",
                ),
                _probe_line(
                    dut="cva6-clean",
                    probe="cva6_pmp_csr_state",
                    chain="pmp-csr",
                    stage="csr",
                    entry="1",
                    cfg="0x00",
                ),
            ]
        )

        summary = summarize_bapc_for_pmpfuzz_case(
            case,
            _result(),
            log_text=log_text,
            bapc_core_version="v4",
        )

        self.assertTrue(summary["eligible"])
        self.assertEqual(
            summary["event_records"][0]["actual_pmpcfg_entries"],
            [
                {
                    "address_mode": "off",
                    "evidence_kind": "trace-observed",
                    "execute": True,
                    "index": 0,
                    "locked": True,
                    "raw_log_sha256": hashlib.sha256(log_text.encode("utf-8")).hexdigest(),
                    "read": False,
                    "write": False,
                }
            ],
        )

    def test_cascade_v4_static_actual_csr_state_is_not_treated_as_readback(self):
        stdout_text = "*** PASSED ***\n"
        summary = summarize_bapc_for_cascade_execution(
            {
                "translation": "bare",
                "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
                "pmp_entries": [_entry_dict(mode="off", rwx="111", locked=True, pmpaddr=0)],
                "actual_csr_state": {"mstatus": 0, "pmpcfg0": 0x84, "pmpaddr0": 0},
                "privilege": "S",
                "access": "load",
                "size": 4,
                "physical_address": "0x80008020",
            },
            _result(),
            stdout_text=stdout_text,
            bapc_core_version="v4",
        )

        self.assertTrue(summary["eligible"])
        self.assertIn(
            "family=config|pmp_mode=off|permission_rwx=000|locked=false",
            summary["observed_bins"],
        )
        self.assertNotIn("actual_pmpcfg_entries", summary["event_records"][0])

    def test_bapc_core_v4_mapper_outputs_remain_within_v4_universe(self):
        universe = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=1,
            supports_fault_stage=True,
            supports_smepmp=False,
            bapc_core_version="v4",
        )
        universe_bins = set(universe["bin_ids"])

        for l in (0, 1):
            for r in (0, 1):
                for w in (0, 1):
                    for x in (0, 1):
                        mapped = map_bapc_normalized_record(
                            _off_state_evidence_record({"l": l, "r": r, "w": w, "x": x}),
                            bapc_core_version="v4",
                        )
                        self.assertTrue(set(mapped["observed_bins"]).issubset(universe_bins))


if __name__ == "__main__":
    unittest.main()
