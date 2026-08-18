import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pmpfuzz.bapc import build_bapc_coverage_universe
from pmpfuzz.cascade_runtime import (
    CASCADE_TARGET_OPERATION_SCHEMA_VERSION,
    collect_cascade_runtime_attribution,
    replay_cascade_runtime_record,
)


def _entry_dict() -> dict:
    return {
        "index": 0,
        "address_mode": "napot",
        "pmpaddr": "0xffffffffffffffff",
        "read": True,
        "write": True,
        "execute": True,
        "locked": False,
    }


def _sidecar(*, dut: str, target_operation_id: str, pc: str, address: str, access: str, size: int) -> dict:
    design = dut.split("-", 1)[0]
    return {
        "design": design,
        "translation": "bare",
        "privilege": "M",
        "access": access,
        "size": size,
        "physical_address": address,
        "target_operation_id": target_operation_id,
        "instruction_address": pc,
        "instruction_page_tag": (int(pc, 16) >> 12) & 0xF,
        "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
        "pmp_entries": [_entry_dict()],
        "target_operation_candidates": [
            {
                "target_operation_id": target_operation_id,
                "privilege": "M",
                "access": access,
                "size": size,
                "physical_address": address,
                "instruction_address": pc,
                "instruction_page_tag": (int(pc, 16) >> 12) & 0xF,
            }
        ],
    }


def _result(**overrides) -> dict:
    payload = {
        "status": "fail",
        "observation_valid": False,
        "observed_event": None,
        "observed_mcause": None,
        "observed_stage": None,
        "observed_fault_address": None,
    }
    payload.update(overrides)
    return payload


class CascadeRuntimeAttributionTest(unittest.TestCase):
    def test_schema_version_is_stable(self):
        self.assertEqual(CASCADE_TARGET_OPERATION_SCHEMA_VERSION, "cascade-target-operation-v1")

    def test_rocket_commit_trace_requires_retired_target_pc(self):
        sidecar = _sidecar(
            dut="rocket-clean",
            target_operation_id="bb24-i77",
            pc="0x8002d4a4",
            address="0x3d232",
            access="load",
            size=2,
        )
        log_text = (
            "PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker schema=2 chain=pmp-check "
            "stage=final addr=0x8003d232 prv=3 access=load allow=1 size=1 r=1 w=1 x=1\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="rocket-clean",
            case_id="cascade_rocket-clean_0000",
            sidecar=sidecar,
            result=_result(),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertFalse(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "missing-target-runtime-record")
        self.assertEqual(actual["runtime_records"], [])

    def test_rocket_commit_trace_replays_to_v4(self):
        sidecar = _sidecar(
            dut="rocket-clean",
            target_operation_id="bb24-i77",
            pc="0x8002d4a4",
            address="0x3d232",
            access="load",
            size=2,
        )
        log_text = (
            "PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker schema=2 chain=pmp-check "
            "stage=final addr=0x8003d232 prv=3 access=load allow=1 size=1 r=1 w=1 x=1\n"
            "C0:      8497 [1] pc=[000000008002d4a4] W[r 1=0000000000000000][0] "
            "R[r 0=0000000000000000] R[r 0=0000000000000000] inst=[5a0020d3]\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="rocket-clean",
            case_id="cascade_rocket-clean_0000",
            sidecar=sidecar,
            result=_result(),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertTrue(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "eligible")
        runtime_record = actual["runtime_records"][0]
        self.assertEqual(runtime_record["dut"], "rocket-clean")
        self.assertEqual(runtime_record["pc"], "0x8002d4a4")
        self.assertEqual(runtime_record["address"], "0x8003d232")
        self.assertEqual(runtime_record["access"], "load")
        self.assertEqual(runtime_record["size"], 2)
        self.assertEqual(runtime_record["status"], "completed")
        self.assertEqual(runtime_record["evidence_kind"], "rocket-commit-trace")

        replay = replay_cascade_runtime_record(
            sidecar=sidecar,
            runtime_record=runtime_record,
            bapc_core_version="v4",
        )
        universe = build_bapc_coverage_universe(
            dut="rocket-clean",
            generator_seed=4,
            supports_fault_stage=True,
            supports_smepmp=False,
            bapc_core_version="v4",
        )

        self.assertTrue(replay["eligible"])
        self.assertEqual(replay["qualification_reason"], "eligible")
        self.assertTrue(set(replay["observed_bins"]).issubset(set(universe["bin_ids"])))

    def test_rocket_commit_trace_accepts_zero_padded_digit_only_hex_pc(self):
        sidecar = _sidecar(
            dut="rocket-clean",
            target_operation_id="bb7-i17",
            pc="0x80013004",
            address="0x3a8fc",
            access="store",
            size=4,
        )
        log_text = (
            "PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker schema=2 chain=pmp-check "
            "stage=final addr=0x8003a8fc prv=3 access=store allow=1 size=2 r=1 w=1 x=1\n"
            "C0:       2972 [1] pc=[0000000080013004] W[r 0=0000000000000000][0] "
            "R[r 4=000000008003a8fc] R[r 3=0000000000000000] inst=[00322023]\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="rocket-clean",
            case_id="cascade_rocket-clean_0005",
            sidecar=sidecar,
            result=_result(),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertTrue(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "eligible")
        runtime_record = actual["runtime_records"][0]
        self.assertEqual(runtime_record["pc"], "0x80013004")
        self.assertEqual(runtime_record["address"], "0x8003a8fc")
        self.assertEqual(runtime_record["access"], "store")
        self.assertEqual(runtime_record["size"], 4)
        self.assertEqual(runtime_record["status"], "completed")

    def test_boom_rejects_foreign_probe_only_logs(self):
        sidecar = _sidecar(
            dut="boom-clean",
            target_operation_id="bb10-i119",
            pc="0x8004a3cc",
            address="0x7ec98",
            access="load",
            size=2,
        )
        log_text = (
            "PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker schema=2 chain=pmp-check "
            "stage=final addr=0x8007ec98 prv=3 access=load allow=1 size=1 r=1 w=1 x=1\n"
            "PMFUZZ_PROBE dut=boom-clean probe=boom_lsu_tlb_pmp_check schema=2 role=diagnostic "
            "chain=pmp-check stage=lsu addr=0x0002000004 prv=3 r=1 w=1 x=0\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="boom-clean",
            case_id="cascade_boom-clean_0000",
            sidecar=sidecar,
            result=_result(),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertFalse(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "missing-target-runtime-record")

    def test_boom_runtime_probe_rejects_wrong_pc(self):
        sidecar = _sidecar(
            dut="boom-clean",
            target_operation_id="bb10-i119",
            pc="0x8004a3cc",
            address="0x7ec98",
            access="load",
            size=2,
        )
        log_text = (
            "PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "status=completed trans_id=11 pc=0x8004a3d0 addr=0x8007ec98\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="boom-clean",
            case_id="cascade_boom-clean_0000",
            sidecar=sidecar,
            result=_result(),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertFalse(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "wrong-runtime-pc")

    def test_boom_runtime_issue_runtime_pair_accepts_matching_queue_index(self):
        sidecar = _sidecar(
            dut="boom-clean",
            target_operation_id="bb10-i119",
            pc="0x8004a3cc",
            address="0x7ec98",
            access="load",
            size=2,
        )
        log_text = (
            "PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "phase=issue pc=0x8004a3cc access=load ldq_idx=11\n"
            "PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "status=trap pc=0x8004a3d0 addr=0x8007ec98 access=load size=2 ldq_idx=11 mcause=5 mtval=0x8007ec98\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="boom-clean",
            case_id="cascade_boom-clean_0000",
            sidecar=sidecar,
            result=_result(observed_mcause=5),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertTrue(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "eligible")
        runtime_record = actual["runtime_records"][0]
        self.assertEqual(runtime_record["pc"], "0x8004a3cc")
        self.assertEqual(runtime_record["status"], "trap")
        self.assertEqual(runtime_record["mcause"], 5)

    def test_boom_runtime_issue_runtime_pair_requires_matching_queue_index(self):
        sidecar = _sidecar(
            dut="boom-clean",
            target_operation_id="bb10-i119",
            pc="0x8004a3cc",
            address="0x7ec98",
            access="load",
            size=2,
        )
        log_text = (
            "PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "phase=issue pc=0x8004a3cc access=load ldq_idx=11\n"
            "PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "status=trap pc=0x8004a3cc addr=0x8007ec98 access=load size=2 ldq_idx=12 mcause=5 mtval=0x8007ec98\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="boom-clean",
            case_id="cascade_boom-clean_0000",
            sidecar=sidecar,
            result=_result(observed_mcause=5),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertFalse(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "missing-target-runtime-record")

    def test_boom_runtime_issue_runtime_pair_tolerates_queue_slot_reuse(self):
        sidecar = _sidecar(
            dut="boom-clean",
            target_operation_id="bb10-i119",
            pc="0x8004a3cc",
            address="0x7ec98",
            access="load",
            size=2,
        )
        log_text = (
            "PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "phase=issue pc=0x8004a3cc access=load ldq_idx=11\n"
            "PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "status=trap pc=0x8004a3d0 addr=0x8007ec98 access=load size=2 ldq_idx=11 mcause=5 mtval=0x8007ec98\n"
            "PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "phase=issue pc=0x8004a3e8 access=load ldq_idx=11\n"
            "PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "status=completed pc=0x8004a3e8 addr=0x8007ed00 access=load size=4 ldq_idx=11\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="boom-clean",
            case_id="cascade_boom-clean_0000",
            sidecar=sidecar,
            result=_result(observed_mcause=5),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertTrue(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "eligible")
        self.assertEqual(actual["runtime_records"][0]["pc"], "0x8004a3cc")
        self.assertEqual(actual["runtime_records"][0]["status"], "trap")

    def test_boom_runtime_probe_rejects_access_conflict(self):
        sidecar = _sidecar(
            dut="boom-clean",
            target_operation_id="bb10-i119",
            pc="0x8004a3cc",
            address="0x7ec98",
            access="load",
            size=2,
        )
        log_text = (
            "PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "status=completed pc=0x8004a3cc addr=0x8007ec98 access=store size=2\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="boom-clean",
            case_id="cascade_boom-clean_0000",
            sidecar=sidecar,
            result=_result(),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertFalse(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "access-conflict")

    def test_boom_runtime_probe_rejects_multiple_target_records(self):
        sidecar = _sidecar(
            dut="boom-clean",
            target_operation_id="bb10-i119",
            pc="0x8004a3cc",
            address="0x7ec98",
            access="load",
            size=2,
        )
        log_text = (
            "PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "status=completed pc=0x8004a3cc addr=0x8007ec98 access=load size=2\n"
            "PMFUZZ_PROBE dut=boom-clean probe=boom_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "status=trap pc=0x8004a3cc addr=0x8007ec98 access=load size=2 mcause=5 mtval=0x8007ec98\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="boom-clean",
            case_id="cascade_boom-clean_0000",
            sidecar=sidecar,
            result=_result(observed_mcause=5),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertFalse(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "multiple-target-runtime-records")

    def test_explicit_selected_target_overrides_multi_candidate_manifest(self):
        sidecar = _sidecar(
            dut="rocket-clean",
            target_operation_id="bb24-i77",
            pc="0x8002d4a4",
            address="0x3d232",
            access="load",
            size=2,
        )
        sidecar["target_operation_candidates"].append(
            {
                "target_operation_id": "bb99-i1",
                "privilege": "M",
                "access": "store",
                "size": 8,
                "physical_address": "0x4d000",
                "instruction_address": "0x8003d000",
                "instruction_page_tag": (0x8003D000 >> 12) & 0xF,
            }
        )
        log_text = (
            "PMFUZZ_PROBE dut=rocket-clean probe=rocket_pmp_checker schema=2 chain=pmp-check "
            "stage=final addr=0x8003d232 prv=3 access=load allow=1 size=1 r=1 w=1 x=1\n"
            "C0:      8497 [1] pc=[000000008002d4a4] W[r 1=0000000000000000][0] "
            "R[r 0=0000000000000000] R[r 0=0000000000000000] inst=[5a0020d3]\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="rocket-clean",
            case_id="cascade_rocket-clean_0000",
            sidecar=sidecar,
            result=_result(),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertTrue(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "eligible")
        self.assertEqual(actual["runtime_records"][0]["target_operation_id"], "bb24-i77")

    def test_cva6_runtime_accepts_duplicate_target_issue_when_one_runtime_matches(self):
        sidecar = _sidecar(
            dut="cva6-clean",
            target_operation_id="bb29-i27",
            pc="0x80097efc",
            address="0xc688c",
            access="load",
            size=4,
        )
        log_text = (
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_issue "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "phase=issue access=load trans_id=1 pc=0x80097efc\n"
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_issue "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "phase=issue access=load trans_id=0 pc=0x80097efc\n"
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "status=completed access=load trans_id=0 addr=0x0\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="cva6-clean",
            case_id="cascade_cva6-clean_0000",
            sidecar=sidecar,
            result=_result(),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertTrue(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "eligible")
        self.assertEqual(actual["runtime_records"][0]["pc"], "0x80097efc")
        self.assertEqual(actual["runtime_records"][0]["access"], "load")
        self.assertEqual(actual["runtime_records"][0]["address"], "0x0")

    def test_cva6_runtime_requires_complete_issue_and_trap_pair(self):
        sidecar = _sidecar(
            dut="cva6-clean",
            target_operation_id="bb3-i85",
            pc="0x80026ff4",
            address="0xa1618",
            access="load",
            size=4,
        )
        log_text = (
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_issue "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "phase=issue trans_id=5 pc=0x80026ff4\n"
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "status=trap trans_id=5 addr=0x800a1618 mcause=5 mtval=0x800a1618\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="cva6-clean",
            case_id="cascade_cva6-clean_0000",
            sidecar=sidecar,
            result=_result(),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertTrue(actual["measurement_valid"])
        runtime_record = actual["runtime_records"][0]
        self.assertEqual(runtime_record["pc"], "0x80026ff4")
        self.assertEqual(runtime_record["status"], "trap")
        self.assertEqual(runtime_record["mcause"], 5)
        self.assertEqual(runtime_record["mtval"], "0x800a1618")
        replay = replay_cascade_runtime_record(
            sidecar=sidecar,
            runtime_record=runtime_record,
            bapc_core_version="v4",
        )
        self.assertTrue(replay["eligible"])

    def test_cva6_runtime_pairs_reused_trans_id_by_log_order(self):
        sidecar = _sidecar(
            dut="cva6-clean",
            target_operation_id="bb15-i6",
            pc="0x800599a8",
            address="0x0",
            access="load",
            size=4,
        )
        log_text = (
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_issue "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "phase=issue access=load trans_id=2 pc=0x800599a8\n"
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "status=completed access=load trans_id=2 addr=0x0\n"
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_issue "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "phase=issue access=store trans_id=2 pc=0x8000fa2c\n"
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "status=completed access=store trans_id=2 addr=0x10\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="cva6-clean",
            case_id="cascade_cva6-clean_0000",
            sidecar=sidecar,
            result=_result(),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertTrue(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "eligible")
        self.assertEqual(actual["runtime_records"][0]["pc"], "0x800599a8")
        self.assertEqual(actual["runtime_records"][0]["access"], "load")
        self.assertEqual(actual["runtime_records"][0]["address"], "0x0")

    def test_cva6_runtime_selects_first_runtime_attributed_candidate(self):
        sidecar = {
            "design": "cva6",
            "translation": "bare",
            "mseccfg": {"mml": False, "mmwp": False, "rlb": False},
            "pmp_entries": [_entry_dict()],
            "runtime_attribution_contract": CASCADE_TARGET_OPERATION_SCHEMA_VERSION,
            "target_operation_selection_rule": "deterministic-first-runtime-attributed-candidate",
            "target_operation_candidates": [
                {
                    "target_operation_id": "bb47-i15",
                    "privilege": "M",
                    "access": "store",
                    "size": 8,
                    "instruction_address": "0x8002d8ac",
                    "instruction_page_tag": (0x8002D8AC >> 12) & 0xF,
                },
                {
                    "target_operation_id": "bb54-i0",
                    "privilege": "M",
                    "access": "store",
                    "size": 4,
                    "instruction_address": "0x80030b6c",
                    "instruction_page_tag": (0x80030B6C >> 12) & 0xF,
                },
            ],
        }
        log_text = (
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_issue "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "phase=issue access=store trans_id=3 pc=0x80030b6c\n"
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "status=completed access=store trans_id=3 addr=0x80052c98\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="cva6-clean",
            case_id="cascade_cva6-clean_0000",
            sidecar=sidecar,
            result=_result(),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertTrue(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "eligible")
        self.assertEqual(actual["runtime_records"][0]["target_operation_id"], "bb54-i0")
        self.assertEqual(actual["runtime_records"][0]["pc"], "0x80030b6c")
        self.assertEqual(actual["runtime_records"][0]["address"], "0x80052c98")

    def test_cva6_runtime_probe_missing_address_is_fail_closed(self):
        sidecar = _sidecar(
            dut="cva6-clean",
            target_operation_id="bb3-i85",
            pc="0x80026ff4",
            address="0xa1618",
            access="load",
            size=4,
        )
        log_text = (
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_issue "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "phase=issue trans_id=5 pc=0x80026ff4\n"
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "status=trap trans_id=5 mcause=5 mtval=0x800a1618\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="cva6-clean",
            case_id="cascade_cva6-clean_0000",
            sidecar=sidecar,
            result=_result(),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertFalse(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "runtime-record-missing-fields")

    def test_cva6_runtime_probe_rejects_cause_mismatch(self):
        sidecar = _sidecar(
            dut="cva6-clean",
            target_operation_id="bb3-i85",
            pc="0x80026ff4",
            address="0xa1618",
            access="load",
            size=4,
        )
        log_text = (
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_issue "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "phase=issue trans_id=5 pc=0x80026ff4\n"
            "PMFUZZ_PROBE dut=cva6-clean probe=cva6_target_operation_runtime "
            "schema=cascade-target-operation-v1 role=runtime chain=target-operation "
            "status=trap access=load trans_id=5 addr=0x800a1618 mcause=7 mtval=0x800a1618\n"
        )

        actual = collect_cascade_runtime_attribution(
            dut="cva6-clean",
            case_id="cascade_cva6-clean_0000",
            sidecar=sidecar,
            result=_result(observed_mcause=5),
            log_text=log_text,
        )

        self.assertTrue(actual["artifact_valid"])
        self.assertFalse(actual["measurement_valid"])
        self.assertEqual(actual["qualification_reason"], "cause-mismatch")


class CascadeRuntimeValidatorScriptExecutionTest(unittest.TestCase):
    def test_validator_script_executes_directly_from_repo_root(self):
        repo_root = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as tmp:
            campaign_dir = Path(tmp) / "campaign"
            metrics_dir = campaign_dir / "metrics"
            metrics_dir.mkdir(parents=True)
            (campaign_dir / "events.json").write_text("[]\n", encoding="ascii")
            (metrics_dir / "campaign_metadata.json").write_text(
                json.dumps({"bapc_core_version": "v4", "coverage_mode": "bapc"}) + "\n",
                encoding="ascii",
            )
            env = dict(os.environ)
            env.pop("PYTHONPATH", None)
            proc = subprocess.run(
                [
                    sys.executable,
                    "scripts/evaluation/validation/validate_cascade_runtime_attribution.py",
                    str(campaign_dir),
                ],
                cwd=repo_root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            report = json.loads(
                (metrics_dir / "cascade_runtime_validation.json").read_text(encoding="utf-8")
            )
            self.assertTrue(report["measurement_valid"])
            self.assertEqual(report["completed_cases"], 0)


if __name__ == "__main__":
    unittest.main()
