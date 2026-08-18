import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from pmpfuzz import off_state, off_state_cva6
from scripts.evaluation.validation import validate_bapc_universe as validator


def _ordered_trace_log(base: int, payload_bytes: list[int]) -> str:
    stride = off_state_cva6._CVA6_TRACE_SLOT_STRIDE_BYTES
    slot_bytes = off_state_cva6._CVA6_TRACE_SLOT_BYTES
    start_slot = off_state_cva6._CVA6_TRACE_SENTINEL_START_SLOT
    end_slot = off_state_cva6._CVA6_TRACE_SENTINEL_END_SLOT
    lines = [
        f"PMFUZZ_PROBE dut=cva6-clean probe=trace chain=exception-arbitration stage=tlb vaddr=0x{base + (start_slot * stride):x} hit=0 flush=0 update=0"
    ]
    for slot_index, byte_value in enumerate(payload_bytes):
        lines.append(
            f"PMFUZZ_PROBE dut=cva6-clean probe=trace chain=exception-arbitration stage=tlb "
            f"vaddr=0x{base + (slot_index * stride) + ((byte_value & 0xff) * slot_bytes):x} hit=0 flush=0 update=0"
        )
    lines.append(
        f"PMFUZZ_PROBE dut=cva6-clean probe=trace chain=exception-arbitration stage=tlb vaddr=0x{base + (end_slot * stride):x} hit=0 flush=0 update=0"
    )
    lines.append("*** PASSED *** Completed after 123 simulation cycles")
    return "\n".join(lines)


def _ordered_trace_log_with_probe(base: int, payload_bytes: list[int], *, probe_name: str) -> str:
    return _ordered_trace_log(base, payload_bytes).replace("probe=trace", f"probe={probe_name}")


def _witness_normalized_record() -> dict:
    report = validator.build_validation_report(
        dut="cva6",
        bapc_core_version="v3",
        generator_seed=7,
    )
    return dict(report["witnesses"][0]["normalized_record"])


def _fake_formal_batch_case_result(
    case: dict,
    *,
    out_dir: Path,
    reset_command: list[str],
    normalized_record: dict,
    case_id_override: str | None = None,
) -> dict:
    case_id = str(case_id_override or case["case_id"])
    case_dir = Path(out_dir) / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    log_path = case_dir / f"{case_id}.log"
    log_text = f"CASE {case_id}\n"
    log_path.write_text(log_text, encoding="utf-8")
    raw_log_sha256 = hashlib.sha256(log_path.read_bytes()).hexdigest()
    payload_sha256 = hashlib.sha256(case_id.encode("utf-8")).hexdigest()
    execution_binding = {
        "source_git_sha": "a" * 40,
        "experiment_branch": "test-branch",
        "dut_name": "cva6-clean",
        "simulator_version": "CVA6Config",
        "payload_sha256": payload_sha256,
        "raw_log_sha256": raw_log_sha256,
        "dut_command": ["/simulator", "--run", case_id],
        "reset_command": list(reset_command),
        "reset_id": str(case["reset_id"]),
        "transport": {
            "kind": "cva6-whitebox-artifacts",
            "dut_specific": True,
            "public_default": False,
        },
    }
    parsed_record = {
        "record_schema_version": off_state.OFF_STATE_RECORD_SCHEMA_VERSION,
        "dut": "cva6",
        "profile_requested": str(case["profile_requested"]),
        "profile_observed": str(case["profile_requested"]),
        "entry_index": int(case["entry_index"]),
        "reset_id": str(case["reset_id"]),
        "subexperiment": str(case["subexperiment"]),
        "requested_bits": dict(case["requested_bits"]),
        "spec_status": str(case.get("spec_status") or off_state.spec_status_for_off_state(case["profile_requested"], case["requested_bits"])),
        "execution_status": "completed",
    }
    control_pass = True
    if parsed_record["subexperiment"] == "readback":
        parsed_record.update(
            {
                "write_outcome": "accepted",
                "readback_relation": "exact",
                "readback_bits_1": dict(case["requested_bits"]),
                "readback_bits_2": dict(case["requested_bits"]),
                "pmpaddr_value": "0x200021fe",
            }
        )
    elif parsed_record["subexperiment"] == "lock":
        parsed_record.update(
            {
                "cfg_lock_effect": "blocked",
                "addr_lock_effect": "blocked",
                "initial_addr": "0x200021fe",
                "addr_after": "0x200021fe",
                "cfg_after_1": "0x85",
                "cfg_after_2": "0x85",
            }
        )
    else:
        allow = bool(case.get("expected_allow", False) and "requested_raw_bin_id" not in case)
        parsed_record.update(
            {
                "probe_result": "unexpected-match" if allow else "expected-nonmatch",
                "access": "load",
                "size": 4,
                "current_privilege": "m",
                "effective_privilege": "u",
                "exception_cause": "none" if allow else "load_access_fault",
                "fault_address": "0x2000",
                "matched_control_case": "behavior-napot-allow" if allow else "behavior-catch-all",
                "readback_bits_1": dict(case["requested_bits"]),
                "readback_bits_2": dict(case["requested_bits"]),
                "pmpaddr_value": "0x200021fe",
            }
        )
        if "requested_raw_bin_id" in case:
            parsed_record["normalized_record"] = dict(normalized_record)
            parsed_record["raw_trace_sha256"] = raw_log_sha256
            parsed_record["supports_fault_stage"] = True
            parsed_record["supports_smepmp"] = False
    return {
        "schema_version": off_state_cva6.CVA6_PILOT_RESULT_SCHEMA_VERSION,
        "artifact_kind": off_state_cva6.CVA6_PILOT_RESULT_KIND,
        "case_id": case_id,
        "case_kind": str(case["case_kind"]),
        "execution_status": "completed",
        "dut_status": "timeout" if "requested_raw_bin_id" in case else "pass",
        "failure_class": "timeout" if "requested_raw_bin_id" in case else None,
        "reason": "synthetic test result",
        "control_pass": control_pass,
        "log": str(log_path),
        "parsed_record": parsed_record,
        "execution_binding": execution_binding,
        "transport_completion": {
            "mode": str(case.get("termination_mode") or "pass-tohost"),
            "frame_complete": True,
            "end_marker": "trace-end-sentinel" if str(case.get("termination_mode") or "") == "host-timeout" else "tohost",
            "required_fields_complete": True,
        },
    }


class Cva6OffStatePilotTest(unittest.TestCase):
    def test_build_plan_enumerates_controls_only_per_reset(self):
        plan = off_state_cva6.build_cva6_pilot_plan(entry_index=0, reset_count=2)

        self.assertEqual(plan["artifact_kind"], off_state_cva6.CVA6_PILOT_PLAN_KIND)
        self.assertEqual(plan["schema_version"], off_state_cva6.CVA6_PILOT_PLAN_SCHEMA_VERSION)
        self.assertEqual(plan["profile_requested"], "base-pmp")
        self.assertEqual(plan["entry_index"], 0)
        self.assertEqual(plan["reset_count"], 2)
        self.assertEqual(
            [case["case_kind"] for case in plan["cases"][:6]],
            [
                "readback-off-control",
                "lock-positive-control",
                "behavior-napot-allow",
                "behavior-napot-deny",
                "behavior-off",
                "behavior-catch-all",
            ],
        )
        self.assertEqual(len(plan["cases"]), 12)

    def test_build_plan_can_enumerate_all_16_encodings_per_subexperiment(self):
        plan = off_state_cva6.build_cva6_pilot_plan(
            entry_index=0,
            reset_count=3,
            include_main_cases=True,
        )

        main_cases = [case for case in plan["cases"] if "requested_raw_bin_id" in case]
        self.assertEqual(plan["requested_raw_vocabulary"]["artifact_kind"], off_state.OFF_STATE_RAW_MAPPER_VERSION)
        self.assertEqual(
            plan["requested_raw_vocabulary"]["bin_set_sha256"],
            off_state.raw_state_universe_bin_set_sha256(plan["requested_raw_vocabulary"]["bin_ids"]),
        )
        self.assertEqual(len(main_cases), 3 * 3 * 16)
        self.assertEqual(sum(1 for case in main_cases if case["subexperiment"] == "readback"), 3 * 16)
        self.assertEqual(sum(1 for case in main_cases if case["subexperiment"] == "lock"), 3 * 16)
        self.assertEqual(sum(1 for case in main_cases if case["subexperiment"] == "behavior"), 3 * 16)
        self.assertEqual(sum(1 for case in main_cases if case["spec_status"] == "spec-reserved"), 3 * 3 * 4)
        self.assertTrue(all(case["termination_mode"] == "host-timeout" for case in main_cases))
        self.assertEqual(
            main_cases[0]["requested_raw_bin_id"],
            "pmpcfg-raw-v1|profile=base-pmp|a=off|l=0|r=0|w=0|x=0",
        )
        self.assertEqual(main_cases[0]["subexperiment"], "readback")

    def test_build_formal_batch_plan_enumerates_144_main_cases_and_pre_post_controls(self):
        plan = off_state_cva6.build_cva6_formal_batch_plan(
            entry_index=0,
            reset_count=3,
        )

        self.assertEqual(plan["artifact_kind"], off_state_cva6.CVA6_FORMAL_BATCH_PLAN_KIND)
        self.assertEqual(plan["profile_requested"], "base-pmp")
        self.assertEqual(plan["entry_index"], 0)
        self.assertEqual(plan["reset_count"], 3)
        self.assertEqual(plan["main_case_count"], 144)
        self.assertEqual(len(plan["main_cases"]), 144)
        self.assertEqual(len(plan["pre_control_cases"]), 18)
        self.assertEqual(len(plan["post_control_cases"]), 18)
        self.assertEqual(len(plan["expected_main_case_ids"]), 144)
        self.assertEqual(len(plan["expected_execution_case_ids"]), 180)
        self.assertEqual(len(set(plan["expected_execution_case_ids"])), 180)
        behavior_case = next(
            item
            for item in plan["main_cases"]
            if item["reset_id"] == "reset-000"
            and item["subexperiment"] == "behavior"
            and item["requested_raw_bin_id"] == "pmpcfg-raw-v1|profile=base-pmp|a=off|l=0|r=0|w=0|x=0"
        )
        self.assertEqual(
            behavior_case["associated_control_case_ids"],
            [
                "reset-000__pre__behavior-napot-allow",
                "reset-000__pre__behavior-napot-deny",
                "reset-000__pre__behavior-off",
                "reset-000__pre__behavior-catch-all",
                "reset-000__post__behavior-napot-allow",
                "reset-000__post__behavior-napot-deny",
                "reset-000__post__behavior-off",
                "reset-000__post__behavior-catch-all",
            ],
        )

    def test_render_behavior_control_avoids_uart_polling_and_sets_mprv(self):
        case = off_state_cva6.build_cva6_pilot_plan(entry_index=0, reset_count=1)["cases"][2]

        asm = off_state_cva6.render_cva6_pilot_assembly(case)

        self.assertIn("csrw pmpaddr0", asm)
        self.assertIn("csrw pmpaddr1", asm)
        self.assertIn("csrw pmpcfg0", asm)
        self.assertIn("(1 << 17)", asm)
        self.assertIn("lw t1, 0(t0)", asm)
        self.assertIn("trace_table:", asm)
        self.assertIn("li a0, 1", asm)
        self.assertNotIn("uart_putc_wait", asm)
        self.assertNotIn("0x10020000", asm)

    def test_render_finish_block_restores_m_mode_store_path(self):
        case = off_state_cva6.build_cva6_pilot_plan(entry_index=0, reset_count=1)["cases"][2]

        asm = off_state_cva6.render_cva6_pilot_assembly(case)

        self.assertIn("la t0, result", asm)
        self.assertIn("sd a0, 32(t0)", asm)
        self.assertIn("li t3, ~(1 << 17)", asm)
        self.assertIn("csrw mstatus, t2", asm)
        self.assertIn("observation_phase:", asm)

    def test_parse_readback_control_decodes_custom_tohost_payload(self):
        case = off_state_cva6.build_cva6_pilot_plan(entry_index=0, reset_count=1)["cases"][0]
        payload = off_state_cva6.encode_cva6_pilot_readback_payload(
            requested_cfg=0x00,
            readback_cfg_1=0x00,
            readback_cfg_2=0x00,
        )

        result = off_state_cva6.parse_cva6_pilot_log(
            case,
            log_text=f"*** FAILED *** (tohost = {payload})\n",
            dut_status="fail",
            failure_class="unknown_failure",
            reason="chipyard simulator reported failure",
        )

        self.assertEqual(result["execution_status"], "completed")
        self.assertTrue(result["control_pass"])
        self.assertEqual(result["parsed_record"]["readback_bits_1"], {"l": 0, "r": 0, "w": 0, "x": 0})
        self.assertEqual(result["parsed_record"]["readback_bits_2"], {"l": 0, "r": 0, "w": 0, "x": 0})

    def test_parse_behavior_control_reuses_bapc_v3_summary(self):
        case = off_state_cva6.build_cva6_pilot_plan(entry_index=0, reset_count=1)["cases"][2]
        payload = off_state_cva6.encode_cva6_pilot_behavior_payload(allowed=True, mcause=0)
        log_text = f"*** FAILED *** (tohost = {payload})\n"

        result = off_state_cva6.parse_cva6_pilot_log(
            case,
            log_text=log_text,
            dut_status="fail",
            failure_class="unknown_failure",
            reason="chipyard simulator reported failure",
        )

        self.assertEqual(result["execution_status"], "completed")
        self.assertTrue(result["control_pass"])
        self.assertEqual(result["bapc_summary"]["bapc_core_version"], "v3")
        self.assertTrue(result["bapc_summary"]["eligible"])
        self.assertTrue(result["bapc_summary"]["observed_bins"])

    def test_parse_behavior_control_decodes_trace_sequence_from_probe_log(self):
        case = dict(off_state_cva6.build_cva6_pilot_plan(entry_index=0, reset_count=1)["cases"][2])
        case["trace_table_base"] = "0x90000000"
        log_text = _ordered_trace_log(0x90000000, [1, 0])

        result = off_state_cva6.parse_cva6_pilot_log(
            case,
            log_text=log_text,
            dut_status="pass",
            failure_class=None,
            reason="chipyard reported explicit pass marker",
        )

        self.assertEqual(result["execution_status"], "completed")
        self.assertTrue(result["control_pass"])
        self.assertEqual(result["bapc_summary"]["bapc_core_version"], "v3")
        self.assertTrue(result["bapc_summary"]["observed_bins"])

    def test_parse_behavior_trace_accepts_cva6_whitebox_probe_name(self):
        case = dict(off_state_cva6.build_cva6_pilot_plan(entry_index=0, reset_count=1)["cases"][2])
        case["trace_table_base"] = "0x90000000"

        result = off_state_cva6.parse_cva6_pilot_log(
            case,
            log_text=_ordered_trace_log_with_probe(
                0x90000000,
                [1, 0],
                probe_name="cva6_tlb_exception_arbitration",
            ),
            dut_status="pass",
            failure_class=None,
            reason="chipyard reported explicit pass marker",
        )

        self.assertEqual(result["execution_status"], "completed")
        self.assertTrue(result["control_pass"])

    def test_parse_lock_trace_ignores_interleaved_pass_banner_after_complete_frame(self):
        case = dict(off_state_cva6.build_cva6_pilot_plan(entry_index=0, reset_count=1)["cases"][1])
        case["trace_table_base"] = "0x90000000"
        addr_after = int(case["target_pmpaddr"]).to_bytes(4, "little")
        cfg_after = int(case["locked_cfg_byte"]) & 0xFF
        payload = [*addr_after, cfg_after, cfg_after]
        log_text = "\n".join(
            [
                _ordered_trace_log_with_probe(
                    0x90000000,
                    payload,
                    probe_name="cva6_tlb_exception_arbitration",
                ),
                "PMFUZZ_PROBE dut=cva6-clean probe=cva6_tlb_exception_arbitratio*** PASSED *** Completed after 123 simulation cycles",
                "n stage=tlb vaddr=0x900001d8 hit=0 flush=0 update=0",
            ]
        )

        result = off_state_cva6.parse_cva6_pilot_log(
            case,
            log_text=log_text,
            dut_status="pass",
            failure_class=None,
            reason="chipyard reported explicit pass marker",
        )

        self.assertEqual(result["execution_status"], "completed")
        self.assertTrue(result["control_pass"])

    def test_parse_behavior_trace_rejects_out_of_order_slot_sequence(self):
        case = dict(off_state_cva6.build_cva6_pilot_plan(entry_index=0, reset_count=1)["cases"][2])
        case["trace_table_base"] = "0x90000000"
        stride = off_state_cva6._CVA6_TRACE_SLOT_STRIDE_BYTES
        slot_bytes = off_state_cva6._CVA6_TRACE_SLOT_BYTES
        start_slot = off_state_cva6._CVA6_TRACE_SENTINEL_START_SLOT
        end_slot = off_state_cva6._CVA6_TRACE_SENTINEL_END_SLOT
        log_text = "\n".join(
            [
                f"PMFUZZ_PROBE dut=cva6-clean probe=trace chain=exception-arbitration stage=tlb vaddr=0x{0x90000000 + (start_slot * stride):x} hit=0 flush=0 update=0",
                f"PMFUZZ_PROBE dut=cva6-clean probe=trace chain=exception-arbitration stage=tlb vaddr=0x{0x90000000 + (1 * stride) + (0 * slot_bytes):x} hit=0 flush=0 update=0",
                f"PMFUZZ_PROBE dut=cva6-clean probe=trace chain=exception-arbitration stage=tlb vaddr=0x{0x90000000 + (0 * stride) + (1 * slot_bytes):x} hit=0 flush=0 update=0",
                f"PMFUZZ_PROBE dut=cva6-clean probe=trace chain=exception-arbitration stage=tlb vaddr=0x{0x90000000 + (end_slot * stride):x} hit=0 flush=0 update=0",
                "*** PASSED *** Completed after 123 simulation cycles",
            ]
        )

        result = off_state_cva6.parse_cva6_pilot_log(
            case,
            log_text=log_text,
            dut_status="pass",
            failure_class=None,
            reason="chipyard reported explicit pass marker",
        )

        self.assertEqual(result["execution_status"], "harness-error")
        self.assertNotIn("bapc_summary", result)

    def test_parse_lock_trace_without_complete_frame_still_fails_closed(self):
        case = dict(off_state_cva6.build_cva6_pilot_plan(entry_index=0, reset_count=1)["cases"][1])
        case["trace_table_base"] = "0x90000000"
        log_text = "\n".join(
            [
                "PMFUZZ_PROBE dut=cva6-clean probe=cva6_tlb_exception_arbitratio*** PASSED *** Completed after 123 simulation cycles",
                "n stage=tlb hit=0 flush=0 update=0",
            ]
        )

        result = off_state_cva6.parse_cva6_pilot_log(
            case,
            log_text=log_text,
            dut_status="pass",
            failure_class=None,
            reason="chipyard reported explicit pass marker",
        )

        self.assertEqual(result["execution_status"], "harness-error")
        self.assertNotIn("parsed_record", result)

    def test_parse_behavior_trace_rejects_truncated_frame(self):
        case = dict(off_state_cva6.build_cva6_pilot_plan(entry_index=0, reset_count=1)["cases"][2])
        case["trace_table_base"] = "0x90000000"
        stride = off_state_cva6._CVA6_TRACE_SLOT_STRIDE_BYTES
        log_text = "\n".join(
            [
                f"PMFUZZ_PROBE dut=cva6-clean probe=trace chain=exception-arbitration stage=tlb vaddr=0x{0x90000000 + (off_state_cva6._CVA6_TRACE_SENTINEL_START_SLOT * stride):x} hit=0 flush=0 update=0",
                f"PMFUZZ_PROBE dut=cva6-clean probe=trace chain=exception-arbitration stage=tlb vaddr=0x{0x90000000:x} hit=0 flush=0 update=0",
                "*** PASSED *** Completed after 123 simulation cycles",
            ]
        )

        result = off_state_cva6.parse_cva6_pilot_log(
            case,
            log_text=log_text,
            dut_status="pass",
            failure_class=None,
            reason="chipyard reported explicit pass marker",
        )

        self.assertEqual(result["execution_status"], "harness-error")
        self.assertNotIn("bapc_summary", result)

    def test_parse_main_behavior_case_records_actual_cfg_readback_from_trace(self):
        plan = off_state_cva6.build_cva6_pilot_plan(
            entry_index=0,
            reset_count=1,
            include_main_cases=True,
        )
        case = next(
            item
            for item in plan["cases"]
            if item.get("requested_raw_bin_id") == "pmpcfg-raw-v1|profile=base-pmp|a=off|l=1|r=0|w=1|x=1"
            and item["subexperiment"] == "behavior"
        )
        case = dict(case)
        case["trace_table_base"] = "0x90000000"
        payload = [0x86, 0x86, 0xAA, 0xBB, 0xCC, 0xDD, 0, 5, 0x44, 0x33, 0x22, 0x11]

        result = off_state_cva6.parse_cva6_pilot_log(
            case,
            log_text=_ordered_trace_log(0x90000000, payload),
            dut_status="pass",
            failure_class=None,
            reason="chipyard reported explicit pass marker",
        )

        self.assertEqual(result["execution_status"], "completed")
        self.assertEqual(result["parsed_record"]["readback_bits_1"], {"l": 1, "r": 0, "w": 1, "x": 1})
        self.assertEqual(result["parsed_record"]["readback_bits_2"], {"l": 1, "r": 0, "w": 1, "x": 1})
        self.assertEqual(result["parsed_record"]["exception_cause"], "load_access_fault")
        self.assertEqual(result["parsed_record"]["fault_address"], "0x11223344")
        self.assertEqual(result["parsed_record"]["pmpaddr_value"], "0xddccbbaa")

    def test_parse_main_behavior_case_can_complete_from_host_timeout(self):
        plan = off_state_cva6.build_cva6_pilot_plan(
            entry_index=0,
            reset_count=1,
            include_main_cases=True,
        )
        case = next(
            item
            for item in plan["cases"]
            if item.get("requested_raw_bin_id") == "pmpcfg-raw-v1|profile=base-pmp|a=off|l=0|r=0|w=0|x=0"
            and item["subexperiment"] == "behavior"
        )
        case = dict(case)
        case["trace_table_base"] = "0x90000000"
        payload = [0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0, 5, 0x44, 0x33, 0x22, 0x11]

        result = off_state_cva6.parse_cva6_pilot_log(
            case,
            log_text=_ordered_trace_log_with_probe(
                0x90000000,
                payload,
                probe_name="cva6_tlb_exception_arbitration",
            ),
            dut_status="timeout",
            failure_class="timeout",
            reason="chipyard direct simulator timeout",
        )

        self.assertEqual(result["execution_status"], "completed")
        self.assertEqual(result["parsed_record"]["probe_result"], "expected-nonmatch")
        self.assertEqual(result["transport_completion"]["mode"], "host-timeout")
        self.assertTrue(result["transport_completion"]["frame_complete"])
        self.assertEqual(result["transport_completion"]["end_marker"], "trace-end-sentinel")
        self.assertTrue(result["transport_completion"]["required_fields_complete"])

    def test_parse_main_behavior_timeout_without_complete_frame_is_harness_error(self):
        plan = off_state_cva6.build_cva6_pilot_plan(
            entry_index=0,
            reset_count=1,
            include_main_cases=True,
        )
        case = next(
            item
            for item in plan["cases"]
            if item.get("requested_raw_bin_id") == "pmpcfg-raw-v1|profile=base-pmp|a=off|l=0|r=0|w=0|x=0"
            and item["subexperiment"] == "behavior"
        )
        case = dict(case)
        case["trace_table_base"] = "0x90000000"
        stride = off_state_cva6._CVA6_TRACE_SLOT_STRIDE_BYTES
        log_text = "\n".join(
            [
                f"PMFUZZ_PROBE dut=cva6-clean probe=cva6_tlb_exception_arbitration chain=exception-arbitration stage=tlb vaddr=0x{0x90000000 + (off_state_cva6._CVA6_TRACE_SENTINEL_START_SLOT * stride):x} hit=0 flush=0 update=0",
                f"PMFUZZ_PROBE dut=cva6-clean probe=cva6_tlb_exception_arbitration chain=exception-arbitration stage=tlb vaddr=0x{0x90000000:x} hit=0 flush=0 update=0",
            ]
        )

        result = off_state_cva6.parse_cva6_pilot_log(
            case,
            log_text=log_text,
            dut_status="timeout",
            failure_class="timeout",
            reason="chipyard direct simulator timeout",
        )

        self.assertEqual(result["execution_status"], "harness-error")
        self.assertNotIn("parsed_record", result)

    def test_render_main_behavior_trap_path_preserves_exception_registers(self):
        plan = off_state_cva6.build_cva6_pilot_plan(
            entry_index=0,
            reset_count=1,
            include_main_cases=True,
        )
        case = next(
            item
            for item in plan["cases"]
            if item.get("requested_raw_bin_id") == "pmpcfg-raw-v1|profile=base-pmp|a=off|l=0|r=0|w=0|x=0"
            and item["subexperiment"] == "behavior"
        )

        asm = off_state_cva6.render_cva6_pilot_assembly(case)
        trap_block = asm.split("trap_handler:\n", 1)[1].split("finish:", 1)[0]

        self.assertIn("    csrr t2, mcause", trap_block)
        self.assertIn("    csrr t3, mtval", trap_block)
        self.assertIn("    csrr t0, mstatus", trap_block)
        self.assertIn("    li t1, ~(1 << 17)", trap_block)
        self.assertNotIn("    csrr t2, mstatus", trap_block)
        self.assertNotIn("    li t3, ~(1 << 17)", trap_block)

    def test_parse_behavior_missing_probe_fails_closed(self):
        case = off_state_cva6.build_cva6_pilot_plan(entry_index=0, reset_count=1)["cases"][2]

        result = off_state_cva6.parse_cva6_pilot_log(
            case,
            log_text="",
            dut_status="pass",
            failure_class=None,
            reason=None,
        )

        self.assertEqual(result["execution_status"], "harness-error")
        self.assertNotIn("bapc_summary", result)

    def test_run_case_requires_reset_command(self):
        case = off_state_cva6.build_cva6_pilot_plan(entry_index=0, reset_count=1)["cases"][0]

        with TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "reset_command"):
                off_state_cva6.run_cva6_pilot_case(
                    case,
                    out_dir=Path(tmp),
                    reset_command=[],
                )

    def test_run_case_resets_then_compiles_then_runs(self):
        plan = off_state_cva6.build_cva6_pilot_plan(entry_index=0, reset_count=1)
        case = plan["cases"][0]
        calls = []
        log_text = (
            f"*** FAILED *** (tohost = {off_state_cva6.encode_cva6_pilot_readback_payload(requested_cfg=0x00, readback_cfg_1=0x00, readback_cfg_2=0x00)})\n"
        )

        def fake_reset(command):
            calls.append(("reset", list(command)))
            return SimpleNamespace(returncode=0, stdout="reset-ok")

        def fake_compile(command):
            calls.append(("compile", list(command)))
            Path(command[-1]).write_bytes(b"ELF")
            return SimpleNamespace(returncode=0, stdout="compile-ok")

        class FakeDut:
            name = "cva6-clean"
            config = "CVA6Config"
            whitebox_artifacts = True

            def __init__(self, simulator_binary: Path):
                self._simulator_binary = simulator_binary

            def command_for(self, elf):
                return [str(self._simulator_binary), "--run", str(elf)]

            def simulator_path(self):
                return self._simulator_binary

            def run(self, elf, *, timeout_seconds, log_path):
                calls.append(("dut", [str(elf), str(timeout_seconds), str(log_path)]))
                log_path.write_text(log_text, encoding="utf-8")
                return SimpleNamespace(status="fail", failure_class="unknown_failure", reason="chipyard simulator reported failure")

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            simulator_binary = out_dir / "simulator-cva6"
            simulator_binary.write_bytes(b"SIM")
            result = off_state_cva6.run_cva6_pilot_case(
                case,
                out_dir=out_dir,
                reset_command=["/usr/bin/true"],
                per_case_timeout_seconds=7,
                reset_runner=fake_reset,
                compile_runner=fake_compile,
                dut_factory=lambda **_: FakeDut(simulator_binary),
            )
            case_dir = out_dir / case["case_id"]
            stored = json.loads((case_dir / "result.json").read_text(encoding="utf-8"))
            raw_log_sha256 = hashlib.sha256(
                (case_dir / f"{case['case_id']}.log").read_bytes()
            ).hexdigest()

        self.assertEqual([item[0] for item in calls], ["reset", "compile", "dut"])
        self.assertEqual(result["execution_status"], "completed")
        self.assertTrue(result["control_pass"])
        self.assertEqual(stored["case_id"], case["case_id"])
        self.assertEqual(stored["execution_binding"]["reset_id"], case["reset_id"])
        self.assertEqual(stored["execution_binding"]["dut_name"], "cva6-clean")
        self.assertEqual(stored["execution_binding"]["simulator_version"], "CVA6Config")
        self.assertEqual(stored["execution_binding"]["payload_sha256"], hashlib.sha256(b"ELF").hexdigest())
        self.assertEqual(stored["execution_binding"]["raw_log_sha256"], raw_log_sha256)
        self.assertEqual(stored["execution_binding"]["dut_command"][1:], ["--run", str(case_dir / f"{case['case_id']}.elf")])
        self.assertEqual(stored["execution_binding"]["transport"]["kind"], "cva6-whitebox-artifacts")
        self.assertFalse(stored["execution_binding"]["transport"]["public_default"])
        self.assertTrue(stored["execution_binding"]["transport"]["dut_specific"])
        self.assertRegex(stored["execution_binding"]["source_git_sha"], r"^[0-9a-f]{40}$")
        self.assertEqual(
            stored["parsed_record"]["raw_log_sha256"],
            raw_log_sha256,
        )

    def test_run_case_resolves_relative_out_dir_before_invoking_dut(self):
        plan = off_state_cva6.build_cva6_pilot_plan(entry_index=0, reset_count=1)
        case = plan["cases"][0]
        observed = {}
        payload = off_state_cva6.encode_cva6_pilot_readback_payload(
            requested_cfg=0x00,
            readback_cfg_1=0x00,
            readback_cfg_2=0x00,
        )

        def fake_reset(command):
            return SimpleNamespace(returncode=0, stdout="reset-ok")

        def fake_compile(command):
            Path(command[-1]).write_bytes(b"ELF")
            return SimpleNamespace(returncode=0, stdout="compile-ok")

        class FakeDut:
            name = "cva6-clean"
            config = "CVA6Config"
            whitebox_artifacts = True

            def command_for(self, elf):
                observed["elf_in_command"] = str(elf)
                return ["/simulator", str(elf)]

            def run(self, elf, *, timeout_seconds, log_path):
                observed["elf_in_run"] = str(elf)
                log_path.write_text(f"*** FAILED *** (tohost = {payload})\n", encoding="utf-8")
                return SimpleNamespace(status="fail", failure_class="unknown_failure", reason="chipyard simulator reported failure")

        with TemporaryDirectory() as tmp:
            previous = Path.cwd()
            os.chdir(tmp)
            try:
                result = off_state_cva6.run_cva6_pilot_case(
                    case,
                    out_dir=Path("relative-out"),
                    reset_command=["/usr/bin/true"],
                    per_case_timeout_seconds=7,
                    reset_runner=fake_reset,
                    compile_runner=fake_compile,
                    dut_factory=lambda **_: FakeDut(),
                )
            finally:
                os.chdir(previous)

        self.assertEqual(result["execution_status"], "completed")
        self.assertTrue(Path(observed["elf_in_command"]).is_absolute())
        self.assertTrue(Path(observed["elf_in_run"]).is_absolute())

    def test_main_plan_writes_machine_readable_artifact(self):
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "artifacts"
            rc = off_state_cva6.main(
                [
                    "plan",
                    "--entry-index",
                    "0",
                    "--reset-count",
                    "1",
                    "--out",
                    str(out_dir),
                ]
            )
            payload = json.loads((out_dir / "cva6-pilot-plan.json").read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertEqual(payload["artifact_kind"], off_state_cva6.CVA6_PILOT_PLAN_KIND)
        self.assertEqual(len(payload["cases"]), 6)

    def test_plan_command_can_emit_exhaustive_cases(self):
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "artifacts"
            rc = off_state_cva6.main(
                [
                    "plan",
                    "--entry-index",
                    "0",
                    "--reset-count",
                    "1",
                    "--include-main-cases",
                    "--out",
                    str(out_dir),
                ]
            )
            payload = json.loads((out_dir / "cva6-pilot-plan.json").read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertEqual(len([case for case in payload["cases"] if "requested_raw_bin_id" in case]), 48)

    def test_formal_plan_command_writes_machine_readable_artifact(self):
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "artifacts"
            rc = off_state_cva6.main(
                [
                    "formal-plan",
                    "--entry-index",
                    "0",
                    "--reset-count",
                    "3",
                    "--out",
                    str(out_dir),
                ]
            )
            payload = json.loads((out_dir / "cva6-formal-batch-plan.json").read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertEqual(payload["artifact_kind"], off_state_cva6.CVA6_FORMAL_BATCH_PLAN_KIND)
        self.assertEqual(payload["main_case_count"], 144)
        self.assertEqual(len(payload["expected_execution_case_ids"]), 180)

    def test_module_cli_entrypoint_executes_formal_plan(self):
        repo_root = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "artifacts"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pmpfuzz.off_state_cva6",
                    "formal-plan",
                    "--entry-index",
                    "0",
                    "--reset-count",
                    "3",
                    "--out",
                    str(out_dir),
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )
            payload = json.loads((out_dir / "cva6-formal-batch-plan.json").read_text(encoding="utf-8"))

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(payload["artifact_kind"], off_state_cva6.CVA6_FORMAL_BATCH_PLAN_KIND)
        self.assertEqual(payload["main_case_count"], 144)

    def test_run_formal_batch_writes_main_records_and_analysis(self):
        plan = off_state_cva6.build_cva6_formal_batch_plan(entry_index=0, reset_count=3)
        normalized_record = _witness_normalized_record()

        def fake_case_runner(case, *, out_dir, reset_command, **_kwargs):
            return _fake_formal_batch_case_result(
                case,
                out_dir=Path(out_dir),
                reset_command=list(reset_command),
                normalized_record=normalized_record,
            )

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "formal-batch"
            summary = off_state_cva6.run_cva6_formal_batch(
                plan,
                out_dir=out_dir,
                reset_command=["/usr/bin/true"],
                case_runner=fake_case_runner,
            )
            records_lines = [line for line in (out_dir / "off-state-records.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            characterization = json.loads((out_dir / "off-state-characterization.json").read_text(encoding="utf-8"))
            analysis = json.loads((out_dir / "off-state-analysis.json").read_text(encoding="utf-8"))
            saved_summary = json.loads((out_dir / "cva6-formal-batch-summary.json").read_text(encoding="utf-8"))

        self.assertEqual(summary["artifact_kind"], off_state_cva6.CVA6_FORMAL_BATCH_SUMMARY_KIND)
        self.assertEqual(len(records_lines), 144)
        self.assertEqual(characterization["record_count"], 144)
        self.assertEqual(len(characterization["records"]), 144)
        self.assertEqual(len(saved_summary["pre_control_results"]), 18)
        self.assertEqual(len(saved_summary["post_control_results"]), 18)
        self.assertTrue(saved_summary["raw_log_validation"]["all_valid"])
        self.assertEqual(len(analysis["stable_readback_set"]["cva6"]["base-pmp"]["0"]), 16)
        self.assertTrue(analysis["mapper_witness_set"]["v3"])

    def test_run_formal_batch_rejects_case_id_closure_mismatch(self):
        plan = off_state_cva6.build_cva6_formal_batch_plan(entry_index=0, reset_count=3)
        normalized_record = _witness_normalized_record()
        mutated = {"done": False}

        def fake_case_runner(case, *, out_dir, reset_command, **_kwargs):
            case_id_override = None
            if not mutated["done"] and "requested_raw_bin_id" in case and case["subexperiment"] == "readback":
                mutated["done"] = True
                case_id_override = "unexpected-main-case-id"
            return _fake_formal_batch_case_result(
                case,
                out_dir=Path(out_dir),
                reset_command=list(reset_command),
                normalized_record=normalized_record,
                case_id_override=case_id_override,
            )

        with TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "formal-batch"
            with self.assertRaisesRegex(ValueError, "case.*mismatch|unexpected"):
                off_state_cva6.run_cva6_formal_batch(
                    plan,
                    out_dir=out_dir,
                    reset_command=["/usr/bin/true"],
                    case_runner=fake_case_runner,
                )


if __name__ == "__main__":
    unittest.main()
