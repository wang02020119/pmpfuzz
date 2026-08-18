from __future__ import annotations

import hashlib
import re
from typing import Any

from . import bapc


CASCADE_TARGET_OPERATION_SCHEMA_VERSION = "cascade-target-operation-v1"
_COMMIT_TRACE_PC_RE = re.compile(r"\bpc=\[(?P<pc>[0-9a-fA-F]+)\]")
_CASCADE_MEM_BASE = 0x80000000
_ACCESS_FAULT_MCAUSE = {
    "fetch": 1,
    "load": 5,
    "store": 7,
}
_MCAUSE_CLASS = {
    1: "instruction_access_fault",
    5: "load_access_fault",
    7: "store_access_fault",
    12: "instruction_page_fault",
    13: "load_page_fault",
    15: "store_page_fault",
}


def collect_cascade_runtime_attribution(
    *,
    dut: str,
    case_id: str,
    sidecar: dict[str, Any],
    result: dict[str, Any],
    log_text: str,
) -> dict[str, Any]:
    raw_log_sha256 = _text_sha256(log_text)
    if dut == "cva6-clean" and str(sidecar.get("target_operation_selection_rule") or "").strip() == (
        "deterministic-first-runtime-attributed-candidate"
    ):
        targets, artifact_reason = _resolve_target_candidates(sidecar)
        base = {
            "schema_version": CASCADE_TARGET_OPERATION_SCHEMA_VERSION,
            "dut": str(dut),
            "case_id": str(case_id),
            "artifact_valid": artifact_reason is None,
            "measurement_valid": False,
            "qualification_reason": artifact_reason or "missing-target-runtime-record",
            "runtime_records": [],
            "raw_log_sha256": raw_log_sha256,
        }
        if artifact_reason is not None:
            return base
        return _collect_cva6_runtime(
            base=base,
            targets=targets,
            result=result,
            log_text=log_text,
        )

    target, artifact_reason = _resolve_target_operation(sidecar)
    base = {
        "schema_version": CASCADE_TARGET_OPERATION_SCHEMA_VERSION,
        "dut": str(dut),
        "case_id": str(case_id),
        "artifact_valid": artifact_reason is None,
        "measurement_valid": False,
        "qualification_reason": artifact_reason or "missing-target-runtime-record",
        "runtime_records": [],
        "raw_log_sha256": raw_log_sha256,
    }
    if artifact_reason is not None:
        return base

    if dut == "rocket-clean":
        return _collect_rocket_runtime(
            base=base,
            target=target,
            result=result,
            log_text=log_text,
        )
    if dut == "boom-clean":
        return _collect_boom_runtime(
            base=base,
            target=target,
            result=result,
            log_text=log_text,
        )
    if dut == "cva6-clean":
        return _collect_cva6_runtime(
            base=base,
            target=target,
            result=result,
            log_text=log_text,
        )
    return {
        **base,
        "artifact_valid": False,
        "qualification_reason": f"unsupported-dut:{dut}",
    }


def replay_cascade_runtime_record(
    *,
    sidecar: dict[str, Any],
    runtime_record: dict[str, Any],
    bapc_core_version: str = bapc.BAPC_CORE_VERSION_V4,
) -> dict[str, Any]:
    actual_csr_state = dict(sidecar.get("actual_csr_state") or {})
    access = _normalize_access(runtime_record.get("access"))
    privilege = _normalize_privilege(runtime_record.get("privilege"))
    translation = _normalize_translation(runtime_record.get("translation"))
    size = _parse_int(runtime_record.get("size"))
    address = _parse_int(runtime_record.get("address"))
    status = _normalize_status(runtime_record.get("status"))
    if access is None or privilege is None or translation not in {"bare", "sv39"}:
        return _ineligible("runtime-record-missing-fields")
    if size is None or size <= 0 or address is None or status is None:
        return _ineligible("runtime-record-missing-fields")

    mcause = _parse_int(runtime_record.get("mcause"))
    if status == "completed":
        allow_or_deny = "allow"
        mcause_class = "none"
    else:
        allow_or_deny = "deny"
        if mcause is None:
            mcause = _ACCESS_FAULT_MCAUSE.get(access, 5)
        mcause_class = _MCAUSE_CLASS.get(mcause, "other")

    mapped = bapc.map_bapc_normalized_record(
        {
            "pmp_entries": list(sidecar.get("pmp_entries") or []),
            "actual_pmpcfg_entries": list(
                runtime_record.get("actual_pmpcfg_entries")
                or sidecar.get("actual_pmpcfg_entries")
                or []
            ),
            "translation": translation,
            "privilege": privilege,
            "access": access,
            "size": size,
            "address": address,
            "mprv": (
                bool(sidecar.get("mprv"))
                if sidecar.get("mprv") is not None
                else bapc._mstatus_mprv(actual_csr_state.get("mstatus"))
            ),
            "mpp": (
                _normalize_privilege(sidecar.get("mpp"))
                or bapc._mstatus_mpp(actual_csr_state.get("mstatus"))
                or "m"
            ),
            "allow_or_deny": allow_or_deny,
            "mcause_class": mcause_class,
        },
        bapc_core_version=bapc_core_version,
    )
    return mapped


def summarize_cascade_runtime_measurement(
    *,
    sidecar: dict[str, Any],
    runtime_payload: dict[str, Any],
    bapc_core_version: str = bapc.BAPC_CORE_VERSION_V4,
) -> dict[str, Any]:
    if not bool(runtime_payload.get("artifact_valid")):
        return {
            "eligible": False,
            "qualification_reason": str(
                runtime_payload.get("qualification_reason") or "invalid-runtime-artifact"
            ),
            "observed_bins": [],
            "artifact_valid": False,
            "measurement_valid": False,
            "runtime_records": [],
        }
    if not bool(runtime_payload.get("measurement_valid")):
        return {
            "eligible": False,
            "qualification_reason": _bapc_measurement_reason(runtime_payload),
            "observed_bins": [],
            "artifact_valid": True,
            "measurement_valid": False,
            "runtime_records": list(runtime_payload.get("runtime_records") or []),
        }

    observed_bins: set[str] = set()
    witness_records: list[dict[str, Any]] = []
    replay_reports: list[dict[str, Any]] = []
    for runtime_record in runtime_payload.get("runtime_records") or []:
        replay = replay_cascade_runtime_record(
            sidecar=sidecar,
            runtime_record=dict(runtime_record),
            bapc_core_version=bapc_core_version,
        )
        replay_reports.append(
            {
                "runtime_record": dict(runtime_record),
                "eligible": bool(replay.get("eligible")),
                "qualification_reason": str(
                    replay.get("qualification_reason") or "missing-replay-qualification"
                ),
                "observed_bins": list(replay.get("observed_bins") or []),
            }
        )
        if not replay.get("eligible"):
            return {
                "eligible": False,
                "qualification_reason": str(
                    replay.get("qualification_reason") or "runtime-replay-ineligible"
                ),
                "observed_bins": [],
                "artifact_valid": True,
                "measurement_valid": False,
                "runtime_records": list(runtime_payload.get("runtime_records") or []),
                "replay_reports": replay_reports,
            }
        replay_bins = {str(item) for item in (replay.get("observed_bins") or [])}
        if replay_bins - observed_bins:
            witness_records.append(dict(replay["normalized_record"]))
        observed_bins.update(replay_bins)

    if not observed_bins:
        return {
            "eligible": False,
            "qualification_reason": "missing-actual-runtime-record",
            "observed_bins": [],
            "artifact_valid": True,
            "measurement_valid": False,
            "runtime_records": list(runtime_payload.get("runtime_records") or []),
            "replay_reports": replay_reports,
        }

    return {
        "eligible": True,
        "qualification_reason": "eligible",
        "observed_bins": sorted(observed_bins),
        "event_records": witness_records,
        "artifact_valid": True,
        "measurement_valid": True,
        "runtime_records": list(runtime_payload.get("runtime_records") or []),
        "replay_reports": replay_reports,
    }


def _collect_rocket_runtime(
    *,
    base: dict[str, Any],
    target: dict[str, Any],
    result: dict[str, Any],
    log_text: str,
) -> dict[str, Any]:
    commit_hits = _rocket_commit_hits(log_text, target_pc=target["pc"])
    if not commit_hits:
        return {**base, "qualification_reason": "missing-target-runtime-record"}
    if len(commit_hits) != 1:
        return {**base, "qualification_reason": "multiple-target-runtime-records"}

    matching_records = []
    parse_failure_reason = None
    for event in bapc.parse_probe_events(log_text):
        fields = dict((event or {}).get("fields") or {})
        if str(fields.get("dut") or "").strip().lower() != "rocket-clean":
            continue
        if str(fields.get("probe") or "").strip().lower() != "rocket_pmp_checker":
            continue
        if str(fields.get("chain") or "").strip().lower() != "pmp-check":
            continue
        access = _normalize_access(fields.get("access"))
        address = _parse_int(fields.get("addr") or fields.get("paddr"))
        privilege = _normalize_privilege(fields.get("prv") or fields.get("privilege"))
        allow = _probe_bool(fields.get("allow"))
        size = _rocket_size_bytes(fields.get("size"), declared_size=target["size"])
        if access is None or address is None or privilege is None or allow is None or size is None:
            parse_failure_reason = "runtime-record-missing-fields"
            continue
        if access != target["access"]:
            continue
        if address not in target["candidate_addresses"]:
            continue
        status = "completed" if allow else "trap"
        if status == "completed" and len(commit_hits) == 1 and not allow:
            return {**base, "qualification_reason": "runtime-record-conflict"}
        matching_records.append(
            _runtime_record(
                base=base,
                target=target,
                privilege=privilege,
                access=access,
                size=size,
                address=address,
                status=status,
                translation=target["translation"],
                evidence_kind="rocket-commit-trace",
                mcause=_parse_int(result.get("observed_mcause")) if status == "trap" else None,
                mtval=_parse_int(result.get("observed_fault_address")) if status == "trap" else None,
            )
        )

    matching_records = _dedupe_runtime_records(matching_records)
    if not matching_records:
        return {
            **base,
            "qualification_reason": parse_failure_reason or "missing-target-runtime-record",
        }
    if len(matching_records) != 1:
        return {**base, "qualification_reason": "multiple-target-runtime-records"}
    return {
        **base,
        "measurement_valid": True,
        "qualification_reason": "eligible",
        "runtime_records": matching_records,
    }


def _collect_boom_runtime(
    *,
    base: dict[str, Any],
    target: dict[str, Any],
    result: dict[str, Any],
    log_text: str,
) -> dict[str, Any]:
    pending_issues: dict[tuple[str, int], dict[str, Any]] = {}
    matched_records: list[dict[str, Any]] = []
    same_probe_records: list[dict[str, Any]] = []
    wrong_pc_seen = False
    parse_failure_reason = None
    for event in bapc.parse_probe_events(log_text):
        fields = dict((event or {}).get("fields") or {})
        if str(fields.get("dut") or "").strip().lower() != "boom-clean":
            continue
        if str(fields.get("probe") or "").strip().lower() != "boom_target_operation_runtime":
            continue
        if str(fields.get("schema") or "").strip() != CASCADE_TARGET_OPERATION_SCHEMA_VERSION:
            continue
        if str(fields.get("role") or "").strip().lower() != "runtime":
            continue
        phase = str(fields.get("phase") or "").strip().lower()
        access = _normalize_access(fields.get("access"))
        queue_key = _boom_runtime_queue_key(fields, access)
        if phase == "issue":
            pc = _parse_int(fields.get("pc"))
            if pc is None or access is None or queue_key is None:
                parse_failure_reason = "runtime-record-missing-fields"
                continue
            if pc != target["pc"]:
                wrong_pc_seen = True
                continue
            if access != target["access"]:
                parse_failure_reason = "access-conflict"
                continue
            if queue_key in pending_issues:
                return {**base, "qualification_reason": "multiple-target-runtime-records"}
            pending_issues[queue_key] = {"pc": int(pc), "access": access}
            continue

        if queue_key is not None and queue_key in pending_issues:
            issue = pending_issues.pop(queue_key)
            candidate, candidate_reason = _runtime_record_from_fields(
                base=base,
                target=target,
                fields=fields,
                fallback_status="completed",
                fallback_privilege=target["privilege"],
                fallback_translation=target["translation"],
                result=result,
                evidence_kind="boom-runtime-probe",
                pc=issue["pc"],
            )
            if candidate_reason is not None:
                return {**base, "qualification_reason": candidate_reason}
            matched_records.append(candidate)
            continue

        pc = _parse_int(fields.get("pc"))
        if pc is None:
            parse_failure_reason = "runtime-record-missing-fields"
            continue
        if pc != target["pc"]:
            wrong_pc_seen = True
            continue
        candidate, candidate_reason = _runtime_record_from_fields(
            base=base,
            target=target,
            fields=fields,
            fallback_status="completed",
            fallback_privilege=target["privilege"],
            fallback_translation=target["translation"],
            result=result,
            evidence_kind="boom-runtime-probe",
        )
        if candidate_reason is not None:
            parse_failure_reason = candidate_reason
            continue
        same_probe_records.append(candidate)

    if pending_issues:
        return {**base, "qualification_reason": parse_failure_reason or "missing-target-runtime-record"}

    records = _dedupe_runtime_records(matched_records + same_probe_records)
    if not records:
        if wrong_pc_seen:
            return {**base, "qualification_reason": "wrong-runtime-pc"}
        return {
            **base,
            "qualification_reason": parse_failure_reason or "missing-target-runtime-record",
        }
    if len(records) != 1:
        return {**base, "qualification_reason": "multiple-target-runtime-records"}
    return {
        **base,
        "measurement_valid": True,
        "qualification_reason": "eligible",
        "runtime_records": records,
    }



def _boom_runtime_queue_key(fields: dict[str, Any], access: str | None) -> tuple[str, int] | None:
    if access == "load":
        ldq_idx = _parse_int(fields.get("ldq_idx"))
        if ldq_idx is None:
            return None
        return ("load", int(ldq_idx))
    if access == "store":
        stq_idx = _parse_int(fields.get("stq_idx"))
        if stq_idx is None:
            return None
        return ("store", int(stq_idx))
    return None


def _collect_cva6_runtime(
    *,
    base: dict[str, Any],
    target: dict[str, Any] | None = None,
    targets: list[dict[str, Any]] | None = None,
    result: dict[str, Any],
    log_text: str,
) -> dict[str, Any]:
    ordered_targets = [dict(target)] if target is not None else [dict(item) for item in (targets or [])]
    if not ordered_targets:
        return {**base, "qualification_reason": "missing-target-operation"}

    targets_by_key: dict[tuple[int, str], list[dict[str, Any]]] = {}
    targets_by_pc: dict[int, list[dict[str, Any]]] = {}
    for item in ordered_targets:
        targets_by_key.setdefault((int(item["pc"]), str(item["access"])), []).append(item)
        targets_by_pc.setdefault(int(item["pc"]), []).append(item)

    pending_issues: dict[int, list[dict[str, Any]]] = {}
    matched_records_by_target: dict[str, list[dict[str, Any]]] = {}
    wrong_pc_seen = False
    parse_failure_reason = None
    for event in bapc.parse_probe_events(log_text):
        fields = dict((event or {}).get("fields") or {})
        if str(fields.get("dut") or "").strip().lower() != "cva6-clean":
            continue
        probe = str(fields.get("probe") or "").strip().lower()
        if str(fields.get("schema") or "").strip() != CASCADE_TARGET_OPERATION_SCHEMA_VERSION:
            continue
        if str(fields.get("role") or "").strip().lower() != "runtime":
            continue
        trans_id = _parse_int(fields.get("trans_id"))
        if trans_id is None:
            parse_failure_reason = "runtime-record-missing-fields"
            continue
        trans_id = int(trans_id)
        if probe == "cva6_target_operation_issue":
            pc = _parse_int(fields.get("pc"))
            access = _normalize_access(fields.get("access"))
            if pc is None:
                parse_failure_reason = "runtime-record-missing-fields"
                continue
            candidates = targets_by_key.get((int(pc), access)) if access is not None else None
            if not candidates:
                candidates = targets_by_pc.get(int(pc))
            if not candidates:
                wrong_pc_seen = True
                continue
            pending_issues.setdefault(trans_id, []).append({"pc": int(pc), "target": candidates[0]})
            continue
        if probe != "cva6_target_operation_runtime":
            continue
        queue = pending_issues.get(trans_id)
        if not queue:
            continue
        issue = queue.pop(0)
        if not queue:
            pending_issues.pop(trans_id, None)
        current_target = dict(issue["target"])
        candidate, candidate_reason = _runtime_record_from_fields(
            base=base,
            target=current_target,
            fields=fields,
            fallback_status="completed",
            fallback_privilege=current_target["privilege"],
            fallback_translation=current_target["translation"],
            result=result,
            evidence_kind="cva6-runtime-probe",
            pc=issue["pc"],
        )
        if candidate_reason is not None:
            parse_failure_reason = candidate_reason
            continue
        matched_records_by_target.setdefault(str(current_target["target_operation_id"]), []).append(candidate)

    for current_target in ordered_targets:
        records = _dedupe_runtime_records(
            list(matched_records_by_target.get(str(current_target["target_operation_id"]), []))
        )
        if not records:
            continue
        if len(records) != 1:
            return {**base, "qualification_reason": "multiple-target-runtime-records"}
        return {
            **base,
            "measurement_valid": True,
            "qualification_reason": "eligible",
            "runtime_records": records,
        }

    if pending_issues:
        return {**base, "qualification_reason": parse_failure_reason or "missing-target-runtime-record"}
    if wrong_pc_seen:
        return {**base, "qualification_reason": "wrong-runtime-pc"}
    return {
        **base,
        "qualification_reason": parse_failure_reason or "missing-target-runtime-record",
    }


def _resolve_target_candidates(sidecar: dict[str, Any]) -> tuple[list[dict[str, Any]] | None, str | None]:
    if not isinstance(sidecar, dict):
        return None, "missing-target-operation"

    declared_candidates = [
        dict(item)
        for item in (sidecar.get("target_operation_candidates") or [])
        if isinstance(item, dict)
    ]
    if not declared_candidates and all(
        sidecar.get(key) is not None
        for key in (
            "target_operation_id",
            "privilege",
            "access",
            "size",
            "instruction_address",
        )
    ):
        declared_candidates = [
            {
                "target_operation_id": sidecar.get("target_operation_id"),
                "privilege": sidecar.get("privilege"),
                "access": sidecar.get("access"),
                "size": sidecar.get("size"),
                "physical_address": sidecar.get("physical_address"),
                "instruction_address": sidecar.get("instruction_address"),
                "translation": sidecar.get("translation"),
            }
        ]
    if not declared_candidates:
        return None, "missing-target-operation"

    resolved: list[dict[str, Any]] = []
    for declared in declared_candidates:
        target_id = str(declared.get("target_operation_id") or "").strip()
        privilege = _normalize_privilege(declared.get("privilege"))
        access = _normalize_access(declared.get("access"))
        size = _parse_int(declared.get("size"))
        address = _parse_int(declared.get("physical_address"))
        pc = _parse_int(declared.get("instruction_address"))
        translation = _normalize_translation(
            sidecar.get("translation") if sidecar.get("translation") is not None else declared.get("translation")
        )
        if not target_id or privilege is None or access is None or size is None or size <= 0:
            return None, "invalid-target-operation"
        if pc is None or translation not in {"bare", "sv39"}:
            return None, "invalid-target-operation"
        resolved_item = {
            "target_operation_id": target_id,
            "privilege": privilege,
            "access": access,
            "size": size,
            "address": address,
            "pc": pc,
            "translation": translation,
        }
        if address is not None:
            resolved_item["candidate_addresses"] = _cascade_candidate_addresses(address=address, pc=pc)
        resolved.append(resolved_item)
    return resolved, None


def _resolve_target_operation(sidecar: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(sidecar, dict):
        return None, "missing-target-operation"

    if all(
        sidecar.get(key) is not None
        for key in (
            "target_operation_id",
            "privilege",
            "access",
            "size",
            "physical_address",
            "instruction_address",
        )
    ):
        explicit_sidecar = {
            "translation": sidecar.get("translation"),
            "target_operation_candidates": [
                {
                    "target_operation_id": sidecar.get("target_operation_id"),
                    "privilege": sidecar.get("privilege"),
                    "access": sidecar.get("access"),
                    "size": sidecar.get("size"),
                    "physical_address": sidecar.get("physical_address"),
                    "instruction_address": sidecar.get("instruction_address"),
                    "translation": sidecar.get("translation"),
                }
            ],
        }
        candidates, reason = _resolve_target_candidates(explicit_sidecar)
    else:
        candidates, reason = _resolve_target_candidates(sidecar)
        if reason is None and candidates is not None and len(candidates) != 1:
            return None, "ambiguous-target-operation"
    if reason is not None:
        return None, reason
    assert candidates is not None
    target = dict(candidates[0])
    if target.get("address") is None:
        return None, "invalid-target-operation"
    target["candidate_addresses"] = _cascade_candidate_addresses(
        address=int(target["address"]),
        pc=int(target["pc"]),
    )
    return target, None


def _runtime_record_from_fields(
    *,
    base: dict[str, Any],
    target: dict[str, Any],
    fields: dict[str, str],
    fallback_status: str,
    fallback_privilege: str,
    fallback_translation: str,
    result: dict[str, Any],
    evidence_kind: str,
    pc: int | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    record_pc = _parse_int(fields.get("pc")) if pc is None else int(pc)
    if record_pc is None:
        return None, "runtime-record-missing-fields"
    if record_pc != target["pc"]:
        return None, "wrong-runtime-pc"
    access = _normalize_access(fields.get("access")) or target["access"]
    if access != target["access"]:
        return None, "access-conflict"
    status = _normalize_status(fields.get("status")) or fallback_status
    privilege = _normalize_privilege(fields.get("privilege") or fields.get("prv")) or fallback_privilege
    translation = _normalize_translation(fields.get("translation")) or fallback_translation
    size = _parse_int(fields.get("size")) or target["size"]
    address = _parse_int(fields.get("addr") or fields.get("address") or fields.get("paddr"))
    mcause = _parse_int(fields.get("mcause"))
    mtval = _parse_int(fields.get("mtval"))
    if status is None or privilege is None or translation not in {"bare", "sv39"}:
        return None, "runtime-record-missing-fields"
    if size is None or size <= 0 or address is None:
        return None, "runtime-record-missing-fields"
    if status == "trap":
        if mcause is None or mtval is None:
            return None, "runtime-record-missing-fields"
        result_mcause = _parse_int(result.get("observed_mcause"))
        if result_mcause is not None and result_mcause != mcause:
            return None, "cause-mismatch"
    return (
        _runtime_record(
            base=base,
            target=target,
            privilege=privilege,
            access=access,
            size=size,
            address=address,
            status=status,
            translation=translation,
            evidence_kind=evidence_kind,
            mcause=mcause,
            mtval=mtval,
        ),
        None,
    )


def _runtime_record(
    *,
    base: dict[str, Any],
    target: dict[str, Any],
    privilege: str,
    access: str,
    size: int,
    address: int,
    status: str,
    translation: str,
    evidence_kind: str,
    mcause: int | None,
    mtval: int | None,
) -> dict[str, Any]:
    return {
        "schema_version": CASCADE_TARGET_OPERATION_SCHEMA_VERSION,
        "dut": str(base["dut"]),
        "case_id": str(base["case_id"]),
        "target_operation_id": str(target["target_operation_id"]),
        "pc": f"0x{int(target['pc']):x}",
        "access": access,
        "size": int(size),
        "address": f"0x{int(address):x}",
        "privilege": privilege,
        "translation": translation,
        "status": status,
        "mcause": None if mcause is None else int(mcause),
        "mtval": None if mtval is None else f"0x{int(mtval):x}",
        "evidence_kind": evidence_kind,
        "raw_log_sha256": str(base["raw_log_sha256"]),
    }


def _rocket_commit_hits(log_text: str, *, target_pc: int) -> list[int]:
    hits = []
    for line in str(log_text or "").splitlines():
        match = _COMMIT_TRACE_PC_RE.search(line)
        if match is None:
            continue
        pc = _parse_int(match.group("pc"))
        if pc == target_pc:
            hits.append(pc)
    return hits


def _cascade_candidate_addresses(*, address: int, pc: int) -> set[int]:
    out = {int(address)}
    if address < _CASCADE_MEM_BASE and pc >= _CASCADE_MEM_BASE:
        out.add(_CASCADE_MEM_BASE + int(address))
    return out


def _dedupe_runtime_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    out = []
    for item in records:
        key = (
            item.get("target_operation_id"),
            item.get("pc"),
            item.get("access"),
            item.get("size"),
            item.get("address"),
            item.get("status"),
            item.get("mcause"),
            item.get("mtval"),
            item.get("evidence_kind"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _bapc_measurement_reason(runtime_payload: dict[str, Any]) -> str:
    reason = str(runtime_payload.get("qualification_reason") or "")
    if reason in {"missing-target-runtime-record", "multiple-target-runtime-records"}:
        return "missing-actual-runtime-record"
    return reason or "missing-actual-runtime-record"


def _rocket_size_bytes(raw_size: Any, *, declared_size: int) -> int | None:
    parsed = _parse_int(raw_size)
    if parsed is None:
        return int(declared_size)
    if parsed <= 0:
        return 1
    if parsed <= 4:
        return 1 << parsed
    return parsed


def _normalize_access(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    if text in {"0", "read", "r", "ld", "load"}:
        return "load"
    if text in {"1", "write", "w", "st", "store"}:
        return "store"
    if text in {"2", "x", "exec", "fetch"}:
        return "fetch"
    return None


def _normalize_privilege(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    if text in {"0", "u", "user"}:
        return "u"
    if text in {"1", "s", "supervisor"}:
        return "s"
    if text in {"3", "m", "machine"}:
        return "m"
    return None


def _normalize_translation(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if text in {"bare", "sv39"}:
        return text
    return None


def _normalize_status(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if text in {"completed", "completion", "retired"}:
        return "completed"
    if text in {"trap", "fault", "exception"}:
        return "trap"
    return None


def _parse_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        if re.fullmatch(r"[0-9a-fA-F]+", text):
            # Rocket and other RTL traces may emit zero-padded hex tokens without 0x.
            if any(ch in "abcdefABCDEF" for ch in text) or (text.startswith("0") and len(text) > 1):
                try:
                    return int(text, 16)
                except ValueError:
                    return None
        return None


def _probe_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes"}:
        return True
    if text in {"0", "false", "no"}:
        return False
    return None


def _text_sha256(text: str) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8")).hexdigest()


def _ineligible(reason: str) -> dict[str, Any]:
    return {
        "eligible": False,
        "qualification_reason": str(reason),
        "observed_bins": [],
    }
