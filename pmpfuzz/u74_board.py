from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

from .bapc import summarize_bapc_for_pmpfuzz_case
from .coverage_qualification import load_case_map, load_results, qualify_result_for_coverage
from .coverage_universe import make_coverage_universe
from .scenario_codec import scenario_from_spec
from .schema import result_to_dict, scenario_to_case_dict, write_json


DEFAULT_U74_CATALOG_PATH = Path(
    os.environ.get("PMPFUZZ_U74_CATALOG", "artifacts/u74/catalog.json")
)

U74_OBSERVATION_PROFILE_ID = "u74-uart-v1"
U74_SUPPORTED_BAPC_RULE_VERSION = "u74-bapc-supported-v1"
# The U74 board campaign targets BAPC-core v4.  The scenario summarizer
# defaults to v2, so every U74 lowered-case result must be stamped v4
# explicitly; otherwise the archived result.json files carry bapc_core_version
# "v2" even though the bin set and universe are the formal v4 144-bin set.
U74_BAPC_CORE_VERSION = "v4"
ENGINEERING_SMOKE_VALIDATOR_PROFILE = "engineering-smoke-v1"
FORMAL_U74_BATCHED_VALIDATOR_PROFILE = "formal-u74-batched-v1"
U74_VALIDATOR_PROFILES = frozenset(
    {
        ENGINEERING_SMOKE_VALIDATOR_PROFILE,
        FORMAL_U74_BATCHED_VALIDATOR_PROFILE,
    }
)

DIRECT_U74_BOARD_CASES = (
    "smoke-bare-u-load-pmp-allow",
    "smoke-bare-u-load-pmp-deny",
    "smoke-mprv-mpp-u-load-deny",
    "smoke-sv39-final-pa-pmp-deny",
    "smoke-amo-pmp-deny-no-side-effect",
    "batch2-fetch-x-to-nx-sfence",
    "batch2-fetch-nx-to-x-sfence-fencei",
    "batch2-fetch-pmp-exec-allow-to-deny",
    "batch2-ptw-pmp-deny-root",
    "batch2-lr-pmp-deny-no-side-effect",
    "batch2-sc-pmp-deny-no-side-effect",
    "batch2-lrsc-allowed",
    "batch2-priority-misaligned-vs-pmp",
    "batch2-priority-misaligned-vs-pagefault",
    "batch2-priority-pagefault-vs-pmp-final-pa",
    "batch2-priority-fetch-illegal-vs-nox",
    "batch2-precision-fetch-illegal",
)

CASE_RE = re.compile(r"^\[pmpfuzz\]\s+case=(?P<case>\S+)\s+(?P<tail>.*)$")
RUNNER_RE = re.compile(r"^\[pmpfuzz\]\s+runner\s+(?P<event>begin|end)\b(?P<tail>.*)$")
MANIFEST_RE = re.compile(r"^\[pmpfuzz\]\s+manifest\b(?P<tail>.*)$")
KV_RE = re.compile(r"(?P<key>[A-Za-z0-9_.-]+)=(?P<value>\S+)")

# Batch group markers: names gated in the board runner that expand to many
# per-sub-case records at execution time. They are present in the generated
# manifest (so the firmware runs the group) but do not themselves produce a
# per-case UART record, so they are excluded from case-set reconciliation.
U74_BATCH_GROUP_MARKERS = frozenset({"batch3-group", "batch4-group", "batch5-group"})


def is_u74_group_marker(name: str) -> bool:
    return str(name or "") in U74_BATCH_GROUP_MARKERS

_PRIV_MAP = {
    "0": "u",
    "1": "s",
    "3": "m",
    "u": "u",
    "s": "s",
    "m": "m",
}
_MCAUSE_CLASS = {
    1: "instruction_access_fault",
    5: "load_access_fault",
    7: "store_access_fault",
    12: "instruction_page_fault",
    13: "load_page_fault",
    15: "store_page_fault",
}


def default_u74_observation_profile() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "dut": "u74",
        "observation_profile_id": U74_OBSERVATION_PROFILE_ID,
        "channel": "uart",
        "structured_log_prefix": "[pmpfuzz]",
        "supported_fields": [
            "result",
            "cause",
            "trap_name",
            "tval",
            "value",
            "before",
            "after",
            "side_effect",
            "mpp",
            "satp",
            "op",
            "addr",
            "entry",
        ],
        "supported_bapc_families": [
            "stimulus",
            "decision",
            "privilege-decision",
        ],
        "excluded_bapc_families": [
            "config",
            "mode-decision",
        ],
        "supports_structured_uart": True,
    }


def load_json(path: Path | str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="ascii"))


def _manifest_sha256(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _recompute_generated_manifest_sha256(payload: dict[str, Any]) -> str:
    normalized = dict(payload or {})
    normalized.pop("manifest_sha256", None)
    return _manifest_sha256(normalized)


def _round_index(value: str) -> int:
    match = re.search(r"round[-_](\d+)$", str(value or ""))
    return int(match.group(1)) if match else 0


def _coverage_hash_payload(observed_bins: set[str] | list[str]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "u74-bapc-cumulative-coverage-v1",
        "observed_bins": sorted({str(item) for item in observed_bins if str(item)}),
    }


def canonical_u74_bapc_coverage_hash(observed_bins: set[str] | list[str]) -> str:
    return _manifest_sha256(_coverage_hash_payload(observed_bins))


def _is_positive_real_number(value: object) -> bool:
    return type(value) in {int, float} and not isinstance(value, bool) and float(value) > 0.0


def _formal_schedule_field_present(entry: dict[str, Any], key: str) -> bool:
    if key not in entry:
        return False
    value = entry.get(key)
    if key == "parent_new_bins":
        return type(value) is int and not isinstance(value, bool)
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value)
    return True


def parse_kv_tail(text: str) -> dict[str, str]:
    return {match.group("key"): match.group("value") for match in KV_RE.finditer(text)}


def parse_uart_log(text: str) -> dict[str, Any]:
    cases: list[dict[str, str]] = []
    runner_events: list[dict[str, str]] = []
    manifests: list[dict[str, str]] = []

    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        case_match = CASE_RE.match(line)
        if case_match:
            item = {"case": case_match.group("case")}
            item.update(parse_kv_tail(case_match.group("tail")))
            cases.append(item)
            continue
        runner_match = RUNNER_RE.match(line)
        if runner_match:
            item = {"event": runner_match.group("event")}
            item.update(parse_kv_tail(runner_match.group("tail")))
            runner_events.append(item)
            continue
        manifest_match = MANIFEST_RE.match(line)
        if manifest_match:
            item = parse_kv_tail(manifest_match.group("tail"))
            manifests.append(item)

    begins = [item for item in runner_events if item.get("event") == "begin"]
    ends = [item for item in runner_events if item.get("event") == "end"]
    return {
        "cases": cases,
        "runner_events": runner_events,
        "runner_begin": begins[0] if begins else {},
        "runner_end": ends[-1] if ends else {},
        "manifest": manifests[-1] if manifests else {},
        "runner_begin_count": len(begins),
        "runner_end_count": len(ends),
        "manifest_count": len(manifests),
    }


def _ordered_case_names_for_feedback(round_dir: Path, *, case_map: dict[str, Any], results_by_case: dict[str, Any]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    timeline_path = round_dir / "metrics" / "coverage_timeline.jsonl"
    if timeline_path.exists():
        try:
            timeline_rows = [
                json.loads(line)
                for line in timeline_path.read_text(encoding="ascii").splitlines()
                if line.strip()
            ]
        except (UnicodeError, OSError, json.JSONDecodeError):
            timeline_rows = []
        completion_rows = sorted(
            (
                row for row in timeline_rows
                if int(row.get("completion_seq") or 0) > 0 and str(row.get("case_id") or "")
            ),
            key=lambda row: int(row.get("completion_seq") or 0),
        )
        for row in completion_rows:
            case_name = str(row.get("case_id") or "")
            if case_name and case_name in case_map and case_name in results_by_case and case_name not in seen:
                ordered.append(case_name)
                seen.add(case_name)
    for case_name in sorted(case_map):
        if case_name in results_by_case and case_name not in seen:
            ordered.append(case_name)
            seen.add(case_name)
    return ordered


def build_u74_round_feedback_records(round_dir: Path, *, dut: str = "u74") -> list[dict[str, Any]]:
    case_map = load_case_map(round_dir)
    results_by_case = load_results(round_dir)
    records: list[dict[str, Any]] = []
    for case_name in _ordered_case_names_for_feedback(round_dir, case_map=case_map, results_by_case=results_by_case):
        case = case_map.get(case_name)
        result_list = results_by_case.get(case_name) or []
        if case is None or len(result_list) != 1:
            continue
        result = result_list[0]
        result_dut = str(result.get("dut") or "")
        if result_dut and result_dut != dut:
            continue
        qualification = qualify_result_for_coverage(case, result)
        bapc_payload = result.get("bapc_coverage") or {}
        coverage_eligible = bool(qualification.eligible and bapc_payload.get("eligible"))
        feedback_eligible = coverage_eligible and str(result.get("status") or "") == "pass"
        qualification_reason = str(qualification.reason or "")
        if coverage_eligible and not feedback_eligible:
            qualification_reason = "nonpass_excluded_from_feedback"
        records.append(
            {
                "case_id": str(case.get("name") or case_name),
                "profile": str(case.get("profile") or ""),
                "scenario_hash": str(case.get("scenario_hash") or ""),
                "scenario_fingerprint": str(case.get("scenario_hash") or ""),
                "scenario_spec": dict(case.get("scenario_spec") or {}),
                "eligible": feedback_eligible,
                "coverage_eligible": coverage_eligible,
                "feedback_eligible": feedback_eligible,
                "qualification_reason": qualification_reason,
                "observed_bins": (
                    sorted({str(item) for item in (bapc_payload.get("observed_bins") or [])})
                    if feedback_eligible
                    else []
                ),
            }
        )
    return records


def build_u74_campaign_feedback_state(round_dirs: list[Path], *, dut: str = "u74") -> dict[str, Any]:
    cumulative_bins: set[str] = set()
    rounds: list[dict[str, Any]] = []
    case_records: dict[str, dict[str, Any]] = {}
    for round_dir in sorted(round_dirs, key=lambda path: _round_index(path.name)):
        round_index = _round_index(round_dir.name)
        round_id = f"round-{round_index:04d}"
        previous_bins = sorted(cumulative_bins)
        previous_hash = canonical_u74_bapc_coverage_hash(cumulative_bins)
        round_records: list[dict[str, Any]] = []
        for record in build_u74_round_feedback_records(round_dir, dut=dut):
            observed_bins = list(record.get("observed_bins") or [])
            new_bins = sorted(set(observed_bins) - cumulative_bins) if record.get("eligible") else []
            if record.get("eligible"):
                cumulative_bins.update(observed_bins)
            case_record = {
                **record,
                "round_index": round_index,
                "round_id": round_id,
                "new_bins": new_bins,
                "new_bin_count": len(new_bins),
                "cumulative_bins_after_case": sorted(cumulative_bins),
            }
            round_records.append(case_record)
            case_id = str(case_record.get("case_id") or "")
            if case_id:
                case_records[case_id] = case_record
        rounds.append(
            {
                "round_dir": round_dir,
                "round_index": round_index,
                "round_id": round_id,
                "previous_coverage_hash": previous_hash,
                "cumulative_bins_before": previous_bins,
                "cumulative_bins_after": sorted(cumulative_bins),
                "cumulative_coverage_hash_after": canonical_u74_bapc_coverage_hash(cumulative_bins),
                "records": round_records,
            }
        )
    return {
        "coverage_hash": canonical_u74_bapc_coverage_hash(cumulative_bins),
        "cumulative_bins": sorted(cumulative_bins),
        "rounds": rounds,
        "case_records": case_records,
    }


def split_round_campaign_id(value: str) -> tuple[str, str]:
    text = str(value or "")
    marker = "__round-"
    if marker not in text:
        return text, "round-0000"
    base, suffix = text.rsplit(marker, 1)
    return base, f"round-{suffix}"


def stable_legacy_scenario_hash(case_name: str, profile: str) -> str:
    payload = json.dumps(
        {
            "case": str(case_name),
            "profile": str(profile),
            "source": "u74-legacy-board-catalog",
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def build_candidate_pool_from_catalog(
    catalog_path: Path | str,
    *,
    seed: int,
) -> list[dict[str, Any]]:
    catalog = load_json(catalog_path)
    candidates: list[dict[str, Any]] = []
    allowed_case_names = set(DIRECT_U74_BOARD_CASES)
    for index, entry in enumerate(catalog.get("cases") or []):
        case_name = str(entry.get("case") or "")
        profile = str(entry.get("profile") or "u74-legacy")
        if not case_name:
            continue
        if case_name not in allowed_case_names:
            continue
        bapc_payload = legacy_case_bapc_coverage(entry)
        candidates.append(
            {
                "candidate_id": hashlib.sha256(f"u74:{seed}:{case_name}".encode("ascii")).hexdigest()[:16],
                "profile": profile,
                "generation_seed": seed,
                "scenario_index": index,
                "name": case_name,
                "semantic_bins": [],
                "pairwise_bins": [],
                "security_triple_bins": [],
                "predicate_bins": [],
                "bapc_bins": list(bapc_payload.get("observed_bins") or []),
                "scenario_spec": {
                    "legacy_case_id": case_name,
                    "catalog_source": str(Path(catalog_path)),
                },
                "scenario_hash": stable_legacy_scenario_hash(case_name, profile),
                "legacy_case_id": case_name,
            }
        )
    return candidates


def build_supported_bapc_universe(
    catalog_path: Path | str,
    *,
    generator_seed: int,
    capability_fingerprint: str,
    observation_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    catalog = load_json(catalog_path)
    bins: set[str] = set()
    excluded_cases: list[dict[str, str]] = []
    for entry in catalog.get("cases") or []:
        payload = legacy_case_bapc_coverage(entry)
        if payload.get("eligible"):
            bins.update(str(item) for item in (payload.get("observed_bins") or []))
        else:
            excluded_cases.append(
                {
                    "case": str(entry.get("case") or ""),
                    "reason": str(payload.get("qualification_reason") or "ineligible"),
                }
            )
    observation_profile = dict(observation_profile or default_u74_observation_profile())
    return make_coverage_universe(
        coverage_mode="bapc",
        bin_ids=sorted(bins),
        capability_fingerprint=capability_fingerprint,
        target="u74-supported-bapc",
        include_experimental=False,
        generator_seed=int(generator_seed),
        generation_rule_version=U74_SUPPORTED_BAPC_RULE_VERSION,
        extra_fields={
            "dut": "u74",
            "observation_profile_id": str(observation_profile.get("observation_profile_id") or U74_OBSERVATION_PROFILE_ID),
            "supported_bapc_families": list(observation_profile.get("supported_bapc_families") or []),
            "excluded_bapc_families": list(observation_profile.get("excluded_bapc_families") or []),
            "catalog_case_count": len(catalog.get("cases") or []),
            "excluded_cases": excluded_cases,
        },
    )


def legacy_case_to_case_dict(
    scheduled_entry: dict[str, Any],
    catalog_entry: dict[str, Any],
) -> dict[str, Any]:
    case_name = str(scheduled_entry.get("name") or catalog_entry.get("case") or "")
    profile = str(scheduled_entry.get("profile") or catalog_entry.get("profile") or "u74-legacy")
    expected_text = str(catalog_entry.get("expected") or "").strip().lower()
    expected_allowed = expected_text in {"allow", "observation"}
    expected_cause = _parse_int(catalog_entry.get("expected_cause"))
    if expected_allowed:
        expected_cause = None
    access = _normalize_access(catalog_entry.get("op"))
    effective_privilege = _effective_privilege_from_entry(catalog_entry)
    privilege = _architectural_privilege_from_entry(catalog_entry, effective_privilege)
    translation = _translation_from_entry(catalog_entry)
    bapc_payload = legacy_case_bapc_coverage(catalog_entry)
    return {
        "schema_version": 1,
        "seed": int(scheduled_entry.get("seed") or 0),
        "index": int(scheduled_entry.get("index") or 0),
        "candidate_id": str(scheduled_entry.get("candidate_id") or ""),
        "name": case_name,
        "profile": profile,
        "scenario_hash": str(scheduled_entry.get("scenario_hash") or stable_legacy_scenario_hash(case_name, profile)),
        "scenario_spec": {
            "legacy_case_id": str(catalog_entry.get("case") or case_name),
            "catalog_source": "u74-legacy-board-catalog",
        },
        "legacy_case_id": str(catalog_entry.get("case") or case_name),
        "selection_source": str(scheduled_entry.get("selection_source") or "bootstrap"),
        "estimated_new_bins": int(scheduled_entry.get("estimated_new_bins") or 0),
        "privilege": privilege.upper(),
        "effective_privilege": effective_privilege.upper(),
        "access": access,
        "translation": translation,
        "physical_address": _parse_int(catalog_entry.get("addr") or catalog_entry.get("entry")),
        "mpp": _parse_int(catalog_entry.get("mpp")),
        "mprv": "mprv" in case_name,
        "expected": {
            "allowed": expected_allowed,
            "trap_cause": expected_cause,
            "stage": "normal",
        },
        "required_capabilities": _required_capabilities_from_case(translation, effective_privilege),
        "oracle_applicability": "valid",
        "bapc_bins": list(bapc_payload.get("observed_bins") or []),
    }


def _is_scenario_native_schedule_entry(scheduled_entry: dict[str, Any]) -> bool:
    spec = scheduled_entry.get("scenario_spec")
    if not isinstance(spec, dict):
        return False
    if "legacy_case_id" in spec or "catalog_source" in spec:
        return False
    return bool(scheduled_entry.get("lowering"))


def scenario_schedule_to_case_dict(scheduled_entry: dict[str, Any]) -> dict[str, Any]:
    case_name = str(scheduled_entry.get("name") or scheduled_entry.get("case_id") or "")
    if not case_name:
        raise ValueError("scenario-native schedule entry is missing name")
    scenario = replace(scenario_from_spec(scheduled_entry.get("scenario_spec")), name=case_name)
    case = scenario_to_case_dict(
        scenario,
        seed=int(scheduled_entry.get("seed") or 0),
        index=int(
            scheduled_entry.get("case_index")
            or scheduled_entry.get("generator_index")
            or scheduled_entry.get("index")
            or 0
        ),
    )
    expected_hash = str(
        scheduled_entry.get("scenario_hash")
        or scheduled_entry.get("scenario_fingerprint")
        or ""
    )
    if expected_hash and str(case.get("scenario_hash") or "") != expected_hash:
        raise ValueError(f"scenario hash mismatch for {case_name}")
    case["candidate_id"] = str(scheduled_entry.get("candidate_id") or "")
    case["selection_source"] = str(scheduled_entry.get("selection_source") or "pmpfuzz-scenario-generator")
    case["lowering"] = dict(scheduled_entry.get("lowering") or {})
    for key in (
        "previous_coverage_hash",
        "parent_case_id",
        "parent_new_bins",
        "selection_energy",
        "mutation_id",
    ):
        if key in scheduled_entry:
            case[key] = scheduled_entry[key]
    return case


def legacy_case_result_dict(
    *,
    case: dict[str, Any],
    observed_entry: dict[str, Any],
    dut: str,
    log_path: Path,
    elapsed_seconds: float | None = None,
) -> dict[str, Any]:
    result_text = str(observed_entry.get("result") or "").strip().lower()
    observed_event = "completion" if result_text == "allow" else "trap"
    observed_phase = "completed" if observed_event == "completion" else "probe"
    observed_tohost = 1 if observed_event == "completion" else None
    observed_mcause = _parse_int(observed_entry.get("cause"))
    observed_mtval = _parse_int(observed_entry.get("tval"))
    payload = legacy_case_bapc_coverage(observed_entry)
    return result_to_dict(
        case=case,
        dut=dut,
        status=str(observed_entry.get("status") or "pass"),
        elapsed_seconds=float(elapsed_seconds) if elapsed_seconds is not None else 0.25,
        returncode=0,
        log=log_path,
        reason=None,
        observed_tohost=observed_tohost,
        observed_mcause=observed_mcause,
        observed_mtval=observed_mtval,
        observed_event=observed_event,
        observed_phase=observed_phase,
        observed_stage="normal",
        observation_valid=True,
        stage_verified=(observed_event == "trap"),
        failure_class=None,
        oracle_applicability="valid",
        bapc_coverage=payload,
    )


def scenario_case_result_dict(
    *,
    case: dict[str, Any],
    observed_entry: dict[str, Any],
    dut: str,
    log_path: Path,
    raw_uart_text: str,
    dut_capability: dict[str, Any],
    elapsed_seconds: float | None = None,
) -> dict[str, Any]:
    result_text = str(observed_entry.get("result") or "").strip().lower()
    status = str(observed_entry.get("status") or "").strip().lower() or "inconclusive"
    observed_event = "completion" if result_text == "allow" else "trap" if result_text == "trap" else None
    observed_phase = "completed" if observed_event == "completion" else "probe" if observed_event == "trap" else None
    observed_tohost = 1 if observed_event == "completion" else None
    observed_mcause = _parse_int(observed_entry.get("cause"))
    observed_mtval = _parse_int(observed_entry.get("tval"))
    provisional = {
        "status": status,
        "observation_valid": observed_event is not None,
        "observed_event": observed_event,
        "observed_mcause": observed_mcause,
    }
    # Classify fail results so error_count==0 is not misread as "0 silicon
    # violations": an observed denial/completion that contradicts the oracle's
    # expected outcome is a real oracle/implementation-difference candidate,
    # not a structural-pass marker.
    # The board runner completes allowed fetches by executing an ecall stub,
    # which traps with cause 8/9 (U/S ecall); that is a completion signal for a
    # fetch probe, not a real trap observation.
    fetch_completion = (
        str(case.get("access") or "").strip().lower() == "fetch"
        and observed_mcause in (8, 9)
    )
    failure_class = None
    if status == "fail" and (observed_event is not None or fetch_completion):
        expected_allowed = bool(case.get("expected_allowed"))
        expected_cause = case.get("expected_cause")
        if expected_allowed:
            failure_class = (
                "expected_allow_observed_allow_mismatch"
                if observed_event == "completion" or fetch_completion
                else "expected_allow_observed_trap"
            )
        else:
            if observed_event == "completion" or fetch_completion:
                failure_class = "expected_deny_observed_allow"
            elif expected_cause is not None and observed_mcause is not None and observed_mcause != expected_cause:
                failure_class = "expected_trap_cause_mismatch"
            else:
                failure_class = "unclassified_trap_failure"
    payload = summarize_bapc_for_pmpfuzz_case(
        case,
        provisional,
        log_text=raw_uart_text,
        supports_smepmp=bool((dut_capability.get("supported_capabilities") or {}).get("smepmp")),
        bapc_core_version=U74_BAPC_CORE_VERSION,
    )
    return result_to_dict(
        case=case,
        dut=dut,
        status=status,
        elapsed_seconds=float(elapsed_seconds) if elapsed_seconds is not None else 0.25,
        returncode=0,
        log=log_path,
        reason=str(observed_entry.get("reason") or "") or None,
        observed_tohost=observed_tohost,
        observed_mcause=observed_mcause,
        observed_mtval=observed_mtval,
        observed_event=observed_event,
        observed_phase=observed_phase,
        observed_stage="normal" if observed_event else None,
        observation_valid=observed_event is not None,
        stage_verified=(observed_event == "trap"),
        failure_class=failure_class,
        oracle_applicability=case.get("oracle_applicability") or "valid",
        bapc_coverage=payload,
    )


def write_round_timeline(
    out_dir: Path,
    *,
    round_campaign_id: str,
    ordered_case_names: list[str] | None = None,
    structured_timeline_rows: list[dict[str, Any]] | None = None,
) -> None:
    metrics_dir = out_dir / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "schema_version": 1,
            "campaign_id": round_campaign_id,
            "completion_seq": 0,
            "case_id": None,
            "elapsed_wall_seconds": 0.0,
        }
    ]
    if structured_timeline_rows:
        for sequence, item in enumerate(structured_timeline_rows, start=1):
            row = {
                "schema_version": 1,
                "campaign_id": round_campaign_id,
                "completion_seq": sequence,
                "case_id": str(item.get("case_id") or ""),
                "elapsed_wall_seconds": float(item.get("elapsed_wall_seconds") or 0.0),
            }
            completion_monotonic = item.get("completion_monotonic_seconds")
            if completion_monotonic is not None:
                row["completion_monotonic_seconds"] = float(completion_monotonic)
            rows.append(row)
    else:
        for sequence, case_name in enumerate(ordered_case_names or [], start=1):
            rows.append(
                {
                    "schema_version": 1,
                    "campaign_id": round_campaign_id,
                    "completion_seq": sequence,
                    "case_id": case_name,
                    "elapsed_wall_seconds": float(sequence),
                    "completion_monotonic_seconds": 1000.0 + float(sequence),
                }
            )
    (metrics_dir / "coverage_timeline.jsonl").write_text(
        "\n".join(json.dumps(row, ensure_ascii=True, sort_keys=True) for row in rows) + "\n",
        encoding="ascii",
    )


def build_structured_uart_timeline(
    structured_uart_events: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    events = list(structured_uart_events or [])
    if not events:
        return []

    runner_begin_elapsed = 0.0
    have_runner_begin = False
    ordered_events: list[dict[str, Any]] = []
    for entry in events:
        line = str(entry.get("line") or "").strip()
        if not line:
            continue
        elapsed = entry.get("elapsed_wall_seconds")
        if elapsed is None:
            continue
        try:
            elapsed_wall = float(elapsed)
        except (TypeError, ValueError):
            continue
        runner_match = RUNNER_RE.match(line)
        if runner_match and runner_match.group("event") == "begin" and not have_runner_begin:
            runner_begin_elapsed = elapsed_wall
            have_runner_begin = True
            continue
        case_match = CASE_RE.match(line)
        if case_match:
            ordered_events.append(
                {
                    "case_id": case_match.group("case"),
                    "elapsed_wall_seconds": elapsed_wall,
                }
            )

    previous_elapsed = runner_begin_elapsed if have_runner_begin else 0.0
    for item in ordered_events:
        current_elapsed = float(item.get("elapsed_wall_seconds") or 0.0)
        item["case_elapsed_seconds"] = max(0.0, current_elapsed - previous_elapsed)
        previous_elapsed = current_elapsed
    return ordered_events


def validate_round_artifacts(
    round_dir: Path,
    *,
    schedule_entries: list[dict[str, Any]],
    validation_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validation_context = dict(validation_context or {})
    raw_path = round_dir / "raw" / "uart.txt"
    parsed = parse_uart_log(raw_path.read_text(encoding="utf-8", errors="replace")) if raw_path.exists() else {
        "cases": [],
        "runner_begin": {},
        "runner_end": {},
        "manifest": {},
        "runner_begin_count": 0,
        "runner_end_count": 0,
        "manifest_count": 0,
    }
    case_map = load_case_map(round_dir)
    results_by_case = load_results(round_dir)
    raw_expected_names = [str(entry.get("name") or "") for entry in schedule_entries]
    # Batch group markers enable firmware-side groups but do not produce their
    # own per-case records, so they are excluded from case-set reconciliation.
    expected_names = [
        name for name in raw_expected_names if name and not is_u74_group_marker(name)
    ]
    parsed_names = [str(item.get("case") or "") for item in parsed.get("cases") or []]
    case_names = sorted(case_map)
    result_names = sorted(results_by_case)
    generated_manifest_path = round_dir / "manifests" / "u74-generated-round-manifest.json"
    round_manifest_path = round_dir / "manifests" / "u74-round-manifest.json"
    board_run_manifest_path = round_dir / "manifests" / "u74-board-run-manifest.json"
    timeline_path = round_dir / "metrics" / "coverage_timeline.jsonl"
    generated_manifest = load_json(generated_manifest_path) if generated_manifest_path.exists() else {}
    round_manifest = load_json(round_manifest_path) if round_manifest_path.exists() else {}
    board_run_manifest = load_json(board_run_manifest_path) if board_run_manifest_path.exists() else {}
    campaign_metadata_path = Path(str(validation_context.get("campaign_metadata_path") or "")) if validation_context.get("campaign_metadata_path") else None
    campaign_metadata = load_json(campaign_metadata_path) if campaign_metadata_path and campaign_metadata_path.exists() else {}
    strict_identity_validation = bool(validation_context) or bool(generated_manifest)

    errors: list[str] = []
    if parsed.get("runner_begin_count") != 1:
        errors.append(f"runner_begin_count={parsed.get('runner_begin_count')}")
    if parsed.get("runner_end_count") != 1:
        errors.append(f"runner_end_count={parsed.get('runner_end_count')}")
    if parsed.get("manifest_count") != 1:
        errors.append(f"manifest_count={parsed.get('manifest_count')}")
    if sorted(expected_names) != sorted(parsed_names):
        errors.append("scheduled_vs_uart_case_set_mismatch")
    if sorted(expected_names) != case_names:
        errors.append("scheduled_vs_casejson_case_set_mismatch")
    if sorted(expected_names) != result_names:
        errors.append("scheduled_vs_resultjson_case_set_mismatch")
    if any(not name for name in raw_expected_names):
        errors.append("missing_schedule_field:name")
    if len(expected_names) != len(set(expected_names)):
        errors.append("duplicate_case_name_in_schedule")
    if any(not str(entry.get("candidate_id") or "") for entry in schedule_entries):
        errors.append("missing_schedule_field:candidate_id")
    expected_candidate_ids = [str(entry.get("candidate_id") or "") for entry in schedule_entries if entry.get("candidate_id")]
    if len(expected_candidate_ids) != len(set(expected_candidate_ids)):
        errors.append("duplicate_candidate_id_in_schedule")
    if any(not str(entry.get("scenario_hash") or "") for entry in schedule_entries):
        errors.append("missing_schedule_field:scenario_hash")
    scenario_hashes = [str(entry.get("scenario_hash") or "") for entry in schedule_entries if entry.get("scenario_hash")]
    if len(scenario_hashes) != len(set(scenario_hashes)):
        errors.append("duplicate_scenario_hash_in_schedule")

    for entry in schedule_entries:
        name = str(entry.get("name") or "")
        case = case_map.get(name)
        if case is None:
            continue
        expected_hash = str(entry.get("scenario_hash") or "")
        if expected_hash and str(case.get("scenario_hash") or "") != expected_hash:
            errors.append(f"scenario_hash_mismatch:{name}")

    runner_begin = dict(parsed.get("runner_begin") or {})
    runner_end = dict(parsed.get("runner_end") or {})
    manifest = dict(parsed.get("manifest") or {})
    scheduled_count = len(schedule_entries)
    runner_begin_case_count = int(runner_begin.get("case_count") or 0) if runner_begin.get("case_count") else 0
    manifest_count = int(manifest.get("case_count") or 0) if manifest.get("case_count") else 0
    if not str(runner_begin.get("case_count") or ""):
        errors.append("missing_runner_begin_case_count")
    elif runner_begin_case_count != scheduled_count:
        errors.append("runner_begin_case_count_mismatch")
    if not str(manifest.get("case_count") or ""):
        errors.append("missing_manifest_case_count")
    elif manifest_count != scheduled_count:
        errors.append("manifest_case_count_mismatch")

    campaign_id = str(runner_begin.get("campaign_id") or manifest.get("campaign_id") or "")
    round_id = str(runner_begin.get("round_id") or manifest.get("round_id") or "")

    expected_campaign_id = str(
        validation_context.get("campaign_id")
        or campaign_metadata.get("campaign_id")
        or campaign_id
        or ""
    )
    expected_round_id = str(validation_context.get("round_id") or round_id or "")
    campaign_identity = dict(campaign_metadata.get("u74_round_identity") or {})
    expected_capability_fingerprint = str(
        validation_context.get("capability_fingerprint")
        or campaign_identity.get("capability_fingerprint")
        or campaign_metadata.get("capability_fingerprint")
        or generated_manifest.get("capability_fingerprint")
        or ""
    )
    expected_universe_sha256 = str(
        validation_context.get("supported_bapc_universe_sha256")
        or campaign_identity.get("supported_bapc_universe_embedded_sha256")
        or (campaign_metadata.get("coverage_universe_hashes") or {}).get("bapc")
        or generated_manifest.get("supported_bapc_universe_sha256")
        or ""
    )
    expected_universe_file_sha256 = str(
        validation_context.get("supported_bapc_universe_file_sha256")
        or campaign_identity.get("supported_bapc_universe_file_sha256")
        or generated_manifest.get("supported_bapc_universe_file_sha256")
        or ""
    )
    requested_validator_profile = str(
        validation_context.get("validator_profile")
        or campaign_identity.get("validator_profile")
        or generated_manifest.get("validator_profile")
        or ENGINEERING_SMOKE_VALIDATOR_PROFILE
    )
    if requested_validator_profile not in U74_VALIDATOR_PROFILES:
        errors.append(f"unknown_validator_profile:{requested_validator_profile}")
    expected_observation_profile_id = str(
        validation_context.get("observation_profile_id")
        or generated_manifest.get("observation_profile_id")
        or ""
    )
    round_index = _round_index(expected_round_id or round_id)

    if strict_identity_validation:
        for field_name, field_value in (
            ("capability_fingerprint", expected_capability_fingerprint),
            ("supported_bapc_universe_sha256", expected_universe_sha256),
            ("supported_bapc_universe_file_sha256", expected_universe_file_sha256),
            ("observation_profile_id", expected_observation_profile_id),
            ("validator_profile", requested_validator_profile),
            ("campaign_id", expected_campaign_id),
            ("round_id", expected_round_id),
        ):
            if not str(field_value or ""):
                errors.append(f"missing_expected_identity_field:{field_name}")
        identity_payloads = {
            "generated_manifest": generated_manifest,
            "round_manifest": round_manifest,
            "board_run_manifest": board_run_manifest,
        }
        if not generated_manifest:
            errors.append("missing_generated_round_manifest")
        if not round_manifest:
            errors.append("missing_round_manifest")
        if not board_run_manifest:
            errors.append("missing_board_run_manifest")
        for source_name, payload in identity_payloads.items():
            if not payload:
                continue
            if expected_campaign_id and str(payload.get("campaign_id") or "") != expected_campaign_id:
                errors.append(f"{source_name}_campaign_id_mismatch")
            if expected_round_id and str(payload.get("round_id") or "") != expected_round_id:
                errors.append(f"{source_name}_round_id_mismatch")
            if expected_capability_fingerprint and str(payload.get("capability_fingerprint") or "") != expected_capability_fingerprint:
                errors.append(f"{source_name}_capability_fingerprint_mismatch")
            if expected_universe_sha256 and str(payload.get("supported_bapc_universe_sha256") or "") != expected_universe_sha256:
                errors.append(f"{source_name}_supported_bapc_universe_sha256_mismatch")
            if expected_universe_file_sha256 and str(payload.get("supported_bapc_universe_file_sha256") or "") != expected_universe_file_sha256:
                errors.append(f"{source_name}_supported_bapc_universe_file_sha256_mismatch")
            if expected_observation_profile_id and str(payload.get("observation_profile_id") or "") != expected_observation_profile_id:
                errors.append(f"{source_name}_observation_profile_id_mismatch")
            if requested_validator_profile and str(payload.get("validator_profile") or "") != requested_validator_profile:
                errors.append(f"{source_name}_validator_profile_mismatch")
        if campaign_metadata:
            if expected_campaign_id and str(campaign_metadata.get("campaign_id") or "") != expected_campaign_id:
                errors.append("campaign_metadata_campaign_id_mismatch")
            if expected_capability_fingerprint and str(campaign_metadata.get("capability_fingerprint") or "") != expected_capability_fingerprint:
                errors.append("campaign_metadata_capability_fingerprint_mismatch")
            if expected_universe_sha256 and str(
                campaign_identity.get("supported_bapc_universe_embedded_sha256")
                or (campaign_metadata.get("coverage_universe_hashes") or {}).get("bapc")
                or ""
            ) != expected_universe_sha256:
                errors.append("campaign_metadata_supported_bapc_universe_sha256_mismatch")
            if expected_universe_file_sha256 and str(campaign_identity.get("supported_bapc_universe_file_sha256") or "") != expected_universe_file_sha256:
                errors.append("campaign_metadata_supported_bapc_universe_file_sha256_mismatch")
            if requested_validator_profile and str(campaign_identity.get("validator_profile") or "") != requested_validator_profile:
                errors.append("campaign_metadata_validator_profile_mismatch")
        for source_name, payload in (
            ("runner_begin", runner_begin),
            ("manifest", manifest),
            ("runner_end", runner_end),
        ):
            if not str(payload.get("campaign_id") or ""):
                errors.append(f"missing_{source_name}_campaign_id")
            elif expected_campaign_id and str(payload.get("campaign_id") or "") != expected_campaign_id:
                errors.append(f"{source_name}_campaign_id_mismatch")
            if not str(payload.get("round_id") or ""):
                errors.append(f"missing_{source_name}_round_id")
            elif expected_round_id and str(payload.get("round_id") or "") != expected_round_id:
                errors.append(f"{source_name}_round_id_mismatch")
        generated_manifest_sha256 = str(generated_manifest.get("manifest_sha256") or "")
        if not generated_manifest_sha256:
            errors.append("missing_generated_manifest_manifest_sha256")
        else:
            if _recompute_generated_manifest_sha256(generated_manifest) != generated_manifest_sha256:
                errors.append("generated_manifest_sha256_recomputed_mismatch")
        uart_manifest_sha256 = str(manifest.get("manifest_sha256") or "")
        if not uart_manifest_sha256:
            errors.append("missing_uart_manifest_sha256")
        elif generated_manifest_sha256 and uart_manifest_sha256 != generated_manifest_sha256:
            errors.append("uart_manifest_sha256_mismatch")
        runner_begin_manifest_sha256 = str(runner_begin.get("manifest_sha256") or "")
        if not runner_begin_manifest_sha256:
            errors.append("missing_runner_begin_manifest_sha256")
        elif generated_manifest_sha256 and runner_begin_manifest_sha256 != generated_manifest_sha256:
            errors.append("runner_begin_manifest_sha256_mismatch")
        if round_manifest:
            round_manifest_sha256 = str(round_manifest.get("generated_manifest_sha256") or "")
            if not round_manifest_sha256:
                errors.append("missing_round_manifest_generated_manifest_sha256")
            elif generated_manifest_sha256 and round_manifest_sha256 != generated_manifest_sha256:
                errors.append("round_manifest_generated_manifest_sha256_mismatch")
        if board_run_manifest:
            board_run_manifest_sha256 = str(board_run_manifest.get("generated_manifest_sha256") or "")
            if not board_run_manifest_sha256:
                errors.append("missing_board_run_manifest_generated_manifest_sha256")
            elif generated_manifest_sha256 and board_run_manifest_sha256 != generated_manifest_sha256:
                errors.append("board_run_manifest_generated_manifest_sha256_mismatch")
        board_patch = dict(round_manifest.get("board_patch") or {})
        for key in ("board_patch_sha256", "runner_sha256", "probe_sha256", "fit_sha256"):
            if not str(board_patch.get(key) or board_run_manifest.get(key) or ""):
                errors.append(f"missing_{key}")
    timeline_rows: list[dict[str, Any]] = []
    if not timeline_path.exists():
        errors.append("missing_round_timeline")
    else:
        for line in timeline_path.read_text(encoding="ascii").splitlines():
            if line.strip():
                timeline_rows.append(json.loads(line))
        if not timeline_rows:
            errors.append("empty_round_timeline")
        else:
            previous_elapsed = None
            case_sequences = []
            for row in timeline_rows:
                elapsed = float(row.get("elapsed_wall_seconds") or 0.0)
                if previous_elapsed is not None and elapsed < previous_elapsed:
                    errors.append("timeline_elapsed_wall_seconds_regressed")
                    break
                previous_elapsed = elapsed
                completion_seq = int(row.get("completion_seq") or 0)
                if completion_seq > 0:
                    case_sequences.append(completion_seq)
            if float(timeline_rows[0].get("elapsed_wall_seconds") or 0.0) != 0.0:
                errors.append("timeline_does_not_start_at_zero")
            if case_sequences != list(range(1, len(case_sequences) + 1)):
                errors.append("timeline_completion_seq_not_continuous")

    qualified = 0
    covered_bins: set[str] = set()
    applicable = 0
    unsupported = 0
    inconclusive = 0
    infrastructure_failure = 0
    for name in expected_names:
        result_list = results_by_case.get(name) or []
        if len(result_list) != 1:
            continue
        result = result_list[0]
        case = case_map.get(name) or {}
        oracle = str(result.get("oracle_applicability") or "")
        if oracle == "valid":
            applicable += 1
        elif oracle in {"unsupported", "infra_unadapted"}:
            unsupported += 1
        if str(result.get("status") or "") == "inconclusive":
            inconclusive += 1
        if str(result.get("status") or "") == "infra_failure":
            infrastructure_failure += 1
        qualification = qualify_result_for_coverage(case, result)
        if qualification.eligible:
            qualified += 1
            covered_bins.update(str(item) for item in ((result.get("bapc_coverage") or {}).get("observed_bins") or []))

    engineering_result = {
        "profile": ENGINEERING_SMOKE_VALIDATOR_PROFILE,
        "passed": len(errors) == 0,
        "error_count": len(errors),
        "errors": list(errors),
    }
    formal_errors = list(errors)
    if len(schedule_entries) != 64:
        formal_errors.append("formal_expected_round_size_64")
    if round_index > 0:
        previous_round_dirs = {
            path.resolve(): path
            for pattern in ("round_*", "round-*")
            for path in round_dir.parent.glob(pattern)
            if path.is_dir() and _round_index(path.name) < round_index
        }
        feedback_state = build_u74_campaign_feedback_state(
            sorted(previous_round_dirs.values(), key=lambda path: _round_index(path.name)),
            dut="u74",
        )
        previous_hash = str(feedback_state.get("coverage_hash") or "")
        case_records = dict(feedback_state.get("case_records") or {})
        if not case_records:
            formal_errors.append("formal_missing_feedback_corpus")
        for key in ("previous_coverage_hash", "parent_case_id", "parent_new_bins", "selection_energy", "mutation_id"):
            if any(not _formal_schedule_field_present(entry, key) for entry in schedule_entries):
                formal_errors.append(f"formal_missing_schedule_field:{key}")
        previous_hashes = {
            str(entry.get("previous_coverage_hash") or "")
            for entry in schedule_entries
            if str(entry.get("previous_coverage_hash") or "")
        }
        if previous_hashes and len(previous_hashes) != 1:
            formal_errors.append("formal_inconsistent_previous_coverage_hash")
        elif previous_hashes and previous_hash not in previous_hashes:
            formal_errors.append("formal_previous_coverage_hash_mismatch")
        for entry in schedule_entries:
            case_name = str(entry.get("name") or "")
            parent_case_id = str(entry.get("parent_case_id") or "")
            parent_record = dict(case_records.get(parent_case_id) or {})
            if parent_case_id and not parent_record:
                formal_errors.append(f"formal_parent_case_id_unknown:{case_name}")
            parent_new_bins = entry.get("parent_new_bins")
            if parent_record and (
                type(parent_new_bins) is not int
                or int(parent_new_bins) != int(parent_record.get("new_bin_count") or 0)
            ):
                formal_errors.append(f"formal_parent_new_bins_mismatch:{case_name}")
            if not _is_positive_real_number(entry.get("selection_energy")):
                formal_errors.append(f"formal_invalid_selection_energy:{case_name}")
    for key in (
        "generation_elapsed_seconds",
        "build_elapsed_seconds",
        "install_elapsed_seconds",
        "serial_elapsed_seconds",
        "runner_elapsed_seconds",
        "parse_elapsed_seconds",
        "validation_elapsed_seconds",
    ):
        if not str(board_run_manifest.get(key) or ""):
            formal_errors.append(f"formal_missing_time_field:{key}")
    formal_result = {
        "profile": FORMAL_U74_BATCHED_VALIDATOR_PROFILE,
        "passed": len(formal_errors) == 0,
        "error_count": len(formal_errors),
        "errors": formal_errors,
    }
    profile_results = {
        ENGINEERING_SMOKE_VALIDATOR_PROFILE: engineering_result,
        FORMAL_U74_BATCHED_VALIDATOR_PROFILE: formal_result,
    }
    requested_result = profile_results.get(requested_validator_profile)
    if requested_result is None:
        requested_result = {
            "profile": requested_validator_profile,
            "passed": False,
            "error_count": len(errors),
            "errors": list(errors),
        }

    return {
        "schema_version": 1,
        "campaign_id": expected_campaign_id or campaign_id,
        "round_id": expected_round_id or round_id,
        "scheduled_case_count": scheduled_count,
        "executed_case_count": len(parsed_names),
        "observation_qualified_case_count": qualified,
        "coverage_eligible_case_count": qualified,
        "runner_begin_count": int(parsed.get("runner_begin_count") or 0),
        "runner_end_count": int(parsed.get("runner_end_count") or 0),
        "manifest_case_count": manifest_count,
        "applicable_count": applicable,
        "unsupported_count": unsupported,
        "inconclusive_count": inconclusive,
        "infrastructure_failure_count": infrastructure_failure,
        "unique_target_specific_bins": len(covered_bins),
        "new_bins_in_round": len(covered_bins),
        "validator_profile": requested_validator_profile,
        "profile_results": profile_results,
        "capability_fingerprint": expected_capability_fingerprint,
        "supported_bapc_universe_sha256": expected_universe_sha256,
        "supported_bapc_universe_file_sha256": expected_universe_file_sha256,
        "error_count": requested_result["error_count"],
        "errors": requested_result["errors"],
        "case_result_manifest_reconciled": requested_result["error_count"] == 0,
    }


def synthesize_fake_uart_log(
    *,
    schedule_entries: list[dict[str, Any]],
    catalog_by_case: dict[str, dict[str, Any]],
    campaign_id: str,
    round_id: str,
    manifest_sha256: str,
) -> str:
    lines = [
        "[pmpfuzz] runner begin "
        f"phase=late-after-pmp backend=board-opensbi-serial layout=visionfive2-u74 "
        f"campaign_id={campaign_id} round_id={round_id} case_count={len(schedule_entries)} manifest_sha256={manifest_sha256}",
        "[pmpfuzz] manifest "
        f"campaign_id={campaign_id} round_id={round_id} case_count={len(schedule_entries)} manifest_sha256={manifest_sha256}",
    ]
    pass_count = 0
    fail_count = 0
    skip_count = 0
    for scheduled in schedule_entries:
        case_name = str(scheduled.get("name") or "")
        if is_u74_group_marker(case_name):
            # Batch group markers enable firmware-side groups; their expanded
            # sub-case records are scheduled individually and emitted below.
            continue
        entry = dict(catalog_by_case.get(case_name) or {})
        if not entry:
            lines.append(f"[pmpfuzz] case={case_name} profile=u74-legacy status=skip reason=missing_catalog")
            skip_count += 1
            continue
        status = str(entry.get("status") or "pass")
        if status == "pass":
            pass_count += 1
        elif status == "skip":
            skip_count += 1
        else:
            fail_count += 1
        parts = [f"case={case_name}"]
        for key, value in entry.items():
            if key == "case" or value in {None, ""}:
                continue
            parts.append(f"{key}={value}")
        lines.append("[pmpfuzz] " + " ".join(parts))
    lines.append(
        "[pmpfuzz] runner end "
        f"phase=late-after-pmp campaign_id={campaign_id} round_id={round_id} "
        f"pass={pass_count} fail={fail_count} skip={skip_count} status={'pass' if fail_count == 0 else 'fail'}"
    )
    return "\n".join(lines) + "\n"


def synthesize_fake_structured_uart_events(raw_uart_text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    elapsed_wall_seconds = 0.0
    for index, line in enumerate(raw_uart_text.splitlines()):
        if not line.strip():
            continue
        if index == 0:
            elapsed_wall_seconds = 0.0
        elif index == 1:
            elapsed_wall_seconds = 0.1
        else:
            elapsed_wall_seconds = float(index)
        events.append(
            {
                "line": line,
                "elapsed_wall_seconds": elapsed_wall_seconds,
            }
        )
    return events


def write_round_materialization(
    out_dir: Path,
    *,
    dut: str,
    round_campaign_id: str,
    schedule_entries: list[dict[str, Any]],
    catalog_by_case: dict[str, dict[str, Any]],
    raw_uart_text: str,
    board_patch_manifest: dict[str, Any],
    dut_capability: dict[str, Any],
    structured_uart_events: list[dict[str, Any]] | None = None,
    generated_round_manifest: dict[str, Any] | None = None,
    board_run_manifest: dict[str, Any] | None = None,
    validation_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    cases_dir = out_dir / "cases"
    results_dir = out_dir / "results"
    validator_dir = out_dir / "validator"
    manifests_dir = out_dir / "manifests"
    cases_dir.mkdir(exist_ok=True)
    results_dir.mkdir(exist_ok=True)
    validator_dir.mkdir(exist_ok=True)
    manifests_dir.mkdir(exist_ok=True)

    raw_path = raw_dir / "uart.txt"
    raw_path.write_text(raw_uart_text, encoding="utf-8")
    parsed = parse_uart_log(raw_uart_text)
    generated_round_manifest = dict(generated_round_manifest or {})
    validation_context = dict(validation_context or {})
    structured_timeline_rows = build_structured_uart_timeline(structured_uart_events)
    timing_by_case = {
        str(item.get("case_id") or ""): dict(item)
        for item in structured_timeline_rows
        if item.get("case_id")
    }
    if structured_uart_events:
        structured_events_path = raw_dir / "pmpfuzz-structured-events.jsonl"
        structured_events_path.write_text(
            "\n".join(json.dumps(item, ensure_ascii=True, sort_keys=True) for item in structured_uart_events) + "\n",
            encoding="ascii",
        )

    for scheduled in schedule_entries:
        case_name = str(scheduled.get("name") or "")
        if is_u74_group_marker(case_name):
            # Batch group markers enable firmware-side groups; they expand to
            # per-sub-case records at execution time and produce no case/result
            # artifacts themselves.
            continue
        catalog_entry = dict(catalog_by_case.get(case_name) or {})
        scenario_native = _is_scenario_native_schedule_entry(scheduled)
        case = (
            scenario_schedule_to_case_dict(scheduled)
            if scenario_native
            else legacy_case_to_case_dict(scheduled, catalog_entry)
        )
        case_dir = cases_dir / case_name
        result_dir = results_dir / case_name
        case_dir.mkdir(parents=True, exist_ok=True)
        result_dir.mkdir(parents=True, exist_ok=True)
        write_json(case_dir / "case.json", case)
        observed = next((item for item in (parsed.get("cases") or []) if item.get("case") == case_name), catalog_entry)
        if scenario_native and not observed:
            observed = {"case": case_name, "status": "inconclusive", "result": "", "reason": "missing_uart_case"}
        result = (
            scenario_case_result_dict(
                case=case,
                observed_entry=observed,
                dut=dut,
                log_path=result_dir / f"{case_name}.log",
                raw_uart_text=raw_uart_text,
                dut_capability=dut_capability,
                elapsed_seconds=timing_by_case.get(case_name, {}).get("case_elapsed_seconds"),
            )
            if scenario_native
            else legacy_case_result_dict(
                case=case,
                observed_entry=observed,
                dut=dut,
                log_path=result_dir / f"{case_name}.log",
                elapsed_seconds=timing_by_case.get(case_name, {}).get("case_elapsed_seconds"),
            )
        )
        write_json(result_dir / "result.json", result)
        (result_dir / f"{case_name}.log").write_text(raw_uart_text, encoding="utf-8")

    write_round_timeline(
        out_dir,
        round_campaign_id=round_campaign_id,
        ordered_case_names=[str(item.get("case") or "") for item in (parsed.get("cases") or [])],
        structured_timeline_rows=structured_timeline_rows,
    )
    write_json(
        out_dir / "run.json",
        {
            "profile": "u74-legacy-board-catalog",
            "dut": dut,
            "seed": int(schedule_entries[0].get("seed") or 0) if schedule_entries else 0,
            "count_requested": len(schedule_entries),
            "jobs": 1,
            "schedule": "",
            "runner": "run_u74_board_round.py",
        },
    )
    write_json(
        out_dir / "dut_capabilities.json",
        {
            "schema_version": dut_capability.get("schema_version"),
            "duts": {dut: dut_capability},
        },
    )
    write_json(
        manifests_dir / "u74-round-manifest.json",
        {
            "schema_version": 1,
            "campaign_id": generated_round_manifest.get("campaign_id") or parsed.get("runner_begin", {}).get("campaign_id") or "",
            "round_id": generated_round_manifest.get("round_id") or parsed.get("runner_begin", {}).get("round_id") or "",
            "case_count": len(schedule_entries),
            "selected_cases": [str(item.get("name") or "") for item in schedule_entries],
            "generated_manifest_sha256": generated_round_manifest.get("manifest_sha256") or "",
            "capability_fingerprint": generated_round_manifest.get("capability_fingerprint") or "",
            "observation_profile_id": generated_round_manifest.get("observation_profile_id") or "",
            "supported_bapc_universe": generated_round_manifest.get("supported_bapc_universe") or "",
            "supported_bapc_universe_sha256": generated_round_manifest.get("supported_bapc_universe_sha256") or "",
            "supported_bapc_universe_file_sha256": generated_round_manifest.get("supported_bapc_universe_file_sha256") or "",
            "validator_profile": generated_round_manifest.get("validator_profile") or "",
            "board_patch": dict(board_patch_manifest or {}),
        },
    )
    board_run_manifest = dict(
        board_run_manifest
        or default_u74_board_run_manifest(
            board_patch_manifest=board_patch_manifest,
            generated_round_manifest=generated_round_manifest,
        )
    )
    write_json(manifests_dir / "u74-board-run-manifest.json", board_run_manifest)
    if generated_round_manifest:
        validation_context.setdefault("campaign_id", str(generated_round_manifest.get("campaign_id") or ""))
        validation_context.setdefault("round_id", str(generated_round_manifest.get("round_id") or ""))
        validation_context.setdefault("validator_profile", str(generated_round_manifest.get("validator_profile") or ""))
        validation_context.setdefault("capability_fingerprint", str(generated_round_manifest.get("capability_fingerprint") or ""))
        validation_context.setdefault("supported_bapc_universe_sha256", str(generated_round_manifest.get("supported_bapc_universe_sha256") or ""))
        validation_context.setdefault("supported_bapc_universe_file_sha256", str(generated_round_manifest.get("supported_bapc_universe_file_sha256") or ""))
        validation_context.setdefault("observation_profile_id", str(generated_round_manifest.get("observation_profile_id") or ""))
    report = validate_round_artifacts(out_dir, schedule_entries=schedule_entries, validation_context=validation_context)
    write_json(validator_dir / "report.json", report)
    return report


def default_u74_board_run_manifest(
    *,
    board_patch_manifest: dict[str, Any],
    generated_round_manifest: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": "synthetic",
        "controller_git_sha": board_patch_manifest.get("controller_git_sha"),
        "controller_patch_sha256": board_patch_manifest.get("controller_patch_sha256"),
        "opensbi_base_sha": board_patch_manifest.get("opensbi_base_sha"),
        "board_patch_sha256": board_patch_manifest.get("board_patch_sha256"),
        "runner_sha256": board_patch_manifest.get("runner_sha256"),
        "probe_sha256": board_patch_manifest.get("probe_sha256"),
        "fit_sha256": board_patch_manifest.get("fit_sha256"),
        "campaign_id": generated_round_manifest.get("campaign_id"),
        "round_id": generated_round_manifest.get("round_id"),
        "generated_manifest_sha256": generated_round_manifest.get("manifest_sha256"),
        "capability_fingerprint": generated_round_manifest.get("capability_fingerprint"),
        "supported_bapc_universe_sha256": generated_round_manifest.get("supported_bapc_universe_sha256"),
        "supported_bapc_universe_file_sha256": generated_round_manifest.get("supported_bapc_universe_file_sha256"),
        "validator_profile": generated_round_manifest.get("validator_profile"),
        "observation_profile_id": generated_round_manifest.get("observation_profile_id"),
        "timing_source": "synthetic_structured_events",
    }


def _required_capabilities_from_case(translation: str, effective_privilege: str) -> list[str]:
    required = ["pmp"]
    if str(translation) == "sv39":
        required.append("sv39")
    if str(effective_privilege) == "s":
        required.append("s_mode")
    if str(effective_privilege) == "u":
        required.extend(["s_mode", "u_mode"])
    return sorted(set(required))


def legacy_case_bapc_coverage(entry: dict[str, Any]) -> dict[str, Any]:
    access = _normalize_access(entry.get("op"))
    effective_privilege = _effective_privilege_from_entry(entry)
    privilege = _architectural_privilege_from_entry(entry, effective_privilege)
    translation = _translation_from_entry(entry)
    allow_or_deny = _allow_or_deny_from_entry(entry)
    mcause_class = _mcause_class_from_entry(entry, allow_or_deny=allow_or_deny)
    if None in {access, effective_privilege, privilege, translation, allow_or_deny, mcause_class}:
        return {
            "eligible": False,
            "qualification_reason": "missing_observable_context",
            "observed_bins": [],
        }
    observed_bins = sorted(
        {
            "family=stimulus"
            f"|privilege={privilege}"
            f"|effective_privilege={effective_privilege}"
            f"|access={access}"
            f"|translation={translation}",
            f"family=decision|access={access}|allow_or_deny={allow_or_deny}|mcause_class={mcause_class}",
            "family=privilege-decision"
            f"|effective_privilege={effective_privilege}"
            f"|access={access}"
            f"|allow_or_deny={allow_or_deny}",
        }
    )
    return {
        "eligible": True,
        "qualification_reason": "eligible",
        "observed_bins": observed_bins,
        "event_records": [
            {
                "access": access,
                "privilege": privilege,
                "effective_privilege": effective_privilege,
                "translation": translation,
                "allow_or_deny": allow_or_deny,
                "mcause_class": mcause_class,
            }
        ],
    }


def _parse_int(value: Any) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _normalize_access(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if text == "fetch":
        return "fetch"
    if text in {"load", "lr.d", "lr.w"}:
        return "load"
    if text in {"store", "sc.d", "sc.w"} or text.startswith("amo"):
        return "store"
    return None


def _translation_from_entry(entry: dict[str, Any]) -> str | None:
    satp = _parse_int(entry.get("satp"))
    if satp is None:
        return None
    return "bare" if satp == 0 else "sv39"


def _effective_privilege_from_entry(entry: dict[str, Any]) -> str | None:
    value = entry.get("mpp")
    if value is not None:
        return _PRIV_MAP.get(str(value).strip().lower())
    name = str(entry.get("case") or "").lower()
    if "-u-" in name or name.endswith("-u"):
        return "u"
    if "-s-" in name or name.endswith("-s"):
        return "s"
    return "m"


def _architectural_privilege_from_entry(entry: dict[str, Any], effective_privilege: str | None) -> str | None:
    if effective_privilege is None:
        return None
    name = str(entry.get("case") or "").lower()
    if "mprv" in name:
        return "m"
    return effective_privilege


def _allow_or_deny_from_entry(entry: dict[str, Any]) -> str | None:
    result = str(entry.get("result") or "").strip().lower()
    if result == "allow":
        return "allow"
    if result == "trap":
        return "deny"
    return None


def _mcause_class_from_entry(entry: dict[str, Any], *, allow_or_deny: str | None) -> str | None:
    if allow_or_deny == "allow":
        return "none"
    cause = _parse_int(entry.get("cause"))
    if cause is None:
        return None
    return _MCAUSE_CLASS.get(cause, "other")
