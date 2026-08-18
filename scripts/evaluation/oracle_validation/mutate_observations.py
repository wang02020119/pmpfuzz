from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

from pmpfuzz.diagnostics import ObservedEvent, ObservationKind, ObservationPhase, mepc_tag, mtval_fingerprint
from pmpfuzz.judgment import judge_observation
from pmpfuzz.schema import scenario_to_case_dict
from pmpfuzz.scenario_codec import scenario_from_spec


def extract_observation_record(result_record: Mapping[str, Any]) -> dict[str, Any]:
    kind = str(result_record.get("observed_event") or "")
    phase = str(result_record.get("observed_phase") or "")
    if kind not in {"completion", "trap"}:
        raise ValueError("result_record missing observed_event")
    if not phase:
        raise ValueError("result_record missing observed_phase")
    mcause = result_record.get("observed_mcause")
    mtval_fingerprint = result_record.get("observed_mtval_fingerprint")
    mepc_tag = result_record.get("observed_mepc_tag")
    if type(mcause) is not int or type(mtval_fingerprint) is not int or type(mepc_tag) is not int:
        raise ValueError("result_record must contain integer observation fields")
    fault_address = result_record.get("observed_fault_address")
    if isinstance(fault_address, str):
        fault_address = int(fault_address, 0)
    elif fault_address is not None and type(fault_address) is not int:
        fault_address = None
    return {
        "schema_version": 1,
        "valid": True,
        "kind": kind,
        "mcause": mcause,
        "mtval_fingerprint": mtval_fingerprint,
        "mepc_tag": mepc_tag,
        "phase": phase,
        "observed_stage": result_record.get("observed_stage"),
        "observed_ptw_level": result_record.get("observed_ptw_level"),
        "observed_fault_address": fault_address,
    }


def build_counterfactuals(
    *,
    case_record: Mapping[str, Any],
    reference_label: Mapping[str, Any],
    result_record: Mapping[str, Any],
) -> list[dict[str, Any]]:
    base = extract_observation_record(result_record)
    case_id = str(reference_label.get("case_id") or case_record.get("case_id") or "")
    mutations: list[dict[str, Any]] = []
    expected_stage = _expected_stage(case_record)
    stateful_final = _expected_stage_is_stateful(case_record)
    side_effect_class = _stateful_side_effect_class(case_record)
    stale_failure_class = _normalized_stale_failure_class(
        (case_record.get("stateful_sequence") or {}).get("stale_failure_class")
    )

    mutations.append(
        _counterfactual(
            case_id=case_id,
            mutation_id="O1",
            mutation_class="completion_trap_inversion",
            observation=_invert_kind_observation(case_record, base),
            expected=_expected_judgment_for_mutation(
                mutation_class="completion_trap_inversion",
                base_observation=base,
                case_record=case_record,
            ),
        )
    )

    mutations.append(
        _counterfactual(
            case_id=case_id,
            mutation_id="O2",
            mutation_class="wrong_mcause",
            observation={**base, "mcause": _different_small_int(int(base["mcause"]))},
            expected=_expected_judgment_for_mutation(
                mutation_class="wrong_mcause",
                base_observation=base,
                case_record=case_record,
            ),
        )
    )

    if base["kind"] != "completion":
        mutations.append(
            _counterfactual(
                case_id=case_id,
                mutation_id="O3",
                mutation_class="wrong_mtval",
                observation={**base, "mtval_fingerprint": _different_small_int(int(base["mtval_fingerprint"]))},
                expected=_expected_judgment_for_mutation(
                    mutation_class="wrong_mtval",
                    base_observation=base,
                    case_record=case_record,
                ),
            )
        )

    mutations.append(
        _counterfactual(
            case_id=case_id,
            mutation_id="O4",
            mutation_class="wrong_mepc",
            observation={**base, "mepc_tag": _different_mepc_tag(case_record, int(base["mepc_tag"]))},
            expected=_expected_judgment_for_mutation(
                mutation_class="wrong_mepc",
                base_observation=base,
                case_record=case_record,
            ),
        )
    )

    mutations.append(
        _counterfactual(
            case_id=case_id,
            mutation_id="O5",
            mutation_class="wrong_path",
            observation={**base, "phase": _different_phase(str(base["phase"]))},
            expected={"status": "fail", "failure_class": "wrong_path"},
        )
    )

    if expected_stage == "page_table_walk":
        mutations.append(
            _counterfactual(
                case_id=case_id,
                mutation_id="O6",
                mutation_class="missing_stage_evidence",
                observation={
                    **base,
                    "observed_stage": None,
                    "observed_ptw_level": None,
                    "observed_fault_address": None,
                },
                expected={"status": "inconclusive", "failure_class": "unverified_trap_stage"},
            )
        )
        mutations.append(
            _counterfactual(
                case_id=case_id,
                mutation_id="O7",
                mutation_class="wrong_ptw_stage",
                observation={**base, "observed_stage": "final_access"},
                expected={"status": "fail", "failure_class": "wrong_trap_stage"},
            )
        )
        wrong_fault = base["observed_fault_address"]
        wrong_fault = (int(wrong_fault) + 0x1000) if type(wrong_fault) is int else 0x1
        mutations.append(
            _counterfactual(
                case_id=case_id,
                mutation_id="O8",
                mutation_class="wrong_ptw_level_or_address",
                observation={
                    **base,
                    "observed_ptw_level": "L0" if str(base.get("observed_ptw_level") or "") != "L0" else "L2",
                    "observed_fault_address": wrong_fault,
                },
                expected={"status": "fail", "failure_class": "wrong_trap_stage"},
            )
        )

    if side_effect_class == "forbidden_side_effect":
        mutations.append(
            _counterfactual(
                case_id=case_id,
                mutation_id="O9",
                mutation_class="forbidden_store_side_effect",
                observation={**base, "phase": "final_sentinel_modified"},
                expected={"status": "fail", "failure_class": "forbidden_side_effect"},
            )
        )
    if side_effect_class == "missing_expected_side_effect":
        mutations.append(
            _counterfactual(
                case_id=case_id,
                mutation_id="O10",
                mutation_class="missing_required_side_effect",
                observation={**base, "phase": "final_sentinel_initial"},
                expected={"status": "fail", "failure_class": "missing_expected_side_effect"},
            )
        )

    if stateful_final and stale_failure_class is not None:
        mutations.append(
            _counterfactual(
                case_id=case_id,
                mutation_id="O11",
                mutation_class="stale_permission_signature",
                observation=_stale_permission_observation(case_record, base),
                expected={"status": "fail", "failure_class": stale_failure_class},
            )
        )

    mutations.append(
        _counterfactual(
            case_id=case_id,
            mutation_id="O12",
            mutation_class="malformed_payload",
            observation={**base, "valid": False},
            expected={"status": "fail", "failure_class": "invalid_observation"},
        )
    )
    return mutations


def run_counterfactual_judgment(
    *,
    case_record: Mapping[str, Any],
    counterfactual: Mapping[str, Any],
) -> dict[str, Any]:
    observation = counterfactual.get("observation") or {}
    if not isinstance(observation, Mapping):
        raise ValueError("counterfactual missing observation")
    if not bool(observation.get("valid", True)):
        return {"status": "fail", "failure_class": "invalid_observation", "reason": "payload marked invalid"}

    event = _event_from_record(observation)
    result = judge_observation(
        dict(case_record),
        event,
        observed_stage=_optional_str(observation.get("observed_stage")),
        observed_ptw_level=_optional_str(observation.get("observed_ptw_level")),
        observed_fault_address=_optional_int(observation.get("observed_fault_address")),
    )
    return {
        "status": result.status,
        "failure_class": result.failure_class,
        "reason": result.reason,
        "observation_valid": result.observation_valid,
        "stage_verified": result.stage_verified,
    }


def normalize_case_record(case_record: Mapping[str, Any]) -> dict[str, Any]:
    if {"expected", "access", "privilege", "translation"} <= set(case_record.keys()):
        return dict(case_record)
    scenario_spec = case_record.get("scenario_spec")
    if not isinstance(scenario_spec, Mapping):
        raise ValueError("counterfactual cases row must be an execution case or contain scenario_spec")
    scenario = scenario_from_spec(dict(scenario_spec))
    normalized = scenario_to_case_dict(
        scenario,
        seed=int(case_record.get("seed") or case_record.get("generator_seed") or 0),
        index=int(case_record.get("index") or case_record.get("scenario_index") or 0),
    )
    normalized["case_id"] = case_record["case_id"]
    return normalized


def build_canonical_result_record(
    *,
    case_record: Mapping[str, Any],
    reference_label: Mapping[str, Any],
) -> dict[str, Any]:
    case = normalize_case_record(case_record)
    expected_allowed = bool(reference_label.get("expected_allowed", (case.get("expected") or {}).get("allowed")))
    expected_stage = str(reference_label.get("expected_stage") or _expected_stage(case) or "none")
    expected_side_effect = str(reference_label.get("expected_side_effect") or "not_applicable")
    expected_cause = _int_like(
        reference_label.get("expected_trap_cause", (case.get("expected") or {}).get("trap_cause"))
    )
    kind = "completion" if expected_allowed else "trap"
    result = {
        "schema_version": 1,
        "observed_event": kind,
        "observed_mcause": _expected_ecall_cause(case) if kind == "completion" else (expected_cause or 0),
        "observed_mtval_fingerprint": mtval_fingerprint(0 if kind == "completion" else (_case_address(case) or 0)),
        "observed_mepc_tag": min(_valid_mepc_tags(case)),
        "observed_phase": _canonical_phase(
            expected_allowed=expected_allowed,
            expected_stage=expected_stage,
            expected_side_effect=expected_side_effect,
        ),
        "observed_stage": None,
        "observed_ptw_level": None,
        "observed_fault_address": None,
    }
    if expected_stage == "page_table_walk":
        expected_level, expected_fault_address = _expected_denied_ptw(case, reference_label)
        result.update(
            {
                "observed_stage": "ptw",
                "observed_ptw_level": expected_level,
                "observed_fault_address": expected_fault_address,
            }
        )
    elif expected_stage == "stateful_final":
        result.update(
            {
                "observed_stage": "final_access",
                "observed_fault_address": _case_address(case),
            }
        )
    return result


def build_counterfactuals_from_reference_cases(
    *,
    cases: Iterable[Mapping[str, Any]],
    labels: Iterable[Mapping[str, Any]],
    require_applicable: bool = True,
) -> list[dict[str, Any]]:
    label_by_case = {str(item["case_id"]): dict(item) for item in labels}
    rows: list[dict[str, Any]] = []
    for raw_case in cases:
        case_id = str(raw_case.get("case_id") or "")
        if not case_id:
            continue
        label = label_by_case.get(case_id)
        if label is None:
            raise KeyError(f"missing reference label for case_id={case_id}")
        if require_applicable and str(label.get("applicability") or "applicable") != "applicable":
            continue
        case = normalize_case_record(raw_case)
        result_record = build_canonical_result_record(case_record=case, reference_label=label)
        rows.extend(build_counterfactuals(case_record=case, reference_label=label, result_record=result_record))
    return rows


def select_counterfactual_rows(
    rows: Iterable[Mapping[str, Any]],
    *,
    target_counts: Mapping[str, int],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        failure_class = str(((row.get("expected_judgment") or {}).get("failure_class")) or "")
        grouped.setdefault(failure_class, []).append(dict(row))
    for items in grouped.values():
        items.sort(key=lambda item: (str(item.get("case_id") or ""), str(item.get("mutation_id") or "")))

    selected: list[dict[str, Any]] = []
    for failure_class, required in sorted((str(key), int(value)) for key, value in target_counts.items()):
        available = grouped.get(failure_class, [])
        if len(available) < required:
            raise ValueError(
                f"insufficient counterfactuals for {failure_class}: required {required}, available {len(available)}"
            )
        selected.extend(available[:required])
    selected.sort(key=lambda item: (str(item.get("case_id") or ""), str(item.get("mutation_id") or "")))
    return selected


def _counterfactual(
    *,
    case_id: str,
    mutation_id: str,
    mutation_class: str,
    observation: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "case_id": case_id,
        "mutation_id": mutation_id,
        "mutation_class": mutation_class,
        "observation": dict(observation),
        "expected_judgment": dict(expected),
    }


def _expected_judgment_for_mutation(
    *,
    mutation_class: str,
    base_observation: Mapping[str, Any],
    case_record: Mapping[str, Any],
) -> dict[str, Any]:
    allowed = bool(((case_record.get("expected") or {}).get("allowed")))
    kind = str(base_observation.get("kind") or "")
    if mutation_class == "completion_trap_inversion":
        return {"status": "fail", "failure_class": "unexpected_trap" if allowed else "unexpected_no_trap"}
    if mutation_class == "wrong_mcause":
        if kind == "completion":
            return {"status": "fail", "failure_class": "invalid_completion"}
        return {"status": "fail", "failure_class": "wrong_mcause"}
    if mutation_class == "wrong_mtval":
        if kind == "completion":
            return {"status": "fail", "failure_class": "invalid_completion"}
        return {"status": "fail", "failure_class": "wrong_mtval"}
    if mutation_class == "wrong_mepc":
        return {"status": "fail", "failure_class": "wrong_mepc"}
    return {"status": "fail", "failure_class": "invalid_observation"}


def _event_from_record(record: Mapping[str, Any]) -> ObservedEvent:
    return ObservedEvent(
        kind=ObservationKind.COMPLETION if str(record.get("kind")) == "completion" else ObservationKind.TRAP,
        mcause=int(record.get("mcause")),
        mtval_fingerprint=int(record.get("mtval_fingerprint")),
        mepc_tag=int(record.get("mepc_tag")),
        phase=_phase_from_name(str(record.get("phase"))),
    )


def _phase_from_name(name: str) -> ObservationPhase:
    normalized = name.strip().upper()
    return ObservationPhase[normalized]


def _different_small_int(value: int) -> int:
    return 1 if value == 0 else 0


def _different_mepc_tag(case_record: Mapping[str, Any], current_tag: int) -> int:
    for candidate in (15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0):
        if candidate != current_tag and candidate not in _valid_mepc_tags(case_record):
            return candidate
    return 15 if current_tag != 15 else 14


def _different_phase(phase_name: str) -> str:
    phase = _phase_from_name(phase_name)
    if phase != ObservationPhase.SETUP:
        return "setup"
    return "probe"


def _invert_kind_observation(case_record: Mapping[str, Any], base: Mapping[str, Any]) -> dict[str, Any]:
    kind = str(base.get("kind") or "")
    observation = dict(base)
    if kind == "completion":
        observation["kind"] = "trap"
        observation["phase"] = _coherent_trap_phase(case_record, str(base.get("phase") or ""))
        return observation
    observation["kind"] = "completion"
    observation["phase"] = _coherent_completion_phase(case_record, str(base.get("phase") or ""))
    ecall = _expected_ecall_cause(case_record)
    if ecall is not None:
        observation["mcause"] = ecall
    return observation


def _stale_permission_observation(case_record: Mapping[str, Any], base: Mapping[str, Any]) -> dict[str, Any]:
    observation = dict(base)
    observation["kind"] = "completion"
    observation["phase"] = _coherent_completion_phase(case_record, str(base.get("phase") or ""))
    ecall = _expected_ecall_cause(case_record)
    if ecall is not None:
        observation["mcause"] = ecall
    return observation


def _coherent_trap_phase(case_record: Mapping[str, Any], base_phase: str) -> str:
    if _expected_stage_is_stateful(case_record):
        return (
            base_phase
            if base_phase in {"final", "final_sentinel_initial", "final_sentinel_modified", "final_sentinel_other"}
            else "final"
        )
    return "probe"


def _coherent_completion_phase(case_record: Mapping[str, Any], base_phase: str) -> str:
    if _expected_stage_is_stateful(case_record):
        return (
            base_phase
            if base_phase in {"final", "final_sentinel_initial", "final_sentinel_modified", "final_sentinel_other"}
            else "final"
        )
    return "completed"


def _expected_stage(case_record: Mapping[str, Any]) -> str:
    return str((case_record.get("expected") or {}).get("stage") or "").strip().lower()


def _expected_stage_is_stateful(case_record: Mapping[str, Any]) -> bool:
    return _expected_stage(case_record) == "stateful_final"


def _stateful_side_effect_class(case_record: Mapping[str, Any]) -> str | None:
    if not _expected_stage_is_stateful(case_record):
        return None
    sequence = case_record.get("stateful_sequence") or {}
    expected_final = str(sequence.get("expected_final") or "")
    if expected_final == "trap_no_side_effect":
        return "forbidden_side_effect"
    if expected_final == "store_side_effect":
        return "missing_expected_side_effect"
    return None


def _expected_ecall_cause(case_record: Mapping[str, Any]) -> int | None:
    return {"U": 8, "S": 9, "M": 11}.get(case_record.get("privilege"))


def _canonical_phase(*, expected_allowed: bool, expected_stage: str, expected_side_effect: str) -> str:
    if expected_stage == "stateful_final":
        if expected_side_effect == "required_store_side_effect":
            return "final_sentinel_modified"
        if expected_side_effect == "forbidden_store_side_effect":
            return "final_sentinel_initial"
        return "final"
    return "completed" if expected_allowed else "probe"


def _valid_mepc_tags(case_record: Mapping[str, Any]) -> set[int]:
    access = case_record.get("access")
    privilege = case_record.get("privilege")
    translation = case_record.get("translation")
    address = case_record.get("address")
    if access == "fetch" and address is not None:
        value = int(address, 0) if isinstance(address, str) else int(address)
        return {mepc_tag(value)}
    if translation == "sv39":
        return {0}
    profile = str(case_record.get("profile") or "")
    if profile.startswith("legacy"):
        return {0, 1}
    if privilege == "M":
        return {0, 1}
    return {4}


def _normalized_stale_failure_class(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    lowered = value.strip().lower()
    if lowered in {"stale_pmp_permission", "stale_tlb_permission", "stale_ptw_permission", "stale_permission"}:
        return "stale_permission"
    return None


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _optional_int(value: Any) -> int | None:
    return value if type(value) is int else None


def _int_like(value: Any) -> int | None:
    if type(value) is int:
        return value
    if isinstance(value, str) and value:
        return int(value, 0)
    return None


def _case_address(case_record: Mapping[str, Any]) -> int | None:
    return _int_like(case_record.get("address"))


def _expected_denied_ptw(case_record: Mapping[str, Any], reference_label: Mapping[str, Any]) -> tuple[str | None, int | None]:
    label_level = reference_label.get("expected_ptw_level")
    label_fault_address = _int_like(reference_label.get("expected_fault_address"))
    if label_level is not None and label_fault_address is not None:
        return str(label_level), label_fault_address
    trace = case_record.get("contract_trace") or {}
    for check in trace.get("pmp_checks") or []:
        if check.get("stage") not in {"ptw", "pte_ad_update"} or bool(check.get("allowed")):
            continue
        level = check.get("ptw_level")
        return (str(level) if level else None), _int_like(check.get("physical_address"))
    return None, label_fault_address


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Section 7.6 counterfactual observations")
    parser.add_argument("--clean-root", type=Path)
    parser.add_argument("--cases-jsonl", type=Path)
    parser.add_argument("--labels-jsonl", type=Path)
    parser.add_argument("--out-jsonl", type=Path, required=True)
    args = parser.parse_args(argv)

    if bool(args.clean_root) == bool(args.cases_jsonl or args.labels_jsonl):
        raise SystemExit("choose exactly one input mode: --clean-root or --cases-jsonl/--labels-jsonl")
    rows: list[dict[str, Any]]
    if args.clean_root is not None:
        rows = []
        for case_dir in sorted(args.clean_root.glob("*")):
            if not case_dir.is_dir():
                continue
            label_path = case_dir / "reference-label.json"
            case_path = case_dir / "case.json"
            result_path = case_dir / "result.json"
            observation_path = case_dir / "observation.json"
            if not (label_path.exists() and case_path.exists() and result_path.exists()):
                continue
            if observation_path.exists():
                observation_record = json.loads(observation_path.read_text(encoding="utf-8"))
                if isinstance(observation_record, dict) and observation_record.get("available") is False:
                    continue
            reference_label = json.loads(label_path.read_text(encoding="utf-8"))
            case_record = json.loads(case_path.read_text(encoding="utf-8"))
            result_record = json.loads(result_path.read_text(encoding="utf-8"))
            rows.extend(
                build_counterfactuals(
                    case_record=case_record,
                    reference_label=reference_label,
                    result_record=result_record,
                )
            )
    else:
        if args.cases_jsonl is None or args.labels_jsonl is None:
            raise SystemExit("--cases-jsonl and --labels-jsonl are both required for canonical mode")
        cases = _load_jsonl(args.cases_jsonl)
        labels = _load_jsonl(args.labels_jsonl)
        rows = build_counterfactuals_from_reference_cases(cases=cases, labels=labels)

    args.out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with args.out_jsonl.open("w", encoding="utf-8", newline="") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n")
    print(f"counterfactuals={len(rows)} out={args.out_jsonl}")
    return 0


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError(f"expected object JSONL row in {path}")
        rows.append(payload)
    return rows


if __name__ == "__main__":
    raise SystemExit(main())
