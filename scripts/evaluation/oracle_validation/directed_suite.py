from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Mapping


SchemaObject = dict[str, Any]
CasePredicate = Callable[[Mapping[str, Any], Mapping[str, Any]], bool]


def build_directed_suite_plans(
    *,
    artifact_root: Path,
    max_controls_per_mutant: int = 8,
) -> dict[str, Any]:
    artifact_root = Path(artifact_root)
    reference_dir = artifact_root / "reference"
    manifests_dir = artifact_root / "manifests"
    cases = _load_jsonl(reference_dir / "cases.jsonl")
    labels_by_case = {
        str(item["case_id"]): item
        for item in _load_jsonl(reference_dir / "labels.jsonl")
    }
    mutants_manifest = json.loads((manifests_dir / "mutants.json").read_text(encoding="utf-8"))
    applicability_by_dut = _load_applicability(manifests_dir / "capabilities.json")

    plans: list[SchemaObject] = []
    for entry in sorted(
        mutants_manifest.get("entries") or [],
        key=lambda item: (str(item.get("dut") or ""), str(item.get("mutant_id") or "")),
    ):
        if not isinstance(entry, dict):
            raise ValueError("mutants manifest entry must be an object")
        plan = build_mutant_case_plan(
            artifact_root=artifact_root,
            mutant_entry=entry,
            cases=cases,
            labels_by_case=labels_by_case,
            applicability_by_case=applicability_by_dut.get(str(entry["dut"]), {}),
            max_controls_per_mutant=max_controls_per_mutant,
        )
        plan_path = artifact_root / "mutants" / str(entry["dut"]) / str(entry["mutant_id"]) / "activation-plan.json"
        _write_json(plan_path, plan)
        plans.append(plan)

    summary = {
        "schema_version": 1,
        "plan_count": len(plans),
        "max_controls_per_mutant": int(max_controls_per_mutant),
        "plans": plans,
    }
    _write_json(manifests_dir / "directed-suite-plan.json", summary)
    return summary


def build_mutant_case_plan(
    *,
    artifact_root: Path,
    mutant_entry: Mapping[str, Any],
    cases: list[SchemaObject],
    labels_by_case: Mapping[str, Mapping[str, Any]],
    applicability_by_case: Mapping[str, str],
    max_controls_per_mutant: int,
) -> SchemaObject:
    dut = str(mutant_entry.get("dut") or "")
    mutant_id = str(mutant_entry.get("mutant_id") or "")
    fault_family = str(mutant_entry.get("fault_family") or "")
    selection_rule, activating_predicate, control_predicate = _selection_rules_for_mutant(mutant_id)

    applicability_status = {
        str(case["case_id"]): str(applicability_by_case.get(str(case["case_id"])) or "valid")
        for case in cases
    }
    eligible_cases = [
        case
        for case in cases
        if applicability_status[str(case["case_id"])] == "valid"
    ]
    if not eligible_cases:
        eligible_cases = list(cases)

    activation_source = eligible_cases
    activation_policy = "valid_only"
    activating_case_ids = _matching_case_ids(activation_source, activating_predicate, labels_by_case)
    activating_case_ids = _filter_dut_specific_activation_cases(
        dut=dut,
        mutant_id=mutant_id,
        activating_case_ids=activating_case_ids,
        cases=activation_source,
    )
    if not activating_case_ids:
        relaxed_cases = [
            case
            for case in cases
            if applicability_status[str(case["case_id"])] not in {"unsupported", "experimental"}
        ]
        activation_source = relaxed_cases or list(cases)
        activation_policy = "nonexperimental_relaxed"
        activating_case_ids = _matching_case_ids(activation_source, activating_predicate, labels_by_case)
        activating_case_ids = _filter_dut_specific_activation_cases(
            dut=dut,
            mutant_id=mutant_id,
            activating_case_ids=activating_case_ids,
            cases=activation_source,
        )
    if not activating_case_ids:
        raise ValueError(f"{dut}/{mutant_id} has no activating cases under selection rule {selection_rule}")

    control_source = eligible_cases
    control_policy = "valid_only"
    control_candidates = _matching_case_ids(control_source, control_predicate, labels_by_case)
    if not control_candidates:
        relaxed_cases = [
            case
            for case in cases
            if applicability_status[str(case["case_id"])] not in {"unsupported", "experimental"}
        ]
        control_source = relaxed_cases or list(cases)
        control_policy = "nonexperimental_relaxed"
        control_candidates = _matching_case_ids(control_source, control_predicate, labels_by_case)
    if not control_candidates:
        raise ValueError(f"{dut}/{mutant_id} has no non-activating controls under selection rule {selection_rule}")

    control_case_ids = control_candidates[: max(1, int(max_controls_per_mutant))]
    mutant_root = artifact_root / "mutants" / dut / mutant_id
    return {
        "schema_version": 1,
        "dut": dut,
        "mutant_id": mutant_id,
        "fault_family": fault_family,
        "selection_rule": selection_rule,
        "applicability_policy": "valid_only" if applicability_by_case else "unfiltered",
        "activation_applicability_policy": activation_policy,
        "control_applicability_policy": control_policy,
        "activation_case_ids": activating_case_ids,
        "activation_case_count": len(activating_case_ids),
        "control_case_ids": control_case_ids,
        "control_case_count": len(control_case_ids),
        "control_candidate_count": len(control_candidates),
        "directed_root": _relpath(artifact_root, mutant_root / "directed"),
        "replay_root": _relpath(artifact_root, mutant_root / "replay"),
    }


def _selection_rules_for_mutant(mutant_id: str) -> tuple[str, CasePredicate, CasePredicate]:
    if mutant_id == "M01":
        return (
            "bare_pmp_load_permission_deny_vs_allow_controls",
            lambda case, label: _is_pmp_permission_case(case, label, access="load", expected_allowed=False),
            lambda case, label: _is_pmp_permission_case(case, label, access="load", expected_allowed=True),
        )
    if mutant_id == "M02":
        return (
            "bare_pmp_store_permission_deny_vs_allow_controls",
            lambda case, label: _is_pmp_permission_case(case, label, access="store", expected_allowed=False),
            lambda case, label: _is_pmp_permission_case(case, label, access="store", expected_allowed=True),
        )
    if mutant_id == "M03":
        return (
            "bare_pmp_fetch_permission_deny_vs_allow_controls",
            lambda case, label: _is_pmp_permission_case(case, label, access="fetch", expected_allowed=False),
            lambda case, label: _is_pmp_permission_case(case, label, access="fetch", expected_allowed=True),
        )
    if mutant_id == "M04":
        return (
            "first_match_overlap_vs_nonoverlap_controls",
            lambda case, label: _is_m04_first_match_priority_activation(case, label),
            lambda case, label: _is_bare_boundary_case(case) and str(case.get("pmp_match_mode") or "") != "first-match-overlap",
        )
    if mutant_id == "M05":
        return (
            "pow2_last_byte_boundary_vs_inside_controls",
            lambda case, label: _is_m05_pow2_last_byte_activation(case, label),
            lambda case, label: _is_m05_nonactivating_control(case, label),
        )
    if mutant_id == "M06":
        return (
            "unmatched_su_default_deny_vs_inside_controls",
            lambda case, label: _is_unmatched_su_default_deny(case, label),
            lambda case, label: (
                _is_bare_boundary_case(case)
                and str(case.get("privilege") or "") in {"S", "U"}
                and str(case.get("probe_offset") or "") == "inside"
                and bool(label.get("expected_allowed"))
                and str(label.get("expected_stage") or "") == "none"
            ),
        )
    if mutant_id == "M07":
        return (
            "mprv_effective_privilege_denies_vs_nomprv_controls",
            lambda case, label: (
                _is_mprv_effective_privilege_case(case, label, expected_allowed=False)
                and _case_has_coverage_tag(case, "unlocked")
            ),
            lambda case, label: _is_bare_boundary_case(case) and str(case.get("privilege") or "") == "M" and str(case.get("access_type") or "") in {"load", "store"} and not bool(case.get("mprv")),
        )
    if mutant_id == "M08":
        return (
            "ptw_fault_cases_vs_pte_permission_sv39_controls",
            lambda case, label: str(label.get("expected_stage") or "") == "page_table_walk" and str(case.get("family") or "") == "C4.ptw_and_translated_access",
            # PTW-PMP bypass can legitimately perturb sv39 cases whose expected outcome is
            # `none` or `final_access`, because those cases still depend on the PTW memory
            # access being checked under the original privilege. `pte_permission` cases keep
            # the PTW leg non-activating while still exercising translated execution.
            lambda case, label: _is_sv39_case(case) and str(label.get("expected_stage") or "") == "pte_permission",
        )
    if mutant_id == "M09":
        return (
            "final_access_fault_cases_vs_other_sv39_controls",
            lambda case, label: _is_sv39_case(case) and str(label.get("expected_stage") or "") == "final_access",
            # Final-access bypass can also perturb sv39 cases whose reference result is
            # successful completion, because those cases still depend on the translated
            # access permissions cached in the TLB refill path. PTE-permission denials
            # remain non-activating because they fault before the final translated access.
            lambda case, label: _is_sv39_case(case) and str(label.get("expected_stage") or "") == "pte_permission",
        )
    if mutant_id == "M10":
        return (
            "sum_disabled_supervisor_user_page_data_cases_vs_other_sv39_controls",
            lambda case, label: _is_sum_sensitive_supervisor_data_case(case, label),
            # SUM-handling drift can also perturb successful-completion sv39 cases that
            # still reuse the translated permission/TLB path. Restrict controls to other
            # pte-permission denials and exclude the activation shape explicitly.
            lambda case, label: _is_m10_nonactivating_control(case, label),
        )
    if mutant_id == "M11":
        return (
            "ad_update_trigger_cases_vs_other_sv39_controls",
            lambda case, label: _is_sv39_case(case) and _is_ad_fault_trigger_case(case, label),
            # A/D handling drift can also perturb successful-completion sv39 cases and any
            # path that still requires an A/D update. Keep controls on deny/fetch shapes
            # whose reference execution does not need A/D side effects.
            lambda case, label: _is_m11_nonactivating_control(case, label),
        )
    if mutant_id == "M12":
        return (
            "sv39_load_store_pte_fault_cases_vs_sv39_fetch_pte_fault_controls",
            lambda case, label: _is_m12_wrong_trap_cause_activation(case, label),
            lambda case, label: _is_m12_wrong_trap_cause_control(case, label),
        )
    if mutant_id == "M13":
        return (
            "ptw_stage_cases_vs_nonptw_stage_controls",
            lambda case, label: str(label.get("expected_stage") or "") == "page_table_walk",
            lambda case, label: str(label.get("expected_stage") or "") != "page_table_walk",
        )
    if mutant_id == "M14":
        return (
            "trap_metadata_cases_vs_allowed_controls",
            lambda case, label: not bool(label.get("expected_allowed")) and label.get("expected_fault_address") is not None,
            lambda case, label: bool(label.get("expected_allowed")),
        )
    if mutant_id == "M15":
        return (
            "stale_pmp_cases_vs_other_stateful_controls",
            lambda case, label: _stateful_stale_failure_class(case) == "STALE_PMP_PERMISSION",
            lambda case, label: _is_stateful_case(case) and _stateful_stale_failure_class(case) != "STALE_PMP_PERMISSION",
        )
    if mutant_id == "M16":
        return (
            "stale_tlb_cases_vs_other_stateful_controls",
            lambda case, label: _stateful_stale_failure_class(case) == "STALE_TLB_PERMISSION",
            lambda case, label: _is_stateful_case(case) and _stateful_stale_failure_class(case) != "STALE_TLB_PERMISSION",
        )
    if mutant_id == "M17":
        return (
            "stateful_forbidden_store_side_effect_vs_required_controls",
            lambda case, label: _is_stateful_case(case) and str(label.get("expected_side_effect") or "") == "forbidden_store_side_effect",
            lambda case, label: _is_stateful_case(case) and str(label.get("expected_side_effect") or "") == "required_store_side_effect",
        )
    if mutant_id == "M18":
        return (
            "stateful_required_store_side_effect_vs_forbidden_controls",
            lambda case, label: _is_stateful_case(case) and str(label.get("expected_side_effect") or "") == "required_store_side_effect",
            lambda case, label: _is_stateful_case(case) and str(label.get("expected_side_effect") or "") == "forbidden_store_side_effect",
        )
    raise ValueError(f"unsupported mutant id: {mutant_id}")


def _is_pmp_permission_case(case: Mapping[str, Any], label: Mapping[str, Any], *, access: str, expected_allowed: bool) -> bool:
    return (
        _is_bare_boundary_case(case)
        and str(case.get("access_type") or "") == access
        and bool(label.get("expected_allowed")) is expected_allowed
        and str(label.get("expected_stage") or "") == ("none" if expected_allowed else "pmp")
        and _is_permission_sensitive_boundary_offset(case, expected_allowed=expected_allowed)
    )


def _is_bare_boundary_case(case: Mapping[str, Any]) -> bool:
    return str(case.get("profile") or "") == "pmp-boundary" and str(case.get("translation_mode") or "") == "bare"


def _is_permission_sensitive_boundary_offset(case: Mapping[str, Any], *, expected_allowed: bool) -> bool:
    probe_offset = str(case.get("probe_offset") or "")
    if expected_allowed:
        return probe_offset in {"inside", "last_byte"}
    # `upper_bound` denials are boundary/no-match effects rather than permission-bit denials,
    # so M01/M02/M03 should not count them as activation cases.
    return probe_offset in {"inside", "last_byte"}


def _is_unmatched_su_default_deny(case: Mapping[str, Any], label: Mapping[str, Any]) -> bool:
    return (
        _is_bare_boundary_case(case)
        and str(case.get("privilege") or "") in {"S", "U"}
        and str(case.get("probe_offset") or "") == "upper_bound"
        and not bool(label.get("expected_allowed"))
        and str(label.get("expected_stage") or "") == "pmp"
    )


def _is_m04_first_match_priority_activation(case: Mapping[str, Any], label: Mapping[str, Any]) -> bool:
    return (
        _is_bare_boundary_case(case)
        and str(case.get("pmp_match_mode") or "") == "first-match-overlap"
        and not (
            str(case.get("privilege") or "") == "M"
            and str(label.get("expected_stage") or "") == "none"
        )
    )


def _cva6_m04_effective_m_noop_case(case: Mapping[str, Any] | None) -> bool:
    if not case:
        return False
    if str(case.get("effective_privilege") or "") != "M":
        return False
    entries = _scenario_spec(case).get("entries") or []
    locked_count = sum(1 for entry in entries if bool(entry.get("locked")))
    return locked_count < 2


def _is_m05_pow2_last_byte_activation(case: Mapping[str, Any], label: Mapping[str, Any]) -> bool:
    return (
        _is_bare_boundary_case(case)
        and str(case.get("pmp_match_mode") or "") in {"napot", "na4"}
        and str(case.get("probe_offset") or "") == "last_byte"
        and str(case.get("privilege") or "") in {"S", "U"}
        and bool(label.get("expected_allowed"))
        and str(label.get("expected_stage") or "") == "none"
    )


def _is_m05_nonactivating_control(case: Mapping[str, Any], label: Mapping[str, Any]) -> bool:
    return (
        _is_bare_boundary_case(case)
        and str(case.get("probe_offset") or "") == "inside"
        and not _pow2_inside_access_reaches_upper_boundary(case)
    )


def _pow2_inside_access_reaches_upper_boundary(case: Mapping[str, Any]) -> bool:
    match_mode = str(case.get("pmp_match_mode") or "")
    if match_mode not in {"na4", "napot"}:
        return False
    spec = _scenario_spec(case)
    probe = spec.get("probe")
    entries = spec.get("entries")
    if not isinstance(probe, Mapping) or not isinstance(entries, list) or not entries:
        return False
    primary = entries[0]
    if not isinstance(primary, Mapping):
        return False
    pmpaddr = primary.get("pmpaddr")
    physical_address = probe.get("physical_address")
    size = probe.get("size")
    if not isinstance(pmpaddr, int) or not isinstance(physical_address, int) or not isinstance(size, int):
        return False
    upper = _pow2_entry_upper_bound(match_mode, pmpaddr)
    return upper is not None and physical_address + size == upper


def _pow2_entry_upper_bound(match_mode: str, pmpaddr: int) -> int | None:
    if match_mode == "na4":
        return (pmpaddr << 2) + 4
    if match_mode != "napot":
        return None
    ones = _trailing_ones(pmpaddr)
    lower = (pmpaddr & ~((1 << ones) - 1)) << 2
    size = 1 << (ones + 3)
    return lower + size


def _trailing_ones(value: int) -> int:
    count = 0
    while value & 1:
        count += 1
        value >>= 1
    return count


def _is_mprv_effective_privilege_case(case: Mapping[str, Any], label: Mapping[str, Any], *, expected_allowed: bool) -> bool:
    return (
        _is_bare_boundary_case(case)
        and str(case.get("privilege") or "") == "M"
        and bool(case.get("mprv"))
        and str(case.get("access_type") or "") in {"load", "store"}
        and bool(label.get("expected_allowed")) is expected_allowed
        and str(label.get("expected_stage") or "") == ("none" if expected_allowed else "pmp")
    )


def _is_sv39_case(case: Mapping[str, Any]) -> bool:
    return str(case.get("translation_mode") or "") == "sv39"


def _case_has_coverage_tag(case: Mapping[str, Any], tag: str) -> bool:
    return tag in {str(item) for item in (case.get("coverage_tags") or [])}


def _is_sum_or_mxr_sensitive(case: Mapping[str, Any]) -> bool:
    spec = _scenario_spec(case)
    return bool(spec.get("sum_enabled")) or bool(spec.get("mxr"))


def _is_sum_sensitive_supervisor_data_case(case: Mapping[str, Any], label: Mapping[str, Any]) -> bool:
    if str(case.get("family") or "") != "C3.sv39_pte_permissions":
        return False
    if not _is_sv39_case(case):
        return False
    if str(case.get("privilege") or "") != "S":
        return False
    access = str(case.get("access_type") or "")
    if access not in {"load", "store"}:
        return False
    spec = _scenario_spec(case)
    if bool(spec.get("mprv")):
        return False
    if bool(spec.get("sum_enabled")) or bool(spec.get("mxr")):
        return False
    pte = spec.get("pte_permissions") or {}
    if not bool(pte.get("valid", True)) or not bool(pte.get("user")):
        return False
    if bool(label.get("expected_allowed")) or str(label.get("expected_stage") or "") != "pte_permission":
        return False
    if not bool(pte.get("accessed", True)):
        return False
    rwx = str(pte.get("rwx") or "")
    if access == "load":
        return "r" in rwx
    return "r" in rwx and "w" in rwx and bool(pte.get("dirty", True))


def _is_m10_nonactivating_control(case: Mapping[str, Any], label: Mapping[str, Any]) -> bool:
    return (
        _is_sv39_case(case)
        and str(label.get("expected_stage") or "") == "pte_permission"
        and not _is_sum_sensitive_supervisor_data_case(case, label)
    )


def _is_m11_nonactivating_control(case: Mapping[str, Any], label: Mapping[str, Any]) -> bool:
    return (
        _is_sv39_case(case)
        and not _requires_ad_update(case)
        and str(label.get("expected_stage") or "") != "none"
    )


def _requires_ad_update(case: Mapping[str, Any]) -> bool:
    spec = _scenario_spec(case)
    sv39 = spec.get("sv39") or {}
    pte = sv39.get("pte") or {}
    accessed = bool(pte.get("accessed", True))
    dirty = bool(pte.get("dirty", True))
    access = str(case.get("access_type") or "")
    return (not accessed) or (access == "store" and not dirty)


def _is_ad_fault_trigger_case(case: Mapping[str, Any], label: Mapping[str, Any]) -> bool:
    if not _requires_ad_update(case):
        return False
    return str(label.get("spec_clause") or "") == "Sv39 A/D-bit update and Svade fault rule"


def _is_m12_wrong_trap_cause_activation(case: Mapping[str, Any], label: Mapping[str, Any]) -> bool:
    return (
        _is_sv39_case(case)
        and str(case.get("access_type") or "") in {"load", "store"}
        and not bool(label.get("expected_allowed"))
        and str(label.get("expected_stage") or "") == "pte_permission"
    )


def _is_m12_wrong_trap_cause_control(case: Mapping[str, Any], label: Mapping[str, Any]) -> bool:
    return (
        _is_sv39_case(case)
        and str(case.get("access_type") or "") == "fetch"
        and not bool(label.get("expected_allowed"))
        and str(label.get("expected_stage") or "") == "pte_permission"
    )


def _is_stateful_case(case: Mapping[str, Any]) -> bool:
    return bool(case.get("stateful")) or bool((_scenario_spec(case).get("stateful_sequence") or {}))


def _stateful_stale_failure_class(case: Mapping[str, Any]) -> str | None:
    sequence = _scenario_spec(case).get("stateful_sequence") or {}
    value = sequence.get("stale_failure_class")
    return str(value) if isinstance(value, str) and value else None


def _scenario_spec(case: Mapping[str, Any]) -> Mapping[str, Any]:
    scenario_spec = case.get("scenario_spec")
    return scenario_spec if isinstance(scenario_spec, Mapping) else {}


def _load_applicability(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    duts = payload.get("duts") if isinstance(payload, dict) else None
    if not isinstance(duts, dict):
        return {}
    result: dict[str, dict[str, str]] = {}
    for dut, record in duts.items():
        if not isinstance(record, dict):
            continue
        applicability = record.get("applicability_by_case")
        if isinstance(applicability, dict):
            result[str(dut)] = {
                str(case_id): str(status)
                for case_id, status in applicability.items()
            }
    return result


def _matching_case_ids(
    cases: list[SchemaObject],
    predicate: CasePredicate,
    labels_by_case: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    return sorted(
        str(case["case_id"])
        for case in cases
        if predicate(case, labels_by_case[str(case["case_id"])])
    )


def _filter_dut_specific_activation_cases(
    *,
    dut: str,
    mutant_id: str,
    activating_case_ids: list[str],
    cases: list[SchemaObject],
) -> list[str]:
    if dut != "cva6-clean" or mutant_id != "M04":
        return activating_case_ids
    cases_by_id = {str(case["case_id"]): case for case in cases}
    return [
        case_id
        for case_id in activating_case_ids
        if not _cva6_m04_effective_m_noop_case(cases_by_id.get(case_id))
    ]


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError(f"expected object row in {path}")
        rows.append(payload)
    return rows


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(dict(payload), indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _relpath(root: Path, path: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")
