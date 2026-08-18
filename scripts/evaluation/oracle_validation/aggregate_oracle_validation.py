from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping

from pmpfuzz.capabilities import required_observation_capabilities_for_case
from pmpfuzz.verdict import _INFRA_FAILURE_CLASSES
from scripts.evaluation.analysis.aggregate_results import _build_timeseries_row, _compute_auc


def aggregate_oracle_validation(
    artifact_root: Path,
    *,
    core_only: bool = False,
    output_dir_name: str = "aggregate",
) -> dict[str, Any]:
    reference_dir = artifact_root / "reference"
    manifests_dir = artifact_root / "manifests"
    aggregate_dir = artifact_root / output_dir_name
    aggregate_dir.mkdir(parents=True, exist_ok=True)

    cases_path = reference_dir / "cases.jsonl"
    labels_path = reference_dir / "labels.jsonl"
    cases = _load_jsonl(cases_path)
    labels = _load_jsonl(labels_path)
    case_by_id = {str(item["case_id"]): item for item in cases}
    errors: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, Any]] = []

    case_ids = [str(item.get("case_id") or "") for item in cases]
    label_ids = [str(item.get("case_id") or "") for item in labels]
    duplicate_case_ids = sorted(_duplicates(case_ids))
    duplicate_label_ids = sorted(_duplicates(label_ids))
    label_missing = sorted(set(case_ids) - set(label_ids))
    orphan_labels = sorted(set(label_ids) - set(case_ids))

    _check(not duplicate_case_ids, "reference_case_ids_unique", checks, errors, f"duplicate case ids: {duplicate_case_ids}")
    _check(not duplicate_label_ids, "reference_label_ids_unique", checks, errors, f"duplicate label ids: {duplicate_label_ids}")
    _check(not label_missing, "reference_labels_cover_cases", checks, errors, f"missing labels for cases: {label_missing[:5]}")
    _check(not orphan_labels, "reference_labels_not_orphaned", checks, errors, f"orphan labels: {orphan_labels[:5]}")

    _check_hash_manifest(
        checks=checks,
        errors=errors,
        manifest_path=manifests_dir / "cases.sha256",
        target_path=cases_path,
        check_name="cases_sha256_matches_manifest",
    )
    _check_hash_manifest(
        checks=checks,
        errors=errors,
        manifest_path=manifests_dir / "labels.sha256",
        target_path=labels_path,
        check_name="labels_sha256_matches_manifest",
    )

    coverage_contract_path = manifests_dir / "coverage-contract.json"
    if coverage_contract_path.exists():
        coverage_contract = json.loads(coverage_contract_path.read_text(encoding="utf-8"))
        bapc_contract = coverage_contract.get("bapc_v2") if isinstance(coverage_contract, dict) else None
        bin_count = bapc_contract.get("bin_count") if isinstance(bapc_contract, dict) else None
        _check(
            bin_count in {None, 208},
            "bapc_denominator_208",
            checks,
            errors,
            f"expected BAPC bin_count 208, got {bin_count!r}",
        )
    else:
        warnings.append("coverage-contract.json not present yet")

    mutants_manifest_path = manifests_dir / "mutants.json"
    _check(
        mutants_manifest_path.exists(),
        "mutants_manifest_present",
        checks,
        errors,
        f"missing manifest: {mutants_manifest_path}",
    )
    mutants_manifest = (
        json.loads(mutants_manifest_path.read_text(encoding="utf-8"))
        if mutants_manifest_path.exists()
        else {}
    )
    capabilities_manifest = _load_json_if_exists(manifests_dir / "capabilities.json") or {}

    label_by_case = {str(item["case_id"]): item for item in labels}
    clean_rows = _aggregate_clean_rows(artifact_root, case_by_id, label_by_case, capabilities_manifest)
    counterfactual_rows = _aggregate_counterfactual_rows(artifact_root)
    _write_clean_tables(aggregate_dir, clean_rows)
    _write_clean_summary_tables(aggregate_dir, clean_rows)
    _write_counterfactual_table(aggregate_dir, counterfactual_rows)
    _write_counterfactual_summary_tables(aggregate_dir, counterfactual_rows)

    e3 = _aggregate_e3(artifact_root, mutants_manifest, core_only=core_only)
    _write_optional_table(aggregate_dir / "directed_evidence.csv", e3["directed_evidence_rows"])
    _write_optional_table(aggregate_dir / "mutation_score.csv", e3["mutation_score_rows"])
    _write_optional_table(aggregate_dir / "mutation_by_family.csv", e3["mutation_by_family_rows"])
    _write_optional_table(aggregate_dir / "time_to_detection.csv", e3["time_to_detection_rows"])
    _write_optional_table(aggregate_dir / "replay.csv", e3["replay_rows"])
    _write_optional_table(aggregate_dir / "coverage_final.csv", e3["coverage_final_rows"])
    _write_optional_table(aggregate_dir / "coverage_timeseries.csv", e3["coverage_timeseries_rows"])
    _write_optional_table(aggregate_dir / "coverage_auc.csv", e3["coverage_auc_rows"])
    _write_optional_table(aggregate_dir / "exclusions.csv", e3["exclusion_rows"])

    warnings.extend(e3["warnings"])
    _validate_e3_directed_rows(
        directed_evidence_rows=e3["directed_evidence_rows"],
        expected_mutant_count=e3["planned_mutant_count"],
        checks=checks,
        errors=errors,
    )
    for row in e3["exclusion_rows"]:
        if not str(row.get("reason") or "").strip():
            errors.append("exclusion row missing reason")
            checks.append(
                {
                    "name": "exclusion_rows_have_reason",
                    "passed": False,
                    "severity": "error",
                    "reason": f"missing reason for exclusion row: {row}",
                }
            )
            break

    report = {
        "schema_version": 1,
        "core_only": core_only,
        "output_dir_name": output_dir_name,
        "valid": not errors,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "errors": errors,
        "warnings": warnings,
        "checks": checks,
        "clean_case_rows": len(clean_rows),
        "counterfactual_rows": len(counterfactual_rows),
        "directed_evidence_rows": len(e3["directed_evidence_rows"]),
        "mutation_score_rows": len(e3["mutation_score_rows"]),
        "mutation_by_family_rows": len(e3["mutation_by_family_rows"]),
        "time_to_detection_rows": len(e3["time_to_detection_rows"]),
        "replay_rows": len(e3["replay_rows"]),
        "coverage_final_rows": len(e3["coverage_final_rows"]),
        "coverage_timeseries_rows": len(e3["coverage_timeseries_rows"]),
        "coverage_auc_rows": len(e3["coverage_auc_rows"]),
        "exclusion_rows": len(e3["exclusion_rows"]),
    }
    core_summary = _build_core_summary(
        clean_rows=clean_rows,
        counterfactual_rows=counterfactual_rows,
        mutation_score_rows=e3["mutation_score_rows"],
        mutation_by_family_rows=e3["mutation_by_family_rows"],
        exclusion_rows=e3["exclusion_rows"],
    )
    (aggregate_dir / "core_summary.json").write_text(
        json.dumps(core_summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (aggregate_dir / "validation_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate Section 7.6 oracle-validation artifacts")
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--core-only", action="store_true")
    parser.add_argument("--output-dir-name", default="aggregate")
    args = parser.parse_args(argv)

    report = aggregate_oracle_validation(
        args.artifact_root,
        core_only=bool(args.core_only),
        output_dir_name=str(args.output_dir_name),
    )
    print(
        f"valid={str(report['valid']).lower()} errors={report['error_count']} "
        f"warnings={report['warning_count']} clean_rows={report['clean_case_rows']}"
    )
    return 0 if report["valid"] else 1


def _aggregate_clean_rows(
    artifact_root: Path,
    case_by_id: Mapping[str, Mapping[str, Any]],
    label_by_case: dict[str, dict[str, Any]],
    capabilities_manifest: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    capability_payload_by_dut = _capability_payload_by_dut(capabilities_manifest)
    for result_path in sorted(artifact_root.glob("clean/**/seed-*/*/result.json")):
        case_root = result_path.parent
        case_id = case_root.name
        frozen_case = case_by_id.get(case_id)
        label = label_by_case.get(case_id)
        if label is None or frozen_case is None:
            continue
        result = json.loads(result_path.read_text(encoding="utf-8"))
        observation_path = case_root / "observation.json"
        observation = json.loads(observation_path.read_text(encoding="utf-8")) if observation_path.exists() else {}
        seed_name = case_root.parent.name
        dut_name = case_root.parent.parent.name
        observability = _a_priori_observability_record(
            frozen_case=frozen_case,
            label=label,
            dut=dut_name,
            capabilities_payload=capability_payload_by_dut.get(dut_name, {}),
        )
        actual_kind = observation.get("kind")
        expected_allowed = bool(label.get("expected_allowed"))
        expected_cause = label.get("expected_trap_cause")
        actual_mcause = observation.get("mcause")
        actual_stage = observation.get("observed_stage")
        actual_ptw_level = observation.get("observed_ptw_level")
        actual_fault_address = observation.get("observed_fault_address")
        label_applicability = str(label.get("applicability") or "applicable")
        oracle_applicability = str(result.get("oracle_applicability") or "valid")
        observation_valid = result.get("observation_valid")
        stage_verified = result.get("stage_verified")
        if isinstance(actual_fault_address, str):
            try:
                actual_fault_address = int(actual_fault_address, 0)
            except ValueError:
                actual_fault_address = None
        expected_fault_address = label.get("expected_fault_address")
        if isinstance(expected_fault_address, str):
            expected_fault_address = int(expected_fault_address, 0)

        oracle_match = False
        if actual_kind == "completion" and expected_allowed:
            oracle_match = True
        elif actual_kind == "trap" and not expected_allowed and actual_mcause == expected_cause:
            if str(label.get("expected_stage") or "") == "page_table_walk":
                oracle_match = (
                    str(actual_stage or "") in {"ptw", "page_table_walk"}
                    and str(actual_ptw_level or "") == str(label.get("expected_ptw_level") or "")
                    and actual_fault_address == expected_fault_address
                )
            else:
                oracle_match = True

        observed_complete = bool(observation_valid) and stage_verified is not False
        fully_observable = bool(observability["a_priori_observable"]) and observed_complete

        rows.append(
            {
                "schema_version": 1,
                "dut": dut_name,
                "order_seed": seed_name,
                "case_id": case_id,
                "family": label["family"],
                "label_applicability": label_applicability,
                "oracle_applicability": oracle_applicability,
                "a_priori_applicability": observability["a_priori_applicability"],
                "a_priori_observable": observability["a_priori_observable"],
                "a_priori_observable_reason": observability["a_priori_observable_reason"],
                "required_observation_capabilities": observability["required_observation_capabilities"],
                "architectural_completion_visible": observability["architectural_completion_visible"],
                "trap_cause_visible": observability["trap_cause_visible"],
                "fault_address_visible": observability["fault_address_visible"],
                "ptw_stage_visible": observability["ptw_stage_visible"],
                "side_effect_visible": observability["side_effect_visible"],
                "observation_valid": observation_valid,
                "stage_verified": stage_verified,
                "observed_complete": observed_complete,
                "fully_observable": fully_observable,
                "expected_allowed": expected_allowed,
                "expected_trap_cause": expected_cause,
                "expected_stage": label.get("expected_stage"),
                "actual_kind": actual_kind,
                "actual_mcause": actual_mcause,
                "actual_stage": actual_stage,
                "actual_ptw_level": actual_ptw_level,
                "result_status": result.get("status"),
                "result_failure_class": result.get("failure_class"),
                "judgment_correct": result.get("status") == "pass",
                "oracle_match": oracle_match,
                "clean_false_violation": result.get("status") in {"fail", "inconclusive"},
            }
        )
    return rows


def _write_clean_tables(aggregate_dir: Path, clean_rows: list[dict[str, Any]]) -> None:
    clean_path = aggregate_dir / "clean_conformance.csv"
    confusion_path = aggregate_dir / "clean_confusion_matrix.csv"
    if clean_rows:
        with clean_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(clean_rows[0].keys()))
            writer.writeheader()
            writer.writerows(clean_rows)
    else:
        clean_path.write_text("", encoding="utf-8")

    confusion = {
        ("allow", "pass"): 0,
        ("allow", "nonpass"): 0,
        ("deny", "pass"): 0,
        ("deny", "nonpass"): 0,
    }
    for row in clean_rows:
        key = (
            "allow" if row["expected_allowed"] else "deny",
            "pass" if row["result_status"] == "pass" else "nonpass",
        )
        confusion[key] += 1
    with confusion_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["expected_class", "judgment_class", "count"])
        writer.writeheader()
        for (expected_class, judgment_class), count in confusion.items():
            writer.writerow(
                {
                    "expected_class": expected_class,
                    "judgment_class": judgment_class,
                    "count": count,
                }
            )


def _write_clean_summary_tables(aggregate_dir: Path, clean_rows: list[dict[str, Any]]) -> None:
    _write_optional_table(aggregate_dir / "clean_by_dut.csv", _summarize_clean_rows(clean_rows, "dut"))
    _write_optional_table(aggregate_dir / "clean_by_family.csv", _summarize_clean_rows(clean_rows, "family"))
    mismatch_rows = [
        row
        for row in clean_rows
        if not bool(row.get("judgment_correct")) or not bool(row.get("oracle_match"))
    ]
    _write_optional_table(aggregate_dir / "clean_mismatches.csv", mismatch_rows)


def _summarize_clean_rows(clean_rows: list[dict[str, Any]], group_field: str) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in clean_rows:
        grouped[str(row.get(group_field) or "")].append(row)
    rows: list[dict[str, Any]] = []
    for group_value in sorted(grouped):
        group_rows = grouped[group_value]
        summary = _clean_summary_stats(group_rows)
        rows.append(
            {
                "schema_version": 1,
                "group_field": group_field,
                "group_value": group_value,
                **summary,
            }
        )
    return rows


def _clean_summary_stats(clean_rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(clean_rows)
    pass_rows = sum(1 for row in clean_rows if str(row.get("result_status") or "") == "pass")
    correct_rows = sum(1 for row in clean_rows if bool(row.get("judgment_correct")))
    oracle_match_rows = sum(1 for row in clean_rows if bool(row.get("oracle_match")))
    false_violation_rows = sum(1 for row in clean_rows if bool(row.get("clean_false_violation")))
    inconclusive_rows = sum(1 for row in clean_rows if str(row.get("result_status") or "") == "inconclusive")
    applicable_rows = sum(1 for row in clean_rows if str(row.get("label_applicability") or "") == "applicable")
    experimental_rows = sum(
        1
        for row in clean_rows
        if str(row.get("label_applicability") or "") == "experimental"
        or str(row.get("oracle_applicability") or "") == "experimental"
    )
    capability_limited_rows = sum(
        1 for row in clean_rows if str(row.get("oracle_applicability") or "") == "capability_dependent"
    )
    unsupported_rows = sum(1 for row in clean_rows if str(row.get("oracle_applicability") or "") == "unsupported")
    infra_unadapted_rows = sum(
        1 for row in clean_rows if str(row.get("oracle_applicability") or "") == "infra_unadapted"
    )
    a_priori_observable_rows = sum(1 for row in clean_rows if bool(row.get("a_priori_observable")))
    a_priori_observable_correct_rows = sum(
        1 for row in clean_rows if bool(row.get("a_priori_observable")) and bool(row.get("judgment_correct"))
    )
    a_priori_observable_oracle_match_rows = sum(
        1 for row in clean_rows if bool(row.get("a_priori_observable")) and bool(row.get("oracle_match"))
    )
    a_priori_observable_false_violation_rows = sum(
        1 for row in clean_rows if bool(row.get("a_priori_observable")) and bool(row.get("clean_false_violation"))
    )
    observed_complete_rows = sum(1 for row in clean_rows if bool(row.get("observed_complete")))
    fully_observable_rows = sum(1 for row in clean_rows if bool(row.get("fully_observable")))
    fully_observable_pass_rows = sum(
        1
        for row in clean_rows
        if bool(row.get("fully_observable")) and str(row.get("result_status") or "") == "pass"
    )
    fully_observable_correct_rows = sum(
        1 for row in clean_rows if bool(row.get("fully_observable")) and bool(row.get("judgment_correct"))
    )
    fully_observable_oracle_match_rows = sum(
        1 for row in clean_rows if bool(row.get("fully_observable")) and bool(row.get("oracle_match"))
    )
    fully_observable_false_violation_rows = sum(
        1 for row in clean_rows if bool(row.get("fully_observable")) and bool(row.get("clean_false_violation"))
    )
    return {
        "total_cases": total,
        "pass_cases": pass_rows,
        "nonpass_cases": total - pass_rows,
        "judgment_correct_cases": correct_rows,
        "judgment_accuracy": _safe_rate(correct_rows, total),
        "oracle_match_cases": oracle_match_rows,
        "oracle_match_rate": _safe_rate(oracle_match_rows, total),
        "false_violation_cases": false_violation_rows,
        "false_violation_rate": _safe_rate(false_violation_rows, total),
        "inconclusive_cases": inconclusive_rows,
        "inconclusive_rate": _safe_rate(inconclusive_rows, total),
        "applicable_cases": applicable_rows,
        "experimental_cases": experimental_rows,
        "capability_limited_cases": capability_limited_rows,
        "unsupported_cases": unsupported_rows,
        "infra_unadapted_cases": infra_unadapted_rows,
        "a_priori_observable_cases": a_priori_observable_rows,
        "a_priori_observable_judgment_correct_cases": a_priori_observable_correct_rows,
        "a_priori_observable_judgment_accuracy": _safe_rate(
            a_priori_observable_correct_rows,
            a_priori_observable_rows,
        ),
        "a_priori_observable_oracle_match_cases": a_priori_observable_oracle_match_rows,
        "a_priori_observable_oracle_match_rate": _safe_rate(
            a_priori_observable_oracle_match_rows,
            a_priori_observable_rows,
        ),
        "a_priori_observable_false_violation_cases": a_priori_observable_false_violation_rows,
        "a_priori_observable_false_violation_rate": _safe_rate(
            a_priori_observable_false_violation_rows,
            a_priori_observable_rows,
        ),
        "observed_complete_cases": observed_complete_rows,
        "observed_complete_rate": _safe_rate(observed_complete_rows, total),
        "fully_observable_cases": fully_observable_rows,
        "fully_observable_pass_cases": fully_observable_pass_rows,
        "fully_observable_judgment_correct_cases": fully_observable_correct_rows,
        "fully_observable_judgment_accuracy": _safe_rate(fully_observable_correct_rows, fully_observable_rows),
        "fully_observable_oracle_match_cases": fully_observable_oracle_match_rows,
        "fully_observable_oracle_match_rate": _safe_rate(fully_observable_oracle_match_rows, fully_observable_rows),
        "fully_observable_false_violation_cases": fully_observable_false_violation_rows,
        "fully_observable_false_violation_rate": _safe_rate(
            fully_observable_false_violation_rows,
            fully_observable_rows,
        ),
    }


def _aggregate_counterfactual_rows(artifact_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for counterfactual_path in sorted(artifact_root.glob("counterfactual/**/counterfactual.json")):
        judgment_path = counterfactual_path.parent / "judgment.json"
        if not judgment_path.exists():
            continue
        counterfactual = json.loads(counterfactual_path.read_text(encoding="utf-8"))
        judgment = json.loads(judgment_path.read_text(encoding="utf-8"))
        expected = counterfactual.get("expected_judgment") if isinstance(counterfactual, dict) else {}
        rows.append(
            {
                "schema_version": 1,
                "case_id": str(counterfactual.get("case_id") or ""),
                "mutation_id": str(counterfactual.get("mutation_id") or ""),
                "mutation_class": str(counterfactual.get("mutation_class") or ""),
                "expected_status": str(expected.get("status") or ""),
                "expected_failure_class": str(expected.get("failure_class") or ""),
                "actual_status": str(judgment.get("status") or ""),
                "actual_failure_class": str(judgment.get("failure_class") or ""),
                "exact_match": (
                    str(expected.get("status") or "") == str(judgment.get("status") or "")
                    and str(expected.get("failure_class") or "") == str(judgment.get("failure_class") or "")
                ),
            }
        )
    return rows


def _write_counterfactual_table(aggregate_dir: Path, counterfactual_rows: list[dict[str, Any]]) -> None:
    path = aggregate_dir / "judgment_counterfactuals.csv"
    if counterfactual_rows:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(counterfactual_rows[0].keys()))
            writer.writeheader()
            writer.writerows(counterfactual_rows)
        return
    path.write_text("", encoding="utf-8")


def _write_counterfactual_summary_tables(aggregate_dir: Path, counterfactual_rows: list[dict[str, Any]]) -> None:
    _write_optional_table(
        aggregate_dir / "counterfactual_by_failure_class.csv",
        _summarize_counterfactual_rows(counterfactual_rows),
    )
    mismatch_rows = [row for row in counterfactual_rows if not bool(row.get("exact_match"))]
    _write_optional_table(aggregate_dir / "counterfactual_mismatches.csv", mismatch_rows)


def _summarize_counterfactual_rows(counterfactual_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in counterfactual_rows:
        key = (
            str(row.get("expected_failure_class") or ""),
            str(row.get("expected_status") or ""),
        )
        grouped[key].append(row)
    rows: list[dict[str, Any]] = []
    for expected_failure_class, expected_status in sorted(grouped):
        group_rows = grouped[(expected_failure_class, expected_status)]
        total = len(group_rows)
        exact_rows = sum(1 for row in group_rows if bool(row.get("exact_match")))
        unexpected_pass_rows = sum(
            1
            for row in group_rows
            if str(row.get("actual_status") or "") == "pass" and str(row.get("expected_status") or "") != "pass"
        )
        wrong_failure_class_rows = sum(
            1
            for row in group_rows
            if str(row.get("actual_status") or "") == str(row.get("expected_status") or "")
            and str(row.get("actual_failure_class") or "") != str(row.get("expected_failure_class") or "")
        )
        rows.append(
            {
                "schema_version": 1,
                "expected_failure_class": expected_failure_class,
                "expected_status": expected_status,
                "total_counterfactuals": total,
                "exact_match_count": exact_rows,
                "exact_match_rate": _safe_rate(exact_rows, total),
                "unexpected_pass_count": unexpected_pass_rows,
                "unexpected_pass_rate": _safe_rate(unexpected_pass_rows, total),
                "wrong_failure_class_count": wrong_failure_class_rows,
            }
        )
    return rows


def _check_hash_manifest(
    *,
    checks: list[dict[str, Any]],
    errors: list[str],
    manifest_path: Path,
    target_path: Path,
    check_name: str,
) -> None:
    if not manifest_path.exists():
        checks.append({"name": check_name, "passed": False, "severity": "error", "reason": "manifest missing"})
        errors.append(f"missing manifest: {manifest_path}")
        return
    if not target_path.exists():
        checks.append({"name": check_name, "passed": False, "severity": "error", "reason": "target missing"})
        errors.append(f"missing target: {target_path}")
        return
    line = manifest_path.read_text(encoding="utf-8").strip()
    expected = line.split("  ", 1)[0] if line else ""
    actual = sha256(target_path.read_bytes()).hexdigest()
    _check(expected == actual, check_name, checks, errors, f"expected {expected}, got {actual}")


def _check(
    passed: bool,
    name: str,
    checks: list[dict[str, Any]],
    errors: list[str],
    reason: str,
) -> None:
    checks.append(
        {
            "name": name,
            "passed": bool(passed),
            "severity": "error",
            "reason": "" if passed else reason,
        }
    )
    if not passed:
        errors.append(reason)


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


def _duplicates(items: list[str]) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for item in items:
        if item in seen:
            duplicates.add(item)
        seen.add(item)
    return duplicates


def _aggregate_e3(
    artifact_root: Path,
    mutants_manifest: Mapping[str, Any],
    *,
    core_only: bool = False,
) -> dict[str, Any]:
    entries = [
        item
        for item in (mutants_manifest.get("entries") or [])
        if isinstance(item, dict)
    ]
    directed_seeds = [int(item) for item in (mutants_manifest.get("directed_order_seeds") or [])]
    online_seeds = [int(item) for item in (mutants_manifest.get("online_seeds") or [])]
    replay_count = int(mutants_manifest.get("replay_count") or 0)
    horizon_seconds = int(mutants_manifest.get("wall_clock_horizon_seconds") or 0)
    warnings: list[str] = []
    exclusion_rows: list[dict[str, Any]] = []

    mutant_rows = [
        _aggregate_mutant_entry(
            artifact_root=artifact_root,
            entry=entry,
            directed_seeds=directed_seeds,
            replay_count=replay_count,
            exclusion_rows=exclusion_rows,
        )
        for entry in entries
    ]

    mutation_score_rows = _build_mutation_score_rows(mutant_rows)
    mutation_by_family_rows = _build_mutation_by_family_rows(mutant_rows)
    replay_rows: list[dict[str, Any]] = []
    time_to_detection_rows: list[dict[str, Any]] = []
    coverage_timeseries_rows: list[dict[str, Any]] = []
    coverage_auc_rows: list[dict[str, Any]] = []
    coverage_final_rows: list[dict[str, Any]] = []
    online_warnings: list[str] = []

    if not core_only:
        replay_rows = _build_replay_rows(mutant_rows)
        online = _aggregate_online_campaigns(
            artifact_root=artifact_root,
            online_seeds=online_seeds,
            exclusion_rows=exclusion_rows,
            default_horizon_seconds=horizon_seconds,
        )
        time_to_detection_rows = [_time_to_detection_row(campaign) for campaign in online["campaigns"]]
        coverage_timeseries_rows = online["coverage_timeseries_rows"]
        coverage_auc_rows = _compute_auc(coverage_timeseries_rows, online["horizon_map"])
        coverage_final_rows = [campaign["coverage_final_row"] for campaign in online["campaigns"]]
        online_warnings = online["warnings"]

    if not entries:
        warnings.append("mutants manifest has no entries")

    return {
        "planned_mutant_count": len(entries),
        "directed_evidence_rows": _build_directed_evidence_rows(mutant_rows),
        "warnings": warnings + online_warnings,
        "mutation_score_rows": mutation_score_rows,
        "mutation_by_family_rows": mutation_by_family_rows,
        "time_to_detection_rows": time_to_detection_rows,
        "replay_rows": replay_rows,
        "coverage_final_rows": coverage_final_rows,
        "coverage_timeseries_rows": coverage_timeseries_rows,
        "coverage_auc_rows": coverage_auc_rows,
        "exclusion_rows": exclusion_rows,
    }


def _aggregate_mutant_entry(
    *,
    artifact_root: Path,
    entry: Mapping[str, Any],
    directed_seeds: list[int],
    replay_count: int,
    exclusion_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    dut = str(entry.get("dut") or "")
    mutant_id = str(entry.get("mutant_id") or "")
    fault_family = str(entry.get("fault_family") or "")
    critical_family = bool(entry.get("critical_family"))
    mutant_root = artifact_root / "mutants" / dut / mutant_id
    activation_plan_path = mutant_root / "activation-plan.json"
    activation_plan = _load_json_if_exists(activation_plan_path)
    activation_case_ids = {
        str(item) for item in (activation_plan.get("activation_case_ids") or [])
    } if isinstance(activation_plan, dict) else set()
    control_case_ids = {
        str(item) for item in (activation_plan.get("control_case_ids") or [])
    } if isinstance(activation_plan, dict) else set()
    clean_activation_precondition_met = (
        bool(activation_plan.get("clean_activation_precondition_met", True))
        if isinstance(activation_plan, dict)
        else True
    )
    activation_selection_policy = (
        str(activation_plan.get("activation_selection_policy") or "")
        if isinstance(activation_plan, dict)
        else ""
    )

    blocking_reasons: list[str] = []
    binary_sha_path = mutant_root / "binary.sha256"
    if not activation_case_ids and not control_case_ids:
        blocking_reasons.append("missing_activation_plan")
        exclusion_rows.append(
            _exclusion_row(
                scope="mutant",
                dut=dut,
                mutant_id=mutant_id,
                reason="missing_activation_plan",
                details=str(activation_plan_path),
                artifact_path=activation_plan_path,
            )
        )
    if not binary_sha_path.exists():
        blocking_reasons.append("missing_binary_sha256")
        exclusion_rows.append(
            _exclusion_row(
                scope="mutant",
                dut=dut,
                mutant_id=mutant_id,
                reason="missing_binary_sha256",
                details=str(binary_sha_path),
                artifact_path=binary_sha_path,
            )
        )

    directed_seed_rows: list[dict[str, Any]] = []
    semantic_failure_classes: set[str] = set()
    for seed in directed_seeds:
        seed_root = mutant_root / "directed" / f"seed-{seed:04d}"
        summary_path = seed_root / "summary.json"
        result_paths = sorted(seed_root.glob("*/result.json"))
        if not summary_path.exists() and not result_paths:
            blocking_reasons.append(f"missing_directed_seed_{seed:04d}")
            exclusion_rows.append(
                _exclusion_row(
                    scope="directed",
                    dut=dut,
                    mutant_id=mutant_id,
                    seed=seed,
                    reason="missing_directed_seed",
                    details=str(summary_path),
                    artifact_path=summary_path,
                )
            )
            continue
        result_by_case = {
            path.parent.name: _load_json(path)
            for path in result_paths
        }
        activation_results = [result_by_case[case_id] for case_id in sorted(activation_case_ids) if case_id in result_by_case]
        control_results = [result_by_case[case_id] for case_id in sorted(control_case_ids) if case_id in result_by_case]
        activation_semantic_failures = [item for item in activation_results if _is_differential_mutation_detection(item)]
        control_semantic_failures = [item for item in control_results if _is_differential_mutation_detection(item)]
        infra_failures = [
            item
            for item in list(activation_results) + list(control_results)
            if _is_infrastructure_failure(item)
        ]
        semantic_failure_classes.update(
            str(item.get("failure_class") or "")
            for item in activation_semantic_failures
            if str(item.get("failure_class") or "")
        )
        directed_seed_rows.append(
            {
                "seed": seed,
                "activation_case_count": len(activation_case_ids),
                "activation_result_count": len(activation_results),
                "activation_semantic_failure_count": len(activation_semantic_failures),
                "control_case_count": len(control_case_ids),
                "control_result_count": len(control_results),
                "control_semantic_failure_count": len(control_semantic_failures),
                "infra_failure_count": len(infra_failures),
                "activation_complete": len(activation_results) == len(activation_case_ids),
                "control_complete": len(control_results) == len(control_case_ids),
                "valid_for_score": (
                    len(activation_results) == len(activation_case_ids)
                    and len(control_results) == len(control_case_ids)
                    and not infra_failures
                    and not control_semantic_failures
                ),
                "seed_killed": (
                    len(activation_results) == len(activation_case_ids)
                    and len(control_results) == len(control_case_ids)
                    and not infra_failures
                    and not control_semantic_failures
                    and bool(activation_semantic_failures)
                ),
            }
        )

    replay_root = mutant_root / "replay"
    replay_summaries = [_load_json(path) for path in sorted(replay_root.glob("**/summary.json"))]
    replay_results: list[dict[str, Any]] = []
    for summary in replay_summaries:
        replay_results.extend(
            item
            for item in (summary.get("results") or [])
            if isinstance(item, dict)
        )
    if not replay_results:
        replay_results = [
            _load_json(path)
            for path in sorted(replay_root.glob("**/result.json"))
        ]

    activation_case_count = sum(int(row["activation_case_count"]) for row in directed_seed_rows)
    activation_result_count = sum(int(row["activation_result_count"]) for row in directed_seed_rows)
    activation_semantic_failure_count = sum(int(row["activation_semantic_failure_count"]) for row in directed_seed_rows)
    control_case_count = sum(int(row["control_case_count"]) for row in directed_seed_rows)
    control_result_count = sum(int(row["control_result_count"]) for row in directed_seed_rows)
    control_semantic_failure_count = sum(int(row["control_semantic_failure_count"]) for row in directed_seed_rows)
    infra_failure_count = sum(int(row["infra_failure_count"]) for row in directed_seed_rows)
    activation_complete = activation_result_count == activation_case_count and activation_case_count > 0
    control_complete = control_result_count == control_case_count and control_case_count > 0
    valid_for_score = (
        clean_activation_precondition_met
        and
        not blocking_reasons
        and bool(directed_seed_rows)
        and activation_complete
        and control_complete
        and infra_failure_count == 0
        and control_semantic_failure_count == 0
    )
    killed = valid_for_score and activation_semantic_failure_count > 0
    kill_reason = "no_activation_semantic_failure"
    scoring_status = "scored"
    if killed:
        kill_reason = "activation_semantic_failure"
    elif not clean_activation_precondition_met:
        kill_reason = "unscorable_clean_precondition"
        scoring_status = "unscorable"
    elif blocking_reasons:
        kill_reason = ";".join(blocking_reasons)
        scoring_status = "invalid"
    elif not activation_complete:
        kill_reason = "incomplete_activation"
        scoring_status = "invalid"
    elif not control_complete:
        kill_reason = "incomplete_control"
        scoring_status = "invalid"
    elif infra_failure_count:
        kill_reason = "infrastructure_failure"
        scoring_status = "invalid"
    elif control_semantic_failure_count:
        kill_reason = "control_semantic_failure"
        scoring_status = "invalid"
    return {
        "dut": dut,
        "mutant_id": mutant_id,
        "fault_family": fault_family,
        "critical_family": critical_family,
        "evidence_scope": "directed-only-confirmation",
        "planned": True,
        "expected_seed_count": len(directed_seeds),
        "observed_seed_count": len(directed_seed_rows),
        "activation_case_count": activation_case_count,
        "activation_result_count": activation_result_count,
        "activation_semantic_failure_count": activation_semantic_failure_count,
        "activation_complete": activation_complete,
        "control_case_count": control_case_count,
        "control_result_count": control_result_count,
        "control_semantic_failure_count": control_semantic_failure_count,
        "control_complete": control_complete,
        "infra_failure_count": infra_failure_count,
        "activation_selection_policy": activation_selection_policy,
        "clean_activation_precondition_met": clean_activation_precondition_met,
        "scoring_status": scoring_status,
        "valid_for_score": valid_for_score,
        "excluded": not valid_for_score,
        "exclusion_reasons": list(blocking_reasons),
        "killed": killed,
        "kill_reason": kill_reason,
        "directed_seed_rows": directed_seed_rows,
        "semantic_failure_classes": sorted(semantic_failure_classes),
        "replay_expected_count": replay_count,
        "replay_results": replay_results,
        "artifact_path": str(mutant_root),
    }


def _build_mutation_score_rows(mutant_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not mutant_rows:
        return []
    rows: list[dict[str, Any]] = []
    rows.extend(
        [
            _mutation_score_row("overall", "all", mutant_rows),
            _mutation_score_row("critical", "all", [row for row in mutant_rows if row["critical_family"]]),
        ]
    )
    for dut in sorted({row["dut"] for row in mutant_rows}):
        dut_rows = [row for row in mutant_rows if row["dut"] == dut]
        rows.append(_mutation_score_row("dut", dut, dut_rows))
    return rows


def _mutation_score_row(group_kind: str, group_value: str, mutant_rows: list[dict[str, Any]]) -> dict[str, Any]:
    planned = len(mutant_rows)
    valid_rows = [row for row in mutant_rows if row["valid_for_score"]]
    killed_rows = [row for row in valid_rows if row["killed"]]
    score = (len(killed_rows) / len(valid_rows)) if valid_rows else None
    return {
        "schema_version": 1,
        "group_kind": group_kind,
        "group_value": group_value,
        "planned_mutants": planned,
        "excluded_mutants": planned - len(valid_rows),
        "valid_mutants": len(valid_rows),
        "killed_mutants": len(killed_rows),
        "mutation_score": score,
    }


def _build_mutation_by_family_rows(mutant_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not mutant_rows:
        return []
    rows: list[dict[str, Any]] = []
    keys = sorted({(row["dut"], row["fault_family"]) for row in mutant_rows})
    for dut, fault_family in keys:
        family_rows = [row for row in mutant_rows if row["dut"] == dut and row["fault_family"] == fault_family]
        valid_rows = [row for row in family_rows if row["valid_for_score"]]
        killed_rows = [row for row in valid_rows if row["killed"]]
        rows.append(
            {
                "schema_version": 1,
                "dut": dut,
                "fault_family": fault_family,
                "critical_family": any(row["critical_family"] for row in family_rows),
                "planned_mutants": len(family_rows),
                "excluded_mutants": len(family_rows) - len(valid_rows),
                "valid_mutants": len(valid_rows),
                "killed_mutants": len(killed_rows),
                "mutation_score": (len(killed_rows) / len(valid_rows)) if valid_rows else None,
            }
        )
    return rows


def _build_directed_evidence_rows(mutant_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in mutant_rows:
        rows.append(
            {
                "schema_version": 1,
                "dut": row["dut"],
                "mutant_id": row["mutant_id"],
                "role": "critical" if row["critical_family"] else "noncritical",
                "fault_family": row["fault_family"],
                "evidence_scope": row["evidence_scope"],
                "expected_seed_count": row["expected_seed_count"],
                "observed_seed_count": row["observed_seed_count"],
                "activation_case_count": row["activation_case_count"],
                "activation_result_count": row["activation_result_count"],
                "activation_complete": row["activation_complete"],
                "activation_semantic_failure_count": row["activation_semantic_failure_count"],
                "control_case_count": row["control_case_count"],
                "control_result_count": row["control_result_count"],
                "control_complete": row["control_complete"],
                "control_semantic_failure_count": row["control_semantic_failure_count"],
                "infra_failure_count": row["infra_failure_count"],
                "activation_selection_policy": row["activation_selection_policy"],
                "clean_activation_precondition_met": row["clean_activation_precondition_met"],
                "scoring_status": row["scoring_status"],
                "valid_for_score": row["valid_for_score"],
                "killed": row["killed"],
                "kill_reason": row["kill_reason"],
                "observed_failure_classes": ";".join(row["semantic_failure_classes"]),
                "artifact_path": row["artifact_path"],
            }
        )
    return rows


def _build_replay_rows(mutant_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in mutant_rows:
        replay_results = row["replay_results"]
        semantic_fail_replays = [item for item in replay_results if _is_differential_mutation_detection(item)]
        observed = len(replay_results)
        expected = int(row["replay_expected_count"] or 0)
        rows.append(
            {
                "schema_version": 1,
                "dut": row["dut"],
                "mutant_id": row["mutant_id"],
                "fault_family": row["fault_family"],
                "critical_family": row["critical_family"],
                "expected_replays": expected,
                "observed_replays": observed,
                "semantic_fail_replays": len(semantic_fail_replays),
                "replay_complete": bool(expected) and observed >= expected,
                "replay_passed": bool(expected) and observed >= expected and len(semantic_fail_replays) >= expected,
                "replay_success_fraction": (
                    f"{len(semantic_fail_replays)}/{expected}" if expected else ""
                ),
            }
        )
    return rows


def _aggregate_online_campaigns(
    *,
    artifact_root: Path,
    online_seeds: list[int],
    exclusion_rows: list[dict[str, Any]],
    default_horizon_seconds: int,
) -> dict[str, Any]:
    campaigns: list[dict[str, Any]] = []
    warnings: list[str] = []
    coverage_timeseries_rows: list[dict[str, Any]] = []
    horizon_map: dict[str, dict[str, Any]] = {}
    seen_keys: set[tuple[str, str, int]] = set()

    for metadata_path in sorted(artifact_root.glob("mutants/*/*/campaigns/seed-*/metrics/campaign_metadata.json")):
        campaign_dir = metadata_path.parent.parent
        seed_name = campaign_dir.name
        mutant_id = metadata_path.parents[3].name
        dut = metadata_path.parents[4].name
        seed = _seed_from_name(seed_name)
        key = (dut, mutant_id, seed)
        if key in seen_keys:
            exclusion_rows.append(
                _exclusion_row(
                    scope="campaign",
                    dut=dut,
                    mutant_id=mutant_id,
                    seed=seed,
                    reason="duplicate_campaign_key",
                    details=str(metadata_path),
                    artifact_path=metadata_path,
                )
            )
            continue
        seen_keys.add(key)

        timeline_path = metadata_path.parent / "coverage_timeline.jsonl"
        if not timeline_path.exists():
            exclusion_rows.append(
                _exclusion_row(
                    scope="campaign",
                    dut=dut,
                    mutant_id=mutant_id,
                    seed=seed,
                    reason="missing_coverage_timeline",
                    details=str(timeline_path),
                    artifact_path=timeline_path,
                )
            )
            continue

        meta = _load_json(metadata_path)
        timeline_rows = _load_jsonl(timeline_path)
        last = timeline_rows[-1] if timeline_rows else {}
        campaign = {
            "experiment_id": str(meta.get("experiment_id") or "oracle-validation-e3"),
            "campaign_id": str(meta.get("campaign_id") or f"{dut}-{mutant_id}-{seed_name}"),
            "method": str(meta.get("method") or "pmpfuzz"),
            "variant": str(meta.get("variant") or "bb-guided"),
            "dut": dut,
            "mutant_id": mutant_id,
            "fault_family": str(meta.get("fault_family") or ""),
            "critical_family": bool(meta.get("critical_family")),
            "seed": int(meta.get("seed") or seed),
            "coverage_mode": str(meta.get("coverage_mode") or "semantic"),
            "timeline_rows": timeline_rows,
            "semantic_final_rate": last.get("semantic_rate"),
            "pairwise_final_rate": last.get("pairwise_rate"),
            "triples_final_rate": last.get("security_triples_rate"),
            "predicates_final_rate": last.get("predicates_rate"),
            "hpm_final_rate": last.get("hpm_rate"),
            "bapc_final_rate": last.get("bapc_rate"),
            "completed_cases": int(last.get("completed_cases") or 0),
            "eligible_cases": int(last.get("eligible_cases") or 0),
            "eligible_hpm_cases": int(last.get("eligible_hpm_cases") or 0),
            "eligible_bapc_cases": int(last.get("eligible_bapc_cases") or 0),
            "coverage_final_row": {},
            "artifact_path": str(campaign_dir),
        }
        campaign["coverage_final_row"] = _coverage_final_campaign_row(campaign)
        campaigns.append(campaign)

        horizon_map[campaign["campaign_id"]] = {
            "wall_clock_horizon_seconds": meta.get("wall_clock_horizon_seconds") or default_horizon_seconds,
            "run_class": meta.get("run_class") or "formal",
        }
        for coverage_mode in _coverage_modes_present(timeline_rows):
            for line in timeline_rows:
                timeseries_row = _build_timeseries_row(
                    campaign["experiment_id"],
                    campaign,
                    line,
                    coverage_mode=coverage_mode,
                )
                if timeseries_row is not None:
                    coverage_timeseries_rows.append(timeseries_row)

    expected_online_seed_set = set(online_seeds)
    if expected_online_seed_set:
        for campaign in campaigns:
            if campaign["seed"] not in expected_online_seed_set:
                warnings.append(
                    f"campaign {campaign['campaign_id']} uses unexpected online seed {campaign['seed']}"
                )

    return {
        "campaigns": campaigns,
        "coverage_timeseries_rows": coverage_timeseries_rows,
        "horizon_map": horizon_map,
        "warnings": warnings,
    }


def _coverage_final_campaign_row(campaign: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "experiment_id": campaign["experiment_id"],
        "campaign_id": campaign["campaign_id"],
        "method": campaign["method"],
        "variant": campaign["variant"],
        "dut": campaign["dut"],
        "seed": campaign["seed"],
        "coverage_mode": campaign["coverage_mode"],
        "semantic_rate": campaign.get("semantic_final_rate"),
        "pairwise_rate": campaign.get("pairwise_final_rate"),
        "triples_rate": campaign.get("triples_final_rate"),
        "predicates_rate": campaign.get("predicates_final_rate"),
        "hpm_rate": campaign.get("hpm_final_rate"),
        "bapc_rate": campaign.get("bapc_final_rate"),
        "completed_cases": campaign.get("completed_cases", 0),
        "eligible_cases": campaign.get("eligible_cases", 0),
        "eligible_hpm_cases": campaign.get("eligible_hpm_cases", 0),
        "eligible_bapc_cases": campaign.get("eligible_bapc_cases", 0),
    }


def _time_to_detection_row(campaign: Mapping[str, Any]) -> dict[str, Any]:
    detection = None
    rows = sorted(
        campaign.get("timeline_rows") or [],
        key=lambda item: (float(item.get("elapsed_wall_seconds") or 0.0), int(item.get("completion_seq") or 0)),
    )
    for row in rows:
        if _is_semantic_detection(row):
            detection = row
            break
    last = rows[-1] if rows else {}
    horizon = None
    if rows:
        horizon = max(float(last.get("elapsed_wall_seconds") or 0.0), 0.0)
    if detection is not None:
        return {
            "schema_version": 1,
            "experiment_id": campaign["experiment_id"],
            "campaign_id": campaign["campaign_id"],
            "dut": campaign["dut"],
            "mutant_id": campaign["mutant_id"],
            "seed": campaign["seed"],
            "method": campaign["method"],
            "variant": campaign["variant"],
            "detected": True,
            "right_censored": False,
            "first_detection_case_id": str(detection.get("case_id") or ""),
            "first_detection_completed_cases": int(detection.get("completed_cases") or 0),
            "first_detection_elapsed_wall_seconds": float(detection.get("elapsed_wall_seconds") or 0.0),
            "censor_completed_cases": "",
            "censor_elapsed_wall_seconds": "",
            "horizon_seconds": horizon,
        }
    return {
        "schema_version": 1,
        "experiment_id": campaign["experiment_id"],
        "campaign_id": campaign["campaign_id"],
        "dut": campaign["dut"],
        "mutant_id": campaign["mutant_id"],
        "seed": campaign["seed"],
        "method": campaign["method"],
        "variant": campaign["variant"],
        "detected": False,
        "right_censored": True,
        "first_detection_case_id": "",
        "first_detection_completed_cases": "",
        "first_detection_elapsed_wall_seconds": "",
        "censor_completed_cases": int(last.get("completed_cases") or 0),
        "censor_elapsed_wall_seconds": float(last.get("elapsed_wall_seconds") or 0.0),
        "horizon_seconds": horizon,
    }


def _coverage_modes_present(timeline_rows: Iterable[Mapping[str, Any]]) -> list[str]:
    modes = ["semantic", "pairwise", "security-triples", "predicates", "bapc"]
    first = next(iter(timeline_rows), None)
    if first is None:
        return []
    present: list[str] = []
    for mode in modes:
        rate_key = {
            "semantic": "semantic_rate",
            "pairwise": "pairwise_rate",
            "security-triples": "security_triples_rate",
            "predicates": "predicates_rate",
            "bapc": "bapc_rate",
        }[mode]
        target_key = {
            "semantic": "semantic_target",
            "pairwise": "pairwise_target",
            "security-triples": "security_triples_target",
            "predicates": "predicates_target",
            "bapc": "bapc_target",
        }[mode]
        if rate_key in first or target_key in first:
            present.append(mode)
    return present


def _build_core_summary(
    *,
    clean_rows: list[dict[str, Any]],
    counterfactual_rows: list[dict[str, Any]],
    mutation_score_rows: list[dict[str, Any]],
    mutation_by_family_rows: list[dict[str, Any]],
    exclusion_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    counter_total = len(counterfactual_rows)
    counter_exact = sum(1 for row in counterfactual_rows if bool(row.get("exact_match")))
    counter_unexpected_pass = sum(
        1
        for row in counterfactual_rows
        if str(row.get("actual_status") or "") == "pass" and str(row.get("expected_status") or "") != "pass"
    )

    score_by_group = {
        (str(row.get("group_kind") or ""), str(row.get("group_value") or "")): row
        for row in mutation_score_rows
    }

    return {
        "schema_version": 1,
        "e1": {
            **_clean_summary_stats(clean_rows),
            "by_dut": _summarize_clean_rows(clean_rows, "dut"),
            "by_family": _summarize_clean_rows(clean_rows, "family"),
        },
        "e2": {
            "total_counterfactuals": counter_total,
            "exact_match_count": counter_exact,
            "exact_match_rate": _safe_rate(counter_exact, counter_total),
            "unexpected_pass_count": counter_unexpected_pass,
            "unexpected_pass_rate": _safe_rate(counter_unexpected_pass, counter_total),
            "by_failure_class": _summarize_counterfactual_rows(counterfactual_rows),
        },
        "e3_directed": {
            "evidence_scope": "directed-only-confirmation",
            "overall": score_by_group.get(("overall", "all")),
            "critical": score_by_group.get(("critical", "all")),
            "by_dut": [
                row
                for row in mutation_score_rows
                if str(row.get("group_kind") or "") == "dut"
            ],
            "by_fault_family": mutation_by_family_rows,
            "exclusions": exclusion_rows,
        },
    }


def _is_semantic_detection(record: Mapping[str, Any]) -> bool:
    status = str(record.get("status") or "")
    failure_class = str(record.get("failure_class") or "")
    applicability = str(record.get("oracle_applicability") or "valid")
    if status != "fail":
        return False
    if applicability != "valid":
        return False
    if failure_class in _INFRA_FAILURE_CLASSES:
        return False
    if record.get("observation_valid") is False:
        return False
    if record.get("stage_verified") is False:
        return False
    return True


def _is_differential_mutation_detection(record: Mapping[str, Any]) -> bool:
    status = str(record.get("status") or "")
    failure_class = str(record.get("failure_class") or "")
    if status != "fail":
        return False
    if failure_class in _INFRA_FAILURE_CLASSES:
        return False
    return not _is_infrastructure_failure(record)


def _is_infrastructure_failure(record: Mapping[str, Any]) -> bool:
    failure_class = str(record.get("failure_class") or "")
    if failure_class in _INFRA_FAILURE_CLASSES:
        return True
    status = str(record.get("status") or "")
    return status in {"timeout", "error", "compile_fail", "materialized_only", "setup_unsupported"}


def _capability_payload_by_dut(capabilities_manifest: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(capabilities_manifest, Mapping):
        return {}
    duts = capabilities_manifest.get("duts")
    if not isinstance(duts, Mapping):
        return {}
    return {
        str(dut): dict(payload)
        for dut, payload in duts.items()
        if isinstance(payload, Mapping)
    }


def _a_priori_observability_record(
    *,
    frozen_case: Mapping[str, Any],
    label: Mapping[str, Any],
    dut: str,
    capabilities_payload: Mapping[str, Any],
) -> dict[str, Any]:
    merged_case = dict(frozen_case)
    merged_case.update(label)
    case_id = str(frozen_case.get("case_id") or "")
    capability = capabilities_payload.get("capability") if isinstance(capabilities_payload.get("capability"), Mapping) else {}
    applicability_by_case = (
        capabilities_payload.get("applicability_by_case")
        if isinstance(capabilities_payload.get("applicability_by_case"), Mapping)
        else {}
    )
    observation_capabilities = {}
    if isinstance(capability, Mapping):
        observation_capabilities.update(capability.get("observation_capabilities") or {})
    available = bool(capability.get("available"))
    finish_protocol = str(capability.get("finish_protocol") or "")
    diagnostic_depth = str(capability.get("diagnostic_depth") or "")
    required_observation = required_observation_capabilities_for_case(merged_case)
    missing_observation = [
        name for name in required_observation if not bool(observation_capabilities.get(name, False))
    ]
    a_priori_applicability = str(applicability_by_case.get(case_id) or "valid")
    architectural_completion_visible = available and bool(finish_protocol)
    trap_cause_visible = available and diagnostic_depth not in {"", "none", "opaque"}
    fault_address_visible = available and bool(observation_capabilities.get("sv39_final_fault_address", False))
    ptw_stage_visible = available and bool(observation_capabilities.get("sv39_ptw_target_attribution", False))
    side_effect_visible = available and bool(observation_capabilities.get("sv39_stateful_reprobe_phase", False))
    label_applicability = str(label.get("applicability") or "applicable")
    a_priori_observable = label_applicability == "applicable" and a_priori_applicability == "valid"
    reasons: list[str] = []
    if label_applicability != "applicable":
        reasons.append(f"label:{label_applicability}")
    if a_priori_applicability != "valid":
        reasons.append(f"capability:{a_priori_applicability}")
    if missing_observation:
        reasons.append("missing_observation:" + ",".join(sorted(missing_observation)))
    if not architectural_completion_visible:
        reasons.append("missing_completion_visibility")
    if not trap_cause_visible:
        reasons.append("missing_trap_cause_visibility")
    return {
        "dut": dut,
        "a_priori_applicability": a_priori_applicability,
        "a_priori_observable": a_priori_observable,
        "a_priori_observable_reason": "observable" if a_priori_observable else ";".join(reasons),
        "required_observation_capabilities": ";".join(required_observation),
        "architectural_completion_visible": architectural_completion_visible,
        "trap_cause_visible": trap_cause_visible,
        "fault_address_visible": fault_address_visible,
        "ptw_stage_visible": ptw_stage_visible,
        "side_effect_visible": side_effect_visible,
    }


def _validate_e3_directed_rows(
    *,
    directed_evidence_rows: list[dict[str, Any]],
    expected_mutant_count: int,
    checks: list[dict[str, Any]],
    errors: list[str],
) -> None:
    _check(
        len(directed_evidence_rows) == expected_mutant_count,
        "e3_expected_actual_mutant_row_count",
        checks,
        errors,
        f"expected {expected_mutant_count} directed evidence rows, got {len(directed_evidence_rows)}",
    )
    inherited_baseline = any(
        str(row.get("evidence_scope") or "") != "directed-only-confirmation"
        for row in directed_evidence_rows
    )
    _check(
        not inherited_baseline,
        "e3_directed_rows_use_explicit_evidence_scope",
        checks,
        errors,
        "directed evidence rows are missing evidence_scope=directed-only-confirmation",
    )
    contradiction_rows = [
        row
        for row in directed_evidence_rows
        if (bool(row.get("killed")) and int(row.get("activation_semantic_failure_count") or 0) <= 0)
        or ((not bool(row.get("killed"))) and int(row.get("activation_semantic_failure_count") or 0) > 0)
    ]
    _check(
        not contradiction_rows,
        "e3_killed_matches_activation_semantic_failures",
        checks,
        errors,
        f"killed/result contradiction rows: {contradiction_rows[:3]}",
    )
    incomplete_rows = [
        row
        for row in directed_evidence_rows
        if not bool(row.get("activation_complete")) or not bool(row.get("control_complete"))
    ]
    _check(
        not incomplete_rows,
        "e3_activation_control_complete",
        checks,
        errors,
        f"incomplete activation/control rows: {incomplete_rows[:3]}",
    )
    control_failure_rows = [
        row for row in directed_evidence_rows if int(row.get("control_semantic_failure_count") or 0) > 0
    ]
    _check(
        not control_failure_rows,
        "e3_control_semantic_failures_zero",
        checks,
        errors,
        f"control semantic failures present: {control_failure_rows[:3]}",
    )
    infra_failure_rows = [
        row for row in directed_evidence_rows if int(row.get("infra_failure_count") or 0) > 0
    ]
    _check(
        not infra_failure_rows,
        "e3_infra_failures_zero",
        checks,
        errors,
        f"infrastructure failures present: {infra_failure_rows[:3]}",
    )
    seed_mismatch_rows = [
        row
        for row in directed_evidence_rows
        if int(row.get("expected_seed_count") or 0) != int(row.get("observed_seed_count") or 0)
    ]
    _check(
        not seed_mismatch_rows,
        "e3_expected_observed_seed_counts_match",
        checks,
        errors,
        f"expected/observed seed count mismatch: {seed_mismatch_rows[:3]}",
    )


def _seed_from_name(seed_name: str) -> int:
    prefix, _, raw = seed_name.partition("-")
    if prefix != "seed" or not raw.isdigit():
        return 0
    return int(raw)


def _exclusion_row(
    *,
    scope: str,
    dut: str,
    mutant_id: str,
    reason: str,
    details: str,
    artifact_path: Path,
    seed: int | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "scope": scope,
        "dut": dut,
        "mutant_id": mutant_id,
        "seed": seed if seed is not None else "",
        "reason": reason,
        "details": details,
        "artifact_path": str(artifact_path),
    }


def _write_optional_table(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _safe_rate(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return numerator / denominator


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object in {path}")
    return payload


def _load_json_if_exists(path: Path) -> dict[str, Any] | None:
    return _load_json(path) if path.exists() else None


if __name__ == "__main__":
    raise SystemExit(main())
