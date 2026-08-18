#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from pathlib import Path as _Path
from typing import Any

_source_root_override = os.environ.get("PMPFUZZ_SOURCE_ROOT")
_script_root = (
    _Path(_source_root_override).resolve()
    if _source_root_override
    else _Path(__file__).resolve().parents[3]
)
if str(_script_root) not in sys.path:
    sys.path.insert(0, str(_script_root))

from pmpfuzz.experiment_protocols import (
    BAPC_CONVERGENCE_FORMAL,
    BAPC_FORMAL_ALLOWED_STOP_REASONS,
    allowed_bapc_formal_field_values,
    bapc_formal_variant_label,
    expected_bapc_formal_run_class,
    is_bapc_formal_campaign,
    is_bapc_formal_contract,
    is_bapc_formal_request,
    typed_int_matches,
    typed_numeric_matches,
)
from pmpfuzz.stop_reasons import normalize_stop_reason


CAMPAIGN_FIELDS = [
    "schema_version", "experiment_id", "campaign_id", "method", "variant",
    "generator_variant", "dut", "seed", "coverage_mode", "source_sha", "dut_sha",
    "dut_binary_path", "dut_binary_sha256", "source_tree_sha256", "source_dirty",
    "capability_fingerprint", "experiment_protocol_id",
    "start_utc", "end_utc", "time_budget_seconds",
    "wall_clock_horizon_seconds", "budget_class", "run_class", "stop_reason",
    "convergence_enabled", "convergence_min_runtime_seconds",
    "convergence_confirmation_seconds", "convergence_confirmation_eligible_cases",
    "max_wall_time_seconds",
    "round_size", "jobs", "per_case_timeout_seconds", "completed_cases",
    "eligible_cases", "eligible_hpm_cases", "eligible_bapc_cases",
    "semantic_target", "pairwise_target", "triples_target", "predicates_target", "hpm_target", "bapc_target",
    "semantic_covered", "pairwise_covered", "triples_covered", "predicates_covered", "hpm_covered", "bapc_covered",
    "semantic_final_rate", "pairwise_final_rate",
    "triples_final_rate", "predicates_final_rate", "hpm_final_rate", "bapc_final_rate", "artifact_path",
]

_STRICT_RUN_CLASSES = {
    "readiness", "pilot", "formal", "baseline-pilot", "baseline-formal",
}
_KNOWN_RUN_CLASSES = _STRICT_RUN_CLASSES | {"development-smoke"}
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

EVENT_FIELDS = [
    "schema_version", "experiment_id", "campaign_id", "method", "variant",
    "dut", "seed", "completion_seq", "event_index", "elapsed_wall_seconds",
    "event_namespace", "event_category", "event_id", "is_new_event",
    "total_distinct_events", "case_id",
]

_PMPFUZZ_FOUR_MODES = ("semantic", "pairwise", "security-triples", "predicates")
_PMPFUZZ_UNIVERSE_METADATA_MODES = ("semantic", "pairwise", "security_triples", "predicates")
_PMPFUZZ_SINGLE_MODE_COVERAGE_MODES = ("hpm", "bapc")


def _expected_universe_metadata_modes(campaign: dict[str, Any]) -> tuple[str, ...]:
    coverage_mode = str(campaign.get("coverage_mode") or "")
    if coverage_mode in _PMPFUZZ_SINGLE_MODE_COVERAGE_MODES:
        return (coverage_mode,)
    return _PMPFUZZ_UNIVERSE_METADATA_MODES


def _campaign_identity(meta: dict[str, Any], lines: list[dict[str, Any]], campaign_dir: Path) -> str:
    last = lines[-1] if lines else {}
    return str(meta.get("campaign_id") or last.get("campaign_id") or campaign_dir.name)


def _classify_run_class(value: object) -> tuple[str, bool, bool]:
    run_class = str(value or "")
    if not run_class:
        return "", False, True
    return run_class, run_class in _STRICT_RUN_CLASSES, run_class in _KNOWN_RUN_CLASSES


def _is_hex_digest(value: object, length: int) -> bool:
    if not isinstance(value, str):
        return False
    pattern = _HEX40_RE if length == 40 else _HEX64_RE
    return pattern.fullmatch(value) is not None


def _load_experiment_contract(artifact_root: Path) -> dict[str, Any] | None:
    path = artifact_root / "manifests" / "experiment-contract.json"
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="ascii"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _is_superseded_campaign_path(path: Path) -> bool:
    return any(
        ".orphaned-" in part
        or ".replaced-" in part
        or ".rerun-aborted-" in part
        or ".interrupted-" in part
        for part in path.parts
    )


def _is_formal_bapc_meta(meta: dict[str, Any], experiment_contract: dict[str, Any] | None = None) -> bool:
    if is_bapc_formal_contract(experiment_contract):
        return True
    return is_bapc_formal_request(
        coverage_mode=meta.get("coverage_mode"),
        run_class=meta.get("run_class"),
        experiment_protocol_id=meta.get("experiment_protocol_id"),
    )


def _analysis_lines_within_horizon(lines: list[dict[str, Any]], meta: dict[str, Any]) -> list[dict[str, Any]]:
    T, _ = _normalize_horizon(meta.get("wall_clock_horizon_seconds"))
    if T is None:
        return list(lines)
    return [
        line for line in lines
        if float(line.get("elapsed_wall_seconds", 0) or 0) <= T + 1e-9
    ]


def _normalize_universe_mode(mode: str) -> str:
    if mode == "security_triples":
        return "security-triples"
    return mode


def _strict_provenance_complete(meta: dict[str, Any]) -> bool:
    if not _is_hex_digest(meta.get("source_sha"), 40):
        return False
    if not _is_hex_digest(meta.get("source_tree_sha256"), 64):
        return False
    if not isinstance(meta.get("source_dirty"), bool):
        return False
    if not _is_hex_digest(meta.get("dut_binary_sha256"), 64):
        return False
    if not str(meta.get("dut_binary_path") or ""):
        return False
    dut_sha_status = str(meta.get("dut_sha_status") or "")
    if dut_sha_status == "not-applicable":
        return bool(str(meta.get("dut_sha_reason") or ""))
    return _is_hex_digest(meta.get("dut_sha"), 40)


def _has_complete_strict_metadata(meta: dict[str, Any]) -> bool:
    required = (
        "method",
        "variant",
        "dut",
        "seed",
        "coverage_mode",
        "capability_fingerprint",
        "jobs",
        "time_budget_seconds",
        "wall_clock_horizon_seconds",
        "budget_class",
        "run_class",
    )
    if not (all(meta.get(field) not in {None, ""} for field in required) and _strict_provenance_complete(meta)):
        return False
    if not _is_formal_bapc_meta(meta):
        return True
    if not str(meta.get("experiment_protocol_id") or ""):
        return False
    if meta.get("source_dirty") is not False:
        return False
    if type(meta.get("convergence_enabled")) is not bool:
        return False
    if not typed_numeric_matches(
        meta.get("convergence_min_runtime_seconds"),
        BAPC_CONVERGENCE_FORMAL["convergence_min_runtime_seconds"],
    ):
        return False
    if not typed_numeric_matches(
        meta.get("convergence_confirmation_seconds"),
        BAPC_CONVERGENCE_FORMAL["convergence_confirmation_seconds"],
    ):
        return False
    if not typed_int_matches(
        meta.get("convergence_confirmation_eligible_cases"),
        BAPC_CONVERGENCE_FORMAL["convergence_confirmation_eligible_cases"],
    ):
        return False
    if not typed_numeric_matches(
        meta.get("max_wall_time_seconds"),
        BAPC_CONVERGENCE_FORMAL["max_wall_time_seconds"],
    ):
        return False
    return True


def _validation_binding_error(
    campaign_dir: Path,
    campaign_id: str,
    meta: dict[str, Any],
    payload: dict[str, Any],
    *,
    artifact_root: Path,
    experiment_contract: dict[str, Any] | None,
) -> str | None:
    if str(payload.get("campaign_id") or "") != campaign_id:
        return "validation bindings campaign_id mismatch"
    inputs = payload.get("inputs")
    if not isinstance(inputs, dict):
        return "validation bindings missing inputs"
    expected: dict[str, Path] = {
        "metadata": campaign_dir / "metrics" / "campaign_metadata.json",
        "timeline": campaign_dir / "metrics" / "coverage_timeline.jsonl",
    }
    schedule_rel = str(meta.get("schedule_v4") or "")
    if schedule_rel:
        expected["schedule_v4"] = (campaign_dir / schedule_rel).resolve()
    for label, path in expected.items():
        entry = inputs.get(label)
        if not isinstance(entry, dict):
            return f"validation bindings missing {label}"
        recorded_path = Path(str(entry.get("path") or ""))
        expected_rel = path.relative_to(campaign_dir)
        if recorded_path != expected_rel:
            return f"validation bindings path mismatch for {label}"
        recorded_sha = str(entry.get("sha256") or "")
        if not _is_hex_digest(recorded_sha, 64):
            return f"validation bindings invalid sha256 for {label}"
        if not path.exists():
            return f"validation bindings missing file for {label}"
        actual_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_sha != recorded_sha:
            return f"validation bindings mismatch for {label}"
    coverage_entry = inputs.get("coverage")
    coverage_path = campaign_dir / "coverage" / "coverage.json"
    if coverage_entry is not None:
        if not isinstance(coverage_entry, dict):
            return "validation bindings missing coverage"
        if not coverage_path.exists():
            return "validation bindings missing file for coverage"
        recorded_path = Path(str(coverage_entry.get("path") or ""))
        if recorded_path != coverage_path.relative_to(campaign_dir):
            return "validation bindings path mismatch for coverage"
        recorded_sha = str(coverage_entry.get("sha256") or "")
        if not _is_hex_digest(recorded_sha, 64):
            return "validation bindings invalid sha256 for coverage"
        actual_sha = hashlib.sha256(coverage_path.read_bytes()).hexdigest()
        if actual_sha != recorded_sha:
            return "validation bindings mismatch for coverage"
    if _is_formal_bapc_meta(meta, experiment_contract):
        contract_path = artifact_root / "manifests" / "experiment-contract.json"
        contract_entry = inputs.get("experiment_contract")
        if not isinstance(contract_entry, dict):
            return "validation bindings missing experiment contract"
        if not contract_path.exists():
            return "validation bindings missing file for experiment contract"
        expected_rel = Path(os.path.relpath(contract_path, campaign_dir))
        recorded_path = Path(str(contract_entry.get("path") or ""))
        if recorded_path != expected_rel:
            return "validation bindings path mismatch for experiment contract"
        recorded_sha = str(contract_entry.get("sha256") or "")
        if not _is_hex_digest(recorded_sha, 64):
            return "validation bindings invalid sha256 for experiment contract"
        actual_sha = hashlib.sha256(contract_path.read_bytes()).hexdigest()
        if actual_sha != recorded_sha:
            return "validation bindings mismatch for experiment contract"
    return None


def _load_validation_gate(
    campaign_dir: Path,
    campaign_id: str,
    meta: dict[str, Any],
    experiment_contract: dict[str, Any] | None,
    artifact_root: Path,
) -> tuple[bool, dict[str, Any] | None]:
    validation_path = campaign_dir / "validation.json"
    run_class, is_strict, is_known = _classify_run_class(meta.get("run_class"))
    formal_bapc_meta = _is_formal_bapc_meta(meta, experiment_contract)
    if formal_bapc_meta:
        is_strict = True
    if run_class and not is_known:
        return False, {
            "campaign_id": campaign_id,
            "excluded": True,
            "reason": f"unknown run_class: {run_class}",
            "recorded_utc": "",
        }
    if formal_bapc_meta and not run_class:
        return False, {
            "campaign_id": campaign_id,
            "excluded": True,
            "reason": "formal contract requires run_class",
            "recorded_utc": "",
        }
    if formal_bapc_meta and not str(meta.get("experiment_protocol_id") or ""):
        return False, {
            "campaign_id": campaign_id,
            "excluded": True,
            "reason": "formal BAPC requires experiment_protocol_id",
            "recorded_utc": "",
        }
    if formal_bapc_meta and not is_bapc_formal_contract(experiment_contract):
        return False, {
            "campaign_id": campaign_id,
            "excluded": True,
            "reason": "formal BAPC requires experiment-contract.json",
            "recorded_utc": "",
        }
    if not validation_path.exists():
        if is_strict:
            return False, {
                "campaign_id": campaign_id,
                "excluded": True,
                "reason": "missing validation.json",
                "recorded_utc": "",
            }
        return True, None
    try:
        payload = json.loads(validation_path.read_text(encoding="ascii"))
    except Exception:
        return False, {
            "campaign_id": campaign_id,
            "excluded": True,
            "reason": "corrupt validation.json",
            "recorded_utc": "",
        }
    valid = payload.get("valid")
    if type(valid) is not bool or not valid:
        return False, {
            "campaign_id": campaign_id,
            "excluded": True,
            "reason": "validation.json valid=false",
            "recorded_utc": "",
        }
    if is_strict:
        binding_error = _validation_binding_error(
            campaign_dir,
            campaign_id,
            meta,
            payload,
            artifact_root=artifact_root,
            experiment_contract=experiment_contract,
        )
        if binding_error is not None:
            return False, {
                "campaign_id": campaign_id,
                "excluded": True,
                "reason": binding_error,
                "recorded_utc": "",
            }
    return True, None


def _pmpfuzz_mode_status(lines: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    data_lines = [line for line in lines if int(line.get("completion_seq", 0) or 0) > 0] or list(lines)
    required = {
        "semantic": (
            ("semantic_covered", "semantic_target", "semantic_rate"),
            "new_semantic_bins",
        ),
        "pairwise": (
            ("pairwise_covered", "pairwise_target", "pairwise_rate"),
            "new_pairwise_bins",
        ),
        "security-triples": (
            ("security_triples_covered", "security_triples_target", "security_triples_rate"),
            "new_security_triple_bins",
        ),
        "predicates": (
            ("predicates_covered", "predicates_target", "predicates_rate"),
            "new_predicate_bins",
        ),
    }
    complete: set[str] = set()
    partial: set[str] = set()
    for mode, (core_fields, delta_field) in required.items():
        if not data_lines:
            partial.add(mode)
            continue
        core_present = all(all(field in line for field in core_fields) for line in data_lines)
        delta_present = all(delta_field in line for line in data_lines)
        any_fields_present = any(
            any(field in line for field in (*core_fields, delta_field))
            for line in data_lines
        )
        if not any_fields_present:
            continue
        if core_present and delta_present:
            complete.add(mode)
        else:
            partial.add(mode)
    return complete, partial


def _timeseries_modes_for_campaign(
    campaign: dict[str, Any],
    lines: list[dict[str, Any]],
) -> tuple[list[str], list[str]]:
    method = str(campaign.get("method") or "")
    coverage_mode = str(campaign.get("coverage_mode") or "")
    if coverage_mode in _PMPFUZZ_SINGLE_MODE_COVERAGE_MODES:
        return [coverage_mode], []
    if method != "pmpfuzz":
        return [coverage_mode or "semantic"], []
    declared_multimode = (
        str(campaign.get("driver_mode") or "") == "continuous"
        or str(campaign.get("coverage_schema") or "") == "pmpfuzz-v1-four-mode"
    )
    if not declared_multimode:
        return ["semantic"], []
    complete_modes, partial_modes = _pmpfuzz_mode_status(lines)
    if complete_modes == set(_PMPFUZZ_FOUR_MODES) and not partial_modes:
        return list(_PMPFUZZ_FOUR_MODES), []
    export_modes = sorted(complete_modes) or [str(campaign.get("coverage_mode") or "semantic")]
    inferred_missing: set[str] = set(partial_modes)
    inferred_missing |= set(_PMPFUZZ_FOUR_MODES) - complete_modes
    if inferred_missing:
        return export_modes, [
            f"campaign {campaign['campaign_id']} incomplete PMPFuzz coverage fields; missing modes: {sorted(inferred_missing)}"
        ]
    return export_modes, []


def _mode_has_activity(lines: list[dict[str, Any]], mode: str) -> bool:
    keys = {
        "semantic": ("semantic_covered", "semantic_rate", "new_semantic_bins"),
        "pairwise": ("pairwise_covered", "pairwise_rate", "new_pairwise_bins"),
        "security-triples": ("security_triples_covered", "security_triples_rate", "new_security_triple_bins"),
        "predicates": ("predicates_covered", "predicates_rate", "new_predicate_bins"),
        "hpm": ("hpm_covered", "hpm_rate", "new_hpm_bins"),
        "bapc": ("bapc_covered", "bapc_rate", "new_bapc_bins"),
    }[mode]
    for line in lines:
        if any(float(line.get(key) or 0) > 0 for key in keys):
            return True
    return False


def _load_coverage_universe_comparability(
    campaign_dir: Path,
    campaign: dict[str, Any],
    meta: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    files = meta.get("coverage_universe_files") or {}
    hashes = meta.get("coverage_universe_hashes") or {}
    if not files and not hashes:
        return {}, []

    from pmpfuzz.coverage_universe import (
        coverage_universe_bin_set_sha256,
        validate_coverage_universe,
    )
    from pmpfuzz.bapc import load_bapc_coverage_universe

    campaign_id = str(campaign.get("campaign_id") or campaign_dir.name)
    comparability: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for metadata_mode in _expected_universe_metadata_modes(campaign):
        raw_path = files.get(metadata_mode)
        expected_hash = str(hashes.get(metadata_mode) or "")
        if not raw_path or not expected_hash:
            errors.append(
                f"campaign {campaign_id} missing coverage universe metadata for mode={metadata_mode}"
            )
            continue
        universe_path = Path(str(raw_path))
        if not universe_path.is_absolute():
            universe_path = campaign_dir / universe_path
        if not universe_path.exists():
            errors.append(
                f"campaign {campaign_id} missing coverage universe file for mode={metadata_mode}: {universe_path}"
            )
            continue
        try:
            if metadata_mode == "bapc":
                universe = load_bapc_coverage_universe(universe_path)
            else:
                universe = json.loads(universe_path.read_text(encoding="ascii"))
                validate_coverage_universe(universe)
        except Exception as exc:
            errors.append(
                f"campaign {campaign_id} invalid coverage universe for mode={metadata_mode}: {exc}"
            )
            continue
        actual_hash = str(universe.get("sha256") or "")
        if expected_hash != actual_hash:
            errors.append(
                f"campaign {campaign_id} coverage universe sha mismatch for mode={metadata_mode}: "
                f"metadata={expected_hash} file={actual_hash}"
            )
            continue
        comparability[_normalize_universe_mode(metadata_mode)] = {
            "bin_count": int(universe.get("bin_count") or 0),
            "bin_set_sha256": str(
                universe.get("bin_set_sha256")
                or coverage_universe_bin_set_sha256(universe.get("bin_ids") or [])
            ),
            "sha256": actual_hash,
        }
    return comparability, errors


def _validate_coverage_universe_comparability(campaigns: list[dict[str, Any]]) -> list[str]:
    grouped: dict[tuple[str, str, str], dict[tuple[int, str], list[str]]] = {}
    for campaign in campaigns:
        summaries = campaign.get("_coverage_universe_comparability") or {}
        campaign_id = str(campaign.get("campaign_id") or "")
        experiment_id = str(campaign.get("experiment_id") or "")
        dut = str(campaign.get("dut") or "")
        for mode, summary in summaries.items():
            group_key = (experiment_id, dut, str(mode))
            compare_key = (
                int(summary.get("bin_count") or 0),
                str(summary.get("bin_set_sha256") or ""),
            )
            grouped.setdefault(group_key, {}).setdefault(compare_key, []).append(campaign_id)

    errors: list[str] = []
    for (experiment_id, dut, mode), variants in grouped.items():
        if len(variants) <= 1:
            continue
        parts = [
            f"bin_count={bin_count} bin_set_sha256={bin_set_sha256} campaigns={sorted(campaign_ids)}"
            for (bin_count, bin_set_sha256), campaign_ids in sorted(variants.items())
        ]
        errors.append(
            f"coverage universe comparability mismatch: experiment={experiment_id} "
            f"dut={dut} coverage_mode={mode} details={parts}"
        )
    return errors


def _validate_analysis_scope(
    artifact_root: Path,
    campaigns: list[dict[str, Any]],
    timeseries_rows: list[dict[str, Any]],
    security_event_rows: list[dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    pmpfuzz_campaigns = [campaign for campaign in campaigns if str(campaign.get("method") or "") == "pmpfuzz"]
    if not pmpfuzz_campaigns:
        return errors

    actual_modes: dict[str, set[str]] = {}
    for row in timeseries_rows:
        key = str(row["campaign_id"])
        actual_modes.setdefault(key, set()).add(str(row["coverage_mode"]))
    multi_mode_campaigns = [
        campaign
        for campaign in pmpfuzz_campaigns
        if len(actual_modes.get(str(campaign.get("campaign_id") or ""), set())) > 1
    ]

    scope_path = artifact_root / "manifests" / "analysis-scope.json"
    scope = None
    if scope_path.exists():
        try:
            scope = json.loads(scope_path.read_text(encoding="ascii"))
        except Exception as exc:
            errors.append(f"analysis_scope unreadable: {exc}")
    elif multi_mode_campaigns:
        errors.append("analysis_scope missing for PMPFuzz aggregate")

    eventful_campaigns = {str(row.get("campaign_id") or "") for row in security_event_rows}
    for campaign in pmpfuzz_campaigns:
        if str(campaign.get("variant") or "") == "bb-wb" and str(campaign.get("campaign_id") or "") not in eventful_campaigns:
            errors.append(f"bb-wb campaign {campaign['campaign_id']} has no security events")

    if scope is None:
        return errors

    expected_modes = {str(mode) for mode in scope.get("coverage_modes") or []}
    expected_variants = {str(variant) for variant in scope.get("primary_variants") or []}
    expected_seeds = {int(seed) for seed in scope.get("primary_seeds") or []}
    guidance_mode = str(scope.get("guidance_mode") or "")
    primary_metric = str(scope.get("primary_metric") or "")

    if multi_mode_campaigns:
        if guidance_mode not in expected_modes:
            errors.append(
                f"analysis_scope guidance_mode must be one of coverage_modes; got {guidance_mode!r}"
            )
        if primary_metric not in expected_modes:
            errors.append(
                f"analysis_scope primary_metric must be one of coverage_modes; got {primary_metric!r}"
            )

    for campaign in pmpfuzz_campaigns:
        variant = str(campaign.get("variant") or "")
        seed = int(campaign.get("seed") or 0)
        if variant not in expected_variants or seed not in expected_seeds:
            continue
        actual = actual_modes.get(str(campaign.get("campaign_id") or ""), set())
        if actual != expected_modes:
            missing = sorted(expected_modes - actual)
            extra = sorted(actual - expected_modes)
            errors.append(
                f"campaign {campaign['campaign_id']} coverage_mode mismatch; missing={missing} extra={extra}"
            )
    return errors


def _validate_bapc_formal_matrix(
    campaigns: list[dict[str, Any]],
    exclusion_rows: list[dict[str, Any]],
    experiment_contract: dict[str, Any] | None,
    *,
    formal_bapc_seen: bool,
) -> list[str]:
    if not is_bapc_formal_contract(experiment_contract):
        if formal_bapc_seen:
            return ["formal BAPC requires valid experiment-contract.json"]
        return []

    contract = experiment_contract or {}
    expected_variants = {str(item) for item in contract.get("variants") or [] if str(item)}
    expected_seeds = {int(item) for item in contract.get("seeds") or []}
    expected_keys = {(variant, seed) for variant in expected_variants for seed in expected_seeds}
    errors: list[str] = []

    if exclusion_rows:
        excluded = sorted(str(row.get("campaign_id") or "") for row in exclusion_rows if str(row.get("campaign_id") or ""))
        errors.append(f"formal contract exclusions present: {excluded}")

    actual_keys: dict[tuple[str, int], list[str]] = {}
    source_shas: set[str] = set()
    source_tree_shas: set[str] = set()
    binary_shas: set[str] = set()
    dut_shas: set[str] = set()
    contract_bound_fields = (
        "source_sha",
        "source_tree_sha256",
        "dut_sha",
        "dut_binary_sha256",
    )

    for campaign in campaigns:
        method = str(campaign.get("method") or "")
        variant = str(campaign.get("variant") or "")
        effective_variant = bapc_formal_variant_label(method, variant)
        seed = int(campaign.get("seed") or 0)
        campaign_id = str(campaign.get("campaign_id") or "")
        actual_keys.setdefault((effective_variant, seed), []).append(campaign_id)

        if effective_variant not in expected_variants:
            errors.append(
                f"formal contract extra campaign variant={effective_variant} seed={seed} campaign={campaign_id}"
            )
        if seed not in expected_seeds:
            errors.append(f"formal contract extra seed={seed} campaign={campaign_id}")
        if str(campaign.get("experiment_protocol_id") or "") != str(contract.get("experiment_protocol_id") or ""):
            errors.append(f"formal protocol mismatch: campaign={campaign_id}")
        if str(campaign.get("coverage_mode") or "") != str(contract.get("coverage_mode") or ""):
            errors.append(f"formal coverage_mode mismatch: campaign={campaign_id}")
        if str(campaign.get("dut") or "") != str(contract.get("dut") or ""):
            errors.append(f"formal dut mismatch: campaign={campaign_id}")

        expected_run_class = expected_bapc_formal_run_class(method)
        if expected_run_class is None or str(campaign.get("run_class") or "") != expected_run_class:
            errors.append(
                f"formal method/run_class mismatch: campaign={campaign_id} method={method} "
                f"run_class={campaign.get('run_class')!r} expected={expected_run_class!r}"
            )

        if normalize_stop_reason(campaign.get("stop_reason")) not in BAPC_FORMAL_ALLOWED_STOP_REASONS:
            errors.append(f"formal stop_reason mismatch: campaign={campaign_id} stop_reason={campaign.get('stop_reason')!r}")

        if type(campaign.get("convergence_enabled")) is not bool or campaign.get("convergence_enabled") is not True:
            errors.append(f"formal convergence_enabled mismatch: campaign={campaign_id}")

        if not typed_numeric_matches(
            campaign.get("convergence_min_runtime_seconds"),
            BAPC_CONVERGENCE_FORMAL["convergence_min_runtime_seconds"],
        ):
            errors.append(f"formal convergence_min_runtime_seconds mismatch: campaign={campaign_id}")
        if not typed_numeric_matches(
            campaign.get("convergence_confirmation_seconds"),
            BAPC_CONVERGENCE_FORMAL["convergence_confirmation_seconds"],
        ):
            errors.append(f"formal convergence_confirmation_seconds mismatch: campaign={campaign_id}")
        if not typed_int_matches(
            campaign.get("convergence_confirmation_eligible_cases"),
            BAPC_CONVERGENCE_FORMAL["convergence_confirmation_eligible_cases"],
        ):
            errors.append(f"formal convergence_confirmation_eligible_cases mismatch: campaign={campaign_id}")
        if not typed_numeric_matches(
            campaign.get("max_wall_time_seconds"),
            BAPC_CONVERGENCE_FORMAL["max_wall_time_seconds"],
        ):
            errors.append(f"formal max_wall_time_seconds mismatch: campaign={campaign_id}")
        if not typed_numeric_matches(
            campaign.get("time_budget_seconds"),
            BAPC_CONVERGENCE_FORMAL["time_budget_seconds"],
        ):
            errors.append(f"formal time_budget_seconds mismatch: campaign={campaign_id}")
        if not typed_numeric_matches(
            campaign.get("wall_clock_horizon_seconds"),
            BAPC_CONVERGENCE_FORMAL["wall_clock_horizon_seconds"],
        ):
            errors.append(f"formal wall_clock_horizon_seconds mismatch: campaign={campaign_id}")
        if str(campaign.get("budget_class") or "") != str(BAPC_CONVERGENCE_FORMAL["budget_class"]):
            errors.append(f"formal budget_class mismatch: campaign={campaign_id}")

        comparability = (campaign.get("_coverage_universe_comparability") or {}).get("bapc") or {}
        if (
            int(comparability.get("bin_count") or 0) != int(contract.get("bin_count") or 0)
            or str(comparability.get("bin_set_sha256") or "") != str(contract.get("bin_set_sha256") or "")
        ):
            errors.append(f"formal universe mismatch: campaign={campaign_id}")
        if campaign.get("source_dirty") is not False:
            errors.append(f"formal source_dirty mismatch: campaign={campaign_id}")
        for field in contract_bound_fields:
            expected_values = allowed_bapc_formal_field_values(contract, field)
            if not expected_values:
                continue
            actual = str(campaign.get(field) or "")
            if actual not in expected_values:
                errors.append(
                    f"formal {field} mismatch: campaign={campaign_id} actual={actual!r} expected={list(expected_values)!r}"
                )

        source_sha = str(campaign.get("source_sha") or "")
        if source_sha:
            source_shas.add(source_sha)
        source_tree_sha = str(campaign.get("source_tree_sha256") or "")
        if source_tree_sha:
            source_tree_shas.add(source_tree_sha)
        dut_sha = str(campaign.get("dut_sha") or "")
        if dut_sha:
            dut_shas.add(dut_sha)
        binary_sha = str(campaign.get("dut_binary_sha256") or "")
        if binary_sha:
            binary_shas.add(binary_sha)

    for key, campaign_ids in sorted(actual_keys.items()):
        if len(campaign_ids) > 1:
            errors.append(f"duplicate formal campaign key {key}: {sorted(campaign_ids)}")

    missing = sorted(expected_keys - set(actual_keys))
    if missing:
        errors.append(f"missing formal campaigns: {missing}")
    extra = sorted(set(actual_keys) - expected_keys)
    if extra:
        errors.append(f"extra formal campaigns: {extra}")

    allowed_source_shas = set(allowed_bapc_formal_field_values(contract, "source_sha"))
    allowed_source_tree_shas = set(allowed_bapc_formal_field_values(contract, "source_tree_sha256"))
    allowed_dut_shas = set(allowed_bapc_formal_field_values(contract, "dut_sha"))
    allowed_binary_shas = set(allowed_bapc_formal_field_values(contract, "dut_binary_sha256"))

    if source_shas and not source_shas.issubset(allowed_source_shas or source_shas):
        errors.append(f"formal source_sha mismatch: {sorted(source_shas)}")
    if source_tree_shas and not source_tree_shas.issubset(allowed_source_tree_shas or source_tree_shas):
        errors.append(f"formal source_tree_sha256 mismatch: {sorted(source_tree_shas)}")
    if dut_shas and not dut_shas.issubset(allowed_dut_shas or dut_shas):
        errors.append(f"formal dut_sha mismatch: {sorted(dut_shas)}")
    if binary_shas and not binary_shas.issubset(allowed_binary_shas or binary_shas):
        errors.append(f"formal dut_binary_sha256 mismatch: {sorted(binary_shas)}")

    return errors


def aggregate(
    artifact_root: Path,
    experiment_id: str,
    *,
    security_events_mode: str = "full",
) -> dict[str, Path]:
    aggregate_dir = artifact_root / "aggregate"
    aggregate_dir.mkdir(parents=True, exist_ok=True)
    normalized_dir = artifact_root / "normalized"
    normalized_dir.mkdir(parents=True, exist_ok=True)
    schemas_dir = artifact_root / "schemas"
    schemas_dir.mkdir(parents=True, exist_ok=True)
    manifests_dir = artifact_root / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    experiment_contract = _load_experiment_contract(artifact_root)

    campaigns: list[dict[str, Any]] = []
    horizon_validation_campaigns: list[dict[str, Any]] = []
    timeseries_rows: list[dict[str, Any]] = []
    security_event_rows: list[dict[str, Any]] = []
    security_event_source_count = 0
    exclusion_rows: list[dict[str, Any]] = []
    contract_errors: list[str] = []
    formal_bapc_seen = False

    def _scan_tree(scan_root: Path) -> None:
        nonlocal formal_bapc_seen, security_event_source_count
        if not scan_root.is_dir():
            return
        for tl_path in scan_root.rglob("coverage_timeline.jsonl"):
            if "rounds" in tl_path.parts:
                continue
            campaign_dir = tl_path.parents[1]
            if _is_superseded_campaign_path(campaign_dir):
                continue
            meta_path = tl_path.parent / "campaign_metadata.json"
            try:
                lines = _parse_jsonl(tl_path)
                meta = json.loads(meta_path.read_text(encoding="ascii")) if meta_path.exists() else {}
                analysis_lines = _analysis_lines_within_horizon(lines, meta)
                campaign_id = _campaign_identity(meta, lines, campaign_dir)
                if _is_formal_bapc_meta(meta, experiment_contract):
                    formal_bapc_seen = True
                allowed, exclusion = _load_validation_gate(
                    campaign_dir,
                    campaign_id,
                    meta,
                    experiment_contract,
                    artifact_root,
                )
                if exclusion is not None:
                    exclusion_rows.append(exclusion)
                    reason = str(exclusion.get("reason") or "")
                    if (
                        "unknown run_class" in reason
                        or "validation bindings" in reason
                        or "formal BAPC" in reason
                    ):
                        contract_errors.append(f"campaign {campaign_id} {reason}")
                if not allowed:
                    run_class, is_strict, _is_known = _classify_run_class(meta.get("run_class"))
                    if is_strict and not _has_complete_strict_metadata(meta):
                        horizon_validation_campaigns.append(
                            _build_campaign_row(experiment_id, campaign_dir, meta, analysis_lines)
                        )
                    continue
                campaign = _build_campaign_row(experiment_id, campaign_dir, meta, analysis_lines)
                comparability, universe_errors = _load_coverage_universe_comparability(
                    campaign_dir, campaign, meta
                )
                campaign["_coverage_universe_comparability"] = comparability
                contract_errors.extend(universe_errors)
                campaigns.append(campaign)
                horizon_validation_campaigns.append(campaign)
                event_rows = _load_security_events(
                    campaign_dir,
                    campaign,
                    security_events_mode=security_events_mode,
                )
                if event_rows is not None:
                    security_event_source_count += 1
                    security_event_rows.extend(event_rows)
                export_modes, errors = _timeseries_modes_for_campaign(campaign, lines)
                contract_errors.extend(errors)
                for line in analysis_lines:
                    for mode in export_modes:
                        row = _build_timeseries_row(experiment_id, campaign, line, coverage_mode=mode)
                        if row is not None:
                            timeseries_rows.append(row)
            except Exception as exc:
                print(f"WARNING: skipping {campaign_dir}: {exc}", file=sys.stderr)

    _scan_tree(artifact_root / "campaigns")
    _scan_tree(artifact_root / "pilot")
    contract_errors.extend(_validate_coverage_universe_comparability(campaigns))
    contract_errors.extend(
        _validate_bapc_formal_matrix(
            campaigns,
            exclusion_rows,
            experiment_contract,
            formal_bapc_seen=formal_bapc_seen,
        )
    )

    outputs: dict[str, Path] = {}

    campaigns_path = normalized_dir / "campaigns.csv"
    _write_csv_with_fields(campaigns_path, campaigns, CAMPAIGN_FIELDS)
    outputs["normalized_campaigns"] = campaigns_path

    normalized_coverage_path = normalized_dir / "coverage_timeseries.csv"
    _write_csv_with_fields(
        normalized_coverage_path,
        timeseries_rows,
        list(timeseries_rows[0].keys()) if timeseries_rows else [
            "schema_version", "experiment_id", "campaign_id", "method", "variant",
            "dut", "seed", "coverage_mode", "completion_seq",
            "elapsed_wall_seconds", "completed_cases", "eligible_cases",
            "eligible_hpm_cases", "eligible_bapc_cases",
            "covered_bins", "target_bins", "coverage_rate", "new_bins",
            "status", "failure_class", "case_id",
        ],
    )
    outputs["normalized_coverage_timeseries"] = normalized_coverage_path

    normalized_events_path = normalized_dir / "security_event_timeseries.csv"
    _write_csv_with_fields(normalized_events_path, security_event_rows, EVENT_FIELDS)
    outputs["normalized_security_event_timeseries"] = normalized_events_path

    if campaigns:
        path = aggregate_dir / "campaign_index.csv"
        _write_csv(path, campaigns)
        outputs["campaign_index"] = path
        print(f"campaign_index: {len(campaigns)} rows -> {path}")

    coverage_final = [_coverage_final_row(c) for c in campaigns if _effective_eligible_count(c) > 0]
    if coverage_final:
        path = aggregate_dir / "coverage_final.csv"
        _write_csv(path, coverage_final)
        outputs["coverage_final"] = path
        print(f"coverage_final: {len(coverage_final)} rows -> {path}")

    bapc_family_rows = _compute_bapc_family_coverage(campaigns)
    if bapc_family_rows:
        path = aggregate_dir / "bapc_family_coverage.csv"
        _write_csv(path, bapc_family_rows)
        outputs["bapc_family_coverage"] = path
        print(f"bapc_family_coverage: {len(bapc_family_rows)} rows -> {path}")

    bapc_reason_rows = _compute_bapc_qualification_reason_distribution(campaigns)
    if bapc_reason_rows:
        path = aggregate_dir / "bapc_qualification_reason_distribution.csv"
        _write_csv(path, bapc_reason_rows)
        outputs["bapc_qualification_reason_distribution"] = path
        print(f"bapc_qualification_reason_distribution: {len(bapc_reason_rows)} rows -> {path}")

    horizon_map: dict[str, dict[str, Any]] = {}
    for c in campaigns:
        horizon_map[str(c["campaign_id"])] = {
            "wall_clock_horizon_seconds": c.get("wall_clock_horizon_seconds"),
            "budget_class": c.get("budget_class", "primary-wall-clock"),
            "experiment_id": c.get("experiment_id", experiment_id),
            "dut": c.get("dut", ""),
            "method": c.get("method", ""),
            "run_class": c.get("run_class", ""),
        }

    threshold_rows = _compute_thresholds(timeseries_rows, horizon_map)
    if threshold_rows:
        path = aggregate_dir / "coverage_threshold_times.csv"
        _write_csv(path, threshold_rows)
        outputs["coverage_threshold_times"] = path
        print(f"coverage_threshold_times: {len(threshold_rows)} rows -> {path}")

    if timeseries_rows:
        path = aggregate_dir / "coverage_timeseries.csv"
        _write_csv(path, timeseries_rows)
        outputs["coverage_timeseries"] = path
        print(f"coverage_timeseries: {len(timeseries_rows)} rows -> {path}")

    auc_rows = _compute_auc(timeseries_rows, horizon_map)
    auc_path = aggregate_dir / "coverage_auc.csv"
    _write_csv_with_fields(
        auc_path,
        auc_rows,
        list(auc_rows[0].keys()) if auc_rows else [
            "schema_version", "experiment_id", "campaign_id", "method", "variant",
            "dut", "seed", "coverage_mode", "horizon_seconds", "auc",
            "normalized_auc", "horizon_source", "final_extension_seconds",
            "not_applicable",
        ],
    )
    outputs["coverage_auc"] = auc_path

    overhead_rows = _compute_overhead(campaigns, timeseries_rows)
    overhead_path = aggregate_dir / "overhead.csv"
    _write_csv_with_fields(
        overhead_path,
        overhead_rows,
        list(overhead_rows[0].keys()) if overhead_rows else [
            "schema_version", "experiment_id", "campaign_id", "method", "variant",
            "dut", "seed", "wall_seconds", "completed_cases", "eligible_cases",
            "eligible_hpm_cases", "eligible_bapc_cases", "effective_eligible_cases",
            "tests_per_second", "jobs",
        ],
    )
    outputs["overhead"] = overhead_path

    exclusions_path = aggregate_dir / "exclusions.csv"
    deduped_exclusions = {
        str(row["campaign_id"]): row for row in exclusion_rows
    }
    _write_csv_with_fields(
        exclusions_path,
        list(deduped_exclusions.values()),
        ["campaign_id", "excluded", "reason", "recorded_utc"],
    )
    outputs["exclusions"] = exclusions_path

    stats = _compute_statistics(campaigns, timeseries_rows)
    stats["security_event_export_mode"] = security_events_mode
    stats["security_event_source_count"] = security_event_source_count
    stats["normalized_security_event_row_count"] = len(security_event_rows)
    path = aggregate_dir / "statistics.json"
    path.write_text(json.dumps(stats, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
    outputs["statistics"] = path

    dictionary_path = schemas_dir / "data_dictionary.md"
    dictionary_path.write_text(_data_dictionary(), encoding="utf-8")
    outputs["data_dictionary"] = dictionary_path

    validation_path = aggregate_dir / "validation_report.json"
    horizon_errors = _validate_horizon_contract(
        horizon_validation_campaigns, timeseries_rows, horizon_map)
    validation = _validate_normalized_outputs(
        campaigns_path, normalized_coverage_path, normalized_events_path,
        auc_path, overhead_path, exclusions_path, dictionary_path,
    )
    for err in horizon_errors:
        validation["errors"].append(err)
    for err in contract_errors:
        validation["errors"].append(err)
    for err in _validate_analysis_scope(artifact_root, campaigns, timeseries_rows, security_event_rows):
        validation["errors"].append(err)
    validation["error_count"] = len(validation["errors"])
    validation["valid"] = validation["error_count"] == 0
    validation_path.write_text(
        json.dumps(validation, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )
    outputs["validation_report"] = validation_path

    hash_path = manifests_dir / "artifact-sha256.txt"
    _write_artifact_hashes(
        artifact_root,
        [path for path in outputs.values() if path != hash_path],
        hash_path,
    )
    outputs["artifact_hashes"] = hash_path

    return outputs


def _load_security_events(
    campaign_dir: Path,
    campaign: dict[str, Any],
    *,
    security_events_mode: str = "full",
) -> list[dict[str, Any]] | None:
    path = campaign_dir / "metrics" / "security_event_timeseries.jsonl"
    if not path.exists():
        return None
    if security_events_mode == "skip":
        return []
    T, _ = _normalize_horizon(campaign.get("wall_clock_horizon_seconds"))
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="ascii").splitlines():
        if not raw.strip():
            continue
        row = json.loads(raw)
        normalized = {field: row.get(field) for field in EVENT_FIELDS}
        normalized["experiment_id"] = normalized.get("experiment_id") or campaign["experiment_id"]
        normalized["campaign_id"] = normalized.get("campaign_id") or campaign["campaign_id"]
        normalized["method"] = normalized.get("method") or campaign["method"]
        normalized["variant"] = normalized.get("variant") or campaign["variant"]
        normalized["dut"] = normalized.get("dut") or campaign["dut"]
        normalized["seed"] = normalized.get("seed") if normalized.get("seed") is not None else campaign["seed"]
        if T is not None and float(normalized.get("elapsed_wall_seconds", 0) or 0) > T + 1e-9:
            continue
        rows.append(normalized)
    return rows


def _parse_jsonl(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="ascii").strip()
    if not raw:
        return []
    return [json.loads(line) for line in raw.split("\n") if line.strip()]




def _effective_eligible_count(campaign: dict[str, Any], line: dict[str, Any] | None = None) -> int:
    source = line or {}
    coverage_mode = str(campaign.get("coverage_mode") or "")
    if coverage_mode == "bapc":
        return int(source.get("eligible_bapc_cases") or campaign.get("eligible_bapc_cases") or 0)
    if coverage_mode == "hpm":
        return int(source.get("eligible_hpm_cases") or campaign.get("eligible_hpm_cases") or 0)
    return int(source.get("eligible_cases") or campaign.get("eligible_cases") or 0)


def _load_json_dict(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="ascii"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _bapc_bin_family(bin_id: str) -> str:
    if not bin_id.startswith("family="):
        return ""
    return bin_id.split("|", 1)[0].removeprefix("family=")


def _bapc_family_field_prefix(family: str) -> str:
    return family.replace("-", "_")


def _load_campaign_bapc_bins(campaign: dict[str, Any]) -> list[str]:
    coverage = _load_json_dict(Path(str(campaign.get("artifact_path") or "")) / "coverage" / "coverage.json")
    bins = coverage.get("bapc_bins")
    if isinstance(bins, list):
        return sorted({str(item) for item in bins})
    by_dut = ((coverage.get("execution_coverage") or {}).get("by_dut") or {})
    dut_name = str(campaign.get("dut") or "")
    dut_payloads: list[dict[str, Any]] = []
    if dut_name and dut_name in by_dut:
        dut_payloads.append(by_dut.get(dut_name) or {})
    dut_payloads.extend(value or {} for key, value in by_dut.items() if key != dut_name)
    for payload in dut_payloads:
        candidate_bins = ((payload.get("bapc") or {}).get("covered_bins") or [])
        if candidate_bins:
            return sorted({str(item) for item in candidate_bins})
    return []


def _load_campaign_bapc_universe(campaign: dict[str, Any]) -> dict[str, Any]:
    universe_dir = Path(str(campaign.get("artifact_path") or "")) / "metrics" / "coverage_universe"
    if not universe_dir.exists():
        return {}
    for path in sorted(universe_dir.glob("bapc*.json")):
        payload = _load_json_dict(path)
        if payload:
            return payload
    return {}


def _compute_bapc_family_coverage(campaigns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from collections import Counter

    rows: list[dict[str, Any]] = []
    for campaign in campaigns:
        if str(campaign.get("coverage_mode") or "") != "bapc":
            continue
        universe = _load_campaign_bapc_universe(campaign)
        bins = _load_campaign_bapc_bins(campaign)
        family_targets = {
            str(name): int(count or 0)
            for name, count in (universe.get("bapc_family_counts") or {}).items()
        }
        family_counts = Counter(
            family
            for family in (_bapc_bin_family(bin_id) for bin_id in bins)
            if family
        )
        row: dict[str, Any] = {
            "schema_version": "1.0",
            "experiment_id": campaign["experiment_id"],
            "campaign_id": campaign["campaign_id"],
            "method": campaign["method"],
            "variant": campaign["variant"],
            "dut": campaign["dut"],
            "seed": campaign["seed"],
            "bapc_core_version": universe.get("bapc_core_version") or "",
            "bin_set_sha256": universe.get("bin_set_sha256") or "",
            "bapc_target": int(universe.get("bin_count") or 0),
            "bapc_covered": len(bins),
            "completed_cases": int(campaign.get("completed_cases") or 0),
            "eligible_cases": int(campaign.get("eligible_cases") or 0),
            "eligible_bapc_cases": int(campaign.get("eligible_bapc_cases") or 0),
        }
        for family, target in family_targets.items():
            prefix = _bapc_family_field_prefix(family)
            covered = int(family_counts.get(family, 0))
            row[f"{prefix}_covered"] = covered
            row[f"{prefix}_target"] = target
            row[f"{prefix}_rate"] = (covered / target) if target > 0 else None
        rows.append(row)
    return rows


def _compute_bapc_qualification_reason_distribution(campaigns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from collections import Counter

    rows: list[dict[str, Any]] = []
    for campaign in campaigns:
        if str(campaign.get("coverage_mode") or "") != "bapc":
            continue
        timeline_path = Path(str(campaign.get("artifact_path") or "")) / "metrics" / "coverage_timeline.jsonl"
        if not timeline_path.exists():
            continue
        completed = 0
        counts: Counter[str] = Counter()
        for line in _parse_jsonl(timeline_path):
            if int(line.get("completion_seq") or 0) <= 0:
                continue
            completed += 1
            reason = str(line.get("qualification_reason") or "(missing)")
            counts[reason] += 1
        if completed <= 0:
            continue
        universe = _load_campaign_bapc_universe(campaign)
        for reason in sorted(counts):
            count = int(counts[reason])
            rows.append({
                "schema_version": "1.0",
                "experiment_id": campaign["experiment_id"],
                "campaign_id": campaign["campaign_id"],
                "method": campaign["method"],
                "variant": campaign["variant"],
                "dut": campaign["dut"],
                "seed": campaign["seed"],
                "bapc_core_version": universe.get("bapc_core_version") or "",
                "bin_set_sha256": universe.get("bin_set_sha256") or "",
                "completed_cases": completed,
                "eligible_cases": int(campaign.get("eligible_cases") or 0),
                "eligible_bapc_cases": int(campaign.get("eligible_bapc_cases") or 0),
                "qualification_reason": reason,
                "count": count,
                "share_of_completed": count / completed,
            })
    return rows




def _build_campaign_row(experiment_id: str, campaign_dir: Path, meta: dict, lines: list[dict]) -> dict:
    last = lines[-1] if lines else {}
    return {
        "schema_version": "1.0",
        "experiment_id": experiment_id,
        "campaign_id": meta.get("campaign_id") or last.get("campaign_id", ""),
        "method": meta.get("method") or "pmpfuzz",
        "variant": meta.get("variant") or last.get("variant", ""),
        "generator_variant": meta.get("generator_variant") or last.get("generator_variant", ""),
        "dut": meta.get("dut") or last.get("dut", ""),
        "seed": meta.get("seed"),
        "coverage_mode": meta.get("coverage_mode") or "",
        "source_sha": meta.get("source_sha") or "",
        "source_tree_sha256": meta.get("source_tree_sha256") or "",
        "source_dirty": meta.get("source_dirty"),
        "dut_sha": meta.get("dut_sha") or "",
        "dut_binary_path": meta.get("dut_binary_path") or "",
        "dut_binary_sha256": meta.get("dut_binary_sha256") or "",
        "capability_fingerprint": meta.get("capability_fingerprint") or "",
        "experiment_protocol_id": meta.get("experiment_protocol_id") or "",
        "driver_mode": meta.get("driver_mode") or "",
        "coverage_schema": meta.get("coverage_schema") or "",
        "start_utc": meta.get("start_utc") or "",
        "end_utc": meta.get("end_utc") or "",
        "time_budget_seconds": meta.get("time_budget_seconds"),
        "wall_clock_horizon_seconds": meta.get("wall_clock_horizon_seconds"),
        "budget_class": meta.get("budget_class") or "primary-wall-clock",
        "run_class": meta.get("run_class") or "",
        "stop_reason": normalize_stop_reason(meta.get("stop_reason")),
        "convergence_enabled": meta.get("convergence_enabled"),
        "convergence_min_runtime_seconds": meta.get("convergence_min_runtime_seconds"),
        "convergence_confirmation_seconds": meta.get("convergence_confirmation_seconds"),
        "convergence_confirmation_eligible_cases": meta.get("convergence_confirmation_eligible_cases"),
        "max_wall_time_seconds": meta.get("max_wall_time_seconds"),
        "round_size": meta.get("round_size") or 0,
        "jobs": meta.get("jobs") or 1,
        "per_case_timeout_seconds": meta.get("per_case_timeout_seconds"),
        "completed_cases": last.get("completed_cases", 0),
        "eligible_cases": last.get("eligible_cases", 0),
        "eligible_hpm_cases": last.get("eligible_hpm_cases", 0),
        "eligible_bapc_cases": last.get("eligible_bapc_cases", 0),
        "semantic_target": last.get("semantic_target"),
        "pairwise_target": last.get("pairwise_target"),
        "triples_target": last.get("security_triples_target"),
        "predicates_target": last.get("predicates_target"),
        "hpm_target": last.get("hpm_target"),
        "bapc_target": last.get("bapc_target"),
        "semantic_covered": last.get("semantic_covered"),
        "pairwise_covered": last.get("pairwise_covered"),
        "triples_covered": last.get("security_triples_covered"),
        "predicates_covered": last.get("predicates_covered"),
        "hpm_covered": last.get("hpm_covered"),
        "bapc_covered": last.get("bapc_covered"),
        "semantic_final_rate": last.get("semantic_rate"),
        "pairwise_final_rate": last.get("pairwise_rate"),
        "triples_final_rate": last.get("security_triples_rate"),
        "predicates_final_rate": last.get("predicates_rate"),
        "hpm_final_rate": last.get("hpm_rate"),
        "bapc_final_rate": last.get("bapc_rate"),
        "artifact_path": str(campaign_dir),
    }


def _build_timeseries_row(
    experiment_id: str,
    campaign: dict,
    line: dict,
    *,
    coverage_mode: str | None = None,
) -> dict:
    coverage_mode = coverage_mode or campaign.get("coverage_mode", "semantic")
    covered_key = {
        "semantic": "semantic_covered",
        "pairwise": "pairwise_covered",
        "security-triples": "security_triples_covered",
        "predicates": "predicates_covered",
        "hpm": "hpm_covered",
        "bapc": "bapc_covered",
    }
    target_key = {
        "semantic": "semantic_target",
        "pairwise": "pairwise_target",
        "security-triples": "security_triples_target",
        "predicates": "predicates_target",
        "hpm": "hpm_target",
        "bapc": "bapc_target",
    }
    rate_key = {
        "semantic": "semantic_rate",
        "pairwise": "pairwise_rate",
        "security-triples": "security_triples_rate",
        "predicates": "predicates_rate",
        "hpm": "hpm_rate",
        "bapc": "bapc_rate",
    }
    if line.get("completion_seq", 0) == 0:
        return None

    new_bins_key = {
        "semantic": "new_semantic_bins",
        "pairwise": "new_pairwise_bins",
        "security-triples": "new_security_triple_bins",
        "predicates": "new_predicate_bins",
        "hpm": "new_hpm_bins",
        "bapc": "new_bapc_bins",
    }

    return {
        "schema_version": "1.0",
        "experiment_id": experiment_id,
        "campaign_id": campaign["campaign_id"],
        "method": campaign["method"],
        "variant": campaign["variant"],
        "generator_variant": campaign.get("generator_variant", ""),
        "dut": campaign["dut"],
        "seed": campaign["seed"],
        "coverage_mode": coverage_mode,
        "completion_seq": line.get("completion_seq", 0),
        "elapsed_wall_seconds": line.get("elapsed_wall_seconds", 0),
        "completed_cases": line.get("completed_cases", 0),
        "eligible_cases": line.get("eligible_cases", 0),
        "eligible_hpm_cases": line.get("eligible_hpm_cases", 0),
        "eligible_bapc_cases": line.get("eligible_bapc_cases", 0),
        "covered_bins": line.get(covered_key.get(coverage_mode, "semantic_covered"), 0),
        "target_bins": line.get(target_key.get(coverage_mode, "semantic_target"), 0),
        "coverage_rate": line.get(rate_key.get(coverage_mode, "semantic_rate")),
        "new_bins": line.get(new_bins_key.get(coverage_mode, "new_semantic_bins"), 0),
        "status": line.get("status") or "",
        "failure_class": line.get("failure_class") or "",
        "case_id": line.get("case_id") or "",
    }


def _coverage_final_row(campaign: dict) -> dict:
    return {
        "schema_version": "1.0",
        "experiment_id": campaign["experiment_id"],
        "campaign_id": campaign["campaign_id"],
        "method": campaign["method"],
        "variant": campaign["variant"],
        "generator_variant": campaign.get("generator_variant", ""),
        "dut": campaign["dut"],
        "seed": campaign["seed"],
        "coverage_mode": campaign["coverage_mode"],
        "covered_bin_count": campaign.get("bapc_covered"),
        "coverage_denominator": campaign.get("bapc_target"),
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
        "effective_eligible_cases": _effective_eligible_count(campaign),
    }


def _compute_thresholds(
    timeseries: list[dict],
    horizon_map: dict[str, dict[str, Any]] | None = None,
) -> list[dict]:
    from collections import defaultdict

    if horizon_map is None:
        horizon_map = {}

    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in timeseries:
        key = (row["campaign_id"], row["coverage_mode"])
        groups[key].append(row)

    thresholds = [0.25, 0.50, 0.75, 0.90, 1.0]
    result = []

    for (cid, cmode), rows in groups.items():
        rows.sort(key=lambda r: r["completion_seq"])
        hinfo = horizon_map.get(str(cid), {})
        T, _ = _normalize_horizon(hinfo.get("wall_clock_horizon_seconds"))

        target_bins = rows[0].get("target_bins", 0) if rows else 0
        has_valid_rates = any(
            r.get("coverage_rate") is not None and r.get("coverage_rate") != ""
            for r in rows
        )
        denominator_zero = int(target_bins) == 0 and not has_valid_rates

        for thresh in thresholds:
            if denominator_zero:
                result.append({
                    "schema_version": "1.0",
                    "experiment_id": rows[0]["experiment_id"],
                    "campaign_id": cid,
                    "method": rows[0]["method"],
                    "variant": rows[0]["variant"],
                    "dut": rows[0]["dut"],
                    "seed": rows[0]["seed"],
                    "coverage_mode": cmode,
                    "threshold": thresh,
                    "threshold_reached": False,
                    "elapsed_wall_seconds": "",
                    "completed_cases": "",
                    "eligible_cases": "",
                    "censored": True,
                    "censor_time_seconds": T,
                    "not_applicable": True,
                })
                continue

            reached = False
            for row in rows:
                rate = row.get("coverage_rate")
                if rate is not None and rate != "" and float(rate) >= thresh:
                    reached = True
                    result.append({
                        "schema_version": "1.0",
                        "experiment_id": rows[0]["experiment_id"],
                        "campaign_id": cid,
                        "method": rows[0]["method"],
                        "variant": rows[0]["variant"],
                        "dut": rows[0]["dut"],
                        "seed": rows[0]["seed"],
                        "coverage_mode": cmode,
                        "threshold": thresh,
                        "threshold_reached": True,
                        "elapsed_wall_seconds": row["elapsed_wall_seconds"],
                        "completed_cases": row["completed_cases"],
                        "eligible_cases": row["eligible_cases"],
                        "censored": False,
                        "censor_time_seconds": "",
                        "not_applicable": False,
                    })
                    break
            if not reached:
                result.append({
                    "schema_version": "1.0",
                    "experiment_id": rows[0]["experiment_id"],
                    "campaign_id": cid,
                    "method": rows[0]["method"],
                    "variant": rows[0]["variant"],
                    "dut": rows[0]["dut"],
                    "seed": rows[0]["seed"],
                    "coverage_mode": cmode,
                    "threshold": thresh,
                    "threshold_reached": False,
                    "elapsed_wall_seconds": "",
                    "completed_cases": "",
                    "eligible_cases": "",
                    "censored": True,
                    "censor_time_seconds": T,
                    "not_applicable": False,
                })

    return result


def _compute_statistics(campaigns: list[dict], timeseries: list[dict]) -> dict:
    import statistics as st
    from collections import defaultdict

    stats: dict[str, Any] = {
        "schema_version": "1.0",
        "total_campaigns": len(campaigns),
        "total_timeseries_rows": len(timeseries),
    }

    groups: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    for c in campaigns:
        for cmode, key in [("semantic", "semantic_final_rate"), ("pairwise", "pairwise_final_rate"),
                            ("security-triples", "triples_final_rate"), ("predicates", "predicates_final_rate"),
                            ("hpm", "hpm_final_rate"), ("bapc", "bapc_final_rate")]:
            rate = c.get(key)
            if rate is not None:
                groups[(c.get("method", ""), c.get("variant", ""), cmode)].append(rate)

    per_group = {}
    for (method, variant, cmode), rates in groups.items():
        if len(rates) >= 2:
            per_group[f"{method}/{variant}/{cmode}"] = {
                "n": len(rates),
                "median": st.median(rates),
                "q1": st.median(sorted(rates)[:len(rates)//2]) if len(rates) >= 4 else None,
                "q3": st.median(sorted(rates)[len(rates)//2:]) if len(rates) >= 4 else None,
                "mean": st.mean(rates),
                "min": min(rates),
                "max": max(rates),
            }

    stats["per_group"] = per_group
    return stats


def _compute_auc(
    timeseries: list[dict[str, Any]],
    horizon_map: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    from collections import defaultdict

    if horizon_map is None:
        horizon_map = {}

    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in timeseries:
        groups[(str(row["campaign_id"]), str(row["coverage_mode"]))].append(row)

    output: list[dict[str, Any]] = []
    for (cid, coverage_mode), rows in groups.items():
        first = rows[0]
        rows_sorted = sorted(
            rows,
            key=lambda item: (float(item["elapsed_wall_seconds"]),
                              int(item["completion_seq"])),
        )

        points: list[tuple[float, float]] = [(0.0, 0.0)]
        all_rates_null = True
        any_rate_valid = False
        for row in rows_sorted:
            rate = row.get("coverage_rate")
            if rate is None or rate == "":
                continue
            any_rate_valid = True
            all_rates_null = False
            points.append(
                (float(row["elapsed_wall_seconds"]), float(rate)))

        hinfo = horizon_map.get(str(cid), {})
        run_class = str(hinfo.get("run_class", ""))
        is_strict = run_class in _STRICT_RUN_CLASSES
        explicit_horizon = hinfo.get("wall_clock_horizon_seconds")
        T, horizon_err = _normalize_horizon(explicit_horizon)

        if T is not None:
            horizon_source = "explicit"
        elif is_strict:

            T = 0.0
            horizon_source = "invalid" if horizon_err else "missing"
        elif points[-1][0] > 0:
            T = points[-1][0]
            horizon_source = "last_point"
        else:
            T = 0.0
            horizon_source = "none"

        target_bins = rows_sorted[0].get("target_bins", 0) if rows_sorted else 0
        denominator_zero = (
            int(target_bins) == 0
            or (not any_rate_valid and int(target_bins) == 0)
        )

        base_row = {
            "schema_version": "1.0",
            "experiment_id": first["experiment_id"],
            "campaign_id": first["campaign_id"],
            "method": first["method"],
            "variant": first["variant"],
            "dut": first["dut"],
            "seed": first["seed"],
            "coverage_mode": coverage_mode,
        }

        if denominator_zero or T == 0.0:
            output.append({
                **base_row,
                "horizon_seconds": T if T > 0 else None,
                "auc": None,
                "normalized_auc": None,
                "horizon_source": horizon_source,
                "final_extension_seconds": None,
                "not_applicable": True,
            })
            continue

        if len(points) < 2:
            output.append({
                **base_row,
                "horizon_seconds": T,
                "auc": 0.0,
                "normalized_auc": 0.0,
                "horizon_source": horizon_source,
                "final_extension_seconds": T,
                "not_applicable": False,
            })
            continue

        area = 0.0
        for i in range(len(points) - 1):
            _x_curr, y_curr = points[i]
            x_next, _y_next = points[i + 1]
            area += y_curr * (x_next - points[i][0])

        last_x, last_y = points[-1]
        extension = max(0.0, T - last_x)
        area += last_y * extension

        output.append({
            **base_row,
            "horizon_seconds": T,
            "auc": area,
            "normalized_auc": area / T if T > 0 else None,
            "horizon_source": horizon_source,
            "final_extension_seconds": extension,
            "not_applicable": False,
        })

    return output


def _compute_overhead(
    campaigns: list[dict[str, Any]], timeseries: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    last_by_campaign: dict[str, dict[str, Any]] = {}
    for row in timeseries:
        campaign_id = str(row["campaign_id"])
        previous = last_by_campaign.get(campaign_id)
        if previous is None or int(row["completion_seq"]) > int(previous["completion_seq"]):
            last_by_campaign[campaign_id] = row

    rows: list[dict[str, Any]] = []
    for campaign in campaigns:
        last = last_by_campaign.get(str(campaign["campaign_id"]), {})
        wall = float(last.get("elapsed_wall_seconds") or 0.0)
        completed = int(last.get("completed_cases") or campaign.get("completed_cases") or 0)
        eligible = int(last.get("eligible_cases") or campaign.get("eligible_cases") or 0)
        eligible_hpm = int(last.get("eligible_hpm_cases") or campaign.get("eligible_hpm_cases") or 0)
        eligible_bapc = int(last.get("eligible_bapc_cases") or campaign.get("eligible_bapc_cases") or 0)
        rows.append({
            "schema_version": "1.0",
            "experiment_id": campaign["experiment_id"],
            "campaign_id": campaign["campaign_id"],
            "method": campaign["method"],
            "variant": campaign["variant"],
            "dut": campaign["dut"],
            "seed": campaign["seed"],
            "wall_seconds": wall,
            "completed_cases": completed,
            "eligible_cases": eligible,
            "eligible_hpm_cases": eligible_hpm,
            "eligible_bapc_cases": eligible_bapc,
            "effective_eligible_cases": _effective_eligible_count(campaign, last),
            "tests_per_second": completed / wall if wall > 0 else None,
            "jobs": campaign.get("jobs"),
        })
    return rows


def _normalize_horizon(value: Any) -> tuple[float | None, str | None]:
    if value is None:
        return None, "missing horizon"



    if isinstance(value, bool):
        return None, f"invalid horizon type bool (value={value})"

    try:
        f = float(value)
    except (ValueError, TypeError):
        return None, f"invalid non-numeric horizon: {value!r}"

    import math
    if not math.isfinite(f):
        return None, f"non-finite horizon: {value!r}"

    if f <= 0:
        return None, f"non-positive horizon: {f}"

    return f, None


def _validate_horizon_contract(
    campaigns: list[dict[str, Any]],
    timeseries_rows: list[dict[str, Any]],
    horizon_map: dict[str, dict[str, Any]],
) -> list[str]:
    errors: list[str] = []

    for c in campaigns:
        cid = str(c["campaign_id"])
        run_class = str(c.get("run_class", ""))
        is_strict = run_class in _STRICT_RUN_CLASSES

        T, horizon_err = _normalize_horizon(c.get("wall_clock_horizon_seconds"))

        if is_strict and horizon_err is not None:
            errors.append(
                f"horizon_invalid: campaign={cid} run_class={run_class} "
                f"{horizon_err}"
            )

        if T is not None:
            for row in timeseries_rows:
                if str(row.get("campaign_id", "")) == cid:
                    elapsed = float(row.get("elapsed_wall_seconds", 0) or 0)
                    if elapsed > T + 1e-9:
                        errors.append(
                            f"horizon_exceeded: campaign={cid} "
                            f"elapsed={elapsed}s exceeds horizon={T}s"
                        )
                        break



    budget_groups: dict[tuple[str, str, str], set[float]] = {}
    for c in campaigns:
        T, _ = _normalize_horizon(c.get("wall_clock_horizon_seconds"))
        if T is None:
            continue
        key = (
            str(c.get("experiment_id", "")),
            str(c.get("dut", "")),
            str(c.get("budget_class", "primary-wall-clock")),
        )
        budget_groups.setdefault(key, set()).add(T)

    for (exp_id, dut, bc), horizons in budget_groups.items():
        if len(horizons) > 1:
            errors.append(
                f"horizon_inconsistent_budget_class: experiment={exp_id} "
                f"dut={dut} budget_class={bc} has multiple horizons "
                f"across methods: {sorted(horizons)}"
            )

    return errors


def _data_dictionary() -> str:
    return """# PMPFuzz normalized evaluation data dictionary

All time values use seconds. Missing or non-applicable values are empty in CSV
and `null` in JSON. Synthetic `completion_seq=0` baseline rows are excluded from
normalized completion tables.

## normalized/campaigns.csv

One row per `(experiment_id, campaign_id)`. Records method, variant, DUT,
seed, version hashes, resource budget, final coverage, and artifact path.
Includes ``wall_clock_horizon_seconds`` (explicit frozen evaluation horizon),
``budget_class`` (comparison-group key, defaults to ``primary-wall-clock``),
and ``run_class`` for validation gating.

## normalized/coverage_timeseries.csv

One row per completed case and coverage mode. `elapsed_wall_seconds` is measured
from the campaign origin at actual case completion. `covered_bins` is cumulative;
`new_bins` is the increment from that completion. Only execution-qualified
results contribute coverage. Rows with `completion_seq=0` (synthetic baseline)
are excluded.

## normalized/security_event_timeseries.csv

One row per normalized DUT event. `completion_seq` refers to the completing
case; `event_index` distinguishes multiple events from the same case. Event IDs
must not depend on method name or case ID.

## aggregate tables

### coverage_auc.csv

Coverage AUC computed via **right-continuous step integration** (not trapezoidal).
Coverage is modelled as a step function: 0 before the first completion, jumping
to the observed rate at each completion time, holding that rate until the next
completion. The final observed rate extends to the explicit
``wall_clock_horizon_seconds`` (T).  AUC = sum(y_i * (t_{i+1} - t_i)) + y_n * (T - t_n).

Columns:
- ``horizon_seconds``: explicit T from campaign metadata.
- ``horizon_source``: ``explicit`` (from metadata) or ``last_point`` (fallback).
- ``final_extension_seconds``: T - last_data_time (0 if pool exhausted exactly at T).
- ``auc``: raw step-integral area under the coverage curve.
- ``normalized_auc``: auc / T (dimensionless, in [0, 1]).
- ``not_applicable``: ``True`` when denominator (target_bins) is 0 or missing;
  all rate/AUC fields are null in that case.

### coverage_threshold_times.csv

One row per (campaign, coverage_mode, threshold). Thresholds: 0.25, 0.50, 0.75, 0.90, 1.0.

- ``threshold_reached``: ``True`` if coverage rate >= threshold at any point.
- ``censored``: ``True`` if the threshold was not reached within the horizon.
- ``censor_time_seconds``: equals T (the explicit horizon) for censored rows.
- ``not_applicable``: ``True`` when denominator is 0; all coverage metrics
  are undefined.

### overhead.csv

Campaign wall time, throughput, and resource allocation.

### exclusions.csv

Predeclared campaign exclusions.
"""


def _validate_normalized_outputs(*paths: Path) -> dict[str, Any]:
    errors: list[str] = []
    checks: list[dict[str, Any]] = []
    for path in paths:
        exists = path.exists()
        checks.append({"name": f"exists:{path.name}", "passed": exists})
        if not exists:
            errors.append(f"missing output: {path}")

    csv_paths = [path for path in paths if path.suffix == ".csv" and path.exists()]
    for path in csv_paths:
        with path.open("r", encoding="ascii", newline="") as handle:
            list(csv.DictReader(handle))

    return {
        "schema_version": "1.0",
        "error_count": len(errors),
        "warning_count": 0,
        "errors": errors,
        "checks": checks,
        "valid": not errors,
    }


def _write_artifact_hashes(
    artifact_root: Path, paths: list[Path], output_path: Path
) -> None:
    unique = sorted({path.resolve() for path in paths if path.exists()})
    lines: list[str] = []
    for path in unique:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        relative = path.relative_to(artifact_root.resolve()).as_posix()
        lines.append(f"{digest.hexdigest()}  {relative}")
    output_path.write_text("\n".join(lines) + "\n", encoding="ascii")


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="ascii", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_csv_with_fields(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="ascii", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate evaluation results")
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--experiment-id", default="eval-v1")
    parser.add_argument(
        "--security-events-mode",
        choices=("full", "skip"),
        default="full",
    )
    args = parser.parse_args(argv)

    outputs = aggregate(
        args.artifact_root,
        args.experiment_id,
        security_events_mode=args.security_events_mode,
    )
    if not outputs:
        print("WARNING: no campaign data found")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
