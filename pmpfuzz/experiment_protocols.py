from __future__ import annotations

import math
from typing import Any, Iterable, Mapping

from pmpfuzz.stop_reasons import STOP_COVERAGE_CONVERGED, STOP_HARD_CAP_CENSORED


BAPC_CONVERGENCE_PROTOCOL_ID = "bapc-convergence-v1"

BAPC_CONVERGENCE_FORMAL = {
    "convergence_min_runtime_seconds": 0,
    "convergence_confirmation_seconds": 600,
    "convergence_confirmation_eligible_cases": 300,
    "max_wall_time_seconds": 7200,
    "time_budget_seconds": 7200,
    "wall_clock_horizon_seconds": 7200,
    "budget_class": "primary-wall-clock",
}

BAPC_FORMAL_RUN_CLASSES = frozenset({"formal", "baseline-formal"})
BAPC_FORMAL_VARIANTS = ("random-mutation", "bb-guided", "cascade")
BAPC_FORMAL_SEEDS = (4, 5, 6)

BAPC_FORMAL_ALLOWED_STOP_REASONS = frozenset(
    {
        STOP_COVERAGE_CONVERGED,
        STOP_HARD_CAP_CENSORED,
    }
)

BAPC_FORMAL_RUN_CLASS_BY_METHOD = {
    "pmpfuzz": "formal",
    "cascade": "baseline-formal",
}

_BAPC_FORMAL_ALLOWED_VALUE_LIST_FIELDS = {
    "source_sha": "allowed_source_shas",
    "source_tree_sha256": "allowed_source_tree_sha256s",
}

_BAPC_FORMAL_STRICT_CONTRACT_FIELDS = (
    "schema_version",
    "experiment_protocol_id",
    "dut",
    "coverage_mode",
    "bin_count",
    "bin_set_sha256",
    "variants",
    "seeds",
    "dut_sha",
    "dut_binary_sha256",
    "convergence_min_runtime_seconds",
    "convergence_confirmation_seconds",
    "convergence_confirmation_eligible_cases",
    "max_wall_time_seconds",
    "time_budget_seconds",
    "wall_clock_horizon_seconds",
    "budget_class",
)


def is_bapc_convergence_protocol(value: object) -> bool:
    return str(value or "") == BAPC_CONVERGENCE_PROTOCOL_ID


def is_bapc_formal_run_class(value: object) -> bool:
    return str(value or "").strip() in BAPC_FORMAL_RUN_CLASSES


def expected_bapc_formal_run_class(method: object) -> str | None:
    return BAPC_FORMAL_RUN_CLASS_BY_METHOD.get(str(method or "").strip())


def bapc_formal_variant_label(method: object, variant: object) -> str:
    method_name = str(method or "").strip()
    if method_name == "cascade":
        return "cascade"
    return str(variant or "").strip()


def build_bapc_convergence_contract(
    *,
    dut: str,
    bin_count: int,
    bin_set_sha256: str,
    variants: Iterable[str] | None = None,
    seeds: Iterable[int] | None = None,
    source_sha: str | None = None,
    source_tree_sha256: str | None = None,
    dut_sha: str | None = None,
    dut_binary_sha256: str | None = None,
    allowed_source_shas: Iterable[str] | None = None,
    allowed_source_tree_sha256s: Iterable[str] | None = None,
) -> dict[str, Any]:
    payload = {
        "schema_version": 1,
        "experiment_protocol_id": BAPC_CONVERGENCE_PROTOCOL_ID,
        "dut": str(dut),
        "coverage_mode": "bapc",
        "bin_count": int(bin_count),
        "bin_set_sha256": str(bin_set_sha256),
        "variants": sorted(
            {
                str(item)
                for item in (variants if variants is not None else BAPC_FORMAL_VARIANTS)
                if str(item)
            }
        ),
        "seeds": sorted(
            {int(item) for item in (seeds if seeds is not None else BAPC_FORMAL_SEEDS)}
        ),
    }
    if str(source_sha or ""):
        payload["source_sha"] = str(source_sha)
    if str(source_tree_sha256 or ""):
        payload["source_tree_sha256"] = str(source_tree_sha256)
    if str(dut_sha or ""):
        payload["dut_sha"] = str(dut_sha)
    if str(dut_binary_sha256 or ""):
        payload["dut_binary_sha256"] = str(dut_binary_sha256)
    if allowed_source_shas:
        payload["allowed_source_shas"] = sorted(
            {str(item) for item in allowed_source_shas if str(item)}
        )
    if allowed_source_tree_sha256s:
        payload["allowed_source_tree_sha256s"] = sorted(
            {str(item) for item in allowed_source_tree_sha256s if str(item)}
        )
    payload.update(BAPC_CONVERGENCE_FORMAL)
    return payload


def is_bapc_formal_contract(payload: Mapping[str, Any] | None) -> bool:
    if not isinstance(payload, Mapping):
        return False
    return (
        is_bapc_convergence_protocol(payload.get("experiment_protocol_id"))
        and str(payload.get("coverage_mode") or "") == "bapc"
    )


def is_bapc_formal_campaign(
    *,
    coverage_mode: object,
    experiment_protocol_id: object,
) -> bool:
    return str(coverage_mode or "") == "bapc" and is_bapc_convergence_protocol(experiment_protocol_id)


def is_bapc_formal_request(
    *,
    coverage_mode: object,
    run_class: object,
    experiment_protocol_id: object,
) -> bool:
    return (
        str(coverage_mode or "") == "bapc"
        and (
            is_bapc_formal_run_class(run_class)
            or is_bapc_convergence_protocol(experiment_protocol_id)
        )
    )


def allowed_bapc_formal_field_values(
    payload: Mapping[str, Any] | None,
    field: str,
) -> tuple[str, ...]:
    if not isinstance(payload, Mapping):
        return ()
    values: list[str] = []
    primary = str(payload.get(field) or "")
    if primary:
        values.append(primary)
    alt_field = _BAPC_FORMAL_ALLOWED_VALUE_LIST_FIELDS.get(field)
    if alt_field:
        raw = payload.get(alt_field) or []
        if isinstance(raw, Iterable) and not isinstance(raw, (str, bytes, bytearray)):
            values.extend(str(item) for item in raw if str(item))
    return tuple(dict.fromkeys(values))


def bapc_formal_contract_matches(
    existing: Mapping[str, Any] | None,
    expected: Mapping[str, Any] | None,
) -> bool:
    if not isinstance(existing, Mapping) or not isinstance(expected, Mapping):
        return False
    if not is_bapc_formal_contract(existing) or not is_bapc_formal_contract(expected):
        return dict(existing) == dict(expected)

    for field in _BAPC_FORMAL_STRICT_CONTRACT_FIELDS:
        if existing.get(field) != expected.get(field):
            return False

    for field in ("source_sha", "source_tree_sha256"):
        required = set(allowed_bapc_formal_field_values(expected, field))
        permitted = set(allowed_bapc_formal_field_values(existing, field))
        if required and not required.issubset(permitted):
            return False

    return True


def canonical_bapc_formal_runtime(*, enabled: bool = True) -> dict[str, Any]:
    payload = {
        "convergence_enabled": bool(enabled),
    }
    payload.update(BAPC_CONVERGENCE_FORMAL)
    return payload


def is_exact_bool(value: object) -> bool:
    return type(value) is bool


def is_exact_int(value: object) -> bool:
    return type(value) is int


def is_finite_real_number(value: object) -> bool:
    return type(value) in {int, float} and not isinstance(value, bool) and math.isfinite(float(value))


def typed_numeric_matches(value: object, expected: int | float) -> bool:
    return is_finite_real_number(value) and float(value) == float(expected)


def typed_int_matches(value: object, expected: int) -> bool:
    return is_exact_int(value) and int(value) == int(expected)
