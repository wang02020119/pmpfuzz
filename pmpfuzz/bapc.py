from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Iterable

from .coverage_universe import (
    load_coverage_universe,
    make_coverage_universe,
    validate_coverage_universe,
)
from .pmp import AddressMode, PmpEntry


BAPC_SCHEMA_VERSION = 2
BAPC_CORE_VERSION_V2 = "v2"
BAPC_CORE_VERSION_V3 = "v3"
BAPC_CORE_VERSION_V4 = "v4"
BAPC_GENERATION_RULE_VERSION_BY_CORE_VERSION = {
    BAPC_CORE_VERSION_V2: "bapc-core-universe-v2",
    BAPC_CORE_VERSION_V3: "bapc-core-universe-v3",
    BAPC_CORE_VERSION_V4: "bapc-core-universe-v4",
}
BAPC_GENERATION_RULE_VERSION = BAPC_GENERATION_RULE_VERSION_BY_CORE_VERSION[BAPC_CORE_VERSION_V2]
BAPC_BIN_COUNT_BY_CORE_VERSION = {
    BAPC_CORE_VERSION_V2: 208,
    BAPC_CORE_VERSION_V3: 129,
    BAPC_CORE_VERSION_V4: 144,
}
BAPC_TARGET = "black-box-architectural-pmp-target-operation"
_BAPC_CORE_BIN_FAMILIES = (
    "config",
    "stimulus",
    "decision",
    "privilege-decision",
    "mode-decision",
)
_PROBE_RE = re.compile(r"\bPMFUZZ_PROBE\b\s+(.*)")
_CASCADE_MEM_BASE = 0x80000000

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
_DECISION_MCAUSE_CLASSES = (
    "none",
    "instruction_access_fault",
    "load_access_fault",
    "store_access_fault",
    "instruction_page_fault",
    "load_page_fault",
    "store_page_fault",
    "other",
)
_ACCESS_FAULT_MCAUSE_CLASS = {
    "fetch": "instruction_access_fault",
    "load": "load_access_fault",
    "store": "store_access_fault",
}
_PAGE_FAULT_MCAUSE_CLASS = {
    "fetch": "instruction_page_fault",
    "load": "load_page_fault",
    "store": "store_page_fault",
}


def normalize_bapc_core_version(value: Any) -> str:
    text = str(value or BAPC_CORE_VERSION_V2).strip().lower()
    if text in {BAPC_CORE_VERSION_V2, BAPC_CORE_VERSION_V3, BAPC_CORE_VERSION_V4}:
        return text
    raise ValueError(f"unsupported BAPC core version {value!r}")


def infer_bapc_core_version(universe: dict[str, Any]) -> str:
    explicit = str(universe.get("bapc_core_version") or "").strip().lower()
    if explicit in {BAPC_CORE_VERSION_V2, BAPC_CORE_VERSION_V3, BAPC_CORE_VERSION_V4}:
        return explicit
    generation_rule_version = str(universe.get("generation_rule_version") or "").strip()
    for core_version, expected_rule_version in BAPC_GENERATION_RULE_VERSION_BY_CORE_VERSION.items():
        if generation_rule_version == expected_rule_version:
            return core_version
    raise ValueError(
        "legacy or incompatible BAPC coverage universe generation_rule_version; "
        f"expected one of {sorted(BAPC_GENERATION_RULE_VERSION_BY_CORE_VERSION.values())}"
    )


def build_bapc_core_family_bins(*, bapc_core_version: str = BAPC_CORE_VERSION_V2) -> dict[str, list[str]]:
    core_version = normalize_bapc_core_version(bapc_core_version)
    families: dict[str, list[str]] = {
        "config": [],
        "stimulus": [],
        "decision": [],
        "privilege-decision": [],
        "mode-decision": [],
    }
    if core_version == BAPC_CORE_VERSION_V2:
        for pmp_mode in ("off", "tor", "na4", "napot"):
            for permission_rwx in _permission_rwx_values():
                for locked in ("false", "true"):
                    families["config"].append(
                        f"family=config|pmp_mode={pmp_mode}|permission_rwx={permission_rwx}|locked={locked}"
                    )
        for privilege in ("m", "s", "u"):
            for effective_privilege in ("m", "s", "u"):
                for access in ("fetch", "load", "store"):
                    for translation in ("bare", "sv39"):
                        families["stimulus"].append(
                            "family=stimulus"
                            f"|privilege={privilege}"
                            f"|effective_privilege={effective_privilege}"
                            f"|access={access}"
                            f"|translation={translation}"
                        )
        for access in ("fetch", "load", "store"):
            for allow_or_deny in ("allow", "deny"):
                for mcause_class in _DECISION_MCAUSE_CLASSES:
                    families["decision"].append(
                        f"family=decision|access={access}|allow_or_deny={allow_or_deny}|mcause_class={mcause_class}"
                    )
    else:
        if core_version == BAPC_CORE_VERSION_V3:
            families["config"].append(
                "family=config|pmp_mode=off|permission_rwx=000|locked=false"
            )
        else:
            for permission_rwx in _permission_rwx_values():
                for locked in ("false", "true"):
                    families["config"].append(
                        f"family=config|pmp_mode=off|permission_rwx={permission_rwx}|locked={locked}"
                    )
        for pmp_mode in ("tor", "na4", "napot"):
            for permission_rwx in _permission_rwx_values():
                for locked in ("false", "true"):
                    families["config"].append(
                        f"family=config|pmp_mode={pmp_mode}|permission_rwx={permission_rwx}|locked={locked}"
                    )
        for privilege in ("m", "s", "u"):
            for translation in ("bare", "sv39"):
                families["stimulus"].append(
                    "family=stimulus"
                    f"|privilege={privilege}"
                    f"|effective_privilege={privilege}"
                    f"|access=fetch"
                    f"|translation={translation}"
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
                        families["stimulus"].append(
                            "family=stimulus"
                            f"|privilege={privilege}"
                            f"|effective_privilege={effective_privilege}"
                            f"|access={access}"
                            f"|translation={translation}"
                        )
        for access in ("fetch", "load", "store"):
            families["decision"].append(
                f"family=decision|access={access}|allow_or_deny=allow|mcause_class=none"
            )
            for mcause_class in (
                _ACCESS_FAULT_MCAUSE_CLASS[access],
                _PAGE_FAULT_MCAUSE_CLASS[access],
                "other",
            ):
                families["decision"].append(
                    f"family=decision|access={access}|allow_or_deny=deny|mcause_class={mcause_class}"
                )
    for effective_privilege in ("m", "s", "u"):
        for access in ("fetch", "load", "store"):
            for allow_or_deny in ("allow", "deny"):
                families["privilege-decision"].append(
                    "family=privilege-decision"
                    f"|effective_privilege={effective_privilege}"
                    f"|access={access}"
                    f"|allow_or_deny={allow_or_deny}"
                )
    for pmp_mode in ("off", "tor", "na4", "napot"):
        for access in ("fetch", "load", "store"):
            for allow_or_deny in ("allow", "deny"):
                families["mode-decision"].append(
                    f"family=mode-decision|pmp_mode={pmp_mode}|access={access}|allow_or_deny={allow_or_deny}"
                )
    return {family: sorted(values) for family, values in families.items()}


def build_bapc_core_bin_ids(*, bapc_core_version: str = BAPC_CORE_VERSION_V2) -> list[str]:
    families = build_bapc_core_family_bins(bapc_core_version=bapc_core_version)
    return sorted(
        item
        for family in _BAPC_CORE_BIN_FAMILIES
        for item in families[family]
    )


def build_bapc_coverage_universe(
    *,
    dut: str,
    generator_seed: int,
    supports_fault_stage: bool,
    supports_smepmp: bool,
    bapc_core_version: str = BAPC_CORE_VERSION_V2,
) -> dict[str, Any]:
    core_version = normalize_bapc_core_version(bapc_core_version)
    families = build_bapc_core_family_bins(bapc_core_version=core_version)
    bin_ids = build_bapc_core_bin_ids(bapc_core_version=core_version)
    return make_coverage_universe(
        coverage_mode="bapc",
        bin_ids=bin_ids,
        capability_fingerprint=(
            f"bapc:{dut.lower()}:fault-stage={int(bool(supports_fault_stage))}:smepmp={int(bool(supports_smepmp))}"
        ),
        target=BAPC_TARGET,
        include_experimental=False,
        generator_seed=generator_seed,
        generation_rule_version=BAPC_GENERATION_RULE_VERSION_BY_CORE_VERSION[core_version],
        extra_fields={
            "bapc_schema_version": BAPC_SCHEMA_VERSION,
            "bapc_core_version": core_version,
            "dut": str(dut),
            "capabilities": {
                "fault_stage": bool(supports_fault_stage),
                "smepmp": bool(supports_smepmp),
            },
            "bin_families": list(_BAPC_CORE_BIN_FAMILIES),
            "bapc_family_counts": {family: len(items) for family, items in families.items()},
            "supplemental_bin_families": (
                ["translation-stage"] if bool(supports_fault_stage) else []
            ),
        },
    )


def validate_bapc_coverage_universe(
    universe: dict[str, Any],
    *,
    expected_bapc_core_version: str | None = None,
) -> dict[str, Any]:
    validate_coverage_universe(universe)
    if str(universe.get("coverage_mode") or "") != "bapc":
        raise ValueError("coverage universe is not a BAPC universe")
    if int(universe.get("bapc_schema_version") or 0) != BAPC_SCHEMA_VERSION:
        raise ValueError(
            "legacy or incompatible BAPC coverage universe schema_version "
            f"{universe.get('bapc_schema_version')!r}; expected v{BAPC_SCHEMA_VERSION}"
        )
    core_version = infer_bapc_core_version(universe)
    if expected_bapc_core_version is not None:
        expected_core_version = normalize_bapc_core_version(expected_bapc_core_version)
        if core_version != expected_core_version:
            raise ValueError(
                f"unexpected BAPC core version {core_version!r}; expected {expected_core_version!r}"
            )
    expected_rule_version = BAPC_GENERATION_RULE_VERSION_BY_CORE_VERSION[core_version]
    if str(universe.get("generation_rule_version") or "") != expected_rule_version:
        raise ValueError(
            "legacy or incompatible BAPC coverage universe generation_rule_version; "
            f"expected {expected_rule_version}"
        )
    if str(universe.get("target") or "") != BAPC_TARGET:
        raise ValueError(f"unexpected BAPC target {universe.get('target')!r}")
    expected_bin_ids = build_bapc_core_bin_ids(bapc_core_version=core_version)
    expected_bin_count = BAPC_BIN_COUNT_BY_CORE_VERSION[core_version]
    if int(universe.get("bin_count") or -1) != expected_bin_count:
        raise ValueError(
            f"unexpected BAPC-core {core_version} bin_count {universe.get('bin_count')!r}; "
            f"expected {expected_bin_count}"
        )
    if list(universe.get("bin_ids") or []) != expected_bin_ids:
        raise ValueError(
            f"BAPC-core {core_version} universe bin_ids do not match the canonical definition"
        )
    if any("family=translation-stage" in str(item) for item in (universe.get("bin_ids") or [])):
        raise ValueError(f"BAPC-core {core_version} universe must not include translation-stage bins")
    return universe


def load_bapc_coverage_universe(
    path: Path | str,
    *,
    expected_bapc_core_version: str | None = None,
) -> dict[str, Any]:
    return validate_bapc_coverage_universe(
        load_coverage_universe(Path(path)),
        expected_bapc_core_version=expected_bapc_core_version,
    )


def summarize_bapc_for_pmpfuzz_case(
    case: dict[str, Any],
    result: dict[str, Any],
    *,
    log_text: str,
    supports_smepmp: bool | None = None,
    bapc_core_version: str = BAPC_CORE_VERSION_V2,
) -> dict[str, Any]:
    probe_events = parse_probe_events(log_text)
    context = {
        "translation": _normalize_translation(case.get("translation")),
        "mseccfg": dict(case.get("mseccfg") or {}),
        "pmp_entries": list(case.get("pmp_entries") or []),
        "default_privilege": case.get("privilege"),
        "default_access": case.get("access"),
        "default_size": _declared_access_size(case),
        "default_address": case.get("physical_address"),
        "default_mprv": case.get("mprv"),
        "default_mpp": case.get("mpp"),
        "supports_smepmp": (
            bool(supports_smepmp)
            if supports_smepmp is not None
            else bool(case.get("supports_smepmp"))
        ),
    }
    context["actual_pmpcfg_entries"] = _actual_pmpcfg_entries_from_probe_events(
        context,
        probe_events,
        raw_log_sha256=_text_sha256(log_text),
    )
    return _with_bapc_contract_metadata(
        summarize_bapc_target_operation(
            context,
            result,
            probe_events=probe_events,
            bapc_core_version=bapc_core_version,
        ),
        bapc_core_version=bapc_core_version,
    )


def summarize_bapc_for_cascade_execution(
    sidecar: dict[str, Any],
    result: dict[str, Any],
    *,
    stdout_text: str,
    supports_smepmp: bool | None = None,
    event_records: list[dict[str, Any]] | None = None,
    bapc_core_version: str = BAPC_CORE_VERSION_V2,
) -> dict[str, Any]:
    actual_csr_state = dict(sidecar.get("actual_csr_state") or {})
    context = {
        "translation": _normalize_translation(sidecar.get("translation")),
        "mseccfg": dict(sidecar.get("mseccfg") or {}),
        "pmp_entries": list(sidecar.get("pmp_entries") or []),
        "default_privilege": sidecar.get("privilege"),
        "default_access": sidecar.get("access"),
        "default_size": _declared_access_size(sidecar),
        "default_address": sidecar.get("physical_address"),
        "default_instruction_address": sidecar.get("instruction_address"),
        "default_mprv": (
            sidecar.get("mprv")
            if sidecar.get("mprv") is not None
            else _mstatus_mprv(actual_csr_state.get("mstatus"))
        ),
        "default_mpp": (
            sidecar.get("mpp")
            if sidecar.get("mpp") is not None
            else _mstatus_mpp(actual_csr_state.get("mstatus"))
        ),
        "supports_smepmp": (
            bool(supports_smepmp)
            if supports_smepmp is not None
            else bool(sidecar.get("supports_smepmp"))
        ),
        "target_operation_candidates": [
            dict(item) for item in (sidecar.get("target_operation_candidates") or []) if isinstance(item, dict)
        ],
        "runtime_event_records": [dict(item) for item in (event_records or []) if isinstance(item, dict)],
    }
    context["actual_pmpcfg_entries"] = _canonical_actual_pmpcfg_entries(
        list(sidecar.get("actual_pmpcfg_entries") or [])
    )
    probe_events = parse_probe_events(stdout_text)
    return _with_bapc_contract_metadata(
        summarize_bapc_runtime_events(
            context,
            result,
            probe_events=probe_events,
            bapc_core_version=bapc_core_version,
        ),
        bapc_core_version=bapc_core_version,
    )


def runtime_bapc_event_records_for_cascade_execution(
    sidecar: dict[str, Any],
    result: dict[str, Any],
    *,
    stdout_text: str,
    supports_smepmp: bool | None = None,
) -> list[dict[str, Any]]:
    actual_csr_state = dict(sidecar.get("actual_csr_state") or {})
    context = {
        "translation": _normalize_translation(sidecar.get("translation")),
        "mseccfg": dict(sidecar.get("mseccfg") or {}),
        "pmp_entries": list(sidecar.get("pmp_entries") or []),
        "default_privilege": sidecar.get("privilege"),
        "default_access": sidecar.get("access"),
        "default_size": _declared_access_size(sidecar),
        "default_address": sidecar.get("physical_address"),
        "default_instruction_address": sidecar.get("instruction_address"),
        "default_mprv": (
            sidecar.get("mprv")
            if sidecar.get("mprv") is not None
            else _mstatus_mprv(actual_csr_state.get("mstatus"))
        ),
        "default_mpp": (
            sidecar.get("mpp")
            if sidecar.get("mpp") is not None
            else _mstatus_mpp(actual_csr_state.get("mstatus"))
        ),
        "supports_smepmp": (
            bool(supports_smepmp)
            if supports_smepmp is not None
            else bool(sidecar.get("supports_smepmp"))
        ),
        "target_operation_candidates": [
            dict(item) for item in (sidecar.get("target_operation_candidates") or []) if isinstance(item, dict)
        ],
    }
    return _runtime_event_records_from_probe_events(
        context,
        result,
        probe_events=parse_probe_events(stdout_text),
    )


def parse_probe_events(text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in str(text or "").splitlines():
        match = _PROBE_RE.search(line)
        if not match:
            continue
        fields: dict[str, str] = {}
        for token in match.group(1).split():
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            fields[key.strip()] = value.strip().rstrip(",")
        events.append({"kind": "source_probe", "fields": fields})
    return events


def _with_bapc_contract_metadata(
    payload: dict[str, Any],
    *,
    bapc_core_version: str,
) -> dict[str, Any]:
    return {
        **payload,
        "bapc_schema_version": BAPC_SCHEMA_VERSION,
        "bapc_core_version": normalize_bapc_core_version(bapc_core_version),
    }


def map_bapc_normalized_record(
    record: dict[str, Any],
    *,
    bapc_core_version: str = BAPC_CORE_VERSION_V2,
) -> dict[str, Any]:
    core_version = normalize_bapc_core_version(bapc_core_version)
    if core_version == BAPC_CORE_VERSION_V2:
        return map_bapc_normalized_record_v2(record)
    if core_version == BAPC_CORE_VERSION_V3:
        return map_bapc_normalized_record_v3(record)
    return map_bapc_normalized_record_v4(record)


def map_bapc_normalized_record_v2(record: dict[str, Any]) -> dict[str, Any]:
    return _map_bapc_normalized_record(record, bapc_core_version=BAPC_CORE_VERSION_V2)


def map_bapc_normalized_record_v3(record: dict[str, Any]) -> dict[str, Any]:
    return _map_bapc_normalized_record(record, bapc_core_version=BAPC_CORE_VERSION_V3)


def map_bapc_normalized_record_v4(record: dict[str, Any]) -> dict[str, Any]:
    return _map_bapc_normalized_record(record, bapc_core_version=BAPC_CORE_VERSION_V4)


def _map_bapc_normalized_record(
    record: dict[str, Any],
    *,
    bapc_core_version: str,
) -> dict[str, Any]:
    pmp_entries = list(record.get("pmp_entries") or [])
    if not pmp_entries:
        return _ineligible("missing-pmp-context")

    translation = _normalize_translation(record.get("translation"))
    if translation not in {"bare", "sv39"}:
        return _ineligible("missing-translation")

    privilege = _normalize_privilege(record.get("privilege"))
    if privilege is None:
        return _ineligible("missing-actual-privilege")

    access = _normalize_access(record.get("access"))
    if access is None:
        return _ineligible("missing-actual-access")

    size = _parse_int(record.get("size"))
    if size is None or size <= 0:
        return _ineligible("missing-actual-size")

    address = _parse_int(record.get("address"))
    if address is None:
        return _ineligible("missing-actual-address")

    allow_or_deny = str(record.get("allow_or_deny") or "").strip().lower()
    if allow_or_deny not in {"allow", "deny"}:
        return _ineligible("missing-actual-outcome")

    mcause_class = _normalize_mcause_class_token(
        record.get("mcause_class"),
        allow_or_deny,
        access=access,
        translation=translation,
        bapc_core_version=bapc_core_version,
    )
    if mcause_class is None:
        return _ineligible("missing-actual-mcause-class")

    effective_privilege = _effective_privilege(
        privilege=privilege,
        access=access,
        mprv=bool(record.get("mprv")),
        mpp=_normalize_privilege(record.get("mpp")) or "m",
    )
    matched_entry = _first_matching_entry(pmp_entries, address, size=size)
    pmp_mode = _entry_mode(matched_entry)
    actual_pmpcfg_entries = _actual_pmpcfg_entries_for_core_version(
        record,
        bapc_core_version=bapc_core_version,
    )
    config_entries = _context_config_entries(
        pmp_entries,
        actual_pmpcfg_entries=actual_pmpcfg_entries,
        bapc_core_version=bapc_core_version,
    )
    observed_bins: set[str] = set()
    for entry in config_entries:
        observed_bins.add(
            "family=config"
            f"|pmp_mode={entry['pmp_mode']}"
            f"|permission_rwx={entry['permission_rwx']}"
            f"|locked={entry['locked']}"
        )
    observed_bins.add(
        "family=stimulus"
        f"|privilege={privilege}"
        f"|effective_privilege={effective_privilege}"
        f"|access={access}"
        f"|translation={translation}"
    )
    observed_bins.add(
        f"family=decision|access={access}|allow_or_deny={allow_or_deny}|mcause_class={mcause_class}"
    )
    observed_bins.add(
        "family=privilege-decision"
        f"|effective_privilege={effective_privilege}"
        f"|access={access}"
        f"|allow_or_deny={allow_or_deny}"
    )
    observed_bins.add(
        f"family=mode-decision|pmp_mode={pmp_mode}|access={access}|allow_or_deny={allow_or_deny}"
    )
    normalized_record = {
        "address": f"0x{address:x}",
        "privilege": privilege,
        "effective_privilege": effective_privilege,
        "access": access,
        "size": size,
        "translation": translation,
        "allow_or_deny": allow_or_deny,
        "mcause_class": mcause_class,
        "matched_pmp_mode": pmp_mode,
        "mprv": bool(record.get("mprv")),
        "mpp": _normalize_privilege(record.get("mpp")) or "m",
        "pmp_entries": _canonical_pmp_entries(pmp_entries),
        "config_entries": config_entries,
    }
    if actual_pmpcfg_entries:
        normalized_record["actual_pmpcfg_entries"] = actual_pmpcfg_entries
    return {
        "eligible": True,
        "qualification_reason": "eligible",
        "observed_bins": sorted(observed_bins),
        "normalized_record": normalized_record,
    }


def summarize_bapc_target_operation(
    context: dict[str, Any],
    result: dict[str, Any],
    *,
    probe_events: list[dict[str, Any]] | None = None,
    bapc_core_version: str = BAPC_CORE_VERSION_V2,
) -> dict[str, Any]:
    if not bool(result.get("observation_valid")):
        return _ineligible("missing-actual-observation")
    if not context.get("pmp_entries"):
        return _ineligible("missing-pmp-context")

    translation = context.get("translation")
    if translation not in {"bare", "sv39"}:
        return _ineligible("missing-translation")
    allow_or_deny = _allow_or_deny(result)
    if allow_or_deny is None:
        return _ineligible("missing-actual-outcome")

    runtime_record = _select_runtime_event_record(
        result,
        context.get("runtime_event_records") or [],
    )

    privilege = _normalize_privilege(context.get("default_privilege"))
    if privilege is None and runtime_record is not None:
        privilege = _normalize_privilege(runtime_record.get("privilege"))
    if privilege is None:
        return _ineligible("missing-actual-privilege")

    access = _normalize_access(context.get("default_access"))
    if access is None and runtime_record is not None:
        access = _normalize_access(runtime_record.get("access"))
    if access is None:
        return _ineligible("missing-actual-access")

    size = _parse_int(context.get("default_size"))
    if size is None and runtime_record is not None:
        size = _parse_int(runtime_record.get("size"))
    if size is None or size <= 0:
        return _ineligible("missing-actual-size")

    address = _parse_int(context.get("default_address"))
    if address is None and runtime_record is not None:
        address = _parse_int(runtime_record.get("address"))
    if address is None:
        return _ineligible("missing-actual-address")
    mcause_class = _target_mcause_class(result, allow_or_deny=allow_or_deny, access=access)
    mapped = map_bapc_normalized_record(
        {
            "pmp_entries": context.get("pmp_entries") or [],
            "actual_pmpcfg_entries": context.get("actual_pmpcfg_entries") or [],
            "translation": translation,
            "privilege": privilege,
            "access": access,
            "size": size,
            "address": address,
            "mprv": bool(context.get("default_mprv")),
            "mpp": _normalize_privilege(context.get("default_mpp")) or "m",
            "allow_or_deny": allow_or_deny,
            "mcause_class": mcause_class,
        },
        bapc_core_version=bapc_core_version,
    )
    if not mapped["eligible"]:
        return mapped
    return {
        "eligible": True,
        "qualification_reason": "eligible",
        "observed_bins": list(mapped["observed_bins"]),
        "event_records": [dict(mapped["normalized_record"])],
        "ignored_probe_events": len(probe_events or []),
    }


def summarize_bapc_runtime_events(
    context: dict[str, Any],
    result: dict[str, Any],
    *,
    probe_events: list[dict[str, Any]] | None = None,
    bapc_core_version: str = BAPC_CORE_VERSION_V2,
) -> dict[str, Any]:
    runtime_event_records = [
        dict(item)
        for item in (context.get("runtime_event_records") or [])
        if isinstance(item, dict)
    ]
    if _requires_concrete_runtime_deny_record(result):
        deny_runtime_records = [
            record
            for record in runtime_event_records
            if str(record.get("allow_or_deny") or "").strip().lower() == "deny"
        ]
        if deny_runtime_records:
            runtime_event_records = deny_runtime_records
        elif not runtime_event_records:
            return _ineligible("missing-actual-runtime-record")
    if not runtime_event_records:
        return summarize_bapc_target_operation(
            context,
            result,
            probe_events=probe_events,
            bapc_core_version=bapc_core_version,
        )

    observed_bins: set[str] = set()
    witness_records: list[dict[str, Any]] = []
    eligible_runtime_records = 0
    for runtime_record in runtime_event_records:
        mapped = map_bapc_normalized_record(
            {
                "pmp_entries": context.get("pmp_entries") or [],
                "actual_pmpcfg_entries": context.get("actual_pmpcfg_entries") or [],
                "translation": runtime_record.get("translation") or context.get("translation"),
                "privilege": runtime_record.get("privilege"),
                "access": runtime_record.get("access"),
                "size": runtime_record.get("size") if runtime_record.get("size") is not None else context.get("default_size"),
                "address": runtime_record.get("address"),
                "mprv": bool(context.get("default_mprv")),
                "mpp": _normalize_privilege(context.get("default_mpp")) or "m",
                "allow_or_deny": runtime_record.get("allow_or_deny"),
                "mcause_class": runtime_record.get("mcause_class"),
            },
            bapc_core_version=bapc_core_version,
        )
        if not mapped["eligible"]:
            continue
        eligible_runtime_records += 1
        mapped_bins = set(str(item) for item in (mapped.get("observed_bins") or []))
        new_bins = mapped_bins - observed_bins
        observed_bins.update(mapped_bins)
        if new_bins:
            witness_records.append(dict(mapped["normalized_record"]))

    if not observed_bins:
        return summarize_bapc_target_operation(
            context,
            result,
            probe_events=probe_events,
            bapc_core_version=bapc_core_version,
        )

    ignored_probe_events = max(len(probe_events or []) - eligible_runtime_records, 0)
    return {
        "eligible": True,
        "qualification_reason": "eligible",
        "observed_bins": sorted(observed_bins),
        "event_records": witness_records,
        "ignored_probe_events": ignored_probe_events,
    }


def _requires_concrete_runtime_deny_record(result: dict[str, Any]) -> bool:
    if str(result.get("observed_event") or "").strip().lower() != "trap":
        return False
    if result.get("observed_mcause") is not None:
        return False
    if result.get("observed_fault_address") is not None:
        return False
    if str(result.get("observed_stage") or "").strip():
        return False
    return True


def _permission_rwx_values() -> Iterable[str]:
    for value in range(8):
        yield f"{value:03b}"


def _context_config_entries(
    entries: list[dict[str, Any]],
    *,
    actual_pmpcfg_entries: list[dict[str, Any]] | None = None,
    bapc_core_version: str = BAPC_CORE_VERSION_V2,
) -> list[dict[str, str]]:
    core_version = normalize_bapc_core_version(bapc_core_version)
    actual_off_entries = _actual_off_entry_map(actual_pmpcfg_entries or []) if core_version == BAPC_CORE_VERSION_V4 else {}
    normalized: list[dict[str, str]] = []
    for raw in entries:
        entry_index = int(_parse_int(raw.get("index")) or 0)
        mode = _normalize_mode(raw.get("address_mode"))
        if mode == "off":
            if entry_index in actual_off_entries:
                normalized.append(dict(actual_off_entries[entry_index]))
            else:
                normalized.append({"pmp_mode": "off", "permission_rwx": "000", "locked": "false"})
            continue
        normalized.append(
            {
                "pmp_mode": mode,
                "permission_rwx": _permission_rwx_for_entry(raw),
                "locked": _bool_text(raw.get("locked")),
            }
        )
    return normalized or [{"pmp_mode": "off", "permission_rwx": "000", "locked": "false"}]


def _actual_pmpcfg_entries_for_core_version(
    record: dict[str, Any],
    *,
    bapc_core_version: str,
) -> list[dict[str, Any]]:
    if normalize_bapc_core_version(bapc_core_version) != BAPC_CORE_VERSION_V4:
        return []
    return _canonical_actual_pmpcfg_entries(list(record.get("actual_pmpcfg_entries") or []))


def _canonical_actual_pmpcfg_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for raw in entries:
        if not isinstance(raw, dict):
            continue
        if _normalize_mode(raw.get("address_mode")) != "off":
            continue
        evidence_kind = _normalize_off_state_evidence_kind(raw.get("evidence_kind"))
        index = _strict_nonnegative_int(raw.get("index"))
        read = _strict_bool(raw.get("read"))
        write = _strict_bool(raw.get("write"))
        execute = _strict_bool(raw.get("execute"))
        locked = _strict_bool(raw.get("locked"))
        raw_log_sha256 = _normalize_sha256(raw.get("raw_log_sha256"))
        if None in (evidence_kind, index, read, write, execute, locked, raw_log_sha256):
            continue
        item: dict[str, Any] = {
            "index": index,
            "address_mode": "off",
            "read": read,
            "write": write,
            "execute": execute,
            "locked": locked,
            "evidence_kind": evidence_kind,
            "raw_log_sha256": raw_log_sha256,
        }
        reset_id = str(raw.get("reset_id") or "").strip()
        if reset_id:
            item["reset_id"] = reset_id
        source_artifact = str(raw.get("source_artifact") or "").strip()
        if source_artifact:
            item["source_artifact"] = source_artifact
        normalized.append(item)
    return normalized


def _actual_pmpcfg_entries_from_probe_events(
    context: dict[str, Any],
    probe_events: list[dict[str, Any]] | None,
    *,
    raw_log_sha256: str,
) -> list[dict[str, Any]]:
    actual_by_index: dict[int, dict[str, Any]] = {}
    off_indices = _off_context_entry_indices(context.get("pmp_entries") or [])
    for event in probe_events or []:
        fields = dict((event or {}).get("fields") or {})
        chain = str(fields.get("chain") or event.get("chain") or "").strip().lower()
        if chain != "pmp-csr":
            continue
        cfg_value = _parse_int(fields.get("cfg") or fields.get("pmpcfg"))
        if cfg_value is None:
            continue
        entry_index = _probe_event_entry_index(fields, context)
        if entry_index is None or entry_index not in off_indices:
            continue
        actual = _cfg_value_to_actual_pmpcfg_entry(
            index=entry_index,
            cfg_value=cfg_value,
            evidence_kind="trace-observed",
            raw_log_sha256=raw_log_sha256,
        )
        if actual is not None:
            actual_by_index[entry_index] = actual
    return [actual_by_index[index] for index in sorted(actual_by_index)]


def _off_context_entry_indices(entries: list[dict[str, Any]]) -> set[int]:
    indices: set[int] = set()
    for raw in entries:
        if _normalize_mode(raw.get("address_mode")) != "off":
            continue
        index = _parse_int(raw.get("index"))
        if index is None or index < 0:
            continue
        indices.add(int(index))
    return indices


def _probe_event_entry_index(fields: dict[str, Any], context: dict[str, Any]) -> int | None:
    index = _parse_int(fields.get("entry") or fields.get("index"))
    if index is not None and index >= 0:
        return int(index)
    off_indices = sorted(_off_context_entry_indices(context.get("pmp_entries") or []))
    if off_indices == [0]:
        return 0
    return None


def _cfg_value_to_actual_pmpcfg_entry(
    *,
    index: int,
    cfg_value: int,
    evidence_kind: str,
    raw_log_sha256: str,
) -> dict[str, Any] | None:
    if index < 0:
        return None
    raw_cfg = int(cfg_value) & 0xFF
    if ((raw_cfg >> 3) & 0x3) != 0:
        return None
    digest = _normalize_sha256(raw_log_sha256)
    if digest is None:
        return None
    return {
        "index": index,
        "address_mode": "off",
        "read": bool(raw_cfg & 0x1),
        "write": bool(raw_cfg & 0x2),
        "execute": bool(raw_cfg & 0x4),
        "locked": bool(raw_cfg & 0x80),
        "evidence_kind": evidence_kind,
        "raw_log_sha256": digest,
    }


def _actual_off_entry_map(entries: list[dict[str, Any]]) -> dict[int, dict[str, str]]:
    actual: dict[int, dict[str, str]] = {}
    for raw in entries:
        actual[int(raw["index"])] = {
            "pmp_mode": "off",
            "permission_rwx": _permission_rwx_for_entry(raw),
            "locked": _bool_text(raw.get("locked")),
        }
    return actual


def _normalize_off_state_evidence_kind(value: Any) -> str | None:
    text = str(value or "").strip().lower().replace("_", "-").replace(" ", "-")
    if text in {"csr-readback", "trace-observed", "off-state-replay-artifact"}:
        return text
    return None


def _strict_nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0:
        return None
    return value


def _strict_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _normalize_sha256(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", text):
        return text
    return None


def _text_sha256(text: str) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8")).hexdigest()


def _permission_rwx_for_entry(entry: dict[str, Any]) -> str:
    return "".join(
        "1" if bool(entry.get(field)) else "0"
        for field in ("read", "write", "execute")
    )


def _normalize_mode(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"off", "tor", "na4", "napot"}:
        return text
    return "off"


def _normalize_translation(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if text in {"bare", "sv39"}:
        return text
    return None


def _normalize_privilege(value: Any) -> str | None:
    if value is None:
        return None
    return _PRIV_MAP.get(str(value).strip().lower())


def _normalize_access(value: Any) -> str | None:
    if isinstance(value, dict):
        explicit = str(value.get("access") or "").strip().lower()
        if explicit in {"fetch", "load", "store"}:
            return explicit
        access_flags = {
            "load": _probe_bool(value.get("r")),
            "store": _probe_bool(value.get("w")),
            "fetch": _probe_bool(value.get("x")),
        }
        asserted = [name for name, enabled in access_flags.items() if enabled is True]
        if len(asserted) == 1:
            return asserted[0]
        return None
    text = str(value or "").strip().lower()
    if text in {"fetch", "load", "store"}:
        return text
    if text == "0":
        return "load"
    if text == "1":
        return "store"
    if text == "2":
        return "fetch"
    return None


def _declared_access_size(record: dict[str, Any]) -> Any:
    if record.get("size") is not None:
        return record.get("size")
    scenario_spec = record.get("scenario_spec")
    if isinstance(scenario_spec, dict):
        probe = scenario_spec.get("probe")
        if isinstance(probe, dict) and probe.get("size") is not None:
            return probe.get("size")
    candidates = record.get("target_operation_candidates")
    if isinstance(candidates, list) and len(candidates) == 1 and isinstance(candidates[0], dict):
        return candidates[0].get("size")
    return None


def _normalize_mcause_class_token(
    value: Any,
    allow_or_deny: str,
    *,
    access: str | None = None,
    translation: str | None = None,
    bapc_core_version: str = BAPC_CORE_VERSION_V2,
) -> str | None:
    core_version = normalize_bapc_core_version(bapc_core_version)
    text = str(value or "").strip().lower()
    if core_version == BAPC_CORE_VERSION_V2:
        if allow_or_deny == "allow" and text == "":
            return "none"
        if text in _DECISION_MCAUSE_CLASSES:
            return text
        return None
    if allow_or_deny == "allow":
        if text in {"", "none"}:
            return "none"
        return None
    if text in {"", "none"}:
        return None
    if text in _DECISION_MCAUSE_CLASSES and text in _legal_deny_mcause_classes(
        access=access,
        translation=translation,
    ):
        return text
    return None


def _legal_deny_mcause_classes(
    *,
    access: str | None,
    translation: str | None,
) -> set[str]:
    normalized_access = _normalize_access(access)
    normalized_translation = _normalize_translation(translation)
    if normalized_access is None:
        return {"other"}
    allowed = {
        _ACCESS_FAULT_MCAUSE_CLASS[normalized_access],
        "other",
    }
    if normalized_translation == "sv39":
        allowed.add(_PAGE_FAULT_MCAUSE_CLASS[normalized_access])
    return allowed


def _canonical_pmp_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for raw in entries:
        pmpaddr = _parse_int(raw.get("pmpaddr"))
        normalized.append(
            {
                "index": int(_parse_int(raw.get("index")) or 0),
                "address_mode": _normalize_mode(raw.get("address_mode")),
                "pmpaddr": f"0x{(pmpaddr if pmpaddr is not None else 0):x}",
                "read": bool(raw.get("read")),
                "write": bool(raw.get("write")),
                "execute": bool(raw.get("execute")),
                "locked": bool(raw.get("locked")),
            }
        )
    return normalized


def _allow_or_deny(result: dict[str, Any]) -> str | None:
    event = str(result.get("observed_event") or "").strip().lower()
    if event == "completion":
        return "allow"
    if event == "trap":
        return "deny"
    status = str(result.get("status") or "").strip().lower()
    if status == "pass":
        return "allow"
    if status in {"fail", "inconclusive"}:
        return "deny"
    return None


def _event_allow_or_deny(fields: dict[str, str], access: str | None) -> str | None:
    explicit = _probe_bool(fields.get("allow") or fields.get("allowed"))
    if explicit is not None:
        return "allow" if explicit else "deny"
    if access == "load":
        permission = _probe_bool(fields.get("r"))
    elif access == "store":
        permission = _probe_bool(fields.get("w"))
    elif access == "fetch":
        permission = _probe_bool(fields.get("x"))
    else:
        permission = None
    if permission is None:
        return None
    return "allow" if permission else "deny"


def _ptw_response_allow_or_deny(fields: dict[str, str]) -> str | None:
    explicit = _event_allow_or_deny(fields, "load")
    if explicit is not None:
        return explicit
    for key in ("exception", "ae_ptw", "ae_final"):
        value = _probe_bool(fields.get(key))
        if value is not None:
            return "deny" if value else "allow"
    return None


def _mcause_class(value: Any, allow_or_deny: str) -> str:
    if allow_or_deny == "allow":
        return "none"
    parsed = _parse_int(value)
    if parsed is None:
        return "other"
    return _MCAUSE_CLASS.get(parsed, "other")


def _target_mcause_class(result: dict[str, Any], *, allow_or_deny: str, access: str) -> str:
    result_class = _mcause_class(result.get("observed_mcause"), allow_or_deny)
    if allow_or_deny == "allow" or result_class != "other":
        return result_class
    return _ACCESS_FAULT_MCAUSE_CLASS.get(access, "other")


def _event_mcause_class(
    result: dict[str, Any],
    fields: dict[str, str],
    *,
    allow_or_deny: str,
    access: str,
    allow_result_fallback: bool,
) -> str:
    if allow_or_deny == "allow":
        return "none"
    parsed = _parse_int(fields.get("mcause"))
    if parsed is not None:
        return _MCAUSE_CLASS.get(parsed, "other")
    if allow_result_fallback:
        result_class = _mcause_class(result.get("observed_mcause"), allow_or_deny)
        if result_class != "other":
            return result_class
    return {
        "fetch": "instruction_access_fault",
        "load": "load_access_fault",
        "store": "store_access_fault",
    }.get(access, "other")


def _fault_stage(result: dict[str, Any], fields: dict[str, str], allow_or_deny: str) -> str:
    if allow_or_deny == "allow":
        return "none"
    stage = str(fields.get("stage") or result.get("observed_stage") or "").strip().lower()
    if "ptw" in stage:
        return "ptw"
    return "final"


def _effective_privilege(*, privilege: str, access: str, mprv: bool, mpp: str) -> str:
    if privilege == "m" and mprv and access in {"load", "store"}:
        return mpp
    return privilege


def _runtime_event_translation(default_translation: str, fields: dict[str, str]) -> str:
    stage = str(fields.get("stage") or "").strip().lower()
    if "ptw" in stage:
        return "sv39"
    return default_translation


def _cascade_declared_target_addresses(
    *,
    physical_address: Any,
    instruction_address: Any,
) -> set[int]:
    address = _parse_int(physical_address)
    if address is None:
        return set()
    addresses = {address}
    instruction = _parse_int(instruction_address)
    if address < _CASCADE_MEM_BASE and instruction is not None and instruction >= _CASCADE_MEM_BASE:
        addresses.add(_CASCADE_MEM_BASE + address)
    return addresses


def _runtime_event_declared_target_addresses(context: dict[str, Any]) -> set[int]:
    addresses = _cascade_declared_target_addresses(
        physical_address=context.get("default_address"),
        instruction_address=context.get("default_instruction_address"),
    )
    for item in context.get("target_operation_candidates") or []:
        if not isinstance(item, dict):
            continue
        addresses.update(
            _cascade_declared_target_addresses(
                physical_address=item.get("physical_address"),
                instruction_address=item.get("instruction_address"),
            )
        )
    return addresses


def _runtime_event_matches_declared_target(
    context: dict[str, Any],
    fields: dict[str, str],
    *,
    address: int,
) -> bool:
    stage = str(fields.get("stage") or "").strip().lower()
    if "ptw" in stage:
        return True
    target_addresses = _runtime_event_declared_target_addresses(context)
    if target_addresses and address not in target_addresses:
        return False
    return True


def _build_runtime_record(
    *,
    context: dict[str, Any],
    result: dict[str, Any],
    fields: dict[str, str],
    seq: int,
    privilege: str,
    access: str,
    address: int,
    size: int | None,
    allow_or_deny: str,
    translation: str,
) -> dict[str, Any]:
    mpp = _normalize_privilege(context.get("default_mpp")) or "m"
    return {
        "address": f"0x{address:x}",
        "privilege": privilege,
        "effective_privilege": _effective_privilege(
            privilege=privilege,
            access=access,
            mprv=bool(context.get("default_mprv")),
            mpp=mpp,
        ),
        "access": access,
        "size": size,
        "translation": translation,
        "allow_or_deny": allow_or_deny,
        "mcause_class": _event_mcause_class(
            result,
            fields,
            allow_or_deny=allow_or_deny,
            access=access,
            allow_result_fallback=True,
        ),
        "fault_stage": _fault_stage(result, fields, allow_or_deny),
        "_seq": seq,
    }


def _runtime_event_records_from_probe_events(
    context: dict[str, Any],
    result: dict[str, Any],
    *,
    probe_events: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    translation = _normalize_translation(context.get("translation"))
    if translation not in {"bare", "sv39"}:
        return records
    for seq, event in enumerate(probe_events or []):
        fields = dict((event or {}).get("fields") or {})
        chain = str(fields.get("chain") or event.get("chain") or "").strip().lower()
        if chain == "pmp-check":
            privilege = _normalize_privilege(
                fields.get("prv") or fields.get("priv") or fields.get("privilege")
            )
            access = _normalize_access(fields.get("access"))
            address = _parse_int(fields.get("addr") or fields.get("paddr"))
            if privilege is None or access is None or address is None:
                continue
            if not _runtime_event_matches_declared_target(
                context,
                fields,
                address=address,
            ):
                continue
            allow_or_deny = _event_allow_or_deny(fields, access)
            if allow_or_deny is None:
                continue
            records.append(
                _build_runtime_record(
                    context=context,
                    result=result,
                    fields=fields,
                    seq=seq,
                    privilege=privilege,
                    access=access,
                    address=address,
                    size=_parse_int(fields.get("size")),
                    allow_or_deny=allow_or_deny,
                    translation=_runtime_event_translation(translation, fields),
                )
            )
            continue
        probe = str(fields.get("probe") or "").strip().lower()
        if chain == "ptw-response" and probe in {"cva6_ptw_exception", "rocket_ptw_access_exception"}:
            address = _parse_int(fields.get("paddr") or fields.get("addr") or fields.get("pte_page_base"))
            allow_or_deny = _ptw_response_allow_or_deny(fields)
            if address is None or allow_or_deny is None:
                continue
            records.append(
                _build_runtime_record(
                    context=context,
                    result=result,
                    fields=fields,
                    seq=seq,
                    privilege="s",
                    access="load",
                    address=address,
                    size=8,
                    allow_or_deny=allow_or_deny,
                    translation="sv39",
                )
            )
    return records


def _select_runtime_event_record(
    result: dict[str, Any],
    event_records: list[dict[str, Any]] | None,
) -> dict[str, Any] | None:
    candidates = [dict(item) for item in (event_records or []) if isinstance(item, dict)]
    if not candidates:
        return None
    target_outcome = _allow_or_deny(result)
    target_stage = "ptw" if "ptw" in str(result.get("observed_stage") or "").lower() else "final"
    target_mcause = _mcause_class(result.get("observed_mcause"), target_outcome or "deny")
    target_address = _parse_int(result.get("observed_fault_address"))
    best: dict[str, Any] | None = None
    best_key: tuple[int, int, int, int, int] | None = None
    for index, item in enumerate(candidates):
        record_outcome = str(item.get("allow_or_deny") or "").strip().lower()
        record_stage = str(item.get("fault_stage") or "").strip().lower()
        record_access = str(item.get("access") or "").strip().lower()
        record_mcause = str(item.get("mcause_class") or "").strip().lower()
        record_address = _parse_int(item.get("address"))
        key = (
            1 if target_outcome and record_outcome == target_outcome else 0,
            1 if target_outcome == "deny" and record_stage == target_stage else 0,
            1 if target_outcome == "deny" and target_address is not None and record_address == target_address else 0,
            1 if target_outcome == "deny" and target_mcause != "other" and record_mcause == target_mcause else 0,
            1 if record_access != "fetch" else 0,
        )
        comparison = key + (index,)
        if best_key is None or comparison > best_key:
            best_key = comparison
            best = item
    return best


def _first_matching_entry(entries: list[dict[str, Any]], address: int, *, size: int) -> dict[str, Any] | None:
    parsed = sorted((_parse_entry(entry) for entry in entries), key=lambda item: item.index)
    for index, entry in enumerate(parsed):
        bounds = _entry_bounds(entry, previous=parsed[index - 1] if index > 0 else None)
        if bounds is None:
            continue
        lower, upper = bounds
        if lower < address + size and address < upper:
            return {
                "index": entry.index,
                "address_mode": entry.address_mode.name.lower(),
                "read": entry.read,
                "write": entry.write,
                "execute": entry.execute,
                "locked": entry.locked,
            }
    return None


def _parse_entry(entry: dict[str, Any]) -> PmpEntry:
    mode = _normalize_mode(entry.get("address_mode"))
    return PmpEntry(
        index=int(entry.get("index") or 0),
        address_mode={
            "off": AddressMode.OFF,
            "tor": AddressMode.TOR,
            "na4": AddressMode.NA4,
            "napot": AddressMode.NAPOT,
        }[mode],
        pmpaddr=_parse_int(entry.get("pmpaddr")) or 0,
        read=bool(entry.get("read")),
        write=bool(entry.get("write")),
        execute=bool(entry.get("execute")),
        locked=bool(entry.get("locked")),
    )


def _entry_bounds(entry: PmpEntry, *, previous: PmpEntry | None) -> tuple[int, int] | None:
    if entry.address_mode == AddressMode.TOR:
        previous_addr = previous.pmpaddr if previous is not None else 0
        lower = previous_addr << 2
        upper = entry.pmpaddr << 2
        if upper <= lower:
            return None
        return lower, upper
    if entry.address_mode == AddressMode.NA4:
        lower = entry.pmpaddr << 2
        return lower, lower + 4
    if entry.address_mode == AddressMode.NAPOT:
        ones = _trailing_ones(entry.pmpaddr)
        size = 1 << (ones + 3)
        lower = (entry.pmpaddr & ~((1 << ones) - 1)) << 2
        return lower, lower + size
    return None


def _entry_mode(entry: dict[str, Any] | None) -> str:
    if entry is None:
        return "off"
    return _normalize_mode(entry.get("address_mode"))


def _trailing_ones(value: int) -> int:
    count = 0
    while value & (1 << count):
        count += 1
    return count


def _probe_bool(value: Any) -> bool | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "allow", "allowed"}:
        return True
    if text in {"0", "false", "no", "deny", "denied"}:
        return False
    return None


def _bool_text(value: Any) -> str:
    return "true" if bool(value) else "false"


def _parse_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _ineligible(reason: str) -> dict[str, Any]:
    return {
        "eligible": False,
        "qualification_reason": str(reason),
        "observed_bins": [],
        "event_records": [],
    }


def _mstatus_mprv(value: Any) -> bool:
    raw = _parse_int(value)
    if raw is None:
        return False
    return bool(raw & (1 << 17))


def _mstatus_mpp(value: Any) -> str:
    raw = _parse_int(value)
    if raw is None:
        return "m"
    return {
        0: "u",
        1: "s",
        3: "m",
    }.get((raw >> 11) & 0x3, "m")
