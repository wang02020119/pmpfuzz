"""ScenarioSpec codec: strict fail-closed serialization — final.

All protocol values are validated with typed helpers:
- _read_bool – only JSON true/false; explicit null is rejected
- _read_int  – only JSON integer; rejects float/str/bool
- _read_optional_int – integer or null (for int|None fields)
- _read_str / _read_optional_str – only JSON string
- _read_str_tuple / _read_int_tuple – typed arrays
- _validate_json_value – recursive JSON constraint

Missing fields may use documented defaults.  Illegal types or values
always raise ValueError/TypeError — no silent coercion.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
from enum import Enum
from typing import Any

SPEC_SCHEMA_VERSION = 1

_MISSING = object()

_HASH_EXCLUDED_KEYS = frozenset({
    "name", "case_id", "candidate_id", "scenario_index",
    "expected_result", "expected_mcause", "expected_mtval",
    "semantic_bins", "pairwise_bins", "security_triple_bins",
    "predicate_bins", "combo_bins", "contract_predicates",
    "artifact_path", "campaign_seed", "execution_seq",
    "coverage_tags",
})

_JSON_DUMPS_KWARGS = {
    "sort_keys": True,
    "ensure_ascii": True,
    "allow_nan": False,
    "separators": (",", ":"),
}


# ═════════════════════════════════════════════════════════════════════════════
# Public API
# ═════════════════════════════════════════════════════════════════════════════

def scenario_to_spec(scenario: object) -> dict[str, object]:
    from pmpfuzz.scenario import PmpScenario
    from pmpfuzz.stateful import canonical_stateful_sequence
    if not isinstance(scenario, PmpScenario):
        raise TypeError(
            f"scenario_to_spec expects PmpScenario, "
            f"got {type(scenario).__name__}")
    spec: dict[str, object] = {"schema_version": SPEC_SCHEMA_VERSION}
    _serialize_dataclass(scenario, spec)
    if scenario.stateful_sequence is not None:
        spec["stateful_sequence"] = _serialize_value(canonical_stateful_sequence(scenario))
    return _sort_spec(spec)


def scenario_from_spec(spec: object) -> object:
    spec = _validate_spec(spec)

    from pmpfuzz.scenario import PmpScenario, AccessProbe
    from pmpfuzz.pmp import PmpEntry, Mseccfg, Privilege

    entries_raw = spec.get("entries", [])
    if not isinstance(entries_raw, list):
        raise ValueError(f"entries must be a list, got {type(entries_raw).__name__}")
    entries = [_deser_pmp_entry(i, e) for i, e in enumerate(entries_raw)]

    probe_raw = spec.get("probe", {})
    if not isinstance(probe_raw, dict):
        raise ValueError(f"probe must be an object, got {type(probe_raw).__name__}")
    probe = _deser_access_probe(probe_raw)

    mseccfg_raw = spec.get("mseccfg", {})
    if not isinstance(mseccfg_raw, dict):
        raise ValueError(f"mseccfg must be an object, got {type(mseccfg_raw).__name__}")
    mseccfg = _deser_mseccfg(mseccfg_raw)

    sv39_raw = spec.get("sv39")
    if sv39_raw is not None and not isinstance(sv39_raw, dict):
        raise ValueError(f"sv39 must be an object or null, got {type(sv39_raw).__name__}")
    sv39 = _deser_sv39(sv39_raw)

    pte_perms = spec.get("pte_permissions", {})
    if not isinstance(pte_perms, dict):
        raise ValueError(f"pte_permissions must be an object, got {type(pte_perms).__name__}")
    pte_permissions = _validate_json_value(pte_perms, path="pte_permissions")

    stateful = spec.get("stateful_sequence")
    if stateful is not None:
        if not isinstance(stateful, dict):
            raise ValueError(
                f"stateful_sequence must be an object or null, got {type(stateful).__name__}")
        stateful_sequence = _validate_json_value(stateful, path="stateful_sequence")
    else:
        stateful_sequence = None

    return PmpScenario(
        name=_read_str(spec, "name", default=""),
        entries=entries,
        privilege=_require_enum(Privilege, spec.get("privilege"),
                                default=Privilege.M.value, field_name="privilege"),
        probe=probe,
        mprv=_read_bool(spec, "mprv", default=False),
        mpp=_require_enum(Privilege, spec.get("mpp"),
                          default=Privilege.M.value, field_name="mpp"),
        mseccfg=mseccfg,
        translation=_require_translation(spec.get("translation")),
        sv39=sv39,
        profile=_read_str(spec, "profile", default=""),
        sum_enabled=_read_bool(spec, "sum_enabled", default=False),
        mxr=_read_bool(spec, "mxr", default=False),
        sfence_vma=_read_bool(spec, "sfence_vma", default=True),
        coverage_tags=_read_str_tuple(spec, "coverage_tags"),
        ptw_fault_level=_read_optional_str(spec, "ptw_fault_level"),
        preload_mode=_read_optional_str(spec, "preload_mode"),
        pmp_match_mode=_read_optional_str(spec, "pmp_match_mode"),
        pte_permissions=dict(pte_permissions) if isinstance(pte_permissions, dict) else {},
        security_focus=_read_optional_str(spec, "security_focus"),
        smepmp_rule=_read_optional_str(spec, "smepmp_rule"),
        stateful_sequence=stateful_sequence,
        ad_update_mode=_require_ad_update(spec.get("ad_update_mode")),
    )


def canonical_scenario_bytes(spec: dict[str, object]) -> bytes:
    if "stateful_sequence" in spec:
        try:
            spec = scenario_to_spec(scenario_from_spec(spec))
        except Exception:
            spec = _sort_spec(spec)
    return json.dumps(
        _filter_top_level_excluded(spec),
        **_JSON_DUMPS_KWARGS,
    ).encode("ascii")


def scenario_hash(spec: dict[str, object]) -> str:
    return hashlib.sha256(canonical_scenario_bytes(spec)).hexdigest()


# ═════════════════════════════════════════════════════════════════════════════
# Schema validation
# ═════════════════════════════════════════════════════════════════════════════

def _validate_spec(spec: object) -> dict[str, object]:
    if not isinstance(spec, dict):
        raise TypeError(f"ScenarioSpec must be a dict, got {type(spec).__name__}")
    if "schema_version" not in spec:
        raise ValueError("ScenarioSpec missing schema_version")
    sv = spec["schema_version"]
    if type(sv) is not int:
        raise ValueError(
            f"ScenarioSpec schema_version must be an integer, "
            f"got {sv!r} (type {type(sv).__name__})")
    if sv != SPEC_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported ScenarioSpec schema_version {sv}; "
            f"expected {SPEC_SCHEMA_VERSION}")
    return spec


# ═════════════════════════════════════════════════════════════════════════════
# Typed read helpers
# ═════════════════════════════════════════════════════════════════════════════

def _read_bool(
    mapping: dict[str, object],
    key: str,
    *,
    path: str = "",
    default: object = _MISSING,
) -> bool:
    qualified = f"{path}.{key}" if path else key
    value = mapping.get(key, _MISSING)

    if value is _MISSING:
        if default is not _MISSING:
            if type(default) is not bool:
                raise TypeError(f"internal default for {qualified} must be bool")
            return default  # type: ignore[return-value]
        raise ValueError(f"missing required field: {qualified}")

    if type(value) is not bool:
        raise ValueError(
            f"{qualified} must be a JSON boolean, "
            f"got {value!r} ({type(value).__name__})")

    return value  # type: ignore[return-value]


def _read_int(
    mapping: dict[str, object],
    key: str,
    *,
    path: str = "",
    default: object = _MISSING,
    minimum: int | None = None,
    positive: bool = False,
) -> int:
    qualified = f"{path}.{key}" if path else key
    value = mapping.get(key, _MISSING)

    if value is _MISSING:
        if default is _MISSING:
            raise ValueError(f"missing required field: {qualified}")
        if type(default) is not int:
            raise TypeError(f"internal default for {qualified} must be int")
        value = default

    if type(value) is not int:
        raise ValueError(
            f"{qualified} must be a JSON integer, "
            f"got {value!r} ({type(value).__name__})")

    result: int = value  # type: ignore[assignment]
    if positive and result <= 0:
        raise ValueError(f"{qualified} must be positive, got {result}")
    if minimum is not None and result < minimum:
        raise ValueError(f"{qualified} must be >= {minimum}, got {result}")
    return result


def _read_optional_int(
    mapping: dict[str, object],
    key: str,
    *,
    path: str = "",
    minimum: int | None = None,
) -> int | None:
    qualified = f"{path}.{key}" if path else key
    value = mapping.get(key, _MISSING)
    if value is _MISSING or value is None:
        return None
    if type(value) is not int:
        raise ValueError(
            f"{qualified} must be an integer or null, "
            f"got {value!r} ({type(value).__name__})")
    result: int = value  # type: ignore[assignment]
    if minimum is not None and result < minimum:
        raise ValueError(f"{qualified} must be >= {minimum}, got {result}")
    return result


def _read_str(
    mapping: dict[str, object],
    key: str,
    *,
    path: str = "",
    default: object = _MISSING,
    allow_empty: bool = True,
) -> str:
    qualified = f"{path}.{key}" if path else key
    value = mapping.get(key, _MISSING)

    if value is _MISSING:
        if default is _MISSING:
            raise ValueError(f"missing required field: {qualified}")
        if type(default) is not str:
            raise TypeError(f"internal default for {qualified} must be str")
        value = default

    if type(value) is not str:
        raise ValueError(
            f"{qualified} must be a JSON string, "
            f"got {value!r} ({type(value).__name__})")

    result: str = value  # type: ignore[assignment]
    if not allow_empty and not result:
        raise ValueError(f"{qualified} must not be empty")
    return result


def _read_optional_str(
    mapping: dict[str, object],
    key: str,
    *,
    path: str = "",
) -> str | None:
    qualified = f"{path}.{key}" if path else key
    value = mapping.get(key, _MISSING)
    if value is _MISSING or value is None:
        return None
    if type(value) is not str:
        raise ValueError(
            f"{qualified} must be a string or null, "
            f"got {value!r} ({type(value).__name__})")
    return value  # type: ignore[return-value]


def _read_str_tuple(
    mapping: dict[str, object],
    key: str,
    *,
    path: str = "",
    default: tuple[str, ...] = (),
) -> tuple[str, ...]:
    qualified = f"{path}.{key}" if path else key
    value = mapping.get(key, _MISSING)
    if value is _MISSING:
        return default
    if not isinstance(value, list):
        raise ValueError(f"{qualified} must be a JSON array of strings")
    result: list[str] = []
    for index, item in enumerate(value):
        if type(item) is not str:
            raise ValueError(
                f"{qualified}[{index}] must be a string, got {item!r}")
        result.append(item)
    return tuple(result)


def _read_int_tuple(
    mapping: dict[str, object],
    key: str,
    *,
    path: str = "",
    default: tuple[int, ...] = (),
    minimum: int | None = None,
) -> tuple[int, ...]:
    qualified = f"{path}.{key}" if path else key
    value = mapping.get(key, _MISSING)
    if value is _MISSING:
        return default
    if not isinstance(value, list):
        raise ValueError(f"{qualified} must be a JSON array of integers")
    result: list[int] = []
    for index, item in enumerate(value):
        if type(item) is not int:
            raise ValueError(
                f"{qualified}[{index}] must be an integer, got {item!r}")
        if minimum is not None and item < minimum:
            raise ValueError(
                f"{qualified}[{index}] must be >= {minimum}, got {item}")
        result.append(item)
    return tuple(result)


def _validate_json_value(value: object, *, path: str) -> object:
    if value is None:
        return None
    if type(value) in {bool, int, str}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(f"{path} contains non-finite float")
        return value
    if isinstance(value, list):
        return [_validate_json_value(item, path=f"{path}[{index}]")
                for index, item in enumerate(value)]
    if isinstance(value, dict):
        result: dict[str, object] = {}
        for k, v in value.items():
            if type(k) is not str:
                raise ValueError(f"{path} contains non-string key {k!r}")
            result[k] = _validate_json_value(v, path=f"{path}.{k}")
        return result
    raise ValueError(
        f"{path} contains unsupported value {value!r} ({type(value).__name__})")


# ═════════════════════════════════════════════════════════════════════════════
# Enum helpers
# ═════════════════════════════════════════════════════════════════════════════

def _require_enum(
    enum_cls: type[Enum],
    value: object,
    *,
    default: object,
    field_name: str,
) -> Enum:
    if value is None:
        return enum_cls(default)
    try:
        return enum_cls(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {field_name}: {value!r}") from exc


def _require_translation(value: object) -> object:
    from pmpfuzz.mmu import TranslationMode
    return _require_enum(TranslationMode, value, default="bare", field_name="translation")


def _require_ad_update(value: object) -> object:
    from pmpfuzz.mmu import AdUpdateMode
    return _require_enum(AdUpdateMode, value, default="svade", field_name="ad_update_mode")


# ═════════════════════════════════════════════════════════════════════════════
# Deserialization
# ═════════════════════════════════════════════════════════════════════════════

def _deser_pmp_entry(idx: int, d: object) -> object:
    if not isinstance(d, dict):
        raise ValueError(f"entries[{idx}] must be an object, got {type(d).__name__}")
    from pmpfuzz.pmp import PmpEntry, AddressMode
    path = f"entries[{idx}]"
    return PmpEntry(
        index=_read_int(d, "index", path=path, default=0, minimum=0),
        address_mode=_require_enum(AddressMode, d.get("address_mode"),
                                   default=0, field_name=f"{path}.address_mode"),
        pmpaddr=_read_int(d, "pmpaddr", path=path, default=0, minimum=0),
        read=_read_bool(d, "read", path=path),
        write=_read_bool(d, "write", path=path),
        execute=_read_bool(d, "execute", path=path),
        locked=_read_bool(d, "locked", path=path),
    )


def _deser_access_probe(d: dict[str, object]) -> object:
    from pmpfuzz.scenario import AccessProbe
    from pmpfuzz.pmp import Access
    return AccessProbe(
        access=_require_enum(Access, d.get("access"),
                             default="load", field_name="probe.access"),
        physical_address=_read_int(d, "physical_address", path="probe", default=0, minimum=0),
        size=_read_int(d, "size", path="probe", default=4, positive=True),
        offset_name=_read_str(d, "offset_name", path="probe", default=""),
        virtual_address=_read_optional_int(d, "virtual_address", path="probe", minimum=0),
    )


def _deser_mseccfg(d: dict[str, object]) -> object:
    from pmpfuzz.pmp import Mseccfg
    return Mseccfg(
        rlb=_read_bool(d, "rlb", path="mseccfg", default=False),
        mmwp=_read_bool(d, "mmwp", path="mseccfg", default=False),
        mml=_read_bool(d, "mml", path="mseccfg", default=False),
    )


def _deser_sv39(d: dict[str, object] | None) -> object | None:
    if d is None:
        return None
    from pmpfuzz.mmu import Sv39Mapping, PageTableEntry
    pte_d = d.get("pte", {})
    if not isinstance(pte_d, dict):
        raise ValueError(f"sv39.pte must be an object, got {type(pte_d).__name__}")
    pte = PageTableEntry(
        read=_read_bool(pte_d, "read", path="sv39.pte"),
        write=_read_bool(pte_d, "write", path="sv39.pte"),
        execute=_read_bool(pte_d, "execute", path="sv39.pte"),
        user=_read_bool(pte_d, "user", path="sv39.pte"),
        accessed=_read_bool(pte_d, "accessed", path="sv39.pte"),
        dirty=_read_bool(pte_d, "dirty", path="sv39.pte"),
        valid=_read_bool(pte_d, "valid", path="sv39.pte", default=True),
        global_mapping=_read_bool(pte_d, "global_mapping", path="sv39.pte", default=False),
    )
    return Sv39Mapping(
        virtual_page=_read_int(d, "virtual_page", path="sv39", default=0, minimum=0),
        physical_page=_read_int(d, "physical_page", path="sv39", default=0, minimum=0),
        root_table=_read_int(d, "root_table", path="sv39", default=0, minimum=0),
        walk_addresses=_read_int_tuple(d, "walk_addresses", path="sv39", minimum=0),
        pte=pte,
        page_size=_read_int(d, "page_size", path="sv39", default=4096, positive=True),
    )


# ═════════════════════════════════════════════════════════════════════════════
# Serialization
# ═════════════════════════════════════════════════════════════════════════════

def _serialize_dataclass(obj: object, out: dict[str, object]) -> None:
    if not dataclasses.is_dataclass(obj):
        return
    for f in dataclasses.fields(obj):
        out[f.name] = _serialize_value(getattr(obj, f.name))


def _serialize_value(val: object) -> object:
    if dataclasses.is_dataclass(val) and not isinstance(val, type):
        d: dict[str, object] = {}
        _serialize_dataclass(val, d)
        return _sort_spec(d)
    if isinstance(val, Enum):
        return val.value
    if val is None:
        return None
    if type(val) is bool:
        return val
    if type(val) is int:
        return val
    if type(val) is float:
        if not math.isfinite(val):
            raise ValueError(f"non-finite float is not serializable: {val!r}")
        return val
    if type(val) is str:
        return val
    if isinstance(val, (list, tuple)):
        return [_serialize_value(v) for v in val]
    if isinstance(val, dict):
        result: dict[str, object] = {}
        for k, v in val.items():
            if not isinstance(k, str):
                raise TypeError(
                    f"ScenarioSpec dict key must be str, "
                    f"got {k!r} ({type(k).__name__})")
            result[k] = _serialize_value(v)
        return result
    raise TypeError(
        f"cannot serialize unsupported type {type(val).__name__}: {val!r}")


# ═════════════════════════════════════════════════════════════════════════════
# Deterministic helpers
# ═════════════════════════════════════════════════════════════════════════════

def _sort_spec(d: dict[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key in sorted(d.keys()):
        v = d[key]
        if isinstance(v, dict):
            result[key] = _sort_spec(v)
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            result[key] = [_sort_spec(item) for item in v]
        else:
            result[key] = v
    return result


def _filter_top_level_excluded(spec: dict[str, object]) -> dict[str, object]:
    return {
        k: _filter_hash_value(k, v)
        for k, v in spec.items()
        if k not in _HASH_EXCLUDED_KEYS
    }


def _filter_hash_value(key: str, value: object) -> object:
    if isinstance(value, dict):
        excluded = set()
        if key == "stateful_sequence":
            excluded.update({"expected_final", "expected_cause", "stale_failure_class"})
        return {
            nested_key: _filter_hash_value(nested_key, nested_value)
            for nested_key, nested_value in value.items()
            if nested_key not in excluded
        }
    if isinstance(value, list):
        return [_filter_hash_value(key, item) for item in value]
    return value
