from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from .coverage import compute_coverage_targets
from .schema import read_json, write_json


SCHEMA_VERSION = 1
GENERATION_RULE_VERSION = "coverage-universe-v1"
_JSON_DUMPS_KWARGS = {
    "sort_keys": True,
    "ensure_ascii": True,
    "allow_nan": False,
    "separators": (",", ":"),
}


def make_coverage_universe(
    *,
    coverage_mode: str,
    bin_ids: Iterable[str],
    capability_fingerprint: str,
    target: str,
    include_experimental: bool,
    generator_seed: int,
    generation_rule_version: str = GENERATION_RULE_VERSION,
    extra_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_bins = sorted({str(item) for item in bin_ids})
    payload = {
        "schema_version": SCHEMA_VERSION,
        "coverage_mode": coverage_mode,
        "target": target,
        "include_experimental": bool(include_experimental),
        "generator_seed": int(generator_seed),
        "capability_fingerprint": str(capability_fingerprint),
        "generation_rule_version": generation_rule_version,
        "bin_ids": normalized_bins,
        "bin_count": len(normalized_bins),
        "bin_set_sha256": coverage_universe_bin_set_sha256(normalized_bins),
    }
    if extra_fields:
        payload.update(dict(extra_fields))
    payload["sha256"] = _coverage_universe_hash(payload)
    return payload


def validate_coverage_universe(universe: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(universe, dict):
        raise TypeError(f"coverage universe must be a dict, got {type(universe).__name__}")
    if universe.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported coverage universe schema_version {universe.get('schema_version')!r}; "
            f"expected {SCHEMA_VERSION}"
        )
    bin_ids = universe.get("bin_ids")
    if not isinstance(bin_ids, list) or any(type(item) is not str for item in bin_ids):
        raise ValueError("coverage universe bin_ids must be a list[str]")
    normalized_bins = sorted(set(bin_ids))
    if bin_ids != normalized_bins:
        raise ValueError("coverage universe bin_ids must be sorted and deduplicated")
    if int(universe.get("bin_count", -1)) != len(bin_ids):
        raise ValueError("coverage universe bin_count does not match bin_ids length")
    actual_bin_set_hash = coverage_universe_bin_set_sha256(bin_ids)
    expected_bin_set_hash = universe.get("bin_set_sha256")
    if expected_bin_set_hash not in (None, "") and expected_bin_set_hash != actual_bin_set_hash:
        raise ValueError(
            "coverage universe bin_set_sha256 mismatch: "
            f"expected {expected_bin_set_hash}, got {actual_bin_set_hash}"
        )
    expected_hash = universe.get("sha256")
    actual_hash = _coverage_universe_hash(universe)
    if expected_hash != actual_hash:
        raise ValueError(
            f"coverage universe sha256 mismatch: expected {expected_hash}, got {actual_hash}"
        )
    return universe


def classify_observed_bins(universe: dict[str, Any], observed_bins: Iterable[str]) -> dict[str, list[str]]:
    validate_coverage_universe(universe)
    universe_bins = set(universe["bin_ids"])
    observed = {str(item) for item in observed_bins}
    return {
        "covered": sorted(observed & universe_bins),
        "out_of_contract": sorted(observed - universe_bins),
    }


def freeze_coverage_universes(
    *,
    target: str,
    capability: dict[str, Any],
    include_experimental: bool = False,
    seed: int = 20260628,
) -> dict[str, dict[str, Any]]:
    targets = compute_coverage_targets(
        target=target,
        capability=capability,
        include_experimental=include_experimental,
        seed=seed,
    )
    fingerprint = str(targets["capability_fingerprint"])
    return {
        "semantic": make_coverage_universe(
            coverage_mode="semantic",
            bin_ids=targets["semantic"]["target_bins"],
            capability_fingerprint=fingerprint,
            target=target,
            include_experimental=include_experimental,
            generator_seed=seed,
        ),
        "pairwise": make_coverage_universe(
            coverage_mode="pairwise",
            bin_ids=targets["pairwise"]["target_bins"],
            capability_fingerprint=fingerprint,
            target=target,
            include_experimental=include_experimental,
            generator_seed=seed,
        ),
        "security_triples": make_coverage_universe(
            coverage_mode="security_triples",
            bin_ids=targets["security_triples"]["target_bins"],
            capability_fingerprint=fingerprint,
            target=target,
            include_experimental=include_experimental,
            generator_seed=seed,
        ),
        "predicates": make_coverage_universe(
            coverage_mode="predicates",
            bin_ids=targets["predicates"]["target_bins"],
            capability_fingerprint=fingerprint,
            target=target,
            include_experimental=include_experimental,
            generator_seed=seed,
        ),
    }


def write_coverage_universes(out_dir: Path, universes: dict[str, dict[str, Any]]) -> dict[str, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for mode, universe in universes.items():
        validate_coverage_universe(universe)
        path = out_dir / coverage_universe_filename(mode, universe)
        write_json(path, universe)
        written[mode] = path
    contract = {
        "schema_version": SCHEMA_VERSION,
        "modes": {mode: str(path.name) for mode, path in written.items()},
        "hashes": {mode: universes[mode]["sha256"] for mode in written},
    }
    write_json(out_dir / "coverage_contract_v1.json", contract)
    written["contract"] = out_dir / "coverage_contract_v1.json"
    return written


def load_coverage_universe(path: Path) -> dict[str, Any]:
    universe = read_json(Path(path))
    return validate_coverage_universe(universe)


def coverage_universe_bin_set_sha256(bin_ids: Iterable[str]) -> str:
    normalized_bins = sorted({str(item) for item in bin_ids})
    raw = json.dumps(normalized_bins, **_JSON_DUMPS_KWARGS).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def coverage_universe_filename(mode: str, universe: dict[str, Any] | None = None) -> str:
    if str(mode) == "bapc" and int((universe or {}).get("bapc_schema_version") or 0) >= 2:
        core_version = str((universe or {}).get("bapc_core_version") or "").strip().lower()
        if core_version == "v4" or str((universe or {}).get("generation_rule_version") or "") == "bapc-core-universe-v4":
            return "bapc_v4.json"
        if core_version == "v3" or str((universe or {}).get("generation_rule_version") or "") == "bapc-core-universe-v3":
            return "bapc_v3.json"
        return "bapc_v2.json"
    return f"{mode}_v1.json"


def _coverage_universe_hash(payload: dict[str, Any]) -> str:
    normalized = {
        key: value
        for key, value in payload.items()
        if key not in {"sha256", "bin_set_sha256"}
    }
    raw = json.dumps(normalized, **_JSON_DUMPS_KWARGS).encode("ascii")
    return hashlib.sha256(raw).hexdigest()
