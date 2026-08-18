#!/usr/bin/env python3
"""Validate a campaign timeline for data integrity.

Checks are gated by the ``run_class`` field in ``campaign_metadata.json``:

* **strict** (readiness / pilot / formal / baseline-pilot / baseline-formal):
  all checks are errors — missing provenance manifests, missing SHAs, and any
  timeline corruption fails validation.

* **development-smoke**:
  global provenance (environment.json, git-shas.txt, artifact-sha256.txt,
  DUT SHAs) is optional, but timeline / case / result consistency is still
  enforced as errors.

* **legacy** (metadata present but ``run_class`` absent):
  provenance warnings are downgraded to ``warning`` severity for backward
  compatibility; timeline integrity is still ``error``.

* **no metadata at all**:
  ``metadata_exists`` is always an error — every campaign must carry metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from pathlib import Path as _Path
from typing import Any, Mapping

# Ensure repository-local imports work when the validator is executed directly
# from a runtime override tree.
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
    BAPC_CONVERGENCE_PROTOCOL_ID,
    BAPC_FORMAL_ALLOWED_STOP_REASONS,
    expected_bapc_formal_run_class,
    is_bapc_formal_campaign,
    is_bapc_formal_contract,
    is_bapc_formal_request,
    typed_int_matches,
    typed_numeric_matches,
)
from pmpfuzz.stop_reasons import is_legacy_hard_cap_reason, normalize_stop_reason

try:
    from pmpfuzz.experiment_protocols import allowed_bapc_formal_field_values
except ImportError:
    _BAPC_FORMAL_ALLOWED_VALUE_LIST_FIELDS = {
        "source_sha": "allowed_source_shas",
        "source_tree_sha256": "allowed_source_tree_sha256s",
    }

    # Older clean PMPFuzz checkouts used for formal provenance may not export
    # the helper yet; keep validator refresh compatible without mutating that
    # source tree.
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
            if not isinstance(raw, (str, bytes, bytearray)):
                values.extend(str(item) for item in raw if str(item))
        return tuple(dict.fromkeys(values))

# ── run-class gating ─────────────────────────────────────────────────────────

# run_class values that require strict (fail-closed) validation.
_STRICT_RUN_CLASSES = {
    "readiness",
    "pilot",
    "formal",
    "baseline-pilot",
    "baseline-formal",
}
_FORMAL_RUN_CLASSES = {"formal", "baseline-formal"}
_KNOWN_RUN_CLASSES = _STRICT_RUN_CLASSES | {"development-smoke"}
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

_REQUIRED_COVERAGE_MODES = ("semantic", "pairwise", "security_triples", "predicates")
_SINGLE_MODE_COVERAGE_MODES = ("hpm", "bapc")
_TIMELINE_KEYS_BY_MODE = {
    "semantic": ("semantic_covered", "semantic_target"),
    "pairwise": ("pairwise_covered", "pairwise_target"),
    "security_triples": ("security_triples_covered", "security_triples_target"),
    "predicates": ("predicates_covered", "predicates_target"),
    "hpm": ("hpm_covered", "hpm_target"),
    "bapc": ("bapc_covered", "bapc_target"),
}


def _required_coverage_modes_for_metadata(metadata: dict[str, Any] | None) -> tuple[str, ...]:
    coverage_mode = str((metadata or {}).get("coverage_mode") or "")
    if coverage_mode in _SINGLE_MODE_COVERAGE_MODES:
        return (coverage_mode,)
    return _REQUIRED_COVERAGE_MODES


def _load_metadata(metadata_path: Path) -> dict[str, Any] | None:
    """Return parsed metadata dict, or None if file is missing / unreadable."""
    if not metadata_path.exists():
        return None
    try:
        return json.loads(metadata_path.read_text(encoding="ascii"))
    except Exception:
        return None


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


def _validation_input_bindings(
    campaign_dir: Path,
    metadata: dict[str, Any] | None,
    *,
    artifact_root: Path | None,
    formal_bapc_context: bool,
) -> dict[str, dict[str, str]]:
    bindings: dict[str, dict[str, str]] = {}
    candidates = {
        "metadata": campaign_dir / "metrics" / "campaign_metadata.json",
        "timeline": campaign_dir / "metrics" / "coverage_timeline.jsonl",
    }
    schedule_rel = str((metadata or {}).get("schedule_v4") or "")
    if schedule_rel:
        candidates["schedule_v4"] = campaign_dir / schedule_rel
    coverage_path = campaign_dir / "coverage" / "coverage.json"
    if coverage_path.exists():
        candidates["coverage"] = coverage_path
    if formal_bapc_context and artifact_root is not None:
        contract_path = artifact_root / "manifests" / "experiment-contract.json"
        if contract_path.exists():
            candidates["experiment_contract"] = contract_path
    for label, path in candidates.items():
        if not path.exists() or not path.is_file():
            continue
        if label == "experiment_contract":
            rel_path = Path(os.path.relpath(path, campaign_dir)).as_posix()
        else:
            rel_path = path.relative_to(campaign_dir).as_posix()
        bindings[label] = {
            "path": rel_path,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    return bindings


def _resolve_artifact_root(campaign_dir: Path) -> Path | None:
    """Walk up from *campaign_dir* to find the directory that contains
    ``manifests/`` (the artifact root).  This replaces the old hard-coded
    ``parent.parent.parent.parent`` heuristic."""
    p = campaign_dir.resolve()
    for _ in range(12):
        if (p / "manifests").is_dir():
            return p
        if p.parent == p:
            break
        p = p.parent
    return None


def _is_cross_campaign_artifact_root(campaign_dir: Path, artifact_root: Path) -> bool:
    """Return True when *artifact_root* spans sibling campaigns.

    Formal matrix runs store per-DUT manifests above ``campaigns/`` so a
    campaign-local timeline validation should not re-hash every sibling
    campaign artifact before the whole DUT root is stable.
    """
    campaign_resolved = campaign_dir.resolve()
    artifact_resolved = artifact_root.resolve()
    if campaign_resolved == artifact_resolved:
        return False
    campaigns_root = artifact_resolved / "campaigns"
    try:
        campaign_resolved.relative_to(campaigns_root)
    except ValueError:
        return False
    return True


def _load_experiment_contract(artifact_root: Path | None) -> dict[str, Any] | None:
    if artifact_root is None:
        return None
    path = artifact_root / "manifests" / "experiment-contract.json"
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="ascii"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _is_bapc_formal_validation_context(
    metadata: dict[str, Any] | None,
    contract: dict[str, Any] | None,
) -> bool:
    if is_bapc_formal_contract(contract):
        return True
    if not isinstance(metadata, dict):
        return False
    return is_bapc_formal_request(
        coverage_mode=metadata.get("coverage_mode"),
        run_class=metadata.get("run_class"),
        experiment_protocol_id=metadata.get("experiment_protocol_id"),
    )


def _load_campaign_universe(
    campaign_dir: Path,
    metadata: dict[str, Any] | None,
    mode: str,
) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(metadata, dict):
        return None, "metadata unavailable"
    files = metadata.get("coverage_universe_files") or {}
    hashes = metadata.get("coverage_universe_hashes") or {}
    raw_path = files.get(mode)
    if not raw_path:
        return None, f"missing coverage_universe_files[{mode!r}]"
    universe_path = Path(str(raw_path))
    if not universe_path.is_absolute():
        universe_path = campaign_dir / universe_path
    if not universe_path.exists():
        return None, f"missing universe file: {universe_path}"
    try:
        if mode == "bapc":
            from pmpfuzz.bapc import load_bapc_coverage_universe

            universe = load_bapc_coverage_universe(universe_path)
        else:
            from pmpfuzz.coverage_universe import validate_coverage_universe

            universe = json.loads(universe_path.read_text(encoding="ascii"))
            validate_coverage_universe(universe)
    except Exception as exc:
        return None, str(exc)
    expected_sha = str(hashes.get(mode) or "")
    actual_sha = str(universe.get("sha256") or "")
    if expected_sha and expected_sha != actual_sha:
        return None, f"metadata={expected_sha} file={actual_sha}"
    return universe, None


def _check_bapc_formal_contract(
    *,
    campaign_dir: Path,
    metadata: dict[str, Any] | None,
    contract: dict[str, Any] | None,
    normalized_stop_reason: str | None,
    add_check,
) -> None:
    add_check(
        "formal_bapc_contract_manifest_exists",
        is_bapc_formal_contract(contract),
        "present" if is_bapc_formal_contract(contract) else "missing or invalid experiment-contract.json",
        severity="error",
    )
    if not isinstance(metadata, dict):
        return

    protocol_id = str(metadata.get("experiment_protocol_id") or "")
    expected_protocol_id = str((contract or {}).get("experiment_protocol_id") or BAPC_CONVERGENCE_PROTOCOL_ID)
    add_check(
        "formal_bapc_experiment_protocol_id_exact",
        protocol_id == expected_protocol_id,
        protocol_id or "missing",
        severity="error",
    )
    add_check(
        "formal_bapc_coverage_mode_exact",
        str(metadata.get("coverage_mode") or "") == "bapc",
        str(metadata.get("coverage_mode") or ""),
        severity="error",
    )
    add_check(
        "formal_bapc_metadata_dut_matches_contract",
        str(metadata.get("dut") or "") == str((contract or {}).get("dut") or ""),
        f"metadata={metadata.get('dut')!r} contract={(contract or {}).get('dut')!r}",
        severity="error",
    )
    for field in ("source_sha", "source_tree_sha256", "dut_sha", "dut_binary_sha256"):
        expected_values = allowed_bapc_formal_field_values(contract, field)
        actual = str(metadata.get(field) or "")
        if not expected_values:
            continue
        add_check(
            f"formal_bapc_metadata_{field}_matches_contract",
            actual in expected_values,
            f"metadata={actual!r} contract={list(expected_values)!r}",
            severity="error",
        )

    method = str(metadata.get("method") or "")
    run_class = str(metadata.get("run_class") or "")
    expected_run_class = expected_bapc_formal_run_class(method)
    add_check(
        "formal_bapc_method_run_class_coupled",
        expected_run_class is not None and run_class == expected_run_class,
        f"method={method!r} run_class={run_class!r} expected={expected_run_class!r}",
        severity="error",
    )

    add_check(
        "formal_bapc_convergence_enabled_true",
        type(metadata.get("convergence_enabled")) is bool and metadata.get("convergence_enabled") is True,
        repr(metadata.get("convergence_enabled")),
        severity="error",
    )

    numeric_fields = (
        "convergence_min_runtime_seconds",
        "convergence_confirmation_seconds",
        "max_wall_time_seconds",
        "time_budget_seconds",
        "wall_clock_horizon_seconds",
    )
    int_fields = ("convergence_confirmation_eligible_cases",)
    for field in numeric_fields:
        expected = BAPC_CONVERGENCE_FORMAL[field]
        value = metadata.get(field)
        add_check(
            f"formal_bapc_{field}_exact",
            typed_numeric_matches(value, expected),
            f"actual={value!r} expected={expected!r}",
            severity="error",
        )
    for field in int_fields:
        expected = BAPC_CONVERGENCE_FORMAL[field]
        value = metadata.get(field)
        add_check(
            f"formal_bapc_{field}_exact",
            typed_int_matches(value, expected),
            f"actual={value!r} expected={expected!r}",
            severity="error",
        )
    add_check(
        "formal_bapc_budget_class_exact",
        str(metadata.get("budget_class") or "") == BAPC_CONVERGENCE_FORMAL["budget_class"],
        str(metadata.get("budget_class") or ""),
        severity="error",
    )

    add_check(
        "formal_bapc_stop_reason_allowed",
        normalized_stop_reason in BAPC_FORMAL_ALLOWED_STOP_REASONS,
        repr(normalized_stop_reason),
        severity="error",
    )

    contract_payload = contract or {}
    for field, expected in BAPC_CONVERGENCE_FORMAL.items():
        actual = contract_payload.get(field)
        if field == "convergence_confirmation_eligible_cases":
            ok = typed_int_matches(actual, int(expected))
        elif field == "budget_class":
            ok = str(actual or "") == str(expected)
        else:
            ok = typed_numeric_matches(actual, float(expected))
        add_check(
            f"formal_bapc_contract_{field}_exact",
            ok,
            f"actual={actual!r} expected={expected!r}",
            severity="error",
        )

    universe, universe_error = _load_campaign_universe(campaign_dir, metadata, "bapc")
    if universe_error is not None:
        add_check("formal_bapc_universe_matches_contract", False, universe_error, severity="error")
        return
    expected_bin_count = int(contract_payload.get("bin_count") or 0)
    expected_bin_set_sha256 = str(contract_payload.get("bin_set_sha256") or "")
    actual_bin_count = int(universe.get("bin_count") or 0)
    actual_bin_set_sha256 = str(universe.get("bin_set_sha256") or "")
    add_check(
        "formal_bapc_universe_matches_contract",
        actual_bin_count == expected_bin_count and actual_bin_set_sha256 == expected_bin_set_sha256,
        (
            f"bin_count={actual_bin_count}/{expected_bin_count} "
            f"bin_set_sha256={actual_bin_set_sha256}/{expected_bin_set_sha256}"
        ),
        severity="error",
    )


# ── internal helpers ─────────────────────────────────────────────────────────


def _check_child_timelines(campaign_dir: Path, add_check) -> None:
    """Recursively validate every ``rounds/round_*/metrics/coverage_timeline.jsonl``.

    *Missing* or *corrupted* child timelines are always ``error`` severity
    regardless of run_class.
    """
    rounds_dir = campaign_dir / "rounds"
    if not rounds_dir.is_dir():
        return

    round_dirs = sorted(rounds_dir.glob("round_*"))
    if not round_dirs:
        return

    for rd in round_dirs:
        rd_tl = rd / "metrics" / "coverage_timeline.jsonl"
        if not rd_tl.exists():
            add_check(
                f"round_timeline_{rd.name}_exists",
                False,
                f"missing: {rd_tl}",
                severity="error",
            )
            continue

        # Validate the child timeline is parseable JSONL.
        try:
            raw = rd_tl.read_text(encoding="ascii").strip()
        except Exception as exc:
            add_check(
                f"round_timeline_{rd.name}_readable",
                False,
                f"cannot read: {exc}",
                severity="error",
            )
            continue

        if not raw:
            add_check(
                f"round_timeline_{rd.name}_nonempty",
                False,
                "empty file",
                severity="error",
            )
            continue

        for i, line in enumerate(raw.split("\n")):
            if not line.strip():
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:
                add_check(
                    f"round_timeline_{rd.name}_parse",
                    False,
                    f"line {i}: {exc}",
                    severity="error",
                )
                break
        else:
            add_check(f"round_timeline_{rd.name}", True, "valid JSONL")


def _check_orphans_and_duplicates(campaign_dir: Path, lines: list[dict], add_check) -> None:
    """Verify 1:1 correspondence between timeline entries and on-disk case/result dirs.

    * Orphan cases/results (on disk but not in timeline) → error.
    * Duplicate result files for a single case → error.
    """
    cases_dir = campaign_dir / "cases"
    results_dir = campaign_dir / "results"

    if not cases_dir.is_dir() and not results_dir.is_dir():
        return

    # Case IDs from timeline (non-baseline rows: completion_seq > 0).
    tl_case_ids: set[str] = set()
    for line in lines:
        cid = line.get("case_id")
        if cid and (line.get("completion_seq") or 0) > 0:
            tl_case_ids.add(cid)

    # --- orphan cases ---
    if cases_dir.is_dir():
        disk_case_ids: set[str] = set()
        for d in cases_dir.iterdir():
            if d.is_dir():
                disk_case_ids.add(d.name)
        orphan_cases = disk_case_ids - tl_case_ids
        if orphan_cases:
            add_check(
                "orphan_cases",
                False,
                f"{len(orphan_cases)} orphan case dir(s) not in timeline: "
                f"{sorted(orphan_cases)[:5]}",
                severity="error",
            )

    # --- orphan results & duplicate results ---
    if results_dir.is_dir():
        disk_result_ids: set[str] = set()
        dup_count = 0
        for d in results_dir.iterdir():
            if not d.is_dir():
                continue
            disk_result_ids.add(d.name)
            # Count result*.json files; > 1 is a duplicate.
            result_files = sorted(d.glob("result*.json"))
            if len(result_files) > 1:
                dup_count += 1
                add_check(
                    f"duplicate_results_{d.name}",
                    False,
                    f"{len(result_files)} result files: "
                    f"{[f.name for f in result_files]}",
                    severity="error",
                )

        orphan_results = disk_result_ids - tl_case_ids
        if orphan_results:
            add_check(
                "orphan_results",
                False,
                f"{len(orphan_results)} orphan result dir(s) not in timeline: "
                f"{sorted(orphan_results)[:5]}",
                severity="error",
            )


def _check_metadata_identity(metadata: dict[str, Any] | None,
                              lines: list[dict], add_check) -> None:
    """Verify that metadata identity fields match the campaign timeline.

    Checks campaign_id, dut, seed, and method (if present).
    """
    if metadata is None:
        return

    # Campaign-level identity from timeline (first non-baseline row, or baseline).
    tl_campaign_id: str | None = None
    tl_dut: str | None = None
    tl_seed: int | None = None
    for line in lines:
        tl_campaign_id = tl_campaign_id or line.get("campaign_id")
        tl_dut = tl_dut or line.get("dut")
        tl_seed = tl_seed or line.get("seed")
        if tl_campaign_id and tl_dut and tl_seed is not None:
            break

    _check_field = (
        ("campaign_id", tl_campaign_id),
        ("dut", tl_dut),
        ("seed", tl_seed),
    )
    for field, tl_val in _check_field:
        meta_val = metadata.get(field)
        if meta_val is not None and tl_val is not None and meta_val != tl_val:
            add_check(
                f"metadata_{field}_identity",
                False,
                f"metadata {field}={meta_val!r} != timeline {field}={tl_val!r}",
                severity="error",
            )


def _is_volatile_validation_log_entry(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/")
    return (
        normalized.startswith("controller/logs/")
        and normalized.endswith(".validation.log")
    )


def _is_mutable_aggregate_contract_entry(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/")
    return normalized in {
        "normalized/campaigns.csv",
        "normalized/coverage_timeseries.csv",
    }


def _is_regenerated_validation_contract_entry(rel_path: str) -> bool:
    normalized = rel_path.replace("\\", "/")
    return normalized.startswith("campaigns/") and normalized.endswith("/validation.json")


def _check_artifact_sha_manifest(artifact_root: Path, add_check) -> None:
    """Parse ``manifests/artifact-sha256.txt`` and verify every entry.

    Each entry is ``<sha256>  <relative_path>`` (two spaces).

    Boundary checks (fail-closed):

    * Manifest must contain at least one valid, non-self-referencing file entry.
    * ``rel_path`` must be relative — absolute paths are rejected.
    * The resolved target must stay inside *artifact_root* (no ``../`` escape).
    * The entry must not reference the manifest itself.
    * The target must exist and be a regular file (not a directory).
    * The same normalised target must not appear more than once.
    * The expected hash must be exactly 64 hexadecimal digits.
    """
    manifest_path = artifact_root / "manifests" / "artifact-sha256.txt"
    if not manifest_path.exists():
        return  # handled by the manifest-existence check

    try:
        raw = manifest_path.read_text(encoding="ascii").strip()
    except Exception as exc:
        add_check("artifact_sha_manifest_readable", False, str(exc), severity="error")
        return

    if not raw:
        add_check("artifact_sha_manifest_nonempty", False,
                  "manifest is empty", severity="error")
        return

    # Collect non-empty lines; reject whitespace-only manifests.
    non_empty = [ln for ln in (ln.strip() for ln in raw.split("\n")) if ln]
    if not non_empty:
        add_check("artifact_sha_manifest_nonempty", False,
                  "manifest has no non-empty lines", severity="error")
        return

    root_resolved = artifact_root.resolve()
    manifest_resolved = manifest_path.resolve()

    _HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")

    seen: set[Path] = set()
    missing_files: list[str] = []
    hash_mismatches: list[str] = []
    skipped_volatile_logs: list[str] = []
    skipped_mutable_aggregate_hashes: list[str] = []
    skipped_regenerated_validation_hashes: list[str] = []
    valid_entry_count = 0
    has_structural_error = False

    for line in non_empty:
        parts = line.split("  ", 1)  # two spaces between hash and path
        if len(parts) != 2:
            add_check("artifact_sha_manifest_parse", False,
                      f"malformed line: {line[:80]}", severity="error")
            has_structural_error = True
            continue

        expected_hash, rel_path = parts

        # ── hash must be exactly 64 hex digits ─────────────────────────
        if not _HEX64.match(expected_hash):
            add_check("artifact_sha_manifest_parse", False,
                      "hash is not 64 hex digits", severity="error")
            has_structural_error = True
            continue

        # ── rel_path must be non-empty ─────────────────────────────────
        if not rel_path:
            add_check("artifact_sha_manifest_entry_empty_path", False,
                      "empty path", severity="error")
            has_structural_error = True
            continue

        # ── rel_path must be relative (no absolute paths) ──────────────
        path_obj = Path(rel_path)
        if path_obj.is_absolute():
            add_check("artifact_sha_manifest_entry_absolute", False,
                      "absolute path not allowed", severity="error")
            has_structural_error = True
            continue

        # ── resolve and verify containment within artifact root ───────
        candidate = (artifact_root / rel_path).resolve()
        try:
            candidate.relative_to(root_resolved)
        except ValueError:
            add_check("artifact_sha_manifest_entry_escape", False,
                      "path escapes artifact root", severity="error")
            has_structural_error = True
            continue

        # ── reject self-reference (manifest must not hash itself) ──────
        if candidate == manifest_resolved:
            add_check("artifact_sha_manifest_entry_self_ref", False,
                      "entry references the manifest itself", severity="error")
            has_structural_error = True
            continue

        if _is_volatile_validation_log_entry(rel_path):
            skipped_volatile_logs.append(rel_path)
            continue

        # ── target must exist and be a regular file ────────────────────
        if not candidate.exists():
            missing_files.append(rel_path)
            continue
        if not candidate.is_file():
            add_check("artifact_sha_manifest_entry_not_file", False,
                      "target is not a regular file", severity="error")
            has_structural_error = True
            continue

        # ── detect duplicate normalised targets ───────────────────────
        if candidate in seen:
            add_check("artifact_sha_manifest_entry_duplicate", False,
                      "duplicate normalised target", severity="error")
            has_structural_error = True
            continue
        seen.add(candidate)

        # ── verify SHA-256 hash ────────────────────────────────────────
        try:
            actual_hash = hashlib.sha256(candidate.read_bytes()).hexdigest()
        except Exception as exc:
            add_check("artifact_sha_manifest_hash", False,
                      f"cannot hash entry: {exc}", severity="error")
            has_structural_error = True
            continue

        if actual_hash != expected_hash:
            if _is_mutable_aggregate_contract_entry(rel_path):
                skipped_mutable_aggregate_hashes.append(rel_path)
                valid_entry_count += 1
            elif _is_regenerated_validation_contract_entry(rel_path):
                skipped_regenerated_validation_hashes.append(rel_path)
                valid_entry_count += 1
            else:
                hash_mismatches.append(rel_path)
        else:
            valid_entry_count += 1

    # ── report accumulated results ─────────────────────────────────────
    if missing_files:
        add_check("artifact_sha_manifest_files_exist", False,
                  f"{len(missing_files)} missing: {missing_files[:5]}",
                  severity="error")
    if hash_mismatches:
        add_check("artifact_sha_manifest_hash_match", False,
                  f"{len(hash_mismatches)} SHA mismatch: {hash_mismatches[:5]}",
                  severity="error")

    if valid_entry_count == 0:
        add_check("artifact_sha_manifest_nonempty", False,
                  "no valid non-self-referencing file entries",
                  severity="error")
    elif (not has_structural_error
          and not missing_files
          and not hash_mismatches):
        detail = "all entries verified"
        if skipped_volatile_logs:
            detail += f"; skipped {len(skipped_volatile_logs)} volatile validation logs"
        if skipped_mutable_aggregate_hashes:
            detail += (
                f"; tolerated {len(skipped_mutable_aggregate_hashes)} mutable aggregate "
                "hash drift entries"
            )
        if skipped_regenerated_validation_hashes:
            detail += (
                f"; tolerated {len(skipped_regenerated_validation_hashes)} regenerated "
                "validation report hash drift entries"
            )
        add_check("artifact_sha_manifest_integrity", True, detail)


# ── main validation entry point ──────────────────────────────────────────────


def _is_continuous_campaign(metadata: dict[str, Any] | None) -> bool:
    if metadata is None:
        return False
    return metadata.get("driver_mode") == "continuous" or bool(metadata.get("schedule_v4"))


def _resolve_schedule_v4_path(campaign_dir: Path, metadata: dict[str, Any]) -> Path:
    raw = str(metadata.get("schedule_v4") or "metrics/schedule_v4.jsonl")
    schedule_path = Path(raw)
    if not schedule_path.is_absolute():
        schedule_path = campaign_dir / schedule_path
    return schedule_path


def _load_schedule_v4_state(campaign_dir: Path, metadata: dict[str, Any], add_check):
    schedule_path = _resolve_schedule_v4_path(campaign_dir, metadata)
    if not schedule_path.exists():
        add_check("schedule_v4_exists", False, str(schedule_path), severity="error")
        return None
    try:
        from pmpfuzz.schedule_v4 import recover_schedule_v4

        recovered = recover_schedule_v4(schedule_path)
    except Exception as exc:
        add_check("schedule_v4_readable", False, str(exc), severity="error")
        return None
    add_check("schedule_v4_readable", True, str(schedule_path))
    return recovered


def _load_schedule_v4_stop_reasons(campaign_dir: Path, metadata: dict[str, Any]) -> list[str]:
    schedule_path = _resolve_schedule_v4_path(campaign_dir, metadata)
    if not schedule_path.exists():
        return []
    try:
        rows = [
            json.loads(line)
            for line in schedule_path.read_text(encoding="ascii").splitlines()
            if line.strip()
        ]
    except Exception:
        return []
    return [
        str(row.get("stop_reason") or "").strip()
        for row in rows
        if str(row.get("event") or "") in {"stop_latched", "checkpoint", "campaign_closed"}
        and str(row.get("stop_reason") or "").strip()
    ]


def _normalize_coverage_sections(
    cov: dict[str, Any],
    metadata: dict[str, Any] | None,
) -> dict[str, dict[str, Any]] | None:
    exec_cov = cov.get("execution_coverage", {}).get("by_dut", {})
    if isinstance(exec_cov, dict) and exec_cov:
        dut_name = str((metadata or {}).get("dut") or "")
        raw_sections = exec_cov.get(dut_name) if dut_name else next(iter(exec_cov.values()))
        if not isinstance(raw_sections, dict):
            return None
        normalized: dict[str, dict[str, Any]] = {}
        for mode in tuple(_REQUIRED_COVERAGE_MODES) + _SINGLE_MODE_COVERAGE_MODES:
            section = raw_sections.get(mode)
            if not isinstance(section, dict):
                continue
            normalized[mode] = {
                "covered_target_bins": int(section.get("covered_target_bins", 0)),
                "total_target_bins": int(section.get("total_target_bins", 0)),
                "covered_bins": sorted({str(item) for item in (section.get("covered_bins") or [])}),
                "universe_sha256": section.get("universe_sha256"),
            }
        return normalized
    if cov.get("schema_version") == 6 and cov.get("driver_mode") == "campaign":
        return {
            "semantic": {
                "covered_target_bins": int(cov.get("covered_target_bins", 0)),
                "total_target_bins": int(cov.get("target_bins", 0)),
                "covered_bins": sorted({str(item) for item in (cov.get("semantic_bins") or [])}),
                "universe_sha256": (cov.get("coverage_universe_hashes") or {}).get("semantic"),
            },
            "pairwise": {
                "covered_target_bins": int(cov.get("covered_target_combo_bins", 0)),
                "total_target_bins": int(cov.get("target_combo_bins", 0)),
                "covered_bins": sorted({str(item) for item in (cov.get("pairwise_bins") or [])}),
                "universe_sha256": (cov.get("coverage_universe_hashes") or {}).get("pairwise"),
            },
            "security_triples": {
                "covered_target_bins": int(cov.get("covered_target_triples", 0)),
                "total_target_bins": int(cov.get("target_triples", 0)),
                "covered_bins": sorted({str(item) for item in (cov.get("security_triples_bins") or [])}),
                "universe_sha256": (cov.get("coverage_universe_hashes") or {}).get("security_triples"),
            },
            "predicates": {
                "covered_target_bins": int(cov.get("covered_target_predicates", 0)),
                "total_target_bins": int(cov.get("target_predicates", 0)),
                "covered_bins": sorted({str(item) for item in (cov.get("predicate_bins") or [])}),
                "universe_sha256": (cov.get("coverage_universe_hashes") or {}).get("predicates"),
            },
            "hpm": {
                "covered_target_bins": int(cov.get("covered_target_hpm_bins", 0)),
                "total_target_bins": int(cov.get("target_hpm_bins", 0)),
                "covered_bins": sorted({str(item) for item in (cov.get("hpm_bins") or [])}),
                "universe_sha256": (cov.get("coverage_universe_hashes") or {}).get("hpm"),
            },
            "bapc": {
                "covered_target_bins": int(cov.get("covered_target_bapc_bins", 0)),
                "total_target_bins": int(cov.get("target_bapc_bins", 0)),
                "covered_bins": sorted({str(item) for item in (cov.get("bapc_bins") or [])}),
                "universe_sha256": (cov.get("coverage_universe_hashes") or {}).get("bapc"),
            },
        }
    return None


def _check_continuous_universe_artifacts(
    campaign_dir: Path,
    metadata: dict[str, Any],
    coverage_sections: dict[str, dict[str, Any]] | None,
    lines: list[dict[str, Any]],
    recovered,
    add_check,
) -> None:
    required_modes = _required_coverage_modes_for_metadata(metadata)
    files = metadata.get("coverage_universe_files") or {}
    hashes = metadata.get("coverage_universe_hashes") or {}
    missing = [mode for mode in required_modes if mode not in files or mode not in hashes]
    if missing:
        add_check(
            "coverage_universe_metadata_complete",
            False,
            f"missing coverage universe metadata for: {missing}",
            severity="error",
        )
        return
    add_check("coverage_universe_metadata_complete", True)

    from pmpfuzz.coverage_universe import validate_coverage_universe
    from pmpfuzz.bapc import load_bapc_coverage_universe

    last = lines[-1] if lines else {}
    for mode in required_modes:
        raw_path = Path(str(files[mode]))
        universe_path = raw_path if raw_path.is_absolute() else campaign_dir / raw_path
        if not universe_path.exists():
            add_check(f"coverage_universe_file_{mode}", False, str(universe_path), severity="error")
            continue
        try:
            if mode == "bapc":
                universe = load_bapc_coverage_universe(universe_path)
            else:
                universe = json.loads(universe_path.read_text(encoding="ascii"))
                validate_coverage_universe(universe)
        except Exception as exc:
            add_check(f"coverage_universe_file_{mode}", False, str(exc), severity="error")
            continue
        expected_hash = str(hashes.get(mode) or "")
        actual_hash = str(universe.get("sha256") or "")
        if expected_hash != actual_hash:
            add_check(
                f"coverage_universe_sha_{mode}",
                False,
                f"metadata={expected_hash} file={actual_hash}",
                severity="error",
            )
            continue
        coverage_hash = str((coverage_sections or {}).get(mode, {}).get("universe_sha256") or "")
        if coverage_sections is not None and coverage_hash != actual_hash:
            add_check(
                f"coverage_universe_sha_{mode}",
                False,
                f"coverage={coverage_hash} file={actual_hash}",
                severity="error",
            )
            continue
        add_check(f"coverage_universe_sha_{mode}", True, actual_hash[:12])
        timeline_target_key = _TIMELINE_KEYS_BY_MODE[mode][1]
        timeline_target = int(last.get(timeline_target_key, 0) or 0)
        coverage_target = int((coverage_sections or {}).get(mode, {}).get("total_target_bins", 0) or 0)
        universe_target = int(universe.get("bin_count", 0) or 0)
        if coverage_sections is not None and timeline_target == universe_target and coverage_target == universe_target:
            add_check(f"coverage_universe_target_{mode}", True, str(universe_target))
        else:
            add_check(
                f"coverage_universe_target_{mode}",
                False,
                f"timeline={timeline_target} coverage={coverage_target} universe={universe_target}",
                severity="error",
            )
        universe_bins = set(str(item) for item in (universe.get("bin_ids") or []))
        coverage_bins = set((coverage_sections or {}).get(mode, {}).get("covered_bins") or [])
        schedule_bins = set(getattr(recovered, "coverage_state", {}).get(mode, set()) or set())
        out_of_contract = sorted((coverage_bins | schedule_bins) - universe_bins)
        if out_of_contract:
            add_check(
                f"coverage_universe_membership_{mode}",
                False,
                f"out_of_contract_bins={out_of_contract[:5]}",
                severity="error",
            )
        else:
            add_check(f"coverage_universe_membership_{mode}", True)


def _check_continuous_schedule_consistency(lines: list[dict[str, Any]], recovered, coverage_sections, add_check) -> None:
    if not lines:
        return
    last = lines[-1]
    if int(last.get("completed_cases", 0)) == int(getattr(recovered, "completed_cases", 0)):
        add_check("schedule_v4_completed_cases_match_timeline", True)
    else:
        add_check(
            "schedule_v4_completed_cases_match_timeline",
            False,
            f"timeline={last.get('completed_cases')} schedule_v4={getattr(recovered, 'completed_cases', 0)}",
            severity="error",
        )
    if int(last.get("eligible_cases", 0)) == int(getattr(recovered, "eligible_cases", 0)):
        add_check("schedule_v4_eligible_cases_match_timeline", True)
    else:
        add_check(
            "schedule_v4_eligible_cases_match_timeline",
            False,
            f"timeline={last.get('eligible_cases')} schedule_v4={getattr(recovered, 'eligible_cases', 0)}",
            severity="error",
        )

    required_modes = tuple(
        mode for mode in getattr(recovered, "coverage_state", {}).keys() if mode in _TIMELINE_KEYS_BY_MODE
    ) or _REQUIRED_COVERAGE_MODES
    for mode in required_modes:
        tl_key_covered, tl_key_target = _TIMELINE_KEYS_BY_MODE[mode]
        schedule_bins = set(getattr(recovered, "coverage_state", {}).get(mode, set()) or set())
        timeline_covered = int(last.get(tl_key_covered, 0) or 0)
        timeline_target = int(last.get(tl_key_target, 0) or 0)
        if timeline_covered == len(schedule_bins):
            add_check(f"schedule_v4_{mode}_matches_timeline", True)
        else:
            add_check(
                f"schedule_v4_{mode}_matches_timeline",
                False,
                f"timeline={timeline_covered}/{timeline_target} schedule_v4={len(schedule_bins)}",
                severity="error",
            )
        if coverage_sections is None or mode not in coverage_sections:
            continue
        coverage_section = coverage_sections[mode]
        coverage_bins = set(coverage_section.get("covered_bins") or [])
        coverage_count = int(coverage_section.get("covered_target_bins", 0) or 0)
        if coverage_bins == schedule_bins and coverage_count == len(schedule_bins):
            add_check(f"schedule_v4_{mode}_matches_coverage", True)
        else:
            add_check(
                f"schedule_v4_{mode}_matches_coverage",
                False,
                f"coverage_count={coverage_count} coverage_bins={len(coverage_bins)} schedule_v4={len(schedule_bins)}",
                severity="error",
            )


def validate_timeline(
    campaign_dir: Path,
    *,
    defer_cross_campaign_artifact_manifest: bool = False,
) -> dict[str, Any]:
    """Run all validation checks and return a report.

    Returns a dict with ``valid`` (bool), ``error_count``, ``warning_count``,
    and a ``checks`` list of per-check results.
    """
    timeline_path = campaign_dir / "metrics" / "coverage_timeline.jsonl"
    metadata_path = campaign_dir / "metrics" / "campaign_metadata.json"
    coverage_path = campaign_dir / "coverage" / "coverage.json"

    report: dict[str, Any] = {
        "schema_version": "1.0",
        "campaign": str(campaign_dir),
        "checked_utc": None,
        "error_count": 0,
        "warning_count": 0,
        "checks": [],
        "stop_reason": None,
        "valid": True,
    }
    from datetime import datetime, timezone
    report["checked_utc"] = datetime.now(timezone.utc).isoformat()

    def add_check(name: str, passed: bool, detail: str = "",
                  severity: str = "error") -> None:
        report["checks"].append({
            "name": name, "passed": passed, "severity": severity, "detail": detail,
        })
        if not passed:
            if severity == "error":
                report["error_count"] += 1
            else:
                report["warning_count"] += 1

    # ── determine validation mode ────────────────────────────────────────
    metadata: dict[str, Any] | None = _load_metadata(metadata_path)
    artifact_root = _resolve_artifact_root(campaign_dir)
    experiment_contract = _load_experiment_contract(artifact_root)
    formal_bapc_context = _is_bapc_formal_validation_context(metadata, experiment_contract)
    run_class, is_strict, is_known_run_class = _classify_run_class(
        metadata.get("run_class") if metadata else None
    )
    if formal_bapc_context:
        is_strict = True
    is_dev_smoke = run_class == "development-smoke"
    is_continuous = _is_continuous_campaign(metadata)
    # is_legacy: metadata present but run_class absent → legacy warn-on-provenance

    def _provenance_severity() -> str:
        """Return the severity for global-provenance checks (manifests, SHAs)."""
        if is_strict:
            return "error"
        return "warning"

    # ── 1. Metadata must exist (error for all modes) ─────────────────────
    if metadata is None:
        add_check("metadata_exists", False, "missing campaign_metadata.json",
                  severity="error")
    else:
        add_check("metadata_exists", True)
        if run_class:
            add_check("run_class_known", is_known_run_class, run_class, severity="error")

    # ── 2. JSONL exists and every line parseable ─────────────────────────
    if not timeline_path.exists():
        add_check("timeline_exists", False, str(timeline_path))
        report["valid"] = False
        return report

    try:
        raw_lines = timeline_path.read_text(encoding="ascii").strip().split("\n")
    except Exception as exc:
        add_check("timeline_readable", False, str(exc))
        report["valid"] = False
        return report

    lines: list[dict[str, Any]] = []
    for i, raw in enumerate(raw_lines):
        if not raw.strip():
            continue
        try:
            lines.append(json.loads(raw))
        except json.JSONDecodeError as exc:
            add_check("parse_line", False, f"line {i}: {exc}")
    if not lines:
        add_check("timeline_nonempty", False, "no valid lines")
        report["valid"] = False
        return report
    add_check("timeline_nonempty", True, f"{len(lines)} lines")

    schedule_state = None
    schedule_stop_reasons: list[str] = []
    if is_continuous and metadata is not None:
        schedule_state = _load_schedule_v4_state(campaign_dir, metadata, add_check)
        schedule_stop_reasons = _load_schedule_v4_stop_reasons(campaign_dir, metadata)

    # ── 3. campaign_id consistent ───────────────────────────────────────
    campaign_ids = {line.get("campaign_id") for line in lines if line.get("campaign_id")}
    if len(campaign_ids) == 0:
        add_check("campaign_id_present", False, "no campaign_id found")
    elif len(campaign_ids) > 1:
        add_check("campaign_id_unique", False, f"multiple: {campaign_ids}")
    else:
        add_check("campaign_id_unique", True)

    # ── 4. completion_seq continuous from 0 ──────────────────────────────
    # Requirement 11: exactly one baseline row (seq=0, case_id=None) is
    # valid; real completion sequences must be 1..N continuous.
    seqs = [line.get("completion_seq") for line in lines
            if line.get("completion_seq") is not None]
    if seqs:
        expected = list(range(len(seqs)))
        if seqs == expected:
            add_check("completion_seq_continuous", True)
        else:
            add_check("completion_seq_continuous", False,
                      f"expected {expected[:5]}..., got {seqs[:5]}...")

    # ── 5. elapsed_wall_seconds monotonically non-decreasing ─────────────
    times = [line.get("elapsed_wall_seconds") for line in lines
             if line.get("elapsed_wall_seconds") is not None]
    if times:
        monotonic = all(times[i] >= times[i - 1] for i in range(1, len(times)))
        if monotonic:
            add_check("wall_seconds_monotonic", True)
        else:
            add_check("wall_seconds_monotonic", False, "found decreasing wall time")

    # ── 6. Coverage rates monotonically non-decreasing ───────────────────
    for key in ["semantic_rate", "pairwise_rate", "security_triples_rate",
                "predicates_rate", "hpm_rate", "bapc_rate"]:
        rates = [line.get(key) for line in lines[1:]
                 if line.get(key) is not None]
        if rates:
            non_decr = all(
                (rates[i] or 0) >= (rates[i - 1] or 0) - 1e-9
                for i in range(1, len(rates))
            )
            if not non_decr:
                add_check(f"{key}_monotonic", False,
                          "rate decreased at some point")

    # ── 7. Denominator constant ─────────────────────────────────────────
    for key in ["semantic_target", "pairwise_target", "security_triples_target",
                "predicates_target", "hpm_target", "bapc_target"]:
        targets = [line.get(key) for line in lines if line.get(key) is not None]
        if targets:
            unique = set(targets)
            if len(unique) == 1:
                add_check(f"{key}_constant", True)
            else:
                add_check(f"{key}_constant", False, f"varies: {unique}")

    # ── 8. Rate = covered / target ──────────────────────────────────────
    for prefix in ["semantic", "pairwise", "security_triples", "predicates", "hpm", "bapc"]:
        for line in lines[1:]:
            covered = line.get(f"{prefix}_covered")
            target = line.get(f"{prefix}_target")
            rate = line.get(f"{prefix}_rate")
            if (covered is not None and target is not None
                    and target > 0 and rate is not None):
                expected_rate = covered / target
                if abs(rate - expected_rate) > 1e-9:
                    add_check(
                        f"{prefix}_rate_consistent", False,
                        f"seq={line.get('completion_seq')}: "
                        f"rate={rate} != {covered}/{target}={expected_rate}",
                    )
                    break
        else:
            add_check(f"{prefix}_rate_consistent", True)

    # ── 9. Final timeline matches coverage.json ──────────────────────────
    cov: dict[str, Any] | None = None
    coverage_sections: dict[str, dict[str, Any]] | None = None
    coverage_severity = "error" if is_continuous else "warning"
    if coverage_path.exists():
        try:
            cov = json.loads(coverage_path.read_text(encoding="ascii"))
            add_check("coverage_json_readable", True)
            exec_cov = cov.get("execution_coverage", {}).get("by_dut", {})
            dut_name = str((metadata or {}).get("dut") or "")
            if is_continuous and isinstance(exec_cov, dict) and exec_cov:
                if dut_name and dut_name not in exec_cov:
                    add_check(
                        "coverage_by_dut_matches_metadata",
                        False,
                        f"metadata dut {dut_name!r} missing from by_dut keys {sorted(exec_cov)}",
                        severity="error",
                    )
                else:
                    add_check("coverage_by_dut_matches_metadata", True, dut_name or "first-by-dut")
                    coverage_sections = _normalize_coverage_sections(cov, metadata)
            else:
                coverage_sections = _normalize_coverage_sections(cov, metadata)
        except Exception as exc:
            add_check("coverage_json_readable", False, str(exc), severity=coverage_severity)
    elif is_continuous:
        add_check("coverage_json_readable", False, f"missing: {coverage_path}", severity="error")

    if coverage_sections is not None:
        last = lines[-1]

        def _check_coverage_match(label, tl_key_covered, tl_key_target, cov_section):
            if not cov_section:
                return
            tl_covered = last.get(tl_key_covered, 0)
            tl_target = last.get(tl_key_target, 0)
            cov_covered = cov_section.get("covered_target_bins", 0)
            cov_target = cov_section.get("total_target_bins", 0)
            if tl_covered == cov_covered and tl_target == cov_target:
                add_check(f"final_{label}_matches_coverage", True)
            else:
                add_check(
                    f"final_{label}_matches_coverage", False,
                    f"timeline: {tl_covered}/{tl_target}, coverage: {cov_covered}/{cov_target}",
                )

        _check_coverage_match("semantic", "semantic_covered", "semantic_target", coverage_sections.get("semantic"))
        _check_coverage_match("pairwise", "pairwise_covered", "pairwise_target", coverage_sections.get("pairwise"))
        _check_coverage_match(
            "triples",
            "security_triples_covered",
            "security_triples_target",
            coverage_sections.get("security_triples"),
        )
        _check_coverage_match(
            "predicates",
            "predicates_covered",
            "predicates_target",
            coverage_sections.get("predicates"),
        )
        _check_coverage_match("hpm", "hpm_covered", "hpm_target", coverage_sections.get("hpm"))
        _check_coverage_match("bapc", "bapc_covered", "bapc_target", coverage_sections.get("bapc"))
    if is_continuous:
        required_modes = _required_coverage_modes_for_metadata(metadata)
        missing_modes = [mode for mode in required_modes if mode not in (coverage_sections or {})]
        if missing_modes:
            add_check("coverage_modes_complete", False, f"missing modes: {missing_modes}", severity="error")
        else:
            add_check("coverage_modes_complete", True)

    # ── 10. Case/result existence on disk ───────────────────────────────
    _check_case_result_integrity(campaign_dir, lines, add_check)

    # ── 11. Orphan & duplicate detection ────────────────────────────────
    _check_orphans_and_duplicates(campaign_dir, lines, add_check)

    # ── 12. Metadata identity vs timeline ───────────────────────────────
    _check_metadata_identity(metadata, lines, add_check)
    metadata_stop_reason_raw = str((metadata or {}).get("stop_reason") or "").strip()
    normalized_metadata_stop_reason = normalize_stop_reason(metadata_stop_reason_raw)
    normalized_schedule_stop_reason = normalize_stop_reason(getattr(schedule_state, "stop_reason", None))
    report["stop_reason"] = normalized_metadata_stop_reason or normalized_schedule_stop_reason
    normalized_schedule_stop_reasons = {
        normalize_stop_reason(reason) for reason in schedule_stop_reasons if normalize_stop_reason(reason) is not None
    }
    if schedule_stop_reasons:
        add_check(
            "schedule_stop_reason_consistent",
            len(normalized_schedule_stop_reasons) <= 1,
            ", ".join(sorted(set(schedule_stop_reasons))),
            severity="error",
        )
    if normalized_metadata_stop_reason is not None and normalized_schedule_stop_reason is not None:
        add_check(
            "stop_reason_consistent",
            normalized_metadata_stop_reason == normalized_schedule_stop_reason,
            f"metadata={normalized_metadata_stop_reason} schedule={normalized_schedule_stop_reason}",
            severity="error",
        )
    if formal_bapc_context:
        _check_bapc_formal_contract(
            campaign_dir=campaign_dir,
            metadata=metadata,
            contract=experiment_contract,
            normalized_stop_reason=report["stop_reason"],
            add_check=add_check,
        )
    if run_class in _FORMAL_RUN_CLASSES:
        legacy_names = sorted(
            {
                reason
                for reason in [metadata_stop_reason_raw, *schedule_stop_reasons]
                if is_legacy_hard_cap_reason(reason)
            }
        )
        add_check(
            "formal_stop_reason_legacy_name_rejected",
            not legacy_names,
            ", ".join(legacy_names) if legacy_names else "no legacy stop reasons",
            severity="error",
        )

    # ── 13. SHA / capability completeness (strict → error) ───────────────
    if metadata is not None:
        source_sha = metadata.get("source_sha", "")
        if source_sha:
            add_check("source_sha_present", True, str(source_sha)[:12])
            add_check("source_sha_format", _is_hex_digest(source_sha, 40), str(source_sha),
                      severity=_provenance_severity())
        else:
            add_check("source_sha_present", False, "empty or missing source_sha",
                      severity=_provenance_severity())

        source_tree_sha256 = metadata.get("source_tree_sha256", "")
        if source_tree_sha256:
            add_check("source_tree_sha256_format", _is_hex_digest(source_tree_sha256, 64),
                      str(source_tree_sha256)[:12], severity=_provenance_severity())
        elif is_strict:
            add_check("source_tree_sha256_format", False, "missing source_tree_sha256", severity="error")

        source_dirty = metadata.get("source_dirty")
        if isinstance(source_dirty, bool):
            add_check("source_dirty_typed", True, str(source_dirty))
        elif is_strict:
            add_check("source_dirty_typed", False, "source_dirty must be bool", severity="error")
        if formal_bapc_context:
            add_check(
                "source_dirty_false",
                source_dirty is False,
                repr(source_dirty),
                severity="error",
            )

        dut_sha_status = str(metadata.get("dut_sha_status") or "")
        dut_sha = metadata.get("dut_sha", "")
        if dut_sha_status == "not-applicable":
            reason = str(metadata.get("dut_sha_reason") or "")
            add_check("dut_sha_present", bool(reason), reason or "missing dut_sha_reason",
                      severity=_provenance_severity())
        elif dut_sha:
            add_check("dut_sha_present", True, str(dut_sha)[:12])
            add_check("dut_sha_format", _is_hex_digest(dut_sha, 40), str(dut_sha),
                      severity=_provenance_severity())
        else:
            add_check("dut_sha_present", False, "empty or missing dut_sha",
                      severity=_provenance_severity())

        dut_binary_sha256 = metadata.get("dut_binary_sha256", "")
        if dut_binary_sha256:
            add_check("dut_binary_sha256_present", True, str(dut_binary_sha256)[:12])
            add_check("dut_binary_sha256_format", _is_hex_digest(dut_binary_sha256, 64),
                      str(dut_binary_sha256), severity=_provenance_severity())
        else:
            add_check("dut_binary_sha256_present", False, "empty or missing dut_binary_sha256",
                      severity=_provenance_severity())

        dut_binary_path_raw = str(metadata.get("dut_binary_path") or "")
        dut_binary_path = Path(dut_binary_path_raw) if dut_binary_path_raw else None
        if dut_binary_path is not None and dut_binary_path.exists() and dut_binary_path.is_file():
            add_check("dut_binary_path_exists", True, str(dut_binary_path))
            if dut_binary_sha256:
                actual_sha = hashlib.sha256(dut_binary_path.read_bytes()).hexdigest()
                add_check("dut_binary_sha256_matches_file", actual_sha == dut_binary_sha256,
                          f"metadata={dut_binary_sha256} file={actual_sha}",
                          severity=_provenance_severity())
        elif is_strict:
            add_check("dut_binary_path_exists", False, "dut_binary_path missing or unreadable", severity="error")

        capability_fingerprint = metadata.get("capability_fingerprint", "")
        if capability_fingerprint:
            add_check("capability_fingerprint_present", True, str(capability_fingerprint)[:12])
        else:
            add_check("capability_fingerprint_present", False, "empty or missing capability_fingerprint",
                      severity=_provenance_severity())

    # ── 14. Whitebox events monotonic ───────────────────────────────────
    wb_events = [line.get("whitebox_distinct_events", 0) or 0
                 for line in lines if line.get("completion_seq", 0) > 0]
    if wb_events and any(
            wb_events[i] < wb_events[i - 1] for i in range(1, len(wb_events))):
        add_check("whitebox_events_monotonic", False, "whitebox events decreased")
    elif wb_events:
        add_check("whitebox_events_monotonic", True)

    # ── 15. Child round timelines (always error) ────────────────────────
    _check_child_timelines(campaign_dir, add_check)

    # ── 16. Provenance manifests ────────────────────────────────────────
    artifact_root = _resolve_artifact_root(campaign_dir)
    if artifact_root is not None:
        manifests_dir = artifact_root / "manifests"
        for manifest_file in ["environment.json", "git-shas.txt"]:
            if (manifests_dir / manifest_file).exists():
                add_check(f"manifest_{manifest_file}", True)
            else:
                add_check(f"manifest_{manifest_file}", False,
                          f"not found in {manifests_dir}",
                          severity=_provenance_severity())

        # ── 17. artifact-sha256.txt ─────────────────────────────────────
        if formal_bapc_context:
            add_check(
                "manifest_experiment_contract.json",
                (manifests_dir / "experiment-contract.json").exists(),
                f"not found in {manifests_dir}",
                severity="error",
            )
        sha_manifest = manifests_dir / "artifact-sha256.txt"
        if sha_manifest.exists():
            add_check("artifact_sha_manifest_exists", True)
            if (
                defer_cross_campaign_artifact_manifest
                and _is_cross_campaign_artifact_root(campaign_dir, artifact_root)
            ):
                add_check(
                    "artifact_sha_manifest_deferred",
                    True,
                    f"deferred cross-campaign root manifest verification for {artifact_root}",
                )
            else:
                _check_artifact_sha_manifest(artifact_root, add_check)
        else:
            add_check("artifact_sha_manifest_exists", False,
                      f"not found: {sha_manifest}",
                      severity=_provenance_severity())
    else:
        # Cannot resolve artifact root — warn or error depending on mode.
        add_check("artifact_root_resolved", False,
                  "cannot resolve artifact root from campaign path",
                  severity=_provenance_severity())

    # ── Final validity ──────────────────────────────────────────────────
    if is_continuous and metadata is not None:
        _check_continuous_universe_artifacts(
            campaign_dir,
            metadata,
            coverage_sections,
            lines,
            schedule_state,
            add_check,
        )
        if schedule_state is not None:
            _check_continuous_schedule_consistency(lines, schedule_state, coverage_sections, add_check)
    report["campaign_id"] = str((metadata or {}).get("campaign_id") or (next(iter(campaign_ids)) if len(campaign_ids) == 1 else ""))
    report["inputs"] = _validation_input_bindings(
        campaign_dir,
        metadata,
        artifact_root=artifact_root,
        formal_bapc_context=formal_bapc_context,
    )
    report["valid"] = report["error_count"] == 0
    return report


def _schema6_coverage_sections(cov: dict[str, object]) -> dict[str, dict[str, object]] | None:
    if cov.get("schema_version") != 6 or cov.get("driver_mode") != "campaign":
        return None
    return {
        "semantic": {
            "covered_target_bins": cov.get("covered_target_bins", 0),
            "total_target_bins": cov.get("target_bins", 0),
        },
        "pairwise": {
            "covered_target_bins": cov.get("covered_target_combo_bins", 0),
            "total_target_bins": cov.get("target_combo_bins", 0),
        },
        "security_triples": {
            "covered_target_bins": cov.get("covered_target_triples", 0),
            "total_target_bins": cov.get("target_triples", 0),
        },
        "predicates": {
            "covered_target_bins": cov.get("covered_target_predicates", 0),
            "total_target_bins": cov.get("target_predicates", 0),
        },
    }


# ── retained: D4 case/result integrity helper ────────────────────────────────


def _check_case_result_integrity(campaign_dir: Path, lines: list[dict],
                                  add_check) -> None:
    """Check that timeline case_ids have corresponding case.json and result.json."""
    cases_dir = campaign_dir / "cases"
    results_dir = campaign_dir / "results"

    if not cases_dir.is_dir() or not results_dir.is_dir():
        return

    tl_case_ids: set[str] = set()
    for line in lines:
        cid = line.get("case_id")
        if cid and line.get("completion_seq", 0) > 0:
            tl_case_ids.add(cid)

    missing_cases = []
    missing_results = []
    for cid in sorted(tl_case_ids):
        if not (cases_dir / cid / "case.json").exists():
            missing_cases.append(cid)
        if not (results_dir / cid / "result.json").exists():
            missing_results.append(cid)

    if missing_cases:
        add_check("case_files_exist", False,
                  f"{len(missing_cases)} missing: {missing_cases[:3]}...")
    else:
        add_check("case_files_exist", True,
                  f"all {len(tl_case_ids)} cases present")

    if missing_results:
        add_check("result_files_exist", False,
                  f"{len(missing_results)} missing: {missing_results[:3]}...")
    else:
        add_check("result_files_exist", True,
                  f"all {len(tl_case_ids)} results present")


# ── CLI ──────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate a campaign timeline for data integrity")
    parser.add_argument("--campaign", type=Path, required=True,
                        help="Path to campaign output directory")
    parser.add_argument(
        "--defer-cross-campaign-artifact-manifest",
        action="store_true",
        help=(
            "Defer artifact-sha256.txt verification when the resolved artifact "
            "root spans sibling campaigns. Intended only for mid-matrix "
            "validation before the shared DUT-root artifact set is stable."
        ),
    )
    args = parser.parse_args(argv)

    campaign_dir = args.campaign.resolve()
    if not campaign_dir.is_dir():
        print(f"ERROR: campaign directory not found: {campaign_dir}",
              file=sys.stderr)
        return 1

    report = validate_timeline(
        campaign_dir,
        defer_cross_campaign_artifact_manifest=args.defer_cross_campaign_artifact_manifest,
    )

    # Write validation result
    val_path = campaign_dir / "validation.json"
    val_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )

    # Print summary
    print(f"campaign={campaign_dir}")
    print(f"valid={report['valid']} errors={report['error_count']} "
          f"warnings={report['warning_count']}")
    for check in report["checks"]:
        status = "PASS" if check["passed"] else "FAIL"
        print(f"  [{status}] {check['name']}: {check.get('detail', '')}")

    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
