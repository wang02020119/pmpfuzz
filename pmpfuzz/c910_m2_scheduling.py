from __future__ import annotations

import hashlib
import json
import random
from typing import Any

from .c910_nonpmp_dynamic import build_dynamic_manifest
from .v4_nonpmp_projection import (
    _MCAUSE_TO_CLASS,
    architectural_oracle_allow,
    map_target_operation,
)






M2_BUDGET_PER_ROUND = 16
M2_NUM_ROUNDS = 3
M2_UNIVERSE = "v4-nonpmp-56"


def predict_shared56_bins(case: dict[str, Any]) -> dict[str, Any]:
    access = str(case.get("access") or "").strip().lower()
    translation = str(case.get("translation") or "").strip().lower()
    oracle = architectural_oracle_allow(case)
    expected = case.get("expected") or {}
    if oracle is None:
        allow = bool(expected.get("allowed", True))
    else:
        allow = oracle
    outcome = "allow" if allow else "deny"
    mcause_class = None
    if not allow:
        cause = expected.get("trap_cause")
        if cause is not None:
            mcause_class = _MCAUSE_TO_CLASS.get(int(cause))
        if mcause_class is None:
            mcause_class = {
                "fetch": "instruction_page_fault" if translation == "sv39" else "instruction_access_fault",
                "load": "load_page_fault" if translation == "sv39" else "load_access_fault",
                "store": "store_page_fault" if translation == "sv39" else "store_access_fault",
            }.get(access)
    return map_target_operation(
        privilege=case.get("privilege"),
        effective_privilege=case.get("effective_privilege"),
        access=access,
        translation=translation,
        allow_or_deny=outcome,
        mcause_class=mcause_class,
    )


def _case_fingerprint(case: dict[str, Any]) -> str:
    return str(case.get("scenario_hash") or case.get("name") or "")


def _mapped_selection_candidates(
    catalog: list[dict[str, Any]],
    *,
    used_fingerprints: set[str],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for case in catalog:
        if _case_fingerprint(case) in used_fingerprints:
            continue
        predicted = predict_shared56_bins(case)
        if predicted["status"] != "mapped":
            continue
        candidates.append({"case": case, "predicted": predicted})
    return candidates


def select_guided(
    catalog: list[dict[str, Any]],
    *,
    covered_bins: set[str],
    used_fingerprints: set[str],
    seed: int,
    budget: int,
) -> list[tuple[str, dict[str, Any]]]:
    rng = random.Random(seed)
    candidates = _mapped_selection_candidates(catalog, used_fingerprints=used_fingerprints)
    rng.shuffle(candidates)

    covered = set(covered_bins)
    used_records: set[str] = set()
    selected: list[tuple[str, dict[str, Any]]] = []
    for _ in range(budget):
        best: dict[str, Any] | None = None
        best_key: tuple[int, int] | None = None
        for index, item in enumerate(candidates):
            if str(item["case"].get("uart_record")) in used_records:
                continue
            gain = len(set(item["predicted"]["bins"]) - covered)
            key = (gain, -index)
            if best_key is None or key > best_key:
                best = item
                best_key = key
        if best is None:
            break
        gain = len(set(best["predicted"]["bins"]) - covered)
        selected.append(
            (best["case"]["name"], {"estimated_new_bins": gain, "predicted_bins": best["predicted"]["bins"]})
        )
        covered.update(best["predicted"]["bins"])
        used_records.add(str(best["case"].get("uart_record")))
        candidates.remove(best)
    return selected


def select_random(
    catalog: list[dict[str, Any]],
    *,
    used_fingerprints: set[str],
    seed: int,
    budget: int,
    covered_bins: set[str] | None = None,
) -> list[tuple[str, dict[str, Any]]]:
    rng = random.Random(seed)
    used_records: set[str] = set()
    selected: list[tuple[str, dict[str, Any]]] = []
    pool = _mapped_selection_candidates(catalog, used_fingerprints=used_fingerprints)
    rng.shuffle(pool)
    covered = set(covered_bins or set())
    for item in pool:
        if len(selected) >= budget:
            break
        case = item["case"]
        if str(case.get("uart_record")) in used_records:
            continue
        used_records.add(str(case.get("uart_record")))
        predicted = item["predicted"]
        gain = len(set(predicted["bins"]) - covered)
        selected.append(
            (case["name"], {"estimated_new_bins": gain, "predicted_bins": predicted.get("bins") or []})
        )
        covered.update(predicted["bins"])
    return selected


def build_m2_round(
    catalog: list[dict[str, Any]],
    *,
    mode: str,
    round_index: int,
    campaign_id: str,
    covered_bins: set[str],
    used_fingerprints: set[str],
    seed: int,
    budget: int = M2_BUDGET_PER_ROUND,
) -> dict[str, Any]:
    if mode == "guided":
        selections = select_guided(
            catalog, covered_bins=covered_bins, used_fingerprints=used_fingerprints,
            seed=seed, budget=budget,
        )
        selection_source = "m2-guided-v1"
    elif mode == "random":
        selections = select_random(
            catalog, used_fingerprints=used_fingerprints, seed=seed, budget=budget,
            covered_bins=covered_bins,
        )
        selection_source = "m2-random-v1"
    else:
        raise ValueError(f"unknown M-2 selection mode: {mode!r}")

    case_names = [name for name, _ in selections]
    estimated = {name: int(detail.get("estimated_new_bins") or 0) for name, detail in selections}
    manifest = build_dynamic_manifest(
        case_names=case_names,
        campaign_id=campaign_id,
        round_id=f"round-{round_index:04d}",
        selection_source=selection_source,
        estimated_new_bins_by_case=estimated,
    )
    provenance = {
        "mode": mode,
        "round_index": round_index,
        "seed": seed,
        "budget": budget,
        "campaign_id": campaign_id,
        "selection_source": selection_source,
        "covered_bins_input": sorted(covered_bins),
        "used_fingerprint_count": len(used_fingerprints),
        "catalog_case_count": len(catalog),
        "candidate_filter": "status=mapped",
        "candidate_pool_size": len(
            _mapped_selection_candidates(catalog, used_fingerprints=used_fingerprints)
        ),
        "selected_count": len(case_names),
        "estimated_new_bins_total": sum(estimated.values()),
        "selection_details": {
            name: detail for name, detail in selections
        },
        "manifest_sha256": manifest.get("sha256"),
    }
    return {"manifest": manifest, "provenance": provenance}


def aggregate_shared56(classifications: list[dict[str, Any]]) -> dict[str, Any]:
    covered: set[str] = set()
    mapped = 0
    unsupported = 0
    unqualified = 0
    compliant = 0
    violations: list[str] = []
    for report in classifications:
        status = report.get("status")
        if status == "mapped":
            mapped += 1
            covered.update(report.get("bins") or [])
            if report.get("known_violation"):
                violations.append(str(report.get("case_id")))
            elif report.get("oracle_expected") is not None:
                compliant += 1
        elif status == "unsupported":
            unsupported += 1
        else:
            unqualified += 1
    return {
        "universe": M2_UNIVERSE,
        "universe_size": 56,
        "covered_bins": sorted(covered),
        "covered_count": len(covered),
        "mapped": mapped,
        "unsupported": unsupported,
        "observation_unqualified": unqualified,
        "compliant": compliant,
        "known_violations": violations,
    }
