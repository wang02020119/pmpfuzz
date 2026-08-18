from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping

from pmpfuzz.pmp import Access, Privilege
from pmpfuzz.scenario import PmpScenario, ScenarioGenerator
from pmpfuzz.scenario_codec import scenario_hash, scenario_to_spec

from .reference_model import PRIMARY_SPEC_REVISION, build_reference_label


@dataclass(frozen=True)
class CaseSlice:
    family: str
    profile: str
    start: int
    count: int


DEFAULT_FAMILY_PLAN: tuple[CaseSlice, ...] = (
    CaseSlice("C1.bare_pmp_decisions", "pmp-boundary", 0, 72),
    CaseSlice("C2.matching_priority_boundaries", "pmp-boundary", 72, 72),
    CaseSlice("C3.sv39_pte_permissions", "sv39-perm-matrix", 0, 96),
    CaseSlice("C4.ptw_and_translated_access", "sv39-ptw-pmp-matrix", 0, 72),
    CaseSlice("C5.exception_precedence_metadata", "ooo-exception-priority", 0, 24),
    CaseSlice("C5.exception_precedence_metadata", "ooo-misaligned-page-cross-pmp", 0, 24),
    CaseSlice("C6.stateful_transitions_side_effects", "pmp-side-effect", 0, 24),
    CaseSlice("C6.stateful_transitions_side_effects", "tlb-stale-pte", 0, 24),
    CaseSlice("C6.stateful_transitions_side_effects", "tlb-stale-pmp", 0, 12),
    CaseSlice("C6.stateful_transitions_side_effects", "ptw-stale-pmp", 0, 12),
)


def build_reference_corpus(
    *,
    generator_seed: int,
    spec_revision: str,
    family_plan: Iterable[CaseSlice | Mapping[str, Any]] = DEFAULT_FAMILY_PLAN,
    case_id_offsets: Mapping[str, int] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []
    family_seq: Counter[str] = Counter()
    normalized_plan = tuple(_normalize_family_plan(family_plan))
    normalized_offsets = {str(key): int(value) for key, value in (case_id_offsets or {}).items()}

    for slice_plan in normalized_plan:
        generator = ScenarioGenerator(
            seed=generator_seed,
            include_smepmp=False,
            profile=slice_plan.profile,
        )
        scenarios = generator.generate_batch(slice_plan.start + slice_plan.count)
        selected = scenarios[slice_plan.start : slice_plan.start + slice_plan.count]
        for local_index, scenario in enumerate(selected, start=1):
            family_seq[slice_plan.family] += 1
            case_id = _case_id_for_family(
                slice_plan.family,
                family_seq[slice_plan.family] + normalized_offsets.get(slice_plan.family, 0),
            )
            case_record = _case_record(
                case_id=case_id,
                family=slice_plan.family,
                profile=slice_plan.profile,
                scenario_index=slice_plan.start + local_index - 1,
                generator_seed=generator_seed,
                scenario=scenario,
            )
            label = build_reference_label(case_record, spec_revision=spec_revision)
            cases.append(case_record)
            labels.append(label)

    factor_report = _build_factor_report(cases, normalized_plan, normalized_offsets)
    return cases, labels, factor_report


def write_reference_corpus(
    *,
    artifact_root: Path,
    generator_seed: int,
    spec_revision: str,
    family_plan: Iterable[CaseSlice | Mapping[str, Any]] = DEFAULT_FAMILY_PLAN,
    case_id_offsets: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    reference_dir = artifact_root / "reference"
    manifests_dir = artifact_root / "manifests"
    reference_dir.mkdir(parents=True, exist_ok=False)
    manifests_dir.mkdir(parents=True, exist_ok=True)

    cases, labels, factor_report = build_reference_corpus(
        generator_seed=generator_seed,
        spec_revision=spec_revision,
        family_plan=family_plan,
        case_id_offsets=case_id_offsets,
    )

    expected_case_count = sum(item.count for item in _normalize_family_plan(family_plan))
    if len(cases) != expected_case_count:
        raise ValueError(f"expected {expected_case_count} frozen cases, got {len(cases)}")

    cases_path = reference_dir / "cases.jsonl"
    labels_path = reference_dir / "labels.jsonl"
    factor_path = reference_dir / "factor-coverage.json"
    spec_path = reference_dir / "spec-revision.txt"

    _write_jsonl(cases_path, cases)
    _write_jsonl(labels_path, labels)
    factor_path.write_text(json.dumps(factor_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    spec_path.write_text(spec_revision + "\n", encoding="utf-8")

    cases_digest = sha256(cases_path.read_bytes()).hexdigest()
    labels_digest = sha256(labels_path.read_bytes()).hexdigest()
    (manifests_dir / "cases.sha256").write_text(f"{cases_digest}  reference/cases.jsonl\n", encoding="ascii")
    (manifests_dir / "labels.sha256").write_text(f"{labels_digest}  reference/labels.jsonl\n", encoding="ascii")

    return {
        "case_count": len(cases),
        "label_count": len(labels),
        "generator_seed": generator_seed,
        "spec_revision": spec_revision,
        "cases_sha256": cases_digest,
        "labels_sha256": labels_digest,
        "reference_dir": str(reference_dir),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the frozen Section 7.6 reference corpus")
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--generator-seed", type=int, default=7601)
    parser.add_argument("--spec-revision", default=PRIMARY_SPEC_REVISION)
    parser.add_argument("--family-plan-json", type=Path)
    parser.add_argument("--case-id-offsets-json", type=Path)
    args = parser.parse_args(argv)

    family_plan = _load_family_plan_json(args.family_plan_json) if args.family_plan_json else DEFAULT_FAMILY_PLAN
    case_id_offsets = _load_case_id_offsets_json(args.case_id_offsets_json) if args.case_id_offsets_json else None
    summary = write_reference_corpus(
        artifact_root=args.artifact_root,
        generator_seed=args.generator_seed,
        spec_revision=args.spec_revision,
        family_plan=family_plan,
        case_id_offsets=case_id_offsets,
    )
    print(
        f"reference-cases={summary['case_count']} labels={summary['label_count']} "
        f"cases_sha256={summary['cases_sha256']} labels_sha256={summary['labels_sha256']}"
    )
    return 0


def _case_record(
    *,
    case_id: str,
    family: str,
    profile: str,
    scenario_index: int,
    generator_seed: int,
    scenario: PmpScenario,
) -> dict[str, Any]:
    spec = scenario_to_spec(scenario)
    return {
        "schema_version": 1,
        "case_id": case_id,
        "family": family,
        "profile": profile,
        "scenario_index": scenario_index,
        "generator_seed": generator_seed,
        "scenario_name": scenario.name,
        "scenario_hash": scenario_hash(spec),
        "access_type": scenario.probe.access.value,
        "privilege": scenario.privilege.value,
        "mprv": scenario.mprv,
        "mpp": scenario.mpp.value,
        "effective_privilege": _effective_privilege_value(scenario),
        "translation_mode": scenario.translation.value,
        "probe_offset": scenario.probe.offset_name,
        "pmp_match_mode": scenario.pmp_match_mode,
        "stateful": bool(scenario.stateful_sequence),
        "coverage_tags": list(scenario.coverage_tags),
        "scenario_spec": spec,
    }


def _case_id_for_family(family: str, ordinal: int) -> str:
    prefix = family.split(".", 1)[0]
    return f"{prefix}-{ordinal:04d}"


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n")


def _build_factor_report(
    cases: list[dict[str, Any]],
    family_plan: Iterable[CaseSlice],
    case_id_offsets: Mapping[str, int],
) -> dict[str, Any]:
    family_counts = Counter(case["family"] for case in cases)
    by_family: dict[str, dict[str, Any]] = {}
    dimensions = (
        "profile",
        "access_type",
        "privilege",
        "mprv",
        "mpp",
        "effective_privilege",
        "translation_mode",
        "probe_offset",
        "pmp_match_mode",
        "stateful",
    )
    pair_dimensions = (
        ("access_type", "privilege"),
        ("access_type", "effective_privilege"),
        ("access_type", "translation_mode"),
        ("privilege", "translation_mode"),
        ("privilege", "mprv"),
        ("mprv", "mpp"),
        ("profile", "access_type"),
    )

    for family in sorted(family_counts):
        family_cases = [case for case in cases if case["family"] == family]
        dimension_counts: dict[str, dict[str, int]] = {}
        for dimension in dimensions:
            counter = Counter(str(case.get(dimension)) for case in family_cases)
            dimension_counts[dimension] = dict(sorted(counter.items()))

        pairwise: dict[str, dict[str, int]] = {}
        for left, right in pair_dimensions:
            counter: defaultdict[str, int] = defaultdict(int)
            for case in family_cases:
                key = f"{case.get(left)}|{case.get(right)}"
                counter[key] += 1
            pairwise[f"{left}__{right}"] = dict(sorted(counter.items()))

        by_family[family] = {
            "case_count": len(family_cases),
            "dimensions": dimension_counts,
            "pairwise": pairwise,
        }

    return {
        "schema_version": 1,
        "case_count": len(cases),
        "family_counts": dict(sorted(family_counts.items())),
        "family_plan": [
            {
                "family": item.family,
                "profile": item.profile,
                "start": item.start,
                "count": item.count,
            }
            for item in family_plan
        ],
        "case_id_offsets": dict(sorted(case_id_offsets.items())),
        "by_family": by_family,
    }


def _normalize_family_plan(plan: Iterable[CaseSlice | Mapping[str, Any]]) -> list[CaseSlice]:
    normalized: list[CaseSlice] = []
    for item in plan:
        if isinstance(item, CaseSlice):
            normalized.append(item)
            continue
        normalized.append(
            CaseSlice(
                family=str(item["family"]),
                profile=str(item["profile"]),
                start=int(item["start"]),
                count=int(item["count"]),
            )
        )
    return normalized


def _load_family_plan_json(path: Path) -> list[CaseSlice]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("family plan JSON must be a list")
    return _normalize_family_plan(payload)


def _load_case_id_offsets_json(path: Path) -> dict[str, int]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("case-id offsets JSON must be an object")
    return {str(key): int(value) for key, value in payload.items()}


def _effective_privilege_value(scenario: PmpScenario) -> str:
    if scenario.privilege == Privilege.M and scenario.mprv and scenario.probe.access in {Access.LOAD, Access.STORE}:
        return scenario.mpp.value
    return scenario.privilege.value


if __name__ == "__main__":
    raise SystemExit(main())
