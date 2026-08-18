from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from .schema import read_json, write_json
from .whitebox import extract_security_whitebox_signals


DUT_COVERAGE_SCHEMA_VERSION = 1
DUT_COVERAGE_MATRIX_SCHEMA_VERSION = 1


def dut_coverage_from_run(run_dir: Path, *, artifact_dir: Path | None = None) -> dict[str, Any]:
    whitebox = extract_security_whitebox_signals(run_dir, artifact_dir=artifact_dir)
    signals = [signal for signal in whitebox.get("signals", []) if isinstance(signal, dict)]

    bins: dict[str, dict[str, Any]] = {}
    by_dut: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    by_security_chain: dict[str, int] = {}
    by_artifact: dict[str, int] = {}
    by_case: dict[str, int] = {}

    for signal in signals:
        dut = _text(signal.get("dut"), "unknown")
        kind = _text(signal.get("kind"), "unknown")
        case_name = _text(signal.get("case"), "unknown")
        features = dict(signal.get("features") or {})
        evidence = dict(signal.get("evidence") or {})
        chain = _text(features.get("security_chain"), "unknown")
        artifact = _text(features.get("artifact") or evidence.get("artifact"), "unknown")
        weight = int(signal.get("weight") or 1)

        _bump(by_dut, dut)
        _bump(by_kind, kind)
        _bump(by_security_chain, chain)
        _bump(by_artifact, artifact)
        _bump(by_case, case_name)

        for key in _bins_for_signal(signal):
            _record_bin(bins, key, signal=signal, weight=weight)

    ordered_bins = sorted(
        bins.values(),
        key=lambda item: (-int(item["weight"]), -int(item["count"]), str(item["key"])),
    )
    total_observations = sum(int(item["count"]) for item in ordered_bins)
    weighted_covered_bins = sum(int(item["weight"]) for item in ordered_bins)
    return {
        "schema_version": DUT_COVERAGE_SCHEMA_VERSION,
        "provider": "dut-whitebox",
        "coverage_model": "observed-dut-whitebox-v1",
        "targetless": True,
        "run_dir": str(Path(run_dir)),
        "artifact_dir": str(artifact_dir) if artifact_dir else None,
        "artifacts_scanned": list(whitebox.get("artifacts_scanned") or []),
        "input_signal_count": len(signals),
        "covered_bins": len(ordered_bins),
        "total_observations": total_observations,
        "weighted_covered_bins": weighted_covered_bins,
        "by_dut": dict(sorted(by_dut.items())),
        "by_kind": dict(sorted(by_kind.items())),
        "by_security_chain": dict(sorted(by_security_chain.items())),
        "by_artifact": dict(sorted(by_artifact.items())),
        "by_case": dict(sorted(by_case.items())),
        "bins": ordered_bins,
        "top_bins": ordered_bins[:50],
    }


def write_dut_coverage(run_dir: Path, *, out_dir: Path | None = None, artifact_dir: Path | None = None) -> Path:
    run_dir = Path(run_dir)
    out_dir = Path(out_dir) if out_dir else run_dir / "coverage"
    out = out_dir / "dut_coverage.json"
    write_json(out, dut_coverage_from_run(run_dir, artifact_dir=artifact_dir))
    return out


def dut_coverage_matrix_from_runs(run_dirs: Iterable[Path]) -> dict[str, Any]:
    run_dirs = [Path(item) for item in run_dirs]
    duts: set[str] = set()
    rows: dict[str, dict[str, Any]] = {}
    run_summaries: list[dict[str, Any]] = []

    for run_dir in run_dirs:
        result_duts = _result_duts(run_dir)
        duts.update(result_duts)
        whitebox = extract_security_whitebox_signals(run_dir)
        signals = [signal for signal in whitebox.get("signals", []) if isinstance(signal, dict)]
        coverage = dut_coverage_from_run(run_dir)
        run_summaries.append(
            {
                "run_dir": str(run_dir),
                "result_duts": result_duts,
                "input_signal_count": coverage["input_signal_count"],
                "covered_bins": coverage["covered_bins"],
                "by_dut": coverage["by_dut"],
            }
        )
        for signal in signals:
            dut = _text(signal.get("dut"), "unknown")
            duts.add(dut)
            weight = int(signal.get("weight") or 1)
            for raw_key in _bins_for_signal(signal):
                key = _comparable_bin_key(raw_key)
                if key is None:
                    continue
                _record_matrix_row(rows, key, dut=dut, signal=signal, weight=weight)

    sorted_duts = sorted(duts)
    ordered_rows = _ordered_matrix_rows(rows, sorted_duts)
    total_bins = len(ordered_rows)
    per_dut = {
        dut: _dut_matrix_summary(dut, ordered_rows, total_bins)
        for dut in sorted_duts
    }
    return {
        "schema_version": DUT_COVERAGE_MATRIX_SCHEMA_VERSION,
        "provider": "dut-whitebox",
        "coverage_model": "observed-dut-whitebox-matrix-v1",
        "target_model": "union-of-observed-comparable-bins",
        "run_dirs": [str(item) for item in run_dirs],
        "runs": run_summaries,
        "duts": sorted_duts,
        "total_comparable_bins": total_bins,
        "fully_covered_bins": sum(1 for row in ordered_rows if not row["missing_duts"]),
        "partially_covered_bins": sum(1 for row in ordered_rows if row["missing_duts"] and row["covered_dut_count"] > 0),
        "per_dut": per_dut,
        "top_gaps": [row for row in ordered_rows if row["missing_duts"]][:50],
        "matrix": ordered_rows,
    }


def write_dut_coverage_matrix(run_dirs: Iterable[Path], *, out_dir: Path) -> Path:
    out_dir = Path(out_dir)
    out = out_dir / "dut_coverage_matrix.json"
    write_json(out, dut_coverage_matrix_from_runs(run_dirs))
    return out


def _result_duts(run_dir: Path) -> list[str]:
    duts: set[str] = set()
    for result_path in sorted((run_dir / "results").glob("*/result.json")):
        try:
            result = read_json(result_path)
        except ValueError:
            continue
        dut = result.get("dut")
        if dut:
            duts.add(str(dut))
    return sorted(duts)


def _bins_for_signal(signal: dict[str, Any]) -> Iterable[str]:
    kind = _text(signal.get("kind"), "unknown")
    dut = _text(signal.get("dut"), "unknown")
    features = dict(signal.get("features") or {})
    chain = _text(features.get("security_chain"), "unknown")
    artifact = _text(features.get("artifact"), "unknown")

    yield f"dut={dut}"
    yield f"kind={kind}"
    yield f"chain={chain}"
    yield f"artifact={artifact}"
    yield f"dut={dut}|chain={chain}|kind={kind}"

    stage = features.get("pmp_stage") or features.get("expected_stage")
    level = features.get("ptw_level") or features.get("ptw_fault_level")
    allowed = _allow_text(features.get("pmp_allowed"))
    if stage:
        yield f"chain={chain}|stage={stage}"
    if level:
        yield f"chain={chain}|level={level}"
    if stage and level:
        yield f"chain={chain}|stage={stage}|level={level}"
    if allowed:
        yield f"chain={chain}|allow={allowed}"
    if stage and allowed:
        yield f"chain={chain}|stage={stage}|allow={allowed}"

    probe = features.get("probe")
    if probe:
        yield f"dut={dut}|probe={probe}"
        yield f"chain={chain}|probe={probe}"

    coverage_point = features.get("coverage_point")
    if coverage_point:
        yield f"dut={dut}|coverage_point={coverage_point}"
        yield f"chain={chain}|coverage_point={coverage_point}"

    perf_counter = features.get("perf_counter")
    if perf_counter:
        yield f"dut={dut}|perf_counter={perf_counter}"
        yield f"chain={chain}|perf_counter={perf_counter}"

    match_mode = features.get("pmp_match_mode")
    match_result = features.get("pmp_match_result")
    if match_mode:
        yield f"chain={chain}|pmp_match_mode={match_mode}"
    if match_result:
        yield f"chain={chain}|pmp_match_result={match_result}"


def _comparable_bin_key(key: str) -> str | None:
    parts = [part for part in key.split("|") if part and not part.startswith("dut=")]
    if not parts:
        return None
    return "|".join(parts)


def _record_bin(bins: dict[str, dict[str, Any]], key: str, *, signal: dict[str, Any], weight: int) -> None:
    entry = bins.setdefault(
        key,
        {
            "key": key,
            "count": 0,
            "weight": 0,
            "examples": [],
        },
    )
    entry["count"] = int(entry["count"]) + 1
    entry["weight"] = max(int(entry["weight"]), weight)
    examples = entry["examples"]
    if len(examples) < 3:
        examples.append(
            {
                "case": signal.get("case"),
                "dut": signal.get("dut"),
                "kind": signal.get("kind"),
                "weight": weight,
            }
        )


def _record_matrix_row(rows: dict[str, dict[str, Any]], key: str, *, dut: str, signal: dict[str, Any], weight: int) -> None:
    entry = rows.setdefault(
        key,
        {
            "key": key,
            "count": 0,
            "weight": 0,
            "by_dut": {},
            "examples": [],
        },
    )
    entry["count"] = int(entry["count"]) + 1
    entry["weight"] = max(int(entry["weight"]), weight)
    by_dut = entry["by_dut"]
    dut_entry = by_dut.setdefault(dut, {"count": 0, "weight": 0})
    dut_entry["count"] = int(dut_entry["count"]) + 1
    dut_entry["weight"] = max(int(dut_entry["weight"]), weight)
    examples = entry["examples"]
    if len(examples) < 3:
        examples.append(
            {
                "case": signal.get("case"),
                "dut": dut,
                "kind": signal.get("kind"),
                "weight": weight,
            }
        )


def _ordered_matrix_rows(rows: dict[str, dict[str, Any]], duts: list[str]) -> list[dict[str, Any]]:
    ordered = []
    for row in rows.values():
        by_dut = dict(row["by_dut"])
        covered = sorted(by_dut)
        missing = [dut for dut in duts if dut not in by_dut]
        ordered.append(
            {
                "key": row["key"],
                "count": row["count"],
                "weight": row["weight"],
                "covered_duts": covered,
                "missing_duts": missing,
                "covered_dut_count": len(covered),
                "coverage_rate": round(len(covered) / len(duts), 4) if duts else 0.0,
                "by_dut": by_dut,
                "examples": row["examples"],
            }
        )
    return sorted(
        ordered,
        key=lambda item: (
            int(item["covered_dut_count"]),
            -int(item["weight"]),
            -int(item["count"]),
            str(item["key"]),
        ),
    )


def _dut_matrix_summary(dut: str, rows: list[dict[str, Any]], total_bins: int) -> dict[str, Any]:
    covered = [row["key"] for row in rows if dut in row["covered_duts"]]
    missing = [row["key"] for row in rows if dut in row["missing_duts"]]
    return {
        "covered_bins": len(covered),
        "missing_bins": len(missing),
        "coverage_rate": round(len(covered) / total_bins, 4) if total_bins else 0.0,
        "top_missing_bins": missing[:50],
    }


def _bump(bucket: dict[str, int], key: str) -> None:
    bucket[key] = bucket.get(key, 0) + 1


def _text(value: object, default: str) -> str:
    if value is None:
        return default
    text = str(value)
    return text if text else default


def _allow_text(value: object) -> str | None:
    if value is True:
        return "allowed"
    if value is False:
        return "denied"
    return None
