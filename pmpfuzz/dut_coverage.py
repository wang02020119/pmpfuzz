from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from .schema import write_json
from .whitebox import extract_security_whitebox_signals


DUT_COVERAGE_SCHEMA_VERSION = 1


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
        "top_bins": ordered_bins[:50],
    }


def write_dut_coverage(run_dir: Path, *, out_dir: Path | None = None, artifact_dir: Path | None = None) -> Path:
    run_dir = Path(run_dir)
    out_dir = Path(out_dir) if out_dir else run_dir / "coverage"
    out = out_dir / "dut_coverage.json"
    write_json(out, dut_coverage_from_run(run_dir, artifact_dir=artifact_dir))
    return out


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
