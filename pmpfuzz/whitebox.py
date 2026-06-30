from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

from .schema import read_json, write_json


SECURITY_COVERAGE_KEYWORDS = (
    "pmp",
    "ptw",
    "tlb",
    "itlb",
    "dtlb",
    "sfence",
    "mseccfg",
    "smepmp",
    "trap",
    "exception",
    "store",
)

ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]+")
COVERAGE_RE = re.compile(r"COVERAGE:\s*([^,\s]+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)")
PERF_RE = re.compile(r"\[PERF[^\]]*\].*?:\s*([^,\n]+)\s*,\s*(-?\d+)")


def extract_security_whitebox_signals(run_dir: Path, *, artifact_dir: Path | None = None) -> dict[str, Any]:
    run_dir = Path(run_dir)
    cases = _case_map(run_dir)
    results = _results_by_case(run_dir)
    signals: list[dict[str, Any]] = []
    scanned: list[str] = []

    for case_name, case in sorted(cases.items()):
        case_results = results.get(case_name) or [{"dut": "unknown", "name": case_name}]
        artifact_paths = _artifact_paths(run_dir, case_name, artifact_dir=artifact_dir)
        for artifact_path in artifact_paths:
            scanned.append(str(artifact_path))
            text = artifact_path.read_text(encoding="utf-8", errors="replace")
            for result in case_results:
                signals.extend(_signals_from_artifact(case, result, artifact_path, text))

    return {
        "schema_version": 1,
        "provider": "whitebox",
        "run_dir": str(run_dir),
        "artifact_dir": str(artifact_dir) if artifact_dir else None,
        "artifacts_scanned": sorted(set(scanned)),
        "signal_count": len(_dedupe_signals(signals)),
        "signals": _dedupe_signals(signals),
    }


def write_whitebox_signals(run_dir: Path, *, out_dir: Path | None = None, artifact_dir: Path | None = None) -> Path:
    run_dir = Path(run_dir)
    out_dir = Path(out_dir) if out_dir else run_dir / "whitebox"
    payload = extract_security_whitebox_signals(run_dir, artifact_dir=artifact_dir)
    out = out_dir / "whitebox_signals.json"
    write_json(out, payload)
    return out


def _signals_from_artifact(case: dict[str, Any], result: dict[str, Any], path: Path, text: str) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    lower_name = path.name.lower()
    is_footprint = "footprint" in lower_name
    is_trace = "trace" in lower_name or "commit" in lower_name

    if is_footprint:
        signals.extend(_footprint_signals(case, result, path, text))
    if is_trace:
        signals.extend(_commit_trace_signals(case, result, path, text))
    signals.extend(_coverage_point_signals(case, result, path, text))
    signals.extend(_perf_counter_signals(case, result, path, text))
    return signals


def _footprint_signals(case: dict[str, Any], result: dict[str, Any], path: Path, text: str) -> list[dict[str, Any]]:
    observed_addresses = {item.lower() for item in ADDRESS_RE.findall(text)}
    if not observed_addresses:
        return []
    signals: list[dict[str, Any]] = []
    for check in (case.get("contract_trace") or {}).get("pmp_checks") or []:
        address = str(check.get("physical_address") or "").lower()
        if not address or address not in observed_addresses:
            continue
        if check.get("stage") == "ptw":
            signals.append(
                _signal(
                    case=case,
                    result=result,
                    kind="ptw_pmp_footprint",
                    weight=80 if not check.get("allowed") else 45,
                    features={
                        **_base_features(case, result),
                        "security_chain": "sv39-ptw-pmp",
                        "artifact": "footprint",
                        "address": address,
                        "pmp_stage": "ptw",
                        "ptw_level": check.get("ptw_level"),
                        "pmp_allowed": bool(check.get("allowed")),
                        "pmp_match_index": check.get("match_index"),
                        "pmp_match_mode": check.get("match_mode"),
                    },
                    evidence={"artifact": str(path), "matched_address": address},
                )
            )
        elif check.get("stage") in {"bare", "final"}:
            signals.append(
                _signal(
                    case=case,
                    result=result,
                    kind="final_pmp_footprint",
                    weight=55 if not check.get("allowed") else 30,
                    features={
                        **_base_features(case, result),
                        "security_chain": "pmp-final",
                        "artifact": "footprint",
                        "address": address,
                        "pmp_stage": check.get("stage"),
                        "pmp_allowed": bool(check.get("allowed")),
                        "pmp_match_index": check.get("match_index"),
                        "pmp_match_mode": check.get("match_mode"),
                    },
                    evidence={"artifact": str(path), "matched_address": address},
                )
            )

    physical_address = str(case.get("physical_address") or "").lower()
    if (
        physical_address
        and physical_address in observed_addresses
        and str(case.get("access")) == "store"
        and not bool((case.get("expected") or {}).get("allowed"))
        and _side_effect_forbidden(case)
    ):
        signals.append(
            _signal(
                case=case,
                result=result,
                kind="forbidden_side_effect_footprint",
                weight=95,
                features={
                    **_base_features(case, result),
                    "security_chain": "pmp-side-effect",
                    "artifact": "footprint",
                    "address": physical_address,
                    "side_effect_policy": "forbidden",
                },
                evidence={"artifact": str(path), "matched_address": physical_address},
            )
        )
    return signals


def _commit_trace_signals(case: dict[str, Any], result: dict[str, Any], path: Path, text: str) -> list[dict[str, Any]]:
    expected_cause = (case.get("expected") or {}).get("trap_cause")
    if expected_cause is None:
        return []
    for line_number, line in enumerate(text.splitlines(), 1):
        lower = line.lower()
        if "trap" not in lower and "exception" not in lower and "mcause" not in lower:
            continue
        return [
            _signal(
                case=case,
                result=result,
                kind="trap_commit_trace",
                weight=40,
                features={
                    **_base_features(case, result),
                    "security_chain": "trap-commit",
                    "artifact": "commit-trace",
                    "expected_cause": expected_cause,
                },
                evidence={"artifact": str(path), "line": line_number, "text": line[:160]},
            )
        ]
    return []


def _coverage_point_signals(case: dict[str, Any], result: dict[str, Any], path: Path, text: str) -> list[dict[str, Any]]:
    signals = []
    for match in COVERAGE_RE.finditer(text):
        point = match.group(1)
        if not _is_security_coverage_point(point):
            continue
        total = int(match.group(2))
        covered = int(match.group(3))
        accumulated = int(match.group(4))
        signals.append(
            _signal(
                case=case,
                result=result,
                kind="security_coverage_point",
                weight=25 + min(covered, 25),
                features={
                    **_base_features(case, result),
                    "security_chain": "rtl-security-coverage",
                    "artifact": "coverage",
                    "coverage_point": point,
                    "coverage_total": total,
                    "coverage_covered": covered,
                    "coverage_accumulated": accumulated,
                },
                evidence={"artifact": str(path), "coverage_point": point},
            )
        )
    return signals


def _perf_counter_signals(case: dict[str, Any], result: dict[str, Any], path: Path, text: str) -> list[dict[str, Any]]:
    signals = []
    for line_number, line in enumerate(text.splitlines(), 1):
        match = PERF_RE.search(line)
        if not match:
            continue
        counter = match.group(1).strip()
        value = int(match.group(2))
        if value <= 0 or not _is_security_coverage_point(f"{counter} {line}"):
            continue
        signals.append(
            _signal(
                case=case,
                result=result,
                kind="security_perf_counter",
                weight=_perf_counter_weight(counter, line, value),
                features={
                    **_base_features(case, result),
                    "security_chain": "rtl-security-perf",
                    "artifact": "perf-log",
                    "perf_counter": counter,
                    "perf_value": value,
                },
                evidence={"artifact": str(path), "line": line_number, "text": line[:180]},
            )
        )
    return signals


def _perf_counter_weight(counter: str, line: str, value: int) -> int:
    counter_text = counter.strip().lower()
    line_text = line.lower()
    if counter_text == "access":
        return 20 + min(value, 10)
    if any(keyword in counter_text for keyword in ("ptw", "tlb", "itlb", "dtlb")):
        return 95 + min(value, 25)
    if any(keyword in counter_text for keyword in ("exception", "trap", "pmp")):
        return 85 + min(value, 25)
    if "store" in counter_text:
        return 75 + min(value, 25)
    if any(keyword in line_text for keyword in ("exception", "trap", "pmp")):
        return 65 + min(value, 20)
    return 35 + min(value, 30)


def _signal(
    *,
    case: dict[str, Any],
    result: dict[str, Any],
    kind: str,
    weight: int,
    features: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "provider": "whitebox",
        "kind": kind,
        "case": case.get("name"),
        "dut": result.get("dut") or "unknown",
        "weight": weight,
        "features": features,
        "evidence": evidence,
    }


def _base_features(case: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    pte = case.get("pte_permissions") or {}
    sequence = case.get("stateful_sequence") or {}
    return {
        "profile": case.get("profile"),
        "privilege": case.get("privilege"),
        "access": case.get("access"),
        "translation": case.get("translation"),
        "status": result.get("status"),
        "failure_class": result.get("failure_class") or result.get("status"),
        "expected_stage": (case.get("expected") or {}).get("stage"),
        "expected_cause": (case.get("expected") or {}).get("trap_cause"),
        "ptw_fault_level": case.get("ptw_fault_level"),
        "preload_mode": case.get("preload_mode"),
        "pmp_match_mode": case.get("pmp_match_mode"),
        "pmp_locked": case.get("pmp_locked"),
        "pmp_allow": case.get("pmp_allow"),
        "pmp_match_result": case.get("pmp_match_result"),
        "mxr": case.get("mxr"),
        "sum_enabled": case.get("sum_enabled"),
        "smepmp_rule": case.get("smepmp_rule"),
        "effective_privilege": case.get("effective_privilege"),
        "mseccfg_mml": (case.get("mseccfg") or {}).get("mml"),
        "mseccfg_mmwp": (case.get("mseccfg") or {}).get("mmwp"),
        "mseccfg_rlb": (case.get("mseccfg") or {}).get("rlb"),
        "security_focus": case.get("security_focus"),
        "pte_rwx": pte.get("rwx"),
        "pte_user": pte.get("user"),
        "pte_accessed": pte.get("accessed"),
        "pte_dirty": pte.get("dirty"),
        "stateful_kind": sequence.get("kind"),
        "stateful_mutation": sequence.get("mutation"),
        "stateful_fence": sequence.get("fence"),
        "stateful_expected_final": sequence.get("expected_final"),
    }


def _case_map(run_dir: Path) -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    direct = run_dir / "cases" / "case.json"
    if direct.exists():
        case = read_json(direct)
        cases[str(case.get("name"))] = case
    for case_path in sorted((run_dir / "cases").glob("*/case.json")):
        case = read_json(case_path)
        cases[str(case.get("name"))] = case
    return cases


def _results_by_case(run_dir: Path) -> dict[str, list[dict[str, Any]]]:
    results: dict[str, list[dict[str, Any]]] = {}
    for result_path in sorted((run_dir / "results").glob("*/result.json")):
        result = read_json(result_path)
        results.setdefault(str(result.get("name")), []).append(result)
    return results


def _artifact_paths(run_dir: Path, case_name: str, *, artifact_dir: Path | None) -> list[Path]:
    roots = [run_dir / "results" / case_name, run_dir / "cases" / case_name]
    for result_path in sorted((run_dir / "results").glob("*/result.json")):
        try:
            result = read_json(result_path)
        except ValueError:
            continue
        if str(result.get("name")) == case_name:
            roots.append(result_path.parent)
    if artifact_dir is not None:
        roots.extend([Path(artifact_dir), Path(artifact_dir) / case_name])
    seen: set[Path] = set()
    artifacts: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in _iter_artifact_files(root):
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            artifacts.append(path)
    return sorted(artifacts)


def _iter_artifact_files(root: Path) -> Iterable[Path]:
    patterns = ("*.footprint*", "*.trace", "*.commit*", "*.coverage*", "*.cov", "*.log")
    for pattern in patterns:
        yield from (path for path in root.glob(pattern) if path.is_file())


def _side_effect_forbidden(case: dict[str, Any]) -> bool:
    trace = case.get("contract_trace") or {}
    if trace.get("side_effect_policy") == "forbidden":
        return True
    sequence = case.get("stateful_sequence") or {}
    return sequence.get("expected_final") in {"trap_no_side_effect", "forbidden_side_effect"}


def _is_security_coverage_point(point: str) -> bool:
    lower = point.lower()
    return any(keyword in lower for keyword in SECURITY_COVERAGE_KEYWORDS)


def _dedupe_signals(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for signal in signals:
        key = "|".join(
            [
                str(signal.get("provider")),
                str(signal.get("kind")),
                str(signal.get("case")),
                str(signal.get("dut")),
                str((signal.get("features") or {}).get("security_chain")),
                str((signal.get("features") or {}).get("address")),
                str((signal.get("features") or {}).get("coverage_point")),
                str((signal.get("features") or {}).get("perf_counter")),
                str((signal.get("features") or {}).get("ptw_level")),
            ]
        )
        if key not in unique or int(signal.get("weight") or 0) > int(unique[key].get("weight") or 0):
            unique[key] = signal
    return sorted(
        unique.values(),
        key=lambda item: (
            -int(item.get("weight") or 0),
            str(item.get("kind")),
            str(item.get("case")),
            str(item.get("dut")),
        ),
    )
