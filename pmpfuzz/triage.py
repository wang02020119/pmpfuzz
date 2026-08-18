from __future__ import annotations

from pathlib import Path
from typing import Any

from .coverage import coverage_from_run
from .feedback import behavior_guidance_summary
from .schema import read_json, write_json
from .verdict import verdict_for_run


def failure_signature(result: dict[str, Any]) -> str:
    return "|".join(
        [
            result.get("dut") or "",
            result.get("profile") or "",
            result.get("failure_class") or result.get("status") or "",
            str(result.get("expected_cause")),
            str(result.get("observed_mcause")),
            str(result.get("expected_stage")),
        ]
    )


def triage_run(run_dir: Path) -> dict[str, Any]:
    groups: dict[str, dict[str, Any]] = {}
    for result_path in sorted((run_dir / "results").glob("*/result.json")):
        result = read_json(result_path)
        if result["status"] in {"pass", "setup_unsupported"}:
            continue
        signature = failure_signature(result)
        group = groups.setdefault(
            signature,
            {
                "signature": signature,
                "dut": result.get("dut"),
                "profile": result.get("profile"),
                "status": result.get("status"),
                "failure_class": result.get("failure_class"),
                "expected_cause": result.get("expected_cause"),
                "observed_mcause": result.get("observed_mcause"),
                "expected_stage": result.get("expected_stage"),
                "count": 0,
                "examples": [],
            },
        )
        group["count"] += 1
        if len(group["examples"]) < 5:
            group["examples"].append(
                {
                    "name": result["name"],
                    "log": result.get("log"),
                    "returncode": result.get("returncode"),
                    "reason": result.get("reason"),
                }
            )

    triage = {
        "run_dir": str(run_dir),
        "group_count": len(groups),
        "security_verdict": verdict_for_run(run_dir),
        "groups": sorted(groups.values(), key=lambda item: (-item["count"], item["signature"])),
    }
    out = run_dir / "triage" / "triage.json"
    write_json(out, triage)
    return triage


def render_markdown_report(run_dir: Path) -> str:
    aggregate_path = run_dir / "aggregate.json"
    aggregate = read_json(aggregate_path) if aggregate_path.exists() else {"total": 0, "results": []}
    result_records = _load_result_records(run_dir)
    if not aggregate.get("results") and result_records:
        aggregate = _aggregate_from_results(result_records)
    triage_path = run_dir / "triage" / "triage.json"
    triage = read_json(triage_path) if triage_path.exists() else triage_run(run_dir)
    coverage = coverage_from_run(run_dir)
    verdict = verdict_for_run(run_dir)
    capabilities = _load_capabilities(run_dir)
    applicability = aggregate.get("oracle_applicability") or _oracle_applicability_from_results(result_records)

    lines = [
        "# PMP Fuzz Report",
        "",
        f"- Run directory: `{run_dir}`",
        f"- Total cases: {aggregate.get('total', 0)}",
        f"- Passed: {aggregate.get('passed', 0)}",
        f"- Non-pass: {aggregate.get('nonpass', 0)}",
        "",
        "## Security Verdict",
        "",
        f"- Verdict: `{verdict['verdict']}`",
        f"- Vulnerability found: `{str(verdict['has_vulnerability']).lower()}`",
        f"- Impact: `{verdict.get('impact') or 'none'}`",
        f"- Expected behavior: `{verdict.get('expected') or 'none'}`",
        "",
        "## DUT Capability Matrix",
        "",
        "| DUT | Available | Finish protocol | Diagnostic depth | Oracle default |",
        "| --- | --- | --- | --- | --- |",
    ]
    for dut_name, capability in sorted((capabilities.get("duts") or {}).items()):
        lines.append(
            f"| `{dut_name}` | `{str(capability.get('available')).lower()}` | "
            f"`{capability.get('finish_protocol')}` | `{capability.get('diagnostic_depth')}` | "
            f"`{capability.get('oracle_applicability')}` |"
        )
    if not capabilities.get("duts"):
        lines.append("| none | none | none | none | none |")

    lines.extend(
        [
            "",
            "## Oracle Applicability",
            "",
        ]
    )
    for name, count in sorted(applicability.items()):
        lines.append(f"- `{name}`: {count}")
    if not applicability:
        lines.append("- none")

    lines.extend(
        [
            "",
            "## Medium Campaign Summary",
            "",
            f"- Valid-oracle results: {applicability.get('valid', 0)}",
            f"- Unsupported results: {applicability.get('unsupported', 0)}",
            f"- Infra-unadapted results: {applicability.get('infra_unadapted', 0)}",
            f"- Experimental results: {applicability.get('experimental', 0)}",
            "",
            "## Manifest Coverage (generated-only statistics)",
            "",
            f"- Generated cases: {coverage.get('total_cases', 0)}",
            f"- Result records: {coverage.get('total_results', 0)}",
            f"- Profiles: {', '.join(sorted((coverage.get('profiles') or {}).keys())) or 'none'}",
            f"- Coverage tags: {', '.join(sorted((coverage.get('coverage_tags') or {}).keys())) or 'none'}",
            f"- Semantic target: `{coverage.get('target') or 'none'}`",
            f"- Semantic coverage: {coverage.get('covered_target_bins', 0)}/{coverage.get('target_bins', 0)} "
            f"({coverage.get('coverage_rate', 0.0)})",
            "",
            "> **Note:** Manifest coverage counts every generated case.json, regardless of whether "
            "the test actually executed to the target observation stage. "
            "For paper experiments, use Execution-Qualified Coverage below.",
            "",
        ]
    )

    # ---- Execution-Qualified Coverage ---------------------------------------
    exec_cov = coverage.get("execution_coverage") or {}
    lines.extend([
        "## Execution-Qualified Coverage",
        "",
        f"- Model: `{exec_cov.get('coverage_model', 'none')}`",
        "",
    ])
    by_dut = exec_cov.get("by_dut") or {}
    for dut_name, entry in sorted(by_dut.items()):
        available = entry.get("available", False)
        lines.append(f"### DUT: `{dut_name}`")
        if not available:
            lines.append(f"- **Unavailable:** `{entry.get('unavailable_reason', 'unknown')}`")
            lines.append("")
            continue
        qual = entry.get("qualification") or {}
        lines.extend([
            f"- Capability fingerprint: `{entry.get('capability_fingerprint', 'none')}`",
            f"- Total generated cases: {coverage.get('total_cases', 0)}",
            f"- Total result records: {qual.get('total_results', 0)}",
            f"- Eligible results: {qual.get('eligible_results', 0)}",
            f"- Excluded results: {qual.get('excluded_results', 0)}",
            f"- Missing results: {qual.get('missing_results', 0)}",
            f"- Orphan results: {qual.get('orphan_results', 0)}",
            f"- Valid mismatches: {qual.get('valid_mismatches', 0)}",
            "",
        ])
        excluded = qual.get("excluded_by_reason") or {}
        if excluded:
            lines.append("**Excluded by reason:**")
            for reason, count in sorted(excluded.items()):
                lines.append(f"- `{reason}`: {count}")
            lines.append("")
        for cov_name in ("semantic", "pairwise", "security_triples", "predicates"):
            section = entry.get(cov_name) or {}
            rate = section.get("coverage_rate")
            rate_str = f"{rate:.4f}" if rate is not None else "null"
            lines.append(
                f"- **{cov_name}**: {section.get('covered_target_bins', 0)}/"
                f"{section.get('total_target_bins', 0)} ({rate_str})"
            )
        lines.append("")
        # suggested schedule command
        target = coverage.get("target") or "core-stateful"
        lines.append(
            f"Suggested next schedule: `python3 -m pmpfuzz schedule --from-runs {run_dir} "
            f"--target {target} --coverage-mode predicates --coverage-basis execution "
            f"--dut {dut_name} --max-cases 64 --seed 20260628 --out runs/next`"
        )
        lines.append("")

    if not by_dut:
        lines.append("- No execution coverage data available")
        lines.append("")

    # ---- Old manifest guidance (kept for reference) -------------------------
    lines.extend(
        [
            "## Manifest Coverage Gaps (reference)",
            "",
            f"- Missing semantic bins: {coverage.get('missing_target_bins', 0)}",
            f"- Suggested manifest scheduler: `python3 -m pmpfuzz schedule --from-runs {run_dir} "
            f"--target {coverage.get('target') or 'core-stateful'} --max-cases 64 --seed 20260628 "
            f"--coverage-basis manifest --out runs/semantic_next`",
            "",
        ]
    )

    behavior = behavior_guidance_summary(run_dir)
    lines.extend(
        [
            "",
            "## Behavior Feedback Guidance",
            "",
            f"- Behavior signals: {behavior.get('signal_count', 0)}",
            f"- Suggested feedback scheduler: `python3 -m pmpfuzz feedback --from-runs {run_dir} "
            f"--max-cases 64 --seed 20260629 --out runs/feedback_next`",
            "",
            "Top behavior signals:",
            "",
        ]
    )
    for signal in behavior.get("top_signals", []):
        lines.append(
            f"- `{signal.get('kind')}` case=`{signal.get('case')}` dut=`{signal.get('dut')}` "
            f"failure_class=`{signal.get('failure_class')}` weight={signal.get('weight')}"
        )
    if not behavior.get("top_signals"):
        lines.append("- none")
    lines.extend(["", "Top feedback mutations:", ""])
    for entry in behavior.get("top_entries", []):
        lines.append(
            f"- `{entry.get('name')}` strategy=`{entry.get('mutation_strategy')}` "
            f"score={entry.get('score')} ops=`{','.join(entry.get('mutation_ops') or [])}`"
        )
    if not behavior.get("top_entries"):
        lines.append("- none")

    lines.extend([
        "",
        "## Stateful Permission Verdict",
        "",
        f"- Stateful verdict: `{verdict['verdict']}`",
        f"- Stateful sequences: {', '.join(sorted((coverage.get('stateful_sequences') or {}).keys())) or 'none'}",
        f"- Mutations: {', '.join(sorted((coverage.get('stateful_mutations') or {}).keys())) or 'none'}",
        f"- Fences: {', '.join(sorted((coverage.get('stateful_fences') or {}).keys())) or 'none'}",
        "",
        "## Status Summary",
        "",
    ])
    for status, count in sorted((aggregate.get("statuses") or {}).items()):
        lines.append(f"- `{status}`: {count}")
    lines.extend(["", "## Failure Classes", ""])
    for klass, count in sorted((aggregate.get("failure_classes") or {}).items()):
        lines.append(f"- `{klass}`: {count}")
    if not aggregate.get("failure_classes"):
        lines.append("- none")

    lines.extend(["", "## Triage Groups", ""])
    for group in triage.get("groups", []):
        lines.append(
            f"- `{group['signature']}`: count={group['count']}, "
            f"status={group.get('status')}, failure_class={group.get('failure_class')}"
        )
        for example in group.get("examples", [])[:3]:
            lines.append(f"  - example `{example['name']}` log `{example.get('log')}`")
    if not triage.get("groups"):
        lines.append("- none")

    lines.extend(["", "## Verdict Evidence", ""])
    if verdict.get("evidence"):
        for item in verdict["evidence"]:
            lines.append(
                f"- `{item['case']}`: profile={item.get('profile')}, "
                f"boom_failure_class={item.get('boom_failure_class')}, expected={item.get('expected')}"
            )
    else:
        lines.append("- none")
    if verdict.get("related_evidence"):
        lines.append("")
        lines.append("Related evidence:")
        for item in verdict["related_evidence"]:
            lines.append(f"- `{item['case']}`: observed_mcause={item.get('observed_mcause')}")

    lines.extend(["", "## Repro Commands", ""])
    for group in triage.get("groups", [])[:5]:
        for example in group.get("examples", [])[:1]:
            lines.append(
                f"- `python3 -m pmpfuzz repro --case {run_dir}/cases/{example['name']} "
                "--dut spike,rocket-clean,boom-clean --out repro/<case>`"
            )
    if not triage.get("groups"):
        lines.append("- no failing cases")

    return "\n".join(lines) + "\n"


def write_report(run_dir: Path) -> Path:
    report_path = run_dir / "reports" / "report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(render_markdown_report(run_dir), encoding="ascii")
    return report_path


def _load_capabilities(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "dut_capabilities.json"
    if path.exists():
        return read_json(path)
    return {"duts": {}}


def _load_result_records(run_dir: Path) -> list[dict[str, Any]]:
    return [read_json(path) for path in sorted((run_dir / "results").glob("*/result.json"))]


def _oracle_applicability_from_results(results: list[dict[str, Any]]) -> dict[str, int]:
    applicability: dict[str, int] = {}
    for result in results:
        key = str(result.get("oracle_applicability") or "valid")
        applicability[key] = applicability.get(key, 0) + 1
    return applicability


def _aggregate_from_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    statuses: dict[str, int] = {}
    failure_classes: dict[str, int] = {}
    for result in results:
        status = str(result.get("status") or "unknown")
        statuses[status] = statuses.get(status, 0) + 1
        failure_class = result.get("failure_class")
        if failure_class:
            text = str(failure_class)
            failure_classes[text] = failure_classes.get(text, 0) + 1
    return {
        "total": len(results),
        "results": results,
        "passed": statuses.get("pass", 0),
        "nonpass": sum(count for status, count in statuses.items() if status not in {"pass", "setup_unsupported"}),
        "statuses": statuses,
        "failure_classes": failure_classes,
        "oracle_applicability": _oracle_applicability_from_results(results),
    }
