from __future__ import annotations

from pathlib import Path
from typing import Any

from .coverage import coverage_from_run
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
    triage_path = run_dir / "triage" / "triage.json"
    triage = read_json(triage_path) if triage_path.exists() else triage_run(run_dir)
    coverage = coverage_from_run(run_dir)
    verdict = verdict_for_run(run_dir)

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
        "## Coverage Summary",
        "",
        f"- Generated cases: {coverage.get('total_cases', 0)}",
        f"- Result records: {coverage.get('total_results', 0)}",
        f"- Profiles: {', '.join(sorted((coverage.get('profiles') or {}).keys())) or 'none'}",
        f"- Coverage tags: {', '.join(sorted((coverage.get('coverage_tags') or {}).keys())) or 'none'}",
        "",
        "## Status Summary",
        "",
    ]
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
