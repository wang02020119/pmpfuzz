from __future__ import annotations

import argparse
import json
from pathlib import Path

from .emitter import AssemblyEmitter
from .oracle import evaluate_scenario
from .scenario import ScenarioGenerator


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate stage-1 PMP fuzz scenarios")
    parser.add_argument("--count", type=int, default=16)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--out", type=Path, default=Path("out"))
    parser.add_argument("--no-smepmp", action="store_true")
    parser.add_argument("--profile", default="legacy")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    emitter = AssemblyEmitter()
    scenarios = ScenarioGenerator(
        seed=args.seed,
        include_smepmp=not args.no_smepmp,
        profile=args.profile,
    ).generate_batch(args.count)

    manifest_lines = ["name,profile,privilege,access,address,translation,allowed,stage,reason"]
    expected = []
    for scenario in scenarios:
        outcome = evaluate_scenario(scenario)
        (args.out / f"{scenario.name}.S").write_text(emitter.emit(scenario), encoding="ascii")
        expected.append(
            {
                "name": scenario.name,
                "profile": scenario.profile,
                "privilege": scenario.privilege.value,
                "access": scenario.probe.access.value,
                "address": f"0x{scenario.probe.effective_address():x}",
                "translation": scenario.translation.value,
                "allowed": outcome.allowed,
                "trap_cause": int(outcome.trap_cause) if outcome.trap_cause is not None else None,
                "stage": outcome.stage,
                "reason": outcome.reason,
            }
        )
        manifest_lines.append(
            ",".join(
                [
                    scenario.name,
                    scenario.profile,
                    scenario.privilege.value,
                    scenario.probe.access.value,
                    f"0x{scenario.probe.effective_address():x}",
                    scenario.translation.value,
                    str(int(outcome.allowed)),
                    outcome.stage,
                    outcome.reason.replace(",", ";"),
                ]
            )
        )

    (args.out / "manifest.csv").write_text("\n".join(manifest_lines) + "\n", encoding="ascii")
    (args.out / "expected.json").write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
