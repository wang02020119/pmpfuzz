#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Sequence

from pmpfuzz.continuous import ScenarioStream
from pmpfuzz.emitter import AssemblyEmitter
from pmpfuzz.schema import scenario_to_case_dict, write_json
from pmpfuzz.semantic_coverage import CORE_STATEFUL_TARGET, target_profiles
from scripts.evaluation.baseline_adapters.cascade import _generate_elfs


DEFAULT_COUNT = 300
DEFAULT_PROTOCOL_ID = "input-generation-efficiency-v1"
SUPPORTED_DUTS = ("rocket", "boom", "cva6")
SUPPORTED_TOOLS = ("pmpfuzz", "cascade")
_INSTRUCTION_RE = re.compile(r"^\s*[0-9a-f]+:\s+[0-9a-f]+\s+", re.IGNORECASE)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one generate-to-ELF timing batch for Section 8.2",
    )
    parser.add_argument("--tool", choices=SUPPORTED_TOOLS, required=True)
    parser.add_argument("--dut", choices=SUPPORTED_DUTS, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--profile", default=CORE_STATEFUL_TARGET)
    parser.add_argument("--generator-variant", choices=["full", "syntax"], default="full")
    parser.add_argument("--objdump", type=Path, default=None)
    parser.add_argument("--protocol-id", default=DEFAULT_PROTOCOL_ID)
    return parser


def resolve_profiles(profile_request: str) -> tuple[str, ...]:
    profiles = [item.strip() for item in str(profile_request or "").split(",") if item.strip()]
    if not profiles:
        return ("pmp-boundary",)
    resolved: list[str] = []
    for profile in profiles:
        if profile == CORE_STATEFUL_TARGET:
            resolved.extend(target_profiles(CORE_STATEFUL_TARGET, include_experimental=False))
        else:
            resolved.append(profile)
    return tuple(resolved)


def run_batch(
    args: argparse.Namespace,
    *,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    if args.count <= 0:
        raise ValueError(f"count must be positive, got {args.count}")
    out_dir = args.out.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    generation_start = monotonic()
    if args.tool == "pmpfuzz":
        generation_report = _run_pmpfuzz_batch(
            out_dir=out_dir,
            dut=args.dut,
            seed=args.seed,
            count=args.count,
            profile_request=args.profile,
            generator_variant=args.generator_variant,
        )
    else:
        generation_report = _run_cascade_batch(
            out_dir=out_dir,
            design=args.dut,
            seed=args.seed,
            count=args.count,
        )
    generation_end = monotonic()

    elf_paths = list(generation_report["elf_paths"])
    if len(elf_paths) != args.count:
        raise ValueError(
            f"expected exactly {args.count} ELF files, got {len(elf_paths)}"
        )

    analysis_start = monotonic()
    instruction_report = _measure_static_instructions(elf_paths, objdump_path=args.objdump)
    analysis_end = monotonic()

    timed_generation_seconds = generation_end - generation_start
    post_timed_analysis_seconds = analysis_end - analysis_start
    total_static_instructions = int(instruction_report["total_static_instructions"])
    report = {
        "schema_version": "1.0",
        "protocol_id": str(args.protocol_id),
        "tool": str(args.tool),
        "dut": str(args.dut),
        "seed": int(args.seed),
        "count_requested": int(args.count),
        "generated_elf_count": len(elf_paths),
        "timed_scope": "generate-to-elf",
        "timed_generation_seconds": timed_generation_seconds,
        "post_timed_analysis_seconds": post_timed_analysis_seconds,
        "objdump_counted_outside_timed_window": True,
        "elfs_per_second": (len(elf_paths) / timed_generation_seconds) if timed_generation_seconds > 0 else None,
        "total_static_instructions": total_static_instructions,
        "static_instructions_per_second": (
            total_static_instructions / timed_generation_seconds if timed_generation_seconds > 0 else None
        ),
        "instructions_per_elf": (total_static_instructions / len(elf_paths)) if elf_paths else None,
        "profile_request": str(args.profile),
        "resolved_profiles": list(generation_report.get("resolved_profiles") or ()),
        "profile_distribution": generation_report.get("profile_distribution") or {},
        "generator_variant": (
            str(args.generator_variant) if args.tool == "pmpfuzz" else None
        ),
        "elfs": [
            {
                "name": path.name,
                "sha256": _sha256_file(path),
                "static_instructions": int(instruction_report["per_elf"][path.name]),
            }
            for path in elf_paths
        ],
    }
    if "generator_report" in generation_report:
        report["generator_report"] = generation_report["generator_report"]

    write_json(out_dir / "batch_manifest.json", report)
    return report


def _run_pmpfuzz_batch(
    *,
    out_dir: Path,
    dut: str,
    seed: int,
    count: int,
    profile_request: str,
    generator_variant: str,
) -> dict[str, Any]:
    resolved_profiles = resolve_profiles(profile_request)
    stream = ScenarioStream(
        root_seed=seed,
        profiles=resolved_profiles,
        generator_variant=generator_variant,
    )
    emitter = AssemblyEmitter()
    root = Path(__file__).resolve().parents[3]
    compile_script = root / "scripts" / "compile_one.sh"
    cases_dir = out_dir / "cases"
    elfs_dir = out_dir / "elfs"
    cases_dir.mkdir(parents=True, exist_ok=True)
    elfs_dir.mkdir(parents=True, exist_ok=True)

    elf_paths: list[Path] = []
    profile_counts: Counter[str] = Counter()
    for sequence in range(count):
        generated = stream.generate_root_with_metadata(sequence)
        scenario = replace(generated.scenario, name=f"{dut}_{sequence:04d}")
        profile_counts[str(generated.profile)] += 1

        case_dir = cases_dir / scenario.name
        case_dir.mkdir(parents=True, exist_ok=True)
        asm_path = case_dir / f"{scenario.name}.S"
        elf_path = elfs_dir / f"{scenario.name}.elf"
        asm_path.write_text(emitter.emit(scenario, backend="tohost"), encoding="ascii")
        write_json(
            case_dir / "case.json",
            scenario_to_case_dict(
                scenario,
                seed=seed,
                index=sequence,
                generator_variant=generator_variant,
                generation_seed=generated.generation_seed,
                scenario_index=generated.scenario_index,
                mutation_operator="root",
                continuous_sequence=generated.root_sequence,
            ),
        )
        _compile_elf(
            compile_script=compile_script,
            asm_path=asm_path,
            elf_path=elf_path,
            cwd=root,
        )
        elf_paths.append(elf_path)

    return {
        "elf_paths": elf_paths,
        "resolved_profiles": resolved_profiles,
        "profile_distribution": _normalize_profile_distribution(profile_counts, count),
    }


def _compile_elf(
    *,
    compile_script: Path,
    asm_path: Path,
    elf_path: Path,
    cwd: Path,
) -> None:
    proc = subprocess.run(
        ["sh", str(compile_script), str(asm_path), str(elf_path)],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"compile failed for {asm_path.name} with exit code {proc.returncode}: "
            f"{proc.stdout[-500:] if proc.stdout else ''}"
        )


def _normalize_profile_distribution(counts: Counter[str], total: int) -> dict[str, float]:
    if total <= 0:
        return {}
    return {
        profile: count / float(total)
        for profile, count in sorted(counts.items())
    }


def _run_cascade_batch(
    *,
    out_dir: Path,
    design: str,
    seed: int,
    count: int,
) -> dict[str, Any]:
    elfs_dir = out_dir / "elfs"
    generator_report = _generate_elfs(
        num_elfs=count,
        out_dir=elfs_dir,
        seed=seed,
        design=design,
    )
    if not generator_report.get("success"):
        raise RuntimeError(
            f"cascade generation failed for design={design} seed={seed}: "
            f"returncode={generator_report.get('returncode')} "
            f"stderr={generator_report.get('stderr')!r}"
        )
    elf_paths = sorted(elfs_dir.glob("*.elf"))
    return {
        "elf_paths": elf_paths,
        "resolved_profiles": (),
        "profile_distribution": {},
        "generator_report": generator_report,
    }


def _measure_static_instructions(
    elf_paths: Sequence[Path],
    *,
    objdump_path: Path | None,
) -> dict[str, Any]:
    objdump = _resolve_objdump(objdump_path)
    per_elf: dict[str, int] = {}
    total = 0
    for elf_path in elf_paths:
        proc = subprocess.run(
            [objdump, "-d", str(elf_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"objdump failed for {elf_path.name} with exit code {proc.returncode}: "
                f"{proc.stderr[-500:] if proc.stderr else ''}"
            )
        count = sum(1 for line in proc.stdout.splitlines() if _INSTRUCTION_RE.match(line))
        per_elf[elf_path.name] = count
        total += count
    return {
        "total_static_instructions": total,
        "per_elf": per_elf,
    }


def _resolve_objdump(objdump_path: Path | None) -> str:
    if objdump_path is not None:
        return str(objdump_path)
    env_objdump = os.environ.get("RISCV_OBJDUMP")
    if env_objdump:
        return env_objdump
    env_gcc = os.environ.get("RISCV_GCC")
    if env_gcc:
        candidate = Path(env_gcc).resolve().with_name("riscv64-unknown-elf-objdump")
        if candidate.exists():
            return str(candidate)
    found = shutil.which("riscv64-unknown-elf-objdump")
    if found is None:
        raise FileNotFoundError(
            "riscv64-unknown-elf-objdump not found; set RISCV_OBJDUMP or add it to PATH"
        )
    return found


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = run_batch(args)
    print(
        f"tool={report['tool']} dut={report['dut']} seed={report['seed']} "
        f"elfs={report['generated_elf_count']} rate={report['elfs_per_second']}"
    )
    print(f"manifest={args.out.resolve() / 'batch_manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
