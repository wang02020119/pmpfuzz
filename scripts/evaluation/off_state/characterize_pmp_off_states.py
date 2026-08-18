from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from pmpfuzz.off_state import (
    OFF_STATE_ARTIFACT_KIND,
    OFF_STATE_PLAN_KIND,
    OFF_STATE_RECORD_SCHEMA_VERSION,
    OFF_STATE_PROFILES,
    build_characterization_plan,
    build_raw_state_universe,
    build_spec_encoding_sets,
    capture_repo_metadata,
    enrich_metadata,
    load_records,
    validate_characterization_record,
    write_json,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Plan and normalize PMP OFF-state characterization artifacts")
    parser.add_argument("--dut", required=True)
    parser.add_argument("--profile", dest="profiles", action="append", choices=OFF_STATE_PROFILES, default=None)
    parser.add_argument("--entry-index", dest="entry_indices", action="append", type=int, required=True)
    parser.add_argument("--reset-count", type=int, default=3)
    parser.add_argument("--input-records", type=Path, default=None)
    parser.add_argument("--plan-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dut-binary", type=Path, default=None)
    parser.add_argument("--firmware-payload", type=Path, default=None)
    parser.add_argument("--simulator-version", default=None)
    parser.add_argument("--isa-profile-configuration", default=None)
    parser.add_argument("--xlen", type=int, default=None)
    parser.add_argument("--pmp-entry-count", type=int, default=None)
    parser.add_argument("--pmp-grain", type=int, default=None)
    parser.add_argument("--reset-method", default=None)
    return parser


def build_characterization_artifact(args: argparse.Namespace) -> dict[str, Any]:
    profiles = args.profiles or list(OFF_STATE_PROFILES)
    repo_root = Path(__file__).resolve().parents[3]
    plan = build_characterization_plan(
        dut=str(args.dut),
        profiles=profiles,
        entry_indices=args.entry_indices,
        reset_count=int(args.reset_count),
    )
    metadata = capture_repo_metadata(repo_root, argv=sys.argv[1:])
    metadata = enrich_metadata(
        metadata,
        dut_binary=args.dut_binary,
        firmware_payload=args.firmware_payload,
        simulator_version=args.simulator_version,
        isa_configuration=args.isa_profile_configuration,
        xlen=args.xlen,
        pmp_entry_count=args.pmp_entry_count,
        pmp_grain=args.pmp_grain,
        reset_method=args.reset_method,
    )
    records = load_records(args.input_records) if args.input_records is not None else []
    errors: list[str] = []
    for index, record in enumerate(records):
        for item in validate_characterization_record(record):
            errors.append(f"record[{index}]: {item}")
    if errors:
        raise ValueError("\n".join(errors))
    spec_encoding_sets = build_spec_encoding_sets(profiles)
    requested_raw_vocabularies = {
        profile: build_raw_state_universe(profile)
        for profile in profiles
    }
    return {
        "schema_version": 1,
        "artifact_kind": OFF_STATE_ARTIFACT_KIND,
        "plan_artifact_kind": OFF_STATE_PLAN_KIND,
        "record_schema_version": OFF_STATE_RECORD_SCHEMA_VERSION,
        "metadata": metadata,
        "dut": str(args.dut),
        "profiles": profiles,
        "entry_indices": [int(item) for item in args.entry_indices],
        "reset_count": int(args.reset_count),
        "spec_encoding_sets": spec_encoding_sets,
        "requested_raw_vocabularies": requested_raw_vocabularies,
        "requested_raw_set": {
            profile: list(manifest["bin_ids"])
            for profile, manifest in requested_raw_vocabularies.items()
        },
        "spec_defined_set": {
            profile: list(spec_encoding_sets[profile]["spec-defined"])
            for profile in profiles
        },
        "plan": plan,
        "record_count": len(records),
        "records": records,
    }


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    artifact = build_characterization_artifact(args)
    write_json(args.plan_output, artifact["plan"])
    write_json(args.output, artifact)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
