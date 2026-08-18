from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from pmpfuzz.bapc import (
    BAPC_CORE_VERSION_V3,
    BAPC_CORE_VERSION_V4,
    build_bapc_coverage_universe,
    map_bapc_normalized_record,
    normalize_bapc_core_version,
)
from pmpfuzz import off_state
from pmpfuzz.capabilities import capability_for_dut
from pmpfuzz.pmp import Access, AddressMode, Mseccfg, PmpEntry, PmpModel, Privilege

ACCESS_FAULT_MCAUSE_CLASS = {
    "fetch": "instruction_access_fault",
    "load": "load_access_fault",
    "store": "store_access_fault",
}
PAGE_FAULT_MCAUSE_CLASS = {
    "fetch": "instruction_page_fault",
    "load": "load_page_fault",
    "store": "store_page_fault",
}
DEFAULT_V4_OFF_STATE_ARTIFACT = Path(
    os.environ.get(
        "PMPFUZZ_CVA6_CHARACTERIZATION",
        "artifacts/cva6-off-state/off-state-characterization.json",
    )
)


def _parse_bin_id(bin_id: str) -> dict[str, str]:
    parts: dict[str, str] = {}
    for piece in str(bin_id).split("|"):
        key, value = piece.split("=", 1)
        parts[key] = value
    return parts


def _entry_dict_for_config(config_bin: dict[str, str]) -> dict[str, Any]:
    mode = config_bin["pmp_mode"]
    permission_rwx = config_bin["permission_rwx"]
    locked = config_bin["locked"] == "true"
    read, write, execute = [bit == "1" for bit in permission_rwx]
    if mode == "off":
        return {
            "index": 0,
            "address_mode": "off",
            "pmpaddr": "0x0",
            "read": False,
            "write": False,
            "execute": False,
            "locked": False,
        }
    if mode == "tor":
        return {
            "index": 0,
            "address_mode": "tor",
            "pmpaddr": hex(0x2400),
            "read": read,
            "write": write,
            "execute": execute,
            "locked": locked,
        }
    if mode == "na4":
        return {
            "index": 0,
            "address_mode": "na4",
            "pmpaddr": hex(0x2000),
            "read": read,
            "write": write,
            "execute": execute,
            "locked": locked,
        }
    if mode == "napot":
        return {
            "index": 0,
            "address_mode": "napot",
            "pmpaddr": hex(PmpEntry.encode_napot(0x8000, 16)),
            "read": read,
            "write": write,
            "execute": execute,
            "locked": locked,
        }
    raise ValueError(f"unsupported PMP mode: {mode}")


def _entry_model(entry: dict[str, Any]) -> PmpEntry:
    return PmpEntry(
        index=int(entry["index"]),
        address_mode={
            "off": AddressMode.OFF,
            "tor": AddressMode.TOR,
            "na4": AddressMode.NA4,
            "napot": AddressMode.NAPOT,
        }[str(entry["address_mode"])],
        pmpaddr=int(str(entry["pmpaddr"]), 16),
        read=bool(entry["read"]),
        write=bool(entry["write"]),
        execute=bool(entry["execute"]),
        locked=bool(entry["locked"]),
    )


def _default_address(mode: str) -> int:
    if mode in {"tor", "na4", "napot"}:
        return 0x8000
    return 0x9000


def _effective_state(privilege: str, effective_privilege: str, access: str) -> tuple[bool, str]:
    if access == "fetch":
        return False, "m"
    if privilege == "m" and effective_privilege != "m":
        return True, effective_privilege
    return False, "m"


def _privilege_enum(value: str) -> Privilege:
    return {
        "m": Privilege.M,
        "s": Privilege.S,
        "u": Privilege.U,
    }[str(value).lower()]


def _access_enum(value: str) -> Access:
    return {
        "fetch": Access.FETCH,
        "load": Access.LOAD,
        "store": Access.STORE,
    }[str(value).lower()]


def _permission_or_default_record(
    *,
    config_bin: dict[str, str],
    stimulus_bin: dict[str, str],
    entry: dict[str, Any],
    scenario_kind: str,
) -> dict[str, Any] | None:
    privilege = stimulus_bin["privilege"]
    effective_privilege = stimulus_bin["effective_privilege"]
    access = stimulus_bin["access"]
    translation = stimulus_bin["translation"]
    mprv, mpp = _effective_state(privilege, effective_privilege, access)
    address = _default_address(config_bin["pmp_mode"])
    size = 4
    decision = PmpModel(entries=[_entry_model(entry)], mseccfg=Mseccfg()).check(
        privilege=_privilege_enum(privilege),
        access=_access_enum(access),
        physical_address=address,
        size=size,
        mprv=mprv,
        mpp=_privilege_enum(mpp),
    )
    if decision.effective_privilege.value.lower() != effective_privilege:
        return None
    if scenario_kind == "allow":
        if not decision.allowed:
            return None
        mcause_class = "none"
        allow_or_deny = "allow"
        witness_address = address
        witness_size = size
    elif scenario_kind == "access-fault":
        if decision.allowed:
            return None
        mcause_class = ACCESS_FAULT_MCAUSE_CLASS[access]
        allow_or_deny = "deny"
        witness_address = address
        witness_size = size
    elif scenario_kind == "page-fault":
        if translation != "sv39":
            return None
        mcause_class = PAGE_FAULT_MCAUSE_CLASS[access]
        allow_or_deny = "deny"
        witness_address = address
        witness_size = size
    elif scenario_kind == "other":
        mcause_class = "other"
        allow_or_deny = "deny"
        witness_address = address + 1
        witness_size = 2
    else:
        raise ValueError(f"unsupported witness scenario: {scenario_kind}")
    return {
        "pmp_entries": [entry],
        "translation": translation,
        "privilege": privilege,
        "access": access,
        "size": witness_size,
        "address": hex(witness_address),
        "mprv": mprv,
        "mpp": mpp,
        "allow_or_deny": allow_or_deny,
        "mcause_class": mcause_class,
        "_scenario_kind": scenario_kind,
    }


def _candidate_records(universe: dict[str, Any]) -> list[dict[str, Any]]:
    configs = [
        _parse_bin_id(bin_id)
        for bin_id in universe["bin_ids"]
        if str(bin_id).startswith("family=config|")
    ]
    stimuli = [
        _parse_bin_id(bin_id)
        for bin_id in universe["bin_ids"]
        if str(bin_id).startswith("family=stimulus|")
    ]
    records: list[dict[str, Any]] = []
    for config_bin in configs:
        entry = _entry_dict_for_config(config_bin)
        for stimulus_bin in stimuli:
            for scenario_kind in ("allow", "access-fault", "page-fault", "other"):
                record = _permission_or_default_record(
                    config_bin=config_bin,
                    stimulus_bin=stimulus_bin,
                    entry=entry,
                    scenario_kind=scenario_kind,
                )
                if record is not None:
                    records.append(record)
    return records


def _resolve_off_state_artifact_path(path: Path | str | None) -> Path:
    if path is not None:
        return Path(path)
    if DEFAULT_V4_OFF_STATE_ARTIFACT.is_file():
        return DEFAULT_V4_OFF_STATE_ARTIFACT
    raise ValueError("BAPC-core v4 validation requires --off-state-artifact with stable OFF-state readback evidence")


def _off_state_config_bin_id(bits: dict[str, int]) -> str:
    return (
        "family=config|pmp_mode=off"
        f"|permission_rwx={bits['r']}{bits['w']}{bits['x']}"
        f"|locked={'true' if bits['l'] else 'false'}"
    )


def _off_state_witness_records(path: Path) -> list[dict[str, Any]]:
    artifact = json.loads(Path(path).read_text(encoding="utf-8"))
    off_state.analyze_characterization_artifact(artifact)
    witnesses: dict[str, dict[str, Any]] = {}
    for raw_record in artifact.get("records") or []:
        record = dict(raw_record)
        if not off_state.is_stable_readback_record(record):
            continue
        readback_bits = off_state.normalize_bits(record["readback_bits_2"])
        config_bin = _off_state_config_bin_id(readback_bits)
        if config_bin in witnesses:
            continue
        entry_index = int(record.get("entry_index") or 0)
        pmpaddr_value = str(record.get("pmpaddr_value") or "0x0")
        raw_log_sha256 = str(record.get("raw_log_sha256") or "").strip().lower()
        witness = {
            "pmp_entries": [
                {
                    "index": entry_index,
                    "address_mode": "off",
                    "pmpaddr": pmpaddr_value,
                    "read": False,
                    "write": False,
                    "execute": False,
                    "locked": False,
                }
            ],
            "actual_pmpcfg_entries": [
                {
                    "index": entry_index,
                    "address_mode": "off",
                    "read": bool(readback_bits["r"]),
                    "write": bool(readback_bits["w"]),
                    "execute": bool(readback_bits["x"]),
                    "locked": bool(readback_bits["l"]),
                    "evidence_kind": "off-state-replay-artifact",
                    "raw_log_sha256": raw_log_sha256,
                    "reset_id": str(record.get("reset_id") or ""),
                    "source_artifact": str(path),
                }
            ],
            "translation": "bare",
            "privilege": "m",
            "access": "load",
            "size": 4,
            "address": "0x9000",
            "mprv": True,
            "mpp": "u",
            "allow_or_deny": "deny",
            "mcause_class": "load_access_fault",
            "_scenario_kind": "off-state-readback",
        }
        if raw_log_sha256:
            witness["raw_trace_sha256"] = raw_log_sha256
        witnesses[config_bin] = witness
    return [witnesses[bin_id] for bin_id in sorted(witnesses)]


def _record_mapped_witness(
    *,
    record: dict[str, Any],
    scenario_kind: str,
    core_version: str,
    universe_set: set[str],
    witnessed_bins: set[str],
    unexpected_mapper_bins: set[str],
    witnesses: dict[str, dict[str, Any]],
) -> bool:
    mapped = map_bapc_normalized_record(record, bapc_core_version=core_version)
    if not mapped["eligible"]:
        return False
    mapped_bins = set(str(bin_id) for bin_id in mapped["observed_bins"])
    unexpected_mapper_bins.update(mapped_bins - universe_set)
    normalized_record = dict(mapped["normalized_record"])
    for bin_id in mapped["observed_bins"]:
        witnessed_bins.add(str(bin_id))
        if str(bin_id) in witnesses:
            continue
        witnesses[str(bin_id)] = {
            "bin_id": str(bin_id),
            "family": _parse_bin_id(str(bin_id))["family"],
            "scenario_kind": scenario_kind,
            "normalized_record": normalized_record,
            "all_bins_emitted_by_record": list(mapped["observed_bins"]),
        }
    return True


def build_validation_report(
    *,
    dut: str = "cva6",
    bapc_core_version: str = BAPC_CORE_VERSION_V3,
    generator_seed: int = 20260804,
    off_state_artifact: Path | str | None = None,
) -> dict[str, Any]:
    core_version = normalize_bapc_core_version(bapc_core_version)
    resolved_off_state_artifact = (
        _resolve_off_state_artifact_path(off_state_artifact)
        if core_version == BAPC_CORE_VERSION_V4
        else None
    )
    capability = capability_for_dut(dut)
    supported = dict(capability.get("supported_capabilities") or {})
    universe = build_bapc_coverage_universe(
        dut=dut,
        generator_seed=generator_seed,
        supports_fault_stage=bool(supported.get("sv39", False)),
        supports_smepmp=bool(supported.get("smepmp", False)),
        bapc_core_version=core_version,
    )
    universe_set = set(str(bin_id) for bin_id in universe["bin_ids"])
    candidate_records = _candidate_records(universe)
    witnessed_bins: set[str] = set()
    unexpected_mapper_bins: set[str] = set()
    witnesses: dict[str, dict[str, Any]] = {}
    valid_records = 0
    for record in candidate_records:
        scenario_kind = str(record.pop("_scenario_kind"))
        if _record_mapped_witness(
            record=record,
            scenario_kind=scenario_kind,
            core_version=core_version,
            universe_set=universe_set,
            witnessed_bins=witnessed_bins,
            unexpected_mapper_bins=unexpected_mapper_bins,
            witnesses=witnesses,
        ):
            valid_records += 1
    off_state_records_considered = 0
    if resolved_off_state_artifact is not None:
        for record in _off_state_witness_records(resolved_off_state_artifact):
            off_state_records_considered += 1
            scenario_kind = str(record.pop("_scenario_kind"))
            if _record_mapped_witness(
                record=record,
                scenario_kind=scenario_kind,
                core_version=core_version,
                universe_set=universe_set,
                witnessed_bins=witnessed_bins,
                unexpected_mapper_bins=unexpected_mapper_bins,
                witnesses=witnesses,
            ):
                valid_records += 1
    unwitnessed_bins = sorted(universe_set - witnessed_bins)
    witness_list = [witnesses[bin_id] for bin_id in sorted(witnesses)]
    report = {
        "dut": dut,
        "bapc_core_version": core_version,
        "capability_fingerprint": universe["capability_fingerprint"],
        "candidate_vocabulary_size": len(universe["bin_ids"]),
        "family_sizes": dict(universe.get("bapc_family_counts") or {}),
        "witnessed_bin_count": len(witnessed_bins),
        "unwitnessed_bin_count": len(unwitnessed_bins),
        "unexpected_mapper_bin_count": len(unexpected_mapper_bins),
        "records_considered": len(candidate_records) + off_state_records_considered,
        "records_witnessed": valid_records,
        "universe_hash": universe["sha256"],
        "bin_set_sha256": universe["bin_set_sha256"],
        "universe_bin_count": universe["bin_count"],
        "universe_bins": sorted(universe_set),
        "witnessed_bins": sorted(witnessed_bins),
        "unwitnessed_bins": unwitnessed_bins,
        "unexpected_mapper_bins": sorted(unexpected_mapper_bins),
        "witnesses": witness_list,
    }
    if resolved_off_state_artifact is not None:
        report["off_state_artifact"] = str(resolved_off_state_artifact)
    return report


def replay_validation_report(report: dict[str, Any]) -> dict[str, Any]:
    core_version = normalize_bapc_core_version(report.get("bapc_core_version"))
    universe_bins = set(str(item) for item in report.get("universe_bins") or [])
    replayed_bins: set[str] = set()
    unexpected_mapper_bins: set[str] = set()
    for witness in report.get("witnesses") or []:
        record = dict(witness.get("normalized_record") or {})
        mapped = map_bapc_normalized_record(record, bapc_core_version=core_version)
        if not mapped["eligible"]:
            raise AssertionError(f"witness is not replayable for {witness.get('bin_id')}: {mapped['qualification_reason']}")
        mapped_bins = [str(item) for item in mapped["observed_bins"]]
        if str(witness.get("bin_id")) not in mapped_bins:
            raise AssertionError(f"witness did not reproduce target bin {witness.get('bin_id')}")
        expected_bins = [str(item) for item in (witness.get("all_bins_emitted_by_record") or [])]
        if mapped_bins != expected_bins:
            raise AssertionError(f"witness replay diverged for {witness.get('bin_id')}")
        replayed_bins.update(mapped_bins)
        unexpected_mapper_bins.update(set(mapped_bins) - universe_bins)
    return {
        "replayed_bins": sorted(replayed_bins),
        "unexpected_mapper_bins": sorted(unexpected_mapper_bins),
        "unwitnessed_bins": sorted(universe_bins - replayed_bins),
    }


def _print_summary(report: dict[str, Any]) -> None:
    print(f"BAPC version: {report['bapc_core_version']}")
    print(f"candidate vocabulary size: {report['candidate_vocabulary_size']}")
    print(f"family sizes: {json.dumps(report['family_sizes'], ensure_ascii=True, sort_keys=True)}")
    print(f"number of witnessed bins: {report['witnessed_bin_count']}")
    print(f"number of unwitnessed bins: {report['unwitnessed_bin_count']}")
    print(f"unexpected mapper outputs: {report['unexpected_mapper_bin_count']}")
    print(f"universe hash: {report['universe_hash']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate BAPC universe closure with legal witness records.")
    parser.add_argument("--dut", default="cva6")
    parser.add_argument("--bapc-core-version", default=BAPC_CORE_VERSION_V3, choices=["v2", "v3", "v4"])
    parser.add_argument("--generator-seed", type=int, default=20260804)
    parser.add_argument("--off-state-artifact", default=None)
    parser.add_argument("--output", default="artifacts/bapc-v3-selfcheck.json")
    args = parser.parse_args(argv)

    report = build_validation_report(
        dut=str(args.dut),
        bapc_core_version=str(args.bapc_core_version),
        generator_seed=int(args.generator_seed),
        off_state_artifact=args.off_state_artifact,
    )
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="ascii",
    )
    persisted_report = json.loads(output_path.read_text(encoding="ascii"))
    replay = replay_validation_report(persisted_report)
    _print_summary(report)

    universe_bins = set(report["universe_bins"])
    witnessed = set(report["witnessed_bins"])
    unwitnessed = set(report["unwitnessed_bins"])
    unexpected = set(report["unexpected_mapper_bins"])
    if universe_bins != (witnessed | unwitnessed):
        raise AssertionError("witness bookkeeping is inconsistent")
    if unwitnessed or unexpected:
        raise AssertionError(
            f"universe is not mapper-closed: unwitnessed={len(unwitnessed)} unexpected={len(unexpected)}"
        )
    if set(replay["replayed_bins"]) != universe_bins:
        raise AssertionError("persisted witnesses do not replay to the full selected universe")
    if replay["unexpected_mapper_bins"] or replay["unwitnessed_bins"]:
        raise AssertionError(
            "persisted witness replay is not mapper-closed: "
            f"unwitnessed={len(replay['unwitnessed_bins'])} "
            f"unexpected={len(replay['unexpected_mapper_bins'])}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
