from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from pmpfuzz.bapc import (
    BAPC_GENERATION_RULE_VERSION,
    BAPC_SCHEMA_VERSION,
    BAPC_TARGET,
    build_bapc_coverage_universe,
    validate_bapc_coverage_universe,
)
from pmpfuzz.capabilities import DEFAULT_CAPABILITY_SCHEMA_VERSION, capability_for_dut
from pmpfuzz.experiment_protocols import BAPC_CONVERGENCE_FORMAL, BAPC_CONVERGENCE_PROTOCOL_ID
from pmpfuzz.pmp import Access, AddressMode, Mseccfg, PmpEntry, Privilege
from pmpfuzz.scenario import (
    AccessProbe,
    M_DATA_BASE,
    M_DATA_SIZE,
    M_HARNESS_PMP_INDEX,
    M_TEXT_BASE,
    M_TEXT_SIZE,
    SU_HARNESS_PMP_INDEX,
    SU_CODE_BASE,
    SU_CODE_SIZE,
    PAGE_TABLE_BASE,
    TARGET_BASE,
    PmpScenario,
    ScenarioGenerator,
)
from pmpfuzz.scenario_codec import scenario_from_spec, scenario_hash, scenario_to_spec
from pmpfuzz.schema import scenario_to_case_dict, write_json
from pmpfuzz.u74_boot_chain import (
    bind_boot_chain_policy_to_fit,
    build_boot_chain_policy,
    parse_boot_chain_evidence_text,
    validate_boot_chain_policy,
)
from pmpfuzz.u74_board import (
    DIRECT_U74_BOARD_CASES,
    FORMAL_U74_BATCHED_VALIDATOR_PROFILE,
    _manifest_sha256,
    _recompute_generated_manifest_sha256,
    build_u74_campaign_feedback_state,
)
from scripts.evaluation.hardware.u74 import run_u74_board_round as u74_board_round


ROUND_ID = "round-0000"
DEFAULT_CAMPAIGN_ID = "u74-formal-4x64-seed-0004"
DEFAULT_PACKAGE_ROOT = Path(
    os.environ.get("PMPFUZZ_AUTH_PACKAGE_ROOT", "authorization_packages")
)
BOARD_TARGET_BASE = 0x41005000
BOARD_TARGET_STRIDE = 0x1000
SOURCE_TARGET_STRIDE = 0x2000
SUPPORTED_MATCH_MODES = {"na4", "napot", "tor", "first-match-overlap", "final-pmp"}
ROUND_GENERATOR_PROFILES = ("pmp-boundary", "legacy-data", "sv39-final-pmp")
MAX_GENERATOR_INDEX_PER_PROFILE = 50000
MAX_STALE_GENERATOR_INDICES = 4096
LEGACY_CASES = set(DIRECT_U74_BOARD_CASES)


def _round_id(round_index: int) -> str:
    return f"round-{int(round_index):04d}"


def _schedule_name(round_index: int) -> str:
    return f"schedule_round_{int(round_index):04d}.json"


def _now_utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_payload(payload: Any) -> str:
    raw = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _git_output(repo_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        text=True,
        capture_output=True,
        check=True,
    )
    return completed.stdout.strip()


def _git_status(repo_root: Path) -> str:
    return _git_output(repo_root, "status", "--porcelain", "--untracked-files=all")


def _json_load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="ascii"))


def _copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        raise FileExistsError(f"refusing to overwrite existing tree: {dst}")
    shutil.copytree(
        src,
        dst,
        ignore=shutil.ignore_patterns(".git", "build", "__pycache__", "*.pyc"),
    )


def _copy_boot_artifacts(src: Path, dst: Path) -> dict[str, Any]:
    required = [
        Path("extracted/current-u-boot-payload.bin"),
        Path("extracted/current-fdt.dtb"),
        Path("extracted/current-fdt-lite.dtb"),
    ]
    files = []
    for rel in required:
        src_path = src / rel
        if not src_path.exists():
            raise FileNotFoundError(f"missing boot artifact: {src_path}")
        dst_path = dst / rel
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        dst_path.write_bytes(src_path.read_bytes())
        files.append({"path": rel.as_posix(), "sha256": _sha256_file(dst_path), "bytes": dst_path.stat().st_size})
    return {"schema_version": 1, "source_root": str(dst), "files": files}


def _write_boot_chain_policy(
    package_dir: Path,
    *,
    evidence_path: Path,
    spl_image_path: Path,
    fit_path: Path,
) -> tuple[dict[str, Any], Path]:
    if not evidence_path.exists():
        raise FileNotFoundError(f"missing U74 boot-chain evidence file: {evidence_path}")
    if not spl_image_path.exists():
        raise FileNotFoundError(f"missing U74 p1 SPL image: {spl_image_path}")
    board_dir = package_dir / "frozen_inputs" / "board"
    board_dir.mkdir(parents=True, exist_ok=True)
    raw_dst = board_dir / "boot-chain-evidence.txt"
    spl_dst = board_dir / "mmcblk1p1-spl.img"
    shutil.copyfile(evidence_path, raw_dst)
    shutil.copyfile(spl_image_path, spl_dst)

    evidence = parse_boot_chain_evidence_text(raw_dst.read_text(encoding="utf-8", errors="replace"))
    policy = build_boot_chain_policy(
        evidence,
        expected_fit_sha256=_sha256_file(fit_path),
        expected_fit_bytes=fit_path.stat().st_size,
        raw_evidence_sha256=_sha256_file(raw_dst),
        raw_evidence_bytes=raw_dst.stat().st_size,
        spl_image_sha256=_sha256_file(spl_dst),
        spl_image_bytes=spl_dst.stat().st_size,
    )
    policy["raw_evidence_file"] = str(raw_dst)
    policy["spl_image_file"] = str(spl_dst)
    errors = validate_boot_chain_policy(
        policy,
        actual_fit_sha256=_sha256_file(fit_path),
        actual_fit_bytes=fit_path.stat().st_size,
    )
    if errors:
        raise ValueError("invalid U74 boot-chain policy: " + "; ".join(errors))
    policy_path = board_dir / "u74-sdio3-boot-chain-policy.json"
    write_json(policy_path, policy)
    return policy, policy_path


def _replace_required(text: str, old: str, new: str, *, label: str) -> str:
    if old not in text:
        raise RuntimeError(f"could not patch OpenSBI runner; missing marker: {label}")
    return text.replace(old, new, 1)


def _patch_opensbi_runner_for_formal(source_tree: Path) -> Path:
    runner_path = source_tree / "platform" / "generic" / "starfive" / "pmpfuzz_board_runner.c"
    text = runner_path.read_text(encoding="ascii")
    if "void pmpfuzz_board_record_generated_result(const char *status)" not in text:
        text = _replace_required(
            text,
            (
                "static unsigned int pmpfuzz_passes;\n"
                "static unsigned int pmpfuzz_failures;\n"
                "static unsigned int pmpfuzz_skips;\n\n"
            ),
            (
                "static unsigned int pmpfuzz_passes;\n"
                "static unsigned int pmpfuzz_failures;\n"
                "static unsigned int pmpfuzz_skips;\n\n"
                "void pmpfuzz_board_record_generated_result(const char *status)\n"
                "{\n"
                "\tif (!status) {\n"
                "\t\tpmpfuzz_failures++;\n"
                "\t\treturn;\n"
                "\t}\n"
                "\tif (status[0] == 'p' && status[1] == 'a' && status[2] == 's' &&\n"
                "\t    status[3] == 's' && status[4] == '\\0')\n"
                "\t\tpmpfuzz_passes++;\n"
                "\telse if (status[0] == 's' && status[1] == 'k' &&\n"
                "\t\t status[2] == 'i' && status[3] == 'p' && status[4] == '\\0')\n"
                "\t\tpmpfuzz_skips++;\n"
                "\telse\n"
                "\t\tpmpfuzz_failures++;\n"
                "}\n\n"
            ),
            label="counter declarations",
        )
    if text.count("cycle=0x%lx") < 2:
        text = _replace_required(
            text,
            (
                "\tsbi_printf(PF_TAG\n"
                "\t\t   \"runner begin phase=late-after-pmp backend=board-opensbi-serial layout=visionfive2-u74 campaign_id=%s round_id=%s case_count=%lu manifest_sha256=%s root_pa=0x%lx l1_pa=0x%lx l0_pa=0x%lx data_pa=0x%lx pmp_pa=0x%lx\\n\",\n"
                "\t\t   campaign_id, round_id, manifest_case_count, manifest_sha256,\n"
                "\t\t   PF_EXT_ROOT_PA, PF_EXT_L1_PA, PF_EXT_L0_PA, PF_EXT_DATA_PA,\n"
                "\t\t   PF_EXT_PMP_PA);\n"
            ),
            (
                "\tsbi_printf(PF_TAG\n"
                "\t\t   \"runner begin phase=late-after-pmp backend=board-opensbi-serial layout=visionfive2-u74 campaign_id=%s round_id=%s case_count=%lu manifest_sha256=%s root_pa=0x%lx l1_pa=0x%lx l0_pa=0x%lx data_pa=0x%lx pmp_pa=0x%lx cycle=0x%lx\\n\",\n"
                "\t\t   campaign_id, round_id, manifest_case_count, manifest_sha256,\n"
                "\t\t   PF_EXT_ROOT_PA, PF_EXT_L1_PA, PF_EXT_L0_PA, PF_EXT_DATA_PA,\n"
                "\t\t   PF_EXT_PMP_PA, csr_read(CSR_CYCLE));\n"
            ),
            label="runner begin line",
        )
        text = _replace_required(
            text,
            (
                "\tsbi_printf(PF_TAG\n"
                "\t\t   \"runner end phase=late-after-pmp campaign_id=%s round_id=%s case_count=%lu manifest_sha256=%s pass=%u fail=%u skip=%u status=%s\\n\",\n"
                "\t\t   campaign_id, round_id, manifest_case_count, manifest_sha256,\n"
                "\t\t   pmpfuzz_passes, pmpfuzz_failures, pmpfuzz_skips,\n"
                "\t\t   pmpfuzz_failures ? \"fail\" : \"pass\");\n"
            ),
            (
                "\tsbi_printf(PF_TAG\n"
                "\t\t   \"runner end phase=late-after-pmp campaign_id=%s round_id=%s case_count=%lu manifest_sha256=%s pass=%u fail=%u skip=%u status=%s cycle=0x%lx\\n\",\n"
                "\t\t   campaign_id, round_id, manifest_case_count, manifest_sha256,\n"
                "\t\t   pmpfuzz_passes, pmpfuzz_failures, pmpfuzz_skips,\n"
                "\t\t   pmpfuzz_failures ? \"fail\" : \"pass\", csr_read(CSR_CYCLE));\n"
            ),
            label="runner end line",
        )
    runner_path.write_text(text, encoding="ascii", newline="\n")
    return runner_path


def _trailing_ones(value: int) -> int:
    count = 0
    while value & 1:
        count += 1
        value >>= 1
    return count


def _entry_bounds(entry: PmpEntry, entries: list[PmpEntry]) -> tuple[int, int] | None:
    if entry.address_mode == AddressMode.OFF:
        return None
    if entry.address_mode == AddressMode.NA4:
        lower = entry.pmpaddr << 2
        return lower, lower + 4
    if entry.address_mode == AddressMode.NAPOT:
        ones = _trailing_ones(entry.pmpaddr)
        size = 1 << (ones + 3)
        lower = (entry.pmpaddr & ~((1 << ones) - 1)) << 2
        return lower, lower + size
    if entry.address_mode == AddressMode.TOR:
        previous_addr = 0
        if entry.index > 0:
            previous = next((item for item in entries if item.index == entry.index - 1), None)
            previous_addr = previous.pmpaddr if previous else 0
        lower = previous_addr << 2
        upper = entry.pmpaddr << 2
        return (lower, upper) if upper > lower else None
    return None


def _is_harness_entry(entry: PmpEntry) -> bool:
    if entry.address_mode != AddressMode.NAPOT:
        return False
    return entry.pmpaddr in {
        PmpEntry.encode_napot(base=0x80000000, size=0x4000),
        PmpEntry.encode_napot(base=M_TEXT_BASE, size=M_TEXT_SIZE),
        PmpEntry.encode_napot(base=M_DATA_BASE, size=M_DATA_SIZE),
        PmpEntry.encode_napot(base=SU_CODE_BASE, size=SU_CODE_SIZE),
    }


def _non_harness_entries(scenario: PmpScenario) -> list[PmpEntry]:
    return [
        entry
        for entry in scenario.entries
        if entry.address_mode != AddressMode.OFF and not _is_harness_entry(entry)
    ]


def _is_supported_formal_scenario(scenario: PmpScenario) -> bool:
    entries = _non_harness_entries(scenario)
    return (
        scenario.profile in ROUND_GENERATOR_PROFILES
        and scenario.probe.access in {Access.LOAD, Access.STORE, Access.FETCH}
        and scenario.pmp_match_mode in SUPPORTED_MATCH_MODES
        and not scenario.mseccfg.mml
        and not scenario.mseccfg.mmwp
        and not scenario.mseccfg.rlb
        and 1 <= len(entries) <= 2
        and all(
            entry.address_mode
            in {AddressMode.OFF, AddressMode.NA4, AddressMode.NAPOT, AddressMode.TOR}
            for entry in entries
        )
    )


def _source_base_for_entries(entries: list[PmpEntry], all_entries: list[PmpEntry]) -> int:
    lowers = []
    uppers = []
    for entry in entries:
        bounds = _entry_bounds(entry, all_entries)
        if bounds is not None:
            lowers.append(bounds[0])
            uppers.append(bounds[1])
    if not lowers:
        raise ValueError("lowered scenario has no concrete PMP bounds")
    min_lower = min(lowers)
    if min_lower < TARGET_BASE:
        raise ValueError(f"unsupported U74 source base for lowering: 0x{min_lower:x}")
    source_offset = min_lower - TARGET_BASE
    source_base = TARGET_BASE + (source_offset // SOURCE_TARGET_STRIDE) * SOURCE_TARGET_STRIDE
    if max(uppers) > source_base + SOURCE_TARGET_STRIDE:
        raise ValueError(f"scenario spans multiple U74 source windows from 0x{source_base:x}")
    return source_base


def _board_base_for_source_base(source_base: int) -> int:
    source_offset = source_base - TARGET_BASE
    if source_offset < 0 or source_offset % SOURCE_TARGET_STRIDE != 0:
        raise ValueError(f"unsupported source offset for U74 lowering: 0x{source_offset:x}")
    return BOARD_TARGET_BASE + ((source_offset // SOURCE_TARGET_STRIDE) % 2) * BOARD_TARGET_STRIDE


def _remap_pa(pa: int, *, source_base: int) -> int:
    return _board_base_for_source_base(source_base) + (pa - source_base)


def _prot_for_entry(entry: PmpEntry) -> int:
    prot = 0
    prot |= 0x1 if entry.read else 0
    prot |= 0x2 if entry.write else 0
    prot |= 0x4 if entry.execute else 0
    prot |= 0x80 if entry.locked else 0
    if entry.address_mode == AddressMode.TOR:
        # PMP_A field (bits 4:3): 0b01 = TOR.  OpenSBI's pmp_set derives NA4/
        # NAPOT from log2len but cannot infer TOR, so the mode must be encoded
        # explicitly in the pmpcfg A-field.
        prot |= 0x08
    return prot


def _mpp_for_scenario(scenario: PmpScenario) -> int:
    privilege = scenario.mpp if scenario.mprv and scenario.privilege == Privilege.M else scenario.privilege
    if privilege == Privilege.U:
        return 0
    if privilege == Privilege.S:
        return 1
    if privilege == Privilege.M:
        return 3
    raise ValueError(f"unsupported privilege for U74 lowering: {privilege!r}")


# Board ext page-table region used by pmpfuzz_setup_ext_mapping, plus the
# dedicated page used as the lowered sv39 target (disjoint from the tables).
_U74_EXT_ROOT_PA = 0x41000000
_U74_SV39_TARGET_PA = 0x41004000
_U74_SV39_SATP = (8 << 60) | (_U74_EXT_ROOT_PA >> 12)


def _lower_sv39_scenario(case: dict[str, Any], scenario: PmpScenario, *, ordinal: int) -> dict[str, Any]:
    sv39 = scenario.sv39
    assert sv39 is not None
    va = sv39.virtual_page
    target_pa = _U74_SV39_TARGET_PA
    pte_flags = sv39.pte.flags()
    entries = _non_harness_entries(scenario)
    lowered_entries = []
    for entry in entries:
        bounds = _entry_bounds(entry, scenario.entries)
        entry_base = bounds[0] if bounds is not None else None
        if entry_base is not None and entry_base == PAGE_TABLE_BASE:
            # Page-table read entry -> protect the board ext page-table region.
            addr = _U74_EXT_ROOT_PA
            size = 0x4000  # NAPOT covering 0x41000000..0x41003fff
        else:
            # Target-page entry -> protect the dedicated sv39 target page.
            addr = target_pa
            size = 0x1000
        lowered_entries.append(
            {
                "source_index": entry.index,
                "source_mode": entry.address_mode.name.lower(),
                "source_addr": f"0x{entry_base:x}" if entry_base is not None else "",
                "source_size": (bounds[1] - bounds[0]) if bounds is not None else 0,
                "prot": _prot_for_entry(entry),
                "addr": addr,
                "log2len": size.bit_length() - 1,
            }
        )
    expected = dict(case.get("expected") or {})
    expected_allowed = bool(expected.get("allowed"))
    expected_cause = expected.get("trap_cause")
    return {
        "schema_version": 1,
        "name": case["name"],
        "profile": case["profile"],
        "scenario_hash": case["scenario_hash"],
        "scenario_fingerprint": case["scenario_hash"],
        "source_profile": scenario.profile,
        "source_match_mode": scenario.pmp_match_mode,
        "source_probe_pa": f"0x{va:x}",
        "source_probe_size": scenario.probe.size,
        "probe_pa": target_pa,
        "access": scenario.probe.access.value,
        "mpp": _mpp_for_scenario(scenario),
        "expected_allowed": expected_allowed,
        "expected_cause": int(expected_cause) if expected_cause is not None else 0,
        "store_value": 0x55000000 + ordinal,
        "satp": _U74_SV39_SATP,
        "va": va,
        "pte_flags": pte_flags,
        "pmp_entries": lowered_entries,
    }


def _lower_scenario(case: dict[str, Any], scenario: PmpScenario, *, ordinal: int) -> dict[str, Any]:
    if scenario.sv39 is not None:
        return _lower_sv39_scenario(case, scenario, ordinal=ordinal)
    entries = _non_harness_entries(scenario)
    source_base = _source_base_for_entries(entries, scenario.entries)
    lowered_entries = []
    for entry in entries:
        bounds = _entry_bounds(entry, scenario.entries)
        if bounds is None:
            raise ValueError(f"entry {entry.index} has no PMP bounds")
        lower, upper = bounds
        size = upper - lower
        if size <= 0 or size & (size - 1):
            raise ValueError(f"entry {entry.index} has non-power-of-two PMP size")
        lowered_entries.append(
            {
                "source_index": entry.index,
                "source_mode": entry.address_mode.name.lower(),
                "source_addr": f"0x{lower:x}",
                "source_size": size,
                "prot": _prot_for_entry(entry),
                "addr": _remap_pa(lower, source_base=source_base),
                "log2len": size.bit_length() - 1,
            }
        )
    expected = dict(case.get("expected") or {})
    expected_allowed = bool(expected.get("allowed"))
    expected_cause = expected.get("trap_cause")
    return {
        "schema_version": 1,
        "name": case["name"],
        "profile": case["profile"],
        "scenario_hash": case["scenario_hash"],
        "scenario_fingerprint": case["scenario_hash"],
        "source_profile": scenario.profile,
        "source_match_mode": scenario.pmp_match_mode,
        "source_probe_pa": f"0x{scenario.probe.physical_address:x}",
        "source_probe_size": scenario.probe.size,
        "probe_pa": _remap_pa(scenario.probe.physical_address, source_base=source_base),
        "access": scenario.probe.access.value,
        "mpp": _mpp_for_scenario(scenario),
        "expected_allowed": expected_allowed,
        "expected_cause": int(expected_cause) if expected_cause is not None else 0,
        "store_value": 0x55000000 + ordinal,
        "pmp_entries": lowered_entries,
    }


def _candidate_id(*, seed: int, round_index: int, generator_profile: str, generator_index: int, scenario_fingerprint: str) -> str:
    return _hash_payload(
        {
            "kind": "u74-formal-4x64-candidate-v2",
            "seed": seed,
            "round_index": round_index,
            "generator_profile": generator_profile,
            "generator_index": generator_index,
            "scenario_fingerprint": scenario_fingerprint,
        }
    )[:16]


def _feedback_parent_records(feedback_state: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not feedback_state:
        return []
    records = [
        dict(record)
        for record in (feedback_state.get("case_records") or {}).values()
        if record.get("eligible") and isinstance(record.get("scenario_spec"), dict)
    ]
    return sorted(
        records,
        key=lambda record: (
            -int(record.get("new_bin_count") or 0),
            str(record.get("round_id") or ""),
            str(record.get("case_id") or ""),
        ),
    )


def _parent_energy(record: dict[str, Any]) -> float:
    value = record.get("selection_energy")
    if type(value) in {int, float} and not isinstance(value, bool) and float(value) > 0:
        return float(value)
    return float(max(int(record.get("new_bin_count") or 0), 1))


def _allocate_parent_slots(parents: list[dict[str, Any]], count: int) -> list[dict[str, Any]]:
    if not parents:
        raise RuntimeError("feedback-guided generation requires at least one parent")
    weights = [_parent_energy(parent) for parent in parents]
    total = sum(weights)
    current = [0.0 for _ in parents]
    slots: list[dict[str, Any]] = []
    for _ in range(count):
        for index, weight in enumerate(weights):
            current[index] += weight
        selected = max(
            range(len(parents)),
            key=lambda index: (
                current[index],
                weights[index],
                str(parents[index].get("case_id") or ""),
            ),
        )
        current[selected] -= total
        slots.append(parents[selected])
    return slots


def _stable_int(payload: dict[str, Any]) -> int:
    return int(_hash_payload(payload)[:16], 16)


def _harness_entries_for_privilege(privilege: Privilege) -> list[PmpEntry]:
    entries: list[PmpEntry] = []
    if privilege != Privilege.M:
        entries.append(
            PmpEntry(
                index=SU_HARNESS_PMP_INDEX,
                address_mode=AddressMode.NAPOT,
                pmpaddr=PmpEntry.encode_napot(base=SU_CODE_BASE, size=SU_CODE_SIZE),
                read=True,
                write=False,
                execute=True,
                locked=False,
            )
        )
    entries.append(
        PmpEntry(
            index=M_HARNESS_PMP_INDEX,
            address_mode=AddressMode.NAPOT,
            pmpaddr=PmpEntry.encode_napot(base=0x80000000, size=0x4000),
            read=True,
            write=True,
            execute=True,
            locked=False,
        )
    )
    return entries


def _permissions_for_child(entry: PmpEntry, *, access: Access, allow: bool) -> PmpEntry:
    if allow and access == Access.LOAD:
        read, write = True, False
    elif allow and access == Access.STORE:
        read, write = True, True
    elif access == Access.STORE:
        read, write = True, False
    else:
        read, write = False, False
    return replace(entry, read=read, write=write, execute=False, locked=False)


def _source_window_index_for_scenario(scenario: PmpScenario) -> int:
    try:
        source_base = _source_base_for_entries(_non_harness_entries(scenario), scenario.entries)
    except Exception:
        source_base = TARGET_BASE
    return max(0, (source_base - TARGET_BASE) // SOURCE_TARGET_STRIDE)


def _child_entries_for_mode(
    *,
    mode: str,
    base: int,
    access: Access,
    allow: bool,
) -> tuple[list[PmpEntry], str, int]:
    if mode == "na4":
        address = base if allow else base + 4
        entry = _permissions_for_child(
            PmpEntry(
                index=0,
                address_mode=AddressMode.NA4,
                pmpaddr=base >> 2,
                read=True,
                write=True,
                execute=False,
                locked=False,
            ),
            access=access,
            allow=allow,
        )
        return [entry], "inside" if allow else "upper_bound", address
    if mode == "first-match-overlap":
        first = _permissions_for_child(
            PmpEntry(
                index=0,
                address_mode=AddressMode.NAPOT,
                pmpaddr=PmpEntry.encode_napot(base=base, size=0x1000),
                read=True,
                write=True,
                execute=False,
                locked=False,
            ),
            access=access,
            allow=allow,
        )
        second = _permissions_for_child(
            PmpEntry(
                index=1,
                address_mode=AddressMode.NAPOT,
                pmpaddr=PmpEntry.encode_napot(base=base, size=0x2000),
                read=True,
                write=True,
                execute=False,
                locked=False,
            ),
            access=access,
            allow=not allow,
        )
        return [first, second], "inside", base + 0x100
    offset_selector = 0 if allow else 1
    offset_name, address = (
        ("inside", base + 0x100)
        if offset_selector == 0
        else ("upper_bound", base + 0x1000)
    )
    entry = _permissions_for_child(
        PmpEntry(
            index=0,
            address_mode=AddressMode.NAPOT,
            pmpaddr=PmpEntry.encode_napot(base=base, size=0x1000),
            read=True,
            write=True,
            execute=False,
            locked=False,
        ),
        access=access,
        allow=allow,
    )
    return [entry], offset_name, address


def _mutate_parent_scenario(
    parent: dict[str, Any],
    *,
    case_name: str,
    round_index: int,
    slot: int,
    parent_occurrence: int,
    mutation_nonce: int,
    previous_coverage_hash: str,
) -> PmpScenario:
    parent_scenario = scenario_from_spec(parent.get("scenario_spec"))
    parent_hash = str(parent.get("scenario_hash") or parent.get("scenario_fingerprint") or "")
    selector = _stable_int(
        {
            "kind": "u74-formal-feedback-child-mutation-v1",
            "round_index": round_index,
            "slot": slot,
            "parent_occurrence": parent_occurrence,
            "mutation_nonce": mutation_nonce,
            "parent_case_id": str(parent.get("case_id") or ""),
            "parent_scenario_hash": parent_hash,
            "parent_new_bin_count": int(parent.get("new_bin_count") or 0),
            "previous_coverage_hash": previous_coverage_hash,
        }
    )
    modes = ("na4", "napot", "first-match-overlap")
    parent_mode = str(parent_scenario.pmp_match_mode or "napot")
    parent_mode_index = modes.index(parent_mode) if parent_mode in modes else 1
    mode = modes[(parent_mode_index + 1 + selector % len(modes)) % len(modes)]
    accesses = (Access.LOAD, Access.STORE)
    parent_access_index = accesses.index(parent_scenario.probe.access) if parent_scenario.probe.access in accesses else 0
    access = accesses[(parent_access_index + 1 + ((selector >> 4) % len(accesses))) % len(accesses)]
    privileges = (Privilege.U, Privilege.S, Privilege.M)
    parent_privilege_index = privileges.index(parent_scenario.privilege) if parent_scenario.privilege in privileges else 0
    privilege = privileges[(parent_privilege_index + 1 + ((selector >> 6) % len(privileges))) % len(privileges)]
    mprv = privilege == Privilege.M and bool((selector >> 8) & 1)
    mpp = privileges[(selector >> 9) % len(privileges)] if mprv else Privilege.M
    allow = bool((selector >> 11) & 1)
    parent_window = _source_window_index_for_scenario(parent_scenario)
    source_window = (parent_window + 1 + ((selector >> 12) % 8)) % 8
    base = TARGET_BASE + source_window * SOURCE_TARGET_STRIDE
    entries, offset_name, address = _child_entries_for_mode(
        mode=mode,
        base=base,
        access=access,
        allow=allow,
    )
    entries.extend(_harness_entries_for_privilege(privilege))
    return replace(
        parent_scenario,
        name=case_name,
        entries=entries,
        privilege=privilege,
        probe=AccessProbe(access=access, physical_address=address, size=4, offset_name=offset_name),
        mprv=mprv,
        mpp=mpp,
        mseccfg=Mseccfg(),
        sv39=None,
        profile=parent_scenario.profile if parent_scenario.profile in ROUND_GENERATOR_PROFILES else "legacy-data",
        sum_enabled=False,
        mxr=False,
        sfence_vma=True,
        coverage_tags=tuple(parent_scenario.coverage_tags) + ("feedback-guided", mode, access.value, privilege.value),
        ptw_fault_level=None,
        preload_mode=None,
        pmp_match_mode=mode,
        pte_permissions={},
        security_focus="u74-formal-feedback-guided",
        smepmp_rule=None,
        stateful_sequence=None,
    )


def _generate_feedback_guided_round_cases(
    *,
    seed: int,
    round_index: int,
    count: int,
    seen_hashes: set[str],
    parents: list[dict[str, Any]],
    previous_coverage_hash: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    schedule_entries: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    lowered_cases: list[dict[str, Any]] = []
    round_seen: set[str] = set()
    parent_slots = _allocate_parent_slots(parents, count)
    parent_occurrences: dict[str, int] = {}
    for slot, parent in enumerate(parent_slots):
        parent_case_id = str(parent.get("case_id") or "")
        parent_occurrence = parent_occurrences.get(parent_case_id, 0)
        parent_occurrences[parent_case_id] = parent_occurrence + 1
        case_name = f"u74-formal-r{round_index}-case-{slot:04d}"
        case_index = round_index * 1_000_000 + slot
        for mutation_nonce in range(4096):
            scenario = _mutate_parent_scenario(
                parent,
                case_name=case_name,
                round_index=round_index,
                slot=slot,
                parent_occurrence=parent_occurrence,
                mutation_nonce=mutation_nonce,
                previous_coverage_hash=previous_coverage_hash,
            )
            original_spec = scenario_to_spec(scenario)
            fingerprint = scenario_hash(original_spec)
            if (
                fingerprint in seen_hashes
                or fingerprint in round_seen
                or not _is_supported_formal_scenario(scenario)
            ):
                continue
            case = scenario_to_case_dict(scenario, seed=seed, index=case_index)
            if case["scenario_hash"] != fingerprint:
                raise RuntimeError("scenario fingerprint changed after feedback mutation")
            lowered = _lower_scenario(case, scenario, ordinal=round_index * count + slot)
            parent_new_bins = int(parent.get("new_bin_count") or 0)
            entry = {
                "schema_version": 1,
                "round_id": _round_id(round_index),
                "round_index": round_index,
                "index": slot,
                "name": case_name,
                "case_id": case_name,
                "candidate_id": _candidate_id(
                    seed=seed,
                    round_index=round_index,
                    generator_profile="feedback-guided-parent-mutation-v1",
                    generator_index=case_index,
                    scenario_fingerprint=fingerprint,
                ),
                "seed": seed,
                "generator_profile": "feedback-guided-parent-mutation-v1",
                "generator_index": case_index,
                "case_index": case_index,
                "profile": case["profile"],
                "scenario_hash": fingerprint,
                "scenario_fingerprint": fingerprint,
                "scenario_spec": case["scenario_spec"],
                "lowering": lowered,
                "selection_source": "feedback-guided-parent-mutation",
                "feedback_policy": "feedback-guided-parent-mutation-v1",
                "previous_coverage_hash": previous_coverage_hash,
                "parent_case_id": parent_case_id,
                "parent_scenario_hash": str(parent.get("scenario_hash") or parent.get("scenario_fingerprint") or ""),
                "parent_new_bins": parent_new_bins,
                "selection_energy": _parent_energy(parent),
                "parent_occurrence": parent_occurrence,
                "mutation_nonce": mutation_nonce,
                "mutation_id": _hash_payload(
                    {
                        "kind": "u74-formal-feedback-mutation-v2",
                        "round_index": round_index,
                        "parent_case_id": parent_case_id,
                        "parent_scenario_hash": str(parent.get("scenario_hash") or ""),
                        "parent_occurrence": parent_occurrence,
                        "candidate_id": case_name,
                        "scenario_fingerprint": fingerprint,
                        "previous_coverage_hash": previous_coverage_hash,
                    }
                )[:16],
            }
            schedule_entries.append(entry)
            cases.append(case)
            lowered_cases.append(lowered)
            round_seen.add(fingerprint)
            break
        else:
            raise RuntimeError(f"could not mutate unique child for parent {parent_case_id} slot {slot}")
    return schedule_entries, cases, lowered_cases


def generate_round_cases(
    *,
    seed: int,
    round_index: int,
    count: int,
    exclude_fingerprints: set[str] | None = None,
    feedback_state: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    schedule_entries: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    lowered_cases: list[dict[str, Any]] = []
    seen_hashes: set[str] = {str(item) for item in (exclude_fingerprints or set()) if str(item)}
    round_seen: set[str] = set()
    parents = _feedback_parent_records(feedback_state)
    previous_coverage_hash = str((feedback_state or {}).get("coverage_hash") or "")
    if round_index > 0 and (not parents or not previous_coverage_hash):
        raise RuntimeError(f"Round {round_index} requires validated non-empty feedback provenance")
    if round_index > 0:
        return _generate_feedback_guided_round_cases(
            seed=seed,
            round_index=round_index,
            count=count,
            seen_hashes=seen_hashes,
            parents=parents,
            previous_coverage_hash=previous_coverage_hash,
        )

    for profile_offset, generator_profile in enumerate(ROUND_GENERATOR_PROFILES):
        generator = ScenarioGenerator(seed=seed, include_smepmp=False, profile=generator_profile)
        generator_index = 0
        stale_indices = 0
        while len(cases) < count and generator_index <= MAX_GENERATOR_INDEX_PER_PROFILE:
            scenario = generator.generate_one(generator_index)
            original_spec = scenario_to_spec(scenario)
            fingerprint = scenario_hash(original_spec)
            if (
                fingerprint in seen_hashes
                or fingerprint in round_seen
                or not _is_supported_formal_scenario(scenario)
            ):
                stale_indices += 1
                if stale_indices > MAX_STALE_GENERATOR_INDICES:
                    break
                generator_index += 1
                continue
            slot = len(cases)
            case_name = f"u74-formal-r{round_index}-case-{slot:04d}"
            case_index = round_index * 1_000_000 + profile_offset * 100_000 + generator_index
            scenario = replace(scenario, name=case_name)
            case = scenario_to_case_dict(scenario, seed=seed, index=case_index)
            if case["scenario_hash"] != fingerprint:
                raise RuntimeError("scenario fingerprint changed after case renaming")
            lowered = _lower_scenario(case, scenario, ordinal=round_index * count + slot)
            entry = {
                "schema_version": 1,
                "round_id": _round_id(round_index),
                "round_index": round_index,
                "index": slot,
                "name": case_name,
                "case_id": case_name,
                "candidate_id": _candidate_id(
                    seed=seed,
                    round_index=round_index,
                    generator_profile=generator_profile,
                    generator_index=generator_index,
                    scenario_fingerprint=fingerprint,
                ),
                "seed": seed,
                "generator_profile": generator_profile,
                "generator_index": generator_index,
                "case_index": case_index,
                "profile": case["profile"],
                "scenario_hash": fingerprint,
                "scenario_fingerprint": fingerprint,
                "scenario_spec": case["scenario_spec"],
                "lowering": lowered,
                "selection_source": "pmpfuzz-scenario-generator",
            }
            if round_index > 0:
                parent = parents[slot % len(parents)]
                parent_case_id = str(parent.get("case_id") or "")
                parent_new_bins = int(parent.get("new_bin_count") or 0)
                entry.update(
                    {
                        "previous_coverage_hash": previous_coverage_hash,
                        "parent_case_id": parent_case_id,
                        "parent_new_bins": parent_new_bins,
                        "selection_energy": float(max(parent_new_bins, 1)),
                        "mutation_id": _hash_payload(
                            {
                                "kind": "u74-formal-feedback-mutation-v1",
                                "round_index": round_index,
                                "parent_case_id": parent_case_id,
                                "candidate_id": entry["candidate_id"],
                                "previous_coverage_hash": previous_coverage_hash,
                            }
                        )[:16],
                    }
                )
            schedule_entries.append(entry)
            cases.append(case)
            lowered_cases.append(lowered)
            round_seen.add(fingerprint)
            stale_indices = 0
            generator_index += 1
        if len(cases) >= count:
            break
    if len(cases) != count:
        raise RuntimeError(
            f"could not generate {count} unique supported U74 scenarios for round {round_index}; "
            f"generated={len(cases)}"
        )
    return schedule_entries, cases, lowered_cases


def generate_round0_cases(*, seed: int, count: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    return generate_round_cases(seed=seed, round_index=0, count=count)


def _write_cases(round_dir: Path, cases: list[dict[str, Any]]) -> None:
    for case in cases:
        write_json(round_dir / "cases" / str(case["name"]) / "case.json", case)


def _source_tree_manifest(root: Path) -> dict[str, Any]:
    rows = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_dir():
            continue
        rel = path.relative_to(root).as_posix()
        rows.append({"path": rel, "sha256": _sha256_file(path), "bytes": path.stat().st_size})
    payload = {
        "schema_version": 1,
        "source_root": str(root),
        "file_count": len(rows),
        "files": rows,
        "contains_git_metadata": any(".git" in Path(row["path"]).parts for row in rows),
    }
    payload["tree_sha256"] = _hash_payload([(row["path"], row["sha256"]) for row in rows])
    return payload


def _write_coverage_universe(
    package_dir: Path,
    *,
    seed: int,
    capability: dict[str, Any],
) -> tuple[dict[str, Any], Path, dict[str, Any], Path]:
    universe = build_bapc_coverage_universe(
        dut="u74",
        generator_seed=seed,
        supports_fault_stage=False,
        supports_smepmp=bool((capability.get("supported_capabilities") or {}).get("smepmp")),
    )
    validate_bapc_coverage_universe(universe)
    universe_path = package_dir / "coverage" / "u74-supported-bapc-core-v2-universe.json"
    write_json(universe_path, universe)
    exclusions = {
        "schema_version": 1,
        "dut": "u74",
        "coverage_mode": "bapc",
        "supported_target_label": "u74-supported-bapc-core-v2",
        "source_target": BAPC_TARGET,
        "source_generation_rule_version": BAPC_GENERATION_RULE_VERSION,
        "source_bapc_schema_version": BAPC_SCHEMA_VERSION,
        "source_bin_count": int(universe["bin_count"]),
        "supported_bin_count": int(universe["bin_count"]),
        "excluded_bin_count": 0,
        "excluded_bins": [],
        "exclusion_reasons": [
            {
                "scope": "u74-supported-bapc-core-v2",
                "reason": "BAPC-core v2 target-operation universe is already filtered to bins observable by the U74 UART formal profile; no scenario-derived denominator bins are added.",
            }
        ],
        "capability_fingerprint": str(universe["capability_fingerprint"]),
    }
    exclusions_path = package_dir / "coverage" / "u74-supported-bapc-core-v2-exclusions.json"
    write_json(exclusions_path, exclusions)
    return universe, universe_path, exclusions, exclusions_path


def _build_generated_manifest(
    *,
    campaign_id: str,
    round_id: str,
    seed: int,
    cases: list[dict[str, Any]],
    lowered_cases: list[dict[str, Any]],
    capability_fingerprint: str,
    universe: dict[str, Any],
    universe_path: Path,
    universe_file_sha256: str,
    exclusions_path: Path,
    exclusions_file_sha256: str,
) -> dict[str, Any]:
    payload = {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "round_id": round_id,
        "seed": seed,
        "profile": "pmpfuzz-formal-u74-generated",
        "generator_profiles": list(ROUND_GENERATOR_PROFILES),
        "validator_profile": FORMAL_U74_BATCHED_VALIDATOR_PROFILE,
        "coverage_mode": "bapc",
        "target": BAPC_TARGET,
        "u74_supported_target_label": "u74-supported-bapc-core-v2",
        "bapc_schema_version": BAPC_SCHEMA_VERSION,
        "bapc_generation_rule_version": BAPC_GENERATION_RULE_VERSION,
        "supported_bapc_universe_sha256": str(universe["sha256"]),
        "supported_bapc_universe_file_sha256": universe_file_sha256,
        "supported_bapc_exclusions_file_sha256": exclusions_file_sha256,
        "dut": "u74",
        "round_count": 4,
        "cases_per_round": 64,
        "case_count": len(cases),
        "selected_cases": [str(case["name"]) for case in cases],
        "scenario_fingerprints": [str(case["scenario_hash"]) for case in cases],
        "lowered_cases": lowered_cases,
        "capability_fingerprint": capability_fingerprint,
        "bapc_schema_version": BAPC_SCHEMA_VERSION,
        "bapc_generation_rule_version": BAPC_GENERATION_RULE_VERSION,
        "supported_bapc_universe_sha256": str(universe["sha256"]),
        "supported_bapc_universe_file": str(universe_path),
        "supported_bapc_universe_file_sha256": universe_file_sha256,
        "supported_bapc_exclusions_file": str(exclusions_path),
        "supported_bapc_exclusions_file_sha256": exclusions_file_sha256,
        "observation_profile_id": "u74-formal-round0-offline-preflight-v1",
        "experiment_protocol_id": BAPC_CONVERGENCE_PROTOCOL_ID,
        "round_generation_policy": "round1_to_round3_generated_after_green_feedback_only",
        "feedback_policy": "feedback-guided-parent-mutation-v1",
    }
    payload["manifest_sha256"] = _manifest_sha256(payload)
    return payload


def _write_campaign_metadata(
    package_dir: Path,
    *,
    campaign_id: str,
    seed: int,
    capability: dict[str, Any],
    capability_fingerprint: str,
    universe: dict[str, Any],
    universe_path: Path,
    universe_file_sha256: str,
    exclusions_path: Path,
    exclusions_file_sha256: str,
) -> Path:
    metadata = {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "dut": "u74",
        "method": "pmpfuzz",
        "variant": "bb-guided",
        "run_class": "formal",
        "coverage_mode": "bapc",
        "target": BAPC_TARGET,
        "u74_supported_target_label": "u74-supported-bapc-core-v2",
        "seed": seed,
        "experiment_protocol_id": BAPC_CONVERGENCE_PROTOCOL_ID,
        "validator_profile": FORMAL_U74_BATCHED_VALIDATOR_PROFILE,
        "capability_schema_version": DEFAULT_CAPABILITY_SCHEMA_VERSION,
        "capability_fingerprint": capability_fingerprint,
        "capability": capability,
        "coverage_universe_hashes": {"bapc": str(universe["sha256"])},
        "coverage_universe_files": {"bapc": str(universe_path)},
        "u74_round_identity": {
            "validator_profile": FORMAL_U74_BATCHED_VALIDATOR_PROFILE,
            "supplemental_profiles": [],
            "capability_fingerprint": capability_fingerprint,
            "supported_bapc_universe_embedded_sha256": str(universe["sha256"]),
            "supported_bapc_universe_file": str(universe_path),
            "supported_bapc_universe_file_sha256": universe_file_sha256,
            "supported_bapc_exclusions_file": str(exclusions_path),
            "supported_bapc_exclusions_file_sha256": exclusions_file_sha256,
            "bapc_schema_version": BAPC_SCHEMA_VERSION,
            "bapc_generation_rule_version": BAPC_GENERATION_RULE_VERSION,
            "bapc_target": BAPC_TARGET,
        },
        "round_count": 4,
        "cases_per_round": 64,
        "round_generation_policy": "generate-after-validated-feedback",
        **BAPC_CONVERGENCE_FORMAL,
    }
    path = package_dir / "metrics" / "campaign_metadata.json"
    write_json(path, metadata)
    return path


def _preflight_check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    return {"name": name, "passed": bool(passed), "detail": str(detail)}


def _hex64(value: object) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def run_preflight(
    package_dir: Path,
    *,
    campaign_id: str,
    schedule_entries: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    manifest_payload: dict[str, Any],
    coverage_universe: dict[str, Any],
    universe_path: Path,
    exclusions_manifest: dict[str, Any],
    exclusions_path: Path,
    board_patch_manifest: dict[str, Any],
    source_manifest: dict[str, Any],
    boot_chain_policy: dict[str, Any],
    controller_status: str,
    source_tree: Path,
    fit_path: Path,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    errors: list[str] = []

    def add(name: str, passed: bool, detail: str = "", *, error: str | None = None) -> None:
        checks.append(_preflight_check(name, passed, detail))
        if not passed:
            errors.append(error or name)

    schedule_names = [str(entry.get("name") or "") for entry in schedule_entries]
    case_names = [str(case.get("name") or "") for case in cases]
    manifest_names = [str(item) for item in (manifest_payload.get("selected_cases") or [])]
    fingerprints = [str(entry.get("scenario_fingerprint") or entry.get("scenario_hash") or "") for entry in schedule_entries]
    manifest_fingerprints = [str(item) for item in (manifest_payload.get("scenario_fingerprints") or [])]
    lowered_cases = [dict(item) for item in (manifest_payload.get("lowered_cases") or [])]
    round_id = str(manifest_payload.get("round_id") or ROUND_ID)
    round_dir = package_dir / round_id
    case_json_paths = list((round_dir / "cases").glob("*/case.json"))
    generated_c = source_tree / "platform" / "generic" / "starfive" / "pmpfuzz_board_generated_manifest.c"
    runner_c = source_tree / "platform" / "generic" / "starfive" / "pmpfuzz_board_runner.c"
    probe_c = source_tree / "platform" / "generic" / "starfive" / "security_chain_probe.c"
    board_manifest_copy = round_dir / "manifests" / "board_manifest.c"

    add("scheduled_count_64", len(schedule_entries) == 64, str(len(schedule_entries)))
    add("case_json_count_64", len(case_json_paths) == 64, str(len(case_json_paths)))
    add("manifest_count_64", len(manifest_names) == 64, str(len(manifest_names)))
    add("lowered_count_64", len(lowered_cases) == 64, str(len(lowered_cases)))
    add("schedule_manifest_names_match", schedule_names == manifest_names, "ordered selected_cases")
    add("schedule_case_names_match", schedule_names == case_names, "ordered case JSON names")
    add("unique_case_ids_64", len(set(schedule_names)) == 64, str(len(set(schedule_names))))
    add("unique_candidate_ids_64", len({str(entry.get("candidate_id") or "") for entry in schedule_entries}) == 64, "")
    add("unique_scenario_fingerprints_64", len(set(fingerprints)) == 64, str(len(set(fingerprints))))
    add("manifest_fingerprints_match_schedule", manifest_fingerprints == fingerprints, "")
    add("no_legacy_case_names", not (set(schedule_names) & LEGACY_CASES), ",".join(sorted(set(schedule_names) & LEGACY_CASES)))
    add(
        "no_legacy_scenario_specs",
        all(
            "legacy_case_id" not in dict(entry.get("scenario_spec") or {})
            and "catalog_source" not in dict(entry.get("scenario_spec") or {})
            for entry in schedule_entries
        ),
        "",
    )
    add("validator_profile_formal", manifest_payload.get("validator_profile") == FORMAL_U74_BATCHED_VALIDATOR_PROFILE, "")
    add("campaign_id_bound", manifest_payload.get("campaign_id") == campaign_id, str(manifest_payload.get("campaign_id")))
    add("round_id_present", bool(round_id), str(manifest_payload.get("round_id")))
    add("seed_bound", int(manifest_payload.get("seed") or -1) == 4, str(manifest_payload.get("seed")))
    add("round_count_bound", int(manifest_payload.get("round_count") or 0) == 4, str(manifest_payload.get("round_count")))
    add("cases_per_round_bound", int(manifest_payload.get("cases_per_round") or 0) == 64, str(manifest_payload.get("cases_per_round")))
    add("coverage_mode_bound", manifest_payload.get("coverage_mode") == "bapc", str(manifest_payload.get("coverage_mode")))
    add("target_bound", manifest_payload.get("target") == BAPC_TARGET, str(manifest_payload.get("target")))
    add("u74_supported_target_label_bound", manifest_payload.get("u74_supported_target_label") == "u74-supported-bapc-core-v2", str(manifest_payload.get("u74_supported_target_label")))
    add("dut_bound", manifest_payload.get("dut") == "u74", str(manifest_payload.get("dut")))
    add(
        "manifest_sha256_recomputes",
        _recompute_generated_manifest_sha256(manifest_payload) == manifest_payload.get("manifest_sha256"),
        "",
    )

    for entry, case in zip(schedule_entries, cases):
        if str(entry.get("scenario_hash") or "") != str(case.get("scenario_hash") or ""):
            errors.append(f"scenario_hash_mismatch:{entry.get('name')}")
        if dict(entry.get("scenario_spec") or {}) != dict(case.get("scenario_spec") or {}):
            errors.append(f"scenario_spec_mismatch:{entry.get('name')}")
    checks.append(
        _preflight_check(
            "schedule_case_hash_specs_match",
            not any(error.startswith("scenario_hash_mismatch:") or error.startswith("scenario_spec_mismatch:") for error in errors),
            "",
        )
    )

    universe_file_sha256 = _sha256_file(universe_path)
    exclusions_file_sha256 = _sha256_file(exclusions_path)
    try:
        validate_bapc_coverage_universe(dict(coverage_universe))
        universe_valid = True
    except Exception as exc:
        universe_valid = False
        errors.append(f"coverage_universe_invalid:{exc}")
    checks.append(_preflight_check("coverage_universe_valid", universe_valid, ""))
    add("coverage_universe_file_sha256_bound", manifest_payload.get("supported_bapc_universe_file_sha256") == universe_file_sha256, universe_file_sha256)
    add("coverage_universe_embedded_sha256_bound", manifest_payload.get("supported_bapc_universe_sha256") == coverage_universe.get("sha256"), str(coverage_universe.get("sha256")))
    add("coverage_universe_bin_count_208", int(coverage_universe.get("bin_count") or 0) == 208, str(coverage_universe.get("bin_count")))
    add("coverage_universe_mode_bapc", coverage_universe.get("coverage_mode") == "bapc", str(coverage_universe.get("coverage_mode")))
    add("coverage_universe_target_bapc_core", coverage_universe.get("target") == BAPC_TARGET, str(coverage_universe.get("target")))
    add("coverage_universe_generation_rule_v2", coverage_universe.get("generation_rule_version") == BAPC_GENERATION_RULE_VERSION, str(coverage_universe.get("generation_rule_version")))
    add("coverage_universe_schema_v2", int(coverage_universe.get("bapc_schema_version") or 0) == BAPC_SCHEMA_VERSION, str(coverage_universe.get("bapc_schema_version")))
    add("coverage_universe_dut_u74", coverage_universe.get("dut") == "u74", str(coverage_universe.get("dut")))
    add("coverage_exclusions_file_sha256_bound", manifest_payload.get("supported_bapc_exclusions_file_sha256") == exclusions_file_sha256, exclusions_file_sha256)
    add("coverage_exclusions_target_bound", exclusions_manifest.get("source_target") == BAPC_TARGET, str(exclusions_manifest.get("source_target")))
    add("coverage_exclusions_bin_count_bound", int(exclusions_manifest.get("supported_bin_count") or 0) == int(coverage_universe.get("bin_count") or -1), str(exclusions_manifest.get("supported_bin_count")))
    add(
        "capability_fingerprint_bound",
        manifest_payload.get("capability_fingerprint") == coverage_universe.get("capability_fingerprint"),
        str(manifest_payload.get("capability_fingerprint")),
    )

    add("controller_source_clean", controller_status == "", controller_status)
    add("opensbi_source_root_bound", source_manifest.get("source_root") == str(source_tree), str(source_manifest.get("source_root")))
    add("opensbi_source_has_no_git_metadata", not bool(source_manifest.get("contains_git_metadata")), "")
    add("opensbi_source_manifest_nonempty", int(source_manifest.get("file_count") or 0) > 0, str(source_manifest.get("file_count")))
    source_rows = list(source_manifest.get("files") or [])
    add(
        "opensbi_source_manifest_hashes_match",
        all(_sha256_file(source_tree / str(row["path"])) == str(row["sha256"]) for row in source_rows),
        str(len(source_rows)),
    )
    add("board_manifest_c_exists", board_manifest_copy.exists(), str(board_manifest_copy))
    add(
        "board_manifest_c_matches_generated_source",
        board_manifest_copy.exists() and generated_c.exists() and _sha256_file(board_manifest_copy) == _sha256_file(generated_c),
        "",
    )
    add("board_manifest_c_sha_bound", board_patch_manifest.get("generated_manifest_c_sha256") == _sha256_file(generated_c), str(board_patch_manifest.get("generated_manifest_c_sha256")))
    add("runner_sha_bound", _hex64(board_patch_manifest.get("runner_sha256")), str(board_patch_manifest.get("runner_sha256")))
    add("runner_sha_matches_source", runner_c.exists() and board_patch_manifest.get("runner_sha256") == _sha256_file(runner_c), str(board_patch_manifest.get("runner_sha256")))
    add("probe_sha_bound", _hex64(board_patch_manifest.get("probe_sha256")), str(board_patch_manifest.get("probe_sha256")))
    add("probe_sha_matches_source", probe_c.exists() and board_patch_manifest.get("probe_sha256") == _sha256_file(probe_c), str(board_patch_manifest.get("probe_sha256")))
    add("board_patch_sha_bound", _hex64(board_patch_manifest.get("board_patch_sha256")), str(board_patch_manifest.get("board_patch_sha256")))
    generated_text = generated_c.read_text(encoding="ascii", errors="ignore") if generated_c.exists() else ""
    runner_text = runner_c.read_text(encoding="ascii", errors="ignore") if runner_c.exists() else ""
    add("generated_cases_update_runner_counts", "pmpfuzz_lowered_count_status" in generated_text and "pmpfuzz_board_record_generated_result" in generated_text, "")
    add("runner_exports_generated_result_counter", "pmpfuzz_board_record_generated_result" in runner_text, "")
    add("runner_begin_end_cycle_fields", runner_text.count("cycle=0x%lx") >= 2 and "csr_read(CSR_CYCLE)" in runner_text, "")
    add("fit_exists", fit_path.exists(), str(fit_path))
    fit_sha = _sha256_file(fit_path) if fit_path.exists() else ""
    fit_bytes = fit_path.stat().st_size if fit_path.exists() else 0
    add("fit_sha_real_hex", _hex64(fit_sha), fit_sha)
    add("fit_sha_bound", fit_sha == board_patch_manifest.get("fit_sha256"), str(board_patch_manifest.get("fit_sha256")))
    add("fw_payload_sha_bound", _hex64(board_patch_manifest.get("fw_payload_sha256")), str(board_patch_manifest.get("fw_payload_sha256")))
    add("real_fit_not_empty", fit_path.exists() and fit_bytes > 0, str(fit_bytes))

    boot_chain_errors = validate_boot_chain_policy(
        boot_chain_policy,
        actual_fit_sha256=fit_sha,
        actual_fit_bytes=fit_bytes,
    )
    add(
        "boot_chain_policy_valid",
        not boot_chain_errors,
        ";".join(boot_chain_errors),
        error="boot_chain_policy_invalid:" + ",".join(boot_chain_errors),
    )

    report = {
        "schema_version": 1,
        "profile": FORMAL_U74_BATCHED_VALIDATOR_PROFILE,
        "campaign_id": campaign_id,
        "round_id": round_id,
        "scheduled": len(schedule_entries),
        "manifest": len(manifest_names),
        "unique_case_id_count": len(set(schedule_names)),
        "unique_scenario_fingerprint_count": len(set(fingerprints)),
        "fit_sha256": fit_sha,
        "fit_bytes": fit_bytes,
        "source_clean": controller_status == "" and not bool(source_manifest.get("contains_git_metadata")),
        "boot_chain_policy_kind": str(boot_chain_policy.get("policy_kind") if isinstance(boot_chain_policy, dict) else ""),
        "boot_chain_p1_spl_sha256": str(
            ((boot_chain_policy.get("p1_spl") or {}).get("sha256") if isinstance(boot_chain_policy, dict) else "")
            or ""
        ),
        "boot_chain_disk_ptuuid": str(
            ((boot_chain_policy.get("disk") or {}).get("ptuuid") if isinstance(boot_chain_policy, dict) else "")
            or ""
        ),
        "capability_fingerprint": manifest_payload.get("capability_fingerprint"),
        "supported_bapc_universe_sha256": coverage_universe.get("sha256"),
        "supported_bapc_universe_file_sha256": universe_file_sha256,
        "supported_bapc_exclusions_file_sha256": exclusions_file_sha256,
        "checks": checks,
        "errors": errors,
        "error_count": len(errors),
        "valid": len(errors) == 0,
    }
    return report


def _seal_package(package_dir: Path) -> tuple[str, Path]:
    rows = []
    for path in sorted(package_dir.rglob("*"), key=lambda item: item.relative_to(package_dir).as_posix()):
        if path.is_dir():
            continue
        rel = path.relative_to(package_dir).as_posix()
        if rel == "sha256.txt":
            continue
        rows.append(f"{_sha256_file(path)}  {rel}")
    sha_path = package_dir / "sha256.txt"
    sha_path.write_text("\n".join(rows) + "\n", encoding="ascii")
    return _sha256_file(sha_path), sha_path


def _write_runbook(package_dir: Path, *, fit_sha256: str) -> None:
    text = (
        "# U74 formal 4x64 Round 0 offline package\n\n"
        "- package_sha256: computed as the SHA256 of `sha256.txt` after sealing\n"
        f"- round0_fit_sha256: `{fit_sha256}`\n"
        "- board action state: paused pending exact SHA authorization\n"
        "- profile: `formal-u74-batched-v1`\n"
        "- seed: `4`\n"
        "- denominator: `bapc-core-universe-v2`, U74 supported target-operation universe\n"
        "- round policy: generate Round 1/2/3 only after the previous real board round validates green\n"
        "- retry policy: at most one infrastructure retry with the identical FIT per round\n\n"
        "## After exact SHA authorization only\n\n"
        "1. Run real Round 0 with the packaged FIT, SDIO3 cold boot, early UART capture, MMC2/SDIO3 confirmation, and `--u74-boot-chain-policy '<this-package>/frozen_inputs/board/u74-sdio3-boot-chain-policy.json'`.\n"
        "2. Validate Round 0 with `formal-u74-batched-v1`; stop if any validator field is red.\n"
        "3. Prepare the next round only after the previous round is green:\n\n"
        "```powershell\n"
        "Push-Location '<controller-root>'\n"
        "python -m scripts.evaluation.hardware.u74.u74_formal_round0_prepare prepare-next-round --package-dir '<this-package>' --round-index 1 --previous-round-dir '<real-round-0000-output>'\n"
        "python -m scripts.evaluation.hardware.u74.u74_formal_round0_prepare prepare-next-round --package-dir '<this-package>' --round-index 2 --previous-round-dir '<real-round-0000-output>' --previous-round-dir '<real-round-0001-output>'\n"
        "python -m scripts.evaluation.hardware.u74.u74_formal_round0_prepare prepare-next-round --package-dir '<this-package>' --round-index 3 --previous-round-dir '<real-round-0000-output>' --previous-round-dir '<real-round-0001-output>' --previous-round-dir '<real-round-0002-output>'\n"
        "Pop-Location\n"
        "```\n"
    )
    (package_dir / "execution_runbook.md").write_text(text, encoding="ascii")


def prepare_round0(args: argparse.Namespace) -> dict[str, Any]:
    if int(args.seed) != 4:
        raise ValueError("this formal U74 campaign is fixed to seed=4")
    if int(args.case_count) != 64:
        raise ValueError("this formal U74 Round 0 package is fixed to 64 cases")
    if args.boot_chain_evidence is None:
        raise ValueError("formal U74 Round 0 package requires --boot-chain-evidence")
    if args.boot_chain_spl_image is None:
        raise ValueError("formal U74 Round 0 package requires --boot-chain-spl-image")

    repo_root = Path(__file__).resolve().parents[4]
    controller_git_sha = _git_output(repo_root, "rev-parse", "HEAD")
    controller_status = _git_status(repo_root)

    package_name = args.package_name or f"u74_formal_4x64_round0_seed4_{_now_utc_stamp()}"
    package_dir = args.package_root / package_name
    if package_dir.exists() and any(package_dir.iterdir()):
        raise FileExistsError(f"refusing to reuse non-empty package directory: {package_dir}")
    package_dir.mkdir(parents=True, exist_ok=True)
    round_dir = package_dir / ROUND_ID
    round_dir.mkdir(parents=True, exist_ok=True)

    source_tree = package_dir / "frozen_inputs" / "opensbi" / "source-tree"
    boot_artifacts_dir = package_dir / "frozen_inputs" / "boot-artifacts"
    _copy_tree(args.u74_opensbi_tree.resolve(), source_tree)
    _patch_opensbi_runner_for_formal(source_tree)
    boot_manifest = _copy_boot_artifacts(args.u74_boot_artifacts_dir.resolve(), boot_artifacts_dir)
    write_json(package_dir / "frozen_inputs" / "boot-artifacts-manifest.json", boot_manifest)

    schedule_entries, cases, lowered_cases = generate_round0_cases(seed=args.seed, count=args.case_count)
    write_json(round_dir / "schedule_round_0000.json", {"schema_version": 1, "entries": schedule_entries})
    _write_cases(round_dir, cases)

    capability = capability_for_dut("u74", available=True)
    universe, universe_path, exclusions_manifest, exclusions_path = _write_coverage_universe(
        package_dir,
        seed=args.seed,
        capability=capability,
    )
    capability_fingerprint = str(universe["capability_fingerprint"])
    universe_file_sha256 = _sha256_file(universe_path)
    exclusions_file_sha256 = _sha256_file(exclusions_path)
    metadata_path = _write_campaign_metadata(
        package_dir,
        campaign_id=args.campaign_id,
        seed=args.seed,
        capability=capability,
        capability_fingerprint=capability_fingerprint,
        universe=universe,
        universe_path=universe_path,
        universe_file_sha256=universe_file_sha256,
        exclusions_path=exclusions_path,
        exclusions_file_sha256=exclusions_file_sha256,
    )

    manifest_payload = _build_generated_manifest(
        campaign_id=args.campaign_id,
        round_id=ROUND_ID,
        seed=args.seed,
        cases=cases,
        lowered_cases=lowered_cases,
        capability_fingerprint=capability_fingerprint,
        universe=universe,
        universe_path=universe_path,
        universe_file_sha256=universe_file_sha256,
        exclusions_path=exclusions_path,
        exclusions_file_sha256=exclusions_file_sha256,
    )
    write_json(round_dir / "manifests" / "u74-generated-round-manifest.json", manifest_payload)

    build_args = argparse.Namespace(
        u74_opensbi_tree=source_tree,
        u74_boot_artifacts_dir=boot_artifacts_dir,
        remote_build_host=args.remote_build_host,
        remote_build_root=args.remote_build_root,
    )
    build_meta = u74_board_round._build_remote_fit(
        build_args,
        out_dir=round_dir,
        manifest_payload=manifest_payload,
    )
    board_patch_manifest = json.loads(build_meta["board_patch_manifest_json"])
    board_patch_manifest_path = Path(build_meta["board_patch_manifest_path"])
    write_json(board_patch_manifest_path, board_patch_manifest)
    fit_path = Path(build_meta["fit_path"])
    boot_chain_policy, boot_chain_policy_path = _write_boot_chain_policy(
        package_dir,
        evidence_path=args.boot_chain_evidence.resolve(),
        spl_image_path=args.boot_chain_spl_image.resolve(),
        fit_path=fit_path,
    )

    generated_c = source_tree / "platform" / "generic" / "starfive" / "pmpfuzz_board_generated_manifest.c"
    board_manifest_copy = round_dir / "manifests" / "board_manifest.c"
    board_manifest_copy.write_bytes(generated_c.read_bytes())

    source_manifest = _source_tree_manifest(source_tree)
    write_json(package_dir / "frozen_inputs" / "opensbi" / "source-tree-sha256.json", source_manifest)

    build_manifest = {
        "schema_version": 1,
        "campaign_id": args.campaign_id,
        "round_id": ROUND_ID,
        "controller_git_sha": controller_git_sha,
        "controller_status_porcelain": controller_status,
        "u74_opensbi_tree": str(source_tree),
        "u74_boot_artifacts_dir": str(boot_artifacts_dir),
        "source_tree_manifest": str(package_dir / "frozen_inputs" / "opensbi" / "source-tree-sha256.json"),
        "boot_artifacts_manifest": str(package_dir / "frozen_inputs" / "boot-artifacts-manifest.json"),
        "boot_chain_policy": str(boot_chain_policy_path),
        "boot_chain_policy_sha256": _sha256_file(boot_chain_policy_path),
        "generated_round_manifest": str(round_dir / "manifests" / "u74-generated-round-manifest.json"),
        "board_manifest_c": str(board_manifest_copy),
        "board_manifest_c_sha256": _sha256_file(board_manifest_copy),
        "board_patch_manifest": str(board_patch_manifest_path),
        "fit_path": str(fit_path),
        "fit_sha256": _sha256_file(fit_path),
        "fw_payload_path": str(build_meta["fw_payload_path"]),
        "fw_payload_sha256": _sha256_file(Path(build_meta["fw_payload_path"])),
        "remote_build_host": args.remote_build_host,
        "remote_build_root": build_meta["remote_build_root"],
    }
    write_json(round_dir / "manifests" / "u74-formal-round0-build-manifest.json", build_manifest)

    request = {
        "schema_version": 1,
        "request_kind": "u74-formal-4x64-round0-offline-package",
        "campaign_id": args.campaign_id,
        "round_id": ROUND_ID,
        "seed": args.seed,
        "round_count": 4,
        "cases_per_round": 64,
        "validator_profile": FORMAL_U74_BATCHED_VALIDATOR_PROFILE,
        "coverage_mode": "bapc",
        "target": BAPC_TARGET,
        "u74_supported_target_label": "u74-supported-bapc-core-v2",
        "dut": "u74",
        "controller_git_sha": controller_git_sha,
        "boot_chain_policy": str(boot_chain_policy_path),
        "boot_chain_policy_sha256": _sha256_file(boot_chain_policy_path),
        "p1_spl_sha256": str((boot_chain_policy.get("p1_spl") or {}).get("sha256") or ""),
        "p2_expected_fit_sha256": str((boot_chain_policy.get("p2_fit") or {}).get("expected_prefix_sha256") or ""),
        "board_action_state": "paused_pending_exact_sha_authorization",
        "round_generation_policy": "round1_to_round3_generated_after_green_feedback_only",
    }
    write_json(package_dir / "formal_campaign_request.json", request)

    preflight = run_preflight(
        package_dir,
        campaign_id=args.campaign_id,
        schedule_entries=schedule_entries,
        cases=cases,
        manifest_payload=manifest_payload,
        coverage_universe=universe,
        universe_path=universe_path,
        exclusions_manifest=exclusions_manifest,
        exclusions_path=exclusions_path,
        board_patch_manifest=board_patch_manifest,
        source_manifest=source_manifest,
        boot_chain_policy=boot_chain_policy,
        controller_status=controller_status,
        source_tree=source_tree,
        fit_path=fit_path,
    )
    write_json(package_dir / "round_0000_preflight_report.json", preflight)
    write_json(round_dir / "validator" / "u74_formal_round0_preflight_report.json", preflight)
    if preflight["error_count"] != 0:
        write_json(package_dir / "FAILED_PREFLIGHT_SUMMARY.json", preflight)
        raise RuntimeError(
            "formal Round 0 preflight failed: "
            + "; ".join(str(item) for item in preflight["errors"][:8])
        )

    summary = {
        "package_dir": str(package_dir),
        "round0_fit_sha256": build_manifest["fit_sha256"],
        "round0_fit_path": str(fit_path),
        "boot_chain_policy": str(boot_chain_policy_path),
        "boot_chain_policy_sha256": _sha256_file(boot_chain_policy_path),
        "p1_spl_sha256": str((boot_chain_policy.get("p1_spl") or {}).get("sha256") or ""),
        "preflight_report": str(package_dir / "round_0000_preflight_report.json"),
        "preflight_error_count": preflight["error_count"],
        "controller_git_sha": controller_git_sha,
    }
    _write_runbook(package_dir, fit_sha256=build_manifest["fit_sha256"])
    write_json(package_dir / "package_summary.json", summary)
    package_sha256, sha_path = _seal_package(package_dir)
    output_summary = {
        **summary,
        "package_sha256": package_sha256,
        "package_sha256_manifest": str(sha_path),
    }
    print(json.dumps(output_summary, indent=2, ensure_ascii=True, sort_keys=True))
    return output_summary


def _load_schedule_entries(schedule_path: Path) -> list[dict[str, Any]]:
    payload = _json_load(schedule_path)
    entries = payload.get("entries") if isinstance(payload, dict) else []
    return [dict(entry) for entry in (entries or []) if isinstance(entry, dict)]


def _round_index_from_path(path: Path) -> int:
    match = re.search(r"round[-_](\d+)", path.name)
    return int(match.group(1)) if match else 0


def _collect_prior_scenario_fingerprints(package_dir: Path, dynamic_root: Path, round_index: int) -> set[str]:
    fingerprints: set[str] = set()
    for root in (package_dir, dynamic_root):
        for prior_index in range(round_index):
            schedule_path = root / _round_id(prior_index) / _schedule_name(prior_index)
            if not schedule_path.exists():
                continue
            for entry in _load_schedule_entries(schedule_path):
                fingerprint = str(entry.get("scenario_fingerprint") or entry.get("scenario_hash") or "")
                if fingerprint:
                    fingerprints.add(fingerprint)
    return fingerprints


def _validate_previous_rounds_green(
    previous_round_dirs: list[Path],
    *,
    expected_campaign_id: str,
    next_round_index: int,
) -> None:
    if not previous_round_dirs:
        raise ValueError("prepare-next-round requires at least one real previous round directory")
    normalized = sorted({path.resolve(): path.resolve() for path in previous_round_dirs}.values(), key=_round_index_from_path)
    expected_indices = list(range(next_round_index))
    actual_indices = [_round_index_from_path(path) for path in normalized]
    if actual_indices != expected_indices:
        raise ValueError(f"previous round directories must cover {expected_indices}, got {actual_indices}")
    for round_dir in normalized:
        report_path = round_dir / "validator" / "report.json"
        if not report_path.exists():
            raise FileNotFoundError(f"missing previous round validator report: {report_path}")
        report = _json_load(report_path)
        profile = dict((report.get("profile_results") or {}).get(FORMAL_U74_BATCHED_VALIDATOR_PROFILE) or {})
        if str(report.get("campaign_id") or "") != expected_campaign_id:
            raise ValueError(f"previous round campaign_id mismatch in {report_path}")
        if "error_count" not in profile:
            raise ValueError(f"previous round formal validator is missing error_count: {report_path}")
        if profile.get("passed") is not True or int(profile["error_count"]) != 0:
            raise ValueError(f"previous round formal validator is not green: {report_path}")
        if int(report.get("scheduled_case_count") or -1) != 64:
            raise ValueError(f"previous round scheduled count is not 64: {report_path}")
        if int(report.get("executed_case_count") or -1) != 64:
            raise ValueError(f"previous round executed count is not 64: {report_path}")


def prepare_next_round(args: argparse.Namespace) -> dict[str, Any]:
    package_dir = args.package_dir.resolve()
    round_index = int(args.round_index)
    if round_index not in {1, 2, 3}:
        raise ValueError("prepare-next-round only supports round-index 1, 2, or 3")
    if not package_dir.exists():
        raise FileNotFoundError(f"missing Round 0 package: {package_dir}")

    request = _json_load(package_dir / "formal_campaign_request.json")
    metadata = _json_load(package_dir / "metrics" / "campaign_metadata.json")
    campaign_id = str(request.get("campaign_id") or metadata.get("campaign_id") or "")
    seed = int(request.get("seed") or metadata.get("seed") or 0)
    if seed != 4:
        raise ValueError(f"unexpected formal campaign seed: {seed}")
    if campaign_id != DEFAULT_CAMPAIGN_ID:
        raise ValueError(f"unexpected campaign id for formal U74 seed=4: {campaign_id}")

    dynamic_root = (args.output_root or (package_dir.parent / f"{package_dir.name}_dynamic_rounds")).resolve()
    round_dir = dynamic_root / _round_id(round_index)
    if round_dir.exists() and any(round_dir.iterdir()):
        raise FileExistsError(f"refusing to reuse non-empty next-round directory: {round_dir}")
    round_dir.mkdir(parents=True, exist_ok=True)

    previous_round_dirs = [path.resolve() for path in (args.previous_round_dir or [])]
    _validate_previous_rounds_green(
        previous_round_dirs,
        expected_campaign_id=campaign_id,
        next_round_index=round_index,
    )
    feedback_state = build_u74_campaign_feedback_state(previous_round_dirs, dut="u74")
    prior_fingerprints = _collect_prior_scenario_fingerprints(package_dir, dynamic_root, round_index)
    schedule_entries, cases, lowered_cases = generate_round_cases(
        seed=seed,
        round_index=round_index,
        count=64,
        exclude_fingerprints=prior_fingerprints,
        feedback_state=feedback_state,
    )
    write_json(round_dir / _schedule_name(round_index), {"schema_version": 1, "entries": schedule_entries})
    _write_cases(round_dir, cases)

    universe_path = Path(str((metadata.get("coverage_universe_files") or {}).get("bapc") or ""))
    if not universe_path.is_absolute():
        universe_path = package_dir / universe_path
    universe = _json_load(universe_path)
    validate_bapc_coverage_universe(universe)
    identity = dict(metadata.get("u74_round_identity") or {})
    exclusions_path = Path(str(identity.get("supported_bapc_exclusions_file") or ""))
    if not exclusions_path.is_absolute():
        exclusions_path = package_dir / exclusions_path
    exclusions_manifest = _json_load(exclusions_path)
    universe_file_sha256 = _sha256_file(universe_path)
    exclusions_file_sha256 = _sha256_file(exclusions_path)
    capability_fingerprint = str(universe["capability_fingerprint"])

    source_tree = round_dir / "opensbi-source-tree"
    _copy_tree(package_dir / "frozen_inputs" / "opensbi" / "source-tree", source_tree)
    _patch_opensbi_runner_for_formal(source_tree)
    boot_artifacts_dir = package_dir / "frozen_inputs" / "boot-artifacts"

    manifest_payload = _build_generated_manifest(
        campaign_id=campaign_id,
        round_id=_round_id(round_index),
        seed=seed,
        cases=cases,
        lowered_cases=lowered_cases,
        capability_fingerprint=capability_fingerprint,
        universe=universe,
        universe_path=universe_path,
        universe_file_sha256=universe_file_sha256,
        exclusions_path=exclusions_path,
        exclusions_file_sha256=exclusions_file_sha256,
    )
    write_json(round_dir / "manifests" / "u74-generated-round-manifest.json", manifest_payload)

    build_args = argparse.Namespace(
        u74_opensbi_tree=source_tree,
        u74_boot_artifacts_dir=boot_artifacts_dir,
        remote_build_host=args.remote_build_host,
        remote_build_root=args.remote_build_root,
    )
    build_meta = u74_board_round._build_remote_fit(
        build_args,
        out_dir=round_dir,
        manifest_payload=manifest_payload,
    )
    board_patch_manifest = json.loads(build_meta["board_patch_manifest_json"])
    board_patch_manifest_path = Path(build_meta["board_patch_manifest_path"])
    write_json(board_patch_manifest_path, board_patch_manifest)
    fit_path = Path(build_meta["fit_path"])
    base_boot_chain_policy_path = package_dir / "frozen_inputs" / "board" / "u74-sdio3-boot-chain-policy.json"
    base_boot_chain_policy = _json_load(base_boot_chain_policy_path)
    boot_chain_policy = bind_boot_chain_policy_to_fit(
        base_boot_chain_policy,
        expected_fit_sha256=_sha256_file(fit_path),
        expected_fit_bytes=fit_path.stat().st_size,
    )
    boot_chain_policy_path = round_dir / "manifests" / f"u74-formal-round{round_index}-boot-chain-policy.json"
    write_json(boot_chain_policy_path, boot_chain_policy)

    generated_c = source_tree / "platform" / "generic" / "starfive" / "pmpfuzz_board_generated_manifest.c"
    board_manifest_copy = round_dir / "manifests" / "board_manifest.c"
    board_manifest_copy.write_bytes(generated_c.read_bytes())
    source_manifest = _source_tree_manifest(source_tree)
    source_manifest_path = round_dir / "manifests" / "opensbi-source-tree-sha256.json"
    write_json(source_manifest_path, source_manifest)
    build_manifest = {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "round_id": _round_id(round_index),
        "u74_opensbi_tree": str(source_tree),
        "u74_boot_artifacts_dir": str(boot_artifacts_dir),
        "source_tree_manifest": str(source_manifest_path),
        "boot_chain_policy": str(boot_chain_policy_path),
        "boot_chain_policy_sha256": _sha256_file(boot_chain_policy_path),
        "generated_round_manifest": str(round_dir / "manifests" / "u74-generated-round-manifest.json"),
        "board_manifest_c": str(board_manifest_copy),
        "board_manifest_c_sha256": _sha256_file(board_manifest_copy),
        "board_patch_manifest": str(board_patch_manifest_path),
        "fit_path": str(fit_path),
        "fit_sha256": _sha256_file(fit_path),
        "fw_payload_path": str(build_meta["fw_payload_path"]),
        "fw_payload_sha256": _sha256_file(Path(build_meta["fw_payload_path"])),
        "previous_round_dirs": [str(path) for path in previous_round_dirs],
        "previous_coverage_hash": str(feedback_state.get("coverage_hash") or ""),
        "remote_build_host": args.remote_build_host,
        "remote_build_root": build_meta["remote_build_root"],
    }
    write_json(round_dir / "manifests" / f"u74-formal-round{round_index}-build-manifest.json", build_manifest)

    preflight = run_preflight(
        package_dir=dynamic_root,
        campaign_id=campaign_id,
        schedule_entries=schedule_entries,
        cases=cases,
        manifest_payload=manifest_payload,
        coverage_universe=universe,
        universe_path=universe_path,
        exclusions_manifest=exclusions_manifest,
        exclusions_path=exclusions_path,
        board_patch_manifest=board_patch_manifest,
        source_manifest=source_manifest,
        boot_chain_policy=boot_chain_policy,
        controller_status=_git_status(Path(__file__).resolve().parents[4]),
        source_tree=source_tree,
        fit_path=fit_path,
    )
    write_json(round_dir / "validator" / f"u74_formal_round{round_index}_preflight_report.json", preflight)
    if preflight["error_count"] != 0:
        write_json(round_dir / "FAILED_PREFLIGHT_SUMMARY.json", preflight)
        raise RuntimeError(
            f"formal Round {round_index} preflight failed: "
            + "; ".join(str(item) for item in preflight["errors"][:8])
        )

    output_summary = {
        "round_index": round_index,
        "round_dir": str(round_dir),
        "fit_path": str(fit_path),
        "fit_sha256": build_manifest["fit_sha256"],
        "schedule": str(round_dir / _schedule_name(round_index)),
        "preflight_report": str(round_dir / "validator" / f"u74_formal_round{round_index}_preflight_report.json"),
        "previous_coverage_hash": str(feedback_state.get("coverage_hash") or ""),
    }
    write_json(round_dir / "round_summary.json", output_summary)
    print(json.dumps(output_summary, indent=2, ensure_ascii=True, sort_keys=True))
    return output_summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare real U74 formal 4x64 campaign rounds")
    parser.add_argument("command", nargs="?", default="prepare-round0", choices=("prepare-round0", "prepare-next-round"))
    parser.add_argument("--package-root", type=Path, default=DEFAULT_PACKAGE_ROOT)
    parser.add_argument("--package-name", default="")
    parser.add_argument("--package-dir", type=Path, default=None)
    parser.add_argument("--output-root", type=Path, default=None)
    parser.add_argument("--campaign-id", default=DEFAULT_CAMPAIGN_ID)
    parser.add_argument("--seed", type=int, default=4)
    parser.add_argument("--case-count", type=int, default=64)
    parser.add_argument("--round-index", type=int, default=0)
    parser.add_argument("--previous-round-dir", type=Path, action="append", default=[])
    parser.add_argument("--u74-opensbi-tree", type=Path, default=u74_board_round.DEFAULT_U74_OPEN_SBI_TREE)
    parser.add_argument("--u74-boot-artifacts-dir", type=Path, default=u74_board_round.DEFAULT_U74_BOOT_ARTIFACTS_DIR)
    parser.add_argument("--boot-chain-evidence", type=Path, default=None)
    parser.add_argument("--boot-chain-spl-image", type=Path, default=None)
    parser.add_argument("--remote-build-host", default=u74_board_round.DEFAULT_U74_REMOTE_BUILD_HOST)
    parser.add_argument("--remote-build-root", default=u74_board_round.DEFAULT_U74_REMOTE_BUILD_ROOT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "prepare-next-round":
        if args.package_dir is None:
            raise ValueError("prepare-next-round requires --package-dir")
        prepare_next_round(args)
    else:
        prepare_round0(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
