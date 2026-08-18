from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any, Iterable

from .bapc import build_bapc_coverage_universe, map_bapc_normalized_record


OFF_STATE_SCHEMA_VERSION = 1
OFF_STATE_PLAN_SCHEMA_VERSION = 1
OFF_STATE_RECORD_SCHEMA_VERSION = 1
OFF_STATE_RAW_UNIVERSE_SCHEMA_VERSION = 1
OFF_STATE_PLAN_KIND = "pmp-off-state-plan-v1"
OFF_STATE_ARTIFACT_KIND = "pmp-off-state-characterization-v1"
OFF_STATE_ANALYSIS_KIND = "pmp-off-state-analysis-v1"
OFF_STATE_RAW_MAPPER_VERSION = "pmpcfg-raw-v1"
OFF_STATE_RAW_UNIVERSE_RULE_VERSION = "pmp-off-state-raw-universe-v1"
OFF_STATE_PROFILES = ("base-pmp", "smepmp-mml0", "smepmp-mml1")
OFF_STATE_SUBEXPERIMENTS = ("readback", "lock", "behavior")
SPEC_STATUSES = ("spec-defined", "spec-reserved", "profile-dependent", "not-applicable")
WRITE_OUTCOMES = ("accepted", "ignored", "trap")
READBACK_RELATIONS = ("exact", "canonicalized", "hardwired", "unstable")
LOCK_EFFECTS = ("blocked", "not-blocked", "inconclusive")
PROBE_RESULTS = ("expected-nonmatch", "unexpected-match", "inconclusive")
EXECUTION_STATUSES = ("completed", "unsupported", "inconclusive", "harness-error")
UNSUPPORTED_PROFILE_REASONS = (
    "csr_trap",
    "field_read_only_zero",
    "bootrom_preconfigured",
    "sticky_field_cannot_be_changed",
    "pmp_not_implemented",
    "other",
)
_JSON_DUMPS_KWARGS = {
    "sort_keys": True,
    "ensure_ascii": True,
    "allow_nan": False,
    "separators": (",", ":"),
}


@dataclass(frozen=True)
class OffStateEncoding:
    l: int
    r: int
    w: int
    x: int

    def as_dict(self) -> dict[str, int]:
        return {"l": self.l, "r": self.r, "w": self.w, "x": self.x}

    def cfg_byte(self) -> int:
        value = 0
        value |= 0x80 if self.l else 0
        value |= 0x01 if self.r else 0
        value |= 0x02 if self.w else 0
        value |= 0x04 if self.x else 0
        return value


def off_state_encodings() -> list[OffStateEncoding]:
    return [
        OffStateEncoding(l=l, r=r, w=w, x=x)
        for l in (0, 1)
        for r in (0, 1)
        for w in (0, 1)
        for x in (0, 1)
    ]


def normalize_profile(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in OFF_STATE_PROFILES:
        return text
    raise ValueError(f"unsupported OFF-state profile {value!r}")


def normalize_subexperiment(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in OFF_STATE_SUBEXPERIMENTS:
        return text
    raise ValueError(f"unsupported OFF-state subexperiment {value!r}")


def normalize_execution_status(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in EXECUTION_STATUSES:
        return text
    raise ValueError(f"unsupported OFF-state execution_status {value!r}")


def normalize_bits(bits: dict[str, Any]) -> dict[str, int]:
    normalized: dict[str, int] = {}
    for name in ("l", "r", "w", "x"):
        if name not in bits:
            raise ValueError(f"missing OFF-state bit {name!r}")
        raw = bits[name]
        if raw in (True, False):
            normalized[name] = int(raw)
        else:
            normalized[name] = int(raw)
        if normalized[name] not in (0, 1):
            raise ValueError(f"OFF-state bit {name!r} must be 0/1, got {raw!r}")
    return normalized


def spec_status_for_off_state(profile: str, bits: dict[str, Any]) -> str:
    normalized_profile = normalize_profile(profile)
    normalized_bits = normalize_bits(bits)
    if normalized_profile in {"base-pmp", "smepmp-mml0"}:
        if normalized_bits["r"] == 0 and normalized_bits["w"] == 1:
            return "spec-reserved"
        return "spec-defined"
    return "profile-dependent"


def raw_state_bin_id(profile: str, bits: dict[str, Any]) -> str:
    normalized_profile = normalize_profile(profile)
    normalized_bits = normalize_bits(bits)
    return (
        f"{OFF_STATE_RAW_MAPPER_VERSION}|profile={normalized_profile}|a=off"
        f"|l={normalized_bits['l']}|r={normalized_bits['r']}|w={normalized_bits['w']}|x={normalized_bits['x']}"
    )


def build_spec_encoding_sets(
    profiles: Iterable[str] = OFF_STATE_PROFILES,
) -> dict[str, dict[str, list[str]]]:
    result: dict[str, dict[str, list[str]]] = {}
    for raw_profile in profiles:
        profile = normalize_profile(raw_profile)
        by_status = {status: [] for status in SPEC_STATUSES}
        for encoding in off_state_encodings():
            status = spec_status_for_off_state(profile, encoding.as_dict())
            by_status[status].append(raw_state_bin_id(profile, encoding.as_dict()))
        for status in SPEC_STATUSES:
            by_status[status] = sorted(by_status[status])
        result[profile] = by_status
    return result


def raw_state_universe_bin_set_sha256(bin_ids: Iterable[str]) -> str:
    normalized_bins = sorted({str(item) for item in bin_ids})
    raw = json.dumps(normalized_bins, **_JSON_DUMPS_KWARGS).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def build_raw_state_universe(profile: str) -> dict[str, Any]:
    normalized_profile = normalize_profile(profile)
    bin_ids = [raw_state_bin_id(normalized_profile, item.as_dict()) for item in off_state_encodings()]
    payload = {
        "schema_version": OFF_STATE_RAW_UNIVERSE_SCHEMA_VERSION,
        "artifact_kind": OFF_STATE_RAW_MAPPER_VERSION,
        "profile": normalized_profile,
        "address_mode": "off",
        "generation_rule_version": OFF_STATE_RAW_UNIVERSE_RULE_VERSION,
        "bin_ids": bin_ids,
        "bin_count": len(bin_ids),
        "bin_set_sha256": raw_state_universe_bin_set_sha256(bin_ids),
    }
    payload["sha256"] = _sha256_without_self_hash(payload)
    return payload


def validate_raw_state_universe(universe: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(universe, dict):
        raise TypeError(f"raw state universe must be a dict, got {type(universe).__name__}")
    if int(universe.get("schema_version") or -1) != OFF_STATE_RAW_UNIVERSE_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported raw state universe schema_version {universe.get('schema_version')!r}; "
            f"expected {OFF_STATE_RAW_UNIVERSE_SCHEMA_VERSION}"
        )
    if str(universe.get("artifact_kind") or "") != OFF_STATE_RAW_MAPPER_VERSION:
        raise ValueError(
            f"unsupported raw state universe artifact_kind {universe.get('artifact_kind')!r}; "
            f"expected {OFF_STATE_RAW_MAPPER_VERSION!r}"
        )
    profile = normalize_profile(universe.get("profile"))
    if str(universe.get("generation_rule_version") or "") != OFF_STATE_RAW_UNIVERSE_RULE_VERSION:
        raise ValueError(
            "unsupported raw state universe generation_rule_version "
            f"{universe.get('generation_rule_version')!r}"
        )
    bin_ids = universe.get("bin_ids")
    if not isinstance(bin_ids, list) or any(type(item) is not str for item in bin_ids):
        raise ValueError("raw state universe bin_ids must be a list[str]")
    expected_bins = [raw_state_bin_id(profile, item.as_dict()) for item in off_state_encodings()]
    if bin_ids != expected_bins:
        raise ValueError("raw state universe bin_ids must equal the canonical 16 OFF-state bins")
    if int(universe.get("bin_count") or -1) != 16:
        raise ValueError("raw state universe bin_count must be 16")
    actual_set_hash = raw_state_universe_bin_set_sha256(bin_ids)
    if str(universe.get("bin_set_sha256") or "") != actual_set_hash:
        raise ValueError(
            "raw state universe bin_set_sha256 mismatch: "
            f"expected {universe.get('bin_set_sha256')}, got {actual_set_hash}"
        )
    actual_hash = _sha256_without_self_hash(universe)
    if str(universe.get("sha256") or "") != actual_hash:
        raise ValueError(
            f"raw state universe sha256 mismatch: expected {universe.get('sha256')}, got {actual_hash}"
        )
    return universe


def build_characterization_plan(
    *,
    dut: str,
    profiles: Iterable[str],
    entry_indices: Iterable[int],
    reset_count: int,
) -> dict[str, Any]:
    profile_list = [normalize_profile(item) for item in profiles]
    index_list = [int(item) for item in entry_indices]
    if reset_count <= 0:
        raise ValueError("reset_count must be positive")
    main_cases: list[dict[str, Any]] = []
    lock_control_cases: list[dict[str, Any]] = []
    for profile in profile_list:
        for entry_index in index_list:
            for reset_index in range(reset_count):
                reset_id = f"reset-{reset_index:03d}"
                lock_control_cases.append(
                    {
                        "dut": str(dut),
                        "profile_requested": profile,
                        "entry_index": entry_index,
                        "reset_id": reset_id,
                        "subexperiment": "lock",
                        "control_kind": "lock-positive-control",
                        "control_pmp_mode": "napot",
                        "requested_bits": {"l": 1, "r": 1, "w": 0, "x": 0},
                    }
                )
                for subexperiment in OFF_STATE_SUBEXPERIMENTS:
                    for encoding in off_state_encodings():
                        main_cases.append(
                            {
                                "dut": str(dut),
                                "profile_requested": profile,
                                "entry_index": entry_index,
                                "reset_id": reset_id,
                                "subexperiment": subexperiment,
                                "requested_bits": encoding.as_dict(),
                                "spec_status": spec_status_for_off_state(profile, encoding.as_dict()),
                            }
                        )
    return {
        "schema_version": OFF_STATE_PLAN_SCHEMA_VERSION,
        "artifact_kind": OFF_STATE_PLAN_KIND,
        "dut": str(dut),
        "profiles": profile_list,
        "entry_indices": index_list,
        "reset_count": int(reset_count),
        "record_schema_version": OFF_STATE_RECORD_SCHEMA_VERSION,
        "main_cases": main_cases,
        "lock_control_cases": lock_control_cases,
    }


def derive_readback_relation(
    *,
    requested_bits: dict[str, Any],
    readback_bits_1: dict[str, Any],
    readback_bits_2: dict[str, Any],
    write_outcome: str,
) -> str:
    requested = normalize_bits(requested_bits)
    first = normalize_bits(readback_bits_1)
    second = normalize_bits(readback_bits_2)
    outcome = str(write_outcome or "").strip().lower()
    if first != second:
        return "unstable"
    if first == requested:
        return "exact"
    if outcome == "ignored":
        return "hardwired"
    return "canonicalized"


def validate_characterization_record(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if int(record.get("record_schema_version") or -1) != OFF_STATE_RECORD_SCHEMA_VERSION:
        errors.append(
            f"unsupported record_schema_version {record.get('record_schema_version')!r}; "
            f"expected {OFF_STATE_RECORD_SCHEMA_VERSION}"
        )
    required_common = (
        "dut",
        "profile_requested",
        "profile_observed",
        "entry_index",
        "reset_id",
        "subexperiment",
        "requested_bits",
        "spec_status",
        "execution_status",
    )
    for field in required_common:
        if field not in record:
            errors.append(f"missing field {field}")
    if errors:
        return errors
    try:
        requested_profile = normalize_profile(record["profile_requested"])
    except ValueError as exc:
        errors.append(str(exc))
        requested_profile = "base-pmp"
    try:
        observed_profile = normalize_profile(record["profile_observed"])
    except ValueError as exc:
        errors.append(str(exc))
        observed_profile = requested_profile
    try:
        execution_status = normalize_execution_status(record["execution_status"])
    except ValueError as exc:
        errors.append(str(exc))
        execution_status = "harness-error"
    if execution_status == "completed" and observed_profile != requested_profile:
        errors.append(
            f"profile_observed mismatch: expected {requested_profile}, got {observed_profile}"
        )
    try:
        subexperiment = normalize_subexperiment(record["subexperiment"])
    except ValueError as exc:
        errors.append(str(exc))
        subexperiment = "readback"
    try:
        requested_bits = normalize_bits(record["requested_bits"])
    except ValueError as exc:
        errors.append(str(exc))
        requested_bits = {"l": 0, "r": 0, "w": 0, "x": 0}
    expected_status = spec_status_for_off_state(requested_profile, requested_bits)
    if str(record.get("spec_status") or "") != expected_status:
        errors.append(
            f"spec_status mismatch: expected {expected_status}, got {record.get('spec_status')!r}"
        )
    reason = record.get("unsupported_profile_reason")
    if execution_status == "unsupported":
        if reason is None:
            errors.append("unsupported record requires unsupported_profile_reason")
        elif str(reason) not in UNSUPPORTED_PROFILE_REASONS:
            errors.append(f"invalid unsupported_profile_reason {reason!r}")
    elif reason is not None:
        errors.append("unsupported_profile_reason is only valid for execution_status=unsupported")

    completed = execution_status == "completed"
    if subexperiment == "readback":
        readback_fields = ("write_outcome", "readback_relation", "readback_bits_1", "readback_bits_2")
        for field in readback_fields:
            if completed and field not in record:
                errors.append(f"missing field {field}")
        if completed or "write_outcome" in record:
            if str(record.get("write_outcome") or "") not in WRITE_OUTCOMES:
                errors.append(f"invalid write_outcome {record.get('write_outcome')!r}")
        relation = str(record.get("readback_relation") or "")
        if completed or "readback_relation" in record:
            if relation not in READBACK_RELATIONS:
                errors.append(f"invalid readback_relation {relation!r}")
            elif completed and relation == "unstable":
                errors.append("completed readback record cannot be unstable")
        if all(field in record for field in readback_fields) and relation in READBACK_RELATIONS:
            try:
                expected_relation = derive_readback_relation(
                    requested_bits=requested_bits,
                    readback_bits_1=record["readback_bits_1"],
                    readback_bits_2=record["readback_bits_2"],
                    write_outcome=str(record.get("write_outcome") or ""),
                )
                if relation != expected_relation:
                    errors.append(
                        f"readback_relation mismatch: expected {expected_relation}, got {relation!r}"
                    )
            except ValueError as exc:
                errors.append(str(exc))
    elif subexperiment == "lock":
        for field in ("cfg_lock_effect", "addr_lock_effect"):
            if completed and field not in record:
                errors.append(f"missing field {field}")
        if completed or "cfg_lock_effect" in record:
            if str(record.get("cfg_lock_effect") or "") not in LOCK_EFFECTS:
                errors.append(f"invalid cfg_lock_effect {record.get('cfg_lock_effect')!r}")
        if completed or "addr_lock_effect" in record:
            if str(record.get("addr_lock_effect") or "") not in LOCK_EFFECTS:
                errors.append(f"invalid addr_lock_effect {record.get('addr_lock_effect')!r}")
    elif subexperiment == "behavior":
        behavior_fields = (
            "probe_result",
            "access",
            "size",
            "current_privilege",
            "effective_privilege",
            "exception_cause",
            "fault_address",
            "matched_control_case",
        )
        for field in behavior_fields:
            if completed and field not in record:
                errors.append(f"missing field {field}")
        if completed or "probe_result" in record:
            if str(record.get("probe_result") or "") not in PROBE_RESULTS:
                errors.append(f"invalid probe_result {record.get('probe_result')!r}")
        if completed or "size" in record:
            try:
                if int(record.get("size") or 0) <= 0:
                    errors.append("behavior size must be positive")
            except (TypeError, ValueError):
                errors.append(f"invalid behavior size {record.get('size')!r}")
    return errors


def is_stable_readback_record(record: dict[str, Any]) -> bool:
    if str(record.get("execution_status") or "") != "completed":
        return False
    if str(record.get("subexperiment") or "") != "readback":
        return False
    if str(record.get("readback_relation") or "") == "unstable":
        return False
    try:
        first = normalize_bits(record["readback_bits_1"])
        second = normalize_bits(record["readback_bits_2"])
    except Exception:
        return False
    return first == second


def load_records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    payload = json.loads(text)
    if isinstance(payload, list):
        return [dict(item) for item in payload]
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        return [dict(item) for item in payload["records"]]
    raise ValueError(f"unsupported OFF-state input payload in {path}")


def append_characterization_records(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded_lines: list[str] = []
    for index, record in enumerate(records):
        item = dict(record)
        errors = validate_characterization_record(item)
        if errors:
            raise ValueError(f"append record[{index}] invalid: {'; '.join(errors)}")
        encoded_lines.append(json.dumps(item, **_JSON_DUMPS_KWARGS))
    with path.open("a", encoding="ascii", newline="\n") as handle:
        for line in encoded_lines:
            handle.write(line)
            handle.write("\n")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="ascii")


def capture_repo_metadata(repo_root: Path, *, argv: Iterable[str] | None = None) -> dict[str, Any]:
    return {
        "source_git_sha": _git_output(repo_root, "rev-parse", "HEAD"),
        "source_git_status": _git_output(repo_root, "status", "--short"),
        "experiment_branch": _git_output(repo_root, "branch", "--show-current"),
        "command_line": list(argv or ()),
        "environment_metadata": {
            "repo_root": str(repo_root.resolve()),
        },
    }


def enrich_metadata(
    metadata: dict[str, Any],
    *,
    dut_binary: Path | None = None,
    firmware_payload: Path | None = None,
    simulator_version: str | None = None,
    isa_configuration: str | None = None,
    xlen: int | None = None,
    pmp_entry_count: int | None = None,
    pmp_grain: int | None = None,
    reset_method: str | None = None,
) -> dict[str, Any]:
    enriched = dict(metadata)
    if dut_binary is not None:
        enriched["dut_binary_sha256"] = sha256_file(dut_binary)
    if firmware_payload is not None:
        enriched["firmware_payload_sha256"] = sha256_file(firmware_payload)
    if simulator_version is not None:
        enriched["simulator_version"] = str(simulator_version)
    if isa_configuration is not None:
        enriched["isa_profile_configuration"] = str(isa_configuration)
    if xlen is not None:
        enriched["xlen"] = int(xlen)
    if pmp_entry_count is not None:
        enriched["pmp_entry_count"] = int(pmp_entry_count)
    if pmp_grain is not None:
        enriched["pmp_grain"] = int(pmp_grain)
    if reset_method is not None:
        enriched["reset_method"] = str(reset_method)
    return enriched


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_mapper_replay(
    record: dict[str, Any],
    *,
    bapc_core_version: str,
) -> dict[str, Any]:
    normalized_record = dict(record["normalized_record"])
    observed = map_bapc_normalized_record(normalized_record, bapc_core_version=bapc_core_version)
    replayed = map_bapc_normalized_record(normalized_record, bapc_core_version=bapc_core_version)
    universe = build_bapc_coverage_universe(
        dut=str(record.get("dut") or "unknown"),
        generator_seed=1,
        supports_fault_stage=bool(record.get("supports_fault_stage", True)),
        supports_smepmp=bool(record.get("supports_smepmp", False)),
        bapc_core_version=bapc_core_version,
    )
    universe_bins = set(universe["bin_ids"])
    observed_bins = [str(item) for item in observed.get("observed_bins") or []]
    replayed_bins = [str(item) for item in replayed.get("observed_bins") or []]
    return {
        "bapc_core_version": str(bapc_core_version),
        "raw_trace_sha256": str(record.get("raw_trace_sha256") or ""),
        "eligible": bool(observed.get("eligible")),
        "observed_bins": observed_bins,
        "repeat_observed_bins": replayed_bins,
        "replay_equal": observed_bins == replayed_bins and bool(observed.get("eligible")) == bool(replayed.get("eligible")),
        "in_universe": set(observed_bins).issubset(universe_bins),
        "universe_hash": str(universe.get("sha256") or ""),
    }


def analyze_characterization_records(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    normalized_records = [dict(item) for item in records]
    errors: list[str] = []
    for index, record in enumerate(normalized_records):
        for item in validate_characterization_record(record):
            errors.append(f"record[{index}]: {item}")
    if errors:
        raise ValueError("\n".join(errors))

    spec_sets = build_spec_encoding_sets()
    requested_raw_vocabularies = {
        profile: build_raw_state_universe(profile)
        for profile in spec_sets
    }
    requested_raw_set = {
        profile: list(manifest["bin_ids"])
        for profile, manifest in requested_raw_vocabularies.items()
    }
    spec_defined_set = {
        profile: list(groups["spec-defined"])
        for profile, groups in spec_sets.items()
    }
    stable_readback_set: dict[str, dict[str, dict[str, list[str]]]] = {}
    state_signatures: dict[str, dict[str, Any]] = {}
    mapper_validations: list[dict[str, Any]] = []
    mapper_witness_set = {"v2": set(), "v3": set()}
    execution_status_counts = {status: 0 for status in EXECUTION_STATUSES}

    for record in normalized_records:
        execution_status = normalize_execution_status(record["execution_status"])
        execution_status_counts[execution_status] += 1
        if execution_status != "completed":
            continue
        dut = str(record["dut"])
        requested_profile = normalize_profile(record["profile_requested"])
        observed_profile = normalize_profile(record["profile_observed"])
        entry_key = str(int(record["entry_index"]))
        requested_bin = raw_state_bin_id(requested_profile, record["requested_bits"])
        state_key = f"{dut}|{observed_profile}|entry={entry_key}|requested={requested_bin}"
        signature = state_signatures.setdefault(
            state_key,
            {
                "readback_bin": None,
                "cfg_lock_effects": set(),
                "addr_lock_effects": set(),
                "behaviors": set(),
            },
        )

        if is_stable_readback_record(record):
            readback_bin = raw_state_bin_id(observed_profile, record["readback_bits_2"])
            signature["readback_bin"] = readback_bin
            dut_profile = stable_readback_set.setdefault(dut, {}).setdefault(observed_profile, {}).setdefault(entry_key, [])
            if readback_bin not in dut_profile:
                dut_profile.append(readback_bin)

        subexperiment = normalize_subexperiment(record["subexperiment"])
        if subexperiment == "lock":
            signature["cfg_lock_effects"].add(str(record["cfg_lock_effect"]))
            signature["addr_lock_effects"].add(str(record["addr_lock_effect"]))
        elif subexperiment == "behavior":
            signature["behaviors"].add(
                (
                    str(record["access"]),
                    int(record["size"]),
                    str(record["current_privilege"]),
                    str(record["effective_privilege"]),
                    str(record["probe_result"]),
                    str(record["exception_cause"]),
                )
            )
        if "normalized_record" in record:
            for core_version in ("v2", "v3"):
                replay = build_mapper_replay(record, bapc_core_version=core_version)
                if not replay["replay_equal"]:
                    raise ValueError(
                        f"mapper replay mismatch for {core_version} trace {replay['raw_trace_sha256']}"
                    )
                if not replay["in_universe"]:
                    raise ValueError(
                        f"mapper produced out-of-universe bins for {core_version} trace {replay['raw_trace_sha256']}"
                    )
                mapper_validations.append(replay)
                if replay["eligible"]:
                    mapper_witness_set[core_version].update(replay["observed_bins"])

    behavioral_classes: dict[tuple[Any, ...], list[str]] = {}
    for state_key, signature in state_signatures.items():
        signature_key = (
            signature["readback_bin"],
            tuple(sorted(signature["cfg_lock_effects"])),
            tuple(sorted(signature["addr_lock_effects"])),
            tuple(sorted(signature["behaviors"])),
        )
        behavioral_classes.setdefault(signature_key, []).append(state_key)
    behavioral_equivalence_set = [
        {
            "class_id": f"behavior-class-{index:03d}",
            "members": sorted(members),
            "signature": {
                "readback_bin": signature_key[0],
                "cfg_lock_effects": list(signature_key[1]),
                "addr_lock_effects": list(signature_key[2]),
                "behaviors": [list(item) for item in signature_key[3]],
            },
        }
        for index, (signature_key, members) in enumerate(sorted(behavioral_classes.items(), key=lambda item: repr(item[0])))
    ]

    universe_candidates = {
        "bapc_core_v3_semantic_universe": sorted(mapper_witness_set["v3"]),
        "base_pmp_raw_state_candidate": sorted(
            {
                item
                for profile_sets in stable_readback_set.values()
                for item in profile_sets.get("base-pmp", {}).get("0", [])
            }
        ),
        "smepmp_mml0_raw_state_candidate": sorted(
            {
                item
                for profile_sets in stable_readback_set.values()
                for entry_bins in profile_sets.get("smepmp-mml0", {}).values()
                for item in entry_bins
            }
        ),
        "smepmp_mml1_raw_state_candidate": sorted(
            {
                item
                for profile_sets in stable_readback_set.values()
                for entry_bins in profile_sets.get("smepmp-mml1", {}).values()
                for item in entry_bins
            }
        ),
        "per_dut_observed_subset": stable_readback_set,
        "behavioral_equivalence_candidate": behavioral_equivalence_set,
    }

    for profile_sets in stable_readback_set.values():
        for entry_sets in profile_sets.values():
            for entry_key, values in entry_sets.items():
                entry_sets[entry_key] = sorted(values)

    return {
        "schema_version": OFF_STATE_SCHEMA_VERSION,
        "artifact_kind": OFF_STATE_ANALYSIS_KIND,
        "raw_mapper_version": OFF_STATE_RAW_MAPPER_VERSION,
        "record_schema_version": OFF_STATE_RECORD_SCHEMA_VERSION,
        "record_count": len(normalized_records),
        "execution_status_counts": execution_status_counts,
        "spec_encoding_sets": spec_sets,
        "requested_raw_vocabularies": requested_raw_vocabularies,
        "requested_raw_set": requested_raw_set,
        "spec_defined_set": spec_defined_set,
        "stable_readback_set": stable_readback_set,
        "mapper_validations": mapper_validations,
        "mapper_witness_set": {
            "v2": sorted(mapper_witness_set["v2"]),
            "v3": sorted(mapper_witness_set["v3"]),
        },
        "behavioral_equivalence_set": behavioral_equivalence_set,
        "universe_candidates": universe_candidates,
    }


def analyze_characterization_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(artifact, dict):
        raise TypeError(f"characterization artifact must be a dict, got {type(artifact).__name__}")
    if int(artifact.get("schema_version") or -1) != OFF_STATE_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported characterization schema_version {artifact.get('schema_version')!r}; "
            f"expected {OFF_STATE_SCHEMA_VERSION}"
        )
    if str(artifact.get("artifact_kind") or "") != OFF_STATE_ARTIFACT_KIND:
        raise ValueError(
            f"unsupported characterization artifact_kind {artifact.get('artifact_kind')!r}; "
            f"expected {OFF_STATE_ARTIFACT_KIND!r}"
        )
    if int(artifact.get("record_schema_version") or -1) != OFF_STATE_RECORD_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported characterization record_schema_version {artifact.get('record_schema_version')!r}; "
            f"expected {OFF_STATE_RECORD_SCHEMA_VERSION}"
        )
    reset_count = int(artifact.get("reset_count") or 0)
    if reset_count <= 0:
        raise ValueError("characterization artifact reset_count must be positive")
    records = [dict(item) for item in (artifact.get("records") or [])]
    reset_evidence: dict[tuple[str, str, int, str], set[str]] = {}
    for index, record in enumerate(records):
        requested_profile = normalize_profile(record.get("profile_requested"))
        requested_bits = normalize_bits(record.get("requested_bits") or {})
        key = (
            str(record.get("dut") or ""),
            requested_profile,
            int(record.get("entry_index") or 0),
            raw_state_bin_id(requested_profile, requested_bits),
        )
        reset_evidence.setdefault(key, set()).add(str(record.get("reset_id") or f"missing-{index}"))
    for key, reset_ids in reset_evidence.items():
        if len(reset_ids) < reset_count:
            dut, profile, entry_index, raw_bin = key
            raise ValueError(
                "missing reset evidence for "
                f"{dut}/{profile}/entry={entry_index}/{raw_bin}: "
                f"expected {reset_count}, got {len(reset_ids)}"
            )
    return analyze_characterization_records(records)


def _git_output(repo_root: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
    return completed.stdout.strip()


def _sha256_without_self_hash(payload: dict[str, Any]) -> str:
    normalized = {
        key: value
        for key, value in payload.items()
        if key not in {"sha256", "bin_set_sha256"}
    }
    raw = json.dumps(normalized, **_JSON_DUMPS_KWARGS).encode("ascii")
    return hashlib.sha256(raw).hexdigest()
