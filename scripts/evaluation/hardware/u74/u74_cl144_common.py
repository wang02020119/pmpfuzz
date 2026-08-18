from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pmpfuzz.bapc import BAPC_CORE_VERSION_V4, summarize_bapc_for_pmpfuzz_case
from pmpfuzz.scenario import PmpScenario
from pmpfuzz.schema import scenario_to_case_dict
from pmpfuzz.u74_board import canonical_u74_bapc_coverage_hash

import u74_formal_round0_prepare as _frp



CONTRACT_UNIVERSE_SHA256 = "3aa0ee76465cae3fae0e5216cde8d47d1bc3d67917e12af80db6d0f03bd73cd0"
CONTRACT_CAPABILITY_FINGERPRINT = "bapc:u74:fault-stage=0:smepmp=0"
CAMPAIGN_ID = "closedloop-144"



FAMILY_PRIORITY = {
    "family=config": 0,
    "family=stimulus": 1,
    "family=decision": 2,
    "family=privilege-decision": 3,
    "family=mode-decision": 4,
}



ROUND_GENERATOR_PROFILES = ("pmp-boundary", "legacy-data", "sv39-final-pmp")





CORPUS_MUTATION_OPERATORS = (
    "toggle-pmp-permissions",
    "toggle-access",
    "toggle-pmp-address-mode",
    "toggle-privilege",
    "set-pmp-locked=1",
)


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="ascii"))


def write_json(path: str | Path, payload: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="ascii")


def _json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def sha256_payload(payload: Any) -> str:
    return hashlib.sha256(_json_bytes(payload)).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_universe(path: str | Path) -> dict[str, Any]:
    universe = load_json(path)
    if int(universe.get("bin_count") or 0) != 144:
        raise ValueError(f"closedloop-144 requires a 144-bin universe, got {universe.get('bin_count')}")
    actual_sha = str(universe.get("sha256") or "")
    if actual_sha != CONTRACT_UNIVERSE_SHA256:
        raise ValueError(
            f"closedloop-144 contract universe mismatch: expected {CONTRACT_UNIVERSE_SHA256}, "
            f"got {actual_sha}"
        )
    return universe


def compute_unsupported_bins(universe: dict[str, Any]) -> list[str]:
    REACHABLE_OFF_CONFIG_BIN = "family=config|pmp_mode=off|permission_rwx=000|locked=false"

    unsupported = []
    for bin_id in (universe.get("bin_ids") or []):
        text = str(bin_id)
        family = text.split("|", 1)[0]
        if family == "family=config" and "|pmp_mode=off|" in text and text != REACHABLE_OFF_CONFIG_BIN:
            unsupported.append(text)
            continue



        if family == "family=stimulus" and "|access=fetch|" in text and "|translation=sv39" in text:
            unsupported.append(text)
            continue


        if family == "family=decision" and "|mcause_class=instruction_page_fault" in text:
            unsupported.append(text)
    return sorted(set(unsupported))


def reachable_bins(universe: dict[str, Any]) -> list[str]:
    unsupported = set(compute_unsupported_bins(universe))
    return sorted(str(bin_id) for bin_id in (universe.get("bin_ids") or []) if bin_id not in unsupported)


def non_harness_entries(scenario: PmpScenario) -> list[Any]:
    return _frp._non_harness_entries(scenario)


def is_supported_scenario(scenario: PmpScenario) -> bool:
    return _frp._is_supported_formal_scenario(scenario)


def lower_scenario(case: dict[str, Any], scenario: PmpScenario, *, ordinal: int) -> dict[str, Any]:
    return _frp._lower_scenario(case, scenario, ordinal=ordinal)


def scenario_locked_tor_flags(scenario: PmpScenario) -> dict[str, bool]:
    has_tor = False
    has_locked = False
    for entry in non_harness_entries(scenario):
        if entry.address_mode.name.lower() == "tor":
            has_tor = True
        if bool(entry.locked):
            has_locked = True
    return {"has_tor": has_tor, "has_locked": has_locked}


def firmware_ready_for_scenario(scenario: PmpScenario) -> bool:
    return True


def config_classes_for_scenario(scenario: PmpScenario) -> list[list[str]]:
    classes = []
    for entry in non_harness_entries(scenario):
        rwx = f"{int(entry.read)}{int(entry.write)}{int(entry.execute)}"
        classes.append([entry.address_mode.name.lower(), rwx, str(bool(entry.locked)).lower()])
    return classes


def predict_case_bins(
    case: dict[str, Any],
    *,
    expected_allowed: bool,
    expected_cause: int | None,
) -> dict[str, Any]:
    provisional = {
        "status": "pass" if expected_allowed else "fail",
        "observation_valid": True,
        "observed_event": "completion" if expected_allowed else "trap",
        "observed_mcause": int(expected_cause) if expected_cause is not None else 0,
    }
    return summarize_bapc_for_pmpfuzz_case(
        case,
        provisional,
        log_text="",
        supports_smepmp=False,
        bapc_core_version=BAPC_CORE_VERSION_V4,
    )


def build_case_and_lowering(
    scenario: PmpScenario,
    *,
    seed: int,
    index: int,
    case_name: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    from dataclasses import replace

    scenario = replace(scenario, name=case_name)
    case = scenario_to_case_dict(scenario, seed=seed, index=index)
    lowering = lower_scenario(case, scenario, ordinal=index)
    return case, lowering


def make_candidate_id(*, seed: int, profile: str, generator_index: int, scenario_hash: str, mutation: str) -> str:
    return sha256_payload(
        {
            "kind": "u74-cl144-candidate-v1",
            "seed": seed,
            "profile": profile,
            "generator_index": generator_index,
            "scenario_hash": scenario_hash,
            "mutation": mutation,
        }
    )[:16]


def coverage_hash_of_bins(bins: list[str]) -> str:
    return canonical_u74_bapc_coverage_hash(sorted(set(str(b) for b in bins if str(b))))


def family_of_bin(bin_id: str) -> str:
    return str(bin_id).split("|", 1)[0]


def family_breakdown(bins: list[str], families: list[str] | None = None) -> dict[str, dict[str, int]]:
    families = families or ["family=config", "family=stimulus", "family=decision",
                            "family=privilege-decision", "family=mode-decision"]
    counts = {f: 0 for f in families}
    for bin_id in bins:
        fam = family_of_bin(bin_id)
        if fam in counts:
            counts[fam] += 1
    return {fam: {"covered": counts[fam]} for fam in families}
