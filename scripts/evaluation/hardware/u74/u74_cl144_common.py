"""Shared helpers for the U74 closedloop-144 experiment scripts.

This module is imported by ``u74_build_candidate_corpus.py``,
``u74_guided_select.py``, ``u74_random_select.py`` and
``aggregate_u74_bapc.py``.  It centralizes:

- universe loading + structural unsupported-bin computation (TOR / locked / OFF
  config bins are pre-registered unsupported until the TOR/locked firmware is
  ready, so the campaign honestly reports convergence *within the reachable
  space* of the fixed 144-bin universe);
- scenario -> lowered-case materialization (reusing
  ``u74_formal_round0_prepare._lower_scenario`` so schedules stay byte-identical
  to the pre-flight formal materialization path);
- BAPC v4/144 bin prediction through the exact same code path the board adapter
  uses for real observations (``summarize_bapc_for_pmpfuzz_case`` with the
  *expected* outcome instead of the observed one);
- deterministic hashing helpers used for corpus / selection-log provenance.
"""
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

import u74_formal_round0_prepare as _frp  # noqa: E402  (lowering/materialization helpers)


# Fixed contract (EXPERIMENT_PROTOCOL.md §1).  Keep frozen across all runs.
CONTRACT_UNIVERSE_SHA256 = "3aa0ee76465cae3fae0e5216cde8d47d1bc3d67917e12af80db6d0f03bd73cd0"
CONTRACT_CAPABILITY_FINGERPRINT = "bapc:u74:fault-stage=0:smepmp=0"
CAMPAIGN_ID = "closedloop-144"

# Coverage-family priority used as the secondary marginal-gain score in guided
# selection (EXPERIMENT_PROTOCOL.md §4.3): config and stimulus gaps win ties.
FAMILY_PRIORITY = {
    "family=config": 0,
    "family=stimulus": 1,
    "family=decision": 2,
    "family=privilege-decision": 3,
    "family=mode-decision": 4,
}

# Generator profiles validated on the U74 board harness (see
# u74_formal_round0_prepare.ROUND_GENERATOR_PROFILES).
ROUND_GENERATOR_PROFILES = ("pmp-boundary", "legacy-data", "sv39-final-pmp")

# Mutation operators used for corpus augmentation.  toggle-pmp-permissions is
# the key one: it produces 010 / 011 permission combinations that the base
# generators rarely emit; set-pmp-locked=1 produces locked config classes the
# base profiles never emit.
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
    """Structurally / firmware-blocked bins of the fixed 144-bin universe.

    The U74 board firmware supports TOR and locked entries (verified on the
    board: run-m1-tor20-fix3 clean, run-m1-144-fix 78/144 under the 144
    universe), so TOR / locked config and mode-decision bins are *reachable*.

    The only structurally unsupported bins are the 15 non-canonical OFF config
    bins.  The mapper canonicalizes every declared OFF entry to
    ``family=config|pmp_mode=off|permission_rwx=000|locked=false`` -- that one
    bin is reachable; the other 15 (rwx != 000, or locked=true) are never
    emitted because ``_non_harness_entries`` excludes OFF entries from lowering
    (OFF is a non-config-entry state on this harness).

    Everything else stays in the reachable denominator.  The 144-bin universe
    is *never* resized; unsupported bins are recorded explicitly.
    """
    REACHABLE_OFF_CONFIG_BIN = "family=config|pmp_mode=off|permission_rwx=000|locked=false"

    unsupported = []
    for bin_id in (universe.get("bin_ids") or []):
        text = str(bin_id)
        family = text.split("|", 1)[0]
        if family == "family=config" and "|pmp_mode=off|" in text and text != REACHABLE_OFF_CONFIG_BIN:
            unsupported.append(text)
            continue
        # sv39 fetch stimulus bins: the sv39 fetch path is not stable on the
        # current firmware (deadlocks the runner); bare fetch still covers the
        # translation-independent decision/privilege/mode-decision fetch bins.
        if family == "family=stimulus" and "|access=fetch|" in text and "|translation=sv39" in text:
            unsupported.append(text)
            continue
        # instruction_page_fault requires the sv39 fetch path, which is not
        # stable on the current firmware (excluded as board_unstable).
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
    """Lower a scenario to the U74 board case payload (reuses the formal path)."""
    return _frp._lower_scenario(case, scenario, ordinal=ordinal)


def scenario_locked_tor_flags(scenario: PmpScenario) -> dict[str, bool]:
    """Per-scenario flags for firmware-aware reporting.

    The U74 firmware supports TOR and locked entries, so these flags are
    informational (the campaign's reachable denominator includes TOR/locked
    bins).  They let the corpus summary report how much of the config space
    comes from TOR / locked candidates.
    """
    has_tor = False
    has_locked = False
    for entry in non_harness_entries(scenario):
        if entry.address_mode.name.lower() == "tor":
            has_tor = True
        if bool(entry.locked):
            has_locked = True
    return {"has_tor": has_tor, "has_locked": has_locked}


def firmware_ready_for_scenario(scenario: PmpScenario) -> bool:
    """True when the U74 board firmware can currently run this scenario.

    TOR and locked entries are supported by the current firmware (verified on
    the board), so every lowering-valid scenario is firmware-ready.
    """
    return True


def config_classes_for_scenario(scenario: PmpScenario) -> list[list[str]]:
    """[(pmp_mode, permission_rwx, locked), ...] for non-harness entries."""
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
    """Predict BAPC v4 observed bins for a scenario-native case.

    Uses ``summarize_bapc_for_pmpfuzz_case`` -- the exact code path the board
    adapter uses for real observations -- but feeds it the *expected* outcome
    rather than the observed one.  The return value mirrors
    ``result.json``'s ``bapc_coverage`` payload (eligible / observed_bins /
    event_records / ...).
    """
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
