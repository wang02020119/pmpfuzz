#!/usr/bin/env python3
"""Shared machinery for the C910 closedloop-56 v2 generation campaign.

Defines the declared reachable set (46/56), the directed bin->params
constructors, and the parent-mutation operators.  The guided and random
generators share this module so the only difference is *guidance*.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from random import Random
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from pmpfuzz.c910_m2_scheduling import predict_shared56_bins
from pmpfuzz.c910_nonpmp_dynamic import build_generated_case
from pmpfuzz.v4_nonpmp_projection import build_v4_nonpmp_bin_ids


CL56_UNIVERSE = "v4-nonpmp-56"

# 10 structurally unreachable bins on a no-PMP C910 (see PROBE_PARAM_AUDIT.md).
STRUCTURALLY_UNREACHABLE = frozenset(
    [
        # decision deny *access_fault: bare probe addresses are always mapped;
        # sv39 permission violations fault as page faults, never access faults.
        "family=decision|access=fetch|allow_or_deny=deny|mcause_class=instruction_access_fault",
        "family=decision|access=load|allow_or_deny=deny|mcause_class=load_access_fault",
        "family=decision|access=store|allow_or_deny=deny|mcause_class=store_access_fault",
        # decision deny mcause=other: an unexpected trap cause cannot be directed.
        "family=decision|access=fetch|allow_or_deny=deny|mcause_class=other",
        "family=decision|access=load|allow_or_deny=deny|mcause_class=other",
        "family=decision|access=store|allow_or_deny=deny|mcause_class=other",
        # privdec effective=m deny: without PMP an M-mode access is never denied.
        "family=privilege-decision|effective_privilege=m|access=fetch|allow_or_deny=deny",
        "family=privilege-decision|effective_privilege=m|access=load|allow_or_deny=deny",
        "family=privilege-decision|effective_privilege=m|access=store|allow_or_deny=deny",
        # stimulus m/m fetch sv39: MPRV affects only load/store; M-mode
        # instruction fetch is architecturally physical, so this never occurs.
        "family=stimulus|privilege=m|effective_privilege=m|access=fetch|translation=sv39",
    ]
)

REACHABLE_BINS = sorted(set(build_v4_nonpmp_bin_ids()) - STRUCTURALLY_UNREACHABLE)


def parse_bin(bin_id: str) -> dict[str, str]:
    return dict(part.split("=", 1) for part in str(bin_id).split("|"))


def _sv39_access_params(
    *, privilege: str, effective: str, access: str,
    pte_rwx: str, pte_user: bool, pte_valid: bool = True,
    sum_enabled: bool = False, mxr: bool = False,
) -> dict[str, Any]:
    return {
        "runner_kind": "sv39_access",
        "privilege": privilege,
        "effective_privilege": effective,
        "access": access,
        "translation": "sv39",
        "pte_rwx": pte_rwx,
        "pte_user": pte_user,
        "pte_valid": pte_valid,
        "sum": sum_enabled,
        "mxr": mxr,
    }


def _mprv_bare_params(*, privilege: str, effective: str, access: str) -> dict[str, Any]:
    return {
        "runner_kind": "mprv_bare",
        "privilege": privilege,
        "effective_privilege": effective,
        "access": access,
        "translation": "bare",
        "pte_rwx": "---",
        "pte_user": False,
        "pte_valid": True,
        "sum": False,
        "mxr": False,
    }


def construct_params_for_bin(bin_id: str, index: int, seed: int) -> dict[str, Any] | None:
    """Directed construction: params whose predicted bins contain ``bin_id``.

    Returns ``None`` when the bin is not constructible (structurally
    unreachable, or outside the parameterized-runner vocabulary).  The two
    reachable-but-missing M-3 targets are:
      privdec s/load/deny  -> sv39 S-mode load of a user page, SUM=0;
      privdec s/store/deny -> sv39 S-mode store of a user page, SUM=0.
    """
    f = parse_bin(bin_id)
    family = f.get("family")
    if family == "stimulus":
        return _construct_stimulus(f)
    if family == "decision":
        return _construct_decision(f)
    if family == "privilege-decision":
        return _construct_privdec(f)
    return None


def _construct_stimulus(f: dict[str, str]) -> dict[str, Any] | None:
    priv = f["privilege"]
    eff = f["effective_privilege"]
    acc = f["access"]
    trans = f["translation"]
    if acc == "fetch":
        # No parameterized fetch runner; fetch stimulus is covered by the
        # catalog's phase-handled fetch records.
        return None
    if trans == "sv39":
        return _sv39_access_params(
            privilege=priv, effective=eff, access=acc,
            pte_rwx="rw-", pte_user=(eff == "u"),
        )
    return _mprv_bare_params(privilege=priv, effective=eff, access=acc)


def _construct_decision(f: dict[str, str]) -> dict[str, Any] | None:
    acc = f["access"]
    allow = f["allow_or_deny"] == "allow"
    cause = f["mcause_class"]
    if acc == "fetch":
        # fetch decision bins are covered by catalog fetch records (the
        # parameterized runner is load/store only).
        return None
    if allow:
        return _sv39_access_params(
            privilege="u", effective="u", access=acc,
            pte_rwx="rw-", pte_user=True,
        )
    if cause in ("other",) or cause.endswith("_access_fault"):
        return None  # structurally unreachable / undirectable
    # page-fault deny -> a U-mode sv39 PTE that denies the access.
    pte_rwx = {"load": "--x", "store": "r--"}[acc]
    return _sv39_access_params(
        privilege="u", effective="u", access=acc,
        pte_rwx=pte_rwx, pte_user=True,
    )


def _construct_privdec(f: dict[str, str]) -> dict[str, Any] | None:
    eff = f["effective_privilege"]
    acc = f["access"]
    allow = f["allow_or_deny"]
    if acc == "fetch":
        return None  # fetch via catalog fetch records only
    if eff == "m":
        if allow == "deny":
            return None  # structurally unreachable
        return _mprv_bare_params(privilege="m", effective="m", access=acc)
    if allow == "allow":
        return _sv39_access_params(
            privilege=eff, effective=eff, access=acc,
            pte_rwx="rw-", pte_user=(eff == "u"),
        )
    # deny under sv39 for effective in {s, u}.
    if eff == "s":
        # S-mode load/store of a user page with SUM=0 -> page fault.
        return _sv39_access_params(
            privilege="s", effective="s", access=acc,
            pte_rwx="rw-", pte_user=True, sum_enabled=False,
        )
    pte_rwx = {"load": "--x", "store": "r--"}[acc]
    return _sv39_access_params(
        privilege="u", effective="u", access=acc,
        pte_rwx=pte_rwx, pte_user=True,
    )


# ---------------------------------------------------------------------------
# parent mutation (fill)
# ---------------------------------------------------------------------------

FILL_OPS = ("toggle-pte-rwx", "toggle-pte-user", "toggle-valid", "toggle-sum", "toggle-mxr", "toggle-mpp", "toggle-access")
_RWX_POOL = ("rw-", "r--", "--x", "r-x", "---")
_ACCESS_POOL = ("load", "store")
_PRIV_POOL = ("m", "s", "u")


def mutate_parent_params(parent: dict[str, Any], op: str, attempt: int, *, seed: int) -> dict[str, Any] | None:
    """Deterministic single-operator mutation of a parent case's params.

    ``op`` is hashed with sha256 (not Python's salted builtin hash) so the
    mutation stream is reproducible across runs and processes.
    """
    op_seed = int(hashlib.sha256(op.encode("utf-8")).hexdigest()[:8], 16)
    rng = Random((seed * 7919 + attempt * 104729 + op_seed % 65536) & 0x7FFFFFFF)
    base = dict(parent.get("generated_params") or {})
    if not base:
        base = _params_from_parent_case(parent)
    if not base:
        return None
    runner_kind = str(base.get("runner_kind") or "sv39_access")
    params = dict(base)
    if op == "toggle-pte-rwx" and runner_kind == "sv39_access":
        params["pte_rwx"] = _pick(rng, [p for p in _RWX_POOL if p != params.get("pte_rwx")], params.get("pte_rwx", "rw-"))
    elif op == "toggle-pte-user" and runner_kind == "sv39_access":
        params["pte_user"] = not bool(params.get("pte_user", False))
    elif op == "toggle-valid" and runner_kind == "sv39_access":
        params["pte_valid"] = not bool(params.get("pte_valid", True))
    elif op == "toggle-sum" and runner_kind == "sv39_access":
        params["sum"] = not bool(params.get("sum", False))
    elif op == "toggle-mxr" and runner_kind == "sv39_access":
        params["mxr"] = not bool(params.get("mxr", False))
    elif op == "toggle-mpp":
        eff = str(params.get("effective_privilege") or params.get("privilege") or "u")
        new_eff = _pick(rng, [p for p in _PRIV_POOL if p != eff], "u")
        params["effective_privilege"] = new_eff
        if new_eff == "m":
            params["privilege"] = "m"
    elif op == "toggle-access":
        acc = str(params.get("access") or "load")
        params["access"] = _pick(rng, [p for p in _ACCESS_POOL if p != acc], "load")
    else:
        return None
    params["runner_kind"] = runner_kind
    return params


def _params_from_parent_case(parent: dict[str, Any]) -> dict[str, Any] | None:
    """Recover a params tuple from a catalog-case parent if expressible."""
    runner = str(parent.get("runner_params") or {}).lower() if not isinstance(parent.get("runner_params"), dict) else str(parent.get("runner_params", {}).get("runner_kind") or "")
    parser = str(parent.get("uart_parser") or "")
    if parser in {"side-effect", "real-mode", "sum-fetch"}:
        return None
    translation = str(parent.get("translation") or "bare").lower()
    access = str(parent.get("access") or "load").lower()
    if access == "fetch":
        return None  # fetch is not expressible in the load/store runner vocabulary
    if translation == "sv39":
        pte = parent.get("pte_permissions") or {}
        return {
            "runner_kind": "sv39_access",
            "privilege": str(parent.get("privilege") or "m").lower(),
            "effective_privilege": str(parent.get("effective_privilege") or "m").lower(),
            "access": access,
            "translation": "sv39",
            "pte_rwx": str(pte.get("rwx") or "rw-"),
            "pte_user": bool(pte.get("user", False)),
            "pte_valid": bool(pte.get("valid", True)),
            "sum": bool(parent.get("sum_enabled", False)),
            "mxr": bool(parent.get("mxr", False)),
        }
    if parser == "mprv":
        return {
            "runner_kind": "mprv_bare",
            "privilege": str(parent.get("privilege") or "m").lower(),
            "effective_privilege": str(parent.get("effective_privilege") or "m").lower(),
            "access": access,
            "translation": "bare",
            "pte_rwx": "---",
            "pte_user": False,
            "pte_valid": True,
            "sum": False,
            "mxr": False,
        }
    return None


def _pick(rng: Random, choices: list[Any], default: Any) -> Any:
    return choices[rng.randrange(len(choices))] if choices else default


# ---------------------------------------------------------------------------
# case assembly (params -> case with predicted bins attached)
# ---------------------------------------------------------------------------

def assemble_generated(
    params: dict[str, Any],
    *,
    index: int,
    target_bin: str,
    operator: str,
    parent_id: str,
    seed: int,
    record_name: str | None = None,
) -> dict[str, Any] | None:
    """Build a generated case (with predicted bins) or None if not mappable."""
    runner_kind = str(params.get("runner_kind") or "sv39_access")
    access = str(params.get("access") or "load").lower()
    if runner_kind in ("sv39_access", "mprv_bare") and access == "fetch":
        # The parameterized case-runner implements load/store only; an access=
        # fetch case would be mis-executed (dispatched as store) and the
        # classification would fabricate coverage of a fetch stimulus bin.
        return None
    if record_name is None:
        record_name = f"gen-{index:04d}"
    params = dict(params)
    params["record"] = record_name
    case = build_generated_case(params=params, index=index, seed=seed)
    predicted = predict_shared56_bins(case)
    if predicted.get("status") != "mapped":
        return None
    case["predicted_bins"] = list(predicted.get("bins") or [])
    if target_bin and target_bin not in case["predicted_bins"]:
        return None
    case["_meta"] = {
        "target_bin": target_bin,
        "operator": operator,
        "parent_id": parent_id,
        "generation_seed": seed,
    }
    return case


def load_seed_pool(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return list(payload.get("candidates") or payload.get("seed_pool") or [])


def board_mappable(case: dict[str, Any]) -> bool:
    """True if the case will be classified ``mapped`` on the board.

    ``predict_shared56_bins`` maps from the case's architectural fields and
    ignores the UART parser, but ``classify_scenario`` marks side-effect
    records and target-less real-mode records as ``unsupported``.  The v2 pool
    builders apply this filter so predicted coverage matches board coverage.
    """
    parser = str(case.get("uart_parser") or "").strip().lower()
    if parser == "side-effect":
        return False
    if parser == "real-mode":
        access = str(case.get("access") or "").strip().lower()
        if access not in ("fetch", "load", "store"):
            return False
    return True


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
