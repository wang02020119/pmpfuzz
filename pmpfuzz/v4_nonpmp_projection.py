"""BAPC-core v4 non-PMP projection mapper.

The formal RTL evaluation uses the full BAPC-core v4 vocabulary of 144 bins
(``family=config`` 64, ``family=stimulus`` 26, ``family=decision`` 12,
``family=privilege-decision`` 18, ``family=mode-decision`` 24).  The ``config``
and ``mode-decision`` families depend on PMP entries and PMP matching modes, so
a target with no usable PMP (e.g. the C910) cannot be scored on them.

This module defines the **non-PMP projection**

    B_{v4}^{non-PMP} = B_stimulus union B_decision union B_privilege-decision,
    |B_{v4}^{non-PMP}| = 56,

which keeps the same stimulus, result, and effective-privilege decision mapping
as the full v4 mapper but never emits ``config`` or ``mode-decision`` bins.  The
56-bin universe is a strict subset of the 144-bin v4 universe, so ``covered/56``
is directly comparable with the shared-56 projection of U74 and the RTL targets.

Per the hardware-experiment v2 protocol, every scenario is classified as
``mapped`` / ``unsupported`` / ``observation-unqualified`` with an explicit
reason, and an operation whose observed outcome contradicts the architectural
oracle is reported as a *known semantic violation* rather than being counted as
an oracle pass.
"""
from __future__ import annotations

from typing import Any

# --- v4 non-PMP vocabulary ----------------------------------------------------

# Architecturally reachable (privilege, effective_privilege) pairs in v4.
# M-mode may lower loads/stores to S or U (MPRV); S and U execute as themselves.
# Instruction fetch is never MPRV-affected, so fetch only appears when v == e.
_REACHABLE_EFFECTIVE = {
    ("m", "m"): {"fetch", "load", "store"},
    ("m", "s"): {"load", "store"},
    ("m", "u"): {"load", "store"},
    ("s", "s"): {"fetch", "load", "store"},
    ("u", "u"): {"fetch", "load", "store"},
}

_ACCESSES = ("fetch", "load", "store")
_PRIVILEGES = ("m", "s", "u")
_TRANSLATIONS = ("bare", "sv39")
_ALLOW_DENY = ("allow", "deny")

_ACCESS_FAULT_CLASS = {
    "fetch": "instruction_access_fault",
    "load": "load_access_fault",
    "store": "store_access_fault",
}
_PAGE_FAULT_CLASS = {
    "fetch": "instruction_page_fault",
    "load": "load_page_fault",
    "store": "store_page_fault",
}
_MCAUSE_TO_CLASS = {
    1: "instruction_access_fault",
    5: "load_access_fault",
    7: "store_access_fault",
    12: "instruction_page_fault",
    13: "load_page_fault",
    15: "store_page_fault",
}
_DENY_CLASSES = ("other",) + tuple(
    sorted(set(_ACCESS_FAULT_CLASS.values()) | set(_PAGE_FAULT_CLASS.values()))
)


def _stimulus_bins() -> list[str]:
    bins: list[str] = []
    for (privilege, effective), access_set in sorted(_REACHABLE_EFFECTIVE.items()):
        for access in sorted(access_set):
            for translation in _TRANSLATIONS:
                bins.append(
                    "family=stimulus"
                    f"|privilege={privilege}"
                    f"|effective_privilege={effective}"
                    f"|access={access}"
                    f"|translation={translation}"
                )
    return bins


def _decision_bins() -> list[str]:
    bins: list[str] = []
    for access in _ACCESSES:
        bins.append(f"family=decision|access={access}|allow_or_deny=allow|mcause_class=none")
        for deny_class in (
            "other",
            _ACCESS_FAULT_CLASS[access],
            _PAGE_FAULT_CLASS[access],
        ):
            bins.append(
                f"family=decision|access={access}|allow_or_deny=deny|mcause_class={deny_class}"
            )
    return bins


def _privilege_decision_bins() -> list[str]:
    bins: list[str] = []
    for effective in _PRIVILEGES:
        for access in _ACCESSES:
            for allow_or_deny in _ALLOW_DENY:
                bins.append(
                    "family=privilege-decision"
                    f"|effective_privilege={effective}"
                    f"|access={access}"
                    f"|allow_or_deny={allow_or_deny}"
                )
    return bins


def build_v4_nonpmp_bin_ids() -> list[str]:
    """Return the frozen 56 non-PMP projection bin IDs (sorted)."""
    return sorted(_stimulus_bins() + _decision_bins() + _privilege_decision_bins())


def nonpmp_family_counts(bin_ids: list[str] | None = None) -> dict[str, int]:
    bin_ids = list(bin_ids if bin_ids is not None else build_v4_nonpmp_bin_ids())
    counts: dict[str, int] = {}
    for item in bin_ids:
        family = str(item.split("|")[0].split("=")[1])
        counts[family] = counts.get(family, 0) + 1
    return counts


# --- pure target-operation mapping ---------------------------------------------

def _normalize(value: Any, allowed: set[str], default: str | None = None) -> str | None:
    if value is None:
        return default
    text = str(value).strip().lower()
    return text if text in allowed else None


def map_target_operation(
    *,
    privilege: Any,
    effective_privilege: Any,
    access: Any,
    translation: Any,
    allow_or_deny: Any,
    mcause_class: Any = None,
) -> dict[str, Any]:
    """Map one qualified target operation to its non-PMP v4 bins.

    Returns ``{"status": "mapped", "bins": [...], "reason": "eligible"}`` or
    ``{"status": "unsupported", "bins": [], "reason": "<cause>"}``.  A result
    that is architecturally representable but whose outcome is not attributable
    is reported by the caller as ``observation-unqualified``.
    """
    privilege = _normalize(privilege, set(_PRIVILEGES))
    effective = _normalize(effective_privilege, set(_PRIVILEGES))
    access = _normalize(access, set(_ACCESSES))
    translation = _normalize(translation, set(_TRANSLATIONS))
    outcome = _normalize(allow_or_deny, set(_ALLOW_DENY))

    if privilege is None or effective is None or access is None or translation is None:
        return {"status": "unsupported", "bins": [], "reason": "missing-required-operation-field"}
    if outcome is None:
        return {"status": "unsupported", "bins": [], "reason": "missing-outcome"}

    allowed_accesses = _REACHABLE_EFFECTIVE.get((privilege, effective))
    if allowed_accesses is None:
        return {
            "status": "unsupported",
            "bins": [],
            "reason": f"v4-unreachable-effective-privilege:{privilege}->{effective}",
        }
    if access not in allowed_accesses:
        return {
            "status": "unsupported",
            "bins": [],
            "reason": f"v4-unreachable-access:{privilege}/{effective}/{access}",
        }

    bins: list[str] = []
    bins.append(
        "family=stimulus"
        f"|privilege={privilege}"
        f"|effective_privilege={effective}"
        f"|access={access}"
        f"|translation={translation}"
    )

    if outcome == "allow":
        decision_class = "none"
    else:
        decision_class = _normalize(
            mcause_class,
            set(
                ("other",)
                + (_ACCESS_FAULT_CLASS[access],)
                + (_PAGE_FAULT_CLASS[access],)
            ),
        )
        if decision_class is None:
            return {
                "status": "unsupported",
                "bins": [],
                "reason": f"unrepresentable-deny-class:{access}/{mcause_class}",
            }
        if decision_class == _PAGE_FAULT_CLASS[access] and translation != "sv39":
            # A page-fault decision is only attributable under sv39 translation.
            return {
                "status": "unsupported",
                "bins": [],
                "reason": f"page-fault-without-sv39:{access}",
            }
    bins.append(
        f"family=decision|access={access}|allow_or_deny={outcome}|mcause_class={decision_class}"
    )
    bins.append(
        "family=privilege-decision"
        f"|effective_privilege={effective}|access={access}|allow_or_deny={outcome}"
    )
    return {"status": "mapped", "bins": sorted(bins), "reason": "eligible"}


# --- C910 target-operation bridge ----------------------------------------------

_PROTECTION_MCAUSE = set(_MCAUSE_TO_CLASS)
# mcause values that are the payload's own trap rather than a protection denial:
# 8=user_ecall, 9=supervisor_ecall, 11=machine_ecall.
_NON_PROTECTION_MCAUSE = {8, 9, 11}


def _c910_outcome(record: dict[str, Any]) -> tuple[str, str] | None:
    """Derive (allow_or_deny, mcause_class) from a parsed C910 UART record.

    ``result=allow``/``result=deny`` are authoritative.  ``result=trap`` is a
    protection denial only when the cause is a protection fault class; otherwise
    the trap is the probe payload's own trap and the protected access was
    allowed.  sum-fetch records carry an explicit verdict/marker evidence that
    takes precedence.
    """
    result = str(record.get("result") or "").strip().lower()
    kind = str(record.get("kind") or "").strip().lower()

    if kind == "sum-fetch":
        verdict = str(record.get("verdict") or "").strip()
        marker_hit = bool(int(record.get("marker_hit") or 0))
        if marker_hit or verdict in {"vulnerable_smode_executed_u_page", "control_pass", "no_trap"}:
            return ("allow", "none")
        if verdict in {
            "instruction_page_fault",
            "load_page_fault",
            "store_page_fault",
            "spec_fetch_page_fault",
        }:
            return ("deny", "instruction_page_fault")
        cause = _as_int(record.get("cause"))
        if cause is not None:
            return _outcome_from_cause(cause, access=str(record.get("access") or ""))
        return None

    if result == "allow":
        return ("allow", "none")
    if result == "deny":
        access = str(record.get("access") or "").strip().lower()
        cause = _as_int(record.get("cause"))
        if cause in _PROTECTION_MCAUSE:
            return ("deny", _MCAUSE_TO_CLASS[cause])
        return ("deny", _ACCESS_FAULT_CLASS.get(access, "other"))
    if result == "trap":
        cause = _as_int(record.get("cause"))
        access = str(record.get("access") or "").strip().lower()
        if cause is None:
            return None
        return _outcome_from_cause(cause, access=access)
    return None


def _outcome_from_cause(cause: int, *, access: str) -> tuple[str, str] | None:
    if cause in _PROTECTION_MCAUSE:
        return ("deny", _MCAUSE_TO_CLASS[cause])
    # Any trap that is not a protection access/page fault means the protected
    # access itself was permitted; the payload trapped for its own reason
    # (ecall, illegal instruction, breakpoint, misalignment, ...).  Such a final
    # trap must never be reported as a protection denial.
    return ("allow", "none")


def c910_target_operation(case: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Build a v4 non-PMP target operation from a C910 case + result.

    Uses the authoritative case fields for privilege/effective-privilege/access/
    translation, and derives the observed outcome from the parsed UART record.
    Returns ``{"status": "observation-unqualified", ...}`` when the outcome
    cannot be attributed, and ``{"status": "unsupported", ...}`` for records
    that are not protection accesses in the v4 sense.
    """
    record = _parse_uart_record(result.get("uart_raw") or "")
    if record is None:
        return {
            "status": "observation-unqualified",
            "bins": [],
            "reason": "missing-uart-record",
        }

    parser = str(case.get("uart_parser") or result.get("uart_parser") or "").strip().lower()
    # Records that observe memory side effects or probe-only privilege behavior
    # are not v4 protection target operations.
    if parser == "side-effect":
        return {"status": "unsupported", "bins": [], "reason": "side-effect-not-v4-target-operation"}
    if parser == "real-mode" and not _has_target_access(case, record):
        return {"status": "unsupported", "bins": [], "reason": "no-target-protection-access"}

    privilege = _normalize(case.get("privilege"), set(_PRIVILEGES))
    effective = _normalize(case.get("effective_privilege"), set(_PRIVILEGES))
    access = _normalize(case.get("access"), set(_ACCESSES))
    translation = _normalize(case.get("translation"), set(_TRANSLATIONS))
    if access is None:
        return {"status": "unsupported", "bins": [], "reason": "missing-access"}

    outcome = _c910_outcome(record)
    if outcome is None:
        return {
            "status": "observation-unqualified",
            "bins": [],
            "reason": "outcome-not-attributable",
        }
    allow_or_deny, mcause_class = outcome

    # The mcause_class is derived from the protection fault; never use the
    # probe's own final trap (e.g. supervisor_ecall) as a protection decision.
    return map_target_operation(
        privilege=privilege,
        effective_privilege=effective,
        access=access,
        translation=translation,
        allow_or_deny=allow_or_deny,
        mcause_class=mcause_class,
    )


def _has_target_access(case: dict[str, Any], record: dict[str, Any]) -> bool:
    parser = str(case.get("uart_parser") or "").strip().lower()
    if parser == "real-mode":
        return str(case.get("access") or "").strip().lower() in _ACCESSES
    return True


def classify_scenario(
    case: dict[str, Any],
    result: dict[str, Any],
    *,
    oracle_allow: bool | None = None,
) -> dict[str, Any]:
    """Classify one executed scenario under the non-PMP v4 projection.

    Returns a report with status ``mapped``/``unsupported``/``observation-unqualified``,
    the mapped bins, an explicit reason, and a ``known_violation`` flag set when
    the observed outcome contradicts the architectural oracle.  When
    ``oracle_allow`` is not supplied it is derived from the case's architectural
    protection context (``architectural_oracle_allow``).
    """
    mapped = c910_target_operation(case, result)
    report = {
        "case_id": str(case.get("name") or result.get("name") or ""),
        "status": mapped["status"],
        "reason": mapped["reason"],
        "bins": list(mapped.get("bins") or []),
        "known_violation": False,
        "observed_outcome": None,
        "oracle_expected": None,
    }
    if mapped["status"] != "mapped":
        return report
    outcome = _c910_outcome(_parse_uart_record(result.get("uart_raw") or "") or {})
    if outcome is None:
        report["status"] = "observation-unqualified"
        report["reason"] = "outcome-not-attributable"
        report["bins"] = []
        return report
    observed = outcome[0]
    report["observed_outcome"] = observed
    if oracle_allow is None:
        oracle_allow = architectural_oracle_allow(case)
    if oracle_allow is None:
        return report
    report["oracle_expected"] = "allow" if oracle_allow else "deny"
    report["known_violation"] = observed != ("allow" if oracle_allow else "deny")
    return report


def architectural_oracle_allow(case: dict[str, Any]) -> bool | None:
    """Architectural allow/deny for a non-PMP (C910) protection access.

    Implements the Sv39 PTE permission rules without PMP: M-mode bypasses PTE
    checks; S-mode may access user pages only through SUM and only for
    loads/stores; instruction fetch never benefits from SUM or MXR; MXR permits
    loads to execute-only pages.  Under bare translation with no usable PMP the
    access is architecturally allowed.  Returns ``None`` when the case does not
    carry enough context to decide (never treated as a violation).
    """
    translation = str(case.get("translation") or "").strip().lower()
    effective = str(case.get("effective_privilege") or case.get("privilege") or "").strip().lower()
    access = str(case.get("access") or "").strip().lower()
    if access not in _ACCESSES:
        return None
    if effective not in _PRIVILEGES:
        return None
    if effective == "m":
        return True
    if translation == "bare":
        # No page tables and no usable PMP on this target: nothing denies it.
        return True
    if translation != "sv39":
        return None

    profile = str(case.get("profile") or "").strip().lower()
    case_name = str(case.get("name") or "").strip().lower()
    # Stateful TLB / stale-mapping / side-effect / A-D / permission-mutation
    # tests probe microarchitectural state (whether a fence was issued, whether
    # a stale mapping is still cached, whether an A/D bit has been set, whether
    # X was cleared before a fence).  A static PTE model cannot decide them;
    # leave them unqualified rather than risk a false violation.
    _STATEFUL_MARKERS = (
        "tlb", "side-effect", "stale", "nosfence", "patch", "fencei",
        "asid", "global", "fill", "after-", "-ad-", "ad-", "watchdog",
        "x-clear", "clear",
    )
    if any(marker in profile or marker in case_name for marker in _STATEFUL_MARKERS):
        return None

    pte = case.get("pte_permissions") or {}
    if not isinstance(pte, dict):
        pte = {}

    if access == "fetch":
        # SUM does not affect instruction fetch; S-mode may never fetch from a
        # user page regardless of SUM, and MXR does not affect fetch.  Fetch
        # probes execute an executable marker page, so the X bit is implied.
        # The user bit comes from the PTE when present, else from the case name.
        pte_user = pte.get("user")
        u_page = (
            bool(pte_user)
            if pte_user is not None
            else ("u-page" in case_name or "u_page" in case_name)
        )
        if effective == "u":
            return bool(u_page)
        if effective == "s":
            return not bool(u_page)
        return None

    # Loads and stores require a fully instantiated PTE.
    if not pte:
        return None
    if not bool(pte.get("valid")):
        return False
    # A/D-update tests run against PTE with the accessed/dirty bits still clear;
    # the expected fault depends on the platform's A/D-update policy and is not
    # modelled here.
    if not bool(pte.get("accessed")) or not bool(pte.get("dirty")):
        return None
    rwx = str(pte.get("rwx") or "")
    r = "r" in rwx
    w = "w" in rwx
    x = "x" in rwx
    user = bool(pte.get("user"))
    sum_enabled = bool(case.get("sum_enabled"))
    mxr = bool(case.get("mxr"))

    if access == "load":
        if user:
            if effective == "s":
                return bool(sum_enabled and r)
            if effective == "u":
                return bool(r) or bool(mxr and x)
        else:
            if effective == "s":
                return bool(r) or bool(mxr and x)
            if effective == "u":
                return False
        return None
    if access == "store":
        if user:
            if effective == "s":
                return bool(sum_enabled and w)
            if effective == "u":
                return bool(w)
        else:
            if effective == "s":
                return bool(w)
            if effective == "u":
                return False
        return None
    return None


def _parse_uart_record(raw: str) -> dict[str, Any] | None:
    if not raw:
        return None
    text = str(raw).strip()
    if text.startswith("["):
        start = text.find("]")
        if start != -1:
            text = text[start + 1:].strip()
    if not text:
        return None
    kind_match = __import__("re").match(r"([a-z-]+)\s+(.+)", text)
    record: dict[str, Any] = {}
    if kind_match:
        record["kind"] = kind_match.group(1)
        fields_text = kind_match.group(2)
    else:
        fields_text = text
    for key, value in __import__("re").findall(r"([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)", fields_text):
        record[key] = _as_int_or_str(value)
    return record


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value)
    try:
        return int(text, 0)
    except ValueError:
        return None


def _as_int_or_str(value: Any) -> Any:
    parsed = _as_int(value)
    return parsed if parsed is not None else str(value)
