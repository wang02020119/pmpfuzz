from __future__ import annotations


STOP_COVERAGE_CONVERGED = "coverage_converged"
STOP_HARD_CAP_CENSORED = "hard_cap_censored"
LEGACY_HARD_CAP_REASONS = frozenset({"right_censored_not_converged"})

_STOP_REASON_ALIASES = {
    reason: STOP_HARD_CAP_CENSORED for reason in LEGACY_HARD_CAP_REASONS
}

CONVERGENCE_TERMINAL_STOP_REASONS = frozenset(
    {
        STOP_COVERAGE_CONVERGED,
        STOP_HARD_CAP_CENSORED,
    }
)


def normalize_stop_reason(reason: object) -> str | None:
    text = str(reason or "").strip()
    if not text:
        return None
    return _STOP_REASON_ALIASES.get(text, text)


def is_legacy_hard_cap_reason(reason: object) -> bool:
    text = str(reason or "").strip()
    return text in LEGACY_HARD_CAP_REASONS


def is_convergence_terminal_stop_reason(reason: object) -> bool:
    normalized = normalize_stop_reason(reason)
    return normalized in CONVERGENCE_TERMINAL_STOP_REASONS


def is_hard_cap_stop_reason(reason: object) -> bool:
    return normalize_stop_reason(reason) == STOP_HARD_CAP_CENSORED
