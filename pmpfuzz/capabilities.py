from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any, Iterable

from .dut import (
    DEFAULT_CLEAN_CHIPYARD_DIR,
    DEFAULT_XIANGSHAN_EMU,
    resolve_xiangshan_binary,
    xiangshan_emu_build_config,
    xiangshan_emu_supports_goodtrap,
)


DEFAULT_CAPABILITY_SCHEMA_VERSION = 3
DEFAULT_CAPABILITY_SPIKE = os.environ.get("PMPFUZZ_SPIKE", shutil.which("spike") or "spike")
DEFAULT_U74_LEGACY_CATALOG = Path(
    os.environ.get("PMPFUZZ_U74_CATALOG", "artifacts/u74/catalog.json")
)


def capability_for_dut(
    dut: str,
    *,
    available: bool | None = None,
    path: Path | str | None = None,
    probe_smepmp: bool = False,
    isa: str | None = None,
) -> dict[str, Any]:
    spec = _DUT_SPECS.get(dut)
    if spec is None:
        raise ValueError(f"unsupported DUT for capability probe: {dut}")
    selected_path = path or spec.get("path") or ""
    if dut == "xiangshan-clean" and selected_path:
        resolved_path = str(resolve_xiangshan_binary(Path(selected_path)))
    else:
        resolved_path = str(selected_path)
    resolved_available = _default_available(dut, resolved_path) if available is None else bool(available)
    notes = list(spec.get("notes", ()))
    oracle_applicability = (
        str(spec.get("oracle_applicability") or "valid") if resolved_available else "infra_unadapted"
    )
    if dut == "xiangshan-clean" and resolved_available:
        goodtrap_support = xiangshan_emu_supports_goodtrap(Path(resolved_path))
        build_config = xiangshan_emu_build_config(Path(resolved_path))
        if goodtrap_support is False:
            oracle_applicability = "infra_unadapted"
            notes.append(
                "selected XiangShan emu was built with CONFIG_NO_DIFFTEST; rebuild with difftest enabled for xstrap good-trap"
            )
        elif build_config is not None:
            notes.append(f"build metadata: {build_config}")
    supported_capabilities = dict(spec["supported_capabilities"])
    observation_capabilities = dict(spec.get("observation_capabilities") or _COMMON_OBSERVATION)

    # -- ISA-driven Smepmp override for Spike ---------------------------------
    if dut == "spike" and isa is not None:
        effective_smepmp = "smepmp" in isa.lower()
        supported_capabilities["smepmp"] = effective_smepmp
        # rlb is hardwired to zero on Spike regardless of ISA
        supported_capabilities["smepmp_rlb"] = False
        if not effective_smepmp:
            notes.append(f"Spike ISA={isa} does not include Smepmp; Smepmp marked unsupported")
        else:
            notes.append(f"Spike ISA={isa} includes Smepmp")

    smepmp_static = spec.get("smepmp_features") or {}
    smepmp_probe = _smepmp_probe_result(
        dut,
        resolved_available,
        supported_capabilities.get("smepmp", False),
        probe_smepmp,
        static_rlb=bool(smepmp_static.get("rlb", supported_capabilities.get("smepmp", False))),
    )
    supported_capabilities["smepmp"] = smepmp_probe["probe_status"] == "supported"
    supported_capabilities["smepmp_rlb"] = bool(smepmp_probe["rlb"])
    capability = {
        "schema_version": DEFAULT_CAPABILITY_SCHEMA_VERSION,
        "dut": dut,
        "available": resolved_available,
        "path": resolved_path,
        "supported_capabilities": supported_capabilities,
        "observation_capabilities": observation_capabilities,
        "finish_protocol": spec["finish_protocol"],
        "diagnostic_depth": spec["diagnostic_depth"],
        "ad_update_mode": str(spec.get("ad_update_mode") or "unknown"),
        "oracle_applicability": oracle_applicability,
        "smepmp": smepmp_probe,
        "notes": notes,
        "isa": isa or "",
    }
    return capability


def capability_matrix(duts: Iterable[str], *, probe_smepmp: bool = False) -> dict[str, Any]:
    entries = {dut: capability_for_dut(dut, probe_smepmp=probe_smepmp) for dut in duts}
    return {
        "schema_version": DEFAULT_CAPABILITY_SCHEMA_VERSION,
        "duts": entries,
    }


def required_capabilities_for_case(case: dict[str, Any]) -> list[str]:
    override = case.get("required_capabilities_override")
    if override is not None:
        return sorted({str(item) for item in override if str(item)})

    required = {"pmp"}
    if str(case.get("translation")) == "sv39" or case.get("sv39") is not None:
        required.add("sv39")
    privilege = case.get("privilege")
    if privilege == "S":
        required.add("s_mode")
    elif privilege == "U":
        required.add("u_mode")
    mseccfg = case.get("mseccfg") or {}
    if any(bool(mseccfg.get(bit)) for bit in ("mml", "mmwp", "rlb")) or "smepmp" in str(case.get("profile")):
        required.add("smepmp")
    if bool(mseccfg.get("rlb")):
        required.add("smepmp_rlb")
    return sorted(required)


def oracle_applicability_for_case(case: dict[str, Any], capability: dict[str, Any] | None = None) -> str:
    if _is_experimental_case(case):
        return "experimental"
    if capability is None:
        return "valid"
    if not capability.get("available"):
        return "infra_unadapted"
    supported = capability.get("supported_capabilities") or {}
    missing = [item for item in required_capabilities_for_case(case) if not supported.get(item, False)]
    if missing:
        return "unsupported"
    if _requires_ad_update(case):
        expected_mode = str(case.get("ad_update_mode") or "svade")
        observed_mode = str(capability.get("ad_update_mode") or "unknown")
        if observed_mode == "unknown":
            return "capability_dependent"
        if observed_mode != expected_mode:
            return "unsupported"
    observation_capabilities = dict(_COMMON_OBSERVATION)
    observation_capabilities.update(capability.get("observation_capabilities") or {})
    missing_observation = [
        item
        for item in required_observation_capabilities_for_case(case)
        if not observation_capabilities.get(item, False)
    ]
    if missing_observation:
        return "capability_dependent"
    return str(capability.get("oracle_applicability") or "valid")


def oracle_applicability_for_result(
    case: dict[str, Any],
    capability: dict[str, Any] | None,
    *,
    status: str,
    failure_class: str | None,
) -> str:
    if status == "setup_unsupported":
        return "unsupported"
    if failure_class == "infra_unadapted":
        return "infra_unadapted"
    return oracle_applicability_for_case(case, capability)


def capability_coverage_projection(capability: dict[str, Any]) -> dict[str, Any]:
    """Return the subset of capability fields that affect C_T (coverage target).

    Only fields that change the oracle-applicability decision or target-space
    enumeration are included.  Paths, timestamps, notes, and smepmp diagnostic
    descriptions (warl_behavior, probe_status, etc.) are deliberately excluded.
    Whether Smepmp is supported is already reflected by supported_capabilities.
    """
    return {
        "schema_version": capability.get("schema_version"),
        "dut": capability.get("dut"),
        "available": capability.get("available"),
        "isa": capability.get("isa"),
        "supported_capabilities": capability.get("supported_capabilities") or {},
        "observation_capabilities": capability.get("observation_capabilities") or {},
        "ad_update_mode": capability.get("ad_update_mode"),
        "oracle_applicability": capability.get("oracle_applicability"),
    }


def required_observation_capabilities_for_case(case: dict[str, Any]) -> list[str]:
    expected = case.get("expected") or {}
    expected_stage = str(expected.get("stage") or case.get("expected_stage") or "none")
    translation = str(
        case.get("translation")
        or case.get("translation_mode")
        or (case.get("scenario_spec") or {}).get("translation")
        or ""
    )
    required: set[str] = set()

    if expected_stage == "page_table_walk":
        required.add("sv39_ptw_target_attribution")

    if (
        translation == "sv39"
        and expected_stage == "final_access"
        and not bool(expected.get("allowed", case.get("expected_allowed", True)))
    ):
        required.add("sv39_final_fault_address")

    stateful = case.get("stateful_sequence") or (case.get("scenario_spec") or {}).get("stateful_sequence") or {}
    if expected_stage == "stateful_final" and stateful.get("final_probe") == "repeat":
        required.add("sv39_stateful_reprobe_phase")

    return sorted(required)


def _is_experimental_case(case: dict[str, Any]) -> bool:
    profile = str(case.get("profile") or "")
    if profile in {"legacy-fetch-experimental"}:
        return True
    sequence = _case_stateful_sequence(case)
    if sequence.get("fence") == "no-fence-experimental":
        return True
    tags = {str(item) for item in (case.get("coverage_tags") or ())}
    return "no-fence-experimental" in tags


def _case_stateful_sequence(case: dict[str, Any]) -> dict[str, Any]:
    sequence = case.get("stateful_sequence")
    if isinstance(sequence, dict):
        return sequence
    scenario_spec = case.get("scenario_spec")
    if isinstance(scenario_spec, dict):
        nested = scenario_spec.get("stateful_sequence")
        if isinstance(nested, dict):
            return nested
    return {}


def _requires_ad_update(case: dict[str, Any]) -> bool:
    sv39 = case.get("sv39") or {}
    pte = sv39.get("pte") or {}
    if not pte:
        return False
    if not bool(pte.get("accessed", True)):
        return True
    return case.get("access") == "store" and not bool(pte.get("dirty", True))


def _default_available(dut: str, path: str) -> bool:
    if dut == "spike":
        return Path(path).exists() or shutil.which(path) is not None
    if dut in {"rocket-clean", "boom-clean", "cva6-clean", "cva6"}:
        return _chipyard_sim_exists(dut)
    if dut == "xiangshan-clean":
        resolved = resolve_xiangshan_binary(Path(path or DEFAULT_XIANGSHAN_EMU))
        return resolved.exists()
    if dut == "rocket-cascade":
        return Path(path).exists()
    if dut == "u74":
        return Path(path or DEFAULT_U74_LEGACY_CATALOG).exists()
    return bool(path and Path(path).exists())


def _smepmp_probe_result(
    dut: str,
    available: bool,
    statically_supported: bool,
    probe_smepmp: bool,
    *,
    static_rlb: bool,
) -> dict[str, Any]:
    if not available:
        status = "infra_unadapted"
    elif not probe_smepmp:
        status = "supported" if statically_supported else "unsupported"
    elif statically_supported:
        status = "supported"
    else:
        status = "unsupported"
    supported = status == "supported"
    return {
        "csr_access": supported,
        "mml": supported,
        "mmwp": supported,
        "rlb": supported and static_rlb,
        "warl_behavior": "assumed_supported" if supported and probe_smepmp else ("static" if supported else "not_available"),
        "probe_status": status,
    }


def _chipyard_sim_exists(dut: str) -> bool:
    configs = {
        "rocket-clean": ("simulator-chipyard.harness-RocketConfig",),
        "boom-clean": ("simulator-chipyard.harness-SmallBoomV3Config",),
        "cva6": ("simulator-chipyard.harness-CVA6Config", "simulator-chipyard-CVA6Config"),
        "cva6-clean": ("simulator-chipyard.harness-CVA6Config", "simulator-chipyard-CVA6Config"),
    }
    sim_dir = DEFAULT_CLEAN_CHIPYARD_DIR / "sims" / "verilator"
    return any((sim_dir / name).exists() for name in configs.get(dut, ()))


_COMMON_FULL = {
    "pmp": True,
    "s_mode": True,
    "u_mode": True,
    "sv39": True,
    "smepmp": False,
    "smepmp_rlb": False,
}

_COMMON_OBSERVATION = {
    "sv39_final_fault_address": True,
    "sv39_ptw_target_attribution": True,
    "sv39_stateful_reprobe_phase": True,
}

_DUT_SPECS: dict[str, dict[str, Any]] = {
    "spike": {
        "path": DEFAULT_CAPABILITY_SPIKE,
        "supported_capabilities": {**_COMMON_FULL, "smepmp": True},
        "smepmp_features": {"rlb": False},
        "finish_protocol": "tohost",
        "diagnostic_depth": "structured_tohost",
        "notes": ["reference ISA simulator; Smepmp availability still depends on selected --isa"],
    },
    "rocket-clean": {
        "path": DEFAULT_CLEAN_CHIPYARD_DIR / "sims" / "verilator" / "simulator-chipyard.harness-RocketConfig",
        "supported_capabilities": _COMMON_FULL,
        "observation_capabilities": _COMMON_OBSERVATION,
        "finish_protocol": "tohost",
        "diagnostic_depth": "structured_tohost",
    },
    "boom-clean": {
        "path": DEFAULT_CLEAN_CHIPYARD_DIR / "sims" / "verilator" / "simulator-chipyard.harness-SmallBoomV3Config",
        "supported_capabilities": _COMMON_FULL,
        "observation_capabilities": _COMMON_OBSERVATION,
        "finish_protocol": "tohost",
        "diagnostic_depth": "structured_tohost",
    },
    "cva6": {
        "path": DEFAULT_CLEAN_CHIPYARD_DIR / "sims" / "verilator" / "simulator-chipyard.harness-CVA6Config",
        "supported_capabilities": _COMMON_FULL,
        "observation_capabilities": {
            **_COMMON_OBSERVATION,
            "sv39_final_fault_address": False,
            "sv39_ptw_target_attribution": False,
            "sv39_stateful_reprobe_phase": False,
        },
        "finish_protocol": "tohost",
        "diagnostic_depth": "structured_tohost",
    },
    "cva6-clean": {
        "path": DEFAULT_CLEAN_CHIPYARD_DIR / "sims" / "verilator" / "simulator-chipyard.harness-CVA6Config",
        "supported_capabilities": _COMMON_FULL,
        "observation_capabilities": {
            **_COMMON_OBSERVATION,
            "sv39_final_fault_address": False,
            "sv39_ptw_target_attribution": False,
            "sv39_stateful_reprobe_phase": False,
        },
        "finish_protocol": "tohost",
        "diagnostic_depth": "structured_tohost",
    },
    "xiangshan-clean": {
        "path": DEFAULT_XIANGSHAN_EMU,
        "supported_capabilities": _COMMON_FULL,
        "observation_capabilities": _COMMON_OBSERVATION,
        "finish_protocol": "xiangshan-goodtrap",
        "diagnostic_depth": "pass_fail_only",
        "oracle_applicability": "valid",
        "notes": [
            "clean OpenXiangShan vanilla emu path only; legacy cascade emu must be passed explicitly",
            "uses XiangShan xstrap instruction encoding rather than standard ebreak/tohost termination",
        ],
    },
    "rocket-cascade": {
        "path": "",
        "supported_capabilities": _COMMON_FULL,
        "observation_capabilities": _COMMON_OBSERVATION,
        "finish_protocol": "cascade-mmio",
        "diagnostic_depth": "result_code_only",
    },
    "u74": {
        "path": DEFAULT_U74_LEGACY_CATALOG,
        "supported_capabilities": _COMMON_FULL,
        "finish_protocol": "board-opensbi-serial",
        "diagnostic_depth": "structured_uart",
        "ad_update_mode": "unknown",
        "notes": [
            "physical VisionFive 2 / U74 black-box adapter via generated OpenSBI runner and UART parsing",
            "Smepmp is currently treated as unsupported in the board-side pilot adapter",
        ],
    },
}
