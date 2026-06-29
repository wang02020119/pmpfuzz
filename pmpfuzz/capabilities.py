from __future__ import annotations

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


DEFAULT_CAPABILITY_SCHEMA_VERSION = 2
DEFAULT_CAPABILITY_SPIKE = "/home/dubhe/wjs/boom_host_deploy/opt-riscv/bin/spike"


def capability_for_dut(
    dut: str,
    *,
    available: bool | None = None,
    path: Path | str | None = None,
    probe_smepmp: bool = False,
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
    smepmp_probe = _smepmp_probe_result(dut, resolved_available, supported_capabilities.get("smepmp", False), probe_smepmp)
    supported_capabilities["smepmp"] = smepmp_probe["probe_status"] == "supported"
    capability = {
        "schema_version": DEFAULT_CAPABILITY_SCHEMA_VERSION,
        "dut": dut,
        "available": resolved_available,
        "path": resolved_path,
        "supported_capabilities": supported_capabilities,
        "finish_protocol": spec["finish_protocol"],
        "diagnostic_depth": spec["diagnostic_depth"],
        "oracle_applicability": oracle_applicability,
        "smepmp": smepmp_probe,
        "notes": notes,
    }
    return capability


def capability_matrix(duts: Iterable[str], *, probe_smepmp: bool = False) -> dict[str, Any]:
    entries = {dut: capability_for_dut(dut, probe_smepmp=probe_smepmp) for dut in duts}
    return {
        "schema_version": DEFAULT_CAPABILITY_SCHEMA_VERSION,
        "duts": entries,
    }


def required_capabilities_for_case(case: dict[str, Any]) -> list[str]:
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


def _is_experimental_case(case: dict[str, Any]) -> bool:
    profile = str(case.get("profile") or "")
    if profile in {"legacy-fetch-experimental"}:
        return True
    sequence = case.get("stateful_sequence") or {}
    return sequence.get("fence") == "no-fence-experimental"


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
    return bool(path and Path(path).exists())


def _smepmp_probe_result(dut: str, available: bool, statically_supported: bool, probe_smepmp: bool) -> dict[str, Any]:
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
        "rlb": supported,
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
}

_DUT_SPECS: dict[str, dict[str, Any]] = {
    "spike": {
        "path": DEFAULT_CAPABILITY_SPIKE,
        "supported_capabilities": {**_COMMON_FULL, "smepmp": True},
        "finish_protocol": "tohost",
        "diagnostic_depth": "structured_tohost",
        "notes": ["reference ISA simulator; Smepmp availability still depends on selected --isa"],
    },
    "rocket-clean": {
        "path": DEFAULT_CLEAN_CHIPYARD_DIR / "sims" / "verilator" / "simulator-chipyard.harness-RocketConfig",
        "supported_capabilities": _COMMON_FULL,
        "finish_protocol": "tohost",
        "diagnostic_depth": "structured_tohost",
    },
    "boom-clean": {
        "path": DEFAULT_CLEAN_CHIPYARD_DIR / "sims" / "verilator" / "simulator-chipyard.harness-SmallBoomV3Config",
        "supported_capabilities": _COMMON_FULL,
        "finish_protocol": "tohost",
        "diagnostic_depth": "structured_tohost",
    },
    "cva6": {
        "path": DEFAULT_CLEAN_CHIPYARD_DIR / "sims" / "verilator" / "simulator-chipyard.harness-CVA6Config",
        "supported_capabilities": _COMMON_FULL,
        "finish_protocol": "tohost",
        "diagnostic_depth": "structured_tohost",
    },
    "cva6-clean": {
        "path": DEFAULT_CLEAN_CHIPYARD_DIR / "sims" / "verilator" / "simulator-chipyard.harness-CVA6Config",
        "supported_capabilities": _COMMON_FULL,
        "finish_protocol": "tohost",
        "diagnostic_depth": "structured_tohost",
    },
    "xiangshan-clean": {
        "path": DEFAULT_XIANGSHAN_EMU,
        "supported_capabilities": _COMMON_FULL,
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
        "finish_protocol": "cascade-mmio",
        "diagnostic_depth": "result_code_only",
    },
}
